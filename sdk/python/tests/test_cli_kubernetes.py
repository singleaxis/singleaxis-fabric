# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 WP8-12: ``fabric init --kubernetes`` and ``--render`` (§10.2, §10.3), the
generator the chart's secrets hook Job runs (``--in-cluster``).

What is pinned: every Secret the chart references is created when missing and never
overwritten, printed or logged (I7); the Node-side ingress Secret and the agent Secret of
a namespace agree on the token, and the source id is the SDK's own pseudonym under the
namespace's id key; certificates chain to the cluster CA with the right names and usages;
manifests reach kubectl on standard input, never on a command line; the API errors name
their cause and fix."""

from __future__ import annotations

import base64
import datetime as dt
import json
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from fabric import cli
from fabric._sequence import label_pseudonym
from fabric.cli import _kube, _secrets
from fabric.cli._report import CliError

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def _json(args: list[str], capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    code = cli.main([*args, "--json"])
    out, _ = capsys.readouterr()
    report: dict[str, Any] = json.loads(out)
    assert report["exit_code"] == code
    return report


def _rendered(directory: Path) -> dict[tuple[str, str], dict[str, bytes]]:
    out = {}
    for path in sorted(directory.rglob("secret-*.yaml")):
        document = json.loads(path.read_text("utf-8"))
        key = (document["metadata"]["namespace"], document["metadata"]["name"])
        out[key] = {k: base64.b64decode(v) for k, v in document["data"].items()}
    return out


class MemoryStore:
    """A cluster in memory: what a Store sees, nothing more."""

    where = "memory"

    def __init__(self, namespaces: tuple[str, ...] = ("fabric-system", "agents")) -> None:
        self.namespaces = set(namespaces)
        self.secrets: dict[tuple[str, str], dict[str, bytes]] = {}
        self.types: dict[tuple[str, str], str] = {}
        self.creates = 0

    def get(self, namespace: str, name: str) -> dict[str, bytes] | None:
        found = self.secrets.get((namespace, name))
        return dict(found) if found is not None else None

    def create(
        self,
        namespace: str,
        name: str,
        data: Mapping[str, bytes],
        labels: Mapping[str, str],
        object_type: str,
    ) -> None:
        assert labels["app.kubernetes.io/managed-by"] == "fabric-cli"
        if (namespace, name) in self.secrets:
            raise _kube.Exists(name)
        self.secrets[(namespace, name)] = dict(data)
        self.types[(namespace, name)] = object_type
        self.creates += 1


def _plan(**kwargs: Any) -> _kube.Plan:
    base: dict[str, Any] = {
        "namespace": "fabric-system",
        "release": "fabric",
        "agents": (_kube.AgentNamespace("agents", "support-bot"),),
    }
    base.update(kwargs)
    return _kube.Plan(**base)


# ---------------------------------------------------------------- what is generated


def test_local_plan_creates_the_ca_node_certificate_and_agent_secret() -> None:
    store = MemoryStore()
    outcomes = _kube.Generator(_plan(), store).run()
    assert {(o.namespace, o.name, o.action) for o in outcomes} == {
        ("fabric-system", "fabric-ca", "created"),
        ("fabric-system", "fabric-node-receiver-tls", "created"),
        ("agents", "fabric-agent", "created"),
    }
    agent = store.secrets[("agents", "fabric-agent")]
    assert sorted(agent) == ["ca.crt", "id.key", "spool.key"]
    assert re.fullmatch(rb"[0-9a-f]{64}", agent["id.key"])
    assert len(base64.b64decode(agent["spool.key"])) == 32
    assert agent["ca.crt"] == store.secrets[("fabric-system", "fabric-ca")]["ca.crt"]
    assert store.types[("fabric-system", "fabric-node-receiver-tls")] == "kubernetes.io/tls"
    # No production material on a local Node.
    assert not any(name.startswith("fabric-ingress-") for _, name in store.secrets)


def test_node_certificate_names_the_service_and_chains_to_the_ca() -> None:
    store = MemoryStore()
    _kube.Generator(
        _plan(node_service="f-otel-collector", cluster_domain="corp.local"), store
    ).run()
    ca = x509.load_pem_x509_certificate(store.secrets[("fabric-system", "fabric-ca")]["ca.crt"])
    node = x509.load_pem_x509_certificate(
        store.secrets[("fabric-system", "fabric-node-receiver-tls")]["tls.crt"]
    )
    node.verify_directly_issued_by(ca)
    names = node.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert names.get_values_for_type(x509.DNSName) == [
        "f-otel-collector",
        "f-otel-collector.fabric-system",
        "f-otel-collector.fabric-system.svc",
        "f-otel-collector.fabric-system.svc.corp.local",
        # A local Node takes no token, so `fabric verify --kubernetes` sends its canary
        # through a port-forward to localhost (spec 058 §10.6).
        "localhost",
    ]
    usage = node.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(usage) == [ExtendedKeyUsageOID.SERVER_AUTH]


def test_production_node_certificate_does_not_name_localhost() -> None:
    store = MemoryStore()
    _kube.Generator(_plan(production=True), store).run()
    node = x509.load_pem_x509_certificate(
        store.secrets[("fabric-system", "fabric-node-receiver-tls")]["tls.crt"]
    )
    names = node.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" not in names.get_values_for_type(x509.DNSName)


def test_production_namespace_token_and_source_id_agree_with_the_sdk() -> None:
    store = MemoryStore()
    _kube.Generator(_plan(production=True, content=True), store).run()
    agent = store.secrets[("agents", "fabric-agent")]
    ingress = store.secrets[("fabric-system", "fabric-ingress-agents")]
    token = re.fullmatch(rb"Authorization=Bearer%20([0-9a-f]{64})", agent["headers"])
    assert token and ingress["token"] == token.group(1)
    # The Node binds what the SDK emits for FABRIC_SOURCE_ID under this id key.
    assert ingress["source-id"].decode() == label_pseudonym("s-", "support-bot", agent["id.key"])
    assert ingress["source-id"].decode() == _kube.source_id("support-bot", agent["id.key"] + b"\n")
    client = x509.load_pem_x509_certificate(agent["tls.crt"])
    ca = x509.load_pem_x509_certificate(store.secrets[("fabric-system", "fabric-ca")]["ca.crt"])
    client.verify_directly_issued_by(ca)
    usage = client.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(usage) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    assert store.secrets[("fabric-system", "fabric-node-client-ca")]["ca.crt"] == agent["ca.crt"]
    assert (
        len(base64.b64decode(store.secrets[("fabric-system", "fabric-node-content-key")]["key"]))
        == 32
    )


def test_content_key_only_with_content_and_injector_certificate_only_with_injector() -> None:
    store = MemoryStore()
    _kube.Generator(_plan(production=True), store).run()
    assert ("fabric-system", "fabric-node-content-key") not in store.secrets
    assert ("fabric-system", "fabric-injector-tls") not in store.secrets
    _kube.Generator(_plan(injector=True, injector_service="f-fabric-injector"), store).run()
    cert = x509.load_pem_x509_certificate(
        store.secrets[("fabric-system", "fabric-injector-tls")]["tls.crt"]
    )
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "f-fabric-injector.fabric-system.svc" in names.get_values_for_type(x509.DNSName)


def test_existing_secrets_are_kept_byte_for_byte_and_never_overwritten() -> None:
    store = MemoryStore()
    _kube.Generator(_plan(production=True), store).run()
    before = {key: dict(value) for key, value in store.secrets.items()}
    creates = store.creates
    outcomes = _kube.Generator(_plan(production=True), store).run()
    assert store.secrets == before and store.creates == creates
    assert {o.action for o in outcomes} == {"kept"}


def test_a_secret_named_by_the_operator_is_used_as_it_is() -> None:
    store = MemoryStore()
    store.secrets[("fabric-system", "my-node-tls")] = {"tls.crt": b"mine", "tls.key": b"mine"}
    _kube.Generator(_plan(names={"node-tls": "my-node-tls"}), store).run()
    assert store.secrets[("fabric-system", "my-node-tls")] == {
        "tls.crt": b"mine",
        "tls.key": b"mine",
    }
    assert ("fabric-system", "fabric-node-receiver-tls") not in store.secrets


def test_an_incomplete_secret_is_reported_and_left_unchanged() -> None:
    store = MemoryStore()
    store.secrets[("agents", "fabric-agent")] = {"ca.crt": b"x", "id.key": b"k" * 64}
    generator = _kube.Generator(_plan(production=True), store)
    generator.run()
    assert store.secrets[("agents", "fabric-agent")] == {"ca.crt": b"x", "id.key": b"k" * 64}
    details = [f.detail for f in generator.findings if f.id == "FC-104"]
    assert details == ["agents/fabric-agent lacks spool.key, headers, tls.crt, tls.key"]
    # Without the agent's token no ingress Secret could match it: none is created.
    assert ("fabric-system", "fabric-ingress-agents") not in store.secrets


def test_an_ingress_secret_without_its_agent_secret_is_refused() -> None:
    store = MemoryStore()
    store.secrets[("fabric-system", "fabric-ingress-agents")] = {"token": b"t", "source-id": b"s"}
    generator = _kube.Generator(_plan(production=True), store)
    generator.run()
    assert [f.id for f in generator.findings] == ["FC-105"]
    assert ("agents", "fabric-agent") not in store.secrets


def test_an_agent_secret_kept_from_before_gets_its_ingress_secret() -> None:
    store = MemoryStore()
    _kube.Generator(_plan(production=True), store).run()
    agent = dict(store.secrets[("agents", "fabric-agent")])
    del store.secrets[("fabric-system", "fabric-ingress-agents")]
    _kube.Generator(_plan(production=True), store).run()
    assert store.secrets[("agents", "fabric-agent")] == agent
    ingress = store.secrets[("fabric-system", "fabric-ingress-agents")]
    assert b"Bearer%20" + ingress["token"] == agent["headers"].split(b"=", 1)[1]


def test_a_concurrent_create_uses_the_secret_that_won() -> None:
    class Racing(MemoryStore):
        def create(
            self,
            namespace: str,
            name: str,
            data: Mapping[str, bytes],
            labels: Mapping[str, str],
            object_type: str,
        ) -> None:
            if name == "fabric-ca" and (namespace, name) not in self.secrets:
                self.secrets[(namespace, name)] = {"ca.crt": b"theirs", "ca.key": b"theirs"}
                raise _kube.Exists(name)
            super().create(namespace, name, data, labels, object_type)

    store = Racing()
    with pytest.raises(CliError) as caught:  # their CA is not a certificate: we used theirs
        _kube.Generator(_plan(), store).run()
    assert caught.value.findings[0].id == "FC-104"
    assert store.secrets[("fabric-system", "fabric-ca")]["ca.crt"] == b"theirs"


def test_ingress_secret_names_match_the_chart() -> None:
    # The same values are pinned in charts/fabric/tests/test-secrets-and-injector.sh.
    assert _kube.ingress_secret_name("agents") == "fabric-ingress-agents"
    long = "a-namespace-name-that-is-longer-than-forty-characters"
    assert (
        _kube.ingress_secret_name(long) == "fabric-ingress-a-namespace-name-that-is-longer-c9bbb667"
    )


@pytest.mark.parametrize(
    "plan",
    [
        {"namespace": "Fabric"},
        {"release": "a_b"},
        {"agents": (_kube.AgentNamespace("fabric-system", "x"),)},
        {"agents": (_kube.AgentNamespace("a", "x"), _kube.AgentNamespace("a", "y"))},
        {"names": {"nope": "x"}},
        {"names": {"ca": "Bad Name"}},
        {"cluster_domain": "a b"},
    ],
)
def test_invalid_names_are_refused_with_fc_109(plan: dict[str, Any]) -> None:
    with pytest.raises(CliError) as caught:
        _plan(**plan).validate()
    assert caught.value.findings[0].id == "FC-109"


def test_agent_namespace_option_parses_a_source_label() -> None:
    assert _kube.AgentNamespace.parse("agents") == _kube.AgentNamespace("agents", "agents")
    assert _kube.AgentNamespace.parse("agents=support:v1") == _kube.AgentNamespace(
        "agents", "support:v1"
    )
    with pytest.raises(CliError):
        _kube.AgentNamespace.parse("agents=has space")


# ---------------------------------------------------------------- --render


def test_render_writes_private_manifests_and_prints_no_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "manifests"
    code = cli.main(
        [
            "init",
            "--kubernetes",
            "--render",
            str(out),
            "--agent-namespace",
            "agents",
            "--profile",
            "production",
            "--content",
        ]
    )
    printed, errors = capsys.readouterr()
    assert code == 0, errors
    secrets_ = _rendered(out)
    assert set(secrets_) == {
        ("fabric-system", "fabric-ca"),
        ("fabric-system", "fabric-node-receiver-tls"),
        ("fabric-system", "fabric-node-client-ca"),
        ("fabric-system", "fabric-node-content-key"),
        ("fabric-system", "fabric-ingress-agents"),
        ("agents", "fabric-agent"),
    }
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    for path in out.rglob("*.yaml"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        document = json.loads(path.read_text("utf-8"))
        assert (
            document["kind"] == "Secret"
            and document["metadata"]["labels"]["app.kubernetes.io/managed-by"] == "fabric-cli"
        )
    for data in secrets_.values():
        for value in data.values():
            for line in value.splitlines():
                if len(line) >= 16 and not line.startswith(b"-----"):
                    assert line.decode() not in printed + errors
                    assert base64.b64encode(value).decode() not in printed + errors
    assert "kubectl create -f" in printed and "created Secret agents/fabric-agent" in printed
    # Rendering again keeps every value.
    assert (
        cli.main(
            [
                "init",
                "--kubernetes",
                "--render",
                str(out),
                "--agent-namespace",
                "agents",
                "--profile",
                "production",
                "--content",
            ]
        )
        == 0
    )
    assert _rendered(out) == secrets_
    assert "kept Secret" in capsys.readouterr()[0]


def test_render_refuses_a_directory_open_to_others(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "open"
    out.mkdir(mode=0o700)
    # The unsafe directory under test: readable by the owner's group.
    out.chmod(out.stat().st_mode | stat.S_IRGRP)
    report = _json(["init", "--kubernetes", "--render", str(out)], capsys)
    assert report["findings"][0]["id"] == "FC-012" and report["exit_code"] == 2


def test_json_report_lists_secrets_without_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _json(
        [
            "init",
            "--kubernetes",
            "--render",
            str(tmp_path / "m"),
            "--injector",
            "--agent-namespace",
            "agents=support",
        ],
        capsys,
    )
    assert report["data"]["kubernetes"]["agent_namespaces"] == ["agents"]
    assert {s["name"] for s in report["data"]["secrets"]} == {
        "fabric-ca",
        "fabric-node-receiver-tls",
        "fabric-injector-tls",
        "fabric-agent",
    }
    assert [f["id"] for f in report["findings"]] == ["FC-107"]  # how to read the caBundle
    assert all("data" not in s for s in report["data"]["secrets"])


# ---------------------------------------------------------------- options


@pytest.mark.parametrize(
    "args",
    [
        ["--namespace", "x"],
        ["--agent-namespace", "a"],
        ["--render", "d"],
        ["--injector"],
        ["--in-cluster"],
        ["--webhook", "w"],
        ["--content"],
    ],
)
def test_kubernetes_options_without_kubernetes_say_so(
    args: list[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    report = _json(["init", *args], capsys)
    assert (report["exit_code"], report["findings"][0]["id"]) == (2, "FC-106")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "args",
    [["--rotate", "ca"], ["--from-env"], ["--force"], ["--provider", "https://llm.example.com/v1"]],
)
def test_local_only_options_are_refused_with_kubernetes(
    args: list[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    report = _json(["init", "--kubernetes", "--render", "m", *args], capsys)
    assert report["findings"][0]["id"] == "FC-011"
    assert list(tmp_path.iterdir()) == []


def test_kubernetes_mode_never_writes_fabric_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert cli.main(["init", "--kubernetes", "--render", "m"]) == 0
    capsys.readouterr()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["m"]


# ---------------------------------------------------------------- kubectl


class FakeKubectl:
    def __init__(self, results: dict[str, Any] | None = None) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.created: list[dict[str, Any]] = []
        self.results = results or {}

    def __call__(self, argv: list[str], *, input: str | None = None, **_: Any) -> Any:
        self.calls.append((argv, input))
        verb = argv[1]
        if verb in self.results:
            return self.results[verb]
        if verb == "get":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        assert input is not None
        self.created.append(json.loads(input))
        return SimpleNamespace(returncode=0, stdout="secret/x\n", stderr="")


def test_kubectl_gets_manifests_on_stdin_never_in_argv() -> None:
    fake = FakeKubectl()
    store = _kube.KubectlStore(kubectl="/usr/bin/kubectl", runner=fake)
    _kube.Generator(_plan(production=True), store).run()
    assert {(m["metadata"]["namespace"], m["metadata"]["name"]) for m in fake.created} >= {
        ("fabric-system", "fabric-ca"),
        ("agents", "fabric-agent"),
    }
    for argv, _ in fake.calls:
        joined = " ".join(argv)
        assert "BEGIN" not in joined and "Bearer" not in joined
        for created in fake.created:
            for value in created["data"].values():
                assert value not in joined
    creates = [argv for argv, stdin in fake.calls if argv[1] == "create"]
    assert creates and all(
        argv == ["/usr/bin/kubectl", "create", "-f", "-", "-o", "name"] for argv in creates
    )


@pytest.mark.parametrize(
    ("stderr", "finding"),
    [
        (
            'Error from server (Forbidden): secrets "fabric-ca" is forbidden: User cannot get',
            "FC-102",
        ),
        ('Error from server (NotFound): namespaces "agents" not found', "FC-101"),
        ("The connection to the server localhost:8080 was refused", "FC-103"),
    ],
)
def test_kubectl_errors_name_their_cause(stderr: str, finding: str) -> None:
    fake = FakeKubectl({"get": SimpleNamespace(returncode=1, stdout="", stderr=stderr)})
    store = _kube.KubectlStore(kubectl="kubectl", runner=fake)
    with pytest.raises(CliError) as caught:
        _kube.Generator(_plan(), store).run()
    assert caught.value.findings[0].id == finding and caught.value.exit_code == 3


def test_no_kubectl_is_a_missing_prerequisite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    report = _json(["init", "--kubernetes"], capsys)
    assert (report["exit_code"], report["findings"][0]["id"]) == (3, "FC-100")


def test_kubectl_already_exists_uses_the_existing_secret() -> None:
    state: dict[str, Any] = {}

    def runner(argv: list[str], *, input: str | None = None, **_: Any) -> Any:
        if argv[1] == "get":
            name = argv[3]
            if name in state:
                return SimpleNamespace(
                    returncode=0, stdout=json.dumps({"data": state[name]}), stderr=""
                )
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        document = json.loads(input or "{}")
        state[document["metadata"]["name"]] = document["data"]
        if document["metadata"]["name"] == "fabric-agent":
            return SimpleNamespace(
                returncode=1, stdout="", stderr='secrets "fabric-agent" already exists'
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    outcomes = _kube.Generator(_plan(), _kube.KubectlStore("kubectl", runner)).run()
    assert [o.action for o in outcomes if o.name == "fabric-agent"] == ["kept"]


# ---------------------------------------------------------------- in-cluster API


class FakeApi:
    """The Kubernetes API endpoints the in-cluster store calls."""

    def __init__(
        self,
        forbidden: tuple[str, ...] = (),
        namespaces: tuple[str, ...] = ("fabric-system", "agents"),
    ) -> None:
        self.secrets: dict[tuple[str, str], dict[str, Any]] = {}
        self.forbidden = forbidden
        self.namespaces = namespaces
        self.webhook = {
            "webhooks": [{"name": "a", "clientConfig": {}}, {"name": "b", "clientConfig": {}}]
        }
        self.patches: list[Any] = []
        self.auth: set[str] = set()

    def __call__(self, request: httpx.Request) -> httpx.Response:  # noqa: PLR0911
        self.auth.add(request.headers.get("Authorization", ""))
        path = request.url.path
        match = re.fullmatch(r"/api/v1/namespaces/([^/]+)/secrets(?:/([^/]+))?", path)
        if match:
            namespace, name = match.groups()
            if namespace in self.forbidden:
                return httpx.Response(403, json={"reason": "Forbidden"})
            if namespace not in self.namespaces:
                return httpx.Response(404, json={"reason": "NotFound"})
            if request.method == "GET":
                found = self.secrets.get((namespace, name or ""))
                return httpx.Response(200, json=found) if found else httpx.Response(404, json={})
            body = json.loads(request.content)
            key = (namespace, body["metadata"]["name"])
            if key in self.secrets:
                return httpx.Response(409, json={"reason": "AlreadyExists"})
            self.secrets[key] = body
            return httpx.Response(201, json=body)
        if path.endswith("/mutatingwebhookconfigurations/fabric-injector-fabric-system-fabric"):
            if request.method == "GET":
                return httpx.Response(200, json=self.webhook)
            assert request.headers["Content-Type"] == "application/json-patch+json"
            self.patches.append(json.loads(request.content))
            return httpx.Response(200, json=self.webhook)
        return httpx.Response(404, json={})


def _cluster(api: FakeApi) -> _kube.InClusterStore:
    client = httpx.Client(
        base_url="https://10.0.0.1",
        transport=httpx.MockTransport(api),
        headers={"Authorization": "Bearer sa-token"},
    )
    return _kube.InClusterStore({}, client=client)


def test_in_cluster_creates_through_the_api_and_patches_the_webhook_ca_bundle() -> None:
    api = FakeApi()
    store = _cluster(api)
    _kube.Generator(_plan(injector=True), store).run()
    assert ("fabric-system", "fabric-injector-tls") in api.secrets
    assert api.auth == {"Bearer sa-token"}
    ca = base64.b64decode(api.secrets[("fabric-system", "fabric-ca")]["data"]["ca.crt"])
    _kube.Generator(_plan(), store).patch_webhook("fabric-injector-fabric-system-fabric")
    bundle = base64.b64encode(ca).decode()
    assert api.patches == [
        [
            {"op": "add", "path": "/webhooks/0/clientConfig/caBundle", "value": bundle},
            {"op": "add", "path": "/webhooks/1/clientConfig/caBundle", "value": bundle},
        ]
    ]


def test_webhook_patch_never_generates_a_ca() -> None:
    api = FakeApi()
    with pytest.raises(CliError) as caught:
        _kube.Generator(_plan(), _cluster(api)).patch_webhook(
            "fabric-injector-fabric-system-fabric"
        )
    assert caught.value.findings[0].id == "FC-104" and not api.secrets


def test_a_missing_webhook_is_named() -> None:
    api = FakeApi()
    store = _cluster(api)
    _kube.Generator(_plan(agents=()), store).run()
    with pytest.raises(CliError) as caught:
        _kube.Generator(_plan(), store).patch_webhook("another-webhook")
    assert caught.value.findings[0].id == "FC-108"


@pytest.mark.parametrize(
    ("api", "finding"),
    [
        (FakeApi(forbidden=("agents",)), "FC-102"),
        (FakeApi(namespaces=("fabric-system",)), "FC-101"),
    ],
)
def test_in_cluster_errors_name_their_cause(api: FakeApi, finding: str) -> None:
    with pytest.raises(CliError) as caught:
        _kube.Generator(_plan(), _cluster(api)).run()
    assert caught.value.findings[0].id == finding


def test_in_cluster_outside_a_pod_says_so() -> None:
    with pytest.raises(CliError) as caught:
        _kube.InClusterStore({})
    assert caught.value.findings[0].id == "FC-103"
    assert "inside a pod" in (caught.value.findings[0].detail or "")


def test_in_cluster_without_a_service_account_token_says_so(tmp_path: Path) -> None:
    with pytest.raises(CliError) as caught:
        _kube.InClusterStore({"KUBERNETES_SERVICE_HOST": "10.0.0.1"}, sa_dir=tmp_path)
    assert caught.value.findings[0].id == "FC-103"
    assert "automountServiceAccountToken: true" in (caught.value.findings[0].detail or "")


def test_an_unreachable_api_server_is_fc_103() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = httpx.Client(base_url="https://10.0.0.1", transport=httpx.MockTransport(refuse))
    with pytest.raises(CliError) as caught:
        _kube.Generator(_plan(), _kube.InClusterStore({}, client=client)).run()
    assert (caught.value.findings[0].id, caught.value.exit_code) == ("FC-103", 3)


# ---------------------------------------------------------------- review: expiry, unusable


def _later(monkeypatch: pytest.MonkeyPatch, days: int) -> None:
    moved = _secrets._now() + dt.timedelta(days=days)
    monkeypatch.setattr(_secrets, "_now", lambda: moved)


def test_a_new_certificate_reports_when_it_expires_and_no_finding() -> None:
    store = MemoryStore()
    generator = _kube.Generator(_plan(production=True, injector=True), store)
    outcomes = {o.name: o for o in generator.run()}
    assert not generator.findings
    for name in ("fabric-ca", "fabric-node-receiver-tls", "fabric-injector-tls", "fabric-agent"):
        shown = outcomes[name].to_json()
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", shown["expires"]), name
        assert shown["fingerprint"].startswith("sha256:")
    # A Secret without a certificate has neither.
    assert "expires" not in outcomes["fabric-ingress-agents"].to_json()


def test_a_kept_certificate_close_to_expiry_is_a_warning_naming_the_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryStore()
    _kube.Generator(_plan(production=True, injector=True), store).run()
    before = {key: dict(value) for key, value in store.secrets.items()}
    _later(monkeypatch, _secrets.LEAF_VALID_DAYS - _secrets.RENEW_BEFORE_DAYS + 1)
    generator = _kube.Generator(_plan(production=True, injector=True), store)
    generator.run()
    assert store.secrets == before  # never renewed in place: a Secret is never overwritten
    assert {f.id for f in generator.findings} == {"FC-111"}
    assert all(f.severity == "warning" for f in generator.findings)
    details = sorted(f.detail or "" for f in generator.findings)
    assert [d.split(",")[0] for d in details] == [
        "agents/fabric-agent tls.crt",
        "fabric-system/fabric-injector-tls tls.crt",
        "fabric-system/fabric-node-receiver-tls tls.crt",
    ]
    assert all(re.search(r", valid until \d{4}-\d\d-\d\d$", d) for d in details)


def test_an_expired_certificate_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    store = MemoryStore()
    _kube.Generator(_plan(), store).run()
    _later(monkeypatch, _secrets.LEAF_VALID_DAYS + 1)
    generator = _kube.Generator(_plan(), store)
    generator.run()
    assert [(f.id, f.severity) for f in generator.findings] == [("FC-112", "error")]
    assert (generator.findings[0].detail or "").startswith(
        "fabric-system/fabric-node-receiver-tls tls.crt, valid until "
    )


def test_deleting_an_expired_node_certificate_issues_a_new_one_from_the_same_ca(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fix FC-111 and FC-112 give, end to end."""
    store = MemoryStore()
    _kube.Generator(_plan(), store).run()
    ca = dict(store.secrets[("fabric-system", "fabric-ca")])
    old = store.secrets.pop(("fabric-system", "fabric-node-receiver-tls"))
    _later(monkeypatch, _secrets.LEAF_VALID_DAYS + 1)
    generator = _kube.Generator(_plan(), store)
    generator.run()
    assert not generator.findings
    new = store.secrets[("fabric-system", "fabric-node-receiver-tls")]
    assert new["tls.crt"] != old["tls.crt"] and new["ca.crt"] == ca["ca.crt"]
    assert store.secrets[("fabric-system", "fabric-ca")] == ca
    issued = x509.load_pem_x509_certificate(new["tls.crt"])
    issued.verify_directly_issued_by(x509.load_pem_x509_certificate(ca["ca.crt"]))


def test_a_secret_that_holds_no_certificate_has_no_expiry_and_no_finding() -> None:
    store = MemoryStore()
    store.secrets[("fabric-system", "fabric-node-receiver-tls")] = {
        "tls.crt": b"not a certificate",
        "tls.key": b"x",
    }
    generator = _kube.Generator(_plan(), store)
    outcomes = {o.name: o for o in generator.run()}
    assert not generator.findings
    assert outcomes["fabric-node-receiver-tls"].to_json() == {
        "namespace": "fabric-system",
        "name": "fabric-node-receiver-tls",
        "action": "kept",
        "keys": ["tls.crt", "tls.key"],
    }


def test_an_agent_secret_without_a_credential_stops_a_production_setup() -> None:
    """A namespace first set up for a local Node, then moved to a production one: its
    Secret has no ingest credential, so no ingress Secret can match it and the Node,
    which reads that Secret when it starts, would wait in CreateContainerConfigError."""
    store = MemoryStore()
    _kube.Generator(_plan(), store).run()
    agent = dict(store.secrets[("agents", "fabric-agent")])
    generator = _kube.Generator(_plan(production=True), store)
    generator.run()
    assert store.secrets[("agents", "fabric-agent")] == agent
    assert ("fabric-system", "fabric-ingress-agents") not in store.secrets
    by_id = {f.id: f for f in generator.findings}
    assert set(by_id) == {"FC-104", "FC-110"}
    assert by_id["FC-110"].severity == "error"
    assert by_id["FC-110"].detail == (
        "agents/fabric-agent (ingress Secret fabric-system/fabric-ingress-agents not made)"
    )
    # The fix it names works: delete the agent Secret, run again.
    del store.secrets[("agents", "fabric-agent")]
    again = _kube.Generator(_plan(production=True), store)
    again.run()
    assert not again.findings
    assert ("fabric-system", "fabric-ingress-agents") in store.secrets


def test_the_unusable_agent_secret_fails_the_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "manifests"
    base = ["init", "--kubernetes", "--agent-namespace", "agents", "--render", str(out)]
    assert _json(base, capsys)["exit_code"] == 0
    report = _json([*base, "--profile", "production"], capsys)
    assert report["exit_code"] == 1
    assert {f["id"] for f in report["findings"]} == {"FC-104", "FC-110"}
    assert not (out / "fabric-system" / "secret-fabric-ingress-agents.yaml").exists()


def test_render_says_the_files_hold_values_in_clear_and_shows_expiry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "manifests"
    assert (
        cli.main(["init", "--kubernetes", "--agent-namespace", "agents", "--render", str(out)]) == 0
    )
    text, _ = capsys.readouterr()
    assert "hold the secret values in clear" in text
    assert re.search(
        r"created Secret fabric-system/fabric-ca \(.*; valid until \d{4}-\d\d-\d\d\)", text
    )


# ---------------------------------------------------------------- the host sensor (§10.5)


def _sensor_plan(**kwargs: Any) -> _kube.Plan:
    return _plan(production=True, host_sensor=True, host_nodes=("node-a", "node-b"), **kwargs)


def test_host_sensor_secrets_are_generated_per_node_with_the_emitters_source_id() -> None:
    """The id key the sensors and agents share, the sensors' client certificate, and for
    each node its token, state key and the source id `fabric-host-emitter print-source-id`
    prints for `<node>/ebpf` under that key (deploy/kubernetes/host-bindings.py's rule)."""
    store = MemoryStore()
    generator = _kube.Generator(_sensor_plan(), store)
    generator.run()
    assert not generator.findings
    id_key = store.secrets[("fabric-system", "fabric-id-key")]["id_key"]
    assert re.fullmatch(rb"[0-9a-f]{64}", id_key)
    tls = store.secrets[("fabric-system", "fabric-host-emitter-tls")]
    assert sorted(tls) == ["ca.crt", "tls.crt", "tls.key"]
    leaf = x509.load_pem_x509_certificate(tls["tls.crt"])
    usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(usage) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    tokens = set()
    for node in ("node-a", "node-b"):
        secret = store.secrets[("fabric-system", _kube.host_secret_name(node))]
        assert sorted(secret) == ["source-id", "state-key", "token"]
        assert secret["source-id"].decode() == label_pseudonym("s-", f"{node}/ebpf", id_key)
        assert len(base64.b64decode(secret["state-key"])) == 32
        assert re.fullmatch(rb"[0-9a-f]{64}", secret["token"])
        tokens.add(secret["token"])
    assert len(tokens) == 2, "each node has its own token"


def test_host_secret_names_match_the_chart() -> None:
    # The same rule as charts/fabric/templates/_hostsensor.tpl (tests/test-host-sensor.sh).
    assert _kube.host_secret_name("node-a") == "fabric-host-66570ff05a20"
    assert len(_kube.host_secret_name("n" * 253)) == len("fabric-host-") + 12


def test_agents_share_the_release_id_key_with_the_sensor() -> None:
    """Host and agent records join only when both sides derive pseudonyms from one key."""
    store = MemoryStore()
    _kube.Generator(_sensor_plan(), store).run()
    shared = store.secrets[("fabric-system", "fabric-id-key")]["id_key"]
    agent = store.secrets[("agents", "fabric-agent")]
    assert agent["id.key"] == shared
    ingress = store.secrets[("fabric-system", "fabric-ingress-agents")]
    assert ingress["source-id"].decode() == label_pseudonym("s-", "support-bot", shared)


def test_an_agent_secret_with_its_own_id_key_is_reported_not_changed() -> None:
    store = MemoryStore()
    _kube.Generator(_plan(production=True), store).run()  # before the sensor was turned on
    before = dict(store.secrets[("agents", "fabric-agent")])
    generator = _kube.Generator(_sensor_plan(), store)
    generator.run()
    assert store.secrets[("agents", "fabric-agent")] == before
    assert [(f.id, f.detail) for f in generator.findings] == [
        ("FC-115", "agents/fabric-agent (agent namespace agents)")
    ]


def test_a_node_secret_made_under_another_id_key_is_an_error() -> None:
    store = MemoryStore()
    _kube.Generator(_sensor_plan(), store).run()
    del store.secrets[("fabric-system", "fabric-id-key")]  # the id key was replaced
    del store.secrets[("agents", "fabric-agent")]
    del store.secrets[("fabric-system", "fabric-ingress-agents")]
    generator = _kube.Generator(_sensor_plan(), store)
    generator.run()
    assert {f.id for f in generator.findings} == {"FC-114"}
    assert len(generator.findings) == 2 and "node-a" in str(generator.findings[0].detail)


def test_a_second_run_keeps_every_host_sensor_secret() -> None:
    store = MemoryStore()
    _kube.Generator(_sensor_plan(), store).run()
    before = {key: dict(value) for key, value in store.secrets.items()}
    generator = _kube.Generator(_sensor_plan(), store)
    generator.run()
    assert store.secrets == before and not generator.findings
    assert {o.action for o in generator.outcomes} == {"kept"}


@pytest.mark.parametrize(
    ("plan", "finding"),
    [
        ({"host_sensor": True, "host_nodes": ("node-a",)}, "FC-113"),  # not production
        ({"production": True, "host_nodes": ("node-a",)}, "FC-106"),  # --host-node alone
        ({"production": True, "host_sensor": True, "host_nodes": ("Node_A",)}, "FC-109"),
        ({"production": True, "host_sensor": True, "host_nodes": ("a", "a")}, "FC-109"),
    ],
)
def test_host_sensor_options_are_checked(plan: dict[str, Any], finding: str) -> None:
    with pytest.raises(CliError) as caught:
        _kube.Generator(_plan(**plan), MemoryStore())
    assert [f.id for f in caught.value.findings] == [finding]


def test_host_sensor_render_prints_names_never_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "render"
    report = _json(
        ["init", "--kubernetes", "--render", str(out), "--profile", "production", "--host-sensor",
         "--host-node", "node-a", "--agent-namespace", "agents"],
        capsys,
    )  # fmt: skip
    assert report["exit_code"] == 0, report
    assert report["data"]["kubernetes"]["host_sensor"] is True
    assert report["data"]["kubernetes"]["host_nodes"] == ["node-a"]
    rendered = _rendered(out)
    node = rendered[("fabric-system", _kube.host_secret_name("node-a"))]
    text = json.dumps(report)
    for value in (node["token"], rendered[("fabric-system", "fabric-id-key")]["id_key"]):
        assert value.decode() not in text
