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
import json
import os
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
from fabric.cli import _kube
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
    ]
    usage = node.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(usage) == [ExtendedKeyUsageOID.SERVER_AUTH]


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
    out.mkdir(mode=0o755)
    os.chmod(out, 0o755)  # noqa: S103 - the unsafe directory under test
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


def test_an_unreachable_api_server_is_fc_103() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = httpx.Client(base_url="https://10.0.0.1", transport=httpx.MockTransport(refuse))
    with pytest.raises(CliError) as caught:
        _kube.Generator(_plan(), _kube.InClusterStore({}, client=client)).run()
    assert (caught.value.findings[0].id, caught.value.exit_code) == ("FC-103", 3)
