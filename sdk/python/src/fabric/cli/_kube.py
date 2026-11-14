# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Kubernetes Secrets without hand work (spec 058 §7, §10.2, §10.3).

One generator, three places to put what it makes:

- the cluster of the current kube context (``fabric init --kubernetes``, through
  ``kubectl``, the manifest on its standard input, never on a command line);
- the cluster the chart's ``pre-install``/``pre-upgrade`` hook Job runs in
  (``--in-cluster``, the Kubernetes API with the Job's service account);
- manifest files for a GitOps pipeline (``--render DIR``: a private directory, one
  ``0600`` file per Secret).

It creates each missing Secret and never overwrites, prints or logs one (I7): output
names Secrets, keys and certificate fingerprints only. Secrets are labelled
``app.kubernetes.io/managed-by: fabric-cli`` and are never part of a Helm release.

In the release namespace: the cluster CA, the Node's server certificate, the client CA
(production), the content key (production), the injector's serving certificate and,
on a production Node, one ingress Secret per agent namespace (its bearer token and its
source id as the Node binds it). In each agent namespace: the agent Secret (CA
certificate, id key, spool key and, on a production Node, the ingest headers file and a
client certificate). The source id is the SDK's own ``s-`` pseudonym of the namespace's
source label under that namespace's id key, so the Node and the agents agree on it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .._sequence import encode_opaque_id, source_label
from . import _secrets
from ._report import EXIT_PREREQUISITE, EXIT_USAGE, CliError, Finding

MANAGED_BY = "fabric-cli"
RELEASE_LABEL = "fabric.singleaxis.ai/release"
#: The Secret roles whose names the chart can change (``--secret-name ROLE=NAME``).
SECRET_ROLES: dict[str, str] = {
    "ca": "fabric-ca",
    "node-tls": "fabric-node-receiver-tls",
    "client-ca": "fabric-node-client-ca",
    "content-key": "fabric-node-content-key",
    "injector-tls": "fabric-injector-tls",
    "agent": "fabric-agent",
}
#: Keys of the agent Secret. The injector mounts it at /var/run/fabric/secrets.
AGENT_KEYS_ALL = ("ca.crt", "id.key", "spool.key")
AGENT_KEYS_PRODUCTION = ("headers", "tls.crt", "tls.key")
SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
_NAMESPACE_RE = re.compile(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?")
_OBJECT_RE = re.compile(r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?")
_SOURCE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DOMAIN_RE = re.compile(r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?")
_TIMEOUT_S = 15.0


def _invalid(what: str) -> CliError:
    return CliError([Finding("FC-109", what)], EXIT_USAGE)


def check_namespace(name: str, what: str = "namespace") -> str:
    if len(name) > 63 or not _NAMESPACE_RE.fullmatch(name):  # noqa: PLR2004 - DNS label
        raise _invalid(f"{what} {name!r}")
    return name


def check_object(name: str, what: str) -> str:
    if len(name) > 253 or not _OBJECT_RE.fullmatch(name):  # noqa: PLR2004 - DNS subdomain
        raise _invalid(f"{what} {name!r}")
    return name


def ingress_secret_name(namespace: str) -> str:
    """The release-namespace Secret of an agent namespace's ingress group: its token and
    source id. Equal to the chart's ``fabric.agentNamespaces`` rule (a test keeps them
    equal): ``fabric-ingress-<ns>``, shortened with a digest past 40 characters."""
    if len(namespace) > 40:  # noqa: PLR2004 - the chart's rule
        short = namespace[:31].rstrip("-")
        return f"fabric-ingress-{short}-{hashlib.sha256(namespace.encode()).hexdigest()[:8]}"
    return f"fabric-ingress-{namespace}"


@dataclass(frozen=True)
class AgentNamespace:
    """A namespace whose agents send to the Node, and their clear source label."""

    name: str
    source: str

    @classmethod
    def parse(cls, text: str) -> AgentNamespace:
        name, _, source = text.partition("=")
        check_namespace(name.strip(), "agent namespace")
        source = source.strip() or name.strip()
        if not _SOURCE_RE.fullmatch(source):
            raise _invalid(f"source label {source!r}")
        return cls(name.strip(), source)


@dataclass(frozen=True)
class Plan:
    """What to generate, from the chart's values or the command line."""

    namespace: str
    release: str = "fabric"
    production: bool = False
    content: bool = False
    injector: bool = False
    agents: tuple[AgentNamespace, ...] = ()
    cluster_domain: str = "cluster.local"
    node_service: str = ""
    injector_service: str = ""
    names: Mapping[str, str] = field(default_factory=dict)

    def name(self, role: str) -> str:
        return self.names.get(role) or SECRET_ROLES[role]

    @property
    def node_host(self) -> str:
        return self.node_service or f"{self.release}-otel-collector"

    @property
    def injector_host(self) -> str:
        return self.injector_service or f"{self.release}-fabric-injector"

    def service_names(self, service: str) -> list[str]:
        ns = self.namespace
        return [
            service,
            f"{service}.{ns}",
            f"{service}.{ns}.svc",
            f"{service}.{ns}.svc.{self.cluster_domain}",
        ]

    def validate(self) -> Plan:
        check_namespace(self.namespace, "release namespace")
        check_namespace(self.release, "release name")
        for role, value in self.names.items():
            if role not in SECRET_ROLES:
                raise _invalid(
                    f"--secret-name role {role!r} (use one of: " + ", ".join(SECRET_ROLES) + ")"
                )
            check_object(value, f"Secret name for {role}")
        for value, what in (
            (self.node_service, "node service"),
            (self.injector_service, "injector service"),
        ):
            if value:
                check_namespace(value, what)
        if not _DOMAIN_RE.fullmatch(self.cluster_domain):
            raise _invalid(f"cluster domain {self.cluster_domain!r}")
        seen: set[str] = set()
        for agent in self.agents:
            if agent.name in seen:
                raise _invalid(f"agent namespace {agent.name!r} is listed twice")
            if agent.name == self.namespace:
                raise _invalid(f"agent namespace {agent.name!r} is the release namespace")
            seen.add(agent.name)
        return self


# ---------------------------------------------------------------- where Secrets go


class Exists(Exception):  # noqa: N818 - a state, not an error
    """The Secret was created by someone else between our read and our create."""


class Store(Protocol):
    """Somewhere Secrets live: the cluster, or rendered files."""

    where: str

    def get(self, namespace: str, name: str) -> dict[str, bytes] | None: ...

    def create(
        self,
        namespace: str,
        name: str,
        data: Mapping[str, bytes],
        labels: Mapping[str, str],
        object_type: str,
    ) -> None: ...


def manifest(
    namespace: str,
    name: str,
    data: Mapping[str, bytes],
    labels: Mapping[str, str],
    object_type: str = "Opaque",
) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": object_type,
        "metadata": {"name": name, "namespace": namespace, "labels": dict(labels)},
        "data": {key: base64.b64encode(value).decode("ascii") for key, value in data.items()},
    }


def _decode(data: Mapping[str, Any] | None) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for key, value in (data or {}).items():
        try:
            out[str(key)] = base64.b64decode(str(value), validate=True)
        except (binascii.Error, ValueError):
            continue
    return out


class KubectlStore:
    """The cluster of the current kube context, through ``kubectl``. A Secret's manifest
    goes to ``kubectl create -f -`` on standard input, never on a command line."""

    where = "the current kube context"

    def __init__(self, kubectl: str | None = None, runner: Callable[..., Any] = subprocess.run):
        found = kubectl or shutil.which("kubectl")
        if not found:
            raise CliError([Finding("FC-100")], EXIT_PREREQUISITE)
        self.kubectl = found
        self.runner = runner

    def _run(self, args: Sequence[str], stdin: str | None = None) -> Any:
        try:
            return self.runner(
                [self.kubectl, *args],
                input=stdin,
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_S * 2,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CliError([Finding("FC-103", type(exc).__name__)], EXIT_PREREQUISITE) from None

    @staticmethod
    def _failed(stderr: str, namespace: str) -> CliError:
        text = stderr or ""
        if "Forbidden" in text or "forbidden" in text:
            return CliError([Finding("FC-102", f"namespace {namespace}")], EXIT_PREREQUISITE)
        if re.search(r'namespaces? "[^"]*" not found', text):
            return CliError([Finding("FC-101", namespace)], EXIT_PREREQUISITE)
        # Connection refused, no context, a bad certificate: kubectl's own last line names it
        # (it never holds a Secret value: we only send manifests on standard input).
        last = text.strip().splitlines()[-1][:300] if text.strip() else "kubectl failed"
        return CliError([Finding("FC-103", last)], EXIT_PREREQUISITE)

    def get(self, namespace: str, name: str) -> dict[str, bytes] | None:
        result = self._run(
            ["get", "secret", name, "-n", namespace, "-o", "json", "--ignore-not-found"]
        )
        if result.returncode != 0:
            raise self._failed(result.stderr, namespace)
        if not result.stdout.strip():
            return None
        try:
            return _decode(json.loads(result.stdout).get("data"))
        except (ValueError, AttributeError):
            raise CliError(
                [Finding("FC-103", "kubectl returned no Secret")], EXIT_PREREQUISITE
            ) from None

    def create(
        self,
        namespace: str,
        name: str,
        data: Mapping[str, bytes],
        labels: Mapping[str, str],
        object_type: str,
    ) -> None:
        body = json.dumps(manifest(namespace, name, data, labels, object_type))
        result = self._run(["create", "-f", "-", "-o", "name"], stdin=body)
        if result.returncode != 0:
            if "AlreadyExists" in (result.stderr or "") or "already exists" in (
                result.stderr or ""
            ):
                raise Exists(name)
            raise self._failed(result.stderr, namespace)


class InClusterStore:
    """The cluster this process runs in (the chart's hook Job): the Kubernetes API with the
    pod's service account token and CA."""

    where = "this cluster"

    def __init__(
        self, environ: Mapping[str, str], sa_dir: Path = SA_DIR, client: Any = None
    ) -> None:
        host = (environ.get("KUBERNETES_SERVICE_HOST") or "").strip()
        port = (environ.get("KUBERNETES_SERVICE_PORT") or "443").strip()
        if client is None:
            if not host:
                raise CliError(
                    [
                        Finding(
                            "FC-103",
                            "KUBERNETES_SERVICE_HOST is not set: --in-cluster runs inside a pod",
                        )
                    ],
                    EXIT_PREREQUISITE,
                )
            try:
                import httpx  # noqa: PLC0415
            except ImportError:
                raise CliError([Finding("FC-005", "httpx is not installed")], EXIT_USAGE) from None
            token = (sa_dir / "token").read_text(encoding="utf-8").strip()
            address = f"[{host}]" if ":" in host else host
            client = httpx.Client(
                base_url=f"https://{address}:{port}",
                verify=str(sa_dir / "ca.crt"),
                headers={"Authorization": f"Bearer {token}"},
                timeout=_TIMEOUT_S,
                trust_env=False,
            )
        self.client = client

    def _request(self, method: str, path: str, namespace: str, **kwargs: Any) -> Any:
        try:
            response = self.client.request(method, path, **kwargs)
        except Exception as exc:  # httpx.HTTPError and the OS errors under it
            raise CliError([Finding("FC-103", type(exc).__name__)], EXIT_PREREQUISITE) from None
        if response.status_code == 403:  # noqa: PLR2004
            raise CliError([Finding("FC-102", f"namespace {namespace}")], EXIT_PREREQUISITE)
        return response

    def get(self, namespace: str, name: str) -> dict[str, bytes] | None:
        response = self._request("GET", f"/api/v1/namespaces/{namespace}/secrets/{name}", namespace)
        if response.status_code == 404:  # noqa: PLR2004 - the Secret (or namespace) is absent
            return None
        if response.status_code != 200:  # noqa: PLR2004
            raise CliError([Finding("FC-103", f"HTTP {response.status_code}")], EXIT_PREREQUISITE)
        return _decode(response.json().get("data"))

    def create(
        self,
        namespace: str,
        name: str,
        data: Mapping[str, bytes],
        labels: Mapping[str, str],
        object_type: str,
    ) -> None:
        response = self._request(
            "POST",
            f"/api/v1/namespaces/{namespace}/secrets",
            namespace,
            json=manifest(namespace, name, data, labels, object_type),
        )
        if response.status_code == 409:  # noqa: PLR2004
            raise Exists(name)
        if response.status_code == 404:  # noqa: PLR2004
            raise CliError([Finding("FC-101", namespace)], EXIT_PREREQUISITE)
        if response.status_code not in (200, 201, 202):
            raise CliError([Finding("FC-103", f"HTTP {response.status_code}")], EXIT_PREREQUISITE)

    def patch_webhook_ca(self, name: str, ca_pem: bytes) -> None:
        path = f"/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations/{name}"
        response = self._request("GET", path, "cluster")
        if response.status_code == 404:  # noqa: PLR2004
            raise CliError([Finding("FC-108", name)], EXIT_PREREQUISITE)
        if response.status_code != 200:  # noqa: PLR2004
            raise CliError([Finding("FC-103", f"HTTP {response.status_code}")], EXIT_PREREQUISITE)
        bundle = base64.b64encode(ca_pem).decode("ascii")
        webhooks = response.json().get("webhooks") or []
        patch = [
            {"op": "add", "path": f"/webhooks/{index}/clientConfig/caBundle", "value": bundle}
            for index in range(len(webhooks))
        ]
        if not patch:
            return
        response = self._request(
            "PATCH",
            path,
            "cluster",
            content=json.dumps(patch),
            headers={"Content-Type": "application/json-patch+json"},
        )
        if response.status_code != 200:  # noqa: PLR2004
            raise CliError([Finding("FC-103", f"HTTP {response.status_code}")], EXIT_PREREQUISITE)


class RenderStore:
    """Manifest files for a GitOps pipeline: ``DIR/<namespace>/secret-<name>.yaml``, each
    ``0600`` in a ``0700`` directory, created exclusively. A file already there is read
    back, so rendering again keeps every value."""

    def __init__(self, directory: Path) -> None:
        self.directory = _secrets.ensure_private_dir(directory)
        self.where = str(directory)
        self.written: list[Path] = []

    def _path(self, namespace: str, name: str) -> Path:
        return self.directory / namespace / f"secret-{name}.yaml"

    def get(self, namespace: str, name: str) -> dict[str, bytes] | None:
        path = self._path(namespace, name)
        if not _secrets.check_secret_file(path):
            return None
        try:
            document = json.loads(_secrets._read(path))
        except ValueError:
            raise _secrets._unsafe_file(path, "is not a manifest this command wrote") from None
        return _decode(document.get("data") if isinstance(document, dict) else None)

    def create(
        self,
        namespace: str,
        name: str,
        data: Mapping[str, bytes],
        labels: Mapping[str, str],
        object_type: str,
    ) -> None:
        path = self._path(namespace, name)
        _secrets.ensure_private_dir(path.parent)
        # JSON is YAML: `kubectl create -f` reads it, and it needs no YAML library here.
        body = json.dumps(manifest(namespace, name, data, labels, object_type), indent=2)
        try:
            _secrets.write_new(path, (body + "\n").encode("utf-8"))
        except FileExistsError:
            raise Exists(name) from None
        self.written.append(path)


# ---------------------------------------------------------------- the generator


@dataclass(frozen=True)
class Outcome:
    """One Secret as the CLI may show it: never a value."""

    namespace: str
    name: str
    action: str  # created, kept, incomplete
    keys: tuple[str, ...]
    fingerprint: str | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "namespace": self.namespace,
            "name": self.name,
            "action": self.action,
            "keys": list(self.keys),
        }
        if self.fingerprint:
            out["fingerprint"] = self.fingerprint
        return out


def _fingerprint(cert_pem: bytes) -> str | None:
    try:
        api = _secrets._crypto()
        der = api.x509.load_pem_x509_certificate(cert_pem).public_bytes(
            api.serialization.Encoding.DER
        )
    except (ValueError, CliError):
        return None
    return "sha256:" + hashlib.sha256(der).hexdigest()


class Generator:
    """Create every missing Secret of ``plan`` in ``store``; never overwrite one."""

    def __init__(self, plan: Plan, store: Store) -> None:
        self.plan = plan.validate()
        self.store = store
        self.outcomes: list[Outcome] = []
        self.findings: list[Finding] = []
        self.labels = {
            "app.kubernetes.io/managed-by": MANAGED_BY,
            "app.kubernetes.io/part-of": "fabric",
            RELEASE_LABEL: plan.release,
        }
        self._ca: tuple[bytes, bytes] | None = None

    # -- helpers

    def _ensure(
        self,
        namespace: str,
        name: str,
        needed: Sequence[str],
        make: Callable[[], dict[str, bytes]],
        object_type: str = "Opaque",
        fingerprint_key: str | None = None,
    ) -> dict[str, bytes]:
        """The Secret's data: the existing Secret (``kept``; a missing key is reported, never
        added), or a new one from ``make`` (``created``)."""
        existing = self.store.get(namespace, name)
        action = "kept"
        if existing is None:
            data = make()
            try:
                self.store.create(namespace, name, data, self.labels, object_type)
                action = "created"
            except Exists:  # created concurrently (another Job attempt): use that one
                existing = self.store.get(namespace, name) or {}
        if existing is not None:
            data = existing
            missing = [key for key in needed if key not in data]
            if missing:
                action = "incomplete"
                self.findings.append(
                    Finding("FC-104", f"{namespace}/{name} lacks " + ", ".join(missing))
                )
        cert = data.get(fingerprint_key) if fingerprint_key else None
        self.outcomes.append(
            Outcome(
                namespace, name, action, tuple(sorted(data)), _fingerprint(cert) if cert else None
            )
        )
        return data

    def _ca_pair(self) -> tuple[bytes, bytes]:
        if self._ca is None:
            api = _secrets._crypto()
            name = self.plan.name("ca")

            def make() -> dict[str, bytes]:
                cert, key = _secrets._new_ca(api, f"{self.plan.release}, {self.plan.namespace}")
                return {"ca.crt": cert, "ca.key": key}

            data = self._ensure(
                self.plan.namespace, name, ("ca.crt", "ca.key"), make, fingerprint_key="ca.crt"
            )
            if "ca.crt" not in data or "ca.key" not in data:
                # Nothing can be issued without the CA's key: stop with the finding.
                raise CliError(list(self.findings), EXIT_USAGE)
            self._ca = (data["ca.crt"], data["ca.key"])
        return self._ca

    def _leaf(
        self, names: Sequence[str], *, common_name: str, client: bool = False
    ) -> tuple[bytes, bytes]:
        ca_cert, ca_key = self._ca_pair()
        try:
            return _secrets._new_leaf(
                _secrets._crypto(),
                ca_cert,
                ca_key,
                names,
                (),
                common_name=common_name,
                client=client,
            )
        except (ValueError, TypeError):
            ca = f"{self.plan.namespace}/{self.plan.name('ca')}"
            raise CliError(
                [Finding("FC-104", f"{ca} holds no usable CA certificate and key")], EXIT_USAGE
            ) from None

    # -- the Secrets

    def run(self, *, node_tls: bool = True) -> list[Outcome]:
        plan = self.plan
        ca_cert, _ = self._ca_pair()
        if node_tls:

            def node() -> dict[str, bytes]:
                cert, key = self._leaf(
                    plan.service_names(plan.node_host), common_name=plan.node_host
                )
                return {"tls.crt": cert, "tls.key": key, "ca.crt": ca_cert}

            self._ensure(
                plan.namespace,
                plan.name("node-tls"),
                ("tls.crt", "tls.key"),
                node,
                "kubernetes.io/tls",
                "tls.crt",
            )
        if plan.production:
            self._ensure(
                plan.namespace,
                plan.name("client-ca"),
                ("ca.crt",),
                lambda: {"ca.crt": ca_cert},
                fingerprint_key="ca.crt",
            )
        if plan.production and plan.content:
            self._ensure(
                plan.namespace,
                plan.name("content-key"),
                ("key",),
                lambda: {"key": base64.b64encode(secrets.token_bytes(32))},
            )
        if plan.injector:

            def injector() -> dict[str, bytes]:
                cert, key = self._leaf(
                    plan.service_names(plan.injector_host), common_name=plan.injector_host
                )
                return {"tls.crt": cert, "tls.key": key, "ca.crt": ca_cert}

            self._ensure(
                plan.namespace,
                plan.name("injector-tls"),
                ("tls.crt", "tls.key"),
                injector,
                "kubernetes.io/tls",
                "tls.crt",
            )
        for agent in plan.agents:
            self._agent(agent, ca_cert)
        return self.outcomes

    def _agent(self, agent: AgentNamespace, ca_cert: bytes) -> None:
        plan = self.plan
        ingress_name = ingress_secret_name(agent.name)
        ingress = self.store.get(plan.namespace, ingress_name) if plan.production else None
        existing = self.store.get(agent.name, plan.name("agent"))
        if existing is None and ingress is not None:
            self.findings.append(
                Finding("FC-105", f"{plan.namespace}/{ingress_name} (agent namespace {agent.name})")
            )
            self.outcomes.append(
                Outcome(plan.namespace, ingress_name, "incomplete", tuple(sorted(ingress)))
            )
            return
        token = secrets.token_hex(32)

        def make() -> dict[str, bytes]:
            data = {
                "ca.crt": ca_cert,
                "id.key": _secrets._new_id_key(),
                "spool.key": base64.b64encode(secrets.token_bytes(32)),
            }
            if plan.production:
                cert, key = self._leaf((), common_name=agent.source, client=True)
                data.update(
                    {
                        "headers": f"Authorization=Bearer%20{token}".encode("ascii"),
                        "tls.crt": cert,
                        "tls.key": key,
                    }
                )
            return data

        needed = AGENT_KEYS_ALL + (AGENT_KEYS_PRODUCTION if plan.production else ())
        data = self._ensure(
            agent.name,
            plan.name("agent"),
            needed,
            make,
            fingerprint_key="tls.crt" if plan.production else None,
        )
        if not plan.production or ingress is not None:
            if ingress is not None:
                self.outcomes.append(
                    Outcome(plan.namespace, ingress_name, "kept", tuple(sorted(ingress)))
                )
            return
        agent_token = _token_from_headers(data.get("headers"))
        id_key = data.get("id.key")
        if agent_token is None or not id_key:
            # FC-104 already names the agent Secret's missing keys.
            return
        node_side = {
            "token": agent_token.encode("ascii"),
            "source-id": source_id(agent.source, id_key).encode("ascii"),
        }
        self._ensure(plan.namespace, ingress_name, ("token", "source-id"), lambda: node_side)

    def patch_webhook(self, name: str) -> None:
        """Set the injector webhook's caBundle from the CA Secret. Reads only: a missing CA
        is reported, never generated here (the pre-install Job generates it)."""
        patch = getattr(self.store, "patch_webhook_ca", None)
        if patch is None:
            raise CliError([Finding("FC-106", "--webhook needs --in-cluster")], EXIT_USAGE)
        ca = self.store.get(self.plan.namespace, self.plan.name("ca")) or {}
        if "ca.crt" not in ca:
            raise CliError(
                [Finding("FC-104", f"{self.plan.namespace}/{self.plan.name('ca')} lacks ca.crt")],
                EXIT_USAGE,
            )
        patch(name, ca["ca.crt"])


def _token_from_headers(raw: bytes | None) -> str | None:
    if not raw:
        return None
    match = re.fullmatch(rb"Authorization=Bearer%20([0-9a-f]{16,256})\n?", raw)
    return match.group(1).decode("ascii") if match else None


def source_id(source: str, id_key: bytes) -> str:
    """The source id the Node binds an agent namespace to: what the SDK emits for
    ``FABRIC_SOURCE_ID=source`` with ``FABRIC_WIRE_ID_KEY_FILE`` holding ``id_key`` (the
    file's bytes, one trailing newline dropped, as the SDK reads it)."""
    key = id_key[:-1] if id_key.endswith(b"\n") else id_key
    return source_label(encode_opaque_id(source), key)


def from_options(options: Any, environ: Mapping[str, str]) -> tuple[Plan, Store]:
    """The plan and store ``fabric init --kubernetes`` options name."""
    names: dict[str, str] = {}
    for item in options.secret_name or ():
        role, _, value = item.partition("=")
        names[role.strip()] = value.strip()
    plan = Plan(
        namespace=(options.namespace or "fabric-system").strip(),
        release=(options.release or "fabric").strip(),
        production=options.profile == "production",
        content=bool(options.content),
        injector=bool(options.injector),
        agents=tuple(AgentNamespace.parse(text) for text in options.agent_namespace or ()),
        cluster_domain=(options.cluster_domain or "cluster.local").strip(),
        node_service=(options.node_service or "").strip(),
        injector_service=(options.injector_service or "").strip(),
        names=names,
    ).validate()
    store: Store
    if options.render:
        store = RenderStore(Path(options.render).expanduser().resolve())
    elif options.in_cluster:
        store = InClusterStore(environ)
    else:
        store = KubectlStore()
    return plan, store


__all__ = [
    "AgentNamespace",
    "Exists",
    "Generator",
    "InClusterStore",
    "KubectlStore",
    "Outcome",
    "Plan",
    "RenderStore",
    "Store",
    "from_options",
    "ingress_secret_name",
    "manifest",
    "source_id",
]
