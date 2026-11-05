# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""AR-1 production (spec 056 §6.2 "AR-1 production", §7.3.3 (m)): the pieces a
production-profile Node needs, shared by the hermetic replay and the live run.

- :class:`Material`: a test CA and the Node's server certificate (127.0.0.1, ::1 and
  localhost), one bearer token per group (all bytes differ), the id key file the agents
  and the sensors share, a state key per host source, the Node's content key and the
  agent's spool key. Every secret is fresh per harness run and lives under ``secrets/``.
- :func:`node_config`: the static dedicated ingress groups of
  ``contracts/capture/v1/fixtures/ingress-groups/valid/agent-ebpf-auditd.yaml`` without the
  auditd group, plus a second ``host.ebpf`` group (the quiet node): ``agent`` (OTLP gRPC
  and HTTP, and its content listener into a ``fabriccontent`` file store sealed with the
  content key), ``ebpf`` and ``quiet`` (``host.ebpf``). Every listener is TLS on loopback;
  delivery is verified HTTPS to the authenticated test sink. The Node starts through
  ``fabric-gate``, which applies every group rule first.
- :func:`agent_source_id`, :func:`host_source_id`: the ``s-`` ids the groups bind (what
  the agent emits for ``FABRIC_SOURCE_ID``; what ``fabric-host-emitter print-source-id``
  prints for a source label).
- :func:`production_env`: the agent's production environment (node mode: telemetry and
  content to the agent group over verified TLS with its token; an encrypted spool; a
  production capture policy; the remote sandbox hook) on top of
  :func:`scenario.agent_env`.
- :class:`FixtureDocker`: the ``docker`` the replay's agent finds first on ``PATH``:
  ``run -d`` prints the 64-hex id the harness chose, ``run`` without ``-d`` prints what
  the two commands would (variant g). It reads the id from the agent's environment, so
  no file holds it.

The live run (Compose, slices, the emitter) is :mod:`ar1.live`.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import os
import secrets
import subprocess
import time
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import scenario
from .node import free_port

AGENT_SOURCE_LABEL = "ar1-agent"
EBPF_SOURCE_LABEL = f"{scenario.HOST_LABEL}/ebpf"
QUIET_HOST_LABEL = "ar1-quiet-node"
QUIET_SOURCE_LABEL = f"{QUIET_HOST_LABEL}/ebpf"
SENSOR_VERSION = "0.0.0-ar1"
# A pinned-looking digest: the production capture policy needs one; it pins nothing here.
POLICY_IMAGE_DIGEST = "sha256:" + hashlib.sha256(b"ar1-production-agent").hexdigest()
REMOTE_ROLES = ("remote.request", "remote.result", "remote.stream")
GROUPS = ("agent", "ebpf", "quiet")


def _write(path: Path, data: bytes, mode: int = 0o400) -> Path:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(data)
    path.chmod(mode)
    return path


def _certificate(name: str, key: ec.EllipticCurvePrivateKey, issuer: x509.Name,
                 signer: ec.EllipticCurvePrivateKey, *, ca: bool,
                 hosts: tuple[str, ...] = ()) -> x509.Certificate:  # fmt: skip
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        # Python 3.13+ verifies strictly (VERIFY_X509_STRICT): key identifiers and usage.
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if not ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    if hosts:
        names: list[x509.GeneralName] = []
        for host in hosts:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(host)))
            except ValueError:
                names.append(x509.DNSName(host))
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(signer, hashes.SHA256())


@dataclass(frozen=True)
class Material:
    """The run's TLS material, tokens and keys (files under ``directory``)."""

    directory: Path
    ca: Path
    server_cert: Path
    server_key: Path
    tokens: Mapping[str, Path]  # group (and "sink") -> token file
    id_key: Path
    state_keys: Mapping[str, Path]  # host group -> state key file
    content_key: Path
    spool_key: Path

    @classmethod
    def create(cls, directory: Path, hosts: tuple[str, ...] = ()) -> Material:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AR-1 test CA")])
        ca = _certificate("AR-1 test CA", ca_key, ca_name, ca_key, ca=True)
        key = ec.generate_private_key(ec.SECP256R1())
        names = ("127.0.0.1", "::1", "localhost", *hosts)
        cert = _certificate("ar1-node", key, ca_name, ca_key, ca=False, hosts=names)
        pem = serialization.Encoding.PEM
        tokens = {
            name: _write(
                directory / f"{name}.token", f"ar1-{name}-{secrets.token_hex(24)}".encode()
            )
            for name in (*GROUPS, "sink")
        }
        return cls(
            directory=directory,
            ca=_write(directory / "ca.crt", ca.public_bytes(pem), 0o444),
            server_cert=_write(directory / "server.crt", cert.public_bytes(pem), 0o444),
            server_key=_write(
                directory / "server.key",
                key.private_bytes(
                    pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                ),
                0o400,
            ),
            tokens=tokens,
            id_key=_write(directory / "id.key", scenario.ID_KEY.encode()),
            state_keys={
                name: _write(directory / f"{name}.state.key", os.urandom(32)) for name in GROUPS[1:]
            },
            content_key=_write(directory / "content.key", os.urandom(32)),
            spool_key=_write(directory / "spool.key", os.urandom(32)),
        )

    def token(self, group: str) -> str:
        return self.tokens[group].read_text()


def agent_source_id() -> str:
    """The ``s-`` id the agent emits for ``FABRIC_SOURCE_ID=ar1-agent`` under the id key."""
    from fabric._sequence import encode_opaque_id, source_label  # noqa: PLC0415

    return source_label(encode_opaque_id(AGENT_SOURCE_LABEL), scenario.ID_KEY.encode())


def host_source_id(label: str) -> str:
    """``s-`` + the label pseudonym of a sensor's source label (``print-source-id``)."""
    from fabric._sequence import label_pseudonym  # noqa: PLC0415

    return str(label_pseudonym("s-", label, scenario.ID_KEY.encode()))


@dataclass
class Ports:
    agent_grpc: int
    agent_http: int
    content: int
    ebpf_grpc: int
    ebpf_http: int
    quiet_http: int
    health: int

    @classmethod
    def free(cls) -> Ports:
        return cls(*(free_port() for _ in range(7)))


def _tls(material: Material) -> dict[str, Any]:
    return {
        "cert_file": str(material.server_cert),
        "key_file": str(material.server_key),
        "min_version": "1.3",
    }


def _grpc(port: int, group: str, material: Material, host: str) -> dict[str, Any]:
    return {
        "endpoint": f"{host}:{port}",
        "auth": {"authenticator": f"bearertokenauth/{group}"},
        "max_recv_msg_size_mib": 8,
        "max_concurrent_streams": 64,
        "keepalive": {"enforcement_policy": {"min_time": "10s", "permit_without_stream": False}},
        "tls": _tls(material),
    }


def _http(port: int, group: str, material: Material, host: str, *, content: bool = False
          ) -> dict[str, Any]:  # fmt: skip
    return {
        "endpoint": f"{host}:{port}",
        "auth": {"authenticator": f"bearertokenauth/{group}"},
        "read_header_timeout": "5s",
        "read_timeout": "120s" if content else "30s",
        "idle_timeout": "120s",
        "max_request_body_size": 67108864 if content else 8388608,
        "tls": _tls(material),
    }


def _guard(source_id: str, kind: str) -> dict[str, Any]:
    guard: dict[str, Any] = {
        "event_class_attribute": "event_class",
        "drop_unknown_classes": True,
        "max_field_bytes": 8192,
        "capture_labels": "pseudonymous",
        "identity_mode": "pseudonymous",
        "profile": "production",
        "source_kind": kind,
        "evidence_source_binding": {"tenant_id": scenario.TENANT, "source_id": source_id},
    }
    if kind != "agent":
        guard["host_digests"] = "omitted"
    return guard


def node_config(
    material: Material,
    ports: Ports,
    sink_url: str,
    directory: Path,
    *,
    sources: Mapping[str, str],
    host: str = "127.0.0.1",
) -> dict[str, Any]:
    """The Node's static ingress groups (see the module docstring); ``sources`` maps each
    group to the ``s-`` id it binds."""
    state = directory / "node-state"
    content_root = directory / "node-content"
    content_root.mkdir(parents=True, exist_ok=True)
    queue = {
        "enabled": True,
        "num_consumers": 4,
        "queue_size": 10000,
        "block_on_overflow": True,
        "storage": "file_storage/fabric",
    }
    retry = {"enabled": True, "initial_interval": "1s", "max_interval": "5s",
             "max_elapsed_time": "0s"}  # fmt: skip
    extensions: dict[str, Any] = {
        "health_check": {"endpoint": f"127.0.0.1:{ports.health}"},
        "noredirect": {},
        "file_storage/fabric": {
            "directory": str(state / "queue"),
            "create_directory": True,
            "fsync": True,
            "timeout": "1s",
        },
        "file_storage/fabric_content_agent": {
            "directory": str(state / "content-queue-agent"),
            "create_directory": True,
            "directory_permissions": "0700",
            "fsync": True,
            "timeout": "1s",
        },
        "fabricenvelope/fabric_content_agent": {
            "key_file": str(material.content_key),
            "storage": "file_storage/fabric_content_agent",
        },
    }
    for group in GROUPS:
        extensions[f"bearertokenauth/{group}"] = {
            "filename": str(material.tokens[group]),
            "require_single_token": True,
        }
    receivers = {
        "otlp/agent": {
            "protocols": {
                "grpc": _grpc(ports.agent_grpc, "agent", material, host),
                "http": _http(ports.agent_http, "agent", material, host),
            }
        },
        "otlp/content-agent": {
            "protocols": {"http": _http(ports.content, "agent", material, host, content=True)}
        },
        "otlp/ebpf": {
            "protocols": {
                "grpc": _grpc(ports.ebpf_grpc, "ebpf", material, host),
                "http": _http(ports.ebpf_http, "ebpf", material, host),
            }
        },
        "otlp/quiet": {"protocols": {"http": _http(ports.quiet_http, "quiet", material, host)}},
    }
    processors: dict[str, Any] = {
        "memory_limiter": {"check_interval": "1s", "limit_mib": 512},
        "fabricguard/agent": _guard(sources["agent"], "agent"),
        "fabricguard/ebpf": _guard(sources["ebpf"], "host.ebpf"),
        "fabricguard/quiet": _guard(sources["quiet"], "host.ebpf"),
    }
    exporters = {
        "otlp_http/fabric": {
            "endpoint": sink_url,
            "headers": {"Authorization": f"Bearer {material.token('sink')}"},
            "timeout": "10s",
            "middlewares": [{"id": "noredirect"}],
            "tls": {"insecure": False, "insecure_skip_verify": False, "ca_file": str(material.ca)},
            "sending_queue": queue,
            "retry_on_failure": retry,
        },
        "fabriccontent/agent": {
            "allowed_tenants": [scenario.TENANT],
            "backend": "file",
            "file": {
                "directory": str(content_root),
                "encryption_key_file": str(material.content_key),
            },
            "profile": "production",
            "queue_directory": str(state / "content-queue-agent"),
            "retry_on_failure": retry,
            "sending_queue": {
                "block_on_overflow": True,
                "enabled": True,
                "num_consumers": 4,
                "queue_size": 64,
                "storage": "fabricenvelope/fabric_content_agent",
            },
            "source_binding": {"tenant_id": scenario.TENANT, "source_id": sources["agent"]},
            "timeout": "60s",
        },
    }
    guarded = ["memory_limiter"]
    pipelines = {
        "traces/agent": {"receivers": ["otlp/agent"], "processors": [*guarded, "fabricguard/agent"],
                         "exporters": ["otlp_http/fabric"]},
        "logs/agent": {"receivers": ["otlp/agent"], "processors": [*guarded, "fabricguard/agent"],
                       "exporters": ["otlp_http/fabric"]},
        "logs/content-agent": {"receivers": ["otlp/content-agent"], "processors": guarded,
                               "exporters": ["fabriccontent/agent"]},
        "traces/ebpf": {"receivers": ["otlp/ebpf"], "processors": [*guarded, "fabricguard/ebpf"],
                        "exporters": ["otlp_http/fabric"]},
        "traces/quiet": {"receivers": ["otlp/quiet"],
                         "processors": [*guarded, "fabricguard/quiet"],
                         "exporters": ["otlp_http/fabric"]},
    }  # fmt: skip
    return {
        "extensions": extensions,
        "receivers": receivers,
        "processors": processors,
        "exporters": exporters,
        "service": {
            "extensions": [
                "health_check",
                "noredirect",
                "file_storage/fabric",
                "file_storage/fabric_content_agent",
                "fabricenvelope/fabric_content_agent",
                *(f"bearertokenauth/{g}" for g in GROUPS),
            ],
            "pipelines": pipelines,
            "telemetry": {"logs": {"level": "info"}, "metrics": {"level": "none"}},
        },
    }


class GroupNode:
    """The production-profile Node as a native process (``fabric-gate`` from ``dist``)."""

    def __init__(
        self,
        dist: Path,
        directory: Path,
        material: Material,
        sink_url: str,
        sources: Mapping[str, str],
    ) -> None:
        self.dist, self.directory, self.material = dist, directory, material
        self.ports = Ports.free()
        self.config_path = directory / "node-config.json"
        self.log_path = directory / "node.log"
        self.content_root = directory / "node-content"
        self.config_path.write_text(
            json.dumps(
                node_config(material, self.ports, sink_url, directory, sources=sources),
                indent=2,
            )
        )
        self.process: subprocess.Popen[bytes] | None = None

    def url(self, group: str, *, path: str = "") -> str:
        port = {
            "agent": self.ports.agent_http,
            "content": self.ports.content,
            "ebpf": self.ports.ebpf_http,
            "quiet": self.ports.quiet_http,
        }[group]
        return f"https://127.0.0.1:{port}{path}"

    def start(self, timeout_s: float = 60.0) -> GroupNode:
        log = self.log_path.open("ab")
        self.process = subprocess.Popen(  # noqa: S603 - the repository's own Node build
            [str(self.dist / "fabric-gate"), "--config", str(self.config_path)],
            stdout=log,
            stderr=subprocess.STDOUT,
            cwd=self.directory,
        )
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                tail = self.log_path.read_text(errors="replace")[-1500:]
                raise RuntimeError(f"the Node exited ({self.process.returncode}): {tail}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.ports.health}/", timeout=1):
                    return self
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("the Node did not become healthy; see node.log")

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=30)
        self.process = None


def write_production_policy(path: Path, *, metadata_only_output: bool = False) -> Path:
    """A production deployment-policy/v1 with every AR-1 role (the remote sandbox's too)
    as ``retain_original``, or the subprocess output as ``metadata_only`` (variant d)."""
    scenario.write_policy(path, metadata_only_output=metadata_only_output)
    policy = json.loads(path.read_text())
    policy["policy_id"] += "-production"
    for role in REMOTE_ROLES:
        policy["privacy"][role] = "retain_original"
    policy["deployment"] = {
        "profile": "production",
        "image_digest": POLICY_IMAGE_DIGEST,
        "tls_required": True,
        "encrypted_store_required": True,
    }
    path.write_text(json.dumps(policy, indent=2))
    return path


@dataclass(frozen=True)
class Delivery:
    """Where the agent delivers: its OTLP/HTTP endpoint and token (the agent group's, or,
    in variant h, a host group's), the content endpoint and the CA."""

    otlp_endpoint: str
    content_endpoint: str
    token: str
    ca: Path


def production_env(
    config: scenario.AgentConfig,
    *,
    delivery: Delivery | None,
    material: Material | None,
    e2b_env: Mapping[str, str],
    remote_secret: str,
    remote_sandbox: bool = True,
    sandbox_host: str = "",
    detach: bool = True,
    extra: Mapping[str, str] | None = None,
    shutdown_s: float | None = None,
) -> dict[str, str]:
    """The agent's environment for AR-1 production (see the module docstring)."""
    env = scenario.agent_env(config)
    env.update(e2b_env)
    env.update(
        {
            "AR1_PROFILE": "production",
            "AR1_REMOTE_SECRET": remote_secret,
            "AR1_CONTAINER_DETACH": "1" if detach else "0",
        }
    )
    env.update(extra or {})
    if not config.capture or delivery is None or material is None:
        return env
    env.pop("FABRIC_WIRE_STORE", None)
    env.update(
        {
            "FABRIC_WIRE_CONTENT_ENDPOINT": delivery.content_endpoint,
            "FABRIC_WIRE_SPOOL_DIR": str(config.workdir / "spool"),
            "FABRIC_WIRE_SPOOL_KEY_FILE": str(material.spool_key),
            "OTEL_EXPORTER_OTLP_ENDPOINT": delivery.otlp_endpoint,
            "OTEL_EXPORTER_OTLP_CERTIFICATE": str(delivery.ca),
            "OTEL_EXPORTER_OTLP_HEADERS": "Authorization=" + quote(f"Bearer {delivery.token}"),
        }
    )
    if remote_sandbox:
        env["FABRIC_WIRE_REMOTE_SANDBOX"] = "e2b"
    if sandbox_host:
        env["FABRIC_WIRE_SANDBOX_HOSTS"] = json.dumps([sandbox_host])
    if shutdown_s is not None:
        env["FABRIC_WIRE_SHUTDOWN_TIMEOUT_S"] = str(shutdown_s)
    return env


FIXTURE_DOCKER = """#!/bin/sh
# AR-1 production replay: the fixture docker (spec 056 §6.2). `run -d` prints the id of
# the container it would have created (AR1_FIXTURE_CONTAINER_ID, from the harness);
# `run` without -d prints what the container's two commands would.
detach=0
for arg in "$@"; do [ "$arg" = "-d" ] && detach=1; done
if [ "$1" = run ] && [ "$detach" = 1 ]; then
  printf '%s\\n' "$AR1_FIXTURE_CONTAINER_ID"
  exit 0
fi
if [ "$1" = run ]; then
  printf 'ar1 container step one\\nar1 container step two\\n'
  exit 0
fi
echo "fixture docker: only 'run' is scripted" >&2
exit 2
"""


class FixtureDocker:
    """``bin/docker`` (the script above) under ``directory``; :meth:`env` puts it first on
    ``PATH`` and hands it the container id."""

    def __init__(self, directory: Path) -> None:
        self.bin = directory / "fixture-bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        script = self.bin / "docker"
        script.write_text(FIXTURE_DOCKER)
        script.chmod(0o755)

    def env(self, base: Mapping[str, str], container_id: str) -> dict[str, str]:
        return {
            "PATH": f"{self.bin}{os.pathsep}{base.get('PATH', os.defpath)}",
            "AR1_FIXTURE_CONTAINER_ID": container_id,
        }
