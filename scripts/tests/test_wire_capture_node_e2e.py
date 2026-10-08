# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""LLM wire capture through a real, production-shaped Fabric Node (spec 042).

This drives the whole recorder path with real processes and real sockets:

    plain-httpx ReAct agent (zero-code autoload, no Fabric import)
        -> fake OpenAI-compatible model (http.server, real TCP)
        -> wire tee: exact bytes -> local file:// store (customer boundary)
        -> private TracerProvider -> OTLP/HTTP over TLS + bearer token
    Fabric Node (the custom Collector image, fabric-gate entrypoint,
    collector-production.yaml with its documented TLS stanzas enabled,
    memory_limiter + fabricguard, persistent file_storage queue)
        -> OTLP/HTTP over TLS (private CA) + egress Authorization
    fsync sink -> decoded JSONL -> ``python -m fabric.reconstruct``

and proves, against the running stack:

- every model call (non-streamed, streamed SSE, tool-call round trip)
  arrives as a ``fabric.model_call`` span, with heartbeats;
- capture spans carry only the spec 042 §8 keys, and their digests/refs
  agree with the store;
- no prompt, completion, tool argument/result, model API key or bearer
  token appears in the sink output, the raw delivered bytes, the Node logs
  or the Node's queue volume (while the store does hold the content);
- the run reconstructs ``complete_for_declared_scope`` with zero gaps;
- spans accepted while the destination is down survive a Node restart in
  the persistent queue and arrive afterwards, still reconstructing cleanly;
- a wrong ingress token is rejected and the agent is unaffected.

Opt-in by environment: the module skips when Docker Compose is unavailable.
``FABRIC_NODE_IMAGE`` reuses a prebuilt Node image instead of building one.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = REPO_ROOT / "deploy" / "compose"
PRODUCTION_CONFIG = COMPOSE_DIR / "collector-config" / "collector-production.yaml"
NODE_CONTEXT = REPO_ROOT / "components" / "otel-collector-fabric"
AGENT = Path(__file__).with_name("_wire_capture_agent.py")
SINK = Path(__file__).with_name("_wire_capture_sink.py")
TENANT = "wire-e2e-tenant"

# Unique per session: content and credentials that must never leave the
# agent process except as bytes in the customer's own store.
MARK = f"WIREE2E{uuid.uuid4().hex[:12]}"
PROMPT = f"{MARK}_prompt What is the temperature in Paris in Fahrenheit?"
CITY = f"{MARK}_city"
TOOL_RESULT = f"{MARK}_toolresult"
COMPLETION = f"{MARK}_completion"
API_KEY = f"sk-{MARK}_apikey"
INGRESS_TOKEN = f"{MARK}_ingress_token"
WRONG_TOKEN = f"{MARK}_wrong_token"
EGRESS_AUTH = f"Bearer {MARK}_egress_token"
CONTENT_MARKERS = [f"{MARK}_prompt", CITY, TOOL_RESULT, COMPLETION]
SECRET_MARKERS = [API_KEY, INGRESS_TOKEN, WRONG_TOKEN, f"{MARK}_egress_token"]

# Spec 042 §8: the fourteen new capture keys plus the reused, already
# allowlisted keys a capture span may carry. Anything else is a leak channel.
CAPTURE_KEYS = frozenset(
    {
        "fabric.source.epoch", "fabric.run.id", "fabric.wire.exchange_id", "fabric.wire.api",
        "fabric.wire.request_sha256", "fabric.wire.response_sha256",
        "fabric.wire.response_state", "fabric.wire.truncated", "fabric.wire.store_status",
        "fabric.loss.reason", "fabric.loss.count", "fabric.loss.first_sequence",
        "fabric.loss.last_sequence", "fabric.heartbeat.last_sequence",
    }
)  # fmt: skip
REUSED_KEYS = frozenset(
    {
        "fabric.source_id", "fabric.source.sequence", "fabric.content.request_ref",
        "fabric.content.result_ref", "gen_ai.operation.name", "gen_ai.provider.name",
        "http.request.method", "http.response.status_code", "error.type",
        "gen_ai.response.model", "gen_ai.response.id", "gen_ai.response.finish_reasons",
        "gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens",
    }
)  # fmt: skip
assert len(CAPTURE_KEYS) == 14
EXCHANGE_REQUIRED = frozenset(
    {
        "fabric.wire.exchange_id", "fabric.run.id", "fabric.source_id",
        "fabric.source.sequence", "fabric.source.epoch", "fabric.wire.api",
        "fabric.wire.request_sha256", "fabric.wire.response_sha256",
        "fabric.wire.response_state", "fabric.wire.truncated", "fabric.wire.store_status",
        "fabric.content.request_ref", "fabric.content.result_ref", "gen_ai.operation.name",
        "gen_ai.provider.name", "http.request.method", "http.response.status_code",
    }
)  # fmt: skip
# Extracted only from a complete, plain-JSON response (spec 042 §5): never
# from the streamed call.
EXCHANGE_METADATA = frozenset(
    {
        "gen_ai.response.model", "gen_ai.response.id", "gen_ai.response.finish_reasons",
        "gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens",
    }
)  # fmt: skip
CAPTURE_SPAN_NAMES = {
    "fabric.model_call",
    "fabric.capture_heartbeat",
    "fabric.capture_loss",
}
SPAN_KIND_CLIENT = 3


def _compose_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        for args in (
            ["docker", "compose", "version"],
            ["docker", "info", "--format", "x"],
        ):
            subprocess.run(args, check=True, capture_output=True, timeout=30)
    except (subprocess.SubprocessError, OSError):
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _compose_available(), reason="docker compose unavailable — env-dependent gate"
)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


# --------------------------------------------------------------------------
# Throwaway TLS material: one private CA, one leaf for the Node and the sink
# --------------------------------------------------------------------------


def _write_tls(directory: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fabric-wire-e2e-ca")])
    usage = dict.fromkeys(
        ("content_commitment", "key_encipherment", "data_encipherment", "key_agreement",
         "encipher_only", "decipher_only"), False,
    )  # fmt: skip
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True, **usage
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    names = [
        x509.DNSName("localhost"),
        x509.DNSName("host.docker.internal"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ]
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fabric-wire-e2e")])
        )
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False, **usage
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    directory.mkdir(parents=True)
    pem = serialization.Encoding.PEM
    (directory / "ca.crt").write_bytes(ca.public_bytes(pem))
    (directory / "server.crt").write_bytes(leaf.public_bytes(pem))
    (directory / "server.key").write_bytes(
        leaf_key.private_bytes(
            pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    # Throwaway material read by the image's nonroot user through a bind
    # mount; a real deployment provisions the key with matching ownership.
    for path in directory.iterdir():
        path.chmod(0o644)


def _production_config_with_tls(target: Path) -> None:
    """collector-production.yaml with exactly its documented TLS edits applied.

    The file says: uncomment the receiver ``tls:`` stanzas before publishing
    beyond loopback, and the exporter ``ca_file`` line for a private-CA
    destination. Nothing else changes, so drift in the shipped file shows up
    here instead of being masked by a hand-written test config.
    """
    text = PRODUCTION_CONFIG.read_text("utf-8")
    text, stanzas = re.subn(r"(?m)^(\s*)# tls:$", r"\1tls:", text)
    text, fields = re.subn(
        r"(?m)^(\s*)#   (cert_file|key_file|min_version):", r"\1  \2:", text
    )
    text, ca = re.subn(r"(?m)^(\s*)# (ca_file:)", r"\1\2", text)
    assert (stanzas, fields, ca) == (2, 6, 1), (
        "collector-production.yaml TLS stanzas moved"
    )
    target.write_text(text, "utf-8")


# --------------------------------------------------------------------------
# Fake OpenAI-compatible model on a real socket
# --------------------------------------------------------------------------


class _Model:
    def __init__(self) -> None:
        self.requests = 0
        self.unauthorized = 0
        self._lock = threading.Lock()
        model = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                with model._lock:
                    model.requests += 1
                    call = model.requests
                if self.path != "/v1/chat/completions":
                    self.send_error(404)
                    return
                if self.headers.get("Authorization") != f"Bearer {API_KEY}":
                    model.unauthorized += 1  # the tee must forward headers untouched
                    self.send_error(401)
                    return
                payload = json.loads(body)
                tool_results = [
                    m for m in payload["messages"] if m.get("role") == "tool"
                ]
                if len(tool_results) == 1:
                    assert payload.get("stream") is True
                    celsius = json.loads(tool_results[0]["content"])["celsius"]
                    self._stream(call, celsius)
                    return
                if not tool_results:
                    message: dict[str, Any] = {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": f"call_weather_{call}", "type": "function",
                            "function": {"name": "get_weather",
                                         "arguments": json.dumps({"city": CITY})},
                        }],
                    }  # fmt: skip
                    finish = "tool_calls"
                else:
                    fahrenheit = json.loads(tool_results[-1]["content"])["fahrenheit"]
                    message = {
                        "role": "assistant",
                        "content": f"{COMPLETION} {fahrenheit:.1f}F",
                    }
                    finish = "stop"
                self._json({
                    "id": f"chatcmpl-e2e-{call}", "object": "chat.completion",
                    "model": "e2e-model-2026",
                    "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                    "usage": {"prompt_tokens": 30 + call, "completion_tokens": 7},
                })  # fmt: skip

            def _json(self, document: dict[str, Any]) -> None:
                data = json.dumps(document).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _stream(self, call: int, celsius: float) -> None:
                arguments = json.dumps({"celsius": celsius})
                half = len(arguments) // 2
                deltas = [
                    {"role": "assistant", "content": None},
                    {"tool_calls": [{"index": 0, "id": f"call_convert_{call}", "type": "function",
                                     "function": {"name": "c_to_f", "arguments": ""}}]},
                    {"tool_calls": [{"index": 0, "function": {"arguments": arguments[:half]}}]},
                    {"tool_calls": [{"index": 0, "function": {"arguments": arguments[half:]}}]},
                ]  # fmt: skip
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()  # HTTP/1.0: the body ends when the connection closes
                base = {"id": f"chatcmpl-e2e-{call}", "object": "chat.completion.chunk",
                        "model": "e2e-model-2026"}  # fmt: skip
                for delta in deltas:
                    chunk = {**base, "choices": [{"index": 0, "delta": delta}]}
                    self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
                    self.wfile.flush()
                    time.sleep(0.01)
                last = {
                    **base,
                    "choices": [
                        {"index": 0, "delta": {}, "finish_reason": "tool_calls"}
                    ],
                }
                self.wfile.write(
                    f"data: {json.dumps(last)}\n\ndata: [DONE]\n\n".encode()
                )
                self.wfile.flush()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = int(self.server.server_address[1])
        self.url = f"http://127.0.0.1:{self.port}/v1/chat/completions"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


# --------------------------------------------------------------------------
# The stack: Node (compose, production overlay) + host sink + fake model
# --------------------------------------------------------------------------


@dataclass
class AgentRun:
    service: str
    store: Path
    result: subprocess.CompletedProcess[str]
    model_requests: int
    info: dict[str, Any] = field(default_factory=dict)


class Stack:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.project = f"fabric-wire-e2e-{uuid.uuid4().hex[:12]}"
        self.tls = root / "tls"
        self.sink_dir = root / "sink"
        self.store = root / "store"
        self.ports = {
            name: _free_port()
            for name in ("otlp_http", "otlp_grpc", "health", "metrics", "sink")
        }
        self.image = (
            os.environ.get("FABRIC_NODE_IMAGE") or "fabric/node:wire-capture-e2e"
        )
        # A host-process sink: the Node reaches it through host.docker.internal.
        # Docker Desktop forwards that to host loopback; on Linux host-gateway
        # is the bridge address, so the sink must listen beyond loopback there.
        self.sink_bind = "127.0.0.1" if sys.platform == "darwin" else "0.0.0.0"  # noqa: S104
        self.sink_process: subprocess.Popen[bytes] | None = None
        self.model = _Model()
        token_file = root / "secrets" / "ingress.token"
        token_file.parent.mkdir()
        token_file.write_text(
            INGRESS_TOKEN, "utf-8"
        )  # no trailing newline (fabric-gate rule)
        token_file.chmod(
            0o644
        )  # nonroot in the container reads it through a bind mount
        _write_tls(self.tls)
        self.config = root / "collector-production.yaml"
        _production_config_with_tls(self.config)
        self.override = root / "compose.override.yml"
        self.override.write_text(
            "services:\n"
            "  fabric-node:\n"
            "    pull_policy: never\n"
            "    volumes:\n"
            f"      - {self.config}:/etc/fabric-node/collector-production.yaml:ro\n"
            "    extra_hosts:\n"
            '      - "host.docker.internal:host-gateway"\n',
            "utf-8",
        )
        (root / "empty.env").write_text("", "utf-8")
        self.env = {
            **{k: v for k, v in os.environ.items() if not k.startswith("FABRIC_")},
            "FABRIC_NODE_IMAGE": self.image,
            "FABRIC_BIND_ADDR": "127.0.0.1",
            "FABRIC_OTLP_HTTP_PORT": str(self.ports["otlp_http"]),
            "FABRIC_OTLP_GRPC_PORT": str(self.ports["otlp_grpc"]),
            "FABRIC_HEALTH_PORT": str(self.ports["health"]),
            "FABRIC_METRICS_PORT": str(self.ports["metrics"]),
            "FABRIC_INGRESS_TOKEN_FILE": str(token_file),
            "FABRIC_INGRESS_TLS_DIR": str(self.tls),
            "FABRIC_EXPORT_ENDPOINT": f"https://host.docker.internal:{self.ports['sink']}",
            "FABRIC_EXPORT_AUTH_HEADER": EGRESS_AUTH,
        }

    # -- compose -------------------------------------------------------------

    def compose(
        self, *args: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        command = [
            "docker", "compose", "-p", self.project, "--project-directory", str(COMPOSE_DIR),
            "--env-file", str(self.root / "empty.env"),
            "-f", str(COMPOSE_DIR / "docker-compose.yml"),
            "-f", str(COMPOSE_DIR / "docker-compose.production.yml"),
            "-f", str(self.override), *args,
        ]  # fmt: skip
        return subprocess.run(
            command, cwd=COMPOSE_DIR, env=self.env, check=check, capture_output=True,
            text=True, timeout=900,
        )  # fmt: skip

    def node_logs(self) -> str:
        result = self.compose("logs", "--no-color", "fabric-node", check=False)
        return result.stdout + result.stderr

    def wait_health(self, timeout_s: float = 60.0) -> None:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                url = f"http://127.0.0.1:{self.ports['health']}/"
                with urllib.request.urlopen(url, timeout=2) as response:
                    if response.status == 200:
                        return
            except (OSError, ValueError):
                pass
            time.sleep(0.5)
        raise AssertionError(
            f"Fabric Node never became healthy:\n{self.node_logs()[-4000:]}"
        )

    def queue_size(self) -> float:
        url = f"http://127.0.0.1:{self.ports['metrics']}/metrics"
        with urllib.request.urlopen(url, timeout=5) as response:
            text = response.read().decode()
        sizes = [
            float(line.rsplit(" ", 1)[1])
            for line in text.splitlines()
            if line.startswith("otelcol_exporter_queue_size{")
            and "otlp_http/fabric" in line
        ]
        return max(sizes, default=0.0)

    # -- sink ----------------------------------------------------------------

    def start_sink(self) -> None:
        self.sink_process = subprocess.Popen(  # noqa: S603
            [sys.executable, str(SINK), str(self.sink_dir), str(self.ports["sink"]),
             self.sink_bind, str(self.tls / "server.crt"), str(self.tls / "server.key"),
             EGRESS_AUTH],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )  # fmt: skip
        context = ssl.create_default_context(cafile=str(self.tls / "ca.crt"))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                url = f"https://localhost:{self.ports['sink']}/health"
                with urllib.request.urlopen(
                    url, timeout=2, context=context
                ) as response:
                    if response.status == 200:
                        return
            except (OSError, ValueError):
                time.sleep(0.2)
        raise AssertionError("sink never became ready")

    def stop_sink(self) -> None:
        if self.sink_process is not None and self.sink_process.poll() is None:
            self.sink_process.terminate()
            self.sink_process.wait(timeout=30)
        self.sink_process = None

    @property
    def records(self) -> Path:
        return self.sink_dir / "records.jsonl"

    def rows(self) -> list[dict[str, Any]]:
        if not self.records.exists():
            return []
        lines = self.records.read_text("utf-8").splitlines()
        return [json.loads(line) for line in lines if line.strip()]

    def spans_of(self, service: str) -> list[dict[str, Any]]:
        return [
            row for row in self.rows()
            if row.get("kind") == "span" and row["resource"].get("service.name") == service
        ]  # fmt: skip

    def wait_for_run(
        self, service: str, calls: int, timeout_s: float = 90.0
    ) -> list[dict[str, Any]]:
        """Until every exchange span and the final tail heartbeat of ``service`` arrived."""
        deadline = time.monotonic() + timeout_s
        spans: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            spans = self.spans_of(service)
            exchanges = {
                s["attributes"].get("fabric.wire.exchange_id")
                for s in spans if s["name"] == "fabric.model_call"
            }  # fmt: skip
            tail = [
                s for s in spans
                if s["attributes"].get("fabric.heartbeat.last_sequence") == calls - 1
            ]  # fmt: skip
            if len(exchanges) >= calls and tail:
                return spans
            time.sleep(1)
        raise AssertionError(
            f"{service}: {len(spans)} spans after {timeout_s}s, expected {calls} exchanges "
            f"and a tail heartbeat\n{self.node_logs()[-4000:]}"
        )

    # -- agent ---------------------------------------------------------------

    def agent_env(self, service: str, store: Path, token: str) -> dict[str, str]:
        autoload = subprocess.run(
            [sys.executable, "-m", "fabric.wire", "--print-autoload-path"],
            check=True, capture_output=True, text=True, timeout=60,
        ).stdout.strip()  # fmt: skip
        endpoints = [{
            "endpoint_id": "e2e-model", "dialect": "openai", "hosts": ["127.0.0.1"],
            "ports": [self.model.port], "path_prefix": "/v1", "schemes": ["http"],
            "provider_name": "openai",
        }]  # fmt: skip
        base = {
            k: v for k, v in os.environ.items()
            if not k.startswith(("FABRIC_", "OTEL_")) and k != "PYTHONPATH"
        }  # fmt: skip
        return {
            **base,
            "PYTHONPATH": autoload,
            "FABRIC_WIRE_AUTOLOAD": "1",
            "FABRIC_TENANT_ID": TENANT,
            "FABRIC_WIRE_STORE": store.as_uri(),
            "FABRIC_WIRE_ENDPOINTS": json.dumps(endpoints),
            "OTEL_SERVICE_NAME": service,
            "OTEL_EXPORTER_OTLP_ENDPOINT": f"https://127.0.0.1:{self.ports['otlp_http']}",
            "OTEL_EXPORTER_OTLP_HEADERS": "Authorization=" + quote(f"Bearer {token}"),
            "OTEL_EXPORTER_OTLP_CERTIFICATE": str(self.tls / "ca.crt"),
            "E2E_MODEL_API_KEY": API_KEY,
            "E2E_TOOL_RESULT_MARK": TOOL_RESULT,
        }

    def run_agent(
        self, service: str, *, token: str = INGRESS_TOKEN, store: Path | None = None
    ) -> AgentRun:
        store = store or self.store
        before = self.model.requests
        result = subprocess.run(  # noqa: S603
            [sys.executable, str(AGENT), "--model-url", self.model.url, "--question", PROMPT],
            env=self.agent_env(service, store, token), cwd=self.root, capture_output=True,
            text=True, timeout=180, check=False,
        )  # fmt: skip
        run = AgentRun(service, store, result, self.model.requests - before)
        assert result.returncode == 0, (
            f"agent failed:\n{result.stdout}\n{result.stderr}"
        )
        run.info = json.loads(result.stdout.strip().splitlines()[-1])
        assert run.info["capture_active"], (
            f"zero-code capture did not install:\n{result.stderr}"
        )
        assert "capture not installed" not in result.stderr
        assert run.info["answer"].startswith(COMPLETION), run.info
        assert run.model_requests == 3 and self.model.unauthorized == 0
        return run

    # -- verification --------------------------------------------------------

    def reconstruct(self, store: Path | None = None) -> tuple[int, dict[str, Any]]:
        out = self.root / f"report-{uuid.uuid4().hex[:8]}.json"
        result = subprocess.run(
            [sys.executable, "-m", "fabric.reconstruct", "--spans", str(self.records),
             "--store-root", str(store or self.store), "--tenant", TENANT, "--out", str(out)],
            capture_output=True, text=True, timeout=300, check=False,
        )  # fmt: skip
        assert result.returncode in (0, 1), f"reconstruct usage error:\n{result.stderr}"
        return result.returncode, json.loads(out.read_text("utf-8"))

    def queue_volume_hits(self, needle: str) -> str:
        volume = f"{self.project}_fabric-queue"
        subprocess.run(
            ["docker", "volume", "inspect", volume], check=True, capture_output=True
        )
        probe = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "-v", f"{volume}:/q:ro",
             "alpine:latest", "grep", "-rl", needle, "/q"],
            capture_output=True, text=True, timeout=120, check=False,
        )  # fmt: skip
        assert probe.returncode in (0, 1), probe.stderr  # 1 = no match
        return probe.stdout.strip()


def _build_image(image: str) -> None:
    subprocess.run(
        ["docker", "build", "-t", image, str(NODE_CONTEXT)],
        check=True, capture_output=True, text=True, timeout=1800,
    )  # fmt: skip


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    stack = Stack(tmp_path_factory.mktemp("wire-node"))
    try:
        if not os.environ.get("FABRIC_NODE_IMAGE"):
            _build_image(stack.image)
        stack.start_sink()
        stack.compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "60")
        stack.wait_health()
        yield stack
    finally:
        stack.compose("down", "-v", "--remove-orphans", check=False)
        stack.stop_sink()
        stack.model.close()


# --------------------------------------------------------------------------
# Assertions shared by the tests
# --------------------------------------------------------------------------


def _store_descriptors(store: Path) -> dict[str, dict[str, Any]]:
    """Descriptor per stored object id, from the self-describing store."""
    return {
        path.stem: json.loads(path.read_text("utf-8"))
        for path in store.glob(f"{TENANT}/evidence/meta/*.json")
    }


def _assert_no_leak(stack: Stack) -> None:
    sink_text = stack.records.read_text("utf-8")
    raw = b"".join(
        path.read_bytes() for path in sorted((stack.sink_dir / "raw").glob("*.bin"))
    )
    logs = stack.node_logs()
    assert sink_text and raw and "fabric-node" in logs, "a leak scan would be vacuous"
    assert b"fabric.wire.exchange_id" in raw  # the raw bytes are the delivered spans
    for marker in CONTENT_MARKERS + SECRET_MARKERS:
        assert marker not in sink_text, f"{marker} reached the decoded sink output"
        assert marker.encode() not in raw, f"{marker} reached the delivered OTLP bytes"
        assert marker not in logs, f"{marker} appeared in the Node logs"
    assert stack.queue_volume_hits(MARK) == "", (
        "a marker persisted in the Node queue volume"
    )


def _assert_capture_spans(
    spans: list[dict[str, Any]], store: Path
) -> list[dict[str, Any]]:
    """Shape of one agent's capture spans after the Node; returns the exchanges."""
    assert {s["name"] for s in spans} <= CAPTURE_SPAN_NAMES, {s["name"] for s in spans}
    for span in spans:
        extra = set(span["attributes"]) - CAPTURE_KEYS - REUSED_KEYS
        assert not extra, f"{span['name']} carries non-allowlisted keys {extra}"
        assert span["scope"] == "", (
            "fabricguard must clear the instrumentation scope name"
        )
    by_id: dict[str, dict[str, Any]] = {}
    for span in spans:
        if span["name"] == "fabric.model_call":
            by_id.setdefault(span["attributes"]["fabric.wire.exchange_id"], span)
    exchanges = sorted(
        by_id.values(), key=lambda s: s["attributes"]["fabric.source.sequence"]
    )
    assert [s["attributes"]["fabric.source.sequence"] for s in exchanges] == [0, 1, 2]
    assert len({s["attributes"]["fabric.source.epoch"] for s in exchanges}) == 1
    assert len({s["attributes"]["fabric.run.id"] for s in exchanges}) == 1
    descriptors = _store_descriptors(store)
    for index, span in enumerate(exchanges):
        attrs = span["attributes"]
        missing = EXCHANGE_REQUIRED - set(attrs)
        assert not missing, f"the Node dropped exchange keys {missing}"
        assert span["span_kind"] == SPAN_KIND_CLIENT
        assert attrs["fabric.wire.api"] == "openai.chat_completions"
        assert attrs["fabric.wire.response_state"] == "complete"
        assert attrs["fabric.wire.store_status"] == "stored"
        assert attrs["fabric.wire.truncated"] is False
        assert attrs["http.response.status_code"] == 200
        assert attrs["gen_ai.operation.name"] == "chat"
        streamed = index == 1
        present = EXCHANGE_METADATA & set(attrs)
        assert present == (set() if streamed else EXCHANGE_METADATA), (index, present)
        for ref_key, digest_key, role in (
            (
                "fabric.content.request_ref",
                "fabric.wire.request_sha256",
                "model.exchange.request",
            ),
            (
                "fabric.content.result_ref",
                "fabric.wire.response_sha256",
                "model.exchange.response",
            ),
        ):
            descriptor = descriptors[attrs[ref_key].rstrip("/").rsplit("/", 1)[-1]]
            assert descriptor["role"] == role
            assert descriptor["operation_id"] == attrs["fabric.wire.exchange_id"]
            assert descriptor["stored_sha256"] == "sha256:" + attrs[digest_key]
            assert descriptor["source_sequence"] == attrs["fabric.source.sequence"]
            assert descriptor["representation"] == "exact"
        if streamed:
            response = descriptors[
                attrs["fabric.content.result_ref"].rsplit("/", 1)[-1]
            ]
            assert response["media_type"] == "text/event-stream"
    heartbeats = [s for s in spans if s["name"] == "fabric.capture_heartbeat"]
    assert heartbeats, "no heartbeat reached the sink"
    assert not [s for s in spans if s["name"] == "fabric.capture_loss"], (
        "unexpected capture loss"
    )
    return exchanges


def _assert_complete(report: dict[str, Any], code: int, runs: set[str]) -> None:
    by_run = {run["run_id"]: run for run in report["runs"]}
    assert runs <= set(by_run), (runs, set(by_run))
    for run_id, run in by_run.items():
        assert run["verdict"] == "complete_for_declared_scope", (
            run_id,
            run["gaps"],
            run["checks"],
        )
        assert run["gaps"] == [], (run_id, run["gaps"])
        assert set(run["checks"].values()) <= {"passed", "not_applicable"}, run[
            "checks"
        ]
    for run_id in runs:
        assert by_run[run_id]["counts"]["exchanges"] == 3
        # One thread: request N+1 continues response N, tool calls matched.
        assert len(by_run[run_id]["threads"]) == 1, by_run[run_id]["threads"]
    assert code == 0


# --------------------------------------------------------------------------
# Tests (module order matters: they share one Node and one sink)
# --------------------------------------------------------------------------


def test_wire_capture_streams_through_production_node_and_reconstructs(
    stack: Stack,
) -> None:
    # The Node boots through fabric-gate, which validated this config.
    container = stack.compose("ps", "-q", "fabric-node").stdout.strip()
    entrypoint = subprocess.run(
        ["docker", "inspect", "--format", "{{json .Config.Entrypoint}}", container],
        check=True, capture_output=True, text=True, timeout=30,
    ).stdout.strip()  # fmt: skip
    assert entrypoint == '["/fabric-gate"]'

    run = stack.run_agent("wire-e2e-agent")
    spans = stack.wait_for_run(run.service, calls=3)
    exchanges = _assert_capture_spans(spans, run.store)

    # The content exists, but only inside the customer's store; headers
    # (the model API key) are never stored at all.
    stored = b"".join(p.read_bytes() for p in run.store.rglob("*") if p.is_file())
    for marker in CONTENT_MARKERS:
        assert marker.encode() in stored, f"{marker} was not captured into the store"
    for secret in SECRET_MARKERS:
        assert secret.encode() not in stored, f"{secret} was written to the store"
    _assert_no_leak(stack)

    code, report = stack.reconstruct()
    _assert_complete(report, code, {exchanges[0]["attributes"]["fabric.run.id"]})


def test_queued_spans_survive_sink_outage_and_node_restart(stack: Stack) -> None:
    stack.stop_sink()
    try:
        run = stack.run_agent("wire-e2e-outage")
        # The Node accepted the export (no loss in the agent) and holds it in
        # its persistent queue because the destination is down.
        deadline = time.monotonic() + 60
        while stack.queue_size() < 1 and time.monotonic() < deadline:
            time.sleep(1)
        assert stack.queue_size() >= 1, "nothing queued while the destination was down"
        assert not stack.spans_of(run.service)
        stack.compose("restart", "fabric-node")
        stack.wait_health()
    finally:
        stack.start_sink()
    spans = stack.wait_for_run(run.service, calls=3, timeout_s=180)
    exchanges = _assert_capture_spans(spans, run.store)
    duplicates = len([s for s in spans if s["name"] == "fabric.model_call"]) - len(
        exchanges
    )
    print(f"durable queue redelivered {duplicates} duplicate exchange span(s)")
    _assert_no_leak(stack)

    # The whole sink file, duplicates included, still reconstructs cleanly.
    code, report = stack.reconstruct()
    _assert_complete(report, code, {exchanges[0]["attributes"]["fabric.run.id"]})


def test_wrong_ingress_token_is_rejected_and_agent_is_unaffected(stack: Stack) -> None:
    node = f"127.0.0.1:{stack.ports['otlp_http']}"
    context = ssl.create_default_context(cafile=str(stack.tls / "ca.crt"))
    request = urllib.request.Request(
        f"https://{node}/v1/traces", data=b"{}", method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {WRONG_TOKEN}"},
    )  # fmt: skip
    with pytest.raises(urllib.error.HTTPError) as rejected:
        urllib.request.urlopen(request, timeout=10, context=context)
    assert rejected.value.code in (401, 403)
    # Receiver TLS is enforced: a plaintext request is not served.
    with pytest.raises(
        (urllib.error.HTTPError, urllib.error.URLError, OSError)
    ) as plain:
        urllib.request.urlopen(f"http://{node}/v1/traces", data=b"{}", timeout=10)
    if isinstance(plain.value, urllib.error.HTTPError):
        assert plain.value.code == 400

    rejected_store = stack.root / "store-rejected"
    bad = stack.run_agent(
        "wire-e2e-wrong-token", token=WRONG_TOKEN, store=rejected_store
    )
    rejected_ids = {
        d["operation_id"] for d in _store_descriptors(rejected_store).values()
    }
    assert len(rejected_ids) == 3, "capture itself must still work locally"

    # Barrier: a correctly authenticated run sent afterwards arrives, so
    # anything the rejected agent sent would have arrived by now.
    barrier = stack.run_agent("wire-e2e-barrier")
    stack.wait_for_run(barrier.service, calls=3)
    assert stack.spans_of(bad.service) == [], (
        "spans with a wrong token reached the sink"
    )
    sink_text = stack.records.read_text("utf-8")
    assert not [i for i in rejected_ids if i in sink_text]
    _assert_no_leak(stack)

    code, report = stack.reconstruct()
    _assert_complete(report, code, set())
