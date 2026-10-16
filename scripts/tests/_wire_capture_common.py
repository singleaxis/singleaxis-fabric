# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared pieces of the wire-capture Node end-to-end tests (specs 047 and 048).

Not a test module. Both ``test_wire_capture_node_e2e.py`` (file backend) and
``test_wire_capture_minio_e2e.py`` (S3 backend on MinIO) drive real processes
and real sockets with:

- throwaway TLS material (one private CA, one leaf for the Node and the sink);
- ``collector-production.yaml`` with exactly its documented TLS edits applied;
- a fake OpenAI-compatible model on a real TCP socket;
- the HTTPS, fsync'ing OTLP sink (``_wire_capture_sink.py``) as a host process;
- readers for the agent's spool directory (spec 048 §2 framing);
- the label pseudonym function (spec 048 J1), computed independently of Fabric.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import ipaddress
import json
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = REPO_ROOT / "deploy" / "compose"
PRODUCTION_CONFIG = COMPOSE_DIR / "collector-config" / "collector-production.yaml"
CONTENT_CONFIG = COMPOSE_DIR / "collector-config" / "collector-content.yaml"
NODE_CONTEXT = REPO_ROOT / "components" / "otel-collector-fabric"
AGENT = Path(__file__).with_name("_wire_capture_agent.py")
SINK = Path(__file__).with_name("_wire_capture_sink.py")
DEFAULT_NODE_IMAGE = "fabric/node:wire-capture-e2e"
SPOOL_MAGIC = b"FWSPOOL1"


def pseudonym(prefix: str, value: str, key: str | None) -> str:
    """Spec 048 J1/H3: ``prefix`` + 32 hex of HMAC-SHA256(key, value) (SHA-256 unkeyed)."""
    data = value.encode("utf-8")
    digest = (
        hmac.new(key.encode("utf-8"), data, hashlib.sha256)
        if key
        else hashlib.sha256(data)
    )
    return prefix + digest.hexdigest()[:32]


def compose_available() -> bool:
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


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def wait_until(
    condition: Callable[[], bool], timeout_s: float, message: Callable[[], str]
) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.5)
    raise AssertionError(message())


def build_image(image: str) -> None:
    subprocess.run(
        ["docker", "build", "-t", image, str(NODE_CONTEXT)],
        check=True, capture_output=True, text=True, timeout=1800,
    )  # fmt: skip


def autoload_path() -> str:
    return subprocess.run(
        [sys.executable, "-m", "fabric.wire", "--print-autoload-path"],
        check=True, capture_output=True, text=True, timeout=60,
    ).stdout.strip()  # fmt: skip


# --------------------------------------------------------------------------
# Throwaway TLS material
# --------------------------------------------------------------------------


def write_tls(directory: Path) -> None:
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


def _uncomment_tls(text: str) -> tuple[str, int, int, int]:
    text, stanzas = re.subn(r"(?m)^(\s*)# tls:$", r"\1tls:", text)
    text, fields = re.subn(
        r"(?m)^(\s*)#   (cert_file|key_file|min_version):", r"\1  \2:", text
    )
    text, ca = re.subn(r"(?m)^(\s*)# (ca_file:)", r"\1\2", text)
    return text, stanzas, fields, ca


def production_config_with_tls(target: Path) -> None:
    """collector-production.yaml with exactly its documented TLS edits applied.

    The file says: uncomment the receiver ``tls:`` stanzas (gRPC and HTTP
    telemetry) before publishing beyond loopback, and the exporter ``ca_file``
    line for a private-CA destination. Nothing else changes, so drift in the
    shipped file shows up here instead of being masked by a hand-written test
    config.
    """
    text, stanzas, fields, ca = _uncomment_tls(PRODUCTION_CONFIG.read_text("utf-8"))
    assert (stanzas, fields, ca) == (2, 6, 1), "collector-production.yaml TLS stanzas moved"
    target.write_text(text, "utf-8")


def content_config_with_tls(target: Path) -> None:
    """collector-content.yaml (the opt-in production content path) with its
    documented TLS edit applied: the content receiver's ``tls:`` stanza, enabled
    together with the telemetry receivers' (fabric-gate refuses a weaker content
    port)."""
    text, stanzas, fields, ca = _uncomment_tls(CONTENT_CONFIG.read_text("utf-8"))
    assert (stanzas, fields, ca) == (1, 3, 0), "collector-content.yaml TLS stanza moved"
    target.write_text(text, "utf-8")


# --------------------------------------------------------------------------
# Fake OpenAI-compatible model on a real socket
# --------------------------------------------------------------------------


class FakeModel:
    """Three-step tool loop: get_weather, streamed c_to_f, final answer."""

    def __init__(self, *, api_key: str, city: str, completion: str) -> None:
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
                if self.headers.get("Authorization") != f"Bearer {api_key}":
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
                                         "arguments": json.dumps({"city": city})},
                        }],
                    }  # fmt: skip
                    finish = "tool_calls"
                else:
                    fahrenheit = json.loads(tool_results[-1]["content"])["fahrenheit"]
                    message = {
                        "role": "assistant",
                        "content": f"{completion} {fahrenheit:.1f}F",
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

    def endpoints_json(self) -> str:
        """``FABRIC_WIRE_ENDPOINTS`` naming this plain-http model."""
        return json.dumps([{
            "endpoint_id": "e2e-model", "dialect": "openai", "hosts": ["127.0.0.1"],
            "ports": [self.port], "path_prefix": "/v1", "schemes": ["http"],
            "provider_name": "openai",
        }])  # fmt: skip

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


# --------------------------------------------------------------------------
# HTTPS fsync sink (host process)
# --------------------------------------------------------------------------


class Sink:
    """The customer-selected destination behind the Node."""

    def __init__(
        self, directory: Path, tls: Path, egress_auth: str, *, id_key: str | None = None
    ) -> None:
        self.directory = directory
        # The agents' FABRIC_WIRE_ID_KEY: capture spans carry service.name only
        # as its svc- pseudonym by default (spec 048 J1).
        self.id_key = id_key
        self.tls = tls
        self.egress_auth = egress_auth
        self.port = free_port()
        # The Node reaches it through host.docker.internal. Docker Desktop
        # forwards that to host loopback; on Linux host-gateway is the bridge
        # address, so the sink must listen beyond loopback there.
        self.bind = "127.0.0.1" if sys.platform == "darwin" else "0.0.0.0"  # noqa: S104
        self.process: subprocess.Popen[bytes] | None = None

    @property
    def endpoint(self) -> str:
        return f"https://host.docker.internal:{self.port}"

    @property
    def records(self) -> Path:
        return self.directory / "records.jsonl"

    def start(self) -> None:
        self.process = subprocess.Popen(  # noqa: S603
            [sys.executable, str(SINK), str(self.directory), str(self.port), self.bind,
             str(self.tls / "server.crt"), str(self.tls / "server.key"), self.egress_auth],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )  # fmt: skip
        context = ssl.create_default_context(cafile=str(self.tls / "ca.crt"))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                url = f"https://localhost:{self.port}/health"
                with urllib.request.urlopen(
                    url, timeout=2, context=context
                ) as response:
                    if response.status == 200:
                        return
            except (OSError, ValueError):
                time.sleep(0.2)
        raise AssertionError("sink never became ready")

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=30)
        self.process = None

    def rows(self) -> list[dict[str, Any]]:
        if not self.records.exists():
            return []
        lines = self.records.read_text("utf-8").splitlines()
        return [json.loads(line) for line in lines if line.strip()]

    def spans_of(self, service: str) -> list[dict[str, Any]]:
        """Spans whose resource ``service.name`` is the J1 pseudonym of ``service``."""
        emitted = pseudonym("svc-", service, self.id_key)
        return [
            row for row in self.rows()
            if row.get("kind") == "span" and row["resource"].get("service.name") == emitted
        ]  # fmt: skip

    def raw_bytes(self) -> bytes:
        return b"".join(
            path.read_bytes() for path in sorted((self.directory / "raw").glob("*.bin"))
        )


# --------------------------------------------------------------------------
# Agent spool (spec 048 §2)
# --------------------------------------------------------------------------


def spool_records(spool: Path) -> list[Path]:
    return sorted(spool.glob("*.rec")) if spool.is_dir() else []


def spool_header(path: Path) -> dict[str, Any]:
    """The JSON header of one spool record (framing checked, blob ignored)."""
    data = path.read_bytes()
    assert data.startswith(SPOOL_MAGIC), path.name
    (length,) = struct.unpack(">I", data[8:12])
    header: dict[str, Any] = json.loads(data[12 : 12 + length])
    return header


def volume_grep(volume: str, needle: str) -> str:
    """Files in a named Docker volume containing ``needle`` (read-only probe)."""
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
