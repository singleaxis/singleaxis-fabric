# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 055 §9.5, unit 055-t14 (milestone M2): zero-code capture from the packed package.

Three unmodified agent scripts, one per client row of §9.3 that sends through undici:
global ``fetch`` (an ES module), the official ``openai`` client (an ES module) and the
official ``@anthropic-ai/sdk`` client (CommonJS). Each knows nothing about Fabric; it is
started only with ``NODE_OPTIONS=--import=@singleaxis/fabric/register`` and environment
variables, from an application directory where the packed tarball is installed
(``_node_package.py``). Each runs a two-turn tool loop (a JSON tool call, then a streamed
answer) against a scripted loopback provider. The preload installs capture before the
script's first line; at exit the bounded drain delivers the record to the recording sink
(``_wire_capture_sink.py``, the customer destination behind a Fabric Node), and
``python -m fabric.reconstruct`` verifies it: every check passes, no gap, the source has no
missing sequence, and the request and response bytes it replays are the bytes the provider
received and sent. No run API is called, so the reader verifies the process's source run:
``complete_for_declared_scope``, its window closed by the final heartbeat. The status file
the Fabric worker wrote at exit validates against ``wire-status-v1.schema.json``.

The ``ts-wire-package`` CI job runs it on the minimum qualified Node with
``FABRIC_REQUIRE_NODE_E2E=1``; elsewhere it is skipped without the tarball.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _node_package  # noqa: E402
from _wire_capture_common import Sink, capture_protection, write_tls  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
SCHEMA = (
    REPO / "contracts" / "diagnostics" / "v1" / "schema" / "wire-status-v1.schema.json"
)
TENANT = "tenant-zero-code"
ID_KEY = "zero-code-id-key-0123456789abcdef"
SPOOL_KEY = bytes(range(32))
EGRESS_AUTH = "Bearer zero-code-egress"
API_KEY = "sk-test-zero-code"

_MISSING = _node_package.missing()
_REQUIRED = os.environ.get("FABRIC_REQUIRE_NODE_E2E") == "1"
pytestmark = pytest.mark.skipif(
    _MISSING is not None and not _REQUIRED, reason=_MISSING or ""
)


@pytest.fixture(autouse=True)
def _prerequisites() -> None:
    if _MISSING is not None:
        pytest.fail(f"FABRIC_REQUIRE_NODE_E2E=1 but this machine {_MISSING}")


def _sse(events: list[tuple[str | None, dict[str, Any]]], done: bool) -> bytes:
    out = b""
    for name, data in events:
        if name is not None:
            out += b"event: " + name.encode() + b"\n"
        out += b"data: " + json.dumps(data).encode() + b"\n\n"
    return out + (b"data: [DONE]\n\n" if done else b"")


TOOL_CALL = {
    "id": "call_weather", "type": "function",
    "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"},
}  # fmt: skip
OPENAI_JSON = json.dumps({
    "id": "chatcmpl-zc-1", "object": "chat.completion", "created": 1, "model": "gpt-4o-mini",
    "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
        "role": "assistant", "content": None, "tool_calls": [TOOL_CALL]}}],
    "usage": {"prompt_tokens": 31, "completion_tokens": 9, "total_tokens": 40},
}).encode()  # fmt: skip
OPENAI_SSE = _sse([
    (None, {"id": "chatcmpl-zc-2", "object": "chat.completion.chunk", "created": 1,
            "model": "gpt-4o-mini",
            "choices": [{"index": 0, "delta": {"role": "assistant", "content": "It is 21"}}]}),
    (None, {"id": "chatcmpl-zc-2", "object": "chat.completion.chunk", "created": 1,
            "model": "gpt-4o-mini",
            "choices": [{"index": 0, "delta": {"content": " C in Paris."},
                         "finish_reason": "stop"}]}),
], done=True)  # fmt: skip
ANTHROPIC_JSON = json.dumps({
    "id": "msg_zc_1", "type": "message", "role": "assistant", "model": "claude-haiku-4-5",
    "content": [{"type": "tool_use", "id": "toolu_weather", "name": "get_weather",
                 "input": {"city": "Paris"}}],
    "stop_reason": "tool_use", "stop_sequence": None,
    "usage": {"input_tokens": 40, "output_tokens": 12},
}).encode()  # fmt: skip
ANTHROPIC_SSE = _sse([
    ("message_start", {"type": "message_start", "message": {
        "id": "msg_zc_2", "type": "message", "role": "assistant", "model": "claude-haiku-4-5",
        "content": [], "stop_reason": None, "stop_sequence": None,
        "usage": {"input_tokens": 60, "output_tokens": 1}}}),
    ("content_block_start", {"type": "content_block_start", "index": 0,
                             "content_block": {"type": "text", "text": ""}}),
    ("content_block_delta", {"type": "content_block_delta", "index": 0,
                             "delta": {"type": "text_delta", "text": "It is 21"}}),
    ("content_block_delta", {"type": "content_block_delta", "index": 0,
                             "delta": {"type": "text_delta", "text": " C in Paris."}}),
    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
    ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn",
                                                          "stop_sequence": None},
                       "usage": {"output_tokens": 8}}),
    ("message_stop", {"type": "message_stop"}),
], done=False)  # fmt: skip


class Provider:
    """A loopback model provider (OpenAI Chat Completions and Anthropic Messages): the
    exact request bytes it received and the exact response bytes it sent, in order."""

    def __init__(self) -> None:
        self.received: list[bytes] = []
        self.sent: list[bytes] = []
        provider = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                provider.received.append(body)
                stream = json.loads(body).get("stream") is True
                anthropic = self.path.endswith("/v1/messages")
                if anthropic:
                    data = ANTHROPIC_SSE if stream else ANTHROPIC_JSON
                else:
                    data = OPENAI_SSE if stream else OPENAI_JSON
                provider.sent.append(data)
                self.send_response(200)
                kind = "text/event-stream" if stream else "application/json"
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture(scope="module")
def app(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("f055-t14-app")
    _node_package.install_app(directory)
    return directory


@pytest.fixture
def provider() -> Iterator[Provider]:
    server = Provider()
    yield server
    server.close()


@pytest.fixture
def sink(tmp_path: Path) -> Iterator[Sink]:
    tls = tmp_path / "tls"
    write_tls(tls)
    destination = Sink(tmp_path / "sink", tls, EGRESS_AUTH)
    destination.directory.mkdir()
    destination.start()
    yield destination
    destination.stop()


def agent_env(
    root: Path, provider: Provider, sink: Sink, dialect: str
) -> dict[str, str]:
    """Only environment variables: the preload, Fabric's settings and the client's own."""
    base = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("FABRIC_", "OTEL_", "OPENAI_", "ANTHROPIC_", "NODE_"))
    }
    headers = root / "otlp-headers"
    headers.write_text("Authorization=" + EGRESS_AUTH.replace(" ", "%20") + "\n")
    headers.chmod(0o600)
    endpoint = {
        "endpoint_id": f"zc-{dialect}", "dialect": dialect, "hosts": ["127.0.0.1"],
        "ports": [provider.port], "schemes": ["http"],
    }  # fmt: skip
    return {
        **base,
        **capture_protection(root, TENANT, SPOOL_KEY),
        "NODE_OPTIONS": "--import=@singleaxis/fabric/register",
        "FABRIC_WIRE_AUTOLOAD": "1",
        "FABRIC_TENANT_ID": TENANT,
        "FABRIC_WIRE_ID_KEY": ID_KEY,
        "FABRIC_WIRE_SPOOL_DIR": str(root / "spool"),
        "FABRIC_WIRE_ENDPOINTS": json.dumps([endpoint]),
        "FABRIC_WIRE_CONTENT_ENDPOINT": f"https://localhost:{sink.port}/v1/logs",
        "FABRIC_OTLP_ENDPOINT": f"https://localhost:{sink.port}",
        "FABRIC_OTLP_HEADERS_FILE": str(headers),
        "FABRIC_OTLP_CERTIFICATE": str(sink.tls / "ca.crt"),
        # The opt-in exit drain: a short script ends before a periodic delivery pass.
        "FABRIC_WIRE_DRAIN_ON_EXIT_S": "20",
        "FABRIC_WIRE_STATUS_FILE": str(root / "fabric-status.json"),
        "OTEL_SERVICE_NAME": "zero-code-agent",
        "MODEL_BASE_URL": f"http://127.0.0.1:{provider.port}",
        "OPENAI_BASE_URL": f"http://127.0.0.1:{provider.port}/v1",
        "OPENAI_API_KEY": API_KEY,
        "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{provider.port}",
        "ANTHROPIC_API_KEY": API_KEY,
    }


def file_store(rows: list[dict[str, Any]], root: Path) -> None:
    """Files each content log the sink received as the Node's directory backend does."""
    from fabric.content_store import LocalFilesystemContentStore

    (root / TENANT).mkdir(parents=True, exist_ok=True)
    store = LocalFilesystemContentStore(root=str(root), tenant_id=TENANT)
    for row in rows:
        if row.get("kind") != "log":
            continue
        descriptor = {k: v for k, v in row["attributes"].items() if k != "event_class"}
        if row["body"] is None or "stored_sha256" not in descriptor:
            store.put_descriptor_only(descriptor)
            continue
        descriptor["encoding"] = "binary"
        descriptor["ref"] = store.evidence_ref_for(descriptor["object_id"])
        store.put_bytes_object(descriptor, bytes.fromhex(row["body"]))


def reconstruct(
    rows: list[dict[str, Any]], root: Path
) -> tuple[int, dict[str, Any], str]:
    spans = root / "spans.jsonl"
    spans.write_text(
        "".join(json.dumps(r) + "\n" for r in rows if r.get("kind") == "span")
    )
    store = root / "store"
    file_store(rows, store)
    out = root / "report.json"
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "fabric.reconstruct", "--spans", str(spans),
         "--store-root", str(store), "--tenant", TENANT, "--out", str(out)],
        env={**os.environ, "FABRIC_WIRE_ID_KEY": ID_KEY}, capture_output=True, text=True,
        timeout=120, check=False,
    )  # fmt: skip
    report = json.loads(out.read_text()) if out.exists() else {}
    return done.returncode, report, done.stderr


CLIENTS = [
    ("fetch.mjs", "openai", "get_weather"),
    ("openai.mjs", "openai", "get_weather"),
    ("anthropic.cjs", "anthropic", "get_weather"),
]


@pytest.mark.parametrize(("script", "dialect", "tool"), CLIENTS, ids=lambda v: str(v))
def test_an_unmodified_script_started_with_the_preload_produces_a_verified_run(
    tmp_path: Path, app: Path, provider: Provider, sink: Sink, script: str, dialect: str,
    tool: str,
) -> None:  # fmt: skip
    env = agent_env(tmp_path, provider, sink, dialect)
    node = _node_package.node_binary()
    assert node is not None
    done = subprocess.run(  # noqa: S603
        [node, script], cwd=app, env=env, capture_output=True, text=True, timeout=180,
        check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    seen = json.loads(done.stdout.strip().splitlines()[-1])
    assert seen["tool"] == tool
    if "answer" in seen:
        assert seen["answer"] == "It is 21 C in Paris."
    # Fabric is silent on the agent's own output by default (spec 055 §4.7).
    assert "fabric" not in done.stderr.lower(), done.stderr
    assert len(provider.received) == 2

    # The Fabric worker's exit document: closed, everything delivered, schema-valid.
    status = json.loads((tmp_path / "fabric-status.json").read_text())
    Draft202012Validator(
        json.loads(SCHEMA.read_text()), format_checker=FormatChecker()
    ).validate(status)
    assert (status["phase"], status["capture"], status["sdk_language"]) == (
        "exit",
        "closed",
        "typescript",
    )
    assert status["delivered"] is True, status
    assert status["stats"]["matched"] == 2 and status["stats"]["spooled"] == 2, status
    assert status["stats"]["backlog"] == 0, status
    assert not list((tmp_path / "spool").glob("*.rec"))

    rows = sink.rows()
    code, report, stderr = reconstruct(rows, tmp_path)
    (run,) = report["runs"]
    # The reader verifies the record: every check passed, no gap, no missing position.
    assert set(run["checks"].values()) == {"passed"}, run["checks"]
    assert run["gaps"] == [], run["gaps"]
    (source,) = report["sources"]
    assert source["missing_sequences"] == [] and source["loss_ranges"] == []
    # No run API is called: the reader verifies the process's source run, its declared
    # scope closed by the final heartbeat the exit drain delivered (048 §6).
    assert code == 0, (stderr, run["verdict"])
    assert run["verdict"] == "complete_for_declared_scope", run["verdict"]
    (window,) = run["declared_scope"]["windows"]
    assert window["closed_by"] == "final_heartbeat", window
    assert (window["first_sequence"], window["last_sequence"]) == (0, 1), window
    # It replays the exact bytes the provider received and sent.
    from fabric.content_store import LocalFilesystemContentStore

    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id=TENANT)
    exchanges = sorted(run["exchanges"], key=lambda e: e["source_sequence"])
    assert [e["parse_status"] for e in exchanges] == ["ok", "ok"]
    for side, expected in (("request", provider.received), ("response", provider.sent)):
        objects = [e["objects"][side] for e in exchanges]
        assert all(o["verification"] == "verified" for o in objects), objects
        assert [
            store.read(store.evidence_ref_for(o["object_id"])) for o in objects
        ] == (expected)
    # The tool loop stitches: the call the first response emitted is the one consumed.
    assert (
        exchanges[0]["tool_call_ids_emitted"] == exchanges[1]["tool_call_ids_consumed"]
    )
    assert exchanges[0]["tool_call_ids_emitted"] != []


# ------------------------------------------------------------------ behaviour identity


class ScenarioProvider:
    """The identity scenarios' provider. The first path segment picks the behaviour:
    ``ok`` (JSON, or SSE events written 50 ms apart so each arrives as its own chunk),
    ``bad`` (HTTP 400 with an error body), ``flaky-*`` (500 once, then as ``ok``) and
    ``never`` (no answer until the client gives up). Records each request's path and body."""

    def __init__(self) -> None:
        self.received: list[tuple[str, bytes]] = []
        self.flaked: set[str] = set()
        self.release = threading.Event()
        provider = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def _send(self, status: int, kind: str, data: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                provider.received.append((self.path, body))
                scenario = self.path.split("/")[1]
                anthropic = self.path.endswith("/v1/messages")
                if scenario == "never":
                    provider.release.wait(10)
                    return
                if scenario == "bad":
                    error = {"type": "error", "error": {"type": "invalid_request_error",
                             "message": "max_tokens is too large"}}  # fmt: skip
                    self._send(400, "application/json", json.dumps(error).encode())
                    return
                if scenario.startswith("flaky") and scenario not in provider.flaked:
                    provider.flaked.add(scenario)
                    self._send(500, "application/json", b'{"error":{"message":"busy"}}')
                    return
                if json.loads(body).get("stream") is not True:
                    data = ANTHROPIC_JSON if anthropic else OPENAI_JSON
                    self._send(200, "application/json", data)
                    return
                data = ANTHROPIC_SSE if anthropic else OPENAI_SSE
                events = [e + b"\n\n" for e in data.split(b"\n\n") if e]
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(sum(len(e) for e in events)))
                self.end_headers()
                for event in events:
                    try:
                        self.wfile.write(event)
                        self.wfile.flush()
                    except OSError:
                        return  # the application aborted
                    provider.release.wait(0.05)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.release.set()
        self.server.shutdown()
        self.server.server_close()


def _identity_run(
    app: Path, root: Path, sink: Sink, kind: str, preload: bool
) -> tuple[dict[str, Any], list[tuple[str, bytes]], int, str]:
    provider = ScenarioProvider()
    try:
        dialect = "anthropic" if kind == "anthropic" else "openai"
        env = agent_env(root, provider, sink, dialect)  # type: ignore[arg-type]
        env["BASE"] = f"http://127.0.0.1:{provider.port}"
        if not preload:
            env = {
                k: v for k, v in env.items() if not k.startswith(("FABRIC_", "NODE_"))
            }
        node = _node_package.node_binary()
        assert node is not None
        done = subprocess.run(  # noqa: S603
            [node, "identity.mjs", kind], cwd=app, env=env, capture_output=True,
            text=True, timeout=180, check=False,
        )  # fmt: skip
        assert done.returncode == 0, done.stderr
        transcript: dict[str, Any] = json.loads(done.stdout.strip().splitlines()[-1])
        return transcript, sorted(provider.received), done.returncode, done.stderr
    finally:
        provider.close()


@pytest.mark.parametrize("kind", ["fetch", "openai", "anthropic"])
def test_behaviour_is_identical_with_and_without_the_preload(
    tmp_path: Path, app: Path, sink: Sink, kind: str
) -> None:
    """Spec 055 §9.2 behaviour identity for the three client rows, from the packed package:
    with the preload on, the application observes exactly what it observes with it off
    (results, every stream event or chunk, error classes, statuses and messages, the SDK's
    retry of a 500, an abort mid-stream, a client timeout), the server receives the same
    requests byte for byte, and the exit code and stderr are the same."""
    (tmp_path / "off").mkdir()
    (tmp_path / "on").mkdir()
    off = _identity_run(app, tmp_path / "off", sink, kind, preload=False)
    on = _identity_run(app, tmp_path / "on", sink, kind, preload=True)
    assert on[0] == off[0]
    assert on[1] == off[1]
    assert (on[2], on[3]) == (off[2], off[3])
    # The scenarios really ran: an error, a retry, an abort and a timeout were observed.
    transcript = on[0]
    if (
        kind == "fetch"
    ):  # fetch resolves an HTTP error; the clients throw it (and retry)
        assert transcript["error_400"]["ok"]["status"] == 400
        assert transcript["retried_500"]["ok"]["status"] == 500
    else:
        assert transcript["error_400"]["error"]["status"] == 400
        assert "ok" in transcript["retried_500"]
    assert "error" in transcript["timed_out"]
    # Capture was on: the Fabric worker wrote its exit document with matched exchanges.
    status = json.loads((tmp_path / "on" / "fabric-status.json").read_text())
    assert status["capture"] == "closed" and status["stats"]["matched"] >= 4, status
