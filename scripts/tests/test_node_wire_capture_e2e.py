# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 055 §9.5, unit 055-t13: the first verified, replayable record of a Node agent.

A Node script calls global ``fetch`` with explicit ``install()`` of the wire core built
from the source tree (``qualification/node-wire/parity/build.mjs``): a two-turn tool loop
(JSON, then SSE) against a scripted provider inside ``run()``, a resume token, ``endRun``
and ``close()``. The Fabric worker protects, spools and delivers: content logs and spans
go over verified TLS to the recording sink (``_wire_capture_sink.py``), which plays the
customer destination behind a Fabric Node. The content logs the sink received are filed
into a local content store as the Node's directory backend files them, and
``python -m fabric.reconstruct`` then reads that record: the run is ``complete`` and
``terminated`` (exit code 0) and the request and response bytes it replays are the bytes
the provider received and sent.

The same protocol fixture through Python's wire capture produces identical spool frames
after the §7.3 substitution (minted ids, source epoch, timings and producer labels).

Needs Node 24.4 or newer (the first build that publishes the body channels), the SDK's
``npm ci`` (esbuild) and a C compiler for the native lock module; skipped otherwise. The
``ts-wire-parity`` CI job runs it on the minimum qualified Node.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _wire_capture_common import Sink, capture_protection, write_tls  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
PARITY = REPO / "qualification" / "node-wire" / "parity"
SDK = REPO / "sdk" / "typescript"
TENANT = "tenant-node-e2e"
ID_KEY = "node-e2e-id-key-0123456789abcdef"
SPOOL_KEY = bytes(range(32))
EGRESS_AUTH = "Bearer node-e2e-egress"
RUN_ID = "node-e2e-run"


def _node() -> str | None:
    node = os.environ.get("FABRIC_TEST_NODE") or shutil.which("node")
    if node is None:
        return None
    try:
        version = subprocess.run(  # noqa: S603
            [node, "-p", "process.versions.node"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
    except OSError:
        return None
    parts = [int(p) for p in version.split(".")[:2] if p.isdigit()]
    return (
        node
        if len(parts) == 2 and (parts[0] > 24 or (parts[0] == 24 and parts[1] >= 4))
        else None
    )


NODE = _node()
_MISSING = next(
    (
        reason
        for missing, reason in (
            (NODE is None, "needs Node.js 24.4 or newer (FABRIC_TEST_NODE)"),
            (
                not (SDK / "node_modules" / "esbuild").is_dir(),
                "run 'npm ci' in sdk/typescript",
            ),
            (shutil.which("cc") is None, "needs a C compiler for the lock module"),
        )
        if missing
    ),
    None,
)
# The ts-wire-parity job sets FABRIC_REQUIRE_NODE_E2E=1: there a missing prerequisite
# fails the run instead of skipping it (a skipped acceptance test proves nothing).
_REQUIRED = os.environ.get("FABRIC_REQUIRE_NODE_E2E") == "1"
pytestmark = pytest.mark.skipif(
    _MISSING is not None and not _REQUIRED, reason=_MISSING or ""
)


@pytest.fixture(autouse=True)
def _prerequisites() -> None:
    if _MISSING is not None:
        pytest.fail(f"FABRIC_REQUIRE_NODE_E2E=1 but this machine {_MISSING}")


# The scripted provider's exact response bytes: a tool call (JSON), then a streamed answer.
RESPONSE_JSON = json.dumps({
    "id": "chatcmpl-node-e2e-1", "object": "chat.completion", "model": "gpt-4o-mini-2024-07-18",
    "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
        "role": "assistant", "content": None, "tool_calls": [{
            "id": "call_weather", "type": "function",
            "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}}]}}],
    "usage": {"prompt_tokens": 31, "completion_tokens": 9},
}).encode()  # fmt: skip
RESPONSE_SSE = b"".join(
    b"data: " + json.dumps(event).encode() + b"\n\n"
    for event in (
        {"id": "chatcmpl-node-e2e-2", "object": "chat.completion.chunk",
         "model": "gpt-4o-mini-2024-07-18",
         "choices": [{"index": 0, "delta": {"role": "assistant", "content": "It is 21"}}]},
        {"id": "chatcmpl-node-e2e-2", "object": "chat.completion.chunk",
         "model": "gpt-4o-mini-2024-07-18",
         "choices": [{"index": 0, "delta": {"content": " C in Paris."}, "finish_reason": "stop"}]},
    )
) + b"data: [DONE]\n\n"  # fmt: skip


# The agent's exact request bodies: a question, then the tool loop's second turn (the
# assistant's tool call and its result, streamed answer).
REQUESTS = [
    json.dumps({"model": "gpt-4o-mini", "messages": [
        {"role": "user", "content": "What is the weather in Paris?"}]}),
    json.dumps({"model": "gpt-4o-mini", "stream": True, "messages": [
        {"role": "user", "content": "What is the weather in Paris?"},
        {"role": "assistant", "content": None, "tool_calls": [{
            "id": "call_weather", "type": "function",
            "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}}]},
        {"role": "tool", "tool_call_id": "call_weather", "content": "{\"celsius\": 21}"}]}),
]  # fmt: skip


class Provider:
    """A loopback model provider: the exact request bytes it received, in order."""

    def __init__(self) -> None:
        self.received: list[bytes] = []
        provider = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                provider.received.append(body)
                stream = json.loads(body).get("stream") is True
                data = RESPONSE_SSE if stream else RESPONSE_JSON
                self.send_response(200)
                self.send_header(
                    "Content-Type",
                    "text/event-stream" if stream else "application/json",
                )
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    out = tmp_path_factory.mktemp("f055-t13-build")
    done = subprocess.run(  # noqa: S603
        [str(NODE), str(PARITY / "build.mjs"), str(out)],
        capture_output=True, text=True, timeout=300, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    result: dict[str, Any] = json.loads(done.stdout)
    return result


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


def qualification(built: dict[str, Any]) -> dict[str, Any] | None:
    """The source tree's table, or (only where it does not list this machine's build, as on
    a developer's macOS) the same table with this build added as an active tuple: tests
    activate capture through the table in the source tree (§9.5)."""
    table = json.loads(Path(built["qualification"]).read_text())
    info = json.loads(subprocess.run(  # noqa: S603
        [str(NODE), "-p", "JSON.stringify({node: process.versions.node, undici: process.versions.undici})"],
        capture_output=True, text=True, check=True,
    ).stdout)  # fmt: skip
    listed = any(
        t.get("claim") == "active" and t["node"] == info["node"] and t["platform"] == built["target"]
        and t.get("undici") == info["undici"] for t in table["tuples"]
    )  # fmt: skip
    if listed:
        return None
    tuple_ = {"point": "wire.ts.undici", "node": info["node"], "undici": info["undici"],
              "undici_origin": "bundled", "platform": built["target"], "claim": "active",
              "report_sha256": "sha256:" + "0" * 64}  # fmt: skip
    return {**table, "tuples": [*table["tuples"], tuple_]}


def agent_env(
    root: Path, provider: Provider, sink: Sink, spool: Path
) -> dict[str, str]:
    base = {
        k: v for k, v in os.environ.items() if not k.startswith(("FABRIC_", "OTEL_"))
    }
    headers = root / "otlp-headers"
    headers.write_text("Authorization=" + EGRESS_AUTH.replace(" ", "%20") + "\n")
    headers.chmod(0o600)
    return {
        **base,
        **capture_protection(root, TENANT, SPOOL_KEY),
        "FABRIC_TENANT_ID": TENANT,
        "FABRIC_WIRE_ID_KEY": ID_KEY,
        "FABRIC_WIRE_SPOOL_DIR": str(spool),
        "FABRIC_WIRE_ENDPOINTS": json.dumps(
            [
                {
                    "endpoint_id": "e2e-model",
                    "dialect": "openai",
                    "hosts": ["127.0.0.1"],
                    "ports": [provider.port],
                    "schemes": ["http"],
                }
            ]
        ),
        "FABRIC_WIRE_CONTENT_ENDPOINT": f"https://localhost:{sink.port}/v1/logs",
        "FABRIC_OTLP_ENDPOINT": f"https://localhost:{sink.port}",
        "FABRIC_OTLP_HEADERS_FILE": str(headers),
        "FABRIC_OTLP_CERTIFICATE": str(sink.tls / "ca.crt"),
        "OTEL_SERVICE_NAME": "node-e2e-agent",
    }


def run_agent(
    built: dict[str, Any], env: dict[str, str], provider: Provider, **extra: Any
) -> dict[str, Any]:
    args = {**built, "base": provider.base, "runId": RUN_ID, "requests": REQUESTS,
            "qualification": qualification(built), **extra}  # fmt: skip
    if args["qualification"] is None:
        del args["qualification"]
    done = subprocess.run(  # noqa: S603
        [str(NODE), str(PARITY / "agent.cjs"), json.dumps(args)],
        env=env, capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    result: dict[str, Any] = json.loads(done.stdout.strip().splitlines()[-1])
    return result


def file_store(rows: list[dict[str, Any]], root: Path) -> None:
    """Files each content log the sink received as the Node's directory backend does: the
    exact bytes at ``<tenant>/evidence/<object_id>`` with the descriptor beside them."""
    from fabric.content_store import LocalFilesystemContentStore

    (root / TENANT).mkdir(parents=True, exist_ok=True)
    store = LocalFilesystemContentStore(root=str(root), tenant_id=TENANT)
    for row in rows:
        if row.get("kind") != "log":
            continue
        descriptor = {k: v for k, v in row["attributes"].items() if k != "event_class"}
        if row["body"] is None or "stored_sha256" not in descriptor:
            store.put_descriptor_only(descriptor)  # no encoding, no ref (as the Node)
            continue
        descriptor["encoding"] = "binary"
        descriptor["ref"] = store.evidence_ref_for(descriptor["object_id"])
        store.put_bytes_object(descriptor, bytes.fromhex(row["body"]))


def reconstruct(
    rows: list[dict[str, Any]], root: Path, *extra: str
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
         "--store-root", str(store), "--tenant", TENANT, "--out", str(out), *extra],
        env={**os.environ, "FABRIC_WIRE_ID_KEY": ID_KEY}, capture_output=True, text=True,
        timeout=120, check=False,
    )  # fmt: skip
    report = json.loads(out.read_text()) if out.exists() else {}
    return done.returncode, report, done.stderr


def test_a_node_fetch_run_is_verified_complete_and_replays_its_bytes(
    tmp_path: Path, built: dict[str, Any], provider: Provider, sink: Sink
) -> None:
    spool = tmp_path / "spool"
    result = run_agent(built, agent_env(tmp_path, provider, sink, spool), provider)
    # The application saw exactly what the provider sent; capture never changed it.
    assert [s["body"].encode() for s in result["seen"]] == [RESPONSE_JSON, RESPONSE_SSE]
    assert result["ended"] == "ended"
    assert result["flushed"] is True, result
    assert result["closed"] is True, result
    assert result["stop"] == {"closed": True, "delivered": True, "backlog": 0}
    # Every record was delivered and retired; nothing left for a later drainer.
    assert not list(spool.glob("*.rec")), sorted(p.name for p in spool.iterdir())

    rows = sink.rows()
    # close() removed the hook: a chained manifest declares the point disabled(shutdown)
    # before final (050 §3.8, as Python's uninstall).
    manifests = sorted(
        (r["attributes"] for r in rows if r.get("kind") == "span"
         and r["name"] == "fabric.capture_manifest"),
        key=lambda a: a["fabric.manifest.manifest_seq"],
    )  # fmt: skip
    points = [
        next(
            p
            for p in m["fabric.manifest.capture_points"]
            if p.startswith("wire.ts.undici@")
        )
        for m in manifests
    ]
    # "<point>@<version>:<kind>:<state>:<a>:<b>:<reason>"
    states = [(p.split(":")[2], p.split(":")[5]) for p in points]
    assert states == [("active", "-"), ("disabled", "shutdown")]
    code, report, stderr = reconstruct(rows, tmp_path)
    # The reader verifies the run: complete (a scoped run's complete verdict) and
    # terminated, exit code 0, every check passed, no gap at all.
    assert code == 0, stderr
    (run,) = report["runs"]
    assert run["verdict"] == "complete_for_observed_scopes", run
    assert run["run_state"] == "terminated", run
    assert run["gaps"] == [], run["gaps"]
    assert set(run["checks"].values()) == {"passed"}, run["checks"]
    (source,) = report["sources"]
    assert source["source_id"] == result["sourceId"]
    assert source["missing_sequences"] == [] and source["loss_ranges"] == []
    assert source["final_heartbeat_sequence"] == len(REQUESTS) - 1
    # It replays the exact bytes: each exchange's request is what the provider received,
    # its response what the provider sent and the application read.
    from fabric.content_store import LocalFilesystemContentStore

    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id=TENANT)
    exchanges = sorted(run["exchanges"], key=lambda e: e["source_sequence"])
    assert [e["parse_status"] for e in exchanges] == ["ok", "ok"]
    replayed = [
        tuple(store.read(store.evidence_ref_for(e["objects"][side]["object_id"]))
              for side in ("request", "response"))
        for e in exchanges
    ]  # fmt: skip
    assert all(
        e["objects"][side]["verification"] == "verified"
        for e in exchanges for side in ("request", "response")
    )  # fmt: skip
    assert (
        [r for r, _ in replayed] == provider.received == [r.encode() for r in REQUESTS]
    )
    assert [r for _, r in replayed] == [RESPONSE_JSON, RESPONSE_SSE]
    # The tool loop stitches: the call the first response emitted is the one consumed.
    assert (
        exchanges[0]["tool_call_ids_emitted"]
        == exchanges[1]["tool_call_ids_consumed"]
        != []
    )


def test_a_rejected_content_record_is_retired_and_read_as_not_captured_store_failed(
    tmp_path: Path, built: dict[str, Any], provider: Provider, sink: Sink
) -> None:
    """Spec 055 §7.1: a body the Node refuses for good (here every content request is
    answered 400, so each is resent alone and refused again) is settled, never retried
    forever; its span is still exported unchanged and the file retired. The reader then
    reports each side ``not_captured(store_failed)``, never stored."""
    (sink.directory / "fault-logs").write_text("400")
    spool = tmp_path / "spool"
    result = run_agent(built, agent_env(tmp_path, provider, sink, spool), provider)
    assert [s["body"].encode() for s in result["seen"]] == [RESPONSE_JSON, RESPONSE_SSE]
    assert result["stop"]["backlog"] == 0
    assert not list(spool.glob("*.rec"))
    rows = sink.rows()
    assert not [r for r in rows if r.get("kind") == "log"]  # nothing was stored
    spans = [
        r for r in rows if r.get("kind") == "span" and r["name"] == "fabric.model_call"
    ]
    assert len(spans) == len(REQUESTS)
    assert all(s["attributes"]["fabric.wire.store_status"] == "stored" for s in spans)
    projection = tmp_path / "projection.json"
    code, report, stderr = reconstruct(rows, tmp_path, "--projection", str(projection))
    assert code == 1, stderr  # the record is not complete: its bodies are missing
    (run,) = report["runs"]
    assert run["run_state"] == "terminated"
    assert {g["gap_type"] for g in run["gaps"]} == {"missing_object"}, run["gaps"]
    document = json.loads(projection.read_text())
    sides = [
        (step["layers"]["content"][role]["status"], step["layers"]["content"][role]["reason"])
        for step in document["steps"] if step["step_kind"] == "model_call"
        for role in ("model.exchange.request", "model.exchange.response")
    ]  # fmt: skip
    assert sides == [("not_captured", "store_failed")] * 2 * len(REQUESTS), sides


# --------------------------------------------------------------------------- parity

PY_CAPTURE = """
import json, sys
import httpx
from fabric import wire
args = json.loads(sys.argv[1])
handle = wire.install_from_env()
assert handle is not None
with httpx.Client() as client, wire.run(args["runId"]):
    for body in args["requests"]:
        client.post(args["base"] + "/v1/chat/completions", content=body.encode(),
                    headers={"content-type": "application/json",
                             "authorization": "Bearer sk-test-e2e"}).read()
handle.close(2.0)
"""

PY_FRAMES = """
import json, struct, sys
from fabric.wire._spool import BATCH_MAGIC, Spool, frame, unframe_all
spool = Spool(sys.argv[1], 1 << 30, key=bytes.fromhex(sys.argv[2]))
out = []

def frames(data):
    # Each record's frame bytes as the file holds them (one frame, or a batch file's).
    if not data.startswith(BATCH_MAGIC):
        return [data]
    found, offset = [], 12
    for _ in range(struct.unpack(">I", data[8:12])[0]):
        (size,) = struct.unpack(">Q", data[offset : offset + 8])
        found.append(data[offset + 8 : offset + 8 + size])
        offset += 8 + size
    return found

try:
    for name in spool.names():
        data = spool.read(name)
        for (doc, blob), raw in zip(unframe_all(data), frames(data), strict=True):
            if doc["record_kind"] == "exchange":
                out.append({"doc": doc, "blob": bytes(blob).hex(), "frame": bytes(raw).hex(),
                            "python_frame": b"".join(frame(doc, [bytes(blob)])).hex()})
finally:
    spool.release()
print(json.dumps(out))
"""

PY_REFRAME = """
import json, sys
from fabric.wire._spool import frame, unframe
doc, bodies = json.loads(sys.argv[1])
data = b"".join(frame(doc, [bytes.fromhex(b) for b in bodies]))
unframe(data)  # a frame Python's own reader accepts (header contract, body ranges)
print(data.hex())
"""

# §7.3's substitution: values minted per capture (ids, the source epoch, times, the
# writer's file order) and the producer's capture-point label. Each distinct value is
# replaced by its category and order of first appearance, so references stay consistent.
_MINTED = {
    "exchange_id": "id", "fabric.wire.exchange_id": "id", "operation_id": "id",
    "event_id": "event", "fabric.event_id": "event",
    "span_id": "span", "trace_id": "trace", "parent_span_id": "span",
    "object_id": "object", "fabric.content.request_ref": "object",
    "fabric.content.result_ref": "object",
    "scope_id": "scope", "fabric.run.scope_id": "scope",
    "segment_id": "segment", "fabric.run.segment_id": "segment",
    "source_epoch": "epoch", "fabric.source.epoch": "epoch",
    "start_time_unix_nano": "time", "end_time_unix_nano": "time", "captured_at": "time",
    "written_at_unix_nano": "time", "order": "order",
    "fabric.wire.first_chunk_offset_ns": "time", "fabric.capture.point": "point",
}  # fmt: skip


def _substitute(category: str, n: int, value: Any) -> Any:
    """A valid value of the same form, the ``n``-th of its category."""
    if category in ("id", "event", "object", "scope"):
        return f"00000000-0000-4000-8000-{n:012x}"
    if category == "span":
        return f"{n + 1:016x}"
    if category == "trace":
        return f"{n + 1:032x}"
    if category == "segment":
        return f"seg-{n + 1:032x}"
    if category == "point":
        return "wire.substituted@0.0.0"
    if isinstance(value, str):  # captured_at
        return f"2026-01-01T00:00:{n % 60:02d}.000000+00:00"
    return n + 1  # epoch, times, order


def substituted(doc: Any) -> Any:
    seen: dict[tuple[str, Any], Any] = {}

    def walk(value: Any, key: str | None = None) -> Any:
        if key in _MINTED and not isinstance(value, dict | list):
            category = _MINTED[key]
            if (category, value) not in seen:
                seen[(category, value)] = _substitute(category, len(seen), value)
            return seen[(category, value)]
        if isinstance(value, dict):
            return {k: walk(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v, key) for v in value]
        return value

    return walk(doc)


def frames_of(spool: Path) -> list[dict[str, Any]]:
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-c", PY_FRAMES, str(spool), SPOOL_KEY.hex()],
        capture_output=True, text=True, timeout=60, check=True,
    )  # fmt: skip
    found: list[dict[str, Any]] = json.loads(done.stdout)
    return sorted(
        found, key=lambda f: f["doc"]["span"]["attributes"]["fabric.source.sequence"]
    )


def reframed(doc: dict[str, Any], blob: str) -> str:
    bodies = [
        blob[2 * b["offset"] : 2 * (b["offset"] + b["length"])] for b in doc["bodies"]
    ]
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-c", PY_REFRAME, json.dumps([doc, bodies])],
        capture_output=True, text=True, timeout=60, check=True,
    )  # fmt: skip
    return done.stdout.strip()


def closed_port() -> int:
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


def test_python_and_node_write_the_same_frames_for_the_same_fixture(
    tmp_path: Path, built: dict[str, Any], provider: Provider
) -> None:
    # Both capture into their spools and deliver nowhere (a closed port): the records
    # stay, so the frames are compared as written.
    class Nowhere:
        port = closed_port()
        tls = tmp_path / "tls"

    write_tls(Nowhere.tls)
    env = agent_env(tmp_path, provider, Nowhere, tmp_path / "node-spool")  # type: ignore[arg-type]
    env["FABRIC_SOURCE_ID"] = "parity-agent"
    # The close budget only bounds the wait for a Node that never answers; the worker
    # spools both exchanges first. Generous, so a loaded machine still spools them.
    node = run_agent(built, env, provider, flush=False, closeTimeoutMs=3000)
    assert node["closed"] is False  # nothing could be delivered
    py_env = {**env, "FABRIC_WIRE_SPOOL_DIR": str(tmp_path / "py-spool")}
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-c", PY_CAPTURE,
         json.dumps({"base": provider.base, "runId": RUN_ID, "requests": REQUESTS})],
        env=py_env, capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    assert provider.received == [r.encode() for r in REQUESTS] * 2

    node_frames = frames_of(tmp_path / "node-spool")
    py_frames = frames_of(tmp_path / "py-spool")
    assert len(node_frames) == len(py_frames) == len(REQUESTS), (node, len(py_frames))
    for ts, py in zip(node_frames, py_frames, strict=True):
        # The frame Node wrote is, byte for byte, the frame Python's writer makes of the
        # same header and bodies (canonical JSON header, length, bodies, digest).
        assert ts["frame"] == ts["python_frame"]
        assert ts["blob"] == py["blob"]  # the protected bodies, byte for byte
        ts_doc, py_doc = substituted(ts["doc"]), substituted(py["doc"])
        assert ts_doc == py_doc
        # The whole frame, as Python's writer frames the substituted header and bodies.
        assert reframed(ts_doc, ts["blob"]) == reframed(py_doc, py["blob"])


PY_RUN = """
import json, sys
import httpx
from fabric import wire
args = json.loads(sys.argv[1])
handle = wire.install_from_env()
assert handle is not None
with httpx.Client() as client, wire.run(args["runId"]):
    for body in args["requests"]:
        client.post(args["base"] + "/v1/chat/completions", content=body.encode(),
                    headers={"content-type": "application/json",
                             "authorization": "Bearer sk-test-e2e"}).read()
    token = wire.resume_token()
ended = wire.end_run(None, "completed", resume=[token], stop_reason="goal_reached")
assert ended == "ended", ended
assert handle.flush(20.0)
assert handle.close(20.0)
"""


def test_python_and_node_runs_project_the_same(
    tmp_path: Path, built: dict[str, Any], provider: Provider
) -> None:
    """Spec 055 §9.2 ``ts-wire-parity``: the same tool loop captured by Node and by
    Python, each delivered to its own recording sink, reconstructs to the same projection
    after the §7.3 substitution (minted ids, the source epoch, timings and the capture
    point label); privacy modes, statuses, counts, locators and digests are compared as
    they are."""
    projections = []
    for side in ("node", "python"):
        root = tmp_path / side
        root.mkdir()
        tls = root / "tls"
        write_tls(tls)
        sink = Sink(root / "sink", tls, EGRESS_AUTH)
        sink.directory.mkdir()
        sink.start()
        try:
            env = agent_env(root, provider, sink, root / "spool")
            env["FABRIC_SOURCE_ID"] = "parity-agent"
            if side == "node":
                result = run_agent(built, env, provider)
                assert result["closed"] is True, result
            else:
                done = subprocess.run(  # noqa: S603
                    [sys.executable, "-c", PY_RUN, json.dumps(
                        {"base": provider.base, "runId": RUN_ID, "requests": REQUESTS})],
                    env=env, capture_output=True, text=True, timeout=120, check=False,
                )  # fmt: skip
                assert done.returncode == 0, done.stderr
            rows = sink.rows()
        finally:
            sink.stop()
        out = root / "projection.json"
        code, report, stderr = reconstruct(rows, root, "--projection", str(out))
        assert code == 0, (side, stderr, report.get("runs"))
        projections.append(json.loads(out.read_text()))
    node, python = (projected(p) for p in projections)
    assert node == python


_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_PROJECTION_MINTED = re.compile(
    rf"(?P<uuid>{_UUID})|(?P<seg>seg-[0-9a-f]{{32}})|(?P<span>(?<=/)[0-9a-f]{{16}}$)"
    r"|(?P<point>wire\.(?:ts|py)\.[a-z_]+@[0-9][0-9A-Za-z.+-]*)"
)
# Values a projection mints or derives from the capture's own manifests: the minted ids
# (inside any string), times, the source epoch, the capture point label, and the
# manifests and digests over them (each SDK declares its own capture points, so its
# manifest documents differ by design). Content digests, statuses, reasons, counts,
# locators and privacy modes are compared as they are (spec 055 §7.3).
_PROJECTION_TIMES = {"started_at_ns", "ended_at_ns", "generated_at", "evaluated_at"}
_PROJECTION_DERIVED = {
    "manifests",
    "manifest_digest",
    "seal_digest",
    "reconstruction_sha256",
}
_PROJECTION_VALUES = {
    "started_at",
    "ended_at",
    "source_epoch",
    "stream.first_chunk_offset_ns",
}


def projected(document: dict[str, Any]) -> Any:
    seen: dict[str, str] = {}

    def minted(match: re.Match[str]) -> str:
        kind = match.lastgroup or ""
        if kind == "point":
            return "wire.substituted@0.0.0"
        key = match.group(0)
        if key not in seen:
            seen[key] = (
                f"<{kind}-{sum(1 for v in seen.values() if v.startswith(f'<{kind}-'))}>"
            )
        return seen[key]

    def walk(value: Any, key: str | None = None, parent: str | None = None) -> Any:
        if key in _PROJECTION_TIMES or key in _PROJECTION_DERIVED:
            return f"<{key}>"
        if (key == "value" and parent in _PROJECTION_VALUES) or (
            key == "source_epoch" and isinstance(value, int)
        ):
            return f"<{parent if key == 'value' else key}>"
        if key == "predecessors":
            return ["none" if p == "none" else "<predecessor>" for p in value]
        if isinstance(value, dict):
            return {k: walk(v, k, key) for k, v in value.items()}
        if isinstance(value, list):
            items = [walk(v, key, parent) for v in value]
            # A run's segments are listed by their (random) ids: order them by role.
            return sorted(items, key=json.dumps) if key == "segments" else items
        if isinstance(value, str):
            return _PROJECTION_MINTED.sub(minted, value)
        return value

    # Segments first, in role order, so minted ids are numbered alike on both sides.
    for run in document.get("runs", ()):
        run["segments"] = sorted(
            run.get("segments", ()),
            key=lambda g: (g.get("terminal"), g.get("predecessors")),
        )
    return walk(document)
