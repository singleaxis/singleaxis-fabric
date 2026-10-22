# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The in-memory window before the durable spool write (spec 048 §2 "Window", Codex r1 #2).

A finished call is handed to the capture worker in memory; the worker digests it and only
then writes the fsync'd spool record. The write stays off the host's thread (passivity), so
a SIGKILL inside that window loses the exchange without a record. These tests kill an agent
with the worker parked inside the window, restart a drainer on the same spool, and run
``fabric.reconstruct`` on everything the Node received: the run is never
``complete_for_declared_scope``. A control run without the kill is complete, so the harness
can produce a complete verdict.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

import fabric
from fabric._sequence import run_pseudonym
from fabric.content_store import LocalFilesystemContentStore
from fabric.reconstruct import reconstruct
from fabric.wire.__main__ import autoload_path

from .test_wire_spool import FakeNode, any_value, records, wait_for

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX spool")

SRC = Path(fabric.__file__).resolve().parents[1]
AGENT = textwrap.dedent(
    """
    import contextlib, os, time, httpx
    from fabric import wire
    handle = wire.current_handle()
    assert handle is not None, "autoload did not install"
    sender = handle._tee.pipeline._sender
    real, seen, block = sender.spool_exchanges, [0], int(os.environ["BLOCK_AT"])

    def spool_exchanges(items):  # one by one, so the window opens at exactly one exchange
        outcomes = []
        for item in items:
            seen[0] += 1
            if seen[0] == block:  # the call has returned to the host; nothing is on disk yet
                print("WINDOW", flush=True)
                time.sleep(600)
            outcomes += real([item])
        return outcomes

    sender.spool_exchanges = spool_exchanges
    reply = (b'{"id":"r","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,'
             b'"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}')
    respond = lambda request: httpx.Response(200, content=reply,
                                             headers={"content-type": "application/json"})
    transport = wire.WireTransport(httpx.MockTransport(respond))
    scope = wire.run("run-window") if os.environ["SCOPED"] == "1" else contextlib.nullcontext()
    with scope, httpx.Client(transport=transport) as client:
        for index in range(3):
            body = {"model": "gpt-4o", "messages": [{"role": "user", "content": f"q{index}"}]}
            assert client.post("https://api.openai.com/v1/chat/completions",
                               json=body).content == reply
    print("CALLS_DONE", flush=True)
    if block:
        time.sleep(600)
    print("CLOSED", handle.close(30.0), flush=True)
    """
)
DRAINER = textwrap.dedent(
    """
    import os, time
    from fabric import wire
    handle = wire.current_handle()
    own, spool = str(handle.allocator.epoch), os.environ["FABRIC_WIRE_SPOOL_DIR"]
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline and any(
        n.endswith(".rec") and not n.startswith((".", own)) for n in os.listdir(spool)
    ):
        time.sleep(0.05)
    print("CLOSED", handle.close(30.0), flush=True)
    """
)


class RecordingNode(FakeNode):
    """FakeNode that also keeps each span as a demo-sink JSONL row for the verifier."""

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[dict[str, Any]] = []

    def receive(self, path: str, data: bytes) -> None:
        super().receive(path, data)
        if path == "/v1/logs":
            return
        for rs in ExportTraceServiceRequest.FromString(data).resource_spans:
            resource = {kv.key: any_value(kv.value) for kv in rs.resource.attributes}
            for ss in rs.scope_spans:
                for span in ss.spans:
                    with self.lock:
                        self.rows.append({
                            "kind": "span", "name": span.name, "trace_id": span.trace_id.hex(),
                            "span_id": span.span_id.hex(),
                            "parent_span_id": span.parent_span_id.hex() or None,
                            "start_ns": span.start_time_unix_nano,
                            "end_ns": span.end_time_unix_nano, "resource": resource,
                            "attributes": {kv.key: any_value(kv.value) for kv in span.attributes},
                        })  # fmt: skip


@pytest.fixture
def node() -> Iterator[RecordingNode]:
    created = RecordingNode()
    yield created
    created.close()


def _env(node: FakeNode, tmp_path: Path, **extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("OTEL_", "FABRIC_", "AWS_"))}
    return {
        **env, "PYTHONPATH": os.pathsep.join([autoload_path(), str(SRC)]),
        "FABRIC_WIRE_AUTOLOAD": "1", "FABRIC_TENANT_ID": "tenant-a",
        "FABRIC_WIRE_STORE": (tmp_path / "store").as_uri(),
        "FABRIC_WIRE_SPOOL_DIR": str(tmp_path / "spool"), "FABRIC_SOURCE_ID": "window-agent",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": node.url + "/v1/traces",
        "OTEL_EXPORTER_OTLP_TIMEOUT": "2", **extra,
    }  # fmt: skip


def _start(script: str, env: dict[str, str]) -> subprocess.Popen[str]:
    return subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", script], env=env, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )  # fmt: skip


def _read_until(process: subprocess.Popen[str], *markers: str) -> None:
    """Read stdout until every marker has been printed (in any order)."""
    assert process.stdout is not None
    pending = set(markers)
    for line in process.stdout:
        pending.discard(line.strip())
        if not pending:
            return
    raise AssertionError(f"agent ended early: {process.stderr.read() if process.stderr else ''}")


COMPLETE = ("complete_for_declared_scope", "complete_for_observed_scopes")


def _exchange_ids(node: RecordingNode) -> set[str]:
    return {str(span["fabric.wire.exchange_id"]) for span in node.named("fabric.model_call")}


def _verdicts(node: RecordingNode, tmp_path: Path) -> dict[str, dict[str, Any]]:
    spans = tmp_path / "spans.jsonl"
    with node.lock:
        spans.write_text("".join(json.dumps(row) + "\n" for row in node.rows), "utf-8")
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    report = reconstruct([spans], store=store, tenant_id="tenant-a")
    return {run["run_id"]: run for run in report["runs"]}


def _agent_runs(runs: dict[str, dict[str, Any]], scoped: str) -> list[dict[str, Any]]:
    window = run_pseudonym("run-window")  # reports carry the run id's pseudonym only
    if scoped == "1":
        return [runs[window]]
    return [run for run_id, run in runs.items() if run_id != window]


@pytest.mark.parametrize(
    ("scoped", "block_at", "expected"),
    [
        ("1", 3, "partial"),  # run_end is durable, the last exchange is not: a gap in-window
        ("1", 2, "partial"),  # the worker parks on call 2: calls 2 and 3 stay in memory
        # No run markers and no final heartbeat, but the drainer declares the killed epoch an
        # orphan (050 §3.2 rule 5): its periodic heartbeat at the last allocated position
        # makes the in-window exchange a visible gap (T2), and partial beats unverified.
        ("0", 3, "partial"),
    ],
)
def test_sigkill_inside_the_window_is_never_complete(
    node: RecordingNode, tmp_path: Path, scoped: str, block_at: int, expected: str
) -> None:
    agent = _start(AGENT, _env(node, tmp_path, SCOPED=scoped, BLOCK_AT=str(block_at)))
    try:
        _read_until(agent, "CALLS_DONE", "WINDOW")  # every call returned to the host
        if scoped == "1":  # worst case: the run's closing marker is already delivered
            assert wait_for(lambda: any(
                b.get("fabric.heartbeat.kind") == "run_end"
                for b in node.named("fabric.capture_heartbeat")
            ), 30)  # fmt: skip
        delivered = block_at - 1
        assert wait_for(lambda: len(_exchange_ids(node)) == delivered, 30)
        os.kill(agent.pid, signal.SIGKILL)  # inside the window: worker parked before the write
        agent.wait(10)
    finally:
        if agent.poll() is None:
            agent.kill()
    drainer = _start(DRAINER, _env(node, tmp_path, FABRIC_SOURCE_ID="window-drainer"))
    out, err = drainer.communicate(timeout=90)
    assert "CLOSED True" in out, err
    assert records(tmp_path / "spool") == []
    # The exchanges still in memory at the kill (in the window) are gone. A
    # delivered record the kill caught before its deletion is re-sent by the
    # drainer (at-least-once, 048 §2), so count distinct exchanges.
    assert len(_exchange_ids(node)) == block_at - 1
    runs = _agent_runs(_verdicts(node, tmp_path), scoped)
    assert runs
    for run in runs:
        assert run["verdict"] not in COMPLETE
        assert run["verdict"] == expected
        if scoped == "0":  # T2: the lost position is a gap, the end past it still unproven
            found = {(g["gap_type"], g["effect"], g.get("first_sequence"), g.get("last_sequence"))
                     for g in run["gaps"]}  # fmt: skip
            assert ("sequence_gap", "partial", block_at - 1, block_at - 1) in found
            assert ("tail_unverified", "unverified", None, None) in found


@pytest.mark.parametrize("scoped", ["1", "0"])
def test_control_run_without_the_kill_is_complete(
    node: RecordingNode, tmp_path: Path, scoped: str
) -> None:
    agent = _start(AGENT, _env(node, tmp_path, SCOPED=scoped, BLOCK_AT="0"))
    out, err = agent.communicate(timeout=90)
    assert "CLOSED True" in out, err
    runs = _agent_runs(_verdicts(node, tmp_path), scoped)
    # H5: a scoped run claims at most its observed scopes; an unscoped one its epoch.
    best = "complete_for_observed_scopes" if scoped == "1" else "complete_for_declared_scope"
    assert [run["verdict"] for run in runs] == [best]
