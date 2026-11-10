# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Short-lived workers (field finding F1): a process that exits with records still in the
spool leaves them for the next process capturing to or draining it. A serverless function,
batch job or autoscaled worker has no next process, so that backlog was lost silently.

Passivity (spec 057 B1-B4) keeps the default exit budget: the exit is never delayed by
default. What changes: the loss is visible (the spool's exit note, read by ``python -m
fabric.wire status``; a diagnostic on Fabric's own channel, never the agent's stderr by
default), and ``FABRIC_WIRE_DRAIN_ON_EXIT_S`` is the explicit opt-in to wait at exit."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from fabric.wire._spool import EXIT_NOTE, Spool, read_exit_note

from ._wire_live import FakeModel, capture_env, run_agent

CALLS = 12
AGENT = textwrap.dedent(
    f"""
    import os
    from openai import OpenAI

    client = OpenAI(base_url=os.environ["LIVE_MODEL_BASE"], api_key="sk-live-fake")
    for i in range({CALLS}):
        client.chat.completions.create(model="m", messages=[{{"role": "user", "content": str(i)}}])
    print("done", flush=True)
    """
)


class SlowSink:
    """An OTLP/HTTP trace sink that takes ``delay_s`` to answer each request and counts the
    ``fabric.model_call`` spans it accepted."""

    def __init__(self, delay_s: float) -> None:
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (  # noqa: PLC0415
            ExportTraceServiceRequest,
        )

        self.delay_s, self.model_calls, self.lock = delay_s, 0, threading.Lock()
        sink = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                return

            def do_POST(self) -> None:
                data = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                time.sleep(sink.delay_s)
                request = ExportTraceServiceRequest.FromString(data)
                calls = sum(1 for rs in request.resource_spans for ss in rs.scope_spans
                            for span in ss.spans if span.name == "fabric.model_call")  # fmt: skip
                with sink.lock:
                    sink.model_calls += calls
                self.send_response(200)
                self.send_header("Content-Type", "application/x-protobuf")
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_address[1]}/v1/traces"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _records(spool: Path) -> int:
    return sum(1 for p in spool.glob("*.rec") if not p.name.startswith("."))


def _status(env: dict[str, str]) -> dict[str, Any]:
    proc = subprocess.run([sys.executable, "-m", "fabric.wire", "status"], env=env,
                          capture_output=True, text=True, timeout=60, check=False)  # fmt: skip
    document: dict[str, Any] = json.loads(proc.stdout)
    return document


@pytest.fixture
def model() -> Any:
    created = FakeModel()
    yield created
    created.close()


def _env(model: FakeModel, sink: SlowSink, tmp_path: Path, **extra: str) -> dict[str, str]:
    (store := tmp_path / "store").mkdir(exist_ok=True)
    return capture_env(model, sink, store, FABRIC_WIRE_SPOOL_DIR=str(tmp_path / "spool"),  # type: ignore[arg-type]
                       FABRIC_WIRE_SHUTDOWN_TIMEOUT_S="2", **extra)  # fmt: skip


def test_default_exit_is_not_delayed_and_the_backlog_left_is_visible(
    model: FakeModel, tmp_path: Path
) -> None:
    sink = SlowSink(delay_s=20.0)  # the destination cannot take anything before exit
    try:
        (script := tmp_path / "agent.py").write_text(AGENT, encoding="utf-8")
        env = _env(model, sink, tmp_path)
        started = time.monotonic()
        result = run_agent(script, env)
        elapsed = time.monotonic() - started
        assert result["returncode"] == 0 and result["stdout"] == "done\n", result
        assert "fabric" not in result["stderr"]  # nothing on the agent's stderr by default
        # The default exit budget (2 s) bounds the wait, with the agent's own run time.
        assert elapsed < 15.0, elapsed
        spool = tmp_path / "spool"
        left = _records(spool)
        assert left > 0
        note = read_exit_note(str(spool))
        assert note is not None and note["records_left"] == left
        assert note["drain_on_exit_s"] == 0.0
        status = _status(env)
        assert status["wire"]["spool"]["records"] == left
        assert status["wire"]["spool"]["left_at_exit"]["records_left"] == left
        (warning,) = [w for w in status["warnings"] if "left" in w and "spool" in w]
        assert "FABRIC_WIRE_DRAIN_ON_EXIT_S" in warning and "fabric.wire drain" in warning
        assert sink.endpoint.split("/v1")[0] not in json.dumps(status)
    finally:
        sink.close()


def test_the_exit_backlog_diagnostic_is_opt_in_and_names_no_endpoint(
    model: FakeModel, tmp_path: Path
) -> None:
    sink = SlowSink(delay_s=20.0)
    try:
        (script := tmp_path / "agent.py").write_text(AGENT, encoding="utf-8")
        env = _env(model, sink, tmp_path, FABRIC_WIRE_DIAGNOSTICS="stderr")
        result = run_agent(script, env)
        assert result["returncode"] == 0, result
        lines = [ln for ln in result["stderr"].splitlines() if "left in the spool at exit" in ln]
        assert len(lines) == 1, result["stderr"][-2000:]
        assert f"{_records(tmp_path / 'spool')} records" in lines[0]
        assert "127.0.0.1" not in result["stderr"] and "sk-live-fake" not in result["stderr"]
    finally:
        sink.close()


def test_drain_on_exit_delivers_the_backlog_before_exit(model: FakeModel, tmp_path: Path) -> None:
    sink = SlowSink(delay_s=0.5)  # slower than the 2 s budget allows for every export
    try:
        (script := tmp_path / "agent.py").write_text(AGENT, encoding="utf-8")
        env = _env(model, sink, tmp_path, FABRIC_WIRE_DRAIN_ON_EXIT_S="60")
        result = run_agent(script, env)
        assert result["returncode"] == 0 and "fabric" not in result["stderr"], result
        assert _records(tmp_path / "spool") == 0
        assert not (tmp_path / "spool" / EXIT_NOTE).exists()
        assert sink.model_calls == CALLS
    finally:
        sink.close()


def test_a_later_drain_delivers_the_backlog_and_clears_the_note(
    model: FakeModel, tmp_path: Path
) -> None:
    slow = SlowSink(delay_s=20.0)
    try:
        (script := tmp_path / "agent.py").write_text(AGENT, encoding="utf-8")
        run_agent(script, _env(model, slow, tmp_path))
    finally:
        slow.close()
    assert read_exit_note(str(tmp_path / "spool")) is not None
    fast = SlowSink(delay_s=0.0)
    try:
        env = _env(model, fast, tmp_path)
        proc = subprocess.run([sys.executable, "-m", "fabric.wire", "drain", "--until-empty",
                               "--timeout", "60"], env=env, capture_output=True, text=True,
                              timeout=120, check=False)  # fmt: skip
        assert proc.returncode == 0, proc.stderr
        assert _records(tmp_path / "spool") == 0 and fast.model_calls == CALLS
        assert read_exit_note(str(tmp_path / "spool")) is None
        status = _status(env)
        assert status["wire"]["spool"] == {"records": 0}
        assert not [w for w in status["warnings"] if "left" in w and "spool" in w]
    finally:
        fast.close()


def test_a_live_drainer_elsewhere_means_no_backlog_is_reported(tmp_path: Path) -> None:
    drainer = Spool(str(tmp_path / "spool"), 8 << 20)
    worker = Spool(str(tmp_path / "spool"), 8 << 20)
    try:
        assert not worker.drained_elsewhere()  # nobody drains yet
        assert drainer.try_lock()
        assert worker.drained_elsewhere()  # the drainer delivers what the worker leaves
        assert not drainer.drained_elsewhere()  # the holder itself is the drainer
        drainer.release()
        assert not worker.drained_elsewhere()
        assert worker.try_lock()  # the probe never kept the lock
    finally:
        drainer.release()
        worker.release()


def test_an_exit_note_that_is_not_one_is_ignored(tmp_path: Path) -> None:
    spool = Spool(str(tmp_path / "spool"), 8 << 20)
    spool.write_exit_note(7, 0.0)
    assert read_exit_note(spool.dir) == {"records_left": 7, "exited_at": read_exit_note(
        spool.dir)["exited_at"], "drain_on_exit_s": 0.0}  # type: ignore[index]  # fmt: skip
    for bad in (b"{", b"[]", b'{"schema": "x"}', b'{"schema": "fabric.wire-exit-backlog/v1",'
                b' "records_left": -1, "exited_at": "t", "drain_on_exit_s": 0}'):  # fmt: skip
        (tmp_path / "spool" / EXIT_NOTE).write_bytes(bad)
        assert read_exit_note(spool.dir) is None
    spool.clear_exit_note()
    spool.clear_exit_note()  # idempotent
    assert not (tmp_path / "spool" / EXIT_NOTE).exists()
    spool.release()
