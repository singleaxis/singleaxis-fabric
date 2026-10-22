# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Wire-tee regressions for review findings: passivity, fork, sampling, autoload."""

from __future__ import annotations

import gc
import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_OFF

from fabric import wire
from fabric._loss import LossEmitter
from fabric._sequence import SourceAllocator
from fabric.wire import _stream
from fabric.wire.__main__ import autoload_path
from fabric.wire._transport import WireTee, WireTransport

from .test_wire_helpers import OPENAI_CHAT, ChunkStream, Rig, attrs, make_rig

SRC = Path(wire.__file__).resolve().parents[2]


@pytest.fixture
def rig(tmp_path: Path) -> Any:
    built = make_rig(tmp_path)
    yield built
    built.close()


def test_abandoned_stream_finalized_by_gc_never_takes_capture_locks(rig: Rig) -> None:
    """GC may run the finalizer on a thread that already holds a capture lock."""
    chunks = [b"data: 1\n\n", b"data: 2\n\n"]
    with rig.client(lambda r: httpx.Response(200, stream=ChunkStream(chunks))) as client:
        response = client.send(client.build_request("POST", OPENAI_CHAT, json={}), stream=True)
        response.cycle = response  # type: ignore[attr-defined] # only cyclic GC frees it
        del response
    finished = threading.Event()

    def collect_while_holding_locks() -> None:
        # Both locks are non-reentrant; a finalizer taking either would deadlock here.
        with rig.loss._lock, _stream._FINISH_LOCK:
            gc.collect()
        finished.set()

    worker = threading.Thread(target=collect_while_holding_locks, daemon=True)
    worker.start()
    worker.join(5.0)
    assert finished.is_set(), "GC finalizer deadlocked on a capture lock"
    deadline = time.monotonic() + 5
    while rig.tee.stats()["submitted"] < 1 and time.monotonic() < deadline:
        time.sleep(0.005)
    rig.flush()
    assert [attrs(s)["fabric.wire.response_state"] for s in rig.spans()] == ["abandoned"]


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_fork_child_reinitializes_wire_locks() -> None:
    script = textwrap.dedent(
        """
        import os, warnings
        warnings.simplefilter("ignore")
        from fabric import _sequence
        from fabric.wire import _stream
        allocator = _sequence.SourceAllocator("fork-src", "wire")
        allocator.next_sequence()
        parent_epoch = allocator.epoch
        _stream._FINISH_LOCK.acquire()  # held by "another thread" at fork time
        allocator._lock.acquire()
        pid = os.fork()
        if pid == 0:
            ok = _stream._FINISH_LOCK.acquire(timeout=2) and _stream._REAPER_PID is None
            epoch, sequence, _ = allocator.next_sequence()
            os._exit(0 if ok and epoch > parent_epoch and sequence == 0 else 1)
        _, status = os.waitpid(pid, 0)
        print("child", os.waitstatus_to_exitcode(status))
        """
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        env={**os.environ, "PYTHONPATH": str(SRC)},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.stdout.strip() == "child 0", result.stderr


class _Holder:
    """An openai.Stream-style object: it and its iterator form a cycle only GC frees."""


@pytest.mark.parametrize("held", ["loss", "finish", "queue", "budget"])
def test_started_stream_collected_by_gc_never_takes_capture_locks(rig: Rig, held: str) -> None:
    """Review fix: GeneratorExit raised inside cyclic GC must not finish synchronously."""
    chunks = [b"data: 1\n\n", b"data: 2\n\n"]
    with rig.client(lambda r: httpx.Response(200, stream=ChunkStream(chunks))) as client:
        response = client.send(client.build_request("POST", OPENAI_CHAT, json={}), stream=True)
        holder = _Holder()
        holder.it = response.iter_raw()  # type: ignore[attr-defined]
        assert next(holder.it) == chunks[0]  # type: ignore[attr-defined]
        holder.cycle, holder.response = holder, response  # type: ignore[attr-defined]
        del holder, response
    lock = {
        "loss": rig.loss._lock,
        "finish": _stream._FINISH_LOCK,
        "queue": rig.tee.pipeline._queue.mutex,
        "budget": rig.tee.budget._lock,
    }[held]
    finished = threading.Event()

    def collect_while_holding() -> None:
        with lock:  # non-reentrant: a synchronous finish inside GC would deadlock here
            gc.collect()
        finished.set()

    gc.disable()
    try:
        worker = threading.Thread(target=collect_while_holding, daemon=True)
        worker.start()
        worker.join(5.0)
    finally:
        gc.enable()
    assert finished.is_set(), "GC-finalized generator deadlocked on a capture lock"
    rig.flush()
    states = [attrs(s)["fabric.wire.response_state"] for s in rig.spans()]
    assert states in (["closed_early"], ["abandoned"])
    assert rig.tee.stats()["inflight_bytes"] == 0


def test_close_does_not_wait_out_the_deadline_on_a_stream_awaiting_gc(tmp_path: Path) -> None:
    """Review fix: an unreachable open stream no longer stalls close for the whole timeout."""
    rig = make_rig(tmp_path, store=None)
    with rig.client(lambda r: httpx.Response(200, stream=ChunkStream([b"a", b"b"]))) as client:
        response = client.send(client.build_request("POST", OPENAI_CHAT, json={}), stream=True)
        holder = _Holder()
        holder.cycle, holder.response = holder, response  # type: ignore[attr-defined]
        del holder, response
    gc.disable()
    try:
        started = time.monotonic()
        closed = rig.tee.close(2.0)
        assert closed is False
        assert time.monotonic() - started < 1.0
    finally:
        gc.enable()
    assert rig.loss_counts() == {"shutdown": 1}
    assert rig.tee.stats()["inflight_bytes"] == 0


def test_close_never_reports_an_exchange_that_finished_after_the_snapshot(rig: Rig) -> None:
    """Review fix: only exchanges close() itself claims become shutdown losses."""
    with rig.client(lambda r: httpx.Response(200, json={"choices": []})) as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    rig.flush()
    (finished,) = rig.spans()
    exchange = _stream.Exchange.__new__(_stream.Exchange)
    exchange.done, exchange.finalizer = True, None  # already finished and submitted
    rig.tee._active.add(exchange)  # still in close()'s snapshot when it finished
    closed = rig.tee.close(1.0)
    assert closed is True
    assert rig.loss_counts() == {}
    assert len(rig.spans()) == 1 and finished in rig.spans()


class _BlockingExporter(SpanExporter):
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.spans: list[ReadableSpan] = []

    def export(self, spans: Any) -> SpanExportResult:
        self.entered.set()
        self.release.wait(5)
        self.spans.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


def test_close_never_reports_a_job_the_worker_is_still_finishing() -> None:
    exporter = _BlockingExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    loss_exporter = InMemorySpanExporter()
    loss_provider = TracerProvider()
    loss_provider.add_span_processor(SimpleSpanProcessor(loss_exporter))
    loss = LossEmitter(tracer_provider=loss_provider)
    config = wire.WireConfig(store=None, tracer_provider=provider, patch_httpx=False)
    tee = WireTee(config, allocator=SourceAllocator("wire-race", "wire"), loss=loss)
    handle = wire.WireHandle(config, tee, patched=False)
    transport = WireTransport(
        httpx.MockTransport(lambda r: httpx.Response(200, json={})), handle=handle
    )
    with httpx.Client(transport=transport) as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert exporter.entered.wait(5)  # the worker is inside span.end()
    closed = tee.pipeline.close(0.05)
    assert closed is False  # deadline expires mid-emit
    exporter.release.set()
    tee.pipeline._worker.join(5)
    assert loss.flush(1.0)
    assert len(exporter.spans) == 1
    assert [s.name for s in loss_exporter.get_finished_spans()] == ["fabric.capture_heartbeat"]
    loss.close(0.5)


def test_sampled_out_exchange_span_is_a_span_dropped_loss(tmp_path: Path) -> None:
    rig = make_rig(tmp_path, store=None)
    sampled_out = TracerProvider(sampler=ALWAYS_OFF)
    rig.tee.pipeline._provider = sampled_out  # a host sampler under FABRIC_WIRE_TRACER=global
    try:
        with rig.client(lambda r: httpx.Response(200, json={})) as client:
            client.post(OPENAI_CHAT, json={"messages": []})
        rig.flush()
        assert rig.spans() == []
        assert rig.loss_counts() == {"span_dropped": 1}
        assert rig.tee.stats()["spans_emitted"] == 0
    finally:
        rig.close()


def test_sampled_out_loss_spans_warn_and_do_not_cascade(
    caplog: pytest.LogCaptureFixture,
) -> None:
    loss = LossEmitter(tracer_provider=TracerProvider(sampler=ALWAYS_OFF))
    caplog.set_level("WARNING", logger="fabric.capture")
    loss.record("wire-sampled", 1, "queue_full", 3)
    loss.record("wire-sampled", 1, "shutdown", 4)
    assert not loss.flush(2.0)  # E10: sampled-away records are a failed flush
    assert loss.spans_unsampled == 2
    assert not loss._pending  # nothing was re-reported
    assert len([r for r in caplog.records if r.name == "fabric.capture"]) == 1
    loss.close(0.5)


def _python(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    base = {k: v for k, v in os.environ.items() if not k.startswith(("FABRIC_", "OTEL_"))}
    base.pop("PYTHONPATH", None)
    base.update(env)
    code = "import builtins; print(getattr(builtins, 'CHAINED', False))"
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", code],
        env=base,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_autoload_reachable_twice_via_symlink_chains_once(tmp_path: Path) -> None:
    alias = tmp_path / "alias"
    alias.symlink_to(autoload_path(), target_is_directory=True)
    other = tmp_path / "other"
    other.mkdir()
    (other / "sitecustomize.py").write_text("import builtins\nbuiltins.CHAINED = True\n")
    pythonpath = os.pathsep.join([autoload_path(), str(alias), str(other), str(SRC)])
    for env in (
        {"PYTHONPATH": pythonpath},
        {"PYTHONPATH": pythonpath, "FABRIC_WIRE_AUTOLOAD": "1", "FABRIC_WIRE_TRACER": "global"},
    ):
        result = _python(env)
        assert result.returncode == 0, result.stderr
        assert "RecursionError" not in result.stderr
        assert "already installed" not in result.stderr
        assert result.stdout.strip() == "True", result.stderr
