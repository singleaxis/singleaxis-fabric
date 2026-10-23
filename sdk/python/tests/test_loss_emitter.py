# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Loss ranges and heartbeats: shape, coalescing, run markers, passivity (spec 047 §6)."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.context import Context
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import _loss
from fabric._loss import SPAN_HEARTBEAT, SPAN_LOSS, LossAttr, LossEmitter, get_loss_emitter
from fabric._sequence import RunScope, SourceAllocator

from .test_wire_helpers import capture_schemas, load_validator, loss_document

VALIDATOR, SCHEMAS = load_validator(), capture_schemas()
SPAN_KEYS = {
    "fabric.source_id", "fabric.source.epoch", "fabric.run.id", "fabric.run.scope_id",
    LossAttr.REASON, LossAttr.COUNT,
    LossAttr.FIRST_SEQUENCE, LossAttr.LAST_SEQUENCE, LossAttr.HEARTBEAT_LAST_SEQUENCE,
    LossAttr.HEARTBEAT_KIND, LossAttr.EVENT_ID,  # every marker's persisted uuid4 (050 R2)
}  # fmt: skip


def _attrs(span: ReadableSpan) -> dict[str, Any]:
    return dict(span.attributes or {})


@pytest.fixture
def exporter() -> InMemorySpanExporter:
    return InMemorySpanExporter()


@pytest.fixture
def emitter(exporter: InMemorySpanExporter) -> Iterator[LossEmitter]:
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    created = LossEmitter(tracer_provider=provider)
    yield created
    created.close(0.5)


def _named(exporter: InMemorySpanExporter, name: str) -> list[dict[str, Any]]:
    return [_attrs(s) for s in exporter.get_finished_spans() if s.name == name]


def _validate_all(exporter: InMemorySpanExporter) -> None:
    for span in exporter.get_finished_spans():
        assert set(_attrs(span)) <= SPAN_KEYS
        assert span.parent is None and span.start_time == span.end_time
        VALIDATOR.validate_document(loss_document(span), SCHEMAS)


def test_losses_coalesce_into_one_range_per_reason(
    emitter: LossEmitter, exporter: InMemorySpanExporter
) -> None:
    for sequence in (5, 3, 4):
        emitter.record("wire-a", 7, "queue_full", sequence)
    emitter.record("wire-a", 7, "shutdown", 9)
    emitter.record("wire-a", 8, "queue_full", 0)  # another epoch is another range
    assert exporter.get_finished_spans() == ()  # never emitted on the caller's thread
    assert emitter.flush(2.0)
    losses = sorted(
        (a["fabric.source.epoch"], a[LossAttr.REASON], a[LossAttr.FIRST_SEQUENCE],
         a[LossAttr.LAST_SEQUENCE], a[LossAttr.COUNT])
        for a in _named(exporter, SPAN_LOSS)
    )  # fmt: skip
    assert losses == [
        (7, "queue_full", 3, 5, 3),
        (7, "shutdown", 9, 9, 1),
        (8, "queue_full", 0, 0, 1),
    ]
    _validate_all(exporter)
    assert emitter.flush(2.0)
    assert len(_named(exporter, SPAN_LOSS)) == 3  # nothing is re-emitted
    assert emitter.spans_unsampled == 0  # recorded spans are never counted as sampled out


def test_count_never_exceeds_the_range(
    emitter: LossEmitter, exporter: InMemorySpanExporter
) -> None:
    emitter.record("wire-a", 1, "internal_error", 4)
    emitter.record("wire-a", 1, "internal_error", 4)
    assert emitter.flush(2.0)
    (loss,) = _named(exporter, SPAN_LOSS)
    assert loss[LossAttr.COUNT] == 1
    _validate_all(exporter)


def test_heartbeat_reports_the_sequence_at_request_time(
    emitter: LossEmitter, exporter: InMemorySpanExporter
) -> None:
    allocator = SourceAllocator("wire-hb", "wire")
    scope = RunScope("run-travel-42", "3d7e1f2a-9b4c-4e5d-8a6f-1b2c3d4e5f60", None)
    emitter.heartbeat(allocator)  # -1: nothing allocated yet
    allocator.next_sequence()
    emitter.heartbeat(allocator, kind="run_start", scope=scope)
    assert not scope.closed
    allocator.next_sequence()
    emitter.heartbeat(allocator, kind="run_end", scope=scope)
    assert scope.closed  # closed under the allocator lock: later calls are outside it
    assert allocator.next_sequence()[2] is None
    assert emitter.flush(2.0)
    beats = [
        (a[LossAttr.HEARTBEAT_LAST_SEQUENCE], a[LossAttr.HEARTBEAT_KIND], a.get("fabric.run.id"),
         a.get("fabric.run.scope_id"))
        for a in _named(exporter, SPAN_HEARTBEAT)
    ]  # fmt: skip
    # Queued beats in order, then the flush heartbeat for the source.
    assert beats == [
        (-1, "periodic", None, None), (0, "run_start", "run-travel-42", scope.scope_id),
        (1, "run_end", "run-travel-42", scope.scope_id), (2, "periodic", None, None),
    ]  # fmt: skip
    assert {a["fabric.source.epoch"] for a in _named(exporter, SPAN_HEARTBEAT)} == {allocator.epoch}
    _validate_all(exporter)
    for kind, scoped in (("run_start", None), ("periodic", scope)):
        with pytest.raises(ValueError, match="scope"):
            emitter.heartbeat(allocator, kind=kind, scope=scoped)


def test_flush_heartbeats_every_known_source_once(
    emitter: LossEmitter, exporter: InMemorySpanExporter
) -> None:
    a, b = SourceAllocator("wire-1", "wire"), SourceAllocator("wire-2", "wire")
    a.next_sequence()
    emitter.note_activity(a)
    emitter.note_activity(b)
    assert emitter.flush(2.0)
    beats = {
        (x["fabric.source_id"], x[LossAttr.HEARTBEAT_LAST_SEQUENCE])
        for x in _named(exporter, SPAN_HEARTBEAT)
    }
    assert beats == {("wire-1", 0), ("wire-2", -1)}
    assert len(_named(exporter, SPAN_HEARTBEAT)) == 2


def test_periodic_heartbeat_only_for_active_sources(
    emitter: LossEmitter, exporter: InMemorySpanExporter
) -> None:
    quiet, busy = SourceAllocator("wire-quiet", "wire"), SourceAllocator("wire-busy", "wire")
    emitter.note_activity(quiet)
    emitter.note_activity(busy)
    with emitter._emit_lock:
        emitter._drain(periodic=True)  # both were active since the last heartbeat
        emitter.note_activity(busy)
        emitter._drain(periodic=True)
        emitter._drain(periodic=False)  # an ordinary tick emits no heartbeat
    sources = [a["fabric.source_id"] for a in _named(exporter, SPAN_HEARTBEAT)]
    assert sorted(sources) == ["wire-busy", "wire-busy", "wire-quiet"]


def test_heartbeat_queue_overflow_drops_only_the_marker(
    emitter: LossEmitter, exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_loss, "MAX_QUEUED_MARKERS", 2)
    allocator = SourceAllocator("wire-full", "wire")
    for index in range(5):
        scope = RunScope(f"run-{index}", f"3d7e1f2a-9b4c-4e5d-8a6f-1b2c3d4e5f6{index}", None)
        emitter.heartbeat(allocator, kind="run_start", scope=scope)
    assert emitter.markers_dropped == 3
    assert emitter.flush(2.0)
    beats = _named(exporter, SPAN_HEARTBEAT)
    assert [b.get("fabric.run.id") for b in beats] == ["run-0", "run-1", None]


class _ThreadRecorder(SpanProcessor):
    def __init__(self) -> None:
        self.threads: list[str] = []

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        self.threads.append(threading.current_thread().name)


def test_background_thread_emits_without_flush(exporter: InMemorySpanExporter) -> None:
    recorder = _ThreadRecorder()
    provider = TracerProvider()
    provider.add_span_processor(recorder)
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    emitter = LossEmitter(tracer_provider=provider)
    emitter.record("wire-bg", 1, "queue_full", 0)
    deadline = threading.Event()
    for _ in range(40):
        if exporter.get_finished_spans():
            break
        deadline.wait(0.1)
    assert [s.name for s in exporter.get_finished_spans()] == [SPAN_LOSS]
    assert recorder.threads == ["fabric-loss"]
    emitter.close(0.5)


def test_record_never_raises_and_emit_failures_are_swallowed() -> None:
    class Broken(TracerProvider):
        def get_tracer(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("broken provider")

    emitter = LossEmitter(tracer_provider=Broken())
    emitter.record("wire-x", 1, "queue_full", None)  # type: ignore[arg-type]
    emitter.record("wire-x", 1, "queue_full", 2)
    assert not emitter.flush(1.0)  # the record could not be emitted: never reported delivered
    assert emitter.internal_errors >= 1
    assert emitter.flush(1.0)  # reported once; nothing is pending any more
    emitter.close(0.5)


def test_record_after_close_is_still_flushed(
    emitter: LossEmitter, exporter: InMemorySpanExporter
) -> None:
    emitter.close(0.5)
    emitter.record("wire-late", 1, "shutdown", 3)
    assert emitter._thread is None or not emitter._thread.is_alive()
    assert emitter.flush(1.0)
    assert len(_named(exporter, SPAN_LOSS)) == 1


def test_singleton(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_loss, "_EMITTER", None)
    first = get_loss_emitter()
    assert get_loss_emitter() is first
    first.close(0.1)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_fork_child_drops_the_parents_pending_losses() -> None:
    script = textwrap.dedent(
        """
        import os, warnings
        warnings.simplefilter("ignore")
        from fabric._loss import LossEmitter
        emitter = LossEmitter()
        emitter.record("wire-p", 1, "queue_full", 3)
        emitter._lock.acquire()  # held by "another thread" at fork time
        pid = os.fork()
        if pid == 0:
            ok = emitter._lock.acquire(timeout=2) and not emitter._pending
            os._exit(0 if ok else 1)
        _, status = os.waitpid(pid, 0)
        print("child", os.waitstatus_to_exitcode(status))
        """
    )
    src = Path(_loss.__file__).resolve().parents[1]
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        env={**os.environ, "PYTHONPATH": str(src)},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.stdout.strip() == "child 0", result.stderr
