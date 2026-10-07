# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Wire-tee regressions for review findings (passivity and loss accounting)."""

from __future__ import annotations

import gc
import gzip
import os
import subprocess
import sys
import textwrap
import threading
import time
import tracemalloc
from pathlib import Path
from typing import Any

import httpx
import pytest
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.sampling import ALWAYS_OFF

from fabric import wire
from fabric._loss import LossEmitter
from fabric._sequence import SequenceAllocator, SourceIdentity
from fabric.wire import _stitch, _stream
from fabric.wire.__main__ import autoload_path
from fabric.wire._transport import WireTee, WireTransport

from .test_wire_helpers import OPENAI_CHAT, ChunkStream, Rig, attrs, make_rig

SRC = Path(wire.__file__).resolve().parents[2]


@pytest.fixture
def rig(tmp_path: Path) -> Any:
    built = make_rig(tmp_path)
    yield built
    built.close()


def _wait_submitted(rig: Rig, count: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while rig.tee.stats()["submitted"] < count and time.monotonic() < deadline:
        time.sleep(0.005)
    assert not rig.tee._active
    rig.flush()


# ------------------------------------------------ abandoned stream inside GC


def test_abandoned_stream_finalized_by_gc_never_takes_capture_locks(rig: Rig) -> None:
    """GC may run the finalizer on a thread that already holds a capture lock."""
    chunks = [b"data: 1\n\n", b"data: 2\n\n"]
    with rig.client(lambda r: httpx.Response(200, stream=ChunkStream(chunks))) as client:
        response = client.send(client.build_request("POST", OPENAI_CHAT, json={}), stream=True)
        response.cycle = response  # type: ignore[attr-defined] # only cyclic GC frees it
        del response
    finished = threading.Event()

    def collect_while_holding_locks() -> None:
        # The loss emitter lock (taken by note_activity/record) and the
        # finish lock are both non-reentrant; a finalizer that takes either
        # would deadlock this thread forever.
        with rig.loss._lock, _stream._FINISH_LOCK:
            gc.collect()
        finished.set()

    worker = threading.Thread(target=collect_while_holding_locks, daemon=True)
    worker.start()
    worker.join(5.0)
    assert finished.is_set(), "GC finalizer deadlocked on a capture lock"
    _wait_submitted(rig, 1)
    assert [attrs(s)["fabric.wire.response_state"] for s in rig.spans()] == ["abandoned"]


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_fork_child_reinitializes_wire_locks() -> None:
    script = textwrap.dedent(
        """
        import os, warnings
        warnings.simplefilter("ignore")
        from fabric.wire import _stream
        _stream._FINISH_LOCK.acquire()  # held by "another thread" at fork time
        pid = os.fork()
        if pid == 0:
            ok = _stream._FINISH_LOCK.acquire(timeout=2)
            os._exit(0 if ok and _stream._REAPER_PID is None else 1)
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


# ----------------------------------------------- setup failure after ticket


def test_setup_failure_after_sequence_allocation_is_a_recorded_loss(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("injected")

    monkeypatch.setattr(_stream, "RequestTee", boom)

    def body() -> Any:
        yield b'{"messages":[]}'

    request = httpx.Request("POST", OPENAI_CHAT, content=body())
    with rig.client(lambda r: httpx.Response(200, json={"choices": []})) as client:
        assert client.send(request).status_code == 200
    rig.flush()
    assert rig.allocator.high_water() == 0  # the sequence was consumed
    assert rig.loss_counts() == {"internal_error": 1}
    assert rig.tee.stats()["internal_errors"] == 1
    assert rig.tee.stats()["inflight_bytes"] == 0
    assert not rig.tee._active


# ------------------------------------------------ shutdown abandon race


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


def test_close_never_reports_a_span_the_worker_is_already_ending(tmp_path: Path) -> None:
    exporter = _BlockingExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    loss = LossEmitter(tracer_provider=TracerProvider())
    config = wire.WireConfig(store=None, tracer_provider=provider, patch_httpx=False)
    allocator = SequenceAllocator(SourceIdentity("wire-race", time.time_ns(), "wire"))
    tee = WireTee(config, allocator=allocator, loss=loss)
    handle = wire.WireHandle(config, tee, patched=False)
    transport = WireTransport(
        httpx.MockTransport(lambda r: httpx.Response(200, json={})), handle=handle
    )
    with httpx.Client(transport=transport) as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert exporter.entered.wait(5)  # worker is inside span.end()
    tee.pipeline.close(0.05)  # deadline expires mid-emit
    exporter.release.set()
    tee.pipeline._worker.join(5)
    identity = allocator.identity
    counts = loss.stats().by_source.get((identity.source_id, identity.source_epoch), {})
    assert len(exporter.spans) == 1
    assert "shutdown_timeout" not in counts
    loss.close(0.5)


# ------------------------------------------------- loss spans and sampling


def test_sampled_out_loss_spans_are_not_counted_as_emitted() -> None:
    provider = TracerProvider(sampler=ALWAYS_OFF)
    loss = LossEmitter(tracer_provider=provider)
    allocator = SequenceAllocator(SourceIdentity("wire-sampled", time.time_ns(), "wire"))
    loss.record(allocator, "queue_full")
    assert loss.flush(2.0)
    stats = loss.stats()
    assert stats.spans_emitted == 0
    assert loss._spans_unsampled >= 1
    loss.close(0.5)


# --------------------------------------------------- decompression bombs


def test_compressed_body_inflation_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_stitch, "MAX_DECODED_BYTES", 1 << 20)
    bomb = gzip.compress(b'{"messages":[' + b" " * (64 << 20) + b"]}", compresslevel=9)
    assert len(bomb) < 1 << 20  # small on the wire, 64 MiB decoded
    tracemalloc.start()
    try:
        keys = _stitch.extract_stitch_keys(
            "openai.chat_completions",
            bomb,
            "application/json",
            "gzip",
            False,
            bomb,
            "application/json",
            "gzip",
            False,
        )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert keys.request_parse_status == "undecodable_encoding"
    assert keys.response_parse_status == "undecodable_encoding"
    assert peak < 8 << 20


def test_compressed_body_under_the_bound_still_parses() -> None:
    body = gzip.compress(b'{"model":"m","messages":[{"role":"user","content":"hi"}]}')
    keys = _stitch.extract_stitch_keys(
        "openai.chat_completions", body, "application/json", "gzip", False, None, None, None, False
    )
    assert keys.request_parse_status == "ok"
    assert len(keys.input_digests) == 1
    with pytest.raises(_stitch._UnparsedError):
        _stitch._decode(gzip.compress(b"x" * 4096), "gzip", 1024)
    with pytest.raises(_stitch._UnparsedError):
        _stitch._decode(gzip.compress(b"x" * 4096)[:-12], "gzip")  # truncated stream


# ------------------------------------------------ sitecustomize chaining


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
