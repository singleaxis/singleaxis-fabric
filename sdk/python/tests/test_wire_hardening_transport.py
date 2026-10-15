# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Transport tee hardening (review 1, findings 2, 3, 5 and 9).

- Matched-call setup is guarded: once a sequence is allocated, any failure is an
  ``internal_error`` loss for it and the request still reaches the transport.
- A fork child never inherits a held ``_PATCH_LOCK``.
- Finished, lost or shut-down exchanges hold no captured bytes, so responses the
  host keeps alive do not pin capture memory.
- A source is heartbeat-eligible from its first allocation, not its first finish.
"""

from __future__ import annotations

import asyncio
import gc
import os
import subprocess
import sys
import textwrap
import tracemalloc
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from fabric import wire
from fabric.wire import _stream, _transport

from .test_wire_helpers import OPENAI_CHAT, ChunkStream, Rig, attrs, make_rig

SRC = Path(wire.__file__).resolve().parents[2]
MIB = 1024 * 1024


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    built = make_rig(tmp_path)
    yield built
    built.close()


def _boom(*args: Any, **kwargs: Any) -> Any:
    raise MemoryError("injected")


class _BoomSet(set[Any]):
    def add(self, item: Any) -> None:
        raise MemoryError("injected")


def _inject(rig: Rig, monkeypatch: pytest.MonkeyPatch, where: str) -> None:
    if where == "construct":
        monkeypatch.setattr(_transport, "Exchange", _boom)
    elif where == "run_id":
        monkeypatch.setattr(_stream, "resolve_run_id", _boom)
    elif where == "retain":
        monkeypatch.setattr(_stream.Exchange, "_retain", _boom)
    elif where == "register":  # after the request bytes were retained
        rig.tee._active = _BoomSet()


SETUP_POINTS = ["construct", "run_id", "retain", "register"]


@pytest.mark.parametrize("where", SETUP_POINTS)
def test_sync_setup_memory_error_still_sends_and_is_a_loss(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    sent: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.content)
        return httpx.Response(200, json={"choices": []})

    _inject(rig, monkeypatch, where)
    with rig.client(handler) as client:
        response = client.post(OPENAI_CHAT, json={"messages": []})
    assert (response.status_code, response.json()) == (200, {"choices": []})
    assert sent == [b'{"messages":[]}']
    _assert_one_internal_error(rig)


@pytest.mark.parametrize("where", SETUP_POINTS)
def test_async_setup_memory_error_still_sends_and_is_a_loss(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    sent: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.content)
        return httpx.Response(200, json={"choices": []})

    async def call() -> httpx.Response:
        async with rig.async_client(handler) as client:
            return await client.post(OPENAI_CHAT, json={"messages": []})

    _inject(rig, monkeypatch, where)
    response = asyncio.run(call())
    assert (response.status_code, response.json()) == (200, {"choices": []})
    assert sent == [b'{"messages":[]}']
    _assert_one_internal_error(rig)


def _assert_one_internal_error(rig: Rig) -> None:
    rig.flush()
    assert rig.spans() == []
    assert rig.allocator.last_sequence()[1] == 0  # the sequence was allocated ...
    assert rig.loss_counts() == {"internal_error": 1}  # ... and is explained
    (loss,) = rig.spans("fabric.capture_loss")
    a = attrs(loss)
    assert (a["fabric.loss.first_sequence"], a["fabric.loss.last_sequence"]) == (0, 0)
    stats = rig.tee.stats()
    assert (stats["internal_errors"], stats["inflight_bytes"], stats["matched"]) == (1, 0, 1)
    assert not rig.tee._active


def test_failing_heartbeat_registration_does_not_drop_capture(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rig.loss, "note_activity", _boom)
    with rig.client(lambda r: httpx.Response(200, json={"choices": []})) as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    rig.flush()
    assert len(rig.spans()) == 1
    assert rig.loss_counts() == {}


def test_open_stream_source_is_heartbeat_eligible_at_allocation(rig: Rig) -> None:
    """Finding 9: a first long-running stream must not leave its source unregistered."""
    chunks = [b"data: 1\n\n", b"data: 2\n\n"]
    with rig.client(lambda r: httpx.Response(200, stream=ChunkStream(chunks))) as client:
        request = client.build_request("POST", OPENAI_CHAT, json={})
        response = client.send(request, stream=True)
        assert next(response.iter_raw()) == chunks[0]  # still open, nothing finished
        assert rig.loss.flush(5.0)
        beats = [
            attrs(s)
            for s in rig.spans("fabric.capture_heartbeat")
            if attrs(s)["fabric.source_id"] == rig.allocator.source_id
        ]
        assert [b["fabric.heartbeat.last_sequence"] for b in beats] == [0]
        assert rig.loss._sources.get(rig.allocator) is False  # drained, still tracked
        response.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_fork_child_gets_a_fresh_patch_lock() -> None:
    script = textwrap.dedent(
        """
        import os, warnings
        warnings.simplefilter("ignore")
        from fabric.wire import _transport
        _transport._PATCH_LOCK.acquire()  # held by "another thread" at fork time
        pid = os.fork()
        if pid == 0:
            ok = _transport._PATCH_LOCK.acquire(timeout=2)
            if ok:
                _transport._PATCH_LOCK.release()
                _transport.patch_httpx()  # would block forever on the inherited lock
                _transport.unpatch_httpx()
            os._exit(0 if ok else 1)
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


@pytest.mark.parametrize("ending", ["complete", "closed_early", "lost", "shutdown"])
def test_ended_exchange_keeps_no_captured_bytes(rig: Rig, ending: str) -> None:
    chunks = [b"data: 1\n\n", b"data: 2\n\n"]
    with rig.client(lambda r: httpx.Response(200, stream=ChunkStream(chunks))) as client:
        request = client.build_request("POST", OPENAI_CHAT, json={"messages": []})
        response = client.send(request, stream=True)
        iterator = response.iter_raw()
        assert next(iterator) == chunks[0]
        (exchange,) = rig.tee._active  # what the kept response's tee stream references
        sides: list[Any] = [exchange.request, exchange.response]
        assert sum(len(side.chunks) for side in sides) == 2  # retained while open
        if ending == "complete":
            assert list(iterator) == chunks[1:]
        elif ending == "closed_early":
            response.close()
        elif ending == "lost":
            exchange.detach(lost=True)
        else:
            rig.tee.close(5.0)
        assert exchange.done and [side.chunks for side in sides] == [[], []]
        response.close()
    rig.flush()
    assert rig.tee.stats()["inflight_bytes"] == 0


class _FreshBytes(httpx.SyncByteStream):
    """Yields new ``bytes`` objects the host does not keep (a real socket's shape)."""

    def __init__(self, count: int, size: int) -> None:
        self.count, self.size = count, size

    def __iter__(self) -> Iterator[bytes]:
        for _ in range(self.count):
            yield os.urandom(self.size)


def test_kept_closed_streams_do_not_pin_capture_bytes(tmp_path: Path) -> None:
    """Finding 5 probe: 10 MiB streamed through a ~1 MiB budget, all responses kept."""
    rig = make_rig(tmp_path, store=None, max_inflight_bytes=MIB + 1024)
    kept: list[httpx.Response] = []
    try:
        tracemalloc.start()
        baseline = tracemalloc.get_traced_memory()[0]
        handler = lambda r: httpx.Response(200, stream=_FreshBytes(4, 256 * 1024))  # noqa: E731
        with rig.client(handler) as client:
            for _ in range(10):
                request = client.build_request("POST", OPENAI_CHAT, json={})
                response = client.send(request, stream=True)
                for _chunk in response.iter_raw():
                    pass
                response.close()
                kept.append(response)
                rig.flush()  # the job is done: its budget is back
        gc.collect()
        retained = tracemalloc.get_traced_memory()[0] - baseline
    finally:
        tracemalloc.stop()
        rig.close()
    assert len(rig.spans()) == 10
    assert rig.tee.stats()["inflight_bytes"] == 0
    assert retained < 3 * MIB, f"{retained / MIB:.1f} MiB still held by kept responses"
