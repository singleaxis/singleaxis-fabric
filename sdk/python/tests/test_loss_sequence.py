# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Source identity, the per-source sequence and run-id resolution (spec 042 §6)."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import warnings
from collections.abc import Iterator

import pytest

from fabric import _sequence
from fabric._sequence import (
    OPAQUE_ID_RE,
    SourceAllocator,
    current_run_id,
    default_source_id,
    encode_opaque_id,
    get_allocator,
    resolve_run_id,
    run_pseudonym,
    run_scope,
)


@pytest.fixture
def fresh_registry(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(_sequence, "_REGISTRY", {})
    monkeypatch.delenv("FABRIC_SOURCE_ID", raising=False)
    yield


def test_encode_opaque_id_passes_valid_ids_through() -> None:
    for value in ("call_abc123", "a", "run:1.2-3_x", "A" * 128):
        assert encode_opaque_id(value) == value


def test_encode_opaque_id_hashes_invalid_ids_stably() -> None:
    for value in ("", "-leading", "has space", "x" * 129, "toolu/01", "é", "\udcff"):
        encoded = encode_opaque_id(value)
        expected = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:40]
        assert encoded == "h-" + expected
        assert OPAQUE_ID_RE.match(encoded)


def test_allocator_rejects_bad_identity() -> None:
    with pytest.raises(ValueError):
        SourceAllocator("bad id", "wire")
    with pytest.raises(ValueError):
        SourceAllocator("ok", "otel")  # type: ignore[arg-type]


def test_sequences_start_at_zero_and_are_monotonic() -> None:
    allocator = SourceAllocator("wire-test", "wire")
    assert allocator.last_sequence() == (allocator.epoch, -1)
    assert [allocator.next_sequence()[1] for _ in range(3)] == [0, 1, 2]
    assert allocator.last_sequence() == (allocator.epoch, 2)
    assert allocator.next_sequence()[0] == allocator.epoch


def test_allocator_is_thread_safe_and_gap_free() -> None:
    allocator = SourceAllocator("wire-threads", "wire")
    seen: list[int] = []
    lock = threading.Lock()

    def work() -> None:
        local = [allocator.next_sequence()[1] for _ in range(2000)]
        with lock:
            seen.extend(local)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(seen) == list(range(16000))


def test_epochs_are_unique_and_increasing() -> None:
    epochs = [SourceAllocator(f"wire-{i}", "wire").epoch for i in range(50)]
    assert epochs == sorted(set(epochs))


def test_default_source_id_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_SERVICE_NAME", "travel-agent")
    expected = hashlib.sha256(f"{socket.gethostname()}\0travel-agent".encode()).hexdigest()[:16]
    assert default_source_id("wire") == f"wire-{expected}"
    assert default_source_id("wire", "other").startswith("wire-")


def test_get_allocator_applies_source_id_on_first_creation(
    fresh_registry: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_SOURCE_ID", "has space")
    first = get_allocator("wire", source_id="node-1")
    assert get_allocator("wire", source_id="ignored") is first
    assert first.source_id == "node-1"
    _sequence._REGISTRY.clear()
    assert get_allocator("wire").source_id == encode_opaque_id("has space")


def test_run_scope_sets_and_restores() -> None:
    assert current_run_id() is None
    with run_scope("outer"):
        with run_scope("inner"):
            assert current_run_id() == run_pseudonym("inner")
        assert current_run_id() == run_pseudonym("outer")
    assert current_run_id() is None
    with pytest.raises(ValueError), run_scope("bad id"):
        pass


def test_resolve_run_id_order() -> None:
    allocator = SourceAllocator("wire-runs", "wire")
    trace_id = 0x4BF92F3577B34DA6A3CE929D0E0E4736
    source = f"source:wire-runs:{allocator.epoch}"
    assert resolve_run_id(allocator) == source
    assert resolve_run_id(allocator, trace_id=trace_id) == f"trace:{trace_id:032x}"
    for bad_trace in (0, 1 << 128, -1):
        assert resolve_run_id(allocator, trace_id=bad_trace) == source
    with run_scope("scoped"):
        assert resolve_run_id(allocator, trace_id=trace_id) == run_pseudonym("scoped")


def test_source_run_id_stays_opaque_for_long_source_ids() -> None:
    allocator = SourceAllocator("s" * 128, "wire")
    assert OPAQUE_ID_RE.match(resolve_run_id(allocator))


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_fork_renews_epoch_and_restarts_sequence() -> None:
    allocator = SourceAllocator("fork-src", "wire")
    allocator.next_sequence()
    allocator.next_sequence()
    parent_epoch = allocator.epoch
    read_fd, write_fd = os.pipe()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        pid = os.fork()
    if pid == 0:  # pragma: no cover - runs in the child
        try:
            epoch, sequence, _ = allocator.next_sequence()
            os.write(write_fd, json.dumps({"epoch": epoch, "sequence": sequence}).encode())
        finally:
            os._exit(0)
    os.close(write_fd)
    os.waitpid(pid, 0)
    with os.fdopen(read_fd) as stream:
        child = json.loads(stream.read())
    assert child["epoch"] > parent_epoch
    assert child["sequence"] == 0
    assert allocator.epoch == parent_epoch
    assert allocator.next_sequence() == (parent_epoch, 2, None)
