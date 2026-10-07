# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Source identity, sequence allocation and run resolution (spec 042 §7)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import sys
import threading
import warnings
from collections import defaultdict
from collections.abc import Iterator

import pytest

from fabric import _loss, _sequence
from fabric._loss import LossEmitter
from fabric._sequence import (
    OPAQUE_ID_RE,
    Component,
    SequenceAllocator,
    SequenceTicket,
    SourceIdentity,
    all_allocators,
    current_run_id,
    default_source_id,
    encode_opaque_id,
    find_allocator,
    get_allocator,
    resolve_run,
    run_scope,
)


@pytest.fixture
def fresh_registry(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(_sequence, "_REGISTRY", {})
    monkeypatch.delenv("FABRIC_SOURCE_ID", raising=False)
    monkeypatch.delenv("FABRIC_RUN_ID", raising=False)
    yield


def _allocator(source_id: str = "wire-test", **kwargs: object) -> SequenceAllocator:
    return SequenceAllocator(
        SourceIdentity(source_id=source_id, source_epoch=1_000, component="wire"),
        **kwargs,  # type: ignore[arg-type]
    )


# -- opaque ids --------------------------------------------------------------


def test_encode_opaque_id_passes_valid_ids_through() -> None:
    for value in ("call_abc123", "a", "run:1.2-3_x", "A" * 128):
        assert encode_opaque_id(value) == value


def test_encode_opaque_id_hashes_invalid_ids_stably() -> None:
    for value in ("", "-leading", "has space", "x" * 129, "toolu/01", "é", "\udcff"):
        encoded = encode_opaque_id(value)
        expected = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:40]
        assert encoded == "h-" + expected
        assert OPAQUE_ID_RE.match(encoded)
        assert encode_opaque_id(value) == encoded


# -- allocator ---------------------------------------------------------------


def test_allocator_rejects_bad_identity() -> None:
    with pytest.raises(ValueError):
        SequenceAllocator(SourceIdentity("bad id", 1, "wire"))
    with pytest.raises(ValueError):
        SequenceAllocator(SourceIdentity("ok", -1, "wire"))
    with pytest.raises(ValueError):
        SequenceAllocator(SourceIdentity("ok", 1, "nope"))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        SequenceAllocator(SourceIdentity("ok", 1, "wire"), max_runs=0)


def test_sequences_and_run_sequences_are_independent_and_monotonic() -> None:
    allocator = _allocator()
    assert allocator.high_water() == -1
    first = allocator.next_exchange("run-a", "explicit")
    assert first == SequenceTicket("wire-test", 1_000, 0, "run-a", "explicit", 0)
    assert allocator.next_record() == (1_000, 1)
    second = allocator.next_exchange("run-b", "trace")
    third = allocator.next_exchange("run-a", "explicit")
    assert (second.source_sequence, second.run_sequence) == (2, 0)
    assert (third.source_sequence, third.run_sequence) == (3, 1)
    assert allocator.high_water() == 3
    assert allocator.run_high_water("run-a") == 1
    assert allocator.run_high_water("missing") is None
    assert allocator.close_run("run-a") == 1
    assert allocator.close_run("run-a") == -1
    assert allocator.run_high_water("run-a") is None
    # A closed run restarts its counter; the source sequence never does.
    again = allocator.next_exchange("run-a", "explicit")
    assert (again.source_sequence, again.run_sequence) == (4, 0)


def test_allocator_is_thread_safe_and_gap_free() -> None:
    allocator = _allocator()
    threads_n, per_thread = 16, 1500
    results: list[list[SequenceTicket]] = [[] for _ in range(threads_n)]
    records: list[list[int]] = [[] for _ in range(threads_n)]
    barrier = threading.Barrier(threads_n)

    def worker(index: int) -> None:
        barrier.wait()
        for i in range(per_thread):
            run_id = f"run-{(index + i) % 5}"
            results[index].append(allocator.next_exchange(run_id, "explicit"))
            if i % 10 == 0:
                records[index].append(allocator.next_record()[1])

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(threads_n)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    tickets = [t for chunk in results for t in chunk]
    record_seqs = [s for chunk in records for s in chunk]
    all_seqs = sorted([t.source_sequence for t in tickets] + record_seqs)
    assert all_seqs == list(range(len(all_seqs)))
    assert allocator.high_water() == len(all_seqs) - 1

    by_run: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for ticket in tickets:
        by_run[ticket.run_id].append((ticket.source_sequence, ticket.run_sequence))
    for pairs in by_run.values():
        pairs.sort()
        # run_sequence is contiguous and follows source order within a run.
        assert [run_seq for _, run_seq in pairs] == list(range(len(pairs)))
    # Each thread observes strictly increasing sequences.
    for chunk in results:
        seqs = [t.source_sequence for t in chunk]
        assert seqs == sorted(seqs)


def test_epoch_is_stable_for_the_allocator_lifetime(fresh_registry: None) -> None:
    allocator = get_allocator("wire")
    identity = allocator.identity
    for _ in range(1000):
        allocator.next_exchange("r", "explicit")
    assert allocator.identity is identity
    assert get_allocator("wire") is allocator
    assert allocator.identity.source_epoch > 0


def test_registry_epochs_are_unique(fresh_registry: None) -> None:
    components: tuple[Component, ...] = ("wire", "gateway", "otel")
    epochs = {get_allocator(c).identity.source_epoch for c in components}
    assert len(epochs) == 3


def test_lru_eviction_calls_back_outside_the_lock() -> None:
    evicted: list[tuple[str, int]] = []
    holder: dict[str, SequenceAllocator] = {}

    def on_evicted(run_id: str, last: int) -> None:
        # Re-entering the allocator proves the callback runs outside its lock.
        holder["a"].next_record()
        evicted.append((run_id, last))

    allocator = _allocator(max_runs=2, on_run_evicted=on_evicted)
    holder["a"] = allocator
    allocator.next_exchange("r1", "explicit")
    allocator.next_exchange("r1", "explicit")
    allocator.next_exchange("r2", "explicit")
    allocator.next_exchange("r1", "explicit")  # r1 most recent; r2 is LRU
    allocator.next_exchange("r3", "explicit")  # r2 live -> retired (remembered)
    assert evicted == []
    assert allocator.run_high_water("r2") == 0
    allocator.next_exchange("r4", "explicit")  # r1 live -> retired
    allocator.next_exchange("r5", "explicit")  # r3 retired; r2 dropped from retired
    assert evicted == [("r2", 0)]
    assert allocator.run_high_water("r1") == 2
    assert allocator.run_high_water("r2") is None


def test_eviction_callback_failure_is_swallowed() -> None:
    def boom(run_id: str, last: int) -> None:
        raise RuntimeError("callback bug")

    allocator = _allocator(max_runs=1, on_run_evicted=boom)
    allocator.next_exchange("r1", "explicit")
    allocator.next_exchange("r2", "explicit")
    ticket = allocator.next_exchange("r3", "explicit")
    assert ticket.source_sequence == 2


def test_finished_runs_evicted_from_the_index_report_no_loss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A long-lived service (one trace-basis run per request) loses nothing."""
    emitter = LossEmitter()
    monkeypatch.setattr(_loss, "_EMITTER", emitter)
    allocator = _allocator(max_runs=2)
    for index in range(50):
        allocator.next_exchange(f"trace:{index:032x}", "trace")
    assert emitter.stats().by_source == {}
    emitter.close(0.5)


def test_retired_run_resumes_numbering_without_loss(monkeypatch: pytest.MonkeyPatch) -> None:
    emitter = LossEmitter()
    monkeypatch.setattr(_loss, "_EMITTER", emitter)
    allocator = _allocator(max_runs=1)
    allocator.next_exchange("r1", "explicit")
    allocator.next_exchange("r1", "explicit")
    allocator.next_exchange("r2", "explicit")  # r1 retired
    ticket = allocator.next_exchange("r1", "explicit")
    assert ticket.run_sequence == 2
    assert emitter.stats().by_source == {}
    emitter.close(0.5)


def test_forgotten_run_reused_reports_run_index_evicted(monkeypatch: pytest.MonkeyPatch) -> None:
    emitter = LossEmitter()
    monkeypatch.setattr(_loss, "_EMITTER", emitter)
    allocator = _allocator(max_runs=1)
    allocator.next_exchange("r1", "explicit")
    allocator.next_exchange("r1", "explicit")
    allocator.next_exchange("r2", "explicit")  # r1 retired
    allocator.next_exchange("r3", "explicit")  # r2 retired, r1 forgotten
    assert emitter.stats().by_source == {}
    ticket = allocator.next_exchange("r1", "explicit")  # counter restarts: visible
    assert ticket.run_sequence == 0
    counts = emitter.stats().by_source[("wire-test", 1_000)]
    assert counts == {"run_index_evicted": 1}
    pending = list(emitter._ledger)
    assert pending[0].affected[0].run_id == "r1"
    assert pending[0].affected[0].run_sequence == 0
    assert pending[0].affected[0].source_sequence == ticket.source_sequence
    # Reported once: the next allocation continues the restarted counter.
    assert allocator.next_exchange("r1", "explicit").run_sequence == 1
    assert emitter.stats().by_source[("wire-test", 1_000)] == {"run_index_evicted": 1}
    emitter.close(0.5)


# -- registry and source ids -------------------------------------------------


def test_default_source_id_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_SERVICE_NAME", "svc")
    host = socket.gethostname()
    expected = hashlib.sha256((host + "\0svc").encode()).hexdigest()[:16]
    assert default_source_id("wire") == f"wire-{expected}"
    other = hashlib.sha256((host + "\0explicit").encode()).hexdigest()[:16]
    assert default_source_id("gateway", "explicit") == f"gateway-{other}"
    monkeypatch.delenv("OTEL_SERVICE_NAME")
    unknown = hashlib.sha256((host + "\0unknown").encode()).hexdigest()[:16]
    assert default_source_id("otel") == f"otel-{unknown}"
    assert re.fullmatch(r"otel-[0-9a-f]{16}", default_source_id("otel"))


def test_get_allocator_applies_source_id_on_first_creation(
    fresh_registry: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_SOURCE_ID", "from-env")
    wire = get_allocator("wire")
    assert wire.identity.source_id == "from-env"
    gateway = get_allocator("gateway", source_id="gw 1")  # invalid -> hashed
    assert gateway.identity.source_id == encode_opaque_id("gw 1")
    assert gateway.identity.component == "gateway"
    assert get_allocator("gateway", source_id="ignored") is gateway
    with pytest.raises(ValueError):
        get_allocator("bogus")  # type: ignore[arg-type]


def test_find_and_list_allocators(fresh_registry: None) -> None:
    wire = get_allocator("wire")
    standalone = _allocator("standalone-src")
    found = find_allocator(wire.identity.source_id, wire.identity.source_epoch)
    assert found is wire
    assert find_allocator("standalone-src", 1_000) is standalone
    assert find_allocator("standalone-src", 999) is None
    listed = all_allocators()
    assert listed[0] is wire
    assert standalone in listed


# -- runs --------------------------------------------------------------------


def test_run_scope_sets_and_restores(fresh_registry: None) -> None:
    assert current_run_id() is None
    with run_scope("outer"):
        assert current_run_id() == "outer"
        with run_scope("inner"):
            assert current_run_id() == "inner"
        assert current_run_id() == "outer"
    assert current_run_id() is None
    with pytest.raises(ValueError), run_scope("not valid"):
        pass


def test_resolve_run_order(fresh_registry: None, monkeypatch: pytest.MonkeyPatch) -> None:
    allocator = _allocator()
    trace_id = 0x0AF7651916CD43DD8448EB211C80319C
    assert resolve_run(allocator) == ("source:wire-test:1000", "source")
    assert resolve_run(allocator, trace_id=0) == ("source:wire-test:1000", "source")
    assert resolve_run(allocator, trace_id=1 << 128) == ("source:wire-test:1000", "source")
    assert resolve_run(allocator, trace_id=trace_id) == (
        "trace:0af7651916cd43dd8448eb211c80319c",
        "trace",
    )
    monkeypatch.setenv("FABRIC_RUN_ID", "env-run")
    assert resolve_run(allocator, trace_id=trace_id) == ("env-run", "explicit")
    with run_scope("scoped"):
        assert resolve_run(allocator, trace_id=trace_id) == ("scoped", "explicit")
        assert resolve_run(allocator, explicit="arg") == ("arg", "explicit")
        assert resolve_run(allocator, explicit="bad id") == (
            encode_opaque_id("bad id"),
            "explicit",
        )


def test_resolve_run_source_basis_stays_opaque() -> None:
    allocator = SequenceAllocator(SourceIdentity("s" * 128, 1_791_331_200_000_000_000, "wire"))
    run_id, basis = resolve_run(allocator)
    assert basis == "source"
    assert OPAQUE_ID_RE.match(run_id)


# -- fork --------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(os, "fork") or sys.platform == "win32", reason="needs fork")
def test_fork_renews_epoch_and_restarts_sequence() -> None:
    allocator = _allocator("fork-src")
    allocator.next_exchange("r", "explicit")
    allocator.next_exchange("r", "explicit")
    parent_epoch = allocator.identity.source_epoch
    read_fd, write_fd = os.pipe()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        pid = os.fork()
    if pid == 0:  # pragma: no cover - runs in the child
        try:
            ticket = allocator.next_exchange("r", "explicit")
            payload = {
                "epoch": allocator.identity.source_epoch,
                "sequence": ticket.source_sequence,
                "run_sequence": ticket.run_sequence,
                "source_id": allocator.identity.source_id,
            }
            os.write(write_fd, json.dumps(payload).encode())
        finally:
            os._exit(0)
    os.close(write_fd)
    os.waitpid(pid, 0)
    with os.fdopen(read_fd) as stream:
        child = json.loads(stream.read())
    assert child["source_id"] == "fork-src"
    assert child["epoch"] > parent_epoch
    assert child["sequence"] == 0
    assert child["run_sequence"] == 0
    # The parent is untouched.
    assert allocator.identity.source_epoch == parent_epoch
    assert allocator.next_exchange("r", "explicit").source_sequence == 2
