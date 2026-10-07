# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Capture-source identity, monotonic sequences and run resolution (spec 042 §7).

Every capture source (the in-process wire tee, the gateway tap, and the
``otel`` fallback used for span-pipeline drops) owns one
:class:`SequenceAllocator`. The allocator hands out one monotonic
``source_sequence`` per ``(source_id, source_epoch)`` to every exchange,
loss record and watermark, plus a per-run ``run_sequence`` for exchanges.
The invariant the verifier relies on: each allocated sequence yields exactly
one emitted span, or appears in a loss record's ``affected`` list, or is
visibly missing.

The hot path is one short lock and a few integer/dict operations. Nothing
here performs I/O, logs content, or raises into the host on allocation.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import os
import re
import socket
import threading
import time
import weakref
from array import array
from collections import OrderedDict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Literal

__all__ = [
    "OPAQUE_ID_RE",
    "Component",
    "RunIdBasis",
    "SequenceAllocator",
    "SequenceTicket",
    "SourceIdentity",
    "all_allocators",
    "current_run_id",
    "default_source_id",
    "encode_opaque_id",
    "find_allocator",
    "get_allocator",
    "resolve_run",
    "run_scope",
]

OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
"""Shape every id carried in capture records and OTLP must match."""

RunIdBasis = Literal["explicit", "trace", "source"]
Component = Literal["wire", "gateway", "otel"]

_COMPONENTS: frozenset[str] = frozenset({"wire", "gateway", "otel"})
_FORGOTTEN_MAX = 1 << 16
"""Slots in the forgotten-run fingerprint table (512 KiB at most)."""
_MAX_TRACE_ID = (1 << 128) - 1


def encode_opaque_id(value: str) -> str:
    """Return ``value`` when it is a valid opaque id, else a stable hashed form.

    The hashed form is ``"h-"`` + the first 40 hex of ``sha256(utf8(value))``
    so an id that is emitted in one place and consumed in another encodes
    identically everywhere (spec 042 §5).
    """
    if OPAQUE_ID_RE.match(value):
        return value
    digest = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()
    return "h-" + digest[:40]


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    """Who allocated a sequence: stable id, process-lifetime epoch, component."""

    source_id: str
    source_epoch: int
    component: Component


@dataclass(frozen=True, slots=True)
class SequenceTicket:
    """One exchange's position in its source and its run."""

    source_id: str
    source_epoch: int
    source_sequence: int
    run_id: str
    run_id_basis: RunIdBasis
    run_sequence: int


# Every live allocator, so fork handling and find_allocator() see allocators
# built outside the registry too (tests, gateway with an explicit source id).
_LIVE: weakref.WeakSet[SequenceAllocator] = weakref.WeakSet()
_LIVE_LOCK = threading.Lock()


class SequenceAllocator:
    """Thread-safe allocator of ``source_sequence`` and per-run ``run_sequence``.

    The run index is bounded in three tiers so a long-lived service never
    reports a loss for a run that merely finished:

    1. up to ``max_runs`` live runs (LRU);
    2. up to ``max_runs`` retired runs evicted from (1), still remembering
       their last ``run_sequence`` -- a retired run that is allocated again
       resumes its numbering, so nothing is lost or reported;
    3. a fixed-size table of fingerprints of runs dropped from (2). Only when
       such a forgotten run is allocated again does its counter restart, and
       that restart is reported as a ``run_index_evicted`` loss naming the
       run, so it can never pass silently (spec 042 §7).

    ``on_run_evicted(run_id, last_run_sequence)`` is called outside the lock
    when a run is dropped from (2). Callback failures are swallowed.
    """

    __slots__ = (
        "__weakref__",
        "_forgotten",
        "_forgotten_mask",
        "_identity",
        "_lock",
        "_max_runs",
        "_next",
        "_on_run_evicted",
        "_retired",
        "_runs",
    )

    def __init__(
        self,
        identity: SourceIdentity,
        *,
        max_runs: int = 65536,
        on_run_evicted: Callable[[str, int], None] | None = None,
    ) -> None:
        if max_runs < 1:
            raise ValueError("max_runs must be >= 1")
        if identity.component not in _COMPONENTS:
            raise ValueError(f"unknown component {identity.component!r}")
        if not OPAQUE_ID_RE.match(identity.source_id):
            raise ValueError("source_id must match the opaque-id pattern")
        if identity.source_epoch < 0:
            raise ValueError("source_epoch must be >= 0")
        self._identity = identity
        self._lock = threading.Lock()
        self._max_runs = max_runs
        self._next = 0
        # run_id -> (last run_sequence, last source_sequence), LRU order.
        self._runs: OrderedDict[str, tuple[int, int]] = OrderedDict()
        self._retired: OrderedDict[str, tuple[int, int]] = OrderedDict()
        size = 1 << max(4, (min(max_runs, _FORGOTTEN_MAX) - 1).bit_length())
        self._forgotten_mask = size - 1
        self._forgotten = array("q", bytes(8 * size))
        self._on_run_evicted = on_run_evicted
        with _LIVE_LOCK:
            _LIVE.add(self)

    @property
    def identity(self) -> SourceIdentity:
        """Current identity. The epoch is renewed in a forked child."""
        return self._identity

    def next_exchange(self, run_id: str, basis: RunIdBasis) -> SequenceTicket:
        """Allocate one source sequence and one run sequence for an exchange."""
        evicted: tuple[str, int] | None = None
        restarted = False
        with self._lock:
            identity = self._identity
            sequence = self._next
            self._next = sequence + 1
            previous = self._runs.pop(run_id, None)
            if previous is None:
                previous = self._retired.pop(run_id, None)
                if previous is None:
                    restarted = self._was_forgotten(run_id)
            run_sequence = 0 if previous is None else previous[0] + 1
            self._runs[run_id] = (run_sequence, sequence)
            if len(self._runs) > self._max_runs:
                old_run, old_entry = self._runs.popitem(last=False)
                self._retired[old_run] = old_entry
                if len(self._retired) > self._max_runs:
                    gone_run, (gone_run_seq, _) = self._retired.popitem(last=False)
                    self._forget(gone_run)
                    evicted = (gone_run, gone_run_seq)
        if evicted is not None and self._on_run_evicted is not None:
            with contextlib.suppress(Exception):  # capture fails open
                self._on_run_evicted(*evicted)
        if restarted:
            self._report_restart(run_id, sequence)
        return SequenceTicket(
            source_id=identity.source_id,
            source_epoch=identity.source_epoch,
            source_sequence=sequence,
            run_id=run_id,
            run_id_basis=basis,
            run_sequence=run_sequence,
        )

    def next_record(self) -> tuple[int, int]:
        """Allocate a sequence for a loss or watermark record: ``(epoch, sequence)``."""
        with self._lock:
            sequence = self._next
            self._next = sequence + 1
            return self._identity.source_epoch, sequence

    def high_water(self) -> int:
        """Last allocated source sequence in the current epoch, ``-1`` if none."""
        with self._lock:
            return self._next - 1

    def run_high_water(self, run_id: str) -> int | None:
        """Last allocated run sequence for ``run_id``, ``None`` when unknown."""
        with self._lock:
            entry = self._runs.get(run_id)
            if entry is None:
                entry = self._retired.get(run_id)
        return None if entry is None else entry[0]

    def close_run(self, run_id: str) -> int:
        """Forget ``run_id`` and return its last run sequence (``-1`` if none).

        A closed run that is allocated again restarts at ``run_sequence`` 0
        (and is not reported). :func:`fabric.wire.run` therefore never closes
        a run; use this only when the id is known never to recur.
        """
        with self._lock:
            entry = self._runs.pop(run_id, None)
            if entry is None:
                entry = self._retired.pop(run_id, None)
        return -1 if entry is None else entry[0]

    @staticmethod
    def _fingerprint(run_id: str) -> int:
        # Process-local str hash; the table never outlives the process epoch.
        return hash(run_id) or 1

    def _forget(self, run_id: str) -> None:
        value = self._fingerprint(run_id)
        self._forgotten[value & self._forgotten_mask] = value

    def _was_forgotten(self, run_id: str) -> bool:
        value = self._fingerprint(run_id)
        slot = value & self._forgotten_mask
        if self._forgotten[slot] != value:
            return False
        self._forgotten[slot] = 0
        return True

    def _report_restart(self, run_id: str, sequence: int) -> None:
        """A forgotten run came back: its ``run_sequence`` restarted at 0."""
        try:
            from ._loss import AffectedItem, get_loss_emitter  # noqa: PLC0415

            get_loss_emitter().record(
                self,
                "run_index_evicted",
                count=1,
                affected=(AffectedItem(source_sequence=sequence, run_id=run_id, run_sequence=0),),
            )
        except Exception:  # noqa: S110 - capture fails open
            pass

    def _after_fork_in_child(self) -> None:
        # The parent's lock may have been held by another thread at fork time.
        self._lock = threading.Lock()
        old = self._identity
        self._identity = SourceIdentity(
            source_id=old.source_id,
            source_epoch=_new_epoch(old.source_epoch),
            component=old.component,
        )
        self._next = 0
        self._runs = OrderedDict()
        self._retired = OrderedDict()
        self._forgotten = array("q", bytes(8 * (self._forgotten_mask + 1)))


_EPOCH_LOCK = threading.Lock()
_LAST_EPOCH = 0


def _new_epoch(previous: int = 0) -> int:
    """``time.time_ns()``, nudged so epochs are unique in this process."""
    global _LAST_EPOCH  # noqa: PLW0603
    with _EPOCH_LOCK:
        epoch = max(time.time_ns(), _LAST_EPOCH + 1, previous + 1)
        _LAST_EPOCH = epoch
        return epoch


def default_source_id(component: Component, service_name: str | None = None) -> str:
    """``<component>-`` + 16 hex of ``sha256(hostname NUL service.name)``."""
    name = service_name or os.environ.get("OTEL_SERVICE_NAME") or "unknown"
    try:
        host = socket.gethostname()
    except OSError:
        host = ""
    digest = hashlib.sha256((host + "\0" + name).encode("utf-8", "surrogatepass")).hexdigest()
    return f"{component}-{digest[:16]}"


_REGISTRY: dict[str, SequenceAllocator] = {}
_REGISTRY_LOCK = threading.Lock()


def get_allocator(component: Component, *, source_id: str | None = None) -> SequenceAllocator:
    """Return the process allocator for ``component``, creating it on first use.

    ``source_id`` (or ``FABRIC_SOURCE_ID``) only applies on first creation; an
    id that is not a valid opaque id is hashed with :func:`encode_opaque_id`.
    """
    if component not in _COMPONENTS:
        raise ValueError(f"unknown component {component!r}")
    existing = _REGISTRY.get(component)
    if existing is not None:
        return existing
    with _REGISTRY_LOCK:
        existing = _REGISTRY.get(component)
        if existing is not None:
            return existing
        chosen = source_id or os.environ.get("FABRIC_SOURCE_ID") or default_source_id(component)
        allocator = SequenceAllocator(
            SourceIdentity(
                source_id=encode_opaque_id(chosen),
                source_epoch=_new_epoch(),
                component=component,
            )
        )
        _REGISTRY[component] = allocator
        return allocator


def _registered_allocators() -> tuple[SequenceAllocator, ...]:
    with _REGISTRY_LOCK:
        return tuple(_REGISTRY[c] for c in sorted(_REGISTRY))


def find_allocator(source_id: str, source_epoch: int) -> SequenceAllocator | None:
    """Find the live allocator whose current identity is ``(source_id, epoch)``."""
    for allocator in all_allocators():
        identity = allocator.identity
        if identity.source_id == source_id and identity.source_epoch == source_epoch:
            return allocator
    return None


def all_allocators() -> tuple[SequenceAllocator, ...]:
    """Registry allocators first (by component), then other live allocators."""
    registered = _registered_allocators()
    with _LIVE_LOCK:
        others = tuple(a for a in list(_LIVE) if a not in registered)
    return registered + others


_RUN_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "fabric_capture_run_id", default=None
)


@contextmanager
def run_scope(run_id: str) -> Iterator[None]:
    """Scope an explicit run id for exchanges made inside the block."""
    if not isinstance(run_id, str) or not OPAQUE_ID_RE.match(run_id):
        raise ValueError("run_id must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    token = _RUN_ID.set(run_id)
    try:
        yield
    finally:
        _RUN_ID.reset(token)


def current_run_id() -> str | None:
    """The run id set by the innermost :func:`run_scope`, if any."""
    return _RUN_ID.get()


def resolve_run(
    allocator: SequenceAllocator,
    *,
    explicit: str | None = None,
    trace_id: int | None = None,
) -> tuple[str, RunIdBasis]:
    """Resolve the run for an exchange (spec 042 §7).

    Order: ``explicit`` -> :func:`run_scope` -> ``FABRIC_RUN_ID`` (all
    ``explicit``), then a valid ``trace_id`` (``trace:<32hex>``), then
    ``source:<source_id>:<epoch>``. Explicit values that are not valid opaque
    ids are hashed rather than rejected, so resolution never raises.
    """
    for candidate in (explicit, _RUN_ID.get(), os.environ.get("FABRIC_RUN_ID")):
        if candidate:
            return encode_opaque_id(candidate), "explicit"
    if isinstance(trace_id, int) and 0 < trace_id <= _MAX_TRACE_ID:
        return f"trace:{trace_id:032x}", "trace"
    identity = allocator.identity
    return encode_opaque_id(f"source:{identity.source_id}:{identity.source_epoch}"), "source"


def _after_fork_in_child() -> None:
    global _REGISTRY_LOCK, _LIVE_LOCK, _EPOCH_LOCK  # noqa: PLW0603
    _REGISTRY_LOCK = threading.Lock()
    _LIVE_LOCK = threading.Lock()
    _EPOCH_LOCK = threading.Lock()
    for allocator in list(_LIVE):
        allocator._after_fork_in_child()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
