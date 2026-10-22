# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Source identity, one monotonic sequence per ``(source_id, epoch)``, run scopes (048 §6)
and label pseudonyms: a caller-supplied run id never leaves the process in clear (H3), and
by default neither does the source id nor the private provider's ``service.name`` (J1)."""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import hmac
import os
import re
import secrets
import socket
import struct
import threading
import uuid
import weakref
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, cast

from ._capture_types import (
    Allocation,
    NullRunTable,
    NullSealAccumulator,
    RunTable,
    SealAccumulator,
    SealEntry,
)

if TYPE_CHECKING:
    import mmap

    from .wire._registration import Registration

OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
RUN_PSEUDONYM_RE = re.compile(r"^r-[0-9a-f]{32}$")
ID_KEY_ENV = "FABRIC_WIRE_ID_KEY"
LABELS_ENV = "FABRIC_WIRE_LABELS"  # "clear": operator labels exported unchanged (opt-in)
Labels = Literal["pseudonymous", "clear"]
IDENTITY_MODE_ENV = "FABRIC_IDENTITY_MODE"  # 049 §2.9 rule 7: ids pseudonymous or clear
IdentityMode = Literal["pseudonymous", "clear"]
# Function v2 prefix -> type string (049 §2.9 rule 2), pinned by pseudonym-v2.json.
V2_TYPES: Mapping[str, str] = {
    "sess": "session", "usr": "user", "act": "actor", "conv": "conversation", "turn": "turn",
    "trg": "trigger", "dsp": "dispatch", "agt": "agent", "tgt": "target", "hst": "host",
    "sbx": "sandbox", "mcps": "mcp_session", "rpc": "jsonrpc", "dbn": "db_namespace",
    "txn": "db_transaction", "mst": "memory_store", "mkey": "memory_key", "p": "provider",
}  # fmt: skip
MIN_ID_KEY_BYTES = 16
# 050 §3.3: one allocator per process, shared by the wire and records inputs. ``"wire"`` is
# accepted as an alias of ``"process"`` for one release.
Component = Literal["process", "wire"]
SOURCE_LABEL_PREFIX = "wire"  # the default source label keeps ``wire-`` across the upgrade
EPOCH_BITS = 63
_LIVE: weakref.WeakSet[SourceAllocator] = weakref.WeakSet()
_REGISTRY: dict[str, SourceAllocator] = {}
_LOCK = threading.Lock()  # guards _LIVE and _REGISTRY
# The registration mirror (050 §3.2 rule 3): ``next_sequence`` is a u64 at this offset of
# the mmap'ed ``.epochs/<epoch>.reg`` file (``wire/_registration.py`` pins the layout).
MIRROR_OFFSET = 256
_MIRROR = struct.Struct("<Q")


@dataclass(eq=False, slots=True)
class RunScope:
    """One ``fabric.wire.run()`` block entry; ``closed`` is set under the allocator lock."""

    run_id: str
    scope_id: str
    parent: RunScope | None
    closed: bool = False


_SCOPE: contextvars.ContextVar[RunScope | None] = contextvars.ContextVar("fabric_run", default=None)


def _open_scope() -> RunScope | None:  # the context's innermost scope not yet closed
    scope = _SCOPE.get()
    while scope is not None and scope.closed:
        scope = scope.parent
    return scope


def encode_opaque_id(value: str) -> str:
    """``value`` when it is a valid opaque id, else ``"h-"`` + 40 hex of its sha256."""
    if OPAQUE_ID_RE.fullmatch(value):
        return value
    return "h-" + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:40]


def label_pseudonym(prefix: str, value: str, key: bytes | None = None) -> str:
    """``prefix`` + the first 32 hex of HMAC-SHA256(``key``, value), or of SHA-256(value)
    without a key: one function for run (``r-``), source (``s-``), service (``svc-``) and
    report tenant (``t-``) labels, pinned by ``run-id-pseudonym-v1.json``."""
    data = value.encode("utf-8", "surrogatepass")
    digest = hmac.new(key, data, hashlib.sha256) if key else hashlib.sha256(data)
    return prefix + digest.hexdigest()[:32]


def run_pseudonym(run_id: str, key: bytes | None = None) -> str:
    """The emitted form of a caller-supplied run id (H3): ``r-`` + :func:`label_pseudonym`.
    Spans, markers, spool records, content descriptors and reports carry only this;
    ``fabric.reconstruct --run`` maps a clear id the same way."""
    return label_pseudonym("r-", run_id, key)


def source_label(source_id: str, key: bytes | None = None, *, clear: bool = False) -> str:
    """The emitted source id (J1): ``s-`` + :func:`label_pseudonym`, or the operator's label
    unchanged when ``clear`` (``FABRIC_WIRE_LABELS=clear``). A caller value is always mapped,
    even an ``s-``-shaped one (Sol P0-A round 5 #1): shape never proves it was emitted."""
    if clear:
        return source_id
    return label_pseudonym("s-", source_id, key)


def operator_label(value: str, key: bytes | None = None, *, clear: bool = False) -> str:
    """An operator label (049 §4.2: policy ids, workflow nodes) as emitted: ``lbl-`` +
    :func:`label_pseudonym` (keyed when ``key`` is set), unchanged only when ``clear``."""
    return value if clear else label_pseudonym("lbl-", value, key)


def pseudonym_v2(prefix: str, value: str, key: bytes | None) -> str | None:
    """Function v2 (049 §2.9): ``prefix-`` + the first 32 hex of HMAC-SHA256(k_type, value),
    k_type = HMAC-SHA256(key, ``"fabric-id/v2/" + type``). ``None`` without a key: an
    unkeyed hash of a low-entropy id is not a pseudonym, so the id is omitted."""
    if key is None:
        return None
    k_type = hmac.new(key, f"fabric-id/v2/{V2_TYPES[prefix]}".encode(), hashlib.sha256).digest()
    data = value.encode("utf-8", "surrogatepass")
    return f"{prefix}-" + hmac.new(k_type, data, hashlib.sha256).hexdigest()[:32]


def key_id(key: bytes) -> str:
    """The id key's public id (049 §2.9 rule 6): ``kid-`` + 8 hex; never the key."""
    return "kid-" + hmac.new(key, b"fabric-id/v2/kid", hashlib.sha256).hexdigest()[:8]


def identity_mode_from_env(environ: Mapping[str, str]) -> IdentityMode:
    """``FABRIC_IDENTITY_MODE``: unset/``pseudonymous`` (default) or ``clear``; else
    ``ValueError`` (fixed text, never the value)."""
    value = (environ.get(IDENTITY_MODE_ENV) or "pseudonymous").strip()
    if value not in ("pseudonymous", "clear"):
        raise ValueError(f"{IDENTITY_MODE_ENV} must be 'pseudonymous' or 'clear'")
    return cast("IdentityMode", value)


def labels_from_env(environ: Mapping[str, str]) -> Labels:
    """``FABRIC_WIRE_LABELS``: unset/``pseudonymous`` (default) or ``clear``; else
    ``ValueError`` (fixed text, never the value)."""
    value = (environ.get(LABELS_ENV) or "pseudonymous").strip()
    if value not in ("pseudonymous", "clear"):
        raise ValueError(f"{LABELS_ENV} must be 'pseudonymous' or 'clear'")
    return cast("Labels", value)


def check_id_key(key: bytes | None) -> bytes | None:
    """``key`` when absent or at least 16 bytes, else ``ValueError`` (fixed text, no value)."""
    if key is not None and (not isinstance(key, bytes) or len(key) < MIN_ID_KEY_BYTES):
        raise ValueError(f"{ID_KEY_ENV} must be at least {MIN_ID_KEY_BYTES} bytes")
    return key


def id_key_from_env(environ: Mapping[str, str], name: str = ID_KEY_ENV) -> bytes | None:
    """The run-id pseudonym key named by ``name`` (unset or empty: ``None``); a secret, never
    logged or echoed."""
    value = environ.get(name) or ""
    return check_id_key(value.encode("utf-8", "surrogatepass")) if value else None


def _new_epoch() -> int:
    """A CSPRNG epoch (050 §3.2 rule 1): 63 random bits, redrawn while 0. Needs no lock
    (``os.urandom`` is fork-safe); two processes sharing a spool are told apart by
    registration, never by the clock or the pid."""
    while not (epoch := secrets.randbits(EPOCH_BITS)):
        pass  # pragma: no cover - probability 2**-63
    return epoch


def _canonical(component: str) -> str:
    """``"process"`` for the process component and its ``"wire"`` alias; else ``""``."""
    return "process" if component in ("process", "wire") else ""


class SourceAllocator:
    """The process's one sequence allocator (050 §3.3), shared by the wire and records
    inputs: thread-safe; a forked child gets a new epoch and restarts at 0.

    Every allocation goes through :meth:`allocate` / :meth:`allocate_for`, which return an
    :class:`Allocation`. Under the allocator lock, and with no I/O or system call, each one
    resolves the scope, asks the run table for the open segment, stores the next sequence
    in the registration mirror and in this process's fork-ledger slot (memory stores into
    shared maps), and counts the position outstanding in the seal accumulator.
    :meth:`next_sequence` and :meth:`next_sequence_for` are the 3-tuple projection kept for
    callers that unpack ``(epoch, sequence, scope)``."""

    __slots__ = (
        "__weakref__", "_fork_note", "_lock", "_mirror", "_next", "component", "epoch",
        "registration", "seals", "segments", "settle_failures", "settled", "source_id",
    )  # fmt: skip

    def __init__(self, source_id: str, component: Component = "process") -> None:
        if not _canonical(component) or not OPAQUE_ID_RE.fullmatch(str(source_id)):
            raise ValueError("component must be process and source_id an opaque id")
        self.source_id = source_id
        self.component: Component = "process"
        self._lock, self._next = threading.Lock(), 0
        # 050 §3.3: the run table opens segments at allocation; the pipeline's seal
        # accumulator counts outstanding positions. No-ops until WP-12 and WP-11a attach.
        self.segments: RunTable = NullRunTable()
        self.seals: SealAccumulator = NullSealAccumulator()
        # 050 §3.2: this epoch's registration and its mmap mirror (``None``: unregistered).
        self.registration: Registration | None = None
        self._mirror: mmap.mmap | None = None
        # The fork ledger (wire/_forks.py): set in a forked child that holds a slot.
        self._fork_note: Callable[[int, int], None] | None = None
        self.settled = self.settle_failures = 0  # settlement accounting (worker paths)
        self.epoch = _new_epoch()
        with _LOCK:
            _LIVE.add(self)

    def attach(
        self, *, segments: RunTable | None = None, seals: SealAccumulator | None = None
    ) -> None:
        """Attach the run table and the seal accumulator (``None``: the no-op ones)."""
        with self._lock:
            self.segments = segments if segments is not None else NullRunTable()
            self.seals = seals if seals is not None else NullSealAccumulator()

    def bind_registration(
        self, registration: Registration, mirror: mmap.mmap | None, *, drawn_from: int
    ) -> bool:
        """Adopt ``registration`` for this allocator's epoch (050 §3.2 rule 2). The
        registration may hold a redrawn epoch: it replaces ``drawn_from`` only while nothing
        was allocated in it, else ``False`` (nothing changes). The mirror is brought up to
        date at once and on every allocation after."""
        with self._lock:
            if self.epoch != drawn_from or (registration.epoch != self.epoch and self._next):
                return False
            self.epoch = registration.epoch
            self.registration, self._mirror = registration, mirror
            if mirror is not None:
                with contextlib.suppress(Exception):
                    _MIRROR.pack_into(mirror, MIRROR_OFFSET, self._next)
            return True

    def unbind_registration(self, registration: Registration | None = None) -> None:
        """Stop mirroring (``registration``: only when it is still the bound one)."""
        with self._lock:
            if registration is None or self.registration is registration:
                self.registration, self._mirror = None, None

    def set_fork_note(self, note: Callable[[int, int], None] | None) -> None:
        """The fork ledger's ``note(epoch, sequence)`` of this child (``None``: none).
        Called from fork hooks only, while the child runs one thread."""
        self._fork_note = note

    def _allocated(self, scope: RunScope | None) -> Allocation:
        """One position for ``scope`` (050 §3.3). Holds ``_lock``; no I/O, no system call.
        A failing hook never fails the allocation: the position is then segment-less."""
        sequence = self._next
        self._next = sequence + 1
        allocation = Allocation(self.epoch, sequence, scope)
        try:
            segment = self.segments.on_allocate(allocation)
        except Exception:
            segment = None
        if (mirror := self._mirror) is not None:
            try:  # a memory store into the MAP_SHARED registration file
                _MIRROR.pack_into(mirror, MIRROR_OFFSET, sequence + 1)
            except Exception:  # an unmapped mirror: stop mirroring
                self._mirror = None
        if (note := self._fork_note) is not None:
            try:  # a memory store into the installing process's fork ledger
                note(allocation.epoch, sequence)
            except Exception:
                self._fork_note = None
        if segment is not None:
            allocation = allocation._replace(segment_id=segment)
            with contextlib.suppress(Exception):
                self.seals.note_allocated(segment, sequence)
        return allocation

    def allocate(self) -> Allocation:
        """Allocate one position in the innermost open run scope (050 §3.3)."""
        with self._lock:
            return self._allocated(_open_scope())

    def allocate_for(self, scope: RunScope | None) -> Allocation:
        """Allocate one position for work begun earlier under ``scope``: the innermost of
        its scopes still open now, read under the lock ``run_end`` closes scopes under, so
        the sequence never lies outside a closed scope's markers."""
        with self._lock:
            while scope is not None and scope.closed:
                scope = scope.parent
            return self._allocated(scope)

    def settle(self, segment_id: str | None, sequence: int, entry: SealEntry) -> None:
        """A position of ``segment_id`` was written (``entry`` its record digest) or lost
        (``"loss:<reason>"``): hand it to the seal accumulator, which decrements its
        outstanding count (050 §3.3). Worker and loss paths only; never raises; a
        segment-less position settles nothing."""
        if segment_id is None:
            return
        try:
            self.seals.settle(segment_id, sequence, entry)
        except Exception:
            self.settle_failures += 1
        else:
            self.settled += 1

    def next_sequence(self) -> tuple[int, int, RunScope | None]:
        """:meth:`allocate` as ``(epoch, sequence, innermost open run scope)``."""
        epoch, sequence, scope, _, _ = self.allocate()
        return epoch, sequence, scope

    def next_sequence_for(self, scope: RunScope | None) -> tuple[int, int, RunScope | None]:
        """:meth:`allocate_for` as ``(epoch, sequence, scope)``."""
        epoch, sequence, found, _, _ = self.allocate_for(scope)
        return epoch, sequence, found

    def open_scope(self, scope: RunScope) -> tuple[int, int]:  # its run_start position
        return self.last_sequence()

    def close_scope(self, scope: RunScope) -> tuple[int, int]:  # run_end; later calls: outside
        with self._lock:
            scope.closed = True
            return self.epoch, self._next - 1

    def last_sequence(self) -> tuple[int, int]:  # (epoch, last allocated), -1 before the first
        with self._lock:
            return self.epoch, self._next - 1

    def seal(self) -> tuple[int, int]:
        """End the epoch: its ``(epoch, last sequence)``; nothing is allocated in it after
        ``last`` (what makes a ``final`` heartbeat true): later allocations use a new,
        unregistered one (050 §3.2 rule 4), so the sealed epoch's mirror is left as is."""
        with self._lock:
            sealed = self.epoch, self._next - 1
            self.epoch, self._next = _new_epoch(), 0
            self.registration, self._mirror = None, None
            return sealed


def default_source_id(component: Component = "process", service_name: str | None = None) -> str:
    """``wire-`` + 16 hex of ``sha256(hostname NUL service.name)``: the process component
    keeps the ``wire-`` label (050 §3.3), so source ids are unchanged across the upgrade."""
    if not _canonical(component):
        raise ValueError("component must be process")
    name = service_name or os.environ.get("OTEL_SERVICE_NAME") or "unknown"
    seed = f"{socket.gethostname()}\0{name}".encode("utf-8", "surrogatepass")
    return f"{SOURCE_LABEL_PREFIX}-{hashlib.sha256(seed).hexdigest()[:16]}"


def get_allocator(
    component: Component = "process", *, source_id: str | None = None
) -> SourceAllocator:
    """The process allocator (``"wire"`` is an alias of ``"process"``); ``source_id``
    applies on first creation only."""
    if not (key := _canonical(component)):
        raise ValueError("component must be process")
    with _LOCK:
        if (existing := _REGISTRY.get(key)) is not None:
            return existing
    chosen = source_id or os.environ.get("FABRIC_SOURCE_ID") or default_source_id()
    created = SourceAllocator(encode_opaque_id(chosen))
    with _LOCK:
        return _REGISTRY.setdefault(key, created)


def live_allocators() -> list[SourceAllocator]:
    """Every live allocator of this process (registration and fork hooks)."""
    with _LOCK:
        return list(_LIVE)


@contextmanager
def run_scope(
    run_id: str, key: bytes | None = None, *, emitted: str | None = None
) -> Iterator[RunScope]:
    """A new uniquely identified scope for ``run_id``, current for the block (closed after);
    the scope carries :func:`run_pseudonym` of ``run_id``, never the clear value, or
    ``emitted`` (a generated fallback) when no value derived from ``run_id`` may leave the
    process (049 §2.9 rule 5)."""
    if not isinstance(run_id, str) or not OPAQUE_ID_RE.fullmatch(run_id):
        raise ValueError("run_id must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    scope = RunScope(emitted or run_pseudonym(run_id, key), str(uuid.uuid4()), _SCOPE.get())
    token = _SCOPE.set(scope)
    try:
        yield scope
    finally:
        scope.closed = True  # normally already closed under the allocator lock
        _SCOPE.reset(token)


def current_run_scope() -> RunScope | None:
    """The innermost open run scope of the current context."""
    return _open_scope()


def current_run_id() -> str | None:
    return scope.run_id if (scope := _open_scope()) is not None else None


def resolve_run_id(allocator: SourceAllocator, *, trace_id: int | None = None) -> str:
    """Innermost open run scope (its ``r-`` pseudonym), ``trace:<32hex>``, else
    ``source:<id>:<epoch>``."""
    if (scope := _open_scope()) is not None:
        return scope.run_id
    if isinstance(trace_id, int) and 0 < trace_id < 1 << 128:
        return f"trace:{trace_id:032x}"
    return encode_opaque_id(f"source:{allocator.source_id}:{allocator.epoch}")


_PROCESS_SOURCE: list[str] = []  # this process's random source id, once generated
_MAX_GENERATED_IDS = 65536
_MINT = object()  # only this module mints an EmittedId


def process_source_id() -> str:
    """This process's random source id (049 §2.9 rule 5): ``s-`` + 32 random hex, the same
    for every caller in the process, new in a forked child. Continuity across restarts is
    lost by design: nothing derived from a host- or caller-supplied id."""
    with _LOCK:
        if not _PROCESS_SOURCE:
            _PROCESS_SOURCE.append("s-" + uuid.uuid4().hex)
        return _PROCESS_SOURCE[0]


class EmittedId(str):
    """An id Fabric emitted or minted (049 §2.9), as returned to callers: a run or source
    id a recorder pins, a call, operation or attempt id it minted. It is recognised by its
    type and issuer, never by its shape or by a lookup (Sol P0-A round 6 #1): passed back
    to a recorder of the same issuer it is kept as is, so ids pass through more than one
    layer and a ``parent_call_id`` joins its parent's ``call_id`` for as long as the value
    lives. A plain ``str`` is always caller input and always mapped, even an ``r-``/``s-``/
    ``lbl-``-shaped one; an id that lost its type (serialised and read back) is a plain
    string again. Only :mod:`fabric._sequence` mints one."""

    _issuer: str

    def __new__(cls, value: str, issuer: str, token: object = None) -> EmittedId:
        if token is not _MINT:
            raise TypeError("emitted ids are minted by Fabric recorders only")
        minted = super().__new__(cls, value)
        minted._issuer = issuer
        return minted

    def __reduce__(self) -> tuple[object, ...]:
        return _remint, (str(self), self._issuer)

    def __copy__(self) -> EmittedId:
        return self

    def __deepcopy__(self, memo: object) -> EmittedId:
        return self

    def issued_by(self, issuer: str) -> bool:
        return self._issuer == issuer


def _remint(value: str, issuer: str) -> EmittedId:  # unpickling and copying
    return EmittedId(value, issuer, _MINT)


class GeneratedIds:
    """Emitted ids when no value derived from a caller-supplied id may leave the process
    (049 §2.9 rule 5: the production profile without ``FABRIC_WIRE_ID_KEY``). The source id
    is :func:`process_source_id`; a run id is its generated source fallback
    (``source:<source>:<epoch>``); any other caller id is a random ``g-`` id generated on
    first sight and remembered (at most 65536 values; beyond that a value gets a new one
    each time) so one recorder's records still join. An :class:`EmittedId` of this
    instance maps to itself, so ids may pass through more than one layer."""

    def __init__(self) -> None:
        self._lock = threading.Lock()  # taken on the app thread; replaced in a forked child
        self._ids: dict[str, EmittedId] = {}
        self._issuer = "gen-" + uuid.uuid4().hex
        _GENERATED.add(self)

    def _mine(self, value: str) -> bool:
        return isinstance(value, EmittedId) and value.issued_by(self._issuer)

    def mint(self, value: str) -> EmittedId:
        """A Fabric-minted id (a call id) as this instance's: it maps to itself."""
        return EmittedId(value, self._issuer, _MINT)

    def source(self, value: str) -> EmittedId:  # nothing is derived from the value
        return self.mint(process_source_id())

    def run(self, value: str, epoch: int) -> EmittedId:  # nothing is derived from the value
        return value if self._mine(value) else (  # type: ignore[return-value]
            self.mint(encode_opaque_id(f"source:{process_source_id()}:{epoch}")))  # fmt: skip

    def agent(self, value: str) -> EmittedId:
        return self.other(value)

    def other(self, value: str) -> EmittedId:
        if self._mine(value):
            return value  # type: ignore[return-value]
        with self._lock:
            if (found := self._ids.get(value)) is not None:
                return found
            generated = self.mint("g-" + uuid.uuid4().hex)
            if len(self._ids) < _MAX_GENERATED_IDS:
                self._ids[value] = generated
            return generated


class KeyedIds:
    """Emitted explicit-line ids in the ``pseudonymous`` identity mode with
    ``FABRIC_WIRE_ID_KEY`` (049 §2.9 rules 1-3), as the wire line and ``decision()`` emit
    them: the run id is :func:`run_pseudonym` (``r-``) and the source id
    :func:`source_label` (``s-``), both function v1 keyed; an agent id is its v2 ``agt-``
    pseudonym; any other caller id (operation, attempt, stream, parent call: step labels,
    049 §2.3) is the keyed v1 operator label ``lbl-``. Deterministic, so records join
    across recorders, processes and restarts that hold the key.

    Provenance, never shape, decides what passes through (Sol P0-A rounds 4-6): every
    result is an :class:`EmittedId` issued under this key, and such a value maps to itself
    (in any recorder holding the key), so ids pass through more than one layer and a
    ``parent_call_id`` joins its parent's ``call_id``; every plain string, even a 32-hex
    or ``r-``/``s-``/``lbl-``-shaped one, is mapped. Nothing is cached, so no amount of
    traffic changes an id a live caller holds. Continuity across processes comes from
    passing the same clear id, never an emitted one."""

    __slots__ = ("_issuer", "_key")

    def __init__(self, key: bytes) -> None:
        self._key = key
        self._issuer = key_id(key)

    def __repr__(self) -> str:  # the key is a secret
        return "KeyedIds()"

    def _mine(self, value: str) -> bool:
        return isinstance(value, EmittedId) and value.issued_by(self._issuer)

    def mint(self, value: str) -> EmittedId:
        """A Fabric-minted id (a call id) as this key's: it maps to itself."""
        return EmittedId(value, self._issuer, _MINT)

    def source(self, value: str) -> EmittedId:
        return value if self._mine(value) else self.mint(source_label(value, self._key))  # type: ignore[return-value]

    def run(self, value: str, epoch: int) -> EmittedId:  # the same in every epoch
        return value if self._mine(value) else self.mint(run_pseudonym(value, self._key))  # type: ignore[return-value]

    def agent(self, value: str) -> EmittedId:
        if self._mine(value):
            return value  # type: ignore[return-value]
        return self.mint(cast("str", pseudonym_v2("agt", value, self._key)))

    def other(self, value: str) -> EmittedId:
        if self._mine(value):
            return value  # type: ignore[return-value]
        return self.mint(label_pseudonym("lbl-", value, self._key))


EmittedIds = GeneratedIds | KeyedIds
_GENERATED: weakref.WeakSet[GeneratedIds] = weakref.WeakSet()


def _reset_generated_ids() -> None:
    """A forked child: every :class:`GeneratedIds` gets a fresh lock (049 §7.1: ``other``
    runs on the app thread; a parent thread inside it at the fork would hold the child's
    lock forever). The ids already generated are kept, so the child's records still join
    the parent's."""
    for ids in list(_GENERATED):
        with contextlib.suppress(Exception):
            ids._lock = threading.Lock()


def emitted_ids(profile: str, key: bytes | None, mode: IdentityMode) -> EmittedIds | None:
    """How the explicit line emits caller-supplied ids (049 §2.9): generated in the
    production profile without the key (rule 5, whatever the mode); keyed pseudonyms in
    the ``pseudonymous`` mode with the key; ``None`` (as given) in the ``clear`` mode, or
    in the local profile without the key."""
    if profile == "production" and key is None:
        return GeneratedIds()
    if key is not None and mode == "pseudonymous":
        return KeyedIds(key)
    return None


def _after_fork_in_child() -> None:
    """A forked child: new locks, a new random source id, and for every allocator a new
    epoch at sequence 0 with no registration (050 §3.2 rule 4: the child never writes the
    parent's mirror; ``wire/_registration.py`` closes the inherited descriptor and map)."""
    global _LOCK  # noqa: PLW0603
    _LOCK = threading.Lock()  # another parent thread may have held it
    _PROCESS_SOURCE.clear()  # a forked child is a new process: a new random source id
    for allocator in list(_LIVE):
        allocator._lock, allocator._next, allocator.epoch = threading.Lock(), 0, _new_epoch()
        allocator.registration, allocator._mirror = None, None
    _reset_generated_ids()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
