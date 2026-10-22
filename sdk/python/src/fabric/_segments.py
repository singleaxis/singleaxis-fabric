# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Segments and run structure (spec 050 §3.6): the run table, seal triggers, resume
tokens, ``end_run`` and the run-outcome hook.

A *segment* is one contiguous piece of a run recorded by one ``(source, epoch)``
(049 §2.10). :class:`SegmentTable` is the process run table: one :class:`RunEntry` per
emitted run id, mutated only under the allocator lock. The allocator calls
:meth:`SegmentTable.on_allocate` under that lock on every allocation, so segment membership
is exact; ``fabric.wire.run()`` calls :meth:`SegmentTable.enter` / :meth:`SegmentTable.exit`.

Run identity (R1). Every segment's ``fabric.run.id`` is decided once, at segment open, by
the first rule that applies (:func:`resolve_identity`; pinned by ``resume-token-v2.json``):

1. valid ``fr3/`` tokens with one correlation id ``c``: ``c`` verbatim (``token``);
2. differing correlation ids and a clear run id: the mapped clear id (``caller_join``);
3. differing correlation ids, no clear run id: the lowest by byte order (``token_conflict``);
4. no valid ``fr3/`` token and a clear run id (argument or same-host ``FABRIC_RUN_ID``):
   the mapped clear id (``caller``);
5. neither: a minted ``r-`` + 32 CSPRNG hex, never derived from caller input (``minted``).

Rules 4 and 5 report ``legacy`` when the only valid tokens are ``fr2/``. The run's
correlation id is its run id, and every token it issues carries it, so A -> B -> C keeps
one run id even when B is wholly lost. A clear run id never leaves the process in the
pseudonymous mode (the default): it is mapped by the keyed function, and only Fabric-emitted
tokens cross a process boundary (OD-7).

Passivity (R9): nothing here does I/O; the hooks take the allocator lock only for memory
updates; every public function fails open (``None``/``()``/``False``/a status) and raises
only under ``FABRIC_RECORDS_STRICT=1``.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import secrets
import threading
import uuid
import weakref
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import unquote

from . import (
    _loss,  # noqa: F401 - its after-fork hook (marker queue reset) runs before ours
    _manifest,  # its after-fork hook (the child's manifest 0) runs before ours
)
from ._capture_types import (
    BRANCH_ID_RE,
    MAX_BRANCHES,
    MAX_RUN_LINKS,
    RUN_OUTCOMES,
    STOP_REASONS,
    EndRunStatus,
    IdBasis,
    Marker,
    RecordsMisuseError,
    RunEntry,
    RunOutcome,
    ScopeStatus,
    SealedSegment,
    StopReason,
    fail_open,
    misuse,
)
from ._seal import SegmentSeals
from ._sequence import (
    OPAQUE_ID_RE,
    EmittedId,
    GeneratedIds,
    IdentityMode,
    KeyedIds,
    RunScope,
    SourceAllocator,
    current_run_scope,
    encode_opaque_id,
    identity_mode_from_env,
    pseudonym_v2,
    run_pseudonym,
)

if TYPE_CHECKING:
    from ._capture_types import Allocation, SealAccumulator
    from ._loss import LossEmitter
    from .wire import WireHandle

_LOG = logging.getLogger("fabric.wire")

SEGMENT_PREFIX, BRANCH_PREFIX = "seg-", "br-"
TOKEN_PREFIX, LEGACY_TOKEN_PREFIX = "fr3/", "fr2/"
RUN_ID_ENV, RESUME_TOKEN_ENV = "FABRIC_RUN_ID", "FABRIC_RUN_RESUME_TOKEN"
OPEN_DEADLINE_ENV, DEFAULT_OPEN_DEADLINE_S = "FABRIC_RUN_OPEN_DEADLINE_S", 604800
OPEN_DEADLINE_RANGE = (60, 31536000)  # capture/v1 marker check
MAX_PREDECESSORS = MAX_BRANCHES  # capture/v1: a run_start names at most 64 predecessors
MAX_SEALED_KEPT = 64  # sealed segments remembered per run (diagnostics; the graph is offline)
# A manifest digest stands in for "no manifest in force" (its build failed or the epoch has
# no chain): the token grammar needs one; the verifier reports that epoch manifest-less.
NO_MANIFEST_DIGEST = "sha256:" + "0" * 64
_INT64_MAX = (1 << 63) - 1
_ROOT = ("none",)
_ENTRY_RE = re.compile(
    r"^(?P<segment_id>seg-[0-9a-f]{32})/(?P<source_id>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})/"
    r"(?P<epoch>[1-9][0-9]{0,18})/(?P<last_sequence>-1|0|[1-9][0-9]{0,18})/"
    r"(?P<manifest_digest>sha256:[0-9a-f]{64})$"
)

# --- tokens (§3.6 "Tokens"; resume-token-v2.json) -------------------------------------------


@dataclass(frozen=True, slots=True)
class ResumeToken:
    """A parsed resume token: ``fr3/`` (with the run correlation id) or legacy ``fr2/``."""

    version: Literal[2, 3]
    correlation_id: str | None
    segment_id: str
    source_id: str
    epoch: int
    last_sequence: int
    manifest_digest: str
    branch_id: str | None = None

    @property
    def entry(self) -> str:
        """The predecessor entry this token names (049 X41)."""
        return format_entry(self.segment_id, self.source_id, self.epoch, self.last_sequence,
                            self.manifest_digest)  # fmt: skip


def _parse_entry(body: str) -> tuple[str, str, int, int, str, str | None] | None:
    branch = None
    head, _, tail = body.rpartition("/")
    if BRANCH_ID_RE.fullmatch(tail):
        body, branch = head, tail
    match = _ENTRY_RE.fullmatch(body)
    if match is None:
        return None
    epoch, last = int(match["epoch"]), int(match["last_sequence"])
    if epoch > _INT64_MAX or last > _INT64_MAX:
        return None
    return (match["segment_id"], match["source_id"], epoch, last, match["manifest_digest"],
            branch)  # fmt: skip


def parse_token(token: object) -> ResumeToken | None:
    """``fr3/<correlation id>/<entry>[/br-<32 hex>]``, or the legacy ``fr2/<entry>[/br-…]``
    (parsed for one release); ``None`` for anything else (the token is dropped). Strict:
    the v2 grammar of ``p1_reference.parse_token``, never a partial match."""
    if not isinstance(token, str):
        return None
    if token.startswith(TOKEN_PREFIX):
        correlation, sep, rest = token[len(TOKEN_PREFIX) :].partition("/")
        if not sep or not OPAQUE_ID_RE.fullmatch(correlation):
            return None
        parsed = _parse_entry(rest)
        return None if parsed is None else ResumeToken(3, correlation, *parsed)
    if token.startswith(LEGACY_TOKEN_PREFIX):
        parsed = _parse_entry(token[len(LEGACY_TOKEN_PREFIX) :])
        return None if parsed is None else ResumeToken(2, None, *parsed)
    return None


def format_entry(
    segment_id: str, source_id: str, epoch: int, last_sequence: int, manifest_digest: str
) -> str:
    """``<segment_id>/<source_id>/<epoch>/<last_sequence>/sha256:<hex>`` (049 X41)."""
    return f"{segment_id}/{source_id}/{epoch}/{last_sequence}/{manifest_digest}"


def format_token(correlation_id: str, entry: str, branch_id: str | None = None) -> str | None:
    """An ``fr3/`` token; ``None`` when it cannot be issued: a correlation id outside the
    opaque-id pattern (a clear id with ``/`` or a space), a malformed entry or branch id."""
    if not isinstance(correlation_id, str) or not OPAQUE_ID_RE.fullmatch(correlation_id):
        return None
    if _parse_entry(entry) is None or "/br-" in entry:
        return None
    if branch_id is not None and not BRANCH_ID_RE.fullmatch(branch_id):
        return None
    return f"{TOKEN_PREFIX}{correlation_id}/{entry}" + (f"/{branch_id}" if branch_id else "")


def split_tokens(value: str, *, carrier: Literal["env", "baggage"] = "env") -> list[str]:
    """The tokens of one carrier value: comma-separated (a join); a W3C ``baggage`` value
    (``fabric.resume``) is percent-decoded first. Empty items are skipped."""
    if carrier == "baggage":
        value = unquote(value, errors="strict")
    return [item.strip() for item in value.split(",") if item.strip()]


# --- run identity (rules 1-5) -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Identity:
    """What :func:`resolve_identity` decided for one segment open."""

    run_id: str
    id_basis: IdBasis
    predecessors: tuple[str, ...]  # ("none",) for a root
    branch_ids: tuple[str, ...]
    tokens_rejected: int
    correlation_ids: tuple[str, ...]  # of the valid fr3 tokens, byte order
    valid_tokens: int


def resolve_identity(
    tokens: Sequence[str], run_id: str | None, *, map_run: Callable[[str], str],
    mint: Callable[[], str],
) -> Identity:  # fmt: skip
    """Run identity at segment open (§3.6, the five rules; module docstring). ``map_run``
    is the identity rule for a clear run id (``EmittedId`` pass-through, keyed mapping,
    clear mode); ``mint`` draws a fresh ``r-`` correlation id (called only by rule 5).
    Malformed tokens are dropped and counted; without a valid token the segment is a root."""
    parsed = [p for p in map(parse_token, tokens) if p is not None]
    correlations = tuple(sorted(
        {p.correlation_id for p in parsed if p.correlation_id is not None},
        key=lambda c: c.encode("utf-8", "surrogatepass"),
    ))  # fmt: skip
    basis: IdBasis
    if len(correlations) == 1:
        out, basis = correlations[0], "token"
    elif correlations and run_id is not None:
        out, basis = map_run(run_id), "caller_join"
    elif correlations:
        out, basis = correlations[0], "token_conflict"
    elif run_id is not None:
        out, basis = map_run(run_id), "legacy" if parsed else "caller"
    else:
        out, basis = mint(), "legacy" if parsed else "minted"
    predecessors: list[str] = []
    branches: list[str] = []
    for token in parsed:
        if (entry := token.entry) not in predecessors:
            predecessors.append(entry)
        if token.branch_id is not None and token.branch_id not in branches:
            branches.append(token.branch_id)
    return Identity(out, basis, tuple(predecessors) or _ROOT, tuple(branches),
                    len(tokens) - len(parsed), correlations, len(parsed))  # fmt: skip


class IdentityRule:
    """The identity rule (R8) for the ids ``run()`` and ``end_run`` take: pseudonymous by
    default (every caller value mapped, whatever its shape; only an ``EmittedId`` of this
    rule's issuer passes through), ``clear`` only as an explicit opt-in. Run ids use the v1
    function (``r-``, ``run-id-pseudonym-v1``), keyed by ``FABRIC_WIRE_ID_KEY``; in the
    production profile without that key nothing derived from the value leaves the process
    (049 §2.9 rule 5): a run id is the generated source fallback, other run links are
    omitted. ``session_id`` and ``user_id`` are v2 (``sess-``, ``usr-``), omitted without a
    key."""

    __slots__ = ("_fallback", "_ids", "key", "mode", "production_without_key")

    def __init__(
        self, *, key: bytes | None, mode: IdentityMode, production: bool,
        fallback: Callable[[], str] | None = None,
    ) -> None:  # fmt: skip
        self.key, self.mode = key, mode
        self.production_without_key = production and key is None
        self._ids: KeyedIds | GeneratedIds = (
            KeyedIds(key) if key is not None and mode == "pseudonymous" else GeneratedIds()
        )  # fmt: skip
        self._fallback = fallback

    def mine(self, value: object) -> bool:
        """Whether ``value`` is an ``EmittedId`` this rule issued (passes through)."""
        return self._ids._mine(value) if isinstance(value, str) else False

    def mint_run(self) -> EmittedId:
        """Rule 5: ``r-`` + 32 CSPRNG hex, an ``EmittedId`` with no caller input (R1)."""
        return self._ids.mint("r-" + secrets.token_hex(16))

    def run(self, value: str) -> str:
        """A clear run id as emitted (rules 2 and 4). The production profile without a key
        derives nothing from it in either mode (049 §2.9 rule 5, as ``emitted_ids``)."""
        if self.mine(value):
            return str.__str__(value)
        if self.production_without_key and self._fallback is not None:
            return self._fallback()
        if self.mode == "clear":
            return encode_opaque_id(value)
        return run_pseudonym(value, self.key)

    def link(self, value: str) -> str | None:
        """``parent_run_id``, ``resumed_from`` and ``links`` (the run-id rule); ``None`` in
        the production profile without a key (nothing derivable leaves the process)."""
        if self.mine(value):
            return str.__str__(value)
        if self.production_without_key:
            return None
        if self.mode == "clear":
            return encode_opaque_id(value)
        return run_pseudonym(value, self.key)

    def v2(self, prefix: str, value: str) -> str | None:
        """``sess-``/``usr-`` v2 pseudonyms (omitted without a key); clear: as given."""
        if self.production_without_key:
            return None
        if self.mode == "clear":
            return encode_opaque_id(value)
        return pseudonym_v2(prefix, value, self.key)


# --- the run table (§3.6 "State") ---------------------------------------------------------------


@dataclass(slots=True)
class _Run(RunEntry):
    """A :class:`RunEntry` plus what segment opening needs (allocator lock only)."""

    open_epoch: int = 0
    open_last: int = -1  # the last position allocated in (or opening) the open segment
    open_basis: IdBasis | None = None
    open_scope: str | None = None  # scope id of the block whose run_start opened it
    pending_predecessors: tuple[str, ...] = ()
    pending_branch_ids: tuple[str, ...] = ()
    pending_declared: list[str] = field(default_factory=list)
    fork_child: bool = False  # this process is a fork child inside the inherited blocks
    block_scope: str | None = None  # the scope id of the run's latest open block here
    last_entry: str | None = None  # the predecessor entry of the last segment sealed here


@dataclass(frozen=True, slots=True)
class _SealOrder:
    """A seal decided under the allocator lock, requested from the accumulator."""

    segment_id: str
    run_id: str
    epoch: int
    last_sequence: int
    manifest_digest: str
    terminal: bool
    resumable: bool
    branch_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RunPlan:
    """Block entry, prepared outside the allocator lock: the identity and root fields."""

    identity: Identity
    resumable: bool
    final: bool
    open_deadline_s: int | None
    session_id: str | None
    user_id: str | None
    parent_run_id: str | None
    resumed_from: str | None
    links: tuple[str, ...]

    @property
    def run_id(self) -> str:
        return self.identity.run_id


_STAT_NAMES = (
    "segments_opened", "segments_sealed", "tokens_issued", "tokens_rejected", "end_runs",
    "post_terminal_allocations", "forced_seals", "fork_branches", "fork_skipped",
    "declared_branches_dropped", "predecessors_dropped", "internal_errors",
)  # fmt: skip
_TABLES: weakref.WeakSet[SegmentTable] = weakref.WeakSet()


class SegmentTable:
    """The process run table (:class:`~fabric._capture_types.RunTable`), bound at install
    to the allocator, the marker queue and the pipeline's seal accumulator. Every method
    is fail-open; the hooks the allocator calls run under its lock and never take it."""

    def __init__(self) -> None:
        self._allocator: SourceAllocator | None = None
        self._loss: LossEmitter | None = None
        self._seals: SealAccumulator | None = None
        self.rule = IdentityRule(key=None, mode="pseudonymous", production=False)
        self._runs: dict[str, _Run] = {}
        self._segment_runs: dict[str, str] = {}  # open segment id -> run id (forced seals)
        self._closed = False
        self._warned = False
        self._manifest: Any = None  # the ManifestRef in force (cached; read under the lock)
        self._env_run_id: str | None = None
        self._env_tokens: list[str] | None = None
        self._fork: dict[str, tuple[str, tuple[str, ...]]] = {}  # run -> (child seg, preds)
        self._fork_seals: list[_SealOrder] = []
        self._fork_locked: Any = None
        self._stats = dict.fromkeys(_STAT_NAMES, 0)
        _TABLES.add(self)

    # -- wiring ---------------------------------------------------------------------------

    def bind(
        self, *, allocator: SourceAllocator, loss: LossEmitter, seals: SealAccumulator,
        key: bytes | None = None, production: bool = False,
        identity_mode: IdentityMode | None = None,
    ) -> None:  # fmt: skip
        """Bind to the install (``wire.install``, before the handle is published)."""
        self._allocator, self._loss, self._seals = allocator, loss, seals
        mode = identity_mode or identity_mode_from_env(os.environ)
        self.rule = IdentityRule(key=key, mode=mode, production=production,
                                 fallback=self._source_fallback)  # fmt: skip
        on_forced = getattr(seals, "on_forced", ...)
        if on_forced is None or callable(on_forced):
            with contextlib.suppress(Exception):
                seals.on_forced = self.on_forced  # type: ignore[attr-defined]
        self.refresh_manifest()

    def set_environment(self, run_id: str | None, tokens: Sequence[str] | None) -> None:
        """Environment intake (``install_from_env``): same-host ``FABRIC_RUN_ID`` (taken by
        every ``run()`` without a run id) and ``FABRIC_RUN_RESUME_TOKEN`` (consumed once, by
        the first outermost ``run()`` without ``resume``). The clear id is kept in memory
        only and always mapped before anything is emitted."""
        self._env_run_id = run_id or None
        self._env_tokens = list(tokens) if tokens else None

    def _source_fallback(self) -> str:
        allocator = self._allocator
        if allocator is None:
            return "r-" + secrets.token_hex(16)
        return encode_opaque_id(f"source:{allocator.source_id}:{allocator.epoch}")

    @property
    def allocator(self) -> SourceAllocator | None:
        return self._allocator

    @property
    def active(self) -> bool:
        return self._allocator is not None and not self._closed

    def _lock(self) -> threading.Lock:
        allocator = cast("SourceAllocator", self._allocator)
        return allocator._lock

    def _last(self) -> int:
        """The allocator's last allocated sequence (-1 before the first); lock held."""
        allocator = cast("SourceAllocator", self._allocator)
        return allocator._next - 1

    def refresh_manifest(self) -> None:
        """Cache the manifest in force (outside the allocator lock: ``in_force`` may issue a
        post-final epoch's manifest 0)."""
        if self._allocator is not None:
            with contextlib.suppress(Exception):
                self._manifest = _manifest.in_force(self._allocator)

    def _manifest_for(self, epoch: int) -> Any:
        ref = self._manifest
        return ref if ref is not None and getattr(ref, "epoch", None) == epoch else None

    def stats(self) -> dict[str, int]:
        """Counters only (``status()["runs"]``)."""
        return {**self._stats, "open_runs": sum(1 for r in self._runs.values() if r.depth)}

    def get(self, run_id: str) -> RunEntry | None:
        return self._runs.get(run_id)

    # -- markers and seals (allocator lock held) -----------------------------------------------

    def _queue(self, marker: Marker) -> None:
        loss = self._loss
        if loss is None:
            return
        try:
            loss.queue_marker(marker)
        except Exception:
            self._stats["internal_errors"] += 1

    def _run_start(
        self, run: _Run, scope_id: str, last: int, epoch: int, *, segment_id: str,
        predecessors: tuple[str, ...] = (), branch_ids: tuple[str, ...] = (),
        declared: tuple[str, ...] = (), basis: IdBasis | None = None, root: RunPlan | None = None,
    ) -> Marker:  # fmt: skip
        ref = self._manifest_for(epoch)
        fields: dict[str, Any] = {}
        if root is not None and predecessors == _ROOT:
            fields.update(
                resumable=run.resumable, open_deadline_s=root.open_deadline_s,
                session_id=root.session_id, user_id=root.user_id,
                parent_run_id=root.parent_run_id, resumed_from=root.resumed_from,
                links=root.links,
            )  # fmt: skip
        return Marker(
            "run_start", self._source_id(), epoch, last, run_id=run.run_id, scope_id=scope_id,
            segment_id=segment_id, predecessors=predecessors, branch_ids=branch_ids,
            declared_branches=declared, id_basis=basis or run.open_basis or run.id_basis,
            manifest_id=ref.manifest_id if ref is not None else None,
            manifest_digest=ref.digest if ref is not None else None, **fields,
        )  # fmt: skip

    def _source_id(self) -> str:
        return cast("SourceAllocator", self._allocator).source_id

    def _open(
        self, run: _Run, scope_id: str, last: int, epoch: int, *,
        predecessors: tuple[str, ...] | None = None, branch_ids: tuple[str, ...] = (),
        basis: IdBasis | None = None, root: RunPlan | None = None,
    ) -> str:  # fmt: skip
        """Open a segment of ``run`` (minted ``seg-`` id) and queue its ``run_start``:
        predecessors are the given ones, else the pending ones (local continuation, fork
        parent), else ``none`` (the run's root)."""
        segment = SEGMENT_PREFIX + secrets.token_hex(16)
        preds = predecessors or run.pending_predecessors or self._last_entry(run) or _ROOT
        if len(preds) > MAX_PREDECESSORS:
            self._stats["predecessors_dropped"] += len(preds) - MAX_PREDECESSORS
            preds = preds[:MAX_PREDECESSORS]
        branches = (branch_ids or run.pending_branch_ids)[:MAX_BRANCHES]
        declared = tuple(run.pending_declared[:MAX_BRANCHES])
        run.open_basis = basis or run.open_basis or run.id_basis
        marker = self._run_start(run, scope_id, last, epoch, segment_id=segment,
                                 predecessors=preds, branch_ids=branches, declared=declared,
                                 basis=run.open_basis, root=root)  # fmt: skip
        run.open_segment, run.open_epoch, run.open_last, run.open_scope = (
            segment, epoch, last, scope_id)  # fmt: skip
        run.pending_predecessors, run.pending_branch_ids = (), ()
        run.pending_declared.clear()
        self._segment_runs[segment] = run.run_id
        self._stats["segments_opened"] += 1
        self._queue(marker)
        return segment

    def _last_entry(self, run: _Run) -> tuple[str, ...]:
        """The run's last sealed segment here as a predecessor (never a second root)."""
        return (run.last_entry,) if run.last_entry is not None else ()

    def _seal(
        self, run: _Run, *, terminal: bool, branch_ids: tuple[str, ...] = ()
    ) -> _SealOrder | None:
        """Seal ``run``'s open segment (lock held): move it to ``sealed``, make it the
        pending predecessor of the run's next segment here, and return the order for
        :meth:`_request`. ``last_sequence`` is the allocator's last sequence at the seal
        (one counter per source), or the segment's own last position when its epoch ended."""
        segment = run.open_segment
        if segment is None:
            return None
        epoch = run.open_epoch
        allocator = cast("SourceAllocator", self._allocator)
        last = self._last() if allocator.epoch == epoch else run.open_last
        ref = self._manifest_for(epoch)
        digest = ref.digest if ref is not None else NO_MANIFEST_DIGEST
        order = _SealOrder(segment, run.run_id, epoch, max(last, run.open_last), digest,
                           terminal, run.resumable, branch_ids)  # fmt: skip
        run.sealed.append(SealedSegment(segment, order.last_sequence, digest, terminal,
                                        run.resumable, branch_ids))  # fmt: skip
        del run.sealed[:-MAX_SEALED_KEPT]
        run.open_segment, run.open_scope = None, None
        self._segment_runs.pop(segment, None)
        run.last_entry = format_entry(segment, self._source_id(), epoch, order.last_sequence,
                                      digest)  # fmt: skip
        run.pending_predecessors = (run.last_entry,)
        run.terminal_sealed = run.terminal_sealed or terminal
        self._stats["segments_sealed"] += 1
        return order

    def _request(self, order: _SealOrder | None) -> None:
        """Ask the accumulator for the ``segment_seal`` (it writes it once the segment has
        no outstanding positions, §3.7). Safe under the allocator lock."""
        seals = self._seals
        if order is None or seals is None:
            return
        try:
            kwargs: dict[str, Any] = {
                "last_sequence": order.last_sequence, "manifest_digest": order.manifest_digest,
                "terminal": order.terminal, "resumable": order.resumable,
                "branch_ids": order.branch_ids,
            }  # fmt: skip
            if isinstance(seals, SegmentSeals):  # the seal names its run, source and epoch
                seals.request_seal(order.segment_id, **kwargs, run_id=order.run_id,
                                   source_id=self._source_id(), epoch=order.epoch)  # fmt: skip
            else:  # an accumulator of the frozen protocol only
                seals.request_seal(order.segment_id, **kwargs)
        except Exception:
            self._stats["internal_errors"] += 1

    # -- the allocator hook (§3.3 step 2; allocator lock held) -----------------------------------

    def on_allocate(self, allocation: Allocation) -> str | None:
        """The scope's open segment, opening one (a continuation ``run_start``) when the
        run has none open; ``None`` outside a run this table knows."""
        scope = allocation.scope
        if scope is None or self._closed:
            return None
        run = self._runs.get(scope.run_id)
        if run is None:
            return None
        if run.open_segment is not None and run.open_epoch != allocation.epoch:
            self._request(self._seal(run, terminal=False))  # its epoch ended (final, fork)
        if run.open_segment is None:
            if run.terminal_sealed:
                self._stats["post_terminal_allocations"] += 1  # K2: one run id, one run
            self._open(run, scope.scope_id, allocation.sequence - 1, allocation.epoch)
        run.open_last = allocation.sequence
        return run.open_segment

    def on_forced(self, segment_id: str) -> None:
        """The accumulator reached 1,000,000 positions in ``segment_id`` (§3.7): seal it
        non-terminal; the run's next allocation continues it in a new local segment. Called
        from ``note_allocated``, under the allocator lock."""
        run_id = self._segment_runs.get(segment_id)
        run = self._runs.get(run_id) if run_id is not None else None
        if run is None or run.open_segment != segment_id:
            return
        self._stats["forced_seals"] += 1
        self._request(self._seal(run, terminal=False))

    # -- block entry and exit (fabric.wire.run) --------------------------------------------------

    def prepare(
        self, run_id: object = None, *, session_id: object = None, user_id: object = None,
        parent_run_id: object = None, resumed_from: object = None, links: object = (),
        resume: object = None, resumable: object = False, final: object = False,
        open_deadline_s: object = None, outermost: bool = True,
    ) -> RunPlan:  # fmt: skip
        """Resolve one block entry's run identity and root fields (outside the lock). A
        malformed optional argument is dropped (``api_misuse``)."""
        tokens = _token_list(resume)
        if resume is None and outermost and self._env_tokens is not None:
            tokens, self._env_tokens = self._env_tokens, None  # consumed once
        clear = run_id if isinstance(run_id, str) else self._env_run_id
        identity = resolve_identity(tokens, clear, map_run=self.rule.run,
                                    mint=self.rule.mint_run)  # fmt: skip
        self._rejected(identity.tokens_rejected)
        deadline = None
        if open_deadline_s is not None:
            low, high = OPEN_DEADLINE_RANGE
            if type(open_deadline_s) is int and low <= open_deadline_s <= high:
                deadline = open_deadline_s
            else:
                misuse("open_deadline_s outside 60..31536000")
        return RunPlan(
            identity, _flag(resumable, "resumable"), _flag(final, "final"), deadline,
            self._v2("sess", session_id), self._v2("usr", user_id),
            self._link(parent_run_id), self._link(resumed_from), self._links(links),
        )  # fmt: skip

    def _rejected(self, count: int) -> None:
        if count:
            self._stats["tokens_rejected"] += count
            if not self._warned:
                self._warned = True
                _LOG.warning("fabric.wire: resume token dropped (%s)", "MalformedResumeToken")

    def _v2(self, prefix: str, value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value:
            misuse(f"{prefix} id must be a non-empty str")
            return None
        mapped = self.rule.v2(prefix, value)
        return str.__str__(mapped) if mapped is not None else None

    def _link(self, value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value:
            misuse("run link must be a non-empty str")
            return None
        return self.rule.link(value)

    def _links(self, values: object) -> tuple[str, ...]:
        if isinstance(values, str) or not isinstance(values, Iterable):
            misuse("links must be a sequence of str")
            return ()
        out: list[str] = []
        for value in values:
            mapped = self._link(value)
            if mapped is not None and mapped not in out:
                out.append(mapped)
        if len(out) > MAX_RUN_LINKS:
            misuse("at most 16 run links")
            out = out[:MAX_RUN_LINKS]
        return tuple(out)

    def enter(self, plan: RunPlan, scope: RunScope) -> None:
        """Block entry (§3.6): the run's entry (new, or re-entered), its depth, and the
        block's ``run_start``. A block opens a segment when none is open (the root with
        ``predecessors=["none"]``, a local continuation, or the segment its tokens resume);
        inside an open segment its ``run_start`` names that segment and no predecessors."""
        if not self.active:
            return
        self.refresh_manifest()
        identity = plan.identity
        resumed = identity.valid_tokens > 0
        orders: list[_SealOrder | None] = []
        with self._lock():
            if self._closed:
                return
            last, epoch = self._last(), cast("SourceAllocator", self._allocator).epoch
            run = self._runs.get(plan.run_id)
            new = run is None
            if run is None:
                run = self._runs[plan.run_id] = _Run(
                    plan.run_id, plan.run_id, identity.id_basis,
                    open_deadline_s=plan.open_deadline_s,
                )  # fmt: skip
            elif run.terminal_sealed and run.depth == 0:
                self._stats["post_terminal_allocations"] += 1  # K2
            run.depth += 1
            run.block_scope = scope.scope_id
            run.resumable = run.resumable or plan.resumable or resumed
            run.final_block = run.final_block or plan.final
            if run.open_segment is not None and run.open_epoch != epoch:
                orders.append(self._seal(run, terminal=False))
            if resumed and run.open_segment is not None:  # a join into an open segment
                orders.append(self._seal(run, terminal=False))
                joined = run.pending_predecessors + identity.predecessors
                self._open(run, scope.scope_id, last, epoch, predecessors=joined,
                           branch_ids=identity.branch_ids, basis=identity.id_basis)  # fmt: skip
            elif run.open_segment is None:
                preds: tuple[str, ...] | None = identity.predecessors if resumed else None
                if preds is None and new:
                    preds = _ROOT
                self._open(run, scope.scope_id, last, epoch, predecessors=preds,
                           branch_ids=identity.branch_ids, basis=identity.id_basis,
                           root=plan if new else None)  # fmt: skip
                run.root_done = True
            else:
                self._queue(self._run_start(run, scope.scope_id, last, epoch,
                                            segment_id=run.open_segment))  # fmt: skip
            for order in orders:
                self._request(order)
            loss = self._loss
        if loss is not None:
            with contextlib.suppress(Exception):
                loss.note_activity(cast("SourceAllocator", self._allocator))

    def exit(self, scope: RunScope, status: ScopeStatus = "ok") -> None:
        """Block exit (§3.6 trigger table): the block's ``run_end`` (closing its scope under
        the allocator lock); at the run's outermost exit in this process the open segment
        seals: terminal for a non-resumable run or a ``final=True`` block, else
        non-terminal (always non-terminal in a fork child's inherited blocks). The
        outermost ``run_end`` carries the run outcome (D30) when one was set."""
        if self._allocator is None:
            return
        with self._lock():
            scope.closed = True
            if self._closed:
                return
            last, epoch = self._last(), self._allocator.epoch
            run = self._runs.get(scope.run_id)
            if run is None or run.depth <= 0:
                self._queue(Marker("run_end", self._source_id(), epoch, last,
                                   run_id=scope.run_id, scope_id=scope.scope_id,
                                   scope_status=status))  # fmt: skip
                return
            run.depth -= 1
            outermost = run.depth == 0
            terminal = outermost and not run.fork_child and (
                not run.resumable or run.final_block)  # fmt: skip
            needs = terminal or bool(run.pending_declared)  # a seal, or fork children to declare
            if (
                outermost and needs and (run.open_segment is None or run.open_epoch != epoch)
            ):  # the seal needs a segment: a zero-width one
                if run.open_segment is not None:
                    self._request(self._seal(run, terminal=False))
                self._open(run, scope.scope_id, last, epoch)
            outcome = run.outcome if outermost else None
            stop = run.stop_reason if outermost else None
            self._queue(Marker(
                "run_end", self._source_id(), epoch, last, run_id=run.run_id,
                scope_id=scope.scope_id, segment_id=run.open_segment, scope_status=status,
                outcome=outcome, stop_reason=stop,
            ))  # fmt: skip
            if outermost:
                self._request(self._seal(run, terminal=terminal))
                run.final_block = run.fork_child = False
                run.outcome = run.stop_reason = None

    # -- the protocol hooks (frozen by WP-01) ----------------------------------------------------

    def on_block_enter(self, scope: RunScope) -> None:
        """Protocol form of :meth:`enter` for a scope whose run id is already emitted (no
        arguments, no tokens: the ``caller`` rule on the emitted id, never mapped again)."""
        identity = Identity(scope.run_id, "caller", _ROOT, (), 0, (), 0)
        self.enter(RunPlan(identity, False, False, None, None, None, None, None, ()), scope)

    def on_block_exit(self, scope: RunScope) -> None:
        self.exit(scope)

    def on_final(self) -> None:
        """``final()`` (epoch end): seal every open segment, non-terminal, except a
        non-resumable run whose outermost block already exited (terminal). Nothing more is
        accounted after it."""
        if self._allocator is None:
            return
        self.refresh_manifest()
        with self._lock():
            if self._closed:
                return
            self._closed = True
            epoch = self._allocator.epoch
            for run in self._runs.values():
                if (
                    run.open_segment is None
                    and run.pending_declared
                    and run.depth > 0
                    and (run.block_scope is not None)
                ):  # fork children not declared yet: a zero-width segment declares them
                    self._open(run, run.block_scope, self._last(), epoch)
                if run.open_segment is not None:
                    terminal = run.depth == 0 and not run.resumable and not run.fork_child
                    self._request(self._seal(run, terminal=terminal))

    # -- tokens, outcome, end_run ---------------------------------------------------------------

    def issue(self, scope: RunScope, branches: int) -> tuple[str, ...]:
        """Seal the run's open segment (non-terminal, ``resumable=true``) and return its
        token (``branches == 0``) or ``branches`` branch tokens, each with its own ``br-``
        id listed in the seal. With no segment open, a zero-width one is opened and sealed."""
        if not self.active:
            return ()
        self.refresh_manifest()
        with self._lock():
            run = self._runs.get(scope.run_id)
            if self._closed or run is None or run.depth <= 0:
                return ()
            if not OPAQUE_ID_RE.fullmatch(run.correlation_id):
                raise RecordsMisuseError("records API misuse: the run id cannot be carried")
            last, epoch = self._last(), cast("SourceAllocator", self._allocator).epoch
            if run.open_segment is not None and run.open_epoch != epoch:
                self._request(self._seal(run, terminal=False))
            if run.open_segment is None:
                self._open(run, scope.scope_id, last, epoch)
            ids = tuple(BRANCH_PREFIX + secrets.token_hex(16) for _ in range(branches))
            run.resumable = True
            order = self._seal(run, terminal=False, branch_ids=ids)
            self._request(order)
        if order is None:
            return ()
        entry = format_entry(order.segment_id, self._source_id(), order.epoch,
                             order.last_sequence, order.manifest_digest)  # fmt: skip
        tokens = tuple(format_token(run.correlation_id, entry, branch) or ""
                       for branch in (ids or (None,)))  # fmt: skip
        self._stats["tokens_issued"] += len(tokens)
        return tokens

    def set_outcome(
        self, outcome: RunOutcome, stop_reason: StopReason | None, run_id: str | None
    ) -> bool:
        if not self.active:
            return False
        if run_id is None:
            scope = current_run_scope()
            emitted = scope.run_id if scope is not None else None
        else:
            emitted = self.rule.run(run_id)
        if emitted is None:
            return False
        with self._lock():
            run = self._runs.get(emitted)
            if run is None or run.depth <= 0:
                return False
            run.outcome, run.stop_reason = outcome, stop_reason
            return True

    def end(
        self, run_id: str | None, outcome: RunOutcome, tokens: Sequence[str],
        stop_reason: StopReason | None,
    ) -> EndRunStatus:  # fmt: skip
        """``end_run`` (§3.6): a zero-width segment, ``run_start`` (predecessors = the
        tokens), ``run_end`` with the outcome, and a terminal ``segment_seal``."""
        if not self.active:
            return "not_capturing"
        parsed = [p for p in map(parse_token, tokens) if p is not None]
        self._rejected(len(tokens) - len(parsed))
        if not parsed:
            return "refused_no_token"
        correlations = {p.correlation_id for p in parsed if p.correlation_id is not None}
        if run_id is None and len(correlations) > 1:
            return "refused_conflicting_tokens"
        identity = resolve_identity(tokens, run_id, map_run=self.rule.run,
                                    mint=self.rule.mint_run)  # fmt: skip
        self.refresh_manifest()
        with self._lock():
            if self._closed:
                return "not_capturing"
            last, epoch = self._last(), cast("SourceAllocator", self._allocator).epoch
            run = _Run(identity.run_id, identity.run_id, identity.id_basis, resumable=True)
            scope_id = str(uuid.uuid4())
            self._open(run, scope_id, last, epoch, predecessors=identity.predecessors,
                       branch_ids=identity.branch_ids, basis=identity.id_basis)  # fmt: skip
            self._queue(Marker("run_end", self._source_id(), epoch, last, run_id=run.run_id,
                               scope_id=scope_id, segment_id=run.open_segment,
                               scope_status="ok", outcome=outcome,
                               stop_reason=stop_reason))  # fmt: skip
            self._request(self._seal(run, terminal=True))
            if (local := self._runs.get(identity.run_id)) is not None:
                local.terminal_sealed = True  # later activity here is post-terminal (K2)
            self._stats["end_runs"] += 1
        return "ended"

    # -- fork (§3.6 "Fork"; locks only, no I/O) ---------------------------------------------------

    def _chain(self) -> list[RunScope]:
        """The forking thread's open scopes, innermost first."""
        scopes: list[RunScope] = []
        scope = current_run_scope()
        while scope is not None:
            if not scope.closed:
                scopes.append(scope)
            scope = scope.parent
        return scopes

    def before_fork(self) -> None:
        """Before fork, for each run in the forking thread's scope chain: mint the child's
        segment id C, seal the parent's open segment S (non-terminal; requested after the
        fork, in the parent) and declare C on the parent's next segment. The allocator lock
        is held across the fork, so no allocation is half done in the child."""
        self._fork, self._fork_seals, self._fork_locked = {}, [], None
        if not self.active:
            return
        lock = self._lock()
        if not lock.acquire(timeout=1.0):
            self._stats["fork_skipped"] += 1
            return
        self._fork_locked = lock
        try:
            for scope in self._chain():
                run = self._runs.get(scope.run_id)
                if run is None or run.run_id in self._fork or run.depth <= 0:
                    continue
                order = self._seal(run, terminal=False)
                if order is not None:
                    self._fork_seals.append(order)
                preds = run.pending_predecessors
                if not preds:
                    continue
                child = SEGMENT_PREFIX + secrets.token_hex(16)
                if len(run.pending_declared) < MAX_BRANCHES:
                    run.pending_declared.append(child)
                else:
                    self._stats["declared_branches_dropped"] += 1
                self._fork[run.run_id] = (child, preds)
                self._stats["fork_branches"] += 1
        except Exception:
            self._stats["internal_errors"] += 1

    def after_fork_in_parent(self) -> None:
        """Release the lock and request the seals the fork decided."""
        lock, self._fork_locked = self._fork_locked, None
        if lock is not None:
            with contextlib.suppress(RuntimeError):
                lock.release()
        orders, self._fork_seals, self._fork = self._fork_seals, [], {}
        for order in orders:
            self._request(order)

    def after_fork_in_child(self) -> None:
        """In the child (its new epoch already drawn): each inherited run continues in
        segment C with predecessor S, every inherited open scope gets a fresh scope id
        (unique per source, 048 §6), and C's ``run_start`` is queued. Runs outside the
        forking thread's chain are forgotten (nothing in the child can reach them). The
        inherited block's exit, or the child's ``final``, seals C non-terminal."""
        plan, self._fork, self._fork_seals, self._fork_locked = self._fork, {}, [], None
        if not self.active:
            return
        try:
            chain = self._chain()
            for scope in chain:
                scope.scope_id = str(uuid.uuid4())
            allocator = cast("SourceAllocator", self._allocator)
            self.refresh_manifest()
            runs, self._runs, self._segment_runs = self._runs, {}, {}
            epoch = allocator.epoch
            for scope in chain:  # innermost first: C's run_start names the innermost block
                run = self._runs.get(scope.run_id)
                if run is not None:  # an outer inherited block of a run already continued
                    if run.open_segment is not None:
                        self._queue(self._run_start(run, scope.scope_id, -1, epoch,
                                                    segment_id=run.open_segment))  # fmt: skip
                    continue
                if (run := runs.get(scope.run_id)) is None:
                    continue
                inherited = plan.get(run.run_id)
                run.depth = sum(1 for s in chain if s.run_id == run.run_id)
                run.open_segment, run.pending_declared = None, []
                run.pending_predecessors, run.pending_branch_ids = (), ()
                run.block_scope = scope.scope_id
                self._runs[run.run_id] = run
                if inherited is None:
                    continue
                child, preds = inherited
                run.fork_child = True
                marker = self._run_start(run, scope.scope_id, -1, epoch, segment_id=child,
                                         predecessors=preds)  # fmt: skip
                run.open_segment, run.open_epoch, run.open_last = child, epoch, -1
                run.open_scope = scope.scope_id
                self._segment_runs[child] = run.run_id
                self._queue(marker)
        except Exception:
            self._stats["internal_errors"] += 1


def _flag(value: object, what: str) -> bool:
    if type(value) is bool:
        return value
    misuse(f"{what} must be a bool")
    return False


def _token_list(resume: object) -> list[str]:
    """``resume``: ``None``, a token string (comma-separated for a join) or a sequence of
    tokens. A non-string entry is dropped (``api_misuse``)."""
    if resume is None:
        return []
    if isinstance(resume, str):
        return split_tokens(resume)
    if not isinstance(resume, Iterable):
        misuse("resume must be a token or a sequence of tokens")
        return []
    tokens: list[str] = []
    for item in resume:
        if isinstance(item, str):
            tokens.extend(split_tokens(item))
        else:
            misuse("resume tokens are str")
    return tokens


def _before_fork() -> None:
    for table in list(_TABLES):
        with contextlib.suppress(Exception):
            table.before_fork()


def _after_fork_in_parent() -> None:
    for table in list(_TABLES):
        with contextlib.suppress(Exception):
            table.after_fork_in_parent()


def _after_fork_in_child() -> None:
    for table in list(_TABLES):
        with contextlib.suppress(Exception):
            table.after_fork_in_child()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(before=_before_fork, after_in_parent=_after_fork_in_parent,
                        after_in_child=_after_fork_in_child)  # fmt: skip


# --- the process API (fabric.wire; §3.6 "Public API") -------------------------------------------


def new_run_table() -> SegmentTable:
    """A process run table; ``wire.install`` binds it (:meth:`SegmentTable.bind`)."""
    return SegmentTable()


def active_table(handle: WireHandle | None = None) -> SegmentTable | None:
    """The run table of ``handle`` (default: the installed handle) while it captures."""
    if handle is None:
        from . import wire  # noqa: PLC0415 - wire imports this module lazily

        handle = wire.current_handle()
    if handle is None or not handle.capturing:
        return None
    table = handle.allocator.segments
    return table if isinstance(table, SegmentTable) and table.active else None


@fail_open(None)
def resume_token() -> str | None:
    """Seal the current run's open segment (non-terminal, ``resumable=true``) and return
    its ``fr3/`` token; ``None`` outside a run or when not capturing. Passing the token to
    ``run(resume=…)`` (here, in a child process through ``FABRIC_RUN_RESUME_TOKEN``, or
    across a service boundary in ``baggage`` ``fabric.resume``) continues the run."""
    table, scope = active_table(), current_run_scope()
    if table is None or scope is None:
        return None
    tokens = table.issue(scope, 0)
    return tokens[0] if tokens and tokens[0] else None


@fail_open(())
def resume_tokens(branches: int) -> tuple[str, ...]:
    """``branches`` (1..64) branch tokens of one seal, each naming its own ``br-`` id (a
    branch token belongs to exactly one consumer); ``()`` outside a run or not capturing."""
    if type(branches) is not int or not 1 <= branches <= MAX_BRANCHES:
        raise RecordsMisuseError("records API misuse: branches must be 1..64")
    table, scope = active_table(), current_run_scope()
    if table is None or scope is None:
        return ()
    tokens = table.issue(scope, branches)
    return tokens if all(tokens) else ()


@fail_open("failed")
def end_run(
    run_id: str | None, outcome: RunOutcome, *, resume: Sequence[str],
    stop_reason: StopReason | None = None,
) -> EndRunStatus:  # fmt: skip
    """End a run from its tokens with a zero-width terminal segment carrying ``outcome``
    on ``run_end`` (§3.6). ``run_id=None`` takes the run id from the tokens' correlation
    id. ``refused_no_token`` without a valid token (nothing is emitted);
    ``refused_conflicting_tokens`` for tokens of different runs and no ``run_id``;
    ``refused_bad_token`` when ``resume`` is not a token sequence."""
    _check_outcome(outcome, stop_reason)
    if run_id is not None and not isinstance(run_id, str):
        raise RecordsMisuseError("records API misuse: run_id must be a str")
    table = active_table()
    if table is None:
        return "not_capturing"
    if isinstance(resume, str):
        tokens = split_tokens(resume)
    elif isinstance(resume, Iterable) and all(isinstance(t, str) for t in resume):
        tokens = [t for item in resume for t in split_tokens(item)]
    else:
        misuse("resume must be a sequence of tokens")
        return "refused_bad_token"
    return table.end(run_id, outcome, tokens, stop_reason)


@fail_open(False)
def set_run_outcome(
    outcome: RunOutcome, stop_reason: StopReason | None = None, *, run_id: str | None = None
) -> bool:
    """The D30 run-level hook (R4; P2's ``fabric.records.set_run_outcome`` calls it): kept
    on the run entry (of ``run_id``, mapped by the identity rule, else of the innermost open
    scope's run) and carried by the run's outermost ``run_end`` here; the last call before
    that block closes wins. ``False`` when there is no open run or capture is not
    installed."""
    _check_outcome(outcome, stop_reason)
    if run_id is not None and (not isinstance(run_id, str) or not run_id):
        raise RecordsMisuseError("records API misuse: run_id must be a non-empty str")
    table = active_table()
    return table.set_outcome(outcome, stop_reason, run_id) if table is not None else False


def intake_environment(handle: WireHandle | None, environ: Mapping[str, str]) -> None:
    """``install_from_env``: hand ``FABRIC_RUN_ID`` and ``FABRIC_RUN_RESUME_TOKEN`` to the
    run table (same-host only, OD-7). Never raises."""
    with contextlib.suppress(Exception):
        table = active_table(handle)
        if table is None:
            return
        tokens = split_tokens(environ.get(RESUME_TOKEN_ENV) or "")
        table.set_environment((environ.get(RUN_ID_ENV) or "").strip() or None, tokens)


def _check_outcome(outcome: object, stop_reason: object) -> None:
    if outcome not in RUN_OUTCOMES:
        raise RecordsMisuseError("records API misuse: outcome outside D30")
    if stop_reason is not None and stop_reason not in STOP_REASONS:
        raise RecordsMisuseError("records API misuse: stop_reason outside D30")


__all__ = [
    "BRANCH_PREFIX", "DEFAULT_OPEN_DEADLINE_S", "LEGACY_TOKEN_PREFIX", "NO_MANIFEST_DIGEST",
    "OPEN_DEADLINE_ENV", "RESUME_TOKEN_ENV", "RUN_ID_ENV", "SEGMENT_PREFIX", "TOKEN_PREFIX",
    "Identity", "IdentityRule", "ResumeToken", "RunPlan", "SegmentTable", "active_table",
    "end_run", "format_entry", "format_token", "intake_environment", "new_run_table",
    "parse_token", "resolve_identity", "resume_token", "resume_tokens", "set_run_outcome",
    "split_tokens",
]  # fmt: skip
