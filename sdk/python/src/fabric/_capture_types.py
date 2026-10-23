# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared P1 capture types (spec 050 §3), frozen by WP-01.

Every P1 module (records input, segments, seal, manifests, registration, spool markers, the
verifier) speaks these types: the allocation result, typed markers, record jobs and bodies,
the evidence carrier, the three status inputs of the phase table (R4), the ``SealAccumulator``
and ``RunTable`` protocols, and the fail-open/strict rule (R9). Nothing here does I/O,
starts a thread or reads content; constructors check the invariants the spec states.

Vocabularies copied from the coverage registry carry a placeholder note: WP-00 generates the
authoritative tables (``_records_keys_generated.py``, ``_manifest_fields_generated.py``) and
a test pins these literals to ``contracts/coverage/v1/registry``.
"""

from __future__ import annotations

import functools
import os
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import (
    TYPE_CHECKING,
    Any,
    Literal,
    NamedTuple,
    ParamSpec,
    Protocol,
    TypeVar,
    cast,
    get_args,
)

if TYPE_CHECKING:
    from opentelemetry.context import Context
    from opentelemetry.util.types import AttributeValue

    from ._sequence import RunScope

# --- vocabularies (§3.4, §3.6; 049 §2.3) ------------------------------------------------

Phase = Literal["start", "data", "update", "end"]
Lifecycle = Literal[
    "queued", "running", "suspended", "deferred", "completed", "cancelled", "unknown"
]  # fmt: skip
ResultStatus = Literal["ok", "error", "cancelled", "timeout", "unknown"]
OtlpStatus = Literal["unset", "ok", "error"]
Provenance = Literal["reported", "observed"]  # X27, fabric.capture.source
ContentProvenance = Literal["caller_reported", "protocol"]
PrivacyMode = Literal[
    "omit", "metadata_only", "redact", "tokenize", "masked_only", "original_plus_masked",
    "retain_original",
]  # fmt: skip
CaptureInput = Literal["wire", "records"]  # X06; hooks never add a third class (R7)
# PLACEHOLDER (WP-00): the registry step_kind vocabulary plus `agent_turn` (§4.1).
StepKind = Literal[
    "run", "model_call", "embedding", "input", "message", "tool_call", "provider_tool_call",
    "mcp_call", "retrieval", "memory", "terminal", "remote_exec", "database", "network", "file",
    "ui_action", "media_stream", "delegation", "workflow_node", "checkpoint", "control",
    "context_change", "selection", "side_effect", "outcome", "hook", "skill", "interaction",
    "extension", "agent_turn",
]  # fmt: skip
DescriptorStatus = Literal["not_captured", "unsupported"]
DescriptorReason = Literal[
    "payload_too_large", "parse_failed", "not_exact_bytes", "encoding_failed"
]
MarkerKind = Literal["periodic", "run_start", "run_end", "final", "segment_seal", "manifest"]
IdBasis = Literal["caller", "caller_join", "token", "token_conflict", "minted", "legacy"]  # X49
RunOutcome = Literal["completed", "failed", "cancelled", "suspended", "unknown"]  # D30
StopReason = Literal[
    "goal_reached", "max_steps", "max_tokens", "error", "cancelled", "handoff", "awaiting_input",
    "other", "unknown",
]  # fmt: skip
ScopeStatus = Literal["ok", "error", "cancelled"]  # S34
EndRunStatus = Literal[
    "ended", "refused_no_token", "refused_bad_token", "refused_conflicting_tokens",
    "not_capturing", "failed",
]  # fmt: skip
RegistrationStatus = Literal[
    "registered", "failed", "registration_full", "unregistered_fork", "unregistered_direct"
]  # fmt: skip
SealEntry = str  # a record digest ("sha256:<64 hex>") or "loss:<reason>" (§3.7)
"""One seal member: the record digest of a written position, or ``"loss:<reason>"``."""

PHASES: frozenset[str] = frozenset(get_args(Phase))
LIFECYCLES: frozenset[str] = frozenset(get_args(Lifecycle))
RESULT_STATUSES: frozenset[str] = frozenset(get_args(ResultStatus))
OTLP_STATUSES: frozenset[str] = frozenset(get_args(OtlpStatus))
PROVENANCES: frozenset[str] = frozenset(get_args(Provenance))
CONTENT_PROVENANCES: frozenset[str] = frozenset(get_args(ContentProvenance))
PRIVACY_MODES: frozenset[str] = frozenset(get_args(PrivacyMode))
STEP_KINDS: frozenset[str] = frozenset(get_args(StepKind))
DESCRIPTOR_STATUSES: frozenset[str] = frozenset(get_args(DescriptorStatus))
DESCRIPTOR_REASONS: frozenset[str] = frozenset(get_args(DescriptorReason))
MARKER_KINDS: frozenset[str] = frozenset(get_args(MarkerKind))
ID_BASES: frozenset[str] = frozenset(get_args(IdBasis))
RUN_OUTCOMES: frozenset[str] = frozenset(get_args(RunOutcome))
STOP_REASONS: frozenset[str] = frozenset(get_args(StopReason))
SCOPE_STATUSES: frozenset[str] = frozenset(get_args(ScopeStatus))

# --- bounds (§3.4, §3.4a, §3.6) ------------------------------------------------------------

MAX_RECORD_BODIES = 8  # bodies + descriptor-only bodies + the evidence object (R6)
MAX_EVENT_IDS = 64  # projection `event_ids` per step (R15)
MAX_BRANCHES = 64  # resume_tokens(n)
MAX_RUN_LINKS = 16  # root run_start `links`
EVIDENCE_ROLE = "record.evidence"
EVIDENCE_MEDIA_TYPE = "application/vnd.fabric.record-evidence+json"
EVIDENCE_SCHEMA_VERSION = "fabric.record-evidence/v1"
EVIDENCE_MAX_BYTES = 1 << 20
EVIDENCE_MAX_ITEMS = 4096
EVIDENCE_MAX_DEPTH = 4  # an item object is depth 1; each nested list or object adds 1
EVIDENCE_MAX_STRING = 256

UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SEGMENT_ID_RE = re.compile(r"^seg-[0-9a-f]{32}$")
BRANCH_ID_RE = re.compile(r"^br-[0-9a-f]{32}$")
_PREDECESSOR_ROOT = ("none",)

# --- fail-open / strict (R9, OD-11) -----------------------------------------------------

STRICT_ENV = "FABRIC_RECORDS_STRICT"


class RecordsMisuseError(ValueError):
    """A recorder API was misused (R9): a bad enum value, a mutable body, an unknown
    prefix, a lifecycle on ``update``. Fail-open APIs count it in ``api_misuse`` and return
    their fail value; it propagates only under ``FABRIC_RECORDS_STRICT=1``. The message is
    fixed text naming the input, never its value."""


class RecordsCounters:
    """Process-level fail-open counters, read into ``status()``: ``api_misuse`` and
    ``internal_errors``. Plain ints (as the other capture counters); never content."""

    __slots__ = ("api_misuse", "internal_errors")

    def __init__(self) -> None:
        self.api_misuse = 0
        self.internal_errors = 0

    def snapshot(self) -> dict[str, int]:
        return {"api_misuse": self.api_misuse, "internal_errors": self.internal_errors}

    def reset(self) -> None:
        self.api_misuse = self.internal_errors = 0


COUNTERS = RecordsCounters()


def strict() -> bool:
    """``FABRIC_RECORDS_STRICT=1`` (the test suites): misuse and internal errors raise."""
    return os.environ.get(STRICT_ENV) == "1"


def misuse(what: str) -> None:
    """Count one misused input that is dropped while the call still proceeds (for example a
    lifecycle on ``update``); raises :class:`RecordsMisuseError` only under strict mode."""
    COUNTERS.api_misuse += 1
    if strict():
        raise RecordsMisuseError(f"records API misuse: {what}")


P = ParamSpec("P")
R = TypeVar("R")
D = TypeVar("D")


def fail_open(default: D) -> Callable[[Callable[P, R]], Callable[P, R | D]]:
    """Decorate a recorder API so it never raises into the application (R9).

    :class:`RecordsMisuseError` counts ``api_misuse``, any other ``Exception`` counts
    ``internal_errors``; both return ``default``. Under ``FABRIC_RECORDS_STRICT=1`` the
    exception propagates instead. ``BaseException`` (cancellation, ``KeyboardInterrupt``,
    ``SystemExit``) always propagates: it is the application's, never Fabric's. The strict
    flag is read only on the failure path, so the success path costs one ``try``."""

    def decorate(fn: Callable[P, R]) -> Callable[P, R | D]:
        @functools.wraps(fn)
        def guarded(*args: P.args, **kwargs: P.kwargs) -> R | D:
            try:
                return fn(*args, **kwargs)
            except RecordsMisuseError:
                COUNTERS.api_misuse += 1
                if strict():
                    raise
                return default
            except Exception:
                COUNTERS.internal_errors += 1
                if strict():
                    raise
                return default

        return guarded

    return decorate


# --- the phase table and the three status inputs (R4) ------------------------------------


@dataclass(frozen=True, slots=True)
class PhaseRule:
    """One row of the §3.4 phase table. ``lifecycles`` empty: ``lifecycle`` must be
    ``None`` (``update`` stamps none)."""

    lifecycles: frozenset[Lifecycle]
    default_lifecycle: Lifecycle | None
    result_allowed: bool
    default_result: ResultStatus | None
    otlp_must_be_unset: bool


PHASE_TABLE: Mapping[Phase, PhaseRule] = MappingProxyType({
    "start": PhaseRule(frozenset({"running", "queued", "suspended"}), "running", False, None,
                       False),
    "data": PhaseRule(frozenset({"running", "suspended"}), "running", False, None, False),
    "update": PhaseRule(frozenset(), None, False, None, True),
    "end": PhaseRule(frozenset({"completed", "cancelled", "deferred", "unknown"}), "completed",
                     True, "unknown", False),
})  # fmt: skip


@dataclass(frozen=True, slots=True)
class StatusInputs:
    """The resolved three inputs of one ``emit``; ``dropped`` names inputs outside the
    table (each one ``api_misuse``; the record is still emitted without them)."""

    lifecycle: Lifecycle | None  # fabric.step.lifecycle_state; None on update
    result_status: ResultStatus | None  # fabric.step.status; end only
    otlp_status: OtlpStatus  # the span status
    dropped: tuple[str, ...] = ()


def resolve_status_inputs(
    phase: Phase, lifecycle: Lifecycle | None = None, result_status: ResultStatus | None = None,
    otlp_status: OtlpStatus = "unset",
) -> StatusInputs:  # fmt: skip
    """Apply the §3.4 phase table. None of the three is derived from another; only the
    table's defaults fill a missing input (``end`` never infers ``ok``; ``otlp_status``
    stays ``unset`` even with ``result_status=error``). An unknown ``phase`` raises
    :class:`RecordsMisuseError` (nothing can be emitted); any other value outside the
    table is dropped and named in ``dropped``."""
    rule = PHASE_TABLE.get(phase) if isinstance(phase, str) else None
    if rule is None:
        raise RecordsMisuseError("records API misuse: unknown phase")
    dropped: list[str] = []
    resolved_lifecycle = rule.default_lifecycle
    if lifecycle is not None:
        if lifecycle in rule.lifecycles:
            resolved_lifecycle = lifecycle
        else:
            dropped.append("lifecycle")
    resolved_result = rule.default_result
    if result_status is not None:
        if rule.result_allowed and result_status in RESULT_STATUSES:
            resolved_result = result_status
        else:
            dropped.append("result_status")
    resolved_otlp: OtlpStatus = "unset"
    if otlp_status != "unset":
        if otlp_status in OTLP_STATUSES and not rule.otlp_must_be_unset:
            resolved_otlp = otlp_status
        else:
            dropped.append("otlp_status")
    return StatusInputs(resolved_lifecycle, resolved_result, resolved_otlp, tuple(dropped))


# --- allocation (§3.3) --------------------------------------------------------------------


class Allocation(NamedTuple):
    """One allocated position: ``segment_id`` is the open segment of the scope's run
    (``None`` outside any run, or until segments are built); ``manifest_seq`` the latest
    manifest of the epoch (``None`` until manifests are built)."""

    epoch: int
    sequence: int
    scope: RunScope | None
    segment_id: str | None = None
    manifest_seq: int | None = None


class Settle(Protocol):
    """``allocator.settle``: hand one position's seal entry over (worker and loss paths)."""

    def __call__(self, segment_id: str | None, sequence: int, entry: SealEntry, /) -> None: ...


def settle_noop(segment_id: str | None, sequence: int, entry: SealEntry) -> None:
    """The settle hook before an allocator is attached: nothing to account."""


class SealAccumulator(Protocol):
    """§3.7: ``segment_id -> {entries, outstanding, seal_request}``, owned by the pipeline.
    Called under the allocator lock (``note_allocated``, ``request_seal``) or on the worker
    and loss paths (``settle``); never blocks, never raises."""

    def note_allocated(self, segment_id: str, sequence: int) -> None:
        """One more outstanding position in ``segment_id`` (allocation step 4)."""
        ...

    def settle(self, segment_id: str, sequence: int, entry: SealEntry) -> None:
        """One outstanding position settled: written (a record digest) or lost."""
        ...

    def request_seal(
        self, segment_id: str, *, last_sequence: int, manifest_digest: str | None,
        terminal: bool, resumable: bool, branch_ids: tuple[str, ...] = (),
    ) -> None:  # fmt: skip
        """Seal once ``outstanding`` is 0: queue the ``segment_seal`` marker."""
        ...

    def outstanding(self, segment_id: str) -> int: ...


class NullSealAccumulator:
    """The accumulator until WP-11a: accounts nothing, seals nothing."""

    __slots__ = ()

    def note_allocated(self, segment_id: str, sequence: int) -> None:
        return None

    def settle(self, segment_id: str, sequence: int, entry: SealEntry) -> None:
        return None

    def request_seal(
        self, segment_id: str, *, last_sequence: int, manifest_digest: str | None,
        terminal: bool, resumable: bool, branch_ids: tuple[str, ...] = (),
    ) -> None:  # fmt: skip
        return None

    def outstanding(self, segment_id: str) -> int:
        return 0


# --- run structure (§3.6) -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SealedSegment:
    segment_id: str
    last_sequence: int
    manifest_digest: str | None
    terminal: bool
    resumable: bool
    branch_ids: tuple[str, ...] = ()


@dataclass(slots=True)
class RunEntry:
    """One emitted run id in this process; mutated only under the allocator lock."""

    run_id: str
    correlation_id: str  # an EmittedId when minted (rule 5)
    id_basis: IdBasis
    open_segment: str | None = None
    pending_start: Marker | None = None
    sealed: list[SealedSegment] = field(default_factory=list)
    depth: int = 0
    resumable: bool = False
    terminal_sealed: bool = False
    final_block: bool = False
    open_deadline_s: int | None = None
    root_done: bool = False
    outcome: RunOutcome | None = None
    stop_reason: StopReason | None = None


class RunTable(Protocol):
    """§3.6: the process-level run table. ``on_allocate`` runs under the allocator lock on
    every allocation; it returns the scope's open segment id (opening one when none is open)
    or ``None`` outside a run. Every method is fail-open and does no I/O."""

    def on_allocate(self, allocation: Allocation) -> str | None: ...

    def on_block_enter(self, scope: RunScope) -> None: ...

    def on_block_exit(self, scope: RunScope) -> None: ...

    def on_final(self) -> None:
        """``final()``: seal every open segment (§3.6 trigger table, last row)."""
        ...

    def get(self, run_id: str) -> RunEntry | None: ...


class NullRunTable:
    """The run table until WP-12: no segments, so every allocation is segment-less."""

    __slots__ = ()

    def on_allocate(self, allocation: Allocation) -> str | None:
        return None

    def on_block_enter(self, scope: RunScope) -> None:
        return None

    def on_block_exit(self, scope: RunScope) -> None:
        return None

    def on_final(self) -> None:
        return None

    def get(self, run_id: str) -> RunEntry | None:
        return None


# --- markers (§3.5; capture/v1 1.3.0 marker branch) ----------------------------------------

LegacyBeat = tuple[str, int, int, str | None, str | None, str]
"""``_loss._Beat``: ``(source, epoch, last, run_id, scope_id, kind)``, until WP-11b."""
_LEGACY_KINDS = frozenset({"periodic", "run_start", "run_end", "final"})
_RUN_MARKERS = frozenset({"run_start", "run_end"})


def new_event_id() -> str:
    """A dashed uuid4, minted once (R2: persisted, never re-derived)."""
    return str(uuid.uuid4())


@dataclass(frozen=True, slots=True)
class SealInfo:
    """The ``seal`` of a ``segment_seal`` marker."""

    last_sequence: int
    manifest_digest: str | None
    seal_digest: str
    branch_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Marker:
    """A typed heartbeat or run marker (replaces ``_loss._Beat``). ``event_id`` is minted
    once at construction and persisted with the marker (R2). Placement follows §4.2: the
    root-only keys need ``predecessors == ("none",)``; ``outcome``/``stop_reason`` only on
    ``run_end``; ``seal`` exactly on ``segment_seal``; ``manifest`` exactly on ``manifest``.
    A violation raises ``ValueError``: markers are built by Fabric, never by the app."""

    kind: MarkerKind
    source_id: str
    epoch: int
    last_sequence: int
    run_id: str | None = None
    scope_id: str | None = None
    segment_id: str | None = None
    predecessors: tuple[str, ...] = ()
    resumable: bool | None = None
    open_deadline_s: int | None = None
    declared_branches: tuple[str, ...] = ()
    branch_ids: tuple[str, ...] = ()
    terminal: bool | None = None
    seal: SealInfo | None = None
    manifest_id: str | None = None
    manifest_digest: str | None = None
    manifest_seq: int | None = None
    scope_status: ScopeStatus | None = None
    outcome: RunOutcome | None = None
    session_id: str | None = None
    user_id: str | None = None
    parent_run_id: str | None = None
    resumed_from: str | None = None
    links: tuple[str, ...] = ()
    manifest: Mapping[str, AttributeValue] | None = None
    id_basis: IdBasis | None = None
    stop_reason: StopReason | None = None
    identity: Mapping[str, str] | None = None  # the X05 block, run_start only (§4.2)
    event_id: str = field(default_factory=new_event_id)

    def __post_init__(self) -> None:  # noqa: PLR0912 - one check per placement rule
        kind = self.kind
        if kind not in MARKER_KINDS:
            raise ValueError("marker kind outside the capture/v1 marker vocabulary")
        if not UUID4_RE.fullmatch(self.event_id):
            raise ValueError("marker event_id must be a dashed uuid4")
        if (self.seal is not None) is not (kind == "segment_seal"):
            raise ValueError("a seal is carried exactly by segment_seal markers")
        if (self.manifest is not None) is not (kind == "manifest"):
            raise ValueError("manifest attributes are carried exactly by manifest markers")
        if kind != "run_end" and (self.outcome is not None or self.stop_reason is not None):
            raise ValueError("outcome and stop_reason are carried by run_end only")
        if self.outcome is not None and self.outcome not in RUN_OUTCOMES:
            raise ValueError("outcome outside the D30 vocabulary")
        if self.stop_reason is not None and self.stop_reason not in STOP_REASONS:
            raise ValueError("stop_reason outside the D30 vocabulary")
        root_only = (self.session_id, self.user_id, self.parent_run_id, self.resumed_from)
        root = kind == "run_start" and self.predecessors == _PREDECESSOR_ROOT
        if not root and (any(v is not None for v in root_only) or self.links):
            raise ValueError("session, user, parent, resumed_from and links: root run_start only")
        if len(self.links) > MAX_RUN_LINKS:
            raise ValueError("at most 16 run links")
        if kind != "run_start" and (self.id_basis is not None or self.identity is not None):
            raise ValueError("id_basis and the identity block are carried by run_start only")
        if self.id_basis is not None and self.id_basis not in ID_BASES:
            raise ValueError("id_basis outside the X49 vocabulary")
        if self.scope_status is not None and self.scope_status not in SCOPE_STATUSES:
            raise ValueError("scope_status outside the S34 vocabulary")
        if self.segment_id is not None and not SEGMENT_ID_RE.fullmatch(self.segment_id):
            raise ValueError("segment_id must be seg- + 32 hex")
        # X46: run_start declares its fork children by segment id, and names the branch
        # ids of the tokens it started from; each list holds at most 64.
        if len(self.declared_branches) > MAX_BRANCHES or not all(
            map(SEGMENT_ID_RE.fullmatch, self.declared_branches)
        ):
            raise ValueError("declared_branches must be seg- + 32 hex, at most 64")
        if len(self.branch_ids) > MAX_BRANCHES or not all(
            map(BRANCH_ID_RE.fullmatch, self.branch_ids)
        ):
            raise ValueError("branch_ids must be br- + 32 hex, at most 64")

    def to_beat(self) -> LegacyBeat | None:
        """The legacy ``_Beat`` of a periodic, run or final marker (``None`` for the P1
        kinds, which have no legacy form): the bridge WP-11b removes."""
        if self.kind not in _LEGACY_KINDS:
            return None
        run = self.kind in _RUN_MARKERS
        run_id, scope_id = (self.run_id, self.scope_id) if run else (None, None)
        return self.source_id, self.epoch, self.last_sequence, run_id, scope_id, self.kind

    @classmethod
    def from_beat(cls, beat: LegacyBeat) -> Marker:
        """A typed marker from a legacy ``_Beat`` (a new event id is minted)."""
        source_id, epoch, last, run_id, scope_id, kind = beat
        if kind not in _LEGACY_KINDS:
            raise ValueError("legacy beats are periodic, run_start, run_end or final")
        run = kind in _RUN_MARKERS
        return cls(cast("MarkerKind", kind), source_id, epoch, last,
                   run_id if run else None, scope_id if run else None)  # fmt: skip


# --- records input (§3.4, §3.4a) ----------------------------------------------------------


def _check_text(value: object, what: str) -> None:
    if not isinstance(value, str) or not value:
        raise RecordsMisuseError(f"records API misuse: {what} must be a non-empty str")


@dataclass(frozen=True, slots=True)
class RecordBody:
    """One body, held by reference until the worker's PROTECT. ``str`` data is encoded to
    UTF-8 on the capture worker only; a mutable buffer (``bytearray``, ``memoryview``) is
    misuse. Empty ``data`` is a captured zero-byte object, never a failure marker."""

    role: str
    data: bytes | str
    media_type: str
    boundary: str
    content_provenance: ContentProvenance = "caller_reported"
    stream_id: str | None = None
    chunk_index: int | None = None

    def __post_init__(self) -> None:
        _check_text(self.role, "body role")
        _check_text(self.media_type, "body media_type")
        _check_text(self.boundary, "body boundary")
        if not isinstance(self.data, (bytes, str)):
            raise RecordsMisuseError("records API misuse: body data must be bytes or str")
        if self.content_provenance not in CONTENT_PROVENANCES:
            raise RecordsMisuseError("records API misuse: unknown content_provenance")
        if self.stream_id is not None:
            _check_text(self.stream_id, "body stream_id")
        index = self.chunk_index
        if index is not None and (type(index) is not int or index < 0):
            raise RecordsMisuseError("records API misuse: chunk_index must be an int >= 0")

    @property
    def inflight_charge(self) -> int:
        """Bytes charged to ``max_inflight_bytes`` until encoded: ``len * 4`` for ``str``
        (the UTF-8 upper bound), else the length."""
        return len(self.data) * 4 if isinstance(self.data, str) else len(self.data)


# reason -> the content-v2 descriptor status it implies, and its projection (§3.4, R5).
DESCRIPTOR_STATUS_OF: Mapping[DescriptorReason, DescriptorStatus] = MappingProxyType({
    "payload_too_large": "not_captured", "parse_failed": "not_captured",
    "encoding_failed": "not_captured", "not_exact_bytes": "unsupported",
})  # fmt: skip
DESCRIPTOR_PROJECTION: Mapping[DescriptorReason, tuple[str, str]] = MappingProxyType({
    "payload_too_large": ("not_captured", "body_cap"),
    "parse_failed": ("not_captured", "parse_failed"),
    "encoding_failed": ("not_captured", "parse_failed"),
    "not_exact_bytes": ("unsupported", "unsupported_api"),
})  # fmt: skip


@dataclass(frozen=True, slots=True)
class DescriptorOnlyBody:
    """A body that could not be produced (R5): no bytes, no digests. ``status`` must be the
    one its ``reason`` implies (:data:`DESCRIPTOR_STATUS_OF`); ``observed_byte_length``
    only when known without encoding."""

    role: str
    media_type: str
    boundary: str
    status: DescriptorStatus
    reason: DescriptorReason
    observed_byte_length: int | None = None

    def __post_init__(self) -> None:
        _check_text(self.role, "body role")
        _check_text(self.media_type, "body media_type")
        _check_text(self.boundary, "body boundary")
        if self.reason not in DESCRIPTOR_REASONS:
            raise RecordsMisuseError("records API misuse: unknown descriptor-only reason")
        if self.status not in DESCRIPTOR_STATUSES:
            raise RecordsMisuseError("records API misuse: unknown descriptor-only status")
        if DESCRIPTOR_STATUS_OF[self.reason] != self.status:
            raise RecordsMisuseError("records API misuse: descriptor status contradicts reason")
        length = self.observed_byte_length
        if length is not None and (type(length) is not int or length < 0):
            raise RecordsMisuseError("records API misuse: observed_byte_length must be >= 0")

    @classmethod
    def for_reason(
        cls, role: str, media_type: str, boundary: str, reason: DescriptorReason,
        observed_byte_length: int | None = None,
    ) -> DescriptorOnlyBody:  # fmt: skip
        """The descriptor-only body for ``reason``, with the status it implies."""
        status = DESCRIPTOR_STATUS_OF.get(reason)
        if status is None:
            raise RecordsMisuseError("records API misuse: unknown descriptor-only reason")
        return cls(role, media_type, boundary, status, reason, observed_byte_length)

    @property
    def projected(self) -> tuple[str, str]:
        """``(status, reason)`` of the projection field (§3.4 R5 table)."""
        return DESCRIPTOR_PROJECTION[self.reason]

    @property
    def inflight_charge(self) -> int:
        return 0


AnyBody = RecordBody | DescriptorOnlyBody


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """A locator into one of this record's bodies (§3.4a); never content."""

    object_id: str
    role: str
    pointer: str | None = None
    byte_range: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class EvidenceContinuation:
    index: int
    final: bool


EvidenceScalar = int | bool | str | None
EvidenceValue = Any  # EvidenceScalar or nested lists/objects, bounded by EvidenceDoc.build


@dataclass(frozen=True, slots=True)
class EvidenceDoc:
    """The record's one structured evidence object (§3.4a), ``fabric.record-evidence/v1``.
    Build it with :meth:`build`, which checks the bounds and the type's closed item schema
    before anything is serialised (serialisation, ID mapping and a second check happen on
    the capture worker). ``charge`` is what it holds of ``max_inflight_bytes`` until the
    worker has encoded it: measured by :meth:`build`, else the 1 MiB cap (conservative)."""

    evidence_type: str
    items: tuple[Mapping[str, EvidenceValue], ...]
    refs: tuple[EvidenceRef, ...] = ()
    continuation: EvidenceContinuation | None = None
    charge: int = field(default=EVIDENCE_MAX_BYTES, init=False, repr=False, compare=False)

    @classmethod
    def build(
        cls, evidence_type: str, items: Sequence[Mapping[str, EvidenceValue]],
        refs: Sequence[EvidenceRef] = (), continuation: EvidenceContinuation | None = None,
        *, boundary: str = "caller",
    ) -> EvidenceDoc | DescriptorOnlyBody:  # fmt: skip
        """The evidence object, or a descriptor-only ``record.evidence`` (fail-open, R9):
        ``payload_too_large`` when an item-count, depth, string-length or total-work bound
        is exceeded; ``parse_failed``, counted ``api_misuse``, for a malformed document (an
        unknown type, a float, bytes, a non-string key, a bad ref or continuation, an item
        outside its type's closed schema). Never raises into the application, except under
        ``FABRIC_RECORDS_STRICT=1`` (:class:`RecordsMisuseError`, or ``TypeError`` for
        non-sequence ``items``/``refs``)."""
        from ._evidence import measure_evidence  # noqa: PLC0415 - _evidence imports this

        if not isinstance(boundary, str) or not boundary:
            misuse("evidence boundary must be a non-empty str")
            boundary = "caller"
        try:
            doc = cls(evidence_type, tuple(items), tuple(refs), continuation)
            charge = measure_evidence(doc)
        except (RecordsMisuseError, TypeError):
            COUNTERS.api_misuse += 1
            if strict():
                raise
            return DescriptorOnlyBody.for_reason(
                EVIDENCE_ROLE, EVIDENCE_MEDIA_TYPE, boundary, "parse_failed"
            )
        except Exception:  # an application object misbehaving while it is read
            COUNTERS.internal_errors += 1
            if strict():
                raise
            return DescriptorOnlyBody.for_reason(
                EVIDENCE_ROLE, EVIDENCE_MEDIA_TYPE, boundary, "parse_failed"
            )
        if charge is None:
            return DescriptorOnlyBody.for_reason(
                EVIDENCE_ROLE, EVIDENCE_MEDIA_TYPE, boundary, "payload_too_large"
            )
        object.__setattr__(doc, "charge", charge)
        return doc


@dataclass(frozen=True, slots=True)
class SpanIds:
    """Host span ids a record reuses (§3.4 "Span ids"): the record's own span id is then
    the host span's, so the ``records.span_id`` alias needs no key."""

    trace_id: int
    span_id: int
    parent_span_id: int | None = None
    parent_is_remote: bool = False


@dataclass(frozen=True, slots=True)
class RecordJob:
    """One records-input job (§3.4 step 3), immutable, bodies held by reference. Field names
    of the source triple match :class:`~fabric.wire._model.CaptureJob`, so the pipeline's
    loss path serves both. ``attributes`` already passed rule A."""

    source_id: str
    source_epoch: int
    source_sequence: int
    segment_id: str | None
    run_id: str | None
    scope_id: str | None
    event_id: str
    attempt_uid: str
    name: str  # rule N category name
    start_ns: int
    end_ns: int
    otlp_status: OtlpStatus
    attributes: Mapping[str, AttributeValue]
    bodies: tuple[AnyBody, ...] = ()
    evidence: EvidenceDoc | None = None
    span_ids: SpanIds | None = None
    parent_context: Context | None = None
    provenance: Provenance = "reported"

    def __post_init__(self) -> None:
        if len(self.bodies) + (self.evidence is not None) > MAX_RECORD_BODIES:
            raise RecordsMisuseError("records API misuse: more than 8 bodies on one record")
        evidence_bodies = sum(body.role == EVIDENCE_ROLE for body in self.bodies)
        if evidence_bodies + (self.evidence is not None) > 1:
            raise RecordsMisuseError("records API misuse: more than one evidence object")
        if self.otlp_status not in OTLP_STATUSES:
            raise RecordsMisuseError("records API misuse: unknown otlp_status")
        if self.provenance not in PROVENANCES:
            raise RecordsMisuseError("records API misuse: unknown provenance")
        if self.provenance == "reported" and any(
            isinstance(body, RecordBody) and body.content_provenance == "protocol"
            for body in self.bodies
        ):  # fmt: skip
            raise RecordsMisuseError("records API misuse: protocol content on a reported record")

    @property
    def inflight_charge(self) -> int:
        """Bytes charged to ``max_inflight_bytes`` (§3.4 step 3): the bodies and the
        evidence object held by reference (its bounded :attr:`EvidenceDoc.charge`)."""
        held = sum(body.inflight_charge for body in self.bodies)
        evidence = self.evidence
        if evidence is not None:
            charge = getattr(evidence, "charge", EVIDENCE_MAX_BYTES)
            held += charge if type(charge) is int and 0 < charge <= EVIDENCE_MAX_BYTES else (
                EVIDENCE_MAX_BYTES)  # fmt: skip
        return held
