# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The records input (spec 050 §3.4): sequenced records on the wire spool, one per handle.

An :class:`Attempt` emits records of one step attempt. Each ``emit`` runs on the
application thread and does only this: the phase table (R4), rule A (the generated
records-class key table: exactly the keys fabricguard keeps), rule N (the span name
fabricguard derives), one allocation on the shared allocator, an immutable
:class:`~fabric._capture_types.RecordJob` holding the bodies by reference, the in-flight
byte charge, and a non-blocking ``put_nowait`` into the capture pipeline. Encoding,
PROTECT, digests, the spool write and the seal all happen on the capture worker
(``wire/_pipeline.py``).

Fail-open (R9): every call returns ``None``/``False``/``"omit"`` on misuse or an internal
failure and counts it (:data:`fabric._capture_types.COUNTERS`); it raises only under
``FABRIC_RECORDS_STRICT=1``. A failure after a position was allocated is an
``internal_error`` loss of that position, never a silent gap.

Identity (R8): in the pseudonymous mode (the default) every caller-supplied id is mapped,
whatever its shape; only an :class:`~fabric._sequence.EmittedId` of this input's issuer
passes through. The ``clear`` mode (``FABRIC_IDENTITY_MODE=clear``) emits ids as given. In
the production profile without ``FABRIC_WIRE_ID_KEY`` nothing derived from a caller id
leaves the process in either mode (049 §2.9 rule 5): join ids are generated ``g-`` ids and
v2 identities are omitted, by the run table's :class:`~fabric._segments.IdentityRule`.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import threading
import uuid
import weakref
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

from opentelemetry import context as otel_context

from ._capture_types import COUNTERS as _COUNTERS
from ._capture_types import (
    EVIDENCE_MEDIA_TYPE,
    EVIDENCE_ROLE,
    MAX_RECORD_BODIES,
    PROVENANCES,
    STEP_KINDS,
    UUID4_RE,
    AnyBody,
    DescriptorOnlyBody,
    EvidenceDoc,
    Lifecycle,
    OtlpStatus,
    Phase,
    PrivacyMode,
    Provenance,
    RecordBody,
    RecordJob,
    RecordsMisuseError,
    ResultStatus,
    SpanIds,
    StepKind,
    fail_open,
    misuse,
    resolve_status_inputs,
    strict,
)
from ._evidence import EvidenceIds
from ._records_keys_generated import RECORD_KEY_CHECKS, RECORD_KEY_CONDITIONS
from ._roles import ROLES
from ._sequence import (
    V2_TYPES,
    EmittedId,
    GeneratedIds,
    IdentityMode,
    KeyedIds,
    Labels,
    encode_opaque_id,
    identity_mode_from_env,
)
from ._version import __version__

if TYPE_CHECKING:
    from opentelemetry.util.types import AttributeValue

    from .wire import WireHandle

_NO_ALIASES: Mapping[str, str] = MappingProxyType({})
RECORDS_POINT = "sdk.records"
CAPTURE_INPUT = "records"
POINT_ID_RE = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")
POINT_RE = re.compile(r"^[a-z][a-z0-9_.]{0,63}@[0-9A-Za-z.+-]{1,32}$")
ALIAS_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}$")
INT64_MIN, INT64_MAX = -(1 << 63), (1 << 63) - 1
MAX_OBJECT_BYTES_ENV = "FABRIC_RECORDS_MAX_OBJECT_BYTES"
DEFAULT_MAX_OBJECT_BYTES = 16 * 1024 * 1024  # 16777216, also the maximum

# Keys only Fabric sets on a record (§3.4 "Keys every record carries"); a caller value for
# one of them is dropped and counted (records_keys_dropped), never kept.
FABRIC_OWNED_KEYS: frozenset[str] = frozenset({
    "fabric.capture.input", "fabric.capture.source", "fabric.capture.point",
    "fabric.source_id", "fabric.source.epoch", "fabric.source.sequence", "fabric.event_id",
    "fabric.attempt.uid", "fabric.run.id", "fabric.run.scope_id", "fabric.run.segment_id",
    "fabric.step.kind", "fabric.step.lifecycle_state", "fabric.step.status",
    "fabric.content.object_ids",
})  # fmt: skip
# Caller ids rule A admits on a record: always emitted in their mapped form (R8, decision 22).
ID_KEYS: frozenset[str] = frozenset({"fabric.step.id", "fabric.step.attempt_id",
                                     "fabric.step.parent_id"})  # fmt: skip


def records_max_object_bytes(environ: Mapping[str, str]) -> int:
    """``FABRIC_RECORDS_MAX_OBJECT_BYTES`` (default and maximum 16777216, minimum 1); a
    malformed value is configuration and raises ``ValueError`` (fixed text) at install."""
    raw = (environ.get(MAX_OBJECT_BYTES_ENV) or "").strip()
    if not raw:
        return DEFAULT_MAX_OBJECT_BYTES
    if not raw.isdigit() or not 1 <= int(raw) <= DEFAULT_MAX_OBJECT_BYTES:
        raise ValueError(f"{MAX_OBJECT_BYTES_ENV} must be an integer between 1 and 16777216")
    return int(raw)


@dataclass(frozen=True, slots=True)
class BudgetRefusedBody(DescriptorOnlyBody):
    """A body refused at ``emit`` because ``max_inflight_bytes`` was exhausted (§3.4 step
    3): the worker writes a descriptor-only object ``not_captured(inflight_budget)``, as
    the wire line does for a side cut by the budget. Holds no reference to the data."""

    @classmethod
    def of(cls, body: RecordBody) -> BudgetRefusedBody:
        return cls(body.role, body.media_type, body.boundary, "not_captured",
                   "payload_too_large")  # fmt: skip


# --- rule A: the attribute projection (generated table, fail closed) ---------------------------

Predicate = Callable[[Any], bool]


def _never(value: Any) -> bool:
    return False


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _string_predicate(check: Mapping[str, Any], labels: Labels) -> Predicate:
    pattern = re.compile(check["pattern"])
    groups = tuple(check.get("int64_groups", ()))
    rule = check.get("capture_labels")
    label = None
    if rule and labels == "pseudonymous":
        label = (rule.get("group"), re.compile(rule["pseudonymous_pattern"]))

    def ok(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        match = pattern.fullmatch(value)
        if match is None:
            return False
        for group in groups:
            found = match.group(group)
            if found is not None and int(found) > INT64_MAX:
                return False
        if label is not None:
            group, labelled = label
            subject = match.group(group) if group is not None else value
            if subject is not None:
                return labelled.fullmatch(subject) is not None
        return True

    return ok


def compile_check(  # noqa: PLR0911 - one return per check type
    check: Mapping[str, Any], *, labels: Labels = "pseudonymous",
    identity: IdentityMode = "pseudonymous",
) -> Predicate:  # fmt: skip
    """A predicate equal to the registry check function
    (``validate_coverage_contracts.check_value``) under the Node's ``capture_labels`` and
    ``identity_mode``. An unknown check type admits nothing (fail closed)."""
    kind = check.get("type")
    if identity == "clear" and check.get("identity_mode", {}).get("clear") == "existing":
        return lambda value: isinstance(value, str)
    if kind == "enum":
        values = frozenset(check["values"])
        return lambda value: isinstance(value, str) and value in values
    if kind == "const":
        const = check["value"]
        return lambda value: type(value) is type(const) and value == const
    if kind == "bool":
        return lambda value: isinstance(value, bool)
    if kind == "int":
        low, high = check["min"], check.get("max", INT64_MAX)
        return lambda value: _is_int(value) and INT64_MIN <= value <= INT64_MAX and (
            low <= value <= high)  # fmt: skip
    if kind == "string":
        return _string_predicate(check, labels)
    if kind == "array":
        item = compile_check(check["items"], labels=labels)
        low, high, unique = check.get("min_items", 0), check["max_items"], check.get("unique")

        def array_ok(value: Any) -> bool:
            if not isinstance(value, list) or not low <= len(value) <= high:
                return False
            if unique and len({json.dumps(v) for v in value}) != len(value):
                return False
            return all(item(v) for v in value)

        return array_ok
    return _never


def compile_checks(
    *, labels: Labels = "pseudonymous", identity: IdentityMode = "pseudonymous",
    table: Mapping[str, Mapping[str, Any]] = RECORD_KEY_CHECKS,
) -> dict[str, Predicate]:  # fmt: skip
    """Rule A's table as predicates for one Node configuration."""
    return {key: compile_check(check, labels=labels, identity=identity)
            for key, check in table.items()}  # fmt: skip


def _condition_holds(condition: Mapping[str, Sequence[str]] | None, point: Any) -> bool:
    """A conditional ``record`` placement, matched against the id part of
    ``fabric.capture.point``. ``capture_point_kinds`` needs the registry's point-kind table,
    which no P1 row uses: it fails closed until a generated kind table exists."""
    if not condition:
        return True
    point_id = point.split("@", 1)[0] if isinstance(point, str) else ""
    if "capture_points" in condition and point_id not in condition["capture_points"]:
        return False
    return "capture_point_kinds" not in condition


def _array_bound(table: Mapping[str, Mapping[str, Any]]) -> int:
    bounds = [int(check["max_items"]) for check in table.values() if check.get("type") == "array"]
    return max(bounds, default=0)


# The longest array any records-class key admits: a longer sequence is refused by its
# length alone, before any element is looked at.
MAX_ATTRIBUTE_ITEMS = _array_bound(RECORD_KEY_CHECKS)
_SCALARS = (str, bool, int)


def _admitted_value(value: Any) -> tuple[bool, Any]:
    """``(True, value as projected)`` when ``value`` has an admissible shape: a ``str``,
    ``bool`` or ``int``, or a flat ``list``/``tuple`` of them no longer than any admitted
    array. Shapes and lengths are checked before anything is copied, and a nested element
    refuses the value without entering it (so a cyclic or huge value costs one bounded
    look). ``str`` subclasses become ``str``; tuples become lists."""
    if isinstance(value, _SCALARS):
        return True, str.__str__(value) if isinstance(value, str) else value
    if not isinstance(value, (list, tuple)) or len(value) > MAX_ATTRIBUTE_ITEMS:
        return False, None
    out: list[Any] = []
    for element in value:
        if not isinstance(element, _SCALARS):
            return False, None
        out.append(str.__str__(element) if isinstance(element, str) else element)
    return True, out


def project_attributes(
    attributes: Mapping[str, Any], checks: Mapping[str, Predicate], *,
    conditions: Mapping[str, Mapping[str, Sequence[str]]] = RECORD_KEY_CONDITIONS,
    point: str | None = None,
) -> tuple[dict[str, Any], list[str]]:  # fmt: skip
    """Rule A (§3.4): keep exactly the keys of the records-class table whose value passes
    the key's check; drop everything else (unknown keys, failing values, floats, maps,
    bytes). A value is never hashed or truncated. Returns ``(kept, sorted dropped keys)``;
    tuples become lists. ``point``: the record's ``fabric.capture.point`` for conditional
    placements (default: the attribute itself)."""
    kept: dict[str, Any] = {}
    dropped: list[str] = []
    where = point if point is not None else attributes.get("fabric.capture.point")
    for key, raw in attributes.items():
        # The key is admitted (its table row and placement) before its value is touched.
        check = checks.get(key) if isinstance(key, str) else None
        if check is None or not _condition_holds(conditions.get(key), where):
            dropped.append(str.__str__(key) if isinstance(key, str) else "<non-str key>")
            continue
        admissible, value = _admitted_value(raw)
        if not admissible or not check(value):
            dropped.append(key)
        else:
            kept[key] = value
    return kept, sorted(dropped)


# --- rule N: the span name (port of fabricguard activityCategory) -------------------------------

_TOOL_KEYS = ("fabric.tool.name", "gen_ai.tool.name", "fabric.tool.result_hash")
_MODEL_KEYS = ("fabric.llm.system", "gen_ai.request.model", "fabric.wire.exchange_id")
_ORDERED = (
    ("fabric.retrieval.source", "fabric.retrieval"), ("fabric.memory.kind", "fabric.memory"),
    ("fabric.side_effect.type", "fabric.side_effect"),
    ("fabric.interaction.kind", "fabric.interaction"),
    ("fabric.file.operation", "fabric.file_access"),
    ("fabric.delegation.protocol", "fabric.delegation"),
    ("fabric.checkpoint.checkpoint_id", "fabric.checkpoint"),
    ("fabric.replay.execution_id", "fabric.replay"),
    ("fabric.mcp.server", "fabric.mcp.inventory"), ("fabric.skill.name", "fabric.skill"),
    ("fabric.hook.phase", "fabric.hook"), ("fabric.coverage.kind", "fabric.coverage"),
    ("fabric.execution.status", "fabric.execution"), ("fabric.execution_id", "fabric.execution"),
    ("fabric.decision_id", "fabric.decision"),
)  # fmt: skip
KNOWN_NAMES: frozenset[str] = frozenset({
    "fabric.execution", "fabric.decision", "fabric.llm_call", "fabric.model_call",
    "fabric.tool_call", "fabric.retrieval", "fabric.memory", "fabric.side_effect",
    "fabric.interaction", "fabric.file_access", "fabric.delegation", "fabric.error",
    "fabric.retry", "fabric.cancellation", "fabric.deployment_change", "fabric.human_action",
    "fabric.checkpoint", "fabric.replay", "fabric.mcp.inventory", "fabric.skill",
    "fabric.hook", "fabric.coverage", "fabric.capture_loss", "fabric.capture_heartbeat",
    "fabric.capture_manifest",
})  # fmt: skip


def category(name_hint: str, attribute_keys: Sequence[str] | Mapping[str, Any]) -> str:
    """The exported span name fabricguard derives (``P/processor.go`` activityCategory):
    decided by attribute keys first, then by the name itself when it is a known Fabric
    name, else ``fabric.activity``. Only keys decide, never values."""
    keys = set(attribute_keys)
    if "fabric.heartbeat.last_sequence" in keys:
        return "fabric.capture_heartbeat"
    if "fabric.loss.reason" in keys:
        return "fabric.capture_loss"
    if any(key in keys for key in _TOOL_KEYS):
        return "fabric.tool_call"
    if any(key in keys for key in _MODEL_KEYS):
        return "fabric.model_call"
    for key, name in _ORDERED:
        if key in keys:
            return name
    return name_hint if name_hint in KNOWN_NAMES else "fabric.activity"


# --- the records input ------------------------------------------------------------------------


class RecordsStats:
    """Counters of one records input (``status()`` material; never a value)."""

    __slots__ = (
        "__weakref__", "_lock", "budget_refused", "emitted", "keys_dropped", "not_submitted",
    )  # fmt: skip

    def __init__(self) -> None:
        self._init_state()
        _STATS.add(self)

    def _init_state(self) -> None:
        """Fresh lock and zero counters: at construction and in a forked child (049 §7.1:
        ``add`` runs on the app thread, and a parent thread inside ``add``/``snapshot`` at
        the fork would otherwise hold the child's lock forever)."""
        self._lock = threading.Lock()
        self.emitted = self.keys_dropped = self.budget_refused = self.not_submitted = 0

    def add(self, name: str, count: int = 1) -> None:
        with self._lock:
            setattr(self, name, getattr(self, name) + count)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {"records_emitted": self.emitted, "records_keys_dropped": self.keys_dropped,
                    "records_budget_refused": self.budget_refused,
                    "records_not_submitted": self.not_submitted}  # fmt: skip


_STATS: weakref.WeakSet[RecordsStats] = weakref.WeakSet()


def _after_fork_in_child() -> None:
    for stats in list(_STATS):
        with contextlib.suppress(Exception):
            stats._init_state()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


def _check_ns(value: object, what: str) -> int:
    if type(value) is not int or not 0 <= value <= INT64_MAX:
        raise RecordsMisuseError(f"records API misuse: {what} must be an int64 >= 0")
    return value


def _event_id(value: object) -> str:
    """The record's ``fabric.event_id``: minted (dashed uuid4), or the explicit
    ``record_id`` normalised to dashed lowercase; anything else is misuse (minted)."""
    if value is None:
        return str(uuid.uuid4())
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        misuse("event_id must be a uuid4")
        return str(uuid.uuid4())
    text = str(parsed)
    if not UUID4_RE.fullmatch(text):
        misuse("event_id must be a uuid4")
        return str(uuid.uuid4())
    return text


class Attempt:
    """One step attempt on the records input (§3.4). ``uid`` is a dashed uuid4 minted by
    Fabric (X19), never taken from the caller."""

    __slots__ = ("base", "kind", "point", "provenance", "records", "uid")

    def __init__(
        self, records: RecordsInput, uid: EmittedId, kind: StepKind, point: str,
        provenance: Provenance = "reported", base: Mapping[str, AttributeValue] | None = None,
    ) -> None:  # fmt: skip
        self.records, self.uid, self.kind = records, uid, kind
        self.point, self.provenance = point, provenance
        self.base: Mapping[str, AttributeValue] = MappingProxyType(dict(base or {}))

    @fail_open(False)
    def emit(
        self, phase: Phase, *, name_hint: str, attributes: Mapping[str, AttributeValue],
        start_ns: int, end_ns: int, lifecycle: Lifecycle | None = None,
        result_status: ResultStatus | None = None, otlp_status: OtlpStatus = "unset",
        bodies: Sequence[AnyBody] = (), evidence: EvidenceDoc | None = None,
        event_id: str | None = None, span_ids: SpanIds | None = None,
    ) -> bool:  # fmt: skip
        """Emit one sequenced record of this attempt; ``False`` when nothing was emitted
        (the input is not active, or the record was lost at the queue: a counted loss).
        ``lifecycle``, ``result_status`` and ``otlp_status`` are three independent inputs
        resolved by :func:`fabric._capture_types.resolve_status_inputs` (R4); an input
        outside the phase table is dropped (``api_misuse``) and the record still emitted."""
        records = self.records
        if not records.active:
            return False
        status = resolve_status_inputs(phase, lifecycle, result_status, otlp_status)
        for name in status.dropped:
            misuse(f"{name} outside the phase table")
        if not isinstance(name_hint, str):
            raise RecordsMisuseError("records API misuse: name_hint must be a str")
        start = _check_ns(start_ns, "start_ns")
        end = _check_ns(end_ns, "end_ns")
        if end < start:
            misuse("end_ns before start_ns")
            end = start
        if not isinstance(attributes, Mapping):
            raise RecordsMisuseError("records API misuse: attributes must be a mapping")
        kept_bodies = records.check_bodies(bodies, evidence, self.provenance)
        if evidence is not None and not isinstance(evidence, EvidenceDoc):
            misuse("evidence must be an EvidenceDoc")
            evidence = None
        if span_ids is not None and not isinstance(span_ids, SpanIds):
            misuse("span_ids must be SpanIds")
            span_ids = None
        minted = _event_id(event_id)  # minted before allocation (§3.4 keys table)
        return records.submit(
            self, minted, status.lifecycle, status.result_status, status.otlp_status,
            name_hint, attributes, start, end, kept_bodies, evidence, span_ids,
        )  # fmt: skip


class RecordsInput:
    """The records input of one installed wire handle (§3.1 "Activation")."""

    def __init__(self, handle: WireHandle | None = None) -> None:
        self.handle = handle
        self.stats = RecordsStats()
        from ._segments import IdentityRule  # noqa: PLC0415 - imported by install already

        config = getattr(handle, "config", None)
        self._labels: Labels = cast("Labels", getattr(config, "labels", None) or "pseudonymous")
        self._identity: IdentityMode = identity_mode_from_env(os.environ)
        self._key: bytes | None = getattr(config, "id_key", None)
        gate = getattr(handle, "gate", None)
        # The run identity rule (049 §2.9 rule 5 included), shared with the run table: the
        # production profile without a key derives nothing from a caller id in either mode.
        self._rule = IdentityRule(
            key=self._key,
            mode=self._identity,
            production=getattr(gate, "profile", None) == "production",
        )
        self._clear = self._identity == "clear" and not self._rule.production_without_key
        self._ids: KeyedIds | GeneratedIds = self._rule._ids
        self._checks = compile_checks(
            labels=self._labels, identity="clear" if self._clear else "pseudonymous"
        )
        self._point_version = __version__
        self._modes: tuple[int, dict[str, PrivacyMode]] = (-1, {})
        self.evidence_ids = EvidenceIds(self._evidence_id, clear=self._clear)
        tee = getattr(handle, "_tee_or_none", None)
        self._tee = tee
        if tee is not None:
            tee.pipeline.set_record_budget(lambda: tee.budget)
            tee.pipeline.set_evidence_ids(self.evidence_ids)

    # -- state ------------------------------------------------------------------------------

    @property
    def active(self) -> bool:
        """Whether this input captures now: its handle is installed and capturing and this
        is still the handle's records input (``close()`` detaches it)."""
        handle = self.handle
        return (handle is not None and self._tee is not None and handle.capturing
                and getattr(handle, "records", None) is self)  # fmt: skip

    @property
    def identity_mode(self) -> IdentityMode:
        """The identity mode ids are emitted in: ``clear`` only as the explicit opt-in and
        never in the production profile without a key (049 §2.9 rule 5)."""
        return "clear" if self._clear else "pseudonymous"

    # -- the API ----------------------------------------------------------------------------

    @fail_open(None)
    def begin(
        self, kind: StepKind, point: str, *, provenance: Provenance = "reported",
        step_id: str | None = None, parent_attempt: str | None = None,
        aliases: Mapping[str, str] = _NO_ALIASES,
    ) -> Attempt | None:  # fmt: skip
        """Open an attempt of step ``kind`` at capture point ``point`` (its id, such as
        ``sdk.records``; the emitted ``fabric.capture.point`` is ``<id>@<sdk version>``);
        ``None`` while the records input is not active (producers keep their current
        path). ``step_id`` is the caller's logical step id and ``parent_attempt`` the
        parent's attempt uid, both mapped by the identity rule (an attempt uid of this
        input passes through). ``aliases`` (049 X38, ``<input>.<name>`` keys) are checked
        but carried by the projection, not by a telemetry key in P1."""
        if kind not in STEP_KINDS:
            raise RecordsMisuseError("records API misuse: unknown step kind")
        if provenance not in PROVENANCES:
            raise RecordsMisuseError("records API misuse: unknown provenance")
        if not isinstance(point, str) or not (
            POINT_ID_RE.fullmatch(point) or POINT_RE.fullmatch(point)
        ):  # fmt: skip
            raise RecordsMisuseError("records API misuse: capture point id")
        if not isinstance(aliases, Mapping) or not all(
            isinstance(k, str) and ALIAS_KEY_RE.fullmatch(k) and isinstance(v, str) and v
            for k, v in aliases.items()
        ):  # fmt: skip
            raise RecordsMisuseError("records API misuse: aliases are <input>.<name> -> id")
        if not self.active:
            return None
        base: dict[str, AttributeValue] = {}
        if step_id is not None:
            base["fabric.step.id"] = self._map(step_id, "step_id")
        if parent_attempt is not None:
            base["fabric.step.parent_id"] = self._map(parent_attempt, "parent_attempt")
        emitted = point if "@" in point else f"{point}@{self._point_version}"
        uid = self._ids.mint(str(uuid.uuid4()))
        return Attempt(self, uid, kind, emitted, provenance, base)

    @fail_open("omit")
    def mode_of(self, role: str) -> PrivacyMode:
        """The privacy mode the capture policy resolves for ``role`` (049 §2.7, §3.4a for
        ``record.evidence``), cached per role for the epoch; ``omit`` when content capture
        is disabled, the role is unknown, or on any failure (fail closed). Producers call it
        before serialising a body: under ``omit`` they build no body at all."""
        tee = self._tee
        if tee is None or not self.active or role not in ROLES:
            return "omit"
        epoch = tee.allocator.epoch
        cached_epoch, modes = self._modes
        if cached_epoch != epoch:
            modes = {}
            self._modes = (epoch, modes)
        mode = modes.get(role)
        if mode is None:
            mode = cast("PrivacyMode", tee.pipeline.record_mode(role))
            modes[role] = mode
        return mode

    @fail_open(None)
    def v2(self, prefix: str, value: str) -> str | None:
        """The identity rule (R8): an ``EmittedId`` of this input's issuer unchanged; the
        keyed v2 pseudonym in pseudonymous mode; ``None`` (omit it) without a key or in the
        production profile without one (049 §2.9 rule 5); in clear mode the value as given
        (``h-`` when not opaque). An unknown ``prefix`` or a non-string value is misuse."""
        if prefix not in V2_TYPES:
            raise RecordsMisuseError("records API misuse: unknown v2 prefix")
        if not isinstance(value, str) or not value:
            raise RecordsMisuseError("records API misuse: v2 value must be a non-empty str")
        return self._evidence_id(prefix, value)

    def _evidence_id(self, prefix: str, value: str) -> str | None:
        """:meth:`v2` without the argument checks: also the evidence ID rule the capture
        worker applies (:class:`~fabric._evidence.EvidenceIds`)."""
        if self._ids._mine(value):
            return value
        mapped = self._rule.v2(prefix, value)
        if mapped is None or self._clear:
            return mapped
        return self._ids.mint(mapped)

    def map_id(self, value: str) -> str:
        """A caller-supplied step, operation or stream id as emitted (R8): pseudonymous:
        the keyed ``lbl-`` label, or a random ``g-`` id remembered per process without a key
        (nothing derived from the value; always so in the production profile without a
        key); clear: as given (``h-`` when not opaque). The result is an ``EmittedId`` of
        this input in the pseudonymous mode, so passed back it is not mapped again."""
        if self._clear and not self._ids._mine(value):
            return encode_opaque_id(value)
        return self._ids.other(value)

    def _map(self, value: object, what: str) -> str:
        if not isinstance(value, str) or not value:
            raise RecordsMisuseError(f"records API misuse: {what} must be a non-empty str")
        return self.map_id(value)

    # -- emit (application thread) --------------------------------------------------------

    def check_bodies(
        self, bodies: object, evidence: object, provenance: Provenance
    ) -> tuple[AnyBody, ...]:
        """The bodies an ``emit`` keeps: frozen ``bytes``/``str`` data, ``protocol``
        provenance only on observed attempts, at most :data:`MAX_RECORD_BODIES` with the
        evidence object, one evidence object. Every refused body is ``api_misuse``."""
        if isinstance(bodies, (str, bytes)) or not isinstance(bodies, Sequence):
            misuse("bodies must be a sequence")
            return ()
        kept: list[AnyBody] = []
        room = MAX_RECORD_BODIES - (evidence is not None)
        has_evidence = evidence is not None
        for body in bodies:
            if isinstance(body, RecordBody):
                if type(body.data) not in (bytes, str):  # a mutable or foreign buffer
                    misuse("body data must be frozen bytes or str")
                    continue
                if body.content_provenance == "protocol" and provenance != "observed":
                    misuse("protocol content on a reported attempt")
                    continue
            elif not isinstance(body, DescriptorOnlyBody):
                misuse("bodies are RecordBody or DescriptorOnlyBody")
                continue
            if body.role == EVIDENCE_ROLE:
                if has_evidence:
                    misuse("more than one evidence object")
                    continue
                has_evidence = True
            if len(kept) >= room:
                misuse("more than 8 bodies on one record")
                continue
            kept.append(body)
        return tuple(kept)

    def submit(
        self, attempt: Attempt, event_id: str, lifecycle: Lifecycle | None,
        result_status: ResultStatus | None, otlp_status: OtlpStatus, name_hint: str,
        attributes: Mapping[str, Any], start_ns: int, end_ns: int,
        bodies: tuple[AnyBody, ...], evidence: EvidenceDoc | None, span_ids: SpanIds | None,
    ) -> bool:  # fmt: skip
        """Steps 1-5 of §3.4: project, allocate, build the job, charge, submit."""
        tee = self._tee
        if tee is None:
            return False
        caller: dict[str, Any] = {}
        for key, value in attributes.items():
            if key in FABRIC_OWNED_KEYS:
                continue
            caller[key] = self.map_id(value) if key in ID_KEYS and isinstance(value, str) else value
        owned = len(attributes) - len(caller)
        caller.update(attempt.base)  # the ids begin() mapped win over a caller value
        kept, dropped = project_attributes(caller, self._checks, point=attempt.point)
        allocator = tee.allocator
        allocation = allocator.allocate()
        try:
            return self._after_allocation(
                tee, allocation, attempt, event_id, lifecycle, result_status, otlp_status,
                name_hint, kept, len(dropped) + owned, start_ns, end_ns, bodies, evidence,
                span_ids,
            )  # fmt: skip
        except BaseException as exc:
            failed = isinstance(exc, Exception)
            if failed and not strict():  # under strict, fail_open counts it as it propagates
                _COUNTERS.internal_errors += 1
            tee.loss.record(allocator.source_id, allocation.epoch, "internal_error",
                            allocation.sequence, segment_id=allocation.segment_id)  # fmt: skip
            if failed and not strict():
                return False
            raise

    def _after_allocation(
        self, tee: Any, allocation: Any, attempt: Attempt, event_id: str,
        lifecycle: Lifecycle | None, result_status: ResultStatus | None,
        otlp_status: OtlpStatus, name_hint: str, kept: dict[str, Any], dropped: int,
        start_ns: int, end_ns: int, bodies: tuple[AnyBody, ...],
        evidence: EvidenceDoc | None, span_ids: SpanIds | None,
    ) -> bool:  # fmt: skip
        allocator, scope = tee.allocator, allocation.scope
        fabric: dict[str, Any] = {
            "fabric.capture.input": CAPTURE_INPUT, "fabric.capture.source": attempt.provenance,
            "fabric.capture.point": attempt.point, "fabric.source_id": allocator.source_id,
            "fabric.source.epoch": allocation.epoch,
            "fabric.source.sequence": allocation.sequence, "fabric.event_id": event_id,
            "fabric.attempt.uid": str.__str__(attempt.uid), "fabric.step.kind": attempt.kind,
        }  # fmt: skip
        if scope is not None:
            fabric["fabric.run.id"] = scope.run_id
            fabric["fabric.run.scope_id"] = scope.scope_id
        if allocation.segment_id is not None:
            fabric["fabric.run.segment_id"] = allocation.segment_id
        if lifecycle is not None:
            fabric["fabric.step.lifecycle_state"] = lifecycle
        if result_status is not None:
            fabric["fabric.step.status"] = result_status
        checked, refused = project_attributes(fabric, self._checks, point=attempt.point)
        attrs = {**kept, **checked}
        attrs.setdefault("fabric.actor.type", "agent")
        if dropped + len(refused):
            self.stats.add("keys_dropped", dropped + len(refused))
        bodies = tuple(
            replace(body, stream_id=str.__str__(self.map_id(body.stream_id)))
            if isinstance(body, RecordBody) and body.stream_id is not None else body
            for body in bodies
        )  # fmt: skip
        job = RecordJob(
            source_id=allocator.source_id, source_epoch=allocation.epoch,
            source_sequence=allocation.sequence, segment_id=allocation.segment_id,
            run_id=scope.run_id if scope is not None else None,
            scope_id=scope.scope_id if scope is not None else None, event_id=event_id,
            attempt_uid=str.__str__(attempt.uid), name=category(name_hint, attrs),
            start_ns=start_ns, end_ns=end_ns, otlp_status=otlp_status,
            attributes=MappingProxyType(attrs), bodies=bodies, evidence=evidence,
            span_ids=span_ids,
            parent_context=otel_context.get_current() if span_ids is None else None,
            provenance=attempt.provenance,
        )  # fmt: skip
        pipeline = tee.pipeline
        if not pipeline.charge_record(job):
            refused_bodies = tuple(
                BudgetRefusedBody.of(body) if isinstance(body, RecordBody) else body
                for body in bodies
            )  # fmt: skip
            if evidence is not None:  # the reference is dropped; the record says why
                boundary = next((body.boundary for body in bodies), "caller")
                refused_bodies += (BudgetRefusedBody(EVIDENCE_ROLE, EVIDENCE_MEDIA_TYPE,
                                   boundary, "not_captured", "payload_too_large"),)  # fmt: skip
            job = replace(job, bodies=refused_bodies, evidence=None)
            self.stats.add("budget_refused")
        if pipeline.submit(job):
            self.stats.add("emitted")
            return True
        self.stats.add("not_submitted")  # queue_full / shutdown: a recorded loss
        return False


def records_input(handle: WireHandle | None) -> RecordsInput | None:
    """The records input of ``handle`` while it captures, else ``None`` (§3.1)."""
    if handle is None or not handle.capturing:
        return None
    return getattr(handle, "records", None)


__all__ = [
    "CAPTURE_INPUT", "DEFAULT_MAX_OBJECT_BYTES", "FABRIC_OWNED_KEYS", "ID_KEYS", "KNOWN_NAMES",
    "MAX_OBJECT_BYTES_ENV", "RECORDS_POINT", "Attempt", "BudgetRefusedBody", "RecordsInput",
    "RecordsStats", "category", "compile_check", "compile_checks", "project_attributes",
    "records_input", "records_max_object_bytes",
]  # fmt: skip
