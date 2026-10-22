# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Opt-in call timelines linked to protected exact bytes (spec 043).

Only explicitly wrapped boundaries are observed. Callers supply final bytes;
opaque identifiers must not contain customer data. Persistence happens in the
existing bounded byte writer, off the action path. Snapshots are offline and
may wait for that writer. Source authentication and durable receipt proofs
are unavailable; a matching local run is never a complete-production claim.

Three modes (spec 050 §3.10). ``journal``: qualified-run mode (a ``source_spool``),
byte for byte the behaviour above. ``records``: no ``source_spool`` and a wire handle
installed; every journal event becomes one sequenced record on the install's records
input, so explicit calls share the wire input's allocator, spool, PROTECT stage, seal and
sender (and its delivery guarantee); the byte writer is not called and ``snapshot()`` is
an in-memory view. ``legacy``: neither; the behaviour above plus one
``DeprecationWarning`` per process. ``auto`` (the default) picks one at construction.
"""

from __future__ import annotations

import asyncio
import copy
import inspect
import logging
import math
import os
import re
import threading
import time
import uuid
import warnings
import weakref
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, TypeVar, get_args

from opentelemetry import context as otel_context
from opentelemetry import trace

from ._capture_scope import ExplicitScope, explicit_model_call
from ._capture_types import (
    AnyBody,
    DescriptorOnlyBody,
    Lifecycle,
    OtlpStatus,
    Phase,
    RecordBody,
    ResultStatus,
    StepKind,
    strict,
)
from ._records import DEFAULT_MAX_OBJECT_BYTES, records_max_object_bytes
from ._roles import ROLES
from ._sequence import GeneratedIds
from .byte_evidence import ByteEvidenceRecorder
from .content_join import CONTENT_JOIN_FIELDS, capture_content_binding
from .source_spool import _MAX_SEAL_TIMEOUT_S, SyntheticSourceSpool
from .tracing import get_tracer

if TYPE_CHECKING:
    from ._records import Attempt, RecordsInput
    from .byte_resolver import ByteEvidenceResolver

_T = TypeVar("_T")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_KINDS = {
    "model": ("provider_bound", "model.request.messages", "model.output.messages"),
    "tool": ("tool", "tool.call.arguments", "tool.call.result"),
    "database": ("service", "database.query", "database.rows"),
    "agent": ("caller", "tool.call.arguments", "tool.call.result"),
}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _seal_refusal(snapshot: dict[str, Any]) -> str | None:
    if snapshot["writer_settled"] is not True or snapshot["source_spool_settled"] is not True:
        return "writers_unsettled"
    if snapshot["recording_gaps"] or snapshot["unretained_drops"]:
        return "recording_loss"
    if any(call["status"] not in {"ok", "error", "cancelled"} for call in snapshot["calls"]):
        return "call_incomplete"
    if any(event["status"] != "stored" for event in snapshot["events"]):
        # Withheld bytes may be valid policy, but cannot establish original-byte
        # completeness for this convenience API.
        return "content_not_stored"
    return None


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("identity must be an opaque ASCII identifier of 1 to 128 characters")
    return value


# --- spec 050 §3.10: the three-way mode shared by the explicit producers ------------------------

ProducerMode = Literal["auto", "records", "journal", "legacy"]
ResolvedMode = Literal["records", "journal", "legacy"]
PRODUCER_MODES: frozenset[str] = frozenset(get_args(ProducerMode))
# CallRecorder kinds as step kinds (§3.10 "Ids") and the record name hint (rule N).
STEP_KIND: Mapping[str, StepKind] = {
    "model": "model_call", "tool": "tool_call", "database": "database", "agent": "delegation",
}  # fmt: skip
NAME_HINT: Mapping[str, str] = {
    "model_call": "fabric.model_call", "tool_call": "fabric.tool_call",
    "delegation": "fabric.delegation",
}  # fmt: skip
# An explicit result as the three R4 status inputs of the ``end`` record (§3.10).
END_STATUS: Mapping[str, tuple[Lifecycle, ResultStatus, OtlpStatus]] = {
    "ok": ("completed", "ok", "unset"),
    "error": ("completed", "error", "error"),
    "cancelled": ("cancelled", "cancelled", "unset"),
    "deferred": ("deferred", "unknown", "unset"),
}
CALL_POINTS: frozenset[str] = frozenset({"explicit.call_recorder", "explicit.final_http"})
# The manifest reason of a point disabled by a byte-config conflict. ``config_conflict`` is
# not in the capture-manifest-v1 point-reason enum (contracts/capture/v1, WP-00), so the
# admitted reason closest to it is used until the registry adds it (one-line change).
CONFLICT_POINT_REASON = "privacy_policy"
_LOG = logging.getLogger("fabric.explicit")
_LEGACY = threading.Lock()
_LEGACY_WARNED: list[bool] = []
_CONFLICT_WARNED: list[bool] = []
# Per install: the points a conflicting producer disabled (another producer's ``active``
# report does not override them).
_DISABLED_POINTS: weakref.WeakKeyDictionary[RecordsInput, set[str]] = weakref.WeakKeyDictionary()
_MEDIA_PREFERENCE = ("application/octet-stream", "application/json", "text/plain")


def _warn_legacy() -> None:
    """One ``DeprecationWarning`` per process for the unsequenced legacy journal."""
    with _LEGACY:
        if _LEGACY_WARNED:
            return
        _LEGACY_WARNED.append(True)
    warnings.warn(
        "fabric: an explicit recorder without a source_spool or an installed wire handle "
        "keeps the unsequenced legacy journal; install fabric.wire (records mode) or pass "
        "a source_spool (journal mode)",
        DeprecationWarning,
        stacklevel=4,
    )


def installed_records() -> RecordsInput | None:
    """The records input of the installed wire handle while it captures (§3.1), else
    ``None``."""
    from . import wire  # noqa: PLC0415 - wire imports the explicit line's modules
    from ._records import records_input  # noqa: PLC0415

    records = records_input(wire.current_handle())
    return records if records is not None and records.active else None


def resolve_mode(mode: object, *, journal: bool) -> ResolvedMode:
    """The §3.10 table: ``auto`` is ``journal`` when a ``source_spool`` was given, else
    ``records`` when a wire handle is installed, else ``legacy``. A mode that contradicts
    the arguments is configuration and raises ``ValueError``."""
    if not isinstance(mode, str) or mode not in PRODUCER_MODES:
        raise ValueError("mode must be auto, records, journal or legacy")
    if mode == "auto":
        mode = "journal" if journal else "records" if installed_records() is not None else "legacy"
    if mode == "journal" and not journal:
        raise ValueError("journal mode requires a source_spool")
    if mode != "journal" and journal:
        raise ValueError("a source_spool is used only in journal mode")
    if mode == "legacy":
        _warn_legacy()
    return mode  # type: ignore[return-value]


def admitted_boundary(role: str, boundary: str) -> str:
    """``boundary`` when the role table admits it for ``role``, else the role's first
    admitted boundary (a record body is placed where the Node admits it)."""
    row = ROLES.get(role)
    return boundary if row is None or boundary in row.boundary else row.boundary[0]


def admitted_media(role: str, media_type: str | None = None) -> str:
    """``media_type`` when the role table admits it for ``role``, else the role's
    preferred admitted type (octet-stream, JSON, plain text, then the first listed)."""
    row = ROLES.get(role)
    if row is None:
        return media_type or "application/octet-stream"
    if media_type is not None and row.admits_media(media_type):
        return media_type
    for preferred in _MEDIA_PREFERENCE:
        if row.admits_media(preferred):
            return preferred
    return row.media_types[0]


def _max_object_bytes() -> int:
    try:
        return records_max_object_bytes(os.environ)
    except ValueError:  # refused at install; the default bounds the producer meanwhile
        return DEFAULT_MAX_OBJECT_BYTES


BodyView = tuple[AnyBody | None, str, str | None]


def _warn_conflict(roles: tuple[str, ...]) -> None:
    """One warning per process for a byte config that disagrees with the capture policy:
    the role names only (a fixed vocabulary), never a value."""
    with _LEGACY:
        if _CONFLICT_WARNED:
            return
        _CONFLICT_WARNED.append(True)
    _LOG.warning(
        "fabric: explicit producer records disabled: byte evidence role policies disagree "
        "with the capture policy for: %s",
        ", ".join(roles) if roles else "(unverifiable configuration)",
    )


def _report_point(records: RecordsInput, point: str, state: str, reason: str | None) -> None:
    if (handle := records.handle) is not None:
        from . import _manifest  # noqa: PLC0415

        _manifest.capture_point_changed(handle, point, state, reason)  # type: ignore[arg-type]


class RecordsProducer:
    """Records-mode plumbing of one explicit producer (§3.10): the records input in force,
    the capture point it reports ``active`` on that install's manifest (once per install
    and point), bodies built on the application thread without a copy, and the emit.

    A producer whose byte config conflicts with the install's capture policy is
    ``disabled`` (:attr:`conflict`): it emits nothing on the records input (never bodies
    under a policy other than the install's) and reports its points ``disabled`` on the
    manifest; no other producer's ``active`` report overrides that for the install."""

    def __init__(self) -> None:
        self.max_object_bytes = _max_object_bytes()
        self._points: dict[str, weakref.ref[RecordsInput]] = {}
        self._last: weakref.ref[RecordsInput] | None = None
        self.conflict: tuple[str, ...] | None = None  # the conflicting roles, when disabled

    def records(self, point: str) -> RecordsInput | None:
        """The active records input, after reporting ``point`` on its manifest: ``active``,
        or ``disabled`` (and ``None``: nothing is emitted) for a conflicting producer."""
        records = installed_records()
        if records is None:
            return None
        if self.conflict is None:
            self._last = weakref.ref(records)
        seen = self._points.get(point)
        if seen is None or seen() is not records:
            self._points[point] = weakref.ref(records)
            with _LEGACY:
                disabled = _DISABLED_POINTS.setdefault(records, set())
                if self.conflict is not None:
                    disabled.add(point)
                report = self.conflict is not None or point not in disabled
            if report:
                if self.conflict is not None:
                    _report_point(records, point, "disabled", CONFLICT_POINT_REASON)
                else:
                    _report_point(records, point, "active", None)
        return None if self.conflict is not None else records

    def check_config(self, recorder: ByteEvidenceRecorder, point: str | None = None) -> None:
        """§3.10 "Bytes": the byte writer's role policies must agree with the capture
        policy of the install, which governs the records' bodies. A conflict raises
        ``ValueError`` only under ``FABRIC_RECORDS_STRICT=1``; otherwise it never stops the
        application (R9, 049 §7.1; the capture policy may come from the environment): the
        producer is disabled (:attr:`conflict`), one warning per process names the roles,
        and ``point`` (when known) is reported ``disabled`` now."""
        records = installed_records()
        gate = getattr(getattr(records, "handle", None), "gate", None)
        policy = getattr(gate, "policy", None)
        if policy is None:
            return
        try:
            conflicts = tuple(recorder.capture_policy_conflicts(policy.mode))
        except Exception:
            if strict():
                raise
            conflicts = ()  # an unverifiable config is disabled too, never written
        else:
            if not conflicts:
                return
            if strict():
                recorder.check_capture_policy(policy.mode)
        self.conflict = conflicts
        _warn_conflict(conflicts)
        if point is not None:
            with suppress(Exception):
                self.records(point)

    def status(self) -> dict[str, Any]:
        """This producer's records-mode health: ``active``, or ``partial`` with the reason
        ``config_conflict`` and the conflicting role names (never a value)."""
        if self.conflict is None:
            return {"capture": "active", "capture_reason": None, "conflicting_roles": []}
        return {"capture": "partial", "capture_reason": "config_conflict",
                "conflicting_roles": list(self.conflict)}  # fmt: skip

    def source(self, records: RecordsInput | None) -> tuple[str | None, int | None]:
        """The process source and its current epoch (in-memory view only)."""
        handle = records.handle if records is not None else None
        if handle is None or not handle.capturing:
            return None, None
        allocator = handle.allocator
        return allocator.source_id, allocator.epoch

    def body(
        self, records: RecordsInput, value: object, *, role: str, boundary: str,
        media_type: str | None = None, stream_id: str | None = None,
        chunk_index: int | None = None,
    ) -> BodyView:  # fmt: skip
        """One body as the records input takes it, with its in-memory status: none at all
        under ``omit`` (§3.4 ``mode_of``: no encoding, no copy); a non-bytes value
        ``unsupported(not_exact_bytes)``; over the cap, measured by ``len()`` without a
        copy, ``not_captured(payload_too_large)``; else the bytes by reference."""
        if records.mode_of(role) == "omit":
            return None, "not_captured", "privacy_policy"
        boundary = admitted_boundary(role, boundary)
        media = admitted_media(role, media_type)
        if not isinstance(value, bytes):
            return (DescriptorOnlyBody(role, media, boundary, "unsupported", "not_exact_bytes"),
                    "unsupported", "not_exact_bytes")  # fmt: skip
        size = len(value)
        if size > self.max_object_bytes:
            return (DescriptorOnlyBody(role, media, boundary, "not_captured", "payload_too_large",
                                       observed_byte_length=size),
                    "not_captured", "payload_too_large")  # fmt: skip
        data = value if type(value) is bytes else bytes(value)
        return (RecordBody(role, data, media, boundary, stream_id=stream_id,
                           chunk_index=chunk_index), "pending", None)  # fmt: skip

    def emit(
        self, attempt: Attempt, phase: Phase, *, name_hint: str, attributes: Mapping[str, str],
        start_ns: int, end_ns: int, event_id: str, bodies: tuple[AnyBody, ...] = (),
        status: tuple[Lifecycle, ResultStatus, OtlpStatus] | None = None,
        span: trace.Span | None = None,
    ) -> bool:  # fmt: skip
        """One record; ``False`` when it was not emitted (a loss Fabric already counts, or
        an inactive input). ``span``: the host span the record is a child of. Never raises
        into the application except under ``FABRIC_RECORDS_STRICT=1``."""
        token = None
        try:
            if span is not None:
                token = otel_context.attach(trace.set_span_in_context(span))
            if status is None:
                return attempt.emit(
                    phase, name_hint=name_hint, attributes=attributes, start_ns=start_ns,
                    end_ns=end_ns, bodies=bodies, event_id=event_id,
                ) is True  # fmt: skip
            lifecycle, result, otlp = status
            return attempt.emit(
                phase, name_hint=name_hint, attributes=attributes, start_ns=start_ns,
                end_ns=end_ns, lifecycle=lifecycle, result_status=result, otlp_status=otlp,
                bodies=bodies, event_id=event_id,
            ) is True  # fmt: skip
        except Exception:
            if strict():
                raise
            return False
        finally:
            if token is not None:
                with suppress(Exception):
                    otel_context.detach(token)

    def flush(self, timeout_s: float) -> bool:
        """``handle.flush()`` of the install the records went to (§3.10 "Snapshots");
        ``False`` once that install is no longer the capturing one."""
        last = self._last() if self._last is not None else None
        if last is None or last is not installed_records() or last.handle is None:
            return False
        try:
            return last.handle.flush(timeout_s)
        except Exception:
            return False


def event_order(event: Mapping[str, Any]) -> int:
    """Snapshot order: the in-process sequence, or a record's ordinal (one counter)."""
    sequence = event.get("source_sequence")
    return int(sequence) if sequence is not None else int(event.get("record_ordinal", 0))


def dashed(record_id: str) -> str:
    """A ``uuid4().hex`` record id as the record's ``fabric.event_id`` (dashed)."""
    return str(uuid.UUID(hex=record_id))


@dataclass
class _Call:
    fields: dict[str, Any]
    span: trace.Span | None
    retained: bool
    ended: bool = False
    # This call's explicit scope (fabric._capture_scope), shared by all its activations and
    # ended with the call: a context copied inside it stops deferring wire capture then.
    capture_scope: ExplicitScope | None = None
    # Records mode (spec 050 §3.10): the call's attempt on the records input (``None``
    # while the input is not active: its events are counted gaps) and its start time.
    records: bool = False
    attempt: Attempt | None = None
    start_ns: int = 0
    step_ids: tuple[str, str] | None = None  # (operation, attempt) as given, for the input


class CallRecorder:
    """One recorder for a custom agent's explicit model/tool dispatch points.

    ``call`` and ``acall`` preserve the delegate's result/exception. ``stream``
    and ``astream`` return pull-through iterators: they never prefetch. Close
    these wrappers explicitly on early exit (``close``/``aclose`` or context
    managers). Unclosed streams remain running and cannot count as complete.
    Context-local parents propagate to asyncio tasks; threads/processes need
    an explicit ``parent_call_id``. Instances do not install global hooks.

    ``mode`` (spec 050 §3.10): ``auto`` (the default), ``journal``, ``records`` or
    ``legacy``; see the module docstring. In records mode ``call_id`` is the attempt's
    dashed uid (``fabric.attempt.uid``), ``operation_id`` and ``attempt_id`` are emitted
    mapped (``fabric.step.id``, ``fabric.step.attempt_id``; the call id when not given),
    and ``source_id``/``source_epoch`` are the process source's. ``seal_source()`` is
    refused (``records_mode``): sealing belongs to qualified-run mode.

    A contradictory ``mode`` argument (journal without a ``source_spool``, an unknown
    mode) raises ``ValueError``: a deterministic coding error seen on the first run. A
    byte config that disagrees with the install's capture policy, which may come from the
    environment, never stops the application: it disables this recorder's records
    (``status()`` ``partial``/``config_conflict``) and raises only under
    ``FABRIC_RECORDS_STRICT=1``.
    """

    def __init__(
        self,
        recorder: ByteEvidenceRecorder,
        *,
        run_id: str,
        agent_id: str,
        source_id: str,
        max_events: int = 4096,
        tracer: trace.Tracer | None = None,
        source_spool: SyntheticSourceSpool | None = None,
        recovery_resolver: ByteEvidenceResolver | None = None,
        mode: ProducerMode = "auto",
    ) -> None:
        self.run_id = _identifier(run_id)
        self.agent_id = _identifier(agent_id)
        self.source_id = _identifier(source_id)
        if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events < 1:
            raise ValueError("max_events must be a positive integer")
        self.mode: ResolvedMode = resolve_mode(mode, journal=source_spool is not None)
        self._producer = RecordsProducer() if self.mode == "records" else None
        if self._producer is not None:
            self._producer.check_config(recorder, "explicit.call_recorder")
        self.recorder = recorder
        self.tenant_id = recorder.tenant_id
        # 049 §2.9: every caller id is emitted as the recorder emits it (keyed pseudonyms,
        # or generated ids in production without the id key). A source spool journals the
        # emitted ids, so it is keyed by the emitted run id (``recorder.emitted_run_id``);
        # generated run ids do not survive a restart, so then the spool is unused.
        self._ids = recorder.emitted_ids
        if self._ids is not None:
            self.run_id = self._ids.run(self.run_id, 0)
            self.source_id = self._ids.source(self.source_id)
            self.agent_id = self._ids.agent(self.agent_id)
            if isinstance(self._ids, GeneratedIds):
                source_spool = recovery_resolver = None
        if source_spool is not None and (
            source_spool.tenant_id != self.tenant_id or source_spool.run_id != self.run_id
        ):
            raise ValueError("source spool tenant/run does not match recorder")
        if recovery_resolver is not None and recovery_resolver.tenant_id != self.tenant_id:
            raise ValueError("recovery resolver tenant does not match recorder")
        self.source_spool = source_spool
        self.source_epoch = source_spool.epoch if source_spool is not None else 0
        if self._producer is not None:  # §3.10: the process source of the records input
            source, epoch = self._producer.source(installed_records())
            if source is not None and epoch is not None:
                self.source_id, self.source_epoch = source, epoch
        self._recovery_resolver = recovery_resolver
        self.max_events = max_events
        self._tracer = tracer if tracer is not None else get_tracer()
        self._current: ContextVar[_Call | None] = ContextVar("fabric_call", default=None)
        self._lock = threading.Lock()
        self._sequence = 0
        self._gaps = 0
        self._events: list[dict[str, Any]] = []
        self._operations: list[dict[str, Any]] = []
        self._calls: list[dict[str, Any]] = []
        self._starts: list[dict[str, Any]] = []

    @property
    def current_call_id(self) -> str | None:
        active = self._current.get()
        return active.fields["call_id"] if active else None

    def _base(self, call: _Call) -> dict[str, Any]:
        with self._lock:
            sequence = self._sequence
            self._sequence += 1
        if call.records:
            # The shared allocator assigns the record's position on emit; the in-memory
            # view keeps only this recorder's order (record_ordinal).
            records = call.attempt.records if call.attempt is not None else None
            source, epoch = self._producer.source(records) if self._producer else (None, None)
            return {
                **{
                    key: call.fields[key]
                    for key in (
                        "call_id",
                        "parent_call_id",
                        "agent_id",
                        "operation_id",
                        "attempt_id",
                        "boundary",
                        "kind",
                    )
                },
                "record_id": uuid.uuid4().hex,
                "tenant_id": self.tenant_id,
                "run_id": self.run_id,
                "source_id": source if source is not None else self.source_id,
                "source_epoch": epoch if epoch is not None else self.source_epoch,
                "source_sequence": None,
                "record_ordinal": sequence,
                "observed_at": _now(),
            }
        return {
            **{
                key: call.fields[key]
                for key in (
                    "call_id",
                    "parent_call_id",
                    "agent_id",
                    "operation_id",
                    "attempt_id",
                    "boundary",
                    "kind",
                )
            },
            "record_id": uuid.uuid4().hex,
            "tenant_id": self.tenant_id,
            "run_id": self.run_id,
            "source_id": self.source_id,
            "source_epoch": self.source_epoch,
            "source_sequence": sequence,
            "observed_at": _now(),
        }

    def _append(self, target: list[dict[str, Any]], item: dict[str, Any]) -> bool:
        with self._lock:
            if len(target) >= self.max_events:
                self._gaps += 1
                return False
            target.append(item)
            return True

    def _fault(self) -> None:
        with self._lock:
            self._gaps += 1

    def _journal(self, event: dict[str, Any]) -> None:
        if self.source_spool is None:
            return
        # Only closed scalar metadata is submitted. Opaque object joins and
        # policy bindings survive restart; content refs/bytes and
        # exception strings never enter the journal. Outcome has its own
        # closed validator in SyntheticSourceSpool.
        fields = {
            "record_id",
            "tenant_id",
            "run_id",
            "source_id",
            "source_epoch",
            "source_sequence",
            "operation_id",
            "attempt_id",
            "boundary",
            "role",
            "object_id",
            "status",
            "status_reason",
            "observed_at",
            "outcome",
            "call_id",
            "parent_call_id",
            "agent_id",
            "kind",
            "streaming",
            "stream_id",
            "chunk_index",
        } | CONTENT_JOIN_FIELDS
        try:
            status = self.source_spool.append(
                {key: value for key, value in event.items() if key in fields}
            )
            if status in {"failed", "dropped"}:
                self._fault()
        except Exception:
            self._fault()
            with self._lock:
                event["source_spool_submission_failed"] = True

    def _start(  # noqa: PLR0912 - the three modes' ids in one place
        self,
        payload: object,
        *,
        kind: str = "tool",
        operation_id: str | None = None,
        attempt_id: str | None = None,
        context: bytes | None = None,
        agent_id: str | None = None,
        parent_call_id: str | None = None,
        streaming: bool = False,
        _point: str = "explicit.call_recorder",
    ) -> _Call:
        if kind not in _KINDS:
            raise ValueError("kind must be model, tool, database or agent")
        if _point not in CALL_POINTS:
            raise ValueError("unknown explicit capture point")
        boundary, input_role, output_role = _KINDS[kind]
        parent = self._current.get()
        call_id = uuid.uuid4().hex
        attempt = self._begin(kind, _point, parent, parent_call_id)
        step_ids: tuple[str, str] | None = None
        if attempt is not None:  # 050 §3.10 ids: the records input's identity rule (R8)
            records = attempt.records
            call_id = attempt.uid
            if parent_call_id is not None:
                parent_call_id = records.map_id(_identifier(parent_call_id))
            if agent_id is not None and (ids := self._ids) is not None:
                agent_id = ids.agent(_identifier(agent_id))
            # The records input maps the caller's ids itself (once); unnamed, they are the
            # attempt uid, which it passes through. The view keeps the emitted forms.
            step_ids = (
                _identifier(operation_id) if operation_id is not None else attempt.uid,
                _identifier(attempt_id) if attempt_id is not None else attempt.uid,
            )
            operation_id, attempt_id = (
                records.map_id(value) if value is not attempt.uid else value for value in step_ids
            )
        elif (ids := self._ids) is not None:  # 049 §2.9: emitted, never the caller's clear id
            # Fabric's own ids map to themselves (a parent call id of this recorder too).
            call_id = ids.mint(call_id)
            if parent_call_id is not None:
                parent_call_id = ids.other(_identifier(parent_call_id))
            if agent_id is not None:
                agent_id = ids.agent(_identifier(agent_id))
            operation_id, attempt_id = (
                ids.other(_identifier(value)) if value is not None else ids.mint(uuid.uuid4().hex)
                for value in (operation_id, attempt_id)
            )
        fields = {
            "call_id": call_id,
            "parent_call_id": _identifier(parent_call_id)
            if parent_call_id is not None
            else parent.fields["call_id"]
            if parent
            else None,
            "agent_id": _identifier(agent_id)
            if agent_id is not None
            else parent.fields["agent_id"]
            if parent
            else self.agent_id,
            "operation_id": _identifier(operation_id)
            if operation_id is not None
            else uuid.uuid4().hex,
            "attempt_id": _identifier(attempt_id) if attempt_id is not None else uuid.uuid4().hex,
            "kind": kind,
            "boundary": boundary,
            "input_role": input_role,
            "output_role": output_role,
            "status": "running",
            "started_at": _now(),
            "streaming": streaming,
            "chunk_count": 0,
            "context_present": context is not None,
        }
        span = None
        try:
            span = self._tracer.start_span("fabric.call." + kind)
            correlation = span.get_span_context()
            if correlation.is_valid:
                fields["trace_id"] = format(correlation.trace_id, "032x")
                fields["span_id"] = format(correlation.span_id, "016x")
        except Exception:
            self._fault()
        call = _Call(
            fields,
            span,
            self._append(self._calls, fields),
            capture_scope=ExplicitScope(kind == "model"),
        )
        if self.mode == "records":
            call.records, call.attempt, call.start_ns = True, attempt, time.time_ns()
            call.step_ids = step_ids
        start = self._base(call)
        start.update(role="operation.start", status="recorded", streaming=streaming)
        self._append(self._starts, start)
        if call.records:  # §3.10: operation.start is the start record, with the input body
            self._record_start(call, start, payload)
        else:
            self._journal(start)
            self._capture(call, payload, role=input_role)
        if context is not None:
            self._capture(call, context, role="interaction.payload")
        return call

    def _begin(
        self, kind: str, point: str, parent: _Call | None, parent_call_id: str | None
    ) -> Attempt | None:
        """Records mode: the call's attempt on the records input (``None`` while the input
        is not active). Its parent is the given ``parent_call_id`` (mapped unless it is an
        attempt uid of this input) or the enclosing call's attempt uid."""
        if self._producer is None:
            return None
        try:
            records = self._producer.records(point)
            if records is None:
                return None
            parent_ref = (  # mapped by begin(), once
                _identifier(parent_call_id) if parent_call_id is not None
                else parent.fields["call_id"] if parent is not None else None
            )  # fmt: skip
            return records.begin(STEP_KIND[kind], point, parent_attempt=parent_ref)
        except ValueError:
            if parent_call_id is not None and not _ID.fullmatch(str(parent_call_id)):
                raise  # a malformed caller id is refused exactly as in the other modes
            if strict():
                raise
            return None
        except Exception:
            if strict():
                raise
            return None

    def _unemitted_reason(self) -> str:
        """Why a records-mode event has no record: the producer is disabled by a byte
        config conflict, or the record was not emitted (inactive input, a counted loss)."""
        producer = self._producer
        return "config_conflict" if producer and producer.conflict is not None else (
            "record_not_emitted")  # fmt: skip

    def status(self) -> dict[str, Any]:
        """This recorder's mode and records-mode capture health (spec 050 §3.10):
        ``capture`` is ``active``, or ``partial`` with ``capture_reason``
        ``config_conflict`` and the conflicting role names while a byte config that
        disagrees with the install's capture policy disables its records."""
        producer = self._producer
        if producer is None:
            return {"mode": self.mode, "capture": None, "capture_reason": None,
                    "conflicting_roles": []}  # fmt: skip
        return {"mode": self.mode, **producer.status()}

    def _emit(
        self, call: _Call, phase: Phase, record_id: str, bodies: tuple[AnyBody, ...] = (),
        status: tuple[Lifecycle, ResultStatus, OtlpStatus] | None = None,
    ) -> bool:  # fmt: skip
        """One record of ``call``'s attempt (§3.10); a record not emitted is a counted
        recording gap of this view."""
        attempt, producer, step_ids = call.attempt, self._producer, call.step_ids
        emitted = False
        if attempt is not None and producer is not None and step_ids is not None:
            now = time.time_ns()
            emitted = producer.emit(
                attempt, phase, name_hint=NAME_HINT.get(attempt.kind, "fabric.activity"),
                attributes={"fabric.step.id": step_ids[0], "fabric.step.attempt_id": step_ids[1]},
                start_ns=call.start_ns if phase == "end" else now, end_ns=now,
                event_id=dashed(record_id), bodies=bodies, status=status, span=call.span,
            )  # fmt: skip
        if not emitted:
            self._fault()
        return emitted

    def _record_body(
        self, call: _Call, event: dict[str, Any], value: object, *, role: str,
        boundary: str, chunk_index: int | None = None,
    ) -> tuple[AnyBody, ...]:  # fmt: skip
        """``value`` as a record body, its in-memory status set on ``event``."""
        attempt, producer = call.attempt, self._producer
        if attempt is None or producer is None:
            event.update(status="failed", status_reason=self._unemitted_reason())
            return ()
        stream = call.fields["call_id"] if chunk_index is not None else None
        body, status, reason = producer.body(
            attempt.records, value, role=role, boundary=boundary, stream_id=stream,
            chunk_index=chunk_index,
        )  # fmt: skip
        event.update(boundary=admitted_boundary(role, boundary), status=status)
        if reason is not None:
            event["status_reason"] = reason
        return (body,) if body is not None else ()

    def _record_start(self, call: _Call, start: dict[str, Any], payload: object) -> None:
        """The ``start`` record: ``operation.start`` with the input body. The view keeps
        the input body as an event row carrying the start record's id."""
        try:
            role = call.fields["input_role"]
            event = {**start, "role": role}
            event.pop("streaming", None)
            event.pop("status", None)
            bodies = self._record_body(call, event, payload, role=role,
                                       boundary=call.fields["boundary"])  # fmt: skip
            self._append(self._events, event)
            if not self._emit(call, "start", start["record_id"], bodies):
                with self._lock:
                    start.update(status="failed", status_reason=self._unemitted_reason())
                    if event["status"] != "failed":
                        event.update(status="failed", status_reason=self._unemitted_reason())
        except Exception:
            if strict():
                raise
            self._fault()

    def _record_capture(
        self, call: _Call, value: object, *, role: str, boundary: str | None,
        chunk_index: int | None,
    ) -> None:  # fmt: skip
        """A ``data`` record (``update`` once the call ended) with one body (§3.10)."""
        try:
            event = self._base(call)
            event.update(role=role)
            if chunk_index is not None:
                event.update(stream_id=call.fields["call_id"], chunk_index=chunk_index)
            bodies = self._record_body(call, event, value, role=role,
                                       boundary=boundary or event["boundary"],
                                       chunk_index=chunk_index)  # fmt: skip
            self._append(self._events, event)
            phase: Phase = "update" if call.ended else "data"
            if not self._emit(call, phase, event["record_id"], bodies):
                with self._lock:
                    if event["status"] != "failed":
                        event.update(status="failed", status_reason=self._unemitted_reason())
        except Exception:
            if strict():
                raise
            self._fault()

    @contextmanager
    def _activate(self, call: _Call) -> Iterator[None]:
        token = self._current.set(call)
        # Disable exception recording: exception messages can contain data.
        # The call's explicit scope (fabric._capture_scope) only tells an installed
        # wire tee to defer to this record while the call runs; it changes nothing here.
        try:
            with explicit_model_call(scope=call.capture_scope):
                if call.span is None:
                    yield
                else:
                    with trace.use_span(
                        call.span,
                        end_on_exit=False,
                        record_exception=False,
                        set_status_on_exception=False,
                    ):
                        yield
        finally:
            self._current.reset(token)

    def _capture(
        self,
        call: _Call,
        value: object,
        *,
        role: str,
        boundary: str | None = None,
        chunk_index: int | None = None,
    ) -> None:
        if call.records:
            self._record_capture(call, value, role=role, boundary=boundary,
                                 chunk_index=chunk_index)  # fmt: skip
            return
        try:
            event = self._base(call)
            event.update(role=role)
            if boundary is not None:
                event["boundary"] = boundary
            if chunk_index is not None:
                event.update(stream_id=call.fields["call_id"], chunk_index=chunk_index)
            # Reserve bounded metadata before handing off bytes.
            event["status"] = "pending"
            if not self._append(self._events, event):
                return
            if not isinstance(value, bytes):
                with self._lock:
                    event.update(status="unsupported", status_reason="not_exact_bytes")
                self._journal(event)
                return
            try:
                descriptor = self.recorder.capture(
                    value,
                    role=role,
                    boundary=event["boundary"],
                    source_id=self.source_id,
                    source_epoch=self.source_epoch,
                    source_sequence=event["source_sequence"],
                    run_id=self.run_id,
                    operation_id=call.fields["operation_id"],
                    attempt_id=call.fields["attempt_id"],
                    stream_id=call.fields["call_id"] if chunk_index is not None else None,
                    chunk_index=chunk_index,
                )
                with self._lock:
                    event.update(
                        object_id=descriptor["object_id"],
                        status=descriptor["status"],
                        **capture_content_binding(descriptor),
                    )
            except Exception:
                with self._lock:
                    event.update(status="failed", status_reason="recorder_exception")
            self._journal(event)
        except Exception:
            self._fault()

    def record_data(self, data: bytes, *, role: str, boundary: str | None = None) -> None:
        """Attach caller-observed file/terminal/DB bytes to the active call.

        Missing active context becomes a counted evidence gap. This does not
        independently observe or confirm the external effect.
        """
        call = self._current.get()
        if call is None:
            self._fault()
            return
        self._capture(call, data, role=role, boundary=boundary)

    def _end(self, call: _Call, status: str, *, collected: bool = False) -> None:
        """``collected``: the stream wrapper was garbage-collected unclosed. In records
        mode no record is emitted from a finalizer (it could run while this thread holds
        the allocator lock): the abandoned attempt stays without an ``end``."""
        if call.ended:
            return
        call.ended = True
        if call.capture_scope is not None:
            call.capture_scope.end()
        try:
            event = self._base(call)
            result = "deferred" if status == "partial" else status
            event.update(
                role="operation.outcome",
                status="recorded",
                outcome={"result_status": result},
                result_status=result,
            )
            self._append(self._operations, event)
            if call.records and collected:
                event.update(status="failed", status_reason="abandoned_unclosed")
            elif call.records:  # §3.10: the end record, with the three R4 status inputs
                if not self._emit(call, "end", event["record_id"], status=END_STATUS[result]):
                    with self._lock:
                        event.update(status="failed", status_reason=self._unemitted_reason())
            else:
                self._journal(event)
            # A snapshot must not see terminal status before the terminal
            # observation has been admitted (or a recording gap counted).
            with self._lock:
                call.fields.update(status=status, ended_at=_now())
            if call.span is not None:
                call.span.set_attribute("fabric.call.outcome", status)
                call.span.end()
        except Exception:
            self._fault()

    @staticmethod
    def _failure(exc: BaseException) -> str:
        return (
            "cancelled" if isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt)) else "error"
        )

    def call(self, payload: bytes, delegate: Callable[[bytes], _T], **options: Any) -> _T:
        call = self._start(payload, **options)
        try:
            with self._activate(call):
                result = delegate(payload)
        except BaseException as exc:
            self._end(call, self._failure(exc))
            raise
        self._capture(call, result, role=call.fields["output_role"])
        deferred = inspect.isawaitable(result) or isinstance(result, (Iterator, AsyncIterator))
        self._end(call, "partial" if deferred else "ok")
        return result

    async def acall(
        self, payload: bytes, delegate: Callable[[bytes], Awaitable[_T]], **options: Any
    ) -> _T:
        call = self._start(payload, **options)
        try:
            with self._activate(call):
                result = await delegate(payload)
        except BaseException as exc:
            self._end(call, self._failure(exc))
            raise
        self._capture(call, result, role=call.fields["output_role"])
        deferred = inspect.isawaitable(result) or isinstance(result, (Iterator, AsyncIterator))
        self._end(call, "partial" if deferred else "ok")
        return result

    def stream(
        self, payload: bytes, delegate: Callable[[bytes], Iterator[_T]], **options: Any
    ) -> RecordedStream[_T]:
        call = self._start(payload, streaming=True, **options)
        try:
            with self._activate(call):
                iterator = iter(delegate(payload))
        except BaseException as exc:
            self._end(call, self._failure(exc))
            raise
        return RecordedStream(self, call, iterator)

    def astream(
        self, payload: bytes, delegate: Callable[[bytes], AsyncIterator[_T]], **options: Any
    ) -> RecordedAsyncStream[_T]:
        call = self._start(payload, streaming=True, **options)
        try:
            with self._activate(call):
                iterator = aiter(delegate(payload))
        except BaseException as exc:
            self._end(call, self._failure(exc))
            raise
        return RecordedAsyncStream(self, call, iterator)

    def _records_snapshot(self, settle_timeout_s: float) -> dict[str, Any]:
        """Records mode (§3.10 "Snapshots"): an in-memory view. ``writer_settled`` is the
        install's ``handle.flush()``; body statuses are ``pending`` until then and
        ``settled`` after it (the worker protected and wrote them; each body's content
        descriptor is in the delivered record, for ``fabric.reconstruct``). Positions are
        assigned by the shared allocator: the view has this recorder's order only."""
        settled = self._producer.flush(settle_timeout_s) if self._producer else False
        with self._lock:
            events = copy.deepcopy(self._events)
            calls = copy.deepcopy(self._calls)
            operations = copy.deepcopy(self._operations)
            starts = copy.deepcopy(self._starts)
            gaps = self._gaps
        if settled:
            for event in events:
                if event.get("status") == "pending":
                    event["status"] = "settled"
        return {
            "schema_version": "fabric.call-recording/v1",
            "capture_mode": "records",
            "capture_health": self.status()["capture"],
            "capture_reason": self.status()["capture_reason"],
            "tenant_id": self.tenant_id,
            "run_id": self.run_id,
            "source_id": self.source_id,
            "source_epoch": self.source_epoch,
            "source_epoch_persisted": False,
            "source_identity_authenticated": False,
            "producer_closure": "unknown",
            "all_observed_calls_finished": bool(calls)
            and all(call["status"] in {"ok", "error", "cancelled"} for call in calls),
            "source_high_water": {},
            "source_high_water_basis": "records_input",
            "source_metadata_seal": None,
            "source_unsealed_epoch_ranges": [],
            "writer_settled": settled,
            "source_spool_settled": False,
            "source_spool_recovered_gaps": [],
            "source_spool_health": None,
            "recovered_records": [],
            "recovery_history_unverified": False,
            "pre_spool_crash_window_unverified": True,
            "unretained_drops": 0,
            "recording_gaps": gaps,
            "calls": calls,
            "starts": sorted(starts, key=event_order),
            "events": sorted(events, key=event_order),
            "operations": sorted(operations, key=event_order),
        }

    def snapshot(self, *, settle_timeout_s: float = 10.0) -> dict[str, Any]:
        """Offline local snapshot; no authenticated completeness claim."""
        if self.mode == "records":
            return self._records_snapshot(settle_timeout_s)
        settled = self.recorder.flush(settle_timeout_s)
        spool_settled = self.source_spool.flush(settle_timeout_s) if self.source_spool else False
        with self._lock:
            events = copy.deepcopy(self._events)
            calls = copy.deepcopy(self._calls)
            operations = copy.deepcopy(self._operations)
            starts = copy.deepcopy(self._starts)
            high_water = self._sequence - 1
            gaps = self._gaps
        for event in events:
            if "object_id" not in event:
                continue
            descriptor = self.recorder.get(event["object_id"])
            if descriptor is None:
                event.update(status="failed", status_reason="descriptor_not_retained")
            else:
                event.update(status=descriptor["status"], descriptor=descriptor)
                derivatives = getattr(self.recorder, "derivatives", None)
                if derivatives is not None:
                    event["derivatives"] = derivatives(event["object_id"])
        if self.source_spool is not None:
            for event in [*starts, *events, *operations]:
                event["source_spool_status"] = self.source_spool.status(event["record_id"])
        return {
            "schema_version": "fabric.call-recording/v1",
            "tenant_id": self.tenant_id,
            "run_id": self.run_id,
            "source_epoch": self.source_epoch,
            "source_epoch_persisted": self.source_spool is not None,
            "source_identity_authenticated": False,
            # A terminal wrapped call cannot enumerate work a delegate may
            # schedule later, including inherited-context tasks and threads.
            "producer_closure": "unknown",
            "all_observed_calls_finished": bool(calls)
            and all(call["status"] in {"ok", "error", "cancelled"} for call in calls),
            "source_high_water": {self.source_id: high_water},
            "source_high_water_basis": "assigned_in_process",
            "source_metadata_seal": self.source_spool.current_seal() if self.source_spool else None,
            "source_unsealed_epoch_ranges": self.source_spool.unsealed_epoch_ranges()
            if self.source_spool
            else [],
            "writer_settled": settled,
            "source_spool_settled": spool_settled,
            "source_spool_recovered_gaps": self.source_spool.recovered_gaps()
            if self.source_spool
            else [],
            "source_spool_health": self.source_spool.health() if self.source_spool else None,
            "recovered_records": self._recovered_records(),
            "recovery_history_unverified": bool(self.source_spool and self.source_spool.epoch > 0),
            "pre_spool_crash_window_unverified": True,
            "unretained_drops": self.recorder.unretained_drops,
            "recording_gaps": gaps,
            "calls": calls,
            "starts": sorted(starts, key=lambda event: event["source_sequence"]),
            "events": sorted(events, key=lambda event: event["source_sequence"]),
            "operations": sorted(operations, key=lambda event: event["source_sequence"]),
        }

    def seal_source(self, *, timeout_s: float = 10.0) -> dict[str, Any]:
        """Finalize metadata persistence after work, never assert run completeness.

        This explicit offline operation may wait for storage. It must not run
        on the delegate's execution path. New calls still execute after sealing,
        but their refused journal writes become evidence gaps; start a new epoch
        for further recorded work. The seal is neither content durability nor
        authenticated proof of all activity and does not change any verdict.
        """
        if self.mode == "records":  # spec 050 §3.10: sealing belongs to qualified-run mode
            return {"status": "refused", "reason": "records_mode"}
        if self.source_spool is None:
            return {"status": "refused", "reason": "source_spool_unavailable"}
        if (
            isinstance(timeout_s, bool)
            or not isinstance(timeout_s, (int, float))
            or not math.isfinite(timeout_s)
            or timeout_s < 0
            or timeout_s > _MAX_SEAL_TIMEOUT_S
        ):
            return {"status": "refused", "reason": "invalid_timeout"}
        try:
            snapshot = self.snapshot(settle_timeout_s=timeout_s)
            reason = _seal_refusal(snapshot)
            if reason is not None:
                return {"status": "refused", "reason": reason}
            return self.source_spool.seal_epoch(snapshot["source_high_water"], timeout_s=timeout_s)
        except Exception:
            return {"status": "refused", "reason": "source_seal_failed"}

    def _recovered_records(self) -> list[dict[str, Any]]:
        records = self.source_spool.recovered() if self.source_spool else []
        for event in records:
            event["source_spool_status"] = "spooled"
            if "object_id" not in event:
                continue
            event["recovery_resolution"] = "unavailable"
            if self._recovery_resolver is None:
                # Persisted observation of an object ID is not persistence
                # of its bytes. Never copy a stored claim without readback.
                event["status"] = "pending"
                continue
            try:
                descriptor = self._recovery_resolver.read_descriptor(event["object_id"])
                identity = (
                    "tenant_id",
                    "run_id",
                    "source_id",
                    "source_epoch",
                    "source_sequence",
                    "operation_id",
                    "attempt_id",
                    "object_id",
                    "boundary",
                    "role",
                    "stream_id",
                    "chunk_index",
                )
                if any(descriptor.get(key) != event.get(key) for key in identity):
                    raise ValueError("recovered content identity mismatch")
                resolution = self._recovery_resolver.resolve(descriptor)
                event["recovery_resolution"] = resolution.status
                if resolution.status != "available":
                    event.update(status="failed", status_reason="recovered_content_unavailable")
                else:
                    event.update(status=descriptor["status"], descriptor=descriptor)
            except Exception:
                event.update(
                    status="failed",
                    status_reason="recovered_content_unavailable",
                    recovery_resolution="unavailable",
                )
        return records

    def recovered_snapshots(self) -> list[dict[str, Any]]:
        """Offline epoch-isolated replay views of fsynced historical metadata.

        Starts and outcomes are paired only when actually recovered; missing
        ends stay running. No inferred receipt/source trust is added. Objects
        require the configured authorized resolver and verified readback.
        """
        epochs: dict[int, list[dict[str, Any]]] = {}
        for event in self._recovered_records():
            epochs.setdefault(event["source_epoch"], []).append(event)
        snapshots = []
        seals = {
            seal["source_epoch"]: seal
            for seal in (self.source_spool.recovered_seals() if self.source_spool else [])
        }
        # Preserve explicit terminal marks even when the sealed epoch was empty.
        for epoch in seals:
            epochs.setdefault(epoch, [])
        for epoch, records in sorted(epochs.items()):
            starts = [event for event in records if event["role"] == "operation.start"]
            operations = [event for event in records if event["role"] == "operation.outcome"]
            events = [
                event
                for event in records
                if event["role"] not in {"operation.start", "operation.outcome"}
            ]
            calls = []
            for start in starts:
                kind = start.get("kind")
                if kind not in _KINDS:
                    continue
                outcomes = [
                    event for event in operations if event.get("call_id") == start["call_id"]
                ]
                status = (
                    outcomes[0]["outcome"].get("result_status", "running")
                    if len(outcomes) == 1
                    else "running"
                )
                _, input_role, output_role = _KINDS[kind]
                calls.append(
                    {
                        **{
                            key: start[key]
                            for key in (
                                "call_id",
                                "parent_call_id",
                                "agent_id",
                                "operation_id",
                                "attempt_id",
                                "boundary",
                                "kind",
                            )
                        },
                        "input_role": input_role,
                        "output_role": output_role,
                        "status": "partial" if status == "deferred" else status,
                        "started_at": start["observed_at"],
                        "streaming": start.get("streaming", False),
                        "chunk_count": sum(
                            1
                            for event in events
                            if event.get("call_id") == start["call_id"] and "chunk_index" in event
                        ),
                        "recovered": True,
                    }
                )
            water: dict[str, int] = {}
            for record in records:
                water[record["source_id"]] = max(
                    water.get(record["source_id"], -1), record["source_sequence"]
                )
            seal = seals.get(epoch)
            gaps = (
                [gap for gap in self.source_spool.recovered_gaps() if gap["source_epoch"] == epoch]
                if self.source_spool
                else []
            )
            snapshots.append(
                {
                    "schema_version": "fabric.call-recording/v1",
                    "tenant_id": self.tenant_id,
                    "run_id": self.run_id,
                    "source_epoch": epoch,
                    "source_epoch_persisted": True,
                    "source_identity_authenticated": False,
                    "source_high_water": seal["source_high_water"] if seal else water,
                    "source_observed_high_water": water,
                    "source_high_water_basis": "sealed_terminal" if seal else "observed_only",
                    "source_metadata_seal": seal,
                    "source_unsealed_epoch_ranges": self.source_spool.unsealed_epoch_ranges()
                    if self.source_spool
                    else [],
                    "writer_settled": all(event.get("status") != "pending" for event in events),
                    "source_spool_settled": True,
                    "source_spool_recovered_gaps": gaps,
                    "source_spool_health": self.source_spool.health()
                    if self.source_spool
                    else None,
                    "pre_spool_crash_window_unverified": True,
                    "recovery_history_unverified": True,
                    "unretained_drops": 0,
                    "recording_gaps": 0,
                    "starts": starts,
                    "calls": calls,
                    "events": events,
                    "operations": operations,
                }
            )
        return snapshots


class RecordedStream(Iterator[_T]):
    """Pull-through stream; close explicitly when stopping early."""

    def __init__(self, owner: CallRecorder, call: _Call, iterator: Iterator[_T]) -> None:
        self._owner, self._call, self._iterator = owner, call, iterator

    def __next__(self) -> _T:
        if self._call.ended:
            raise StopIteration
        try:
            with self._owner._activate(self._call):
                item = next(self._iterator)
        except StopIteration:
            if self._call.fields["chunk_count"] == 0:
                self._owner._capture(self._call, b"", role=self._call.fields["output_role"])
            self._owner._end(self._call, "ok")
            raise
        except BaseException as exc:
            self._owner._end(self._call, self._owner._failure(exc))
            raise
        index = self._call.fields["chunk_count"]
        self._owner._capture(
            self._call, item, role=self._call.fields["output_role"], chunk_index=index
        )
        self._call.fields["chunk_count"] = index + 1
        return item

    def close(self) -> None:
        if self._call.ended:
            return
        try:
            with self._owner._activate(self._call):
                close = getattr(self._iterator, "close", None)
                if close is not None:
                    close()
        except BaseException as exc:
            self._owner._end(self._call, self._owner._failure(exc))
            raise
        finally:
            self._owner._end(self._call, "partial")

    def __enter__(self) -> RecordedStream[_T]:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        # Never run arbitrary delegate cleanup during GC. Mark known abandonment.
        with suppress(Exception):
            self._owner._end(self._call, "partial", collected=True)


class RecordedAsyncStream(AsyncIterator[_T]):
    """Async pull-through stream with explicit aclose on early exit."""

    def __init__(self, owner: CallRecorder, call: _Call, iterator: AsyncIterator[_T]) -> None:
        self._owner, self._call, self._iterator = owner, call, iterator

    async def __anext__(self) -> _T:
        if self._call.ended:
            raise StopAsyncIteration
        try:
            with self._owner._activate(self._call):
                item = await anext(self._iterator)
        except StopAsyncIteration:
            if self._call.fields["chunk_count"] == 0:
                self._owner._capture(self._call, b"", role=self._call.fields["output_role"])
            self._owner._end(self._call, "ok")
            raise
        except BaseException as exc:
            self._owner._end(self._call, self._owner._failure(exc))
            raise
        index = self._call.fields["chunk_count"]
        self._owner._capture(
            self._call, item, role=self._call.fields["output_role"], chunk_index=index
        )
        self._call.fields["chunk_count"] = index + 1
        return item

    async def aclose(self) -> None:
        if self._call.ended:
            return
        try:
            with self._owner._activate(self._call):
                close = getattr(self._iterator, "aclose", None)
                if close is not None:
                    await close()
        except BaseException as exc:
            self._owner._end(self._call, self._owner._failure(exc))
            raise
        finally:
            self._owner._end(self._call, "partial")

    async def __aenter__(self) -> RecordedAsyncStream[_T]:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    def __del__(self) -> None:
        with suppress(Exception):
            self._owner._end(self._call, "partial", collected=True)
