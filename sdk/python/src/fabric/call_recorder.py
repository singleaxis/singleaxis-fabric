# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Opt-in call timelines linked to protected exact bytes (spec 043).

Only explicitly wrapped boundaries are observed. Callers supply final bytes;
opaque identifiers must not contain customer data. Persistence happens in the
existing bounded byte writer, off the action path. Snapshots are offline and
may wait for that writer. Source authentication and durable receipt proofs
are unavailable; a matching local run is never a complete-production claim.
"""

from __future__ import annotations

import asyncio
import copy
import inspect
import math
import re
import threading
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, TypeVar

from opentelemetry import trace

from .byte_evidence import ByteEvidenceRecorder
from .content_join import CONTENT_JOIN_FIELDS, capture_content_binding
from .source_spool import _MAX_SEAL_TIMEOUT_S, SyntheticSourceSpool
from .tracing import get_tracer

if TYPE_CHECKING:
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


@dataclass
class _Call:
    fields: dict[str, Any]
    span: trace.Span | None
    retained: bool
    ended: bool = False


class CallRecorder:
    """One recorder for a custom agent's explicit model/tool dispatch points.

    ``call`` and ``acall`` preserve the delegate's result/exception. ``stream``
    and ``astream`` return pull-through iterators: they never prefetch. Close
    these wrappers explicitly on early exit (``close``/``aclose`` or context
    managers). Unclosed streams remain running and cannot count as complete.
    Context-local parents propagate to asyncio tasks; threads/processes need
    an explicit ``parent_call_id``. Instances do not install global hooks.
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
    ) -> None:
        self.run_id = _identifier(run_id)
        self.agent_id = _identifier(agent_id)
        self.source_id = _identifier(source_id)
        if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events < 1:
            raise ValueError("max_events must be a positive integer")
        self.recorder = recorder
        self.tenant_id = recorder.tenant_id
        if source_spool is not None and (
            source_spool.tenant_id != self.tenant_id or source_spool.run_id != self.run_id
        ):
            raise ValueError("source spool tenant/run does not match recorder")
        if recovery_resolver is not None and recovery_resolver.tenant_id != self.tenant_id:
            raise ValueError("recovery resolver tenant does not match recorder")
        self.source_spool = source_spool
        self.source_epoch = source_spool.epoch if source_spool is not None else 0
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

    def _start(
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
    ) -> _Call:
        if kind not in _KINDS:
            raise ValueError("kind must be model, tool, database or agent")
        boundary, input_role, output_role = _KINDS[kind]
        parent = self._current.get()
        fields = {
            "call_id": uuid.uuid4().hex,
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
        call = _Call(fields, span, self._append(self._calls, fields))
        start = self._base(call)
        start.update(role="operation.start", status="recorded", streaming=streaming)
        self._append(self._starts, start)
        self._journal(start)
        self._capture(call, payload, role=input_role)
        if context is not None:
            self._capture(call, context, role="interaction.payload")
        return call

    @contextmanager
    def _activate(self, call: _Call) -> Iterator[None]:
        token = self._current.set(call)
        # Disable exception recording: exception messages can contain data.
        try:
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

    def _end(self, call: _Call, status: str) -> None:
        if call.ended:
            return
        call.ended = True
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

    def snapshot(self, *, settle_timeout_s: float = 10.0) -> dict[str, Any]:
        """Offline local snapshot; no authenticated completeness claim."""
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
            self._owner._end(self._call, "partial")


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
            self._owner._end(self._call, "partial")
