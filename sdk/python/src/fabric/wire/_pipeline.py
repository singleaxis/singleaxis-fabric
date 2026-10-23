# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Capture worker (047 §5-§8, 048, 049 §7): protect, digest, store or stage bodies, then one
span or spool record per exchange, on a daemon thread. Nothing here logs content.

049 P0-A: the PROTECT stage (:mod:`._protect`) runs here, before anything is stored or
spooled, and ``fabric.wire.request_sha256``/``response_sha256`` are the digests of the
stored, protected objects, absent when nothing is stored: no digest of an original body
is computed unless the role's mode retains the original."""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import queue
import re
import threading
import time
import uuid
import weakref
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.sdk.trace.id_generator import IdGenerator, RandomIdGenerator
from opentelemetry.trace import (
    NonRecordingSpan,
    SpanContext,
    SpanKind,
    Status,
    StatusCode,
    TraceFlags,
    TraceState,
)  # fmt: skip
from opentelemetry.util.types import AttributeValue

from .._capture_types import (
    EVIDENCE_MEDIA_TYPE,
    EVIDENCE_ROLE,
    MAX_RECORD_BODIES,
    DescriptorOnlyBody,
    RecordBody,
    RecordJob,
    SealAccumulator,
    SealEntry,
    Settle,
    SpanIds,
    settle_noop,
)
from .._evidence import encode as encode_evidence
from .._loss import LossEmitter, LossReason, PrivateFallback, resolve_capture_provider
from .._model_names import expose_model
from .._records import BudgetRefusedBody, records_max_object_bytes
from .._roles import ROLES, admits
from .._seal import SegmentSeals, record_digest
from .._sequence import OPAQUE_ID_RE, SourceAllocator
from .._version import __version__
from ._attrs import p1_attributes
from ._match import OPERATION_NAMES
from ._model import FINISH_REASONS, ROLE_REQUEST, ROLE_RESPONSE, SPAN_EXCHANGE, WireAttr
from ._policy import LOCAL_DEFAULT, CapturePolicy, ContentGate
from ._protect import Obj, Protector, SideResult

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import TracerProvider

    from ..content_store.base import ByteEvidenceStore
    from ._config import WireConfig
    from ._model import CapturedBody, CaptureJob, StoreStatus
    from ._sender import Sender
    from ._stream import Budget

    Job = CaptureJob | RecordJob

_MEDIA_RE = re.compile(r"^(?=.{3,128}$)[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_ENCODING_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,31}(,[a-z0-9][a-z0-9._+-]{0,31}){0,3}$")
_ERROR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,127}$")
_FINISH_KEY = {"openai.responses": "status", "anthropic.messages": "stop_reason"}
_STATS = (
    "submitted", "dropped", "truncated", "internal_errors", "store_failures", "spans_emitted",
    "spans_refused", "record_objects_refused",
)  # fmt: skip
_BACKOFFS_S = (0.1, 0.4, 1.6)  # one try plus three retries
# Spool path (D4): the worker takes up to this many queued jobs (and about this many
# captured bytes) at a time and spools them with one admission, one rename lock and one
# directory fsync; each record is still fsync'd before it counts as spooled.
_BATCH_ITEMS, _BATCH_BYTES = 64, 8 * 1024 * 1024
_METADATA_MAX_BYTES = 256 * 1024  # json.loads holds the GIL; larger bodies are left to reconstruct
_STOP = object()
_PIPELINES: weakref.WeakSet[CapturePipeline] = weakref.WeakSet()
_IDS = RandomIdGenerator()
_LOG = logging.getLogger("fabric.wire")
DEFAULT_MAX_BODY_BYTES = 32 * 1024 * 1024
# A side's reason (049 §7.5 status_reason) as the span's store_reason (vocabulary X40).
_SPAN_REASON = {"part_cap": "body_cap"}
# When sides disagree, the span names the most consequential reason.
_REASON_ORDER = (
    "protection_failed", "store_failed", "privacy_policy", "body_cap", "inflight_budget",
    "transport_incomplete",
)  # fmt: skip


def protector_for(config: WireConfig, gate: ContentGate | None) -> Protector | None:
    """The PROTECT stage of an install (``None`` while content is not enabled). Without a
    gate (a tee built directly) a configured destination gets ``fabric.local-default``."""
    if gate is None:
        destination = config.store is not None or config.content_endpoint is not None
        configured = config.capture_policy
        policy = (CapturePolicy.from_deployment(configured) if configured is not None
                  else LOCAL_DEFAULT) if destination else None  # fmt: skip
    else:
        policy = gate.policy if gate.enabled else None
    if policy is None:
        return None
    return Protector(
        policy, max_body_bytes=config.max_body_bytes,
        max_retain_bytes=config.max_retain_bytes, part_min_bytes=config.part_min_bytes,
        transformations=config.transformations, tokenization_key=config.tokenization_key,
        redaction=config.redaction,
    )  # fmt: skip


def capture_parent(context: Context | None) -> Context:
    """A fresh context with only ``context``'s span ids, flags and remoteness (E7): no trace
    state or baggage; else an explicit empty one (a root span). The host's is untouched."""
    parent = trace.get_current_span(context).get_span_context() if context else None
    if parent is None or not parent.is_valid:
        return Context()
    clean = SpanContext(
        parent.trace_id, parent.span_id, parent.is_remote, parent.trace_flags, TraceState()
    )
    return trace.set_span_in_context(NonRecordingSpan(clean), Context())


def media_type_of(value: str) -> str:
    """``Content-Type`` without parameters, lowercased; octet-stream when invalid."""
    media = value.split(";", 1)[0].strip().lower()
    return media if _MEDIA_RE.fullmatch(media) else "application/octet-stream"


def content_encoding_of(value: str) -> str:
    """Lowercased, whitespace removed; ``identity`` when empty, ``unknown`` when invalid."""
    encoding = "".join(value.split()).lower() or "identity"
    return encoding if _ENCODING_RE.fullmatch(encoding) else "unknown"


def response_metadata(job: CaptureJob, model_allowlist: Sequence[str] = ()) -> dict[str, Any]:
    """Model (spec 048 §7 exposure), finish reasons and usage, only from a complete
    plain-JSON response."""
    body = job.response
    if body is None or body.truncated or job.response_state != "complete":
        return {}
    plain = content_encoding_of(body.content_encoding) == "identity"
    if not plain or media_type_of(body.media_type) != "application/json":
        return {}
    if body.captured_byte_length > _METADATA_MAX_BYTES:
        return {}
    try:
        doc = json.loads(b"".join(body.chunks))
    except (ValueError, RecursionError):
        return {}
    if not isinstance(doc, dict):
        return {}
    found: dict[str, Any] = {}
    if (model := expose_model(doc.get("model"), model_allowlist)) is not None:
        found["model"] = model
    choices = doc["choices"] if isinstance(doc.get("choices"), list) else []
    reasons: list[Any] = [doc.get(_FINISH_KEY[job.api])] if job.api in _FINISH_KEY else [
        choice.get("finish_reason") for choice in choices if isinstance(choice, dict)
    ]  # fmt: skip
    if reasons := [r for r in reasons if isinstance(r, str)][:64]:
        found["finish_reasons"] = [r if r in FINISH_REASONS else "other" for r in reasons]
    usage = doc["usage"] if isinstance(doc.get("usage"), dict) else {}
    native = job.api in _FINISH_KEY  # Responses and Anthropic already use OTel's names
    for key, name in (("input_tokens", "prompt_tokens"), ("output_tokens", "completion_tokens")):
        if type(value := usage.get(key if native else name)) is int and 0 <= value < 1 << 63:
            found[key] = value
    return found


def exchange_attributes(
    job: CaptureJob, *, request_sha256: str | None, response_sha256: str | None,
    request_ref: str | None, response_ref: str | None, store_status: StoreStatus,
    truncated: bool, metadata: Mapping[str, Any], store_reason: str | None = None,
) -> dict[str, AttributeValue]:  # fmt: skip
    """The exchange span's attributes (spec 047 §8): ids, digests, object ids and enums only.
    The digests are the stored objects' (049 §2.4 rule 8), absent when nothing is stored."""
    error, status = job.error_type, job.http_status_code
    if job.response_state == "error":
        error = error if error and _ERROR_RE.fullmatch(error) else "UnknownError"
    attrs: dict[str, Any] = {
        WireAttr.EXCHANGE_ID: job.exchange_id, WireAttr.RUN_ID: job.run_id,
        WireAttr.SCOPE_ID: job.scope_id,
        WireAttr.SOURCE_ID: job.source_id, WireAttr.SOURCE_EPOCH: job.source_epoch,
        WireAttr.SOURCE_SEQUENCE: job.source_sequence, WireAttr.API: job.api,
        WireAttr.REQUEST_SHA256: request_sha256,
        WireAttr.RESPONSE_STATE: job.response_state, WireAttr.TRUNCATED: truncated,
        WireAttr.STORE_STATUS: store_status, WireAttr.STORE_REASON: store_reason,
        "http.request.method": "POST",
        "gen_ai.operation.name": OPERATION_NAMES[job.api],
        "gen_ai.provider.name": job.provider_name,
        WireAttr.RESPONSE_SHA256: response_sha256, WireAttr.REQUEST_REF: request_ref,
        WireAttr.RESPONSE_REF: response_ref,
        "http.response.status_code": status if status in range(100, 600) else None,
        "error.type": error if job.response_state == "error" else None,
        "gen_ai.response.model": metadata.get("model"),
        "gen_ai.response.finish_reasons": metadata.get("finish_reasons"),
        "gen_ai.usage.input_tokens": metadata.get("input_tokens"),
        "gen_ai.usage.output_tokens": metadata.get("output_tokens"),
    }  # fmt: skip
    with contextlib.suppress(Exception):  # 050 §3.9 P1 keys (WP-14); never costs the record
        attrs.update(p1_attributes(job))
    return {key: value for key, value in attrs.items() if value is not None}


class CapturePipeline:
    """Bounded single-worker ``ExchangeSink``; ``on_job_done`` runs once per job."""

    def __init__(
        self, *, store: ByteEvidenceStore | None, tracer_provider: TracerProvider | None,
        loss: LossEmitter, queue_max_items: int = 16384,
        on_job_done: Callable[[CaptureJob], None] | None = None, sender: Sender | None = None,
        node_tenant_id: str | None = None, model_allowlist: Sequence[str] = (),
        fallback: PrivateFallback | None = None, gate: ContentGate | None = None,
        protector: Protector | None = None, max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    ) -> None:  # fmt: skip
        """``node_tenant_id`` (with ``sender``): bodies go into spool records for the Node.
        ``fallback``: the private provider used when ``tracer_provider`` (or, without one,
        the global provider) has a Fabric-protected route at emit time. ``gate``: the
        install's content decision (049 §7.3; default: ``fabric.local-default`` when a
        destination is given, else metadata-only); ``protector``: its PROTECT stage."""
        if type(queue_max_items) is not int or not 1 <= queue_max_items <= 65536:  # noqa: PLR2004
            raise ValueError("queue_max_items must be an integer between 1 and 65536")
        tenant = getattr(store, "tenant_id", None) if node_tenant_id is None else node_tenant_id
        if (store or node_tenant_id) and not OPAQUE_ID_RE.fullmatch(str(tenant or "")):
            raise ValueError("the byte store must be tenant-scoped")
        if node_tenant_id is not None and (sender is None or store is not None):
            raise ValueError("node mode needs a spool sender and no byte store")
        self._store, self._tenant_id, self._provider = store, tenant, tracer_provider
        self._sender, self._node, self._models = sender, node_tenant_id is not None, model_allowlist
        self._loss, self._max_items, self._on_job_done = loss, queue_max_items, on_job_done
        self._fallback = fallback
        if gate is None:  # a pipeline built directly (tests, embedders): no production gate
            destination = store is not None or node_tenant_id is not None
            gate = ContentGate("local", "enabled" if destination else "metadata_only",
                               None if destination else "no_store",
                               LOCAL_DEFAULT if destination else None)  # fmt: skip
        self._gate = gate
        self._protector = protector or (
            Protector(gate.policy, max_body_bytes=max_body_bytes)
            if gate.enabled and gate.policy is not None else None
        )  # fmt: skip
        self._warned_epochs: set[int] = set()  # disabled state logged once per epoch
        self._backoffs: tuple[float, ...] = _BACKOFFS_S
        # 050 §3.7: the seal accumulator this pipeline owns (its segment_seal markers go to
        # the loss emitter's marker queue), and the allocator's settle (attached at install).
        self.seals: SealAccumulator = SegmentSeals(loss.queue_marker)
        self._settle: Settle = settle_noop
        # 050 §3.4-§3.5: records-input jobs. Bodies are charged to the tee's in-flight
        # budget at emit (the records input attaches it) and released when the job is done;
        # one object is at most min(role cap, max_body_bytes, records_max_object_bytes).
        self._record_budget: Callable[[], Budget | None] = _no_budget
        self._max_body = max_body_bytes if protector is None else protector.max_body
        self._records_max = records_max_object_bytes(os.environ)
        self._init_state()
        _PIPELINES.add(self)

    def _init_state(self) -> None:
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=self._max_items)
        self._cond, self._closing = threading.Condition(), threading.Event()
        self._closed, self._pending, self._stats = False, 0, dict.fromkeys(_STATS, 0)
        # The jobs in progress (by id) until their outcome is claimed.
        self._current: dict[int, Job] = {}
        # Records-input jobs: their in-flight charge (budget, bytes) until done, and the
        # content list of their record digest (worker only) until settled.
        self._charges: dict[int, tuple[Budget, int]] = {}
        self._record_content: dict[int, list[str | None]] = {}
        self._worker = threading.Thread(target=self._run, name="fabric-wire-capture", daemon=True)
        self._worker.start()

    def set_settle(self, settle: Settle | None) -> None:
        """The allocator's settle (050 §3.3), called once a position is written. The seal
        accumulator reads the segment's source and epoch from that allocator."""
        self._settle = settle if settle is not None else settle_noop
        owner = getattr(settle, "__self__", None)
        if isinstance(owner, SourceAllocator) and isinstance(self.seals, SegmentSeals):
            self.seals.bind_source(lambda: (owner.source_id, owner.epoch))

    # -- records input (050 §3.4, §3.5) ---------------------------------------------------

    def set_record_budget(self, budget: Callable[[], Budget | None] | None) -> None:
        """How to reach the in-flight budget records-input bodies are charged to (read at
        each charge: a forked child's tee has a new one)."""
        self._record_budget = budget if budget is not None else _no_budget

    def charge_record(self, job: RecordJob) -> bool:
        """Charge ``job``'s bodies to the in-flight budget (application thread: one short
        lock, no wait). ``False``: over the budget, the bodies are refused
        (``inflight_budget``). Released when the job is done (:meth:`_done`)."""
        charge = job.inflight_charge
        if charge <= 0:
            return True
        budget = self._record_budget()
        if budget is None:
            return True
        if not budget.try_reserve(charge):
            return False
        with self._cond:
            self._charges[id(job)] = (budget, charge)
        return True

    def _recharge(self, job: RecordJob, charged: int, actual: int) -> None:
        """A ``str`` body was charged ``len * 4`` until encoded: release the excess."""
        with self._cond:
            entry = self._charges.get(id(job))
            if entry is None or charged <= actual:
                return
            budget, charge = entry
            excess = min(charge, charged - actual)
            self._charges[id(job)] = (budget, charge - excess)
        budget.release(excess)

    def record_mode(self, role: str) -> str:
        """The privacy mode the worker applies to a records-input body of ``role`` (049 §2.7
        precedence). ``record.evidence`` (§3.4a item 3) holds no content: it is stored
        (``retain_original``) whenever the content path exists, unless the policy names it
        ``omit`` or ``metadata_only``; any other mode is refused for it (fail closed). Every
        other role: ``omit`` while content capture is not enabled or the role is unknown."""
        destination = self._store is not None or self._node
        if role == EVIDENCE_ROLE:
            if not destination:
                return "omit"
            named = self._protector.policy.modes.get(role) if self._protector else None
            if named is None:
                return "retain_original"
            return named if named in ("omit", "metadata_only", "retain_original") else "omit"
        if self._protector is None or role not in ROLES:
            return "omit"
        return self._protector.policy.mode(role)

    def _lose(self, job: Job, reason: LossReason) -> None:
        self._loss.record(
            job.source_id, job.source_epoch, reason, job.source_sequence,
            segment_id=_segment_of(job),
        )  # fmt: skip

    def _settle_written(self, job: Job, span: Mapping[str, Any]) -> None:
        """050 §3.7: a written position settles its segment with its record digest."""
        content = self._record_content.pop(id(job), None) if isinstance(job, RecordJob) else None
        if (segment := _segment_of(job)) is None:
            return
        with contextlib.suppress(Exception):
            if isinstance(self.seals, SegmentSeals):
                self.seals.note_job(segment, job.source_id, job.source_epoch, job.run_id)
            entry = _record_entry(span) if content is None else record_digest(
                name=span["name"], start_ns=span["start_time_unix_nano"],
                end_ns=span["end_time_unix_nano"], status=span["status"],
                attributes=span["attributes"], content=content,
            )  # fmt: skip
            self._settle(segment, job.source_sequence, entry)

    def submit(self, job: Job) -> bool:
        """Non-blocking; ``False`` means dropped (``queue_full``/``shutdown``) and recorded.
        Takes exchange jobs and records-input jobs (050 §3.5)."""
        reason: LossReason = "shutdown"
        with self._cond:
            if not self._closed:
                try:
                    self._queue.put_nowait(job)
                    self._pending += 1
                    self._stats["submitted"] += 1
                    return True
                except queue.Full:
                    reason = "queue_full"
        self._drop(job, reason)
        return False

    def _drop(self, job: Job, reason: LossReason) -> None:
        with self._cond:
            self._stats["dropped"] += 1
        self._lose(job, reason)
        self._done(job)

    def _done(self, job: Job) -> None:
        if isinstance(job, RecordJob):  # its bodies' in-flight charge is released
            with contextlib.suppress(Exception):
                with self._cond:
                    charged = self._charges.pop(id(job), None)
                    self._record_content.pop(id(job), None)
                if charged is not None:
                    charged[0].release(charged[1])
            return
        if self._on_job_done is not None:
            with contextlib.suppress(Exception):
                self._on_job_done(job)

    def flush(self, timeout_s: float = 5.0) -> bool:
        """Wait until every accepted job has been processed and every segment seal it
        completed is built and queued (050 §3.7: seals are built on the seal worker)."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        with self._cond:
            drained = self._cond.wait_for(lambda: not self._pending, max(0.0, timeout_s))
        drain = getattr(self.seals, "drain", None)
        if callable(drain):
            drained = bool(drain(max(0.0, deadline - time.monotonic()))) and drained
        return drained

    def close(self, timeout_s: float = 2.0) -> bool:
        """Drain within ``timeout_s``; every job unfinished then (the one in progress too, its
        late span suppressed) is reported once as a ``shutdown`` loss."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        with self._cond:
            already, self._closed = self._closed, True
        drained = self.flush(timeout_s)
        if already:
            return drained
        self._closing.set()  # interrupts store retry backoff
        lost: list[Job] = []
        with contextlib.suppress(queue.Empty):
            while True:
                lost.append(self._queue.get_nowait())
        with self._cond:
            self._pending -= len(lost)
            current, self._current = list(self._current.values()), {}
            self._stats["dropped"] += len(current)
            self._cond.notify_all()
        for job in lost:
            self._drop(job, "shutdown")
        for job in current:  # the worker still releases their bytes when it returns
            self._lose(job, "shutdown")
        self._queue.put(_STOP)
        if drained and self._worker is not threading.current_thread():
            self._worker.join(timeout=max(0.0, deadline - time.monotonic()))
        if self._protector is not None:  # its redaction service connections
            self._protector.close(max(0.0, deadline - time.monotonic()))
        return drained and not lost and not current

    def stats(self) -> Mapping[str, int]:
        protect = self._protector.stats() if self._protector is not None else {}
        with self._cond:
            return {**self._stats, **protect, "queue_depth": self._queue.qsize()}

    def resolved_provider(self) -> trace.TracerProvider | None:
        """The provider exchange spans go through now; ``None`` when they are refused."""
        return resolve_capture_provider(self._provider, self._fallback)

    def _commit(self, job: Job) -> bool:
        """The job's single terminal transition: ``True`` gives the worker its outcome;
        ``False`` means ``close`` already reported it as a shutdown loss. Exactly one wins.
        """
        with self._cond:
            return self._current.pop(id(job), None) is not None

    def _run(self) -> None:  # the worker is the only writer of its own counters
        while True:
            job = self._queue.get()
            if job is _STOP:
                return
            jobs, stop = self._batch(job)
            with self._cond:  # close() may claim them until the worker commits
                self._current.update((id(j), j) for j in jobs)
            try:
                if self._sender is not None:
                    self._spool_batch(self._sender, jobs)
                else:
                    self._emit_one(job)
            finally:
                for done in jobs:
                    self._done(done)
                with self._cond:
                    self._pending -= len(jobs)
                    self._cond.notify_all()
            if stop:
                return

    def _batch(self, job: Job) -> tuple[list[Job], bool]:
        """``job`` plus, on the spool path, the jobs already queued behind it (bounded by
        count and captured bytes); ``True`` when the stop sentinel was taken."""
        jobs, size = [job], _job_bytes(job)
        while self._sender is not None and len(jobs) < _BATCH_ITEMS and size < _BATCH_BYTES:
            try:
                queued = self._queue.get_nowait()
            except queue.Empty:
                break
            if queued is _STOP:
                return jobs, True
            jobs.append(queued)
            size += _job_bytes(queued)
        return jobs, False

    def _fail(self, job: Job) -> None:
        """An error before the commit: an ``internal_error`` loss (after the commit the
        outcome is the span or record)."""
        with contextlib.suppress(Exception):
            if self._commit(job):
                self._stats["internal_errors"] += 1
                self._lose(job, "internal_error")

    def _emit_one(self, job: Job) -> None:
        try:
            if isinstance(job, RecordJob):
                self._emit_record(job, *self._prepare(job))
            else:
                self._emit(job, *self._prepare(job))
        except Exception:
            self._fail(job)

    def _spool_batch(self, sender: Sender, jobs: Sequence[Job]) -> None:
        """Protect each job, commit it, then spool the committed ones in one batch. A record
        the spool did not take is a loss: ``queue_full`` (over the bound), ``disk_full``
        (the volume is full) or ``internal_error``."""
        ready: list[tuple[Job, dict[str, Any], Any]] = []
        for job in jobs:
            try:
                attrs, staged = self._prepare(job)
                span = (self._record_span(job, attrs) if isinstance(job, RecordJob)
                        else self._span_record(job, attrs))  # fmt: skip
            except Exception:
                self._fail(job)
                continue
            if self._commit(job):
                ready.append((job, span, staged))
        if not ready:
            return
        try:
            outcomes = sender.spool_exchanges(
                [(job.source_id, job.source_epoch, span, staged) for job, span, staged in ready]
            )
        except Exception:
            outcomes = ["internal_error"] * len(ready)
        for (job, span, _), outcome in zip(ready, outcomes, strict=True):
            if outcome == "spooled":
                self._settle_written(job, span)
                continue
            if outcome == "internal_error":
                self._stats["internal_errors"] += 1
            with contextlib.suppress(Exception):
                self._lose(job, cast("LossReason", outcome))

    def _prepare(self, job: Job) -> tuple[dict[str, AttributeValue], list[Any]]:
        """Protect, then store (or stage, in node mode) both sides; the span attributes.
        A records-input job takes its own path (050 §3.5)."""
        if isinstance(job, RecordJob):
            return self._prepare_record(job)
        sides = [(job.request, ROLE_REQUEST)]
        sides += [] if job.response is None else [(job.response, ROLE_RESPONSE)]
        staged: list[tuple[dict[str, Any], bytes]] = []
        if (protector := self._protector) is None:  # content not enabled (049 §7.3)
            self._warn_disabled(job)
            if truncated := any(body.truncated for body, _ in sides):
                self._stats["truncated"] += 1
            return exchange_attributes(
                job, request_sha256=None, response_sha256=None, request_ref=None,
                response_ref=None, store_status="disabled", truncated=truncated,
                metadata=response_metadata(job, self._models), store_reason=self._gate.reason,
            ), staged  # fmt: skip
        results: list[SideResult] = []
        failed = False
        for body, role in sides:
            partial = role == ROLE_RESPONSE and job.response_state != "complete"
            result = protector.side(
                self._base(job, body, role), role, body.chunks,
                observed=body.observed_byte_length,
                cut_reason=body.cut_reason or ("body_cap" if body.truncated else None),
                partial=partial, prefix=body.prefix_length,
            )  # fmt: skip
            failed |= not self._admit(result, staged)
            results.append(result)
        if truncated := any(result.truncated for result in results):
            self._stats["truncated"] += 1
        stored = sum(result.primary is not None for result in results)
        status: StoreStatus = "stored" if stored == len(results) else "partial" if stored else (
            "failed" if failed else "disabled"
        )  # fmt: skip
        reasons = {_SPAN_REASON.get(r.reason, r.reason) for r in results if r.reason}
        reason = next((r for r in _REASON_ORDER if r in reasons), None)
        digests = [r.primary.descriptor["stored_sha256"][7:] if r.primary else None
                   for r in results]  # fmt: skip
        refs = [r.primary.object_id if r.primary else None for r in results]
        return exchange_attributes(
            job, request_sha256=digests[0], response_sha256=[*digests, None][1],
            request_ref=refs[0], response_ref=[*refs, None][1], store_status=status,
            truncated=truncated, metadata=response_metadata(job, self._models),
            store_reason=reason,
        ), staged  # fmt: skip

    # -- records-input jobs (050 §3.4, §3.4a, §3.5) ------------------------------------------

    def _prepare_record(self, job: RecordJob) -> tuple[dict[str, AttributeValue], list[Any]]:
        """PROTECT a record's bodies and evidence object, then store (direct) or stage
        (node) them; the span attributes gain ``fabric.content.object_ids`` (the objects in
        reference order: bodies, then the evidence object). Over 8 objects the record is
        refused before any write (an ``internal_error`` loss, R6)."""
        objects: list[Obj] = []
        if self._store is not None or self._node:  # no destination: no content objects
            for body in job.bodies:
                objects += self._record_body(job, body)
            if job.evidence is not None:
                objects += self._record_evidence(job)
        if len(objects) > MAX_RECORD_BODIES:
            raise ValueError("a record carries at most 8 content objects")
        staged: list[tuple[dict[str, Any], bytes]] = []
        kept: list[Obj] = []
        for obj in objects:
            if not self._record_admissible(obj):  # the Node's role rules would refuse it
                self._stats["record_objects_refused"] += 1
                continue
            if self._store is None:
                staged.append((obj.descriptor, obj.data))
            elif obj.stored and not self._store_object(obj):
                continue  # never named by the record: its digest could not be verified
            kept.append(obj)
        attrs: dict[str, AttributeValue] = dict(job.attributes)
        if kept:
            attrs["fabric.content.object_ids"] = [obj.object_id for obj in kept]
        self._record_content[id(job)] = [obj.descriptor.get("stored_sha256") for obj in kept]
        return attrs, staged

    def _record_base(
        self, job: RecordJob, *, media_type: str, boundary: str, provenance: str,
        stream_id: str | None = None, chunk_index: int | None = None,
    ) -> dict[str, Any]:  # fmt: skip
        """The identity fields of a record's content-v2 descriptor (the exchange base of
        :meth:`_base`, with ``attempt_id``)."""
        base: dict[str, Any] = {
            "schema_version": "fabric.content-object/v2", "tenant_id": self._tenant_id,
            "media_type": media_type_of(media_type), "content_encoding": "identity",
            "provenance": provenance, "boundary": boundary, "source_id": job.source_id,
            "source_epoch": job.source_epoch, "source_sequence": job.source_sequence,
            "captured_at": datetime.fromtimestamp(job.end_ns / 1e9, UTC).isoformat(),
            "operation_id": job.attempt_uid, "attempt_id": job.attempt_uid,
        }  # fmt: skip
        if job.run_id is not None:
            base["run_id"] = job.run_id
        if stream_id is not None:
            base["stream_id"] = stream_id
            if chunk_index is not None:
                base["chunk_index"] = chunk_index
        return base

    def _record_body(  # noqa: PLR0911 - one return per body outcome
        self, job: RecordJob, body: RecordBody | DescriptorOnlyBody
    ) -> list[Obj]:
        """One body's objects under its role's mode: a descriptor-only body without
        PROTECT; a ``str`` encoded strictly here (a lone surrogate: ``parse_failed``); an
        object over the cap ``not_captured(payload_too_large)``; else the P0-A PROTECT
        stage (redaction service included). Exact or nothing: never truncated."""
        role = body.role
        mode = self.record_mode(role)
        if mode == "omit":
            return []
        stream = (
            (body.stream_id, body.chunk_index) if isinstance(body, RecordBody) else (None, None)
        )
        provenance = body.content_provenance if isinstance(body, RecordBody) else (
            "protocol" if job.provenance == "observed" else "caller_reported")  # fmt: skip
        base = self._record_base(job, media_type=body.media_type, boundary=body.boundary,
                                 provenance=provenance, stream_id=stream[0],
                                 chunk_index=stream[1])  # fmt: skip
        if isinstance(body, BudgetRefusedBody):
            return [self._record_withheld(base, role, mode, "inflight_budget")]
        if isinstance(body, DescriptorOnlyBody):
            return [self._record_withheld(base, role, mode, body.reason, status=body.status,
                                          observed=body.observed_byte_length)]  # fmt: skip
        data = body.data
        if isinstance(data, str):
            charged = len(data) * 4
            try:
                data = data.encode("utf-8")
            except UnicodeEncodeError:
                self._recharge(job, charged, 0)
                return [self._record_withheld(base, role, mode, "parse_failed")]
            self._recharge(job, charged, len(data))
        cap = min(ROLES[role].cap_bytes(self._max_body), self._max_body, self._records_max)
        if len(data) > cap:
            return [self._record_withheld(base, role, mode, "payload_too_large",
                                          observed=len(data))]  # fmt: skip
        if role == EVIDENCE_ROLE:  # caller-made evidence bytes: stored as the role allows
            return [self._evidence_object(base, mode, data)]
        if self._protector is None:
            return []
        return self._protector.side(
            base, role, [data], observed=len(data), cut_reason=None, partial=False
        ).objects

    def _record_evidence(self, job: RecordJob) -> list[Obj]:
        """The record's evidence object (§3.4a): serialised here, then stored under the
        ``record.evidence`` mode. Its boundary is the record's (its first body's, else
        ``caller``); its provenance follows the attempt's."""
        mode = self.record_mode(EVIDENCE_ROLE)
        if mode == "omit" or job.evidence is None:
            return []
        boundary = next((body.boundary for body in job.bodies), "caller")
        provenance = "protocol" if job.provenance == "observed" else "caller_reported"
        base = self._record_base(job, media_type=EVIDENCE_MEDIA_TYPE, boundary=boundary,
                                 provenance=provenance)  # fmt: skip
        try:
            data = encode_evidence(job.evidence)
        except Exception:  # the items changed since emit: no longer a valid document
            return [self._record_withheld(base, EVIDENCE_ROLE, mode, "encoding_failed")]
        cap = min(ROLES[EVIDENCE_ROLE].cap_bytes(self._max_body), self._records_max)
        if data is None or len(data) > cap:
            return [self._record_withheld(base, EVIDENCE_ROLE, mode, "payload_too_large")]
        return [self._evidence_object(base, mode, data)]

    def _evidence_object(self, base: Mapping[str, Any], mode: str, data: bytes) -> Obj:
        if mode == "metadata_only":
            return self._record_withheld(base, EVIDENCE_ROLE, mode, "privacy_policy",
                                         observed=len(data))  # fmt: skip
        if self._protector is not None:
            return self._protector._stored(
                base, EVIDENCE_ROLE, mode, data, "exact", [], "stored", "retained",
                {"source_byte_length": len(data), "source_sha256": _sha256(data)},
            )  # fmt: skip
        # content capture disabled (production without policy or key): the evidence object
        # holds no content and is still written, without a policy block (§3.4a item 3)
        descriptor = {
            **base, "object_id": str(uuid.uuid4()), "role": EVIDENCE_ROLE, "status": "stored",
            "representation": "exact", "transformations": [], "stored_byte_length": len(data),
            "stored_sha256": _sha256(data), "source_byte_length": len(data),
            "source_sha256": _sha256(data),
        }  # fmt: skip
        return Obj(descriptor, data)

    def _record_withheld(
        self, base: Mapping[str, Any], role: str, mode: str, reason: str, *,
        status: str = "not_captured", observed: int | None = None,
    ) -> Obj:  # fmt: skip
        """A descriptor-only object (R5): no bytes, no stored digest; ``status`` and
        ``status_reason`` as given, ``representation: unavailable``."""
        sizes = {} if observed is None else {"source_byte_length": observed}
        if self._protector is not None:
            obj = self._protector._withheld(base, role, mode, reason, **sizes)
        else:
            obj = Obj({**base, "object_id": str(uuid.uuid4()), "role": role,
                       "status": status, "representation": "unavailable",
                       "transformations": [], "status_reason": reason})  # fmt: skip
        obj.descriptor["status"] = status
        return obj

    def _record_admissible(self, obj: Obj) -> bool:
        d = obj.descriptor
        return admits(d["role"], boundary=d["boundary"], provenance=d["provenance"],
                      media_type=d["media_type"], stored_byte_length=len(obj.data),
                      max_body_bytes=self._max_body)  # fmt: skip

    def _record_span(self, job: RecordJob, attrs: Mapping[str, Any]) -> dict[str, Any]:
        """A record's span (spool path; 050 §3.4 "Span ids"): the host span's ids when
        ``span_ids`` names one, else a new span id under the current span at emit."""
        ids = job.span_ids
        if ids is not None:
            trace_id, span_id = ids.trace_id, ids.span_id
            parent, remote = ids.parent_span_id, ids.parent_is_remote
        else:
            ctx = trace.get_current_span(capture_parent(job.parent_context)).get_span_context()
            trace_id = ctx.trace_id if ctx.is_valid else _IDS.generate_trace_id()
            span_id = _IDS.generate_span_id()
            parent, remote = (ctx.span_id, ctx.is_remote) if ctx.is_valid else (None, False)
        span: dict[str, Any] = {
            "name": job.name, "kind": "internal", "trace_flags": 1,
            "trace_id": f"{trace_id:032x}", "span_id": f"{span_id:016x}",
            "start_time_unix_nano": job.start_ns, "end_time_unix_nano": job.end_ns,
            "status": job.otlp_status,
            "attributes": {k: list(v) if isinstance(v, tuple) else v for k, v in attrs.items()},
        }  # fmt: skip
        if parent is not None:
            span |= {"parent_span_id": f"{parent:016x}", "parent_is_remote": remote}
        return span

    def _emit_record(self, job: RecordJob, attrs: dict[str, AttributeValue], staged: Any) -> None:
        """A record through the provider path (050 §3.4 "Without a spool"), as
        :meth:`_emit` does for exchanges: a refused provider (D3: a protected route never
        carries a record) or a sampled-out span is a ``span_dropped`` loss."""
        provider = resolve_capture_provider(self._provider, self._fallback)
        if provider is None:
            if self._commit(job):
                self._stats["spans_refused"] += 1
                self._lose(job, "span_dropped")
            return
        tracer = trace.get_tracer("fabric.records", __version__, tracer_provider=provider)
        parent, fixed = _record_parent(tracer, job.span_ids, job.parent_context)
        try:
            span = tracer.start_span(job.name, parent, SpanKind.INTERNAL, attrs,
                                     start_time=job.start_ns)  # fmt: skip
        finally:
            if fixed is not None:
                fixed.clear()
        if job.otlp_status != "unset":
            span.set_status(Status(StatusCode.OK if job.otlp_status == "ok" else StatusCode.ERROR))
        if not self._commit(job):
            return  # already a shutdown loss: suppress the late outcome
        try:
            if not span.is_recording():  # sampled out: the sequence must not silently vanish
                self._lose(job, "span_dropped")
                return
            span.end(end_time=job.end_ns)
            self._stats["spans_emitted"] += 1
            self._settle_written(job, {
                "name": job.name, "start_time_unix_nano": job.start_ns,
                "end_time_unix_nano": job.end_ns, "status": job.otlp_status, "attributes": attrs,
            })  # fmt: skip
        except Exception:  # committed: never a second outcome for this sequence
            self._stats["internal_errors"] += 1

    def _warn_disabled(self, job: CaptureJob) -> None:
        """049 §7.3: the disabled state is logged at the first exchange of each epoch, by
        reason only (never a value)."""
        gate = self._gate
        if gate.content_capture == "disabled" and job.source_epoch not in self._warned_epochs:
            self._warned_epochs.add(job.source_epoch)
            _LOG.warning("fabric.wire: content capture disabled (%s); metadata continues",
                         gate.reason)  # fmt: skip

    def _admit(self, result: SideResult, staged: list[tuple[dict[str, Any], bytes]]) -> bool:
        """Stage (node mode) or store a side's objects; ``False`` when a store write failed.
        A descriptor-only object travels only to the Node (a direct store holds bytes)."""
        ok = True
        for obj in result.objects:
            if self._store is None:
                staged.append((obj.descriptor, obj.data))
            elif obj.stored and not self._store_object(obj):
                ok = False
                if obj is result.primary:
                    result.primary = None
                result.reason = result.reason or "store_failed"
        return ok

    def _span_record(self, job: CaptureJob, attrs: dict[str, Any]) -> dict[str, Any]:
        """The exchange record's span (spool path)."""
        ctx = trace.get_current_span(capture_parent(job.parent_context)).get_span_context()
        span: dict[str, Any] = {
            "name": SPAN_EXCHANGE, "kind": "client", "trace_flags": 1,
            "trace_id": f"{ctx.trace_id if ctx.is_valid else _IDS.generate_trace_id():032x}",
            "span_id": f"{_IDS.generate_span_id():016x}", "start_time_unix_nano": job.started_ns,
            "end_time_unix_nano": max(job.ended_ns, job.started_ns),
            "status": "error" if _is_error(job) else "unset",
            "attributes": {k: list(v) if isinstance(v, tuple) else v for k, v in attrs.items()},
        }  # fmt: skip
        if ctx.is_valid:
            span |= {"parent_span_id": f"{ctx.span_id:016x}", "parent_is_remote": ctx.is_remote}
        return span

    def _emit(self, job: CaptureJob, attrs: dict[str, AttributeValue], staged: Any) -> None:
        """Build the span, then commit: an unended span is never exported, so a job
        ``close`` claimed meanwhile is dropped here (the spool path is :meth:`_spool_batch`)."""
        provider = resolve_capture_provider(self._provider, self._fallback)
        if provider is None:  # a protected route would rename it and erase its identifiers
            if self._commit(job):
                self._stats["spans_refused"] += 1
                self._lose(job, "span_dropped")
            return
        tracer = trace.get_tracer("fabric.wire", __version__, tracer_provider=provider)
        parent = capture_parent(job.parent_context)
        span = tracer.start_span(
            SPAN_EXCHANGE, parent, SpanKind.CLIENT, attrs, start_time=job.started_ns
        )
        if _is_error(job):
            span.set_status(Status(StatusCode.ERROR))
        if not self._commit(job):
            return  # already a shutdown loss: suppress the late outcome
        try:
            if not span.is_recording():  # sampled out: the sequence must not silently vanish
                self._lose(job, "span_dropped")
                return
            span.end(end_time=max(job.ended_ns, job.started_ns))
            self._stats["spans_emitted"] += 1
            self._settle_written(job, {
                "name": SPAN_EXCHANGE, "start_time_unix_nano": job.started_ns,
                "end_time_unix_nano": max(job.ended_ns, job.started_ns),
                "status": "error" if _is_error(job) else "unset", "attributes": attrs,
            })  # fmt: skip
        except Exception:  # committed: never a second outcome for this sequence
            self._stats["internal_errors"] += 1

    def _store_object(self, obj: Obj) -> bool:
        """Write one protected object to the direct store, with retries."""
        store = self._store
        if store is None:
            return False
        for delay in (*self._backoffs, None):
            try:
                ref = store.evidence_ref_for(obj.object_id)
                descriptor = {**obj.descriptor, "encoding": "binary", "ref": ref}
                result = store.put_bytes_object(descriptor, obj.data)
                if result.uri != ref or "sha256:" + result.content_hash != (
                    obj.descriptor["stored_sha256"]
                ):  # fmt: skip
                    raise ValueError("byte store returned a mismatched reference")
                return True  # resolved again through store.evidence_ref_for
            except Exception:
                if delay is None or self._closing.wait(delay):
                    break
        self._stats["store_failures"] += 1
        return False

    def _base(self, job: CaptureJob, body: CapturedBody, role: str) -> dict[str, Any]:
        """The identity fields every content-v2 descriptor of this side carries (047 §7,
        048 §3); PROTECT adds the object, representation, status and privacy fields."""
        captured_ns = job.started_ns if role == ROLE_REQUEST else job.ended_ns
        return {
            "schema_version": "fabric.content-object/v2", "tenant_id": self._tenant_id,
            "media_type": media_type_of(body.media_type),
            "content_encoding": content_encoding_of(body.content_encoding),
            "provenance": "protocol", "boundary": "provider_bound", "source_id": job.source_id,
            "source_epoch": job.source_epoch, "source_sequence": job.source_sequence,
            "captured_at": datetime.fromtimestamp(captured_ns / 1e9, UTC).isoformat(),
            "run_id": job.run_id, "operation_id": job.exchange_id,
        }  # fmt: skip


def _segment_of(job: Job) -> str | None:
    """The job's segment (050 §3.3); ``None`` outside a run and until segments exist (an
    exchange job carries one once WP-12/WP-14 add it)."""
    segment = getattr(job, "segment_id", None)
    return segment if isinstance(segment, str) else None


def _record_entry(span: Mapping[str, Any]) -> SealEntry:
    """The seal entry of a written exchange (050 §3.7): the record digest over the span,
    with the stored request and response digests, in that order, as its content."""
    attrs = span["attributes"]
    content = [f"sha256:{digest}" for key in (WireAttr.REQUEST_SHA256, WireAttr.RESPONSE_SHA256)
               if isinstance(digest := attrs.get(key), str)]  # fmt: skip
    return record_digest(
        name=span["name"], start_ns=span["start_time_unix_nano"],
        end_ns=span["end_time_unix_nano"], status=span["status"], attributes=attrs,
        content=content,
    )  # fmt: skip


def _no_budget() -> Budget | None:
    return None


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class _OverridableIds(IdGenerator):
    """The id generator of Fabric's ``fabric.records`` tracer: the provider's own, except
    while the capture worker sets a host span's ids for one ``start_span`` call (050 §3.4
    "Span ids": the record then *is* the host span's record)."""

    def __init__(self, base: IdGenerator) -> None:
        self.base, self._local = base, threading.local()

    def set(self, trace_id: int, span_id: int) -> None:
        self._local.ids = (trace_id, span_id)

    def clear(self) -> None:
        self._local.ids = None

    def generate_span_id(self) -> int:
        ids = getattr(self._local, "ids", None)
        return ids[1] if ids else self.base.generate_span_id()

    def generate_trace_id(self) -> int:
        ids = getattr(self._local, "ids", None)
        return ids[0] if ids else self.base.generate_trace_id()


def _record_parent(
    tracer: Any, ids: SpanIds | None, context: Context | None
) -> tuple[Context, _OverridableIds | None]:
    """The parent context of a provider-path record, and the id override set for its one
    ``start_span`` (cleared by the caller). Without ``span_ids``: the current span at emit.
    With them, on an SDK tracer: the host span's own ids under its parent. A tracer whose
    ids cannot be chosen (``global`` mode, K3): a child of the host span."""
    if ids is None:
        return capture_parent(context), None
    generator = getattr(tracer, "id_generator", None)
    if generator is not None and not isinstance(generator, _OverridableIds):
        with contextlib.suppress(Exception):
            generator = tracer.id_generator = _OverridableIds(generator)
    flags = TraceFlags(TraceFlags.SAMPLED)
    if isinstance(generator, _OverridableIds):
        generator.set(ids.trace_id, ids.span_id)
        if ids.parent_span_id is None:
            return Context(), generator
        parent = SpanContext(ids.trace_id, ids.parent_span_id, ids.parent_is_remote, flags)
        return trace.set_span_in_context(NonRecordingSpan(parent), Context()), generator
    host = SpanContext(ids.trace_id, ids.span_id, False, flags)
    return trace.set_span_in_context(NonRecordingSpan(host), Context()), None


def _job_bytes(job: Job) -> int:
    if isinstance(job, RecordJob):
        return job.inflight_charge
    sides = (job.request, job.response)
    return sum(side.captured_byte_length for side in sides if side is not None)


def _is_error(job: CaptureJob) -> bool:
    code = job.http_status_code
    return job.response_state == "error" or (code is not None and code >= 400)  # noqa: PLR2004


def _after_fork_in_child() -> None:
    for pipeline in list(_PIPELINES):  # the parent reports its queued jobs; the child starts empty
        with contextlib.suppress(Exception):
            closed = pipeline._closed
            pipeline._init_state()
            pipeline._closed = closed


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
