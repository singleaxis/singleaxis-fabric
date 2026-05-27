# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The ``decision()`` context manager.

Every agent decision is wrapped in a :class:`Decision`. On enter we
open an OTel span with Fabric's standard attributes; on exit we close
it and record whether the decision succeeded, was blocked by a
guardrail, or raised. The guardrail methods raise
:class:`~fabric.guardrails.GuardrailNotConfiguredError` if no rails
are configured — silent pass-through is a compliance footgun.

Concurrency contract
--------------------

A :class:`Decision` instance represents a single agent turn and is
**not** safe to share across threads or asyncio tasks. Open one
``Decision`` per agent turn; do not pass the same instance into
parallel coroutines or workers.

Mutation methods on a single ``Decision`` (``record_retrieval``,
``remember``, ``record_side_effect``, ``request_escalation``,
``set_attribute``, ``guard_input``, ``guard_output_chunk``,
``guard_output_final``) are **not** internally synchronized. The
rolling counter attributes (``fabric.retrieval_count``,
``fabric.memory_write_count``, ``fabric.side_effect_count``) and the
internal lists they update would race under concurrent access. The
``Fabric`` client itself is safe to share — only ``Decision`` instances
have this constraint.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from types import TracebackType
from typing import TYPE_CHECKING, Self
from uuid import uuid4

from opentelemetry.trace import SpanKind, Status, StatusCode

from ._calls import LLMCall, ToolCall
from ._id_validators import warn_if_pii_shaped
from .escalation import EscalationRequested, EscalationSummary
from .guardrails import (
    GuardrailBlocked,
    GuardrailNotConfiguredError,
    GuardrailPhase,
    GuardrailResult,
)
from .judge import (
    JudgeContext,
    JudgeRequest,
    QueueTransport,
)
from .memory import MemoryKind, MemoryRecord
from .retrieval import RetrievalRecord, RetrievalSource
from .side_effect import ReplayBehavior, SideEffectRecord, SideEffectType

if TYPE_CHECKING:
    from collections.abc import Sequence

    from opentelemetry.trace import Span

    from .client import Fabric

SPAN_NAME = "fabric.decision"

ATTR_TENANT = "fabric.tenant_id"
ATTR_AGENT = "fabric.agent_id"
ATTR_PROFILE = "fabric.profile"
ATTR_WORKFLOW = "fabric.workflow_id"
ATTR_EXECUTION = "fabric.execution_id"
ATTR_SESSION = "fabric.session_id"
ATTR_REQUEST = "fabric.request_id"
ATTR_USER = "fabric.user_id"
ATTR_BLOCKED = "fabric.blocked"
ATTR_BLOCK_POLICIES = "fabric.blocked.policies"
ATTR_ESCALATED = "fabric.escalated"
ATTR_ESC_REASON = "fabric.escalation.reason"
ATTR_ESC_RUBRIC = "fabric.escalation.rubric_id"
ATTR_ESC_MODE = "fabric.escalation.mode"
ATTR_ESC_SCORE = "fabric.escalation.triggering_score"
ATTR_RETRIEVAL_COUNT = "fabric.retrieval_count"
ATTR_RETRIEVAL_SOURCES = "fabric.retrieval_sources"
ATTR_MEMORY_WRITE_COUNT = "fabric.memory_write_count"
ATTR_MEMORY_KINDS = "fabric.memory_kinds"
ATTR_SIDE_EFFECT_COUNT = "fabric.side_effect_count"
ATTR_SIDE_EFFECT_TYPES = "fabric.side_effect_types"
ATTR_SIDE_EFFECT_SYSTEMS = "fabric.side_effect_systems"
ATTR_JUDGE_QUEUED_COUNT = "fabric.judge_queued_count"
ATTR_JUDGE_RUBRICS = "fabric.judge_rubrics"


class Decision(AbstractContextManager["Decision"]):
    """Per-agent-call context. Enter once, exit once."""

    def __init__(
        self,
        *,
        client: Fabric,
        session_id: str,
        request_id: str,
        user_id: str | None,
        attributes: dict[str, str],
    ) -> None:
        if not session_id:
            raise ValueError("session_id is required")
        if not request_id:
            raise ValueError("request_id is required")
        # PII shape warnings on per-turn identifiers. These attach to
        # every emitted span; flagging email/phone shapes once per
        # process keeps a quiet leak loud. See specs/016 §4.5.
        warn_if_pii_shaped("session_id", session_id)
        warn_if_pii_shaped("request_id", request_id)
        warn_if_pii_shaped("user_id", user_id)
        self._client = client
        self._session_id = session_id
        self._request_id = request_id
        self._user_id = user_id
        self._extra_attrs = dict(attributes)
        self._span: Span | None = None
        self._cm: AbstractContextManager[Span] | None = None
        self._blocked: GuardrailResult | None = None
        self._escalation: EscalationSummary | None = None
        self._retrievals: list[RetrievalRecord] = []
        self._memory_writes: list[MemoryRecord] = []
        self._side_effects: list[SideEffectRecord] = []
        self._judge_requests: list[JudgeRequest] = []

    # -- context manager --------------------------------------------------

    def __enter__(self) -> Self:
        tracer = self._client.tracer
        # We own status + exception recording (guardrail blocks,
        # escalations, and raw exceptions each get distinct treatment),
        # so turn off the tracer's auto-record to avoid it clobbering
        # our deliberate status descriptions.
        self._cm = tracer.start_as_current_span(
            SPAN_NAME,
            kind=SpanKind.INTERNAL,
            record_exception=False,
            set_status_on_exception=False,
        )
        self._span = self._cm.__enter__()
        self._span.set_attribute(ATTR_TENANT, self._client.tenant_id)
        self._span.set_attribute(ATTR_AGENT, self._client.agent_id)
        self._span.set_attribute(ATTR_PROFILE, self._client.profile)
        if self._client.config.workflow_id is not None:
            self._span.set_attribute(ATTR_WORKFLOW, self._client.config.workflow_id)
        if self._client.config.execution_id is not None:
            self._span.set_attribute(ATTR_EXECUTION, self._client.config.execution_id)
        self._span.set_attribute(ATTR_SESSION, self._session_id)
        self._span.set_attribute(ATTR_REQUEST, self._request_id)
        if self._user_id is not None:
            self._span.set_attribute(ATTR_USER, self._user_id)
        for key, value in self._extra_attrs.items():
            self._span.set_attribute(key, value)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        if self._span is None or self._cm is None:  # pragma: no cover
            return None
        # Status precedence: blocked + escalated should not silently
        # collapse to one signal. Tag attributes from each outcome
        # independently, then pick a status description that names
        # both when both are present so the audit trail can't lose
        # the escalation behind a block status.
        is_blocked = self._blocked is not None
        is_escalation = isinstance(exc, EscalationRequested) or self._escalation is not None
        if is_blocked:
            self._span.set_attribute(ATTR_BLOCKED, True)
            if self._blocked is not None and self._blocked.policies_fired:
                self._span.set_attribute(ATTR_BLOCK_POLICIES, tuple(self._blocked.policies_fired))
        if is_blocked and is_escalation:
            self._span.set_status(Status(StatusCode.ERROR, description="blocked_and_escalated"))
        elif is_blocked:
            self._span.set_status(Status(StatusCode.ERROR, description="guardrail_blocked"))
        elif is_escalation:
            self._span.set_status(Status(StatusCode.ERROR, description="escalation_requested"))
        elif exc is not None:
            self._span.set_status(Status(StatusCode.ERROR, description=type(exc).__name__))
            self._span.record_exception(exc)
        result = self._cm.__exit__(exc_type, exc, tb)
        self._span = None
        self._cm = None
        return result

    # -- introspection ----------------------------------------------------

    @property
    def span(self) -> Span:
        """The live OTel span. Raises if the context has not entered."""
        if self._span is None:
            raise RuntimeError("Decision has not been entered")
        return self._span

    @property
    def trace_id(self) -> str:
        """Hex-formatted trace id for cross-system correlation."""
        ctx = self.span.get_span_context()
        return f"{ctx.trace_id:032x}"

    @property
    def request_id(self) -> str:
        return self._request_id

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def blocked(self) -> GuardrailResult | None:
        """The blocking guardrail result, or ``None`` if none fired."""
        return self._blocked

    @property
    def escalation(self) -> EscalationSummary | None:
        """The recorded escalation, or ``None`` if none requested."""
        return self._escalation

    @property
    def retrievals(self) -> tuple[RetrievalRecord, ...]:
        """All retrievals recorded on this decision, in emission order."""
        return tuple(self._retrievals)

    @property
    def memory_writes(self) -> tuple[MemoryRecord, ...]:
        """All memory writes recorded on this decision, in emission order."""
        return tuple(self._memory_writes)

    @property
    def side_effects(self) -> tuple[SideEffectRecord, ...]:
        """All external mutations recorded on this decision, in emission order."""
        return tuple(self._side_effects)

    # -- guardrail entry points ------------------------------------------
    #
    # All three delegate to the :class:`GuardrailChain` configured on
    # the :class:`Fabric` client. If no chain is configured we fail
    # loud (``GuardrailNotConfiguredError``) rather than silently pass
    # content through — a silent pass-through is a compliance footgun.

    def guard_input(self, raw_input: str) -> str:
        """Check and redact user input before it reaches the LLM."""
        return self._run_chain(phase="input", path="input", value=raw_input)

    def guard_output_chunk(self, chunk: str) -> str:
        """Redact a streaming output chunk."""
        return self._run_chain(phase="output_stream", path="output_chunk", value=chunk)

    def guard_output_final(self, final_output: str) -> str:
        """Run the post-stream full-text guardrail pass."""
        return self._run_chain(phase="output_final", path="output_final", value=final_output)

    def _run_chain(self, *, phase: GuardrailPhase, path: str, value: str) -> str:
        chain = self._client.guardrail_chain
        if not chain.has_rails:
            raise GuardrailNotConfiguredError(f"no guardrail rails configured for phase={phase!r}")
        result = chain.check(phase=phase, path=path, value=value)
        self._record_guardrail_event(phase=phase, result=result)
        return result.redacted_content

    def _record_guardrail_event(self, *, phase: GuardrailPhase, result: GuardrailResult) -> None:
        """Emit the guardrail event as a span event per spec 005."""
        span = self.span
        attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
            "fabric.guardrail.phase": phase,
            "fabric.guardrail.latency_ms": result.latency_ms,
            "fabric.guardrail.blocked": result.blocked,
        }
        if result.entities_detected:
            attrs["fabric.guardrail.entities"] = tuple(
                f"{e.category}:{e.count}" for e in result.entities_detected
            )
        if result.policies_fired:
            attrs["fabric.guardrail.policies"] = tuple(result.policies_fired)
        span.add_event("fabric.guardrail", attributes=attrs)

    # -- block handling ---------------------------------------------------

    def record_block(self, result: GuardrailResult) -> None:
        """Record a blocking guardrail outcome on the span.

        First-wins: the first block recorded becomes ``self.blocked``.
        Subsequent calls raise :class:`RuntimeError` rather than
        silently overwriting; downstream consumers (graphs, audits)
        rely on a single canonical block per Decision. Host code that
        wants to record multiple guardrail outcomes should use the
        chain's own per-rail span events (already emitted) and call
        ``record_block`` only for the final, canonical block.

        Hosts that prefer an exception-driven flow can call
        ``raise_for_block`` after this to abort the decision with the
        canned block response attached.
        """
        if not result.blocked:
            raise ValueError("record_block called with a non-blocking GuardrailResult")
        if self._blocked is not None:
            raise RuntimeError(
                "Decision is already blocked; record_block is first-wins. "
                "Call only once per Decision."
            )
        self._blocked = result

    def raise_for_block(self) -> None:
        """Raise :class:`GuardrailBlocked` if a block is recorded."""
        if self._blocked is not None:
            raise GuardrailBlocked(self._blocked)

    # -- escalation -------------------------------------------------------

    def request_escalation(self, summary: EscalationSummary) -> None:
        """Record that this decision should be escalated for human review.

        Tags the span and emits a ``fabric.escalation`` span event so
        downstream consumers (judge workers, escalation service) can
        pick it up. Does **not** raise on its own — the SDK leaves
        flow control to the host, which typically pairs this with
        :meth:`raise_for_escalation` and its framework's interrupt.

        First-wins: the first escalation recorded becomes
        ``self.escalation``. Subsequent calls raise :class:`RuntimeError`
        rather than silently overwriting attributes and emitting a
        second event. Aggregation of multiple escalation reasons should
        be done in the caller's :class:`EscalationSummary` (e.g. comma-
        joined ``reason``) before the single ``request_escalation``
        call.
        """

        span = self.span
        if self._escalation is not None:
            raise RuntimeError(
                "Decision already has an escalation requested; request_escalation "
                "is first-wins. Call only once per Decision."
            )
        self._escalation = summary
        span.set_attribute(ATTR_ESCALATED, True)
        span.set_attribute(ATTR_ESC_REASON, summary.reason)
        span.set_attribute(ATTR_ESC_MODE, summary.mode)
        if summary.rubric_id is not None:
            span.set_attribute(ATTR_ESC_RUBRIC, summary.rubric_id)
        if summary.triggering_score is not None:
            span.set_attribute(ATTR_ESC_SCORE, summary.triggering_score)

        event_attrs: dict[str, str | int | float | bool] = {
            "fabric.escalation.reason": summary.reason,
            "fabric.escalation.mode": summary.mode,
        }
        if summary.rubric_id is not None:
            event_attrs["fabric.escalation.rubric_id"] = summary.rubric_id
        if summary.triggering_score is not None:
            event_attrs["fabric.escalation.triggering_score"] = summary.triggering_score
        span.add_event("fabric.escalation", attributes=event_attrs)

    def raise_for_escalation(self) -> None:
        """Raise :class:`EscalationRequested` if an escalation is recorded."""
        if self._escalation is not None:
            raise EscalationRequested(self._escalation)

    # -- retrieval --------------------------------------------------------

    def record_retrieval(
        self,
        source: RetrievalSource | str,
        *,
        query: str,
        result_count: int,
        result_hashes: Sequence[str] | None = None,
        source_document_ids: Sequence[str] | None = None,
        latency_ms: int | None = None,
    ) -> RetrievalRecord:
        """Record a retrieval event on the decision span.

        The tenant agent performs the actual retrieval (RAG, KG, SQL,
        tool, memory). This method captures the allowlisted metadata
        — source enum, SHA-256 of the query, counts, caller-supplied
        document ids — as a ``fabric.retrieval`` span event. It also
        updates rolling ``fabric.retrieval_count`` and
        ``fabric.retrieval_sources`` attributes on the decision span
        so the Telemetry Bridge can fold them into the
        ``DecisionSummary`` wire event without replaying every event.

        Raw query text is hashed locally and is never placed on the
        span.
        """

        record = RetrievalRecord.from_query(
            source=source,
            query=query,
            result_count=result_count,
            result_hashes=result_hashes,
            source_document_ids=source_document_ids,
            latency_ms=latency_ms,
        )
        span = self.span
        self._retrievals.append(record)
        span.set_attribute(ATTR_RETRIEVAL_COUNT, len(self._retrievals))
        unique_sources = sorted({r.source.value for r in self._retrievals})
        span.set_attribute(ATTR_RETRIEVAL_SOURCES, tuple(unique_sources))

        event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
            "fabric.retrieval.source": record.source.value,
            "fabric.retrieval.query_hash": record.query_hash,
            "fabric.retrieval.result_count": record.result_count,
        }
        if record.result_hashes:
            event_attrs["fabric.retrieval.result_hashes"] = record.result_hashes
        if record.source_document_ids:
            event_attrs["fabric.retrieval.source_document_ids"] = record.source_document_ids
        if record.latency_ms is not None:
            event_attrs["fabric.retrieval.latency_ms"] = record.latency_ms
        span.add_event("fabric.retrieval", attributes=event_attrs)
        return record

    # -- memory ----------------------------------------------------------

    def remember(
        self,
        *,
        kind: MemoryKind | str,
        content: str,
        key: str | None = None,
        tags: Sequence[str] | None = None,
        ttl_seconds: int | None = None,
    ) -> MemoryRecord:
        """Record that this decision wrote to long-term memory.

        The tenant agent performs the actual memory write (vector
        store, KV, KG). This method captures allowlisted metadata
        — kind, SHA-256 of the content, caller-supplied key/tags/TTL
        — as a ``fabric.memory`` span event. Rolling
        ``fabric.memory_write_count`` and ``fabric.memory_kinds``
        attributes are kept on the decision span so the Telemetry
        Bridge can fold them into the ``DecisionSummary`` wire event
        without replaying every event.

        Raw content is hashed locally and is never placed on the
        span.
        """

        record = MemoryRecord.from_content(
            kind=kind,
            content=content,
            key=key,
            tags=tags,
            ttl_seconds=ttl_seconds,
        )
        span = self.span
        self._memory_writes.append(record)
        span.set_attribute(ATTR_MEMORY_WRITE_COUNT, len(self._memory_writes))
        unique_kinds = sorted({r.kind.value for r in self._memory_writes})
        span.set_attribute(ATTR_MEMORY_KINDS, tuple(unique_kinds))

        event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
            "fabric.memory.kind": record.kind.value,
            "fabric.memory.content_hash": record.content_hash,
        }
        if record.key is not None:
            event_attrs["fabric.memory.key"] = record.key
        if record.tags:
            event_attrs["fabric.memory.tags"] = record.tags
        if record.ttl_seconds is not None:
            event_attrs["fabric.memory.ttl_seconds"] = record.ttl_seconds
        span.add_event("fabric.memory", attributes=event_attrs)
        return record

    # -- side effects ----------------------------------------------------

    def record_side_effect(
        self,
        effect_type: SideEffectType | str,
        *,
        target_system: str,
        operation: str,
        request_payload: str | None = None,
        result_payload: str | None = None,
        request_hash: str | None = None,
        result_hash: str | None = None,
        idempotency_key: str | None = None,
        approval_required: bool = False,
        committed: bool = True,
        rollback_supported: bool = False,
        replay_behavior: ReplayBehavior | str = ReplayBehavior.SUPPRESS,
    ) -> SideEffectRecord:
        """Record an external mutation caused by this decision.

        Use this for tool calls that mutate state outside the agent
        process: CRM writes, ticket creation, email sends, database
        writes, payments, file writes, and similar operations.

        Raw request/result payloads are hashed locally. If the host has
        already produced hashes, pass ``request_hash`` / ``result_hash``
        instead. Supplying both raw payload and precomputed hash for the
        same field is rejected to avoid ambiguous evidence.
        """

        if request_payload is not None and request_hash is not None:
            raise ValueError("pass either request_payload or request_hash, not both")
        if result_payload is not None and result_hash is not None:
            raise ValueError("pass either result_payload or result_hash, not both")
        if request_payload is not None or result_payload is not None:
            record = SideEffectRecord.from_payloads(
                effect_type=effect_type,
                target_system=target_system,
                operation=operation,
                request_payload=request_payload,
                result_payload=result_payload,
                idempotency_key=idempotency_key,
                approval_required=approval_required,
                committed=committed,
                rollback_supported=rollback_supported,
                replay_behavior=replay_behavior,
            )
        else:
            record = SideEffectRecord(
                effect_type=SideEffectType(effect_type),
                target_system=target_system,
                operation=operation,
                request_hash=request_hash,
                result_hash=result_hash,
                idempotency_key=idempotency_key,
                approval_required=approval_required,
                committed=committed,
                rollback_supported=rollback_supported,
                replay_behavior=ReplayBehavior(replay_behavior),
            )

        span = self.span
        self._side_effects.append(record)
        span.set_attribute(ATTR_SIDE_EFFECT_COUNT, len(self._side_effects))
        unique_types = sorted({r.effect_type.value for r in self._side_effects})
        unique_systems = sorted({r.target_system for r in self._side_effects})
        span.set_attribute(ATTR_SIDE_EFFECT_TYPES, tuple(unique_types))
        span.set_attribute(ATTR_SIDE_EFFECT_SYSTEMS, tuple(unique_systems))

        event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
            "fabric.side_effect.type": record.effect_type.value,
            "fabric.side_effect.target_system": record.target_system,
            "fabric.side_effect.operation": record.operation,
            "fabric.side_effect.approval_required": record.approval_required,
            "fabric.side_effect.committed": record.committed,
            "fabric.side_effect.rollback_supported": record.rollback_supported,
            "fabric.side_effect.replay_behavior": record.replay_behavior.value,
        }
        if record.request_hash is not None:
            event_attrs["fabric.side_effect.request_hash"] = record.request_hash
        if record.result_hash is not None:
            event_attrs["fabric.side_effect.result_hash"] = record.result_hash
        if record.idempotency_key is not None:
            event_attrs["fabric.side_effect.idempotency_key"] = record.idempotency_key
        span.add_event("fabric.side_effect", attributes=event_attrs)
        return record

    # -- judge queue -----------------------------------------------------

    def queue_judge(
        self,
        *,
        rubric_id: str,
        dimensions: tuple[str, ...] | list[str],
        context: JudgeContext,
        transport: QueueTransport,
        payload_ref: str | None = None,
    ) -> JudgeRequest:
        """Forward a judge request to the queue transport.

        Emits a ``fabric.judge.queued`` span event with rubric_id,
        dimensions, and optional payload_ref. **No content** lands on
        the trace stream — the JudgeContext travels exclusively via the
        transport.

        Args:
            rubric_id: opaque identifier of the rubric to score against.
            dimensions: which rubric dimensions to score.
            context: the bundle the judge will evaluate.
            transport: queue transport. Use LocalQueueTransport for
                tests/dev; tenant-supplied adapter for production.
            payload_ref: optional tenant-side URI for the full request
                payload (when context lives in a tenant store).

        Raises:
            ValueError: if rubric_id is empty or dimensions is empty.

        Returns:
            The JudgeRequest that was enqueued.
        """
        if not rubric_id or not rubric_id.strip():
            raise ValueError("rubric_id must be non-empty")
        dim_tuple = tuple(dimensions)
        if not dim_tuple:
            raise ValueError("at least one dimension required")

        request = JudgeRequest(
            request_id=uuid4(),
            decision_id=self._request_id,
            rubric_id=rubric_id.strip(),
            dimensions=dim_tuple,
            context=context,
            payload_ref=payload_ref,
        )

        transport.enqueue(request)
        self._judge_requests.append(request)

        span = self.span
        span.set_attribute(ATTR_JUDGE_QUEUED_COUNT, len(self._judge_requests))
        unique_rubrics = sorted({r.rubric_id for r in self._judge_requests})
        span.set_attribute(ATTR_JUDGE_RUBRICS, tuple(unique_rubrics))

        event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
            "fabric.judge.request_id": str(request.request_id),
            "fabric.judge.rubric_id": request.rubric_id,
            "fabric.judge.dimensions": dim_tuple,
        }
        if payload_ref is not None:
            event_attrs["fabric.judge.payload_ref"] = payload_ref

        span.add_event("fabric.judge.queued", attributes=event_attrs)
        return request

    def snapshot_context(self) -> JudgeContext:
        """Build a JudgeContext from this decision's accumulated state.

        Pulls in whatever the decision has recorded so far — retrievals
        (source_document_ids only; queries were hashed), memory writes
        (keys only). The caller is responsible for attaching
        ``user_input`` and ``agent_response`` to the returned context;
        the SDK never sees the raw user message on the request path
        because Presidio hashes it.

        Returns:
            A JudgeContext with retrieval_docs and memory_reads
            populated from the decision's state. All other fields
            default to None / empty; the caller fills them in.
        """
        retrieval_docs: list[str] = []
        for r in self._retrievals:
            if r.source_document_ids:
                retrieval_docs.extend(r.source_document_ids)

        return JudgeContext(
            retrieval_docs=tuple(retrieval_docs),
            memory_reads=(),
        )

    # -- child spans (LLM call / tool call) ------------------------------

    def llm_call(
        self,
        *,
        system: str,
        model: str,
        temperature: float | None = None,
        top_p: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMCall:
        """Open a child span for one LLM API call.

        Returns an :class:`~fabric._calls.LLMCall` context manager that
        opens ``fabric.llm_call`` (kind=CLIENT) under the current
        decision span. The child span is populated with the
        OpenTelemetry GenAI semantic conventions (``gen_ai.system``,
        ``gen_ai.request.model``, etc.) and the matching ``fabric.llm.*``
        mirrors so dashboards keyed on either namespace render
        natively.

        Usage::

            with decision.llm_call(system="anthropic", model="claude-opus-4-7") as call:
                response = anthropic_client.messages.create(...)
                call.set_usage(
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    finish_reason=response.stop_reason,
                )

        Concurrency: do not nest ``llm_call`` invocations inside one
        another (the OTel current-span context will mis-parent the
        inner one).
        """
        # Ensure the decision is open so the child span parents
        # correctly.
        _ = self.span
        return LLMCall(
            tracer=self._client.tracer,
            system=system,
            model=model,
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_tokens,
        )

    def tool_call(self, name: str, *, call_id: str | None = None) -> ToolCall:
        """Open a child span for one tool / function call.

        Returns a :class:`~fabric._calls.ToolCall` context manager that
        opens ``fabric.tool_call`` (kind=INTERNAL) under the current
        decision span. The child span is populated with
        ``gen_ai.tool.name`` and ``fabric.tool.name`` (plus optional
        ``call.id`` if supplied).

        Usage::

            with decision.tool_call("vector_search") as tool:
                results = my_vector_db.query(...)
                tool.set_result_count(len(results))
        """
        _ = self.span
        return ToolCall(
            tracer=self._client.tracer,
            name=name,
            call_id=call_id,
        )

    # -- OTel passthrough -------------------------------------------------

    def set_attribute(self, key: str, value: str | int | float | bool) -> None:
        """Set a custom attribute on the active decision span.

        Validates that ``value`` is one of the OTel-supported scalar
        types (``str``, ``int``, ``float``, ``bool``). Passing a dict,
        list, or ``None`` raises :class:`TypeError` with the offending
        key — OTel itself silently drops unsupported types or warns
        depending on SDK configuration; the SDK fails loud instead.
        """
        # bool first because isinstance(True, int) is True
        if not isinstance(value, (bool, str, int, float)):
            raise TypeError(
                f"set_attribute({key!r}, ...): value must be str/int/float/bool, "
                f"got {type(value).__name__}"
            )
        self.span.set_attribute(key, value)
