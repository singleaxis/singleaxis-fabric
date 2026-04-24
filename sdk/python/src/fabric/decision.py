# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The ``decision()`` context manager.

Every agent decision is wrapped in a :class:`Decision`. On enter we
open an OTel span with Fabric's standard attributes; on exit we close
it and record whether the decision succeeded, was blocked by a
guardrail, or raised. The guardrail methods raise
:class:`~fabric.guardrails.GuardrailNotConfiguredError` if no rails
are configured — silent pass-through is a compliance footgun.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from types import TracebackType
from typing import TYPE_CHECKING, Self

from opentelemetry.trace import SpanKind, Status, StatusCode

from .escalation import EscalationRequested, EscalationSummary
from .guardrails import (
    GuardrailBlocked,
    GuardrailNotConfiguredError,
    GuardrailPhase,
    GuardrailResult,
)
from .memory import MemoryKind, MemoryRecord
from .retrieval import RetrievalRecord, RetrievalSource

if TYPE_CHECKING:
    from collections.abc import Sequence

    from opentelemetry.trace import Span

    from .client import Fabric

SPAN_NAME = "fabric.decision"

ATTR_TENANT = "fabric.tenant_id"
ATTR_AGENT = "fabric.agent_id"
ATTR_PROFILE = "fabric.profile"
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
        if self._blocked is not None:
            self._span.set_attribute(ATTR_BLOCKED, True)
            if self._blocked.policies_fired:
                self._span.set_attribute(ATTR_BLOCK_POLICIES, tuple(self._blocked.policies_fired))
            self._span.set_status(Status(StatusCode.ERROR, description="guardrail_blocked"))
        elif isinstance(exc, EscalationRequested):
            # Escalation is flow control, not a crash. Tag the span
            # clearly but don't dump a stack into span events.
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

        Hosts that prefer an exception-driven flow can call
        ``raise_for_block`` after this to abort the decision with the
        canned block response attached.
        """
        if not result.blocked:
            raise ValueError("record_block called with a non-blocking GuardrailResult")
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
        """

        span = self.span
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

    # -- OTel passthrough -------------------------------------------------

    def set_attribute(self, key: str, value: str | int | float | bool) -> None:
        """Set a custom attribute on the active decision span."""
        self.span.set_attribute(key, value)
