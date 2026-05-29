# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Deterministic, self-contained benchmark scenarios for the Fabric SDK.

Every scenario exercises a real hot path with a real (non-noop)
``TracerProvider`` feeding an ``InMemorySpanExporter``, so the span
machinery (attribute setting, event recording, hashing) is actually run
— but nothing leaves the process. The exporter is cleared after each
scenario call so memory does not grow unbounded across iterations.

All rails are no-dependency doubles (a stub guardrail checker, stub
policy engine, stub tool authorizer): no Presidio / NeMo / LLM /
network. Inputs are fixed so successive runs are comparable.
"""

from __future__ import annotations

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric.client import Fabric, FabricConfig
from fabric.decision import Decision
from fabric.guardrails import CheckerVerdict
from fabric.policy import EngineVerdict
from fabric.tool_auth import ToolAuthorization

from ._harness import Scenario

# Fixed scenario inputs — kept constant so timings are comparable run to
# run and no per-iteration allocation/formatting skews the measurement.
_SESSION_ID = "bench-session"
_REQUEST_ID = "bench-request"
_SAMPLE_TEXT = "the quick brown fox jumps over the lazy dog " * 4
_STREAM_CHUNK = "lorem ipsum dolor sit amet "
_STREAM_CHUNK_COUNT = 40
_TAIL_WINDOW = 64
_POLICY_INPUT: dict[str, object] = {"action": "read", "resource": "doc-42", "role": "agent"}


class _AllowChecker:
    """A guardrail checker that always allows, with no rewrite.

    Structurally satisfies :class:`fabric.guardrails.GuardrailChecker`.
    Returns a cached verdict so the benchmark measures chain plumbing,
    not verdict construction.
    """

    name = "bench-allow"
    _VERDICT = CheckerVerdict(action="allow")

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        return self._VERDICT

    def close(self) -> None:
        return None


class _AllowPolicyEngine:
    """A policy engine that always returns an allow verdict.

    Structurally satisfies :class:`fabric.policy.PolicyEngine`.
    """

    engine_name = "bench-engine"
    _VERDICT = EngineVerdict(decision="allow")

    def evaluate(
        self,
        *,
        policy_id: str,
        input: dict[str, object],
        timeout_seconds: float,
    ) -> EngineVerdict:
        return self._VERDICT

    def close(self) -> None:
        return None


class _AllowToolAuthorizer:
    """A tool authorizer that always allows.

    Structurally satisfies :class:`fabric.tool_auth.ToolAuthorizer`.
    """

    _AUTH = ToolAuthorization(decision="allow")

    def authorize(self, *, tool_name: str, arguments_hash: str | None) -> ToolAuthorization:
        return self._AUTH


class BenchmarkFixture:
    """The shared, reusable benchmark environment.

    A real ``TracerProvider`` + ``SimpleSpanProcessor`` is used so span
    work is genuinely exercised; the ``InMemorySpanExporter`` keeps
    everything in-process. A stub guardrail checker is wired so the
    guard-input chain has a rail (otherwise it would raise
    ``GuardrailNotConfiguredError``). Each scenario clears the exporter
    so retained spans do not grow memory across iterations.
    """

    def __init__(self) -> None:
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        config = FabricConfig(tenant_id="bench-tenant", agent_id="bench-agent")
        self._exporter = exporter
        self._tracer = provider.get_tracer("fabric.benchmarks")
        self._fabric = Fabric(config, tracer=self._tracer, guardrail_checkers=[_AllowChecker()])
        self._policy_engine = _AllowPolicyEngine()
        self._tool_authorizer = _AllowToolAuthorizer()

    def _decision(self) -> Decision:
        return self._fabric.decision(session_id=_SESSION_ID, request_id=_REQUEST_ID)

    def baseline_bare_span(self) -> None:
        """No-op floor: a bare tracer span with no Fabric attributes."""
        with self._tracer.start_as_current_span("baseline"):
            pass
        self._exporter.clear()

    def decision_enter_exit(self) -> None:
        with self._decision():
            pass
        self._exporter.clear()

    def decision_guard_input(self) -> None:
        with self._decision() as d:
            d.guard_input(_SAMPLE_TEXT)
        self._exporter.clear()

    def decision_record_retrieval(self) -> None:
        with self._decision() as d:
            d.record_retrieval("rag", query=_SAMPLE_TEXT, result_count=5)
        self._exporter.clear()

    def decision_remember(self) -> None:
        with self._decision() as d:
            d.remember(kind="semantic", content=_SAMPLE_TEXT, key="k")
        self._exporter.clear()

    def decision_record_side_effect(self) -> None:
        with self._decision() as d:
            d.record_side_effect(
                "database_write",
                target_system="crm",
                operation="upsert",
                request_payload=_SAMPLE_TEXT,
            )
        self._exporter.clear()

    def decision_evaluate_policy(self) -> None:
        with self._decision() as d:
            d.evaluate_policy(self._policy_engine, policy_id="p1", input=_POLICY_INPUT)
        self._exporter.clear()

    def decision_authorize_tool_call(self) -> None:
        with self._decision() as d:
            d.authorize_tool_call(self._tool_authorizer, tool_name="search", arguments=_SAMPLE_TEXT)
        self._exporter.clear()

    def decision_llm_call(self) -> None:
        with self._decision() as d, d.llm_call(system="anthropic", model="claude") as call:
            call.set_usage(input_tokens=100, output_tokens=50, finish_reason="stop")
        self._exporter.clear()

    def decision_tool_call(self) -> None:
        with self._decision() as d, d.tool_call("vector_search") as tool:
            tool.set_arguments(_SAMPLE_TEXT)
            tool.set_result(_SAMPLE_TEXT)
        self._exporter.clear()

    def decision_stream_redactor(self) -> None:
        with self._decision() as d:
            redactor = d.output_stream(tail_window=_TAIL_WINDOW)
            for _ in range(_STREAM_CHUNK_COUNT):
                redactor.feed(_STREAM_CHUNK)
            redactor.flush()
        self._exporter.clear()


def build_scenarios() -> list[Scenario]:
    """Build the ordered list of benchmark scenarios."""
    fx = BenchmarkFixture()
    return [
        Scenario("baseline: bare tracer span", fx.baseline_bare_span),
        Scenario("decision: enter+exit", fx.decision_enter_exit),
        Scenario("decision + guard_input", fx.decision_guard_input),
        Scenario("decision + record_retrieval", fx.decision_record_retrieval),
        Scenario("decision + remember", fx.decision_remember),
        Scenario("decision + record_side_effect", fx.decision_record_side_effect),
        Scenario("decision + evaluate_policy", fx.decision_evaluate_policy),
        Scenario("decision + authorize_tool_call", fx.decision_authorize_tool_call),
        Scenario("decision + llm_call (+set_usage)", fx.decision_llm_call),
        Scenario("decision + tool_call (args+result hash)", fx.decision_tool_call),
        Scenario("StreamRedactor: 40 chunks + flush", fx.decision_stream_redactor),
    ]
