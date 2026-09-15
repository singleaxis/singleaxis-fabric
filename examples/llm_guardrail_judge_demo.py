# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""LEGACY EXAMPLE — NOT PART OF RECORDER V1.

This file demonstrates the pre-0.8 SDK surface (guardrails, policy
engines, tool authorization, escalation, and eval/judge capture). Those
APIs were removed in singleaxis-fabric 0.8; this example does not run
against the recorder SDK and is kept for historical reference only. See
examples/reference-agent/ for the recorder-v1 surface.

Small, offline Fabric demo: privacy -> guardrail -> LLM -> judge.

The demo uses in-process stand-ins so it runs without API keys, sockets,
queues, or an OTLP backend. In production, keep the Fabric calls unchanged
and replace:

* ``DemoPresidio`` with ``UDSPresidioClient`` (or ``Fabric.from_env()``),
* ``DemoSafetyGuardrail`` with Lakera/HTTP/NeMo or another checker,
* ``DemoApplicationLLM`` with the application's LLM provider, and
* ``LocalQueueTransport`` with NATS, Redis Streams, or SQS.

Run from the repository root:

    uv run --project sdk/python python examples/llm_guardrail_judge_demo.py
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import (
    CheckerVerdict,
    Fabric,
    FabricConfig,
    JudgeContext,
    JudgeRunner,
    LocalQueueTransport,
    RedactionResult,
    SimpleLLMJudge,
)

EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


class DemoPresidio:
    """Presidio-compatible redactor used only by this offline example."""

    def redact(self, path: str, value: str) -> RedactionResult:
        _ = path
        redacted, replacements = EMAIL_PATTERN.subn("<EMAIL>", value)
        return RedactionResult(
            value=redacted,
            hashed=replacements > 0,
            pii_category="EMAIL_ADDRESS" if replacements else "",
        )

    def close(self) -> None:
        return None


@dataclass(slots=True)
class DemoSafetyGuardrail:
    """GuardrailChecker-compatible prompt-injection check."""

    name: str = "demo-safety"

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        _ = phase, path
        if "ignore previous instructions" in value.lower():
            return CheckerVerdict(
                action="block",
                reason="prompt-injection phrase detected",
                rail="prompt-injection",
            )
        return CheckerVerdict(action="allow", rail="prompt-injection")

    def close(self) -> None:
        return None


class DemoApplicationLLM:
    """Stand-in for the model used by the agent application."""

    def complete(self, prompt: str) -> str:
        return f"I received the privacy-safe request: {prompt}"


class DemoJudgeLLM:
    """Separate model used by SimpleLLMJudge after the turn completes."""

    def complete(self, prompt: str) -> str:
        _ = prompt
        return "score: 0.92"


def main() -> None:
    # An in-memory exporter makes the generated trace visible in this demo.
    # Production applications export these spans to the Fabric OTel Collector.
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    judge_queue = LocalQueueTransport()
    fabric = Fabric(
        FabricConfig(tenant_id="tenant-demo", agent_id="support-demo"),
        tracer=provider.get_tracer("fabric-demo"),
        presidio=DemoPresidio(),
        guardrail_checkers=[DemoSafetyGuardrail()],
    )

    original_input = "Please send the summary to alice@example.com"
    application_llm = DemoApplicationLLM()

    with fabric.decision(session_id="session-1", request_id="request-1") as decision:
        # 1. Fabric passes the raw input through Presidio first, then through
        #    every configured guardrail. Only the returned safe value proceeds.
        safe_input = decision.guard_input(original_input)

        # 2. Fabric wraps the application's real model invocation in a GenAI
        #    child span. Fabric observes this call; it does not run the model.
        with decision.llm_call(provider="demo", model="application-llm-v1") as llm_span:
            raw_output = application_llm.complete(safe_input)
            llm_span.set_usage(
                input_tokens=len(safe_input.split()),
                output_tokens=len(raw_output.split()),
                finish_reason="stop",
            )

        # 3. The same privacy + guardrail chain inspects the final output before
        #    the application returns it to the user.
        safe_output = decision.guard_output_final(raw_output)

        # 4. Judging is normally asynchronous. The private judge context travels
        #    on the queue, while the OTel trace receives only request metadata.
        judge_request = decision.queue_judge(
            rubric_id="answer-quality-v1",
            dimensions=("helpfulness",),
            context=JudgeContext(
                user_input=safe_input,
                agent_response=safe_output,
            ),
            transport=judge_queue,
        )
        trace_id = decision.trace_id

    # This consumer runs after the request span has closed. A production judge
    # worker would consume from NATS/Redis/SQS and persist the result using the
    # request's decision_id as its correlation key.
    judge_results = []
    judge = SimpleLLMJudge(
        llm=DemoJudgeLLM(),
        prompt_template=(
            "Score the response for {dimensions}.\n"
            "Input: {user_input}\nResponse: {agent_response}"
        ),
    )
    runner = JudgeRunner(
        judge_queue,
        judge,
        result_sink=lambda request, result: judge_results.append((request, result)),
    )
    runner.run_once()

    _, result = judge_results[0]
    spans = exporter.get_finished_spans()
    decision_span = next(span for span in spans if span.name == "fabric.decision")

    print(f"original input : {original_input}")
    print(f"safe input     : {safe_input}")
    print(f"safe output    : {safe_output}")
    print(f"trace id       : {trace_id}")
    print(f"judge request  : {judge_request.request_id}")
    print(f"judge score    : {result.score:.2f}")
    print("trace spans    :", ", ".join(span.name for span in spans))
    print("decision events:", ", ".join(event.name for event in decision_span.events))

    # The privacy guarantee is part of the executable example: raw PII may be
    # inspected by Presidio, but must never appear on the exported trace.
    exported = repr(spans)
    assert "alice@example.com" not in exported
    assert safe_input == "Please send the summary to <EMAIL>"
    assert result.score == 0.92

    fabric.close()


if __name__ == "__main__":
    main()
