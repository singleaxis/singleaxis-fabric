# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric-reference-agent`` CLI.

Runs one reference-agent turn on the recorder-v1 capture surface and
prints the outcome as JSON. Pass ``--verbose`` to watch each recorded
step as it happens.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field

from fabric import (
    Fabric,
    FabricConfig,
    MemoryKind,
    RetrievalSource,
    install_default_provider,
)

from .agent import _sha256_hex, simulated_llm_call


def _install_local_tracer() -> None:
    """Install a no-export tracer so ``trace_id`` is a real 32-hex
    value rather than the all-zeros sentinel returned by the OTel
    no-op default. Real telemetry export is the host's responsibility;
    this just gets a real ID into the example's JSON output.
    """
    install_default_provider(
        service_name="fabric-reference-agent",
        # No exporter — spans go nowhere; we just need real IDs.
        # For real telemetry pass an OTLPSpanExporter or
        # ConsoleSpanExporter here.
        exporter=None,
    )


@dataclass(slots=True)
class TurnResult:
    """What one ``run_one_turn`` call returns."""

    response: str
    trace_id: str
    event_counts: dict[str, int] = field(default_factory=dict)


def run_one_turn(
    *,
    prompt: str,
    tenant_id: str = "tenant-demo",
    agent_id: str = "reference-agent",
    session_id: str = "sess-demo",
    request_id: str = "req-demo",
    user_id: str | None = None,
    workflow_id: str | None = None,
    execution_id: str | None = None,
    verbose: bool = False,
) -> TurnResult:
    """Run one decision that touches the recorder-v1 capture surface.

    Per turn:

    1. Open ``Fabric.decision(...)``
    2. ``record_retrieval`` (RAG simulation; query hashed locally)
    3. ``llm_call`` wrapping a simulated LLM
    4. ``tool_call`` wrapping a simulated tool invocation
    5. ``remember`` the response in episodic memory
    6. ``record_side_effect`` for the notification
    7. ``checkpoint`` after the turn

    Returns a :class:`TurnResult` with the response, trace_id, and
    per-event-type counts read from span attributes the SDK maintains.
    """
    config = FabricConfig(
        tenant_id=tenant_id,
        agent_id=agent_id,
        workflow_id=workflow_id,
        execution_id=execution_id,
    )
    fabric = Fabric(config)

    def _say(msg: str) -> None:
        if verbose:
            print(msg)

    with fabric.decision(
        session_id=session_id,
        request_id=request_id,
        user_id=user_id,
    ) as decision:
        decision.record_retrieval(
            RetrievalSource.RAG,
            query=prompt,
            result_count=2,
            result_hashes=tuple(_sha256_hex(doc) for doc in ("doc-1", "doc-2")),
            source_document_ids=("doc-1", "doc-2"),
            latency_ms=11,
        )
        _say("retrieval: 2 docs from RAG")

        with decision.llm_call(
            provider="simulated",
            model="reference-agent-stub-v1",
        ) as call:
            response = simulated_llm_call(prompt)
            call.set_usage(
                input_tokens=len(prompt.split()),
                output_tokens=len(response.split()),
                finish_reason="stop",
            )
        _say(f"llm_call: model=reference-agent-stub-v1 → {len(response)} chars")

        with decision.tool_call("respond_to_user", call_id="call-0001") as tool:
            tool.set_arguments('{"channel": "chat"}')
            tool.set_result('{"delivered": true}')
        _say("tool_call: respond_to_user → delivered")

        decision.remember(
            kind=MemoryKind.EPISODIC,
            content=response,
            key="turn",
            tags=("reference-agent",),
            ttl_seconds=3600,
        )
        _say("memory write: episodic turn")

        decision.record_side_effect(
            "notification",
            target_system="reference-agent",
            operation="response.ready",
            request_payload=response,
            committed=True,
            rollback_supported=False,
            replay_behavior="suppress",
        )
        _say("side_effect: notification committed")

        decision.checkpoint("after-output")
        _say("checkpoint: after-output")

        # Snapshot attributes before the span closes; ``decision.span``
        # is invalidated on context exit.
        trace_id = decision.trace_id
        attrs = dict(decision.span.attributes or {})

    return TurnResult(
        response=response,
        trace_id=trace_id,
        event_counts={
            "retrieval": int(attrs.get("fabric.retrieval_count", 0)),
            "memory_write": int(attrs.get("fabric.memory_write_count", 0)),
            "side_effect": int(attrs.get("fabric.side_effect_count", 0)),
            "checkpoint": int(attrs.get("fabric.checkpoint_count", 0)),
        },
    )


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="fabric-reference-agent")
    parser.add_argument("--tenant-id", default="tenant-demo")
    parser.add_argument("--agent-id", default="reference-agent")
    parser.add_argument("--prompt", default="What is the capital of France?")
    parser.add_argument("--session-id", default="sess-demo")
    parser.add_argument("--request-id", default="req-demo")
    parser.add_argument("--user-id", default=None)
    parser.add_argument("--workflow-id", default=None)
    parser.add_argument("--execution-id", default=None)
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print each recorded step as it happens",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    _install_local_tracer()

    result = run_one_turn(
        prompt=args.prompt,
        tenant_id=args.tenant_id,
        agent_id=args.agent_id,
        session_id=args.session_id,
        request_id=args.request_id,
        user_id=args.user_id,
        workflow_id=args.workflow_id,
        execution_id=args.execution_id,
        verbose=args.verbose,
    )
    print(
        json.dumps(
            {
                "response": result.response,
                "trace_id": result.trace_id,
                "event_counts": result.event_counts,
            },
            indent=2,
        ),
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
