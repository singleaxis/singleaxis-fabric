# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Minimal Fabric-instrumented agent used by ../up.sh

Exercises every OSS surface in one decision so you see them flow through
the collector: identity → guard_input → retrieval → llm_call → tool_call
+ authorize_tool_call → guard_output → evaluate_policy → record_eval.

Set FABRIC_DEMO_MOCK=1 to run without ANTHROPIC_API_KEY.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from fabric import EngineVerdict, Fabric, FabricConfig
from fabric.tool_auth import ToolAuthorization


def fake_model_call(prompt: str) -> tuple[str, int, int]:
    """Drop-in stub that pretends to be an LLM (so the demo is deterministic)."""
    return ("Refund of $4,200 exceeds the $2,000 auto-approve cap.", 24, 18)


def real_model_call(prompt: str) -> tuple[str, int, int]:
    from anthropic import Anthropic

    client = Anthropic()
    msg = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=120,
        messages=[{"role": "user", "content": prompt}],
    )
    out = msg.content[0].text if msg.content else ""
    return (out, msg.usage.input_tokens, msg.usage.output_tokens)


@dataclass(slots=True)
class _RefundCap:
    engine_name: str = "demo-opa"

    def evaluate(
        self, *, policy_id: str, input: dict, timeout_seconds: float
    ) -> EngineVerdict:
        amount = float(input.get("amount", 0))
        if amount > 2000:
            return EngineVerdict(
                decision="deny",
                policy_version="v1",
                reason=f"amount ${amount:.0f} exceeds $2,000 cap",
            )
        return EngineVerdict(decision="allow", policy_version="v1")

    def close(self) -> None:
        pass


@dataclass(slots=True)
class _AllowToolAuthorizer:
    def authorize_tool_call(
        self, *, tool_name: str, arguments: dict, **_
    ) -> ToolAuthorization:
        return ToolAuthorization(decision="allow", reason="demo allow-all")


def main() -> None:
    mock = os.environ.get("FABRIC_DEMO_MOCK") == "1"
    do_call = fake_model_call if mock else real_model_call

    fabric = Fabric(FabricConfig(tenant_id="acme-demo", agent_id="refund-bot"))
    print(f"fabric {fabric}, mode={'mock' if mock else 'real'}")

    user_msg = "I want a refund for $4,200, my email is alice@example.com"

    with fabric.decision(
        session_id="sess-demo",
        request_id="req-1",
        user_id="user-42",
    ) as d:
        # In a real deployment guard_input goes through the Presidio sidecar.
        # Here we just record the intent so the span carries the event.
        d.record_retrieval(
            source="vector", query="refund policy", result_hashes=["kb#1182"]
        )

        with d.llm_call(system="anthropic", model="claude-haiku-4-5") as call:
            text, ti, to = do_call(user_msg)
            call.set_usage(input_tokens=ti, output_tokens=to)
            print(f"llm: {text}")

        auth = d.authorize_tool_call(
            tool_name="send_refund",
            arguments={"amount": 4200},
            authorizer=_AllowToolAuthorizer(),
        )
        print(f"tool auth: {auth.decision}")

        with d.tool_call(name="send_refund") as t:
            t.set_arguments(json.dumps({"amount": 4200, "currency": "USD"}))
            verdict = d.evaluate_policy(
                _RefundCap(), policy_id="finance.refund.cap", input={"amount": 4200}
            )
            print(f"policy: {verdict.decision} ({verdict.reason})")
            t.set_result(json.dumps({"status": "blocked", "reason": verdict.reason}))

    print("decision complete — spans flushed to collector")


if __name__ == "__main__":
    main()
