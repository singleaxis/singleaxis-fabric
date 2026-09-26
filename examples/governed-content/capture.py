# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Record a synthetic model -> tool -> model flow into a governed store.

This is the harness-owned posture from spec 034: the flow runs entirely
on the local filesystem — no Fabric Node, no OTLP collector, no
production storage. The SDK writes canonical content objects plus a
per-decision transcript manifest under ``<root>/<tenant>/``; nothing
content-shaped ever enters telemetry.

Run::

    python capture.py --root ./store
    # prints decision_id=<uuid> — pass it to evaluate.py

A development harness can record and read its own local transcripts
directly; offline datasets still carry privacy/access/retention
responsibilities — the store layout enforces tenant namespacing and
0600 file modes so a local transcript is not an accidental leak.
"""

from __future__ import annotations

import argparse
import sys

from fabric import (
    ContentCaptureConfig,
    Fabric,
    FabricConfig,
    LocalFilesystemContentStore,
)


def run(root: str, tenant: str) -> str:
    store = LocalFilesystemContentStore(root, tenant_id=tenant)
    fabric = Fabric(
        FabricConfig(
            tenant_id=tenant,
            agent_id="example-agent",
            profile="permissive-dev",
        ),
        content_capture=ContentCaptureConfig(
            store=store,
            roles="all",
            durability="inline",
        ),
    )
    with fabric.decision(
        session_id="sess-example",
        request_id="req-example",
    ) as decision:
        # The caller supplies context it chose to expose — a policy doc.
        decision.record_context(
            "refund-policy.txt",
            "Refunds above $500 require a supervisor approval code.",
        )
        instructions = [
            {
                "role": "system",
                "content": "You are a refund agent. Check policy before answering.",
            }
        ]
        # Model turn 1: model sees the request and issues a tool call.
        with decision.llm_call(
            provider="example",
            model="model-a",
            system_instructions=instructions,
            input_messages=[{"role": "user", "content": "Can I refund $700?"}],
        ) as call:
            call.set_response(
                output_messages=[
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call-1",
                                "function": {
                                    "name": "lookup_policy",
                                    "arguments": '{"section": "refunds"}',
                                },
                            }
                        ],
                    }
                ]
            )
        # Tool execution: serialized args + result, bound to call-1.
        tool_result = '{"limit": 500, "approver": "supervisor"}'
        with decision.tool_call("lookup_policy", call_id="call-1") as tool:
            tool.set_arguments('{"section": "refunds"}')
            tool.set_result(tool_result)
        # Model turn 2: the request carries the tool result the model
        # observed — the causal link a transcript consumer must verify.
        with decision.llm_call(
            provider="example",
            model="model-a",
            input_messages=[
                {"role": "user", "content": "Can I refund $700?"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "function": {
                                "name": "lookup_policy",
                                "arguments": '{"section": "refunds"}',
                            },
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "call-1", "content": tool_result},
            ],
        ) as call:
            call.set_response(
                output_messages=[
                    {
                        "role": "assistant",
                        "content": "Refunds above $500 need a supervisor approval code.",
                    }
                ]
            )
        result = fabric.flush_content(timeout_s=5.0)
        print(f"flush: {result}")
        print(f"decision_id={decision.decision_id}")
    manifest_uri = decision.content_manifest_uri
    if manifest_uri is None:  # pragma: no cover - defensive
        print("error: manifest was not written at decision close", file=sys.stderr)
        return ""
    print(f"manifest_uri={manifest_uri}")
    print(f"store_root={root}")
    return decision.decision_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="./store", help="governed store root")
    parser.add_argument("--tenant", default="example-tenant")
    args = parser.parse_args()
    if not run(args.root, args.tenant):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
