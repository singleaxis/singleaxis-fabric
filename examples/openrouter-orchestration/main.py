#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

# Ensure fabric SDK from repository is importable if running directly
for parent in [Path(__file__).resolve().parent] + list(Path(__file__).resolve().parents):
    sdk_candidate = parent / "sdk" / "python" / "src"
    if sdk_candidate.exists():
        if str(sdk_candidate) not in sys.path:
            sys.path.insert(0, str(sdk_candidate))
        break

from openai import OpenAI

# 1. Import SingleAxis Fabric
from fabric import (
    Fabric,
    FabricConfig,
    ContentCaptureConfig,
    LocalFilesystemContentStore,
    RetrievalSource,
    install_default_provider,
)
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

# Configuration paths
OUT_DIR = Path("./fabric_run_output")
STORE_DIR = OUT_DIR / "store"
SPOOL_DIR = OUT_DIR / "spool"
TENANT_ID = "production-tenant"
PRIMARY_AGENT = "lead-investigator"
SUB_AGENT = "security-specialist"

# OpenRouter Configuration
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")
if not OPENROUTER_API_KEY:
    print("Error: OPENROUTER_API_KEY environment variable is required.")
    sys.exit(1)

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=OPENROUTER_API_KEY,
)
MODEL_NAME = "anthropic/claude-3.5-sonnet"  # Or "openai/gpt-4o-mini", "meta-llama/llama-3.3-70b-instruct"

# 2. Setup OpenTelemetry & Fabric
# By default, sends OTLP spans to localhost:4318 (Fabric Node or Jaeger)
otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
install_default_provider(
    service_name="openrouter-orchestration",
    exporter=OTLPSpanExporter(endpoint=f"{otlp_endpoint}/v1/traces"),
)

# Initialize Governed Content Store (where raw prompts, files, and outputs are safely stored)
content_store = LocalFilesystemContentStore(str(STORE_DIR), tenant_id=TENANT_ID)

fabric = Fabric(
    FabricConfig(tenant_id=TENANT_ID, agent_id=PRIMARY_AGENT),
    content_capture=ContentCaptureConfig(
        store=content_store,
        roles="all",
        durability="spooled",
        spool_dir=str(SPOOL_DIR),
        worker_flush_interval_ms=50,
    ),
)

# 3. Define Tools
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_incident_file",
            "description": "Read log files from the server",
            "parameters": {
                "type": "object",
                "properties": {"filename": {"type": "string"}},
                "required": ["filename"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "calculate_impact",
            "description": "Calculate rate of error or memory leak",
            "parameters": {
                "type": "object",
                "properties": {
                    "total_requests": {"type": "integer"},
                    "failed_requests": {"type": "integer"},
                },
                "required": ["total_requests", "failed_requests"],
            },
        },
    },
]


def execute_tool(name: str, arguments: dict) -> str:
    if name == "read_incident_file":
        return (
            "2026-10-05 12:00:01 ERROR payments-worker: OOM killed (heap 512MiB breached)\n"
            "2026-10-05 12:00:02 WARN database-pool: 28 connections dropped"
        )
    elif name == "calculate_impact":
        tot, fail = arguments["total_requests"], arguments["failed_requests"]
        rate = (fail / tot) * 100
        return json.dumps({"failure_rate_percent": round(rate, 2), "severity": "HIGH"})
    return "Unknown tool"


# 4. Orchestration Execution Loop
def main():
    print(f"🚀 Starting agent orchestration for tenant: {TENANT_ID}...")

    session_id = "session-inc-992"
    request_id = "req-001"

    # Start a Fabric Decision Scope
    with fabric.decision(session_id=session_id, request_id=request_id) as decision:
        
        # A. Record static context (e.g. system runbook document)
        runbook_content = "# Payments Runbook: In case of OOM, inspect recent flags and restart."
        decision.record_context("runbook.md", runbook_content)

        # B. Model Turn 1: Planner reasoning
        messages = [
            {"role": "system", "content": "You are a lead incident response agent. Inspect files and calculate impact."},
            {"role": "user", "content": "Investigate payments failure in 'deploy.log' and determine failure rate for 1000 total / 42 failed requests."},
        ]

        print("🤖 LLM Turn 1: Calling OpenRouter for plan & tool requests...")
        with decision.llm_call(
            provider="openrouter",
            model=MODEL_NAME,
            system_instructions=messages[0]["content"],
            input_messages=messages[1:],
            tool_definitions=TOOLS,
            step_id="llm-plan",
        ) as call:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                tools=TOOLS,
            )
            choice = response.choices[0]
            # Record OpenRouter usage and output message
            call.set_usage(
                input_tokens=response.usage.prompt_tokens if response.usage else 0,
                output_tokens=response.usage.completion_tokens if response.usage else 0,
                finish_reason=choice.finish_reason,
            )
            call.set_response(
                response_id=response.id,
                model=response.model,
                output_messages=[choice.message.model_dump()],
            )

        messages.append(choice.message.model_dump())

        # C. Execute Tool Calls
        if choice.message.tool_calls:
            for tc in choice.message.tool_calls:
                fn_name = tc.function.name
                fn_args = json.loads(tc.function.arguments)
                print(f"🔧 Executing Tool: {fn_name}({fn_args})...")

                # Wrap tool execution in Fabric ToolCall
                with decision.tool_call(fn_name, call_id=tc.id) as tool_record:
                    tool_record.set_arguments(json.dumps(fn_args))
                    tool_result = execute_tool(fn_name, fn_args)
                    tool_record.set_result(tool_result)

                # Append result to prompt history
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": tool_result,
                })

        # D. Record RAG Retrieval Event
        decision.record_retrieval(
            source=RetrievalSource.DOCUMENT,
            query="payments OOM remediation runbook",
            result_count=1,
            results=[runbook_content],
            source_document_ids=["runbook.md"],
        )

        # E. Delegate to Sub-Agent (Multi-Agent Lineage)
        print("🤝 Delegating to Sub-Agent: Security Specialist...")
        with decision.delegate(to_agent=SUB_AGENT) as delegation:
            # Sub-agent inherits Fabric's context & traceparent via delegation.carrier
            child_fabric = Fabric(
                FabricConfig(tenant_id=TENANT_ID, agent_id=SUB_AGENT),
                content_capture=ContentCaptureConfig(store=content_store, roles="all"),
            )
            with child_fabric.decision(session_id=session_id, request_id="sub-task-002") as child_decision:
                sub_messages = [
                    {"role": "system", "content": "You are a security auditor. Verify whether credentials leaked."},
                    {"role": "user", "content": "Check log excerpt: 28 connections dropped. Any credential risk?"},
                ]
                with child_decision.llm_call(
                    provider="openrouter",
                    model=MODEL_NAME,
                    input_messages=sub_messages,
                    step_id="llm-subagent-check",
                ) as sub_call:
                    sub_resp = client.chat.completions.create(model=MODEL_NAME, messages=sub_messages)
                    sub_choice = sub_resp.choices[0]
                    sub_call.set_usage(
                        input_tokens=sub_resp.usage.prompt_tokens if sub_resp.usage else 0,
                        output_tokens=sub_resp.usage.completion_tokens if sub_resp.usage else 0,
                        finish_reason=sub_choice.finish_reason,
                    )
                    sub_call.set_response(
                        response_id=sub_resp.id,
                        model=sub_resp.model,
                        output_messages=[sub_choice.message.model_dump()],
                    )
                    sub_agent_verdict = sub_choice.message.content

        # F. Model Turn 2: Synthesize Final Investigation Report
        messages.append({
            "role": "user",
            "content": f"Security review verdict: {sub_agent_verdict}. Now synthesize the final report.",
        })

        print("🤖 LLM Turn 2: Final synthesis...")
        with decision.llm_call(
            provider="openrouter",
            model=MODEL_NAME,
            input_messages=messages,
            step_id="llm-final-report",
        ) as final_call:
            final_resp = client.chat.completions.create(model=MODEL_NAME, messages=messages)
            final_choice = final_resp.choices[0]
            final_call.set_usage(
                input_tokens=final_resp.usage.prompt_tokens if final_resp.usage else 0,
                output_tokens=final_resp.usage.completion_tokens if final_resp.usage else 0,
                finish_reason=final_choice.finish_reason,
            )
            final_call.set_response(
                response_id=final_resp.id,
                model=final_resp.model,
                output_messages=[final_choice.message.model_dump()],
            )

        print("\n✅ Final Report from Agent:\n" + "=" * 50)
        print(final_choice.message.content)
        print("=" * 50)

        # Flush content objects to disk
        fabric.flush_content(timeout_s=5.0)

    print(f"\n🎉 Finished! Telemetry and content captured in {OUT_DIR.resolve()}")


if __name__ == "__main__":
    main()
