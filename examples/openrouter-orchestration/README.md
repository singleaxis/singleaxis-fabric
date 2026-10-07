<!-- Copyright 2026 AI5Labs Research OPC Private Limited -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# OpenRouter Agent Orchestration Example

This example demonstrates how to instrument an autonomous multi-agent incident response workflow using **SingleAxis Fabric** and **OpenRouter** (via OpenAI-compatible API).

## What it demonstrates

1. **Governed Content Capture (`ContentCaptureConfig`)**: Prompts, tool arguments/results, retrieved runbooks, and completions are safely persisted into a local governed content store (`durability="spooled"`).
2. **Fabric Decision Scope (`fabric.decision`)**: Correlates multi-turn LLM reasoning, tool invocations, and retrievals under a single session and request lifecycle.
3. **Multi-Agent Lineage (`decision.delegate`)**: Scoped sub-agent execution where context and lineage are preserved across agents.
4. **OpenTelemetry Telemetry (`install_default_provider`)**: Emits GenAI standard spans and Fabric metadata via OTLP.

## Prerequisites

- Python 3.11+
- Fabric SDK (`singleaxis-fabric`)
- `openai` python library
- `opentelemetry-exporter-otlp-proto-http`
- `OPENROUTER_API_KEY` environment variable

```bash
pip install openai opentelemetry-exporter-otlp-proto-http
```

## Running the example

Set your OpenRouter API key and run the script:

```bash
export OPENROUTER_API_KEY="your-openrouter-key"
# Optional: point to custom OTLP endpoint (default: http://localhost:4318)
# export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4318"

python main.py
```
