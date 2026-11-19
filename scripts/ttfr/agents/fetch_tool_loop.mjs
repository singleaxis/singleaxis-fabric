// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// A plain tool-calling agent on Node.js `fetch`, no provider SDK: the "own agent" of the
// Node.js TTFR test (spec 058 §3.3). It imports nothing from this repository. It finds
// its model in OPENAI_BASE_URL, else its own AGENT_MODEL_URL. The lines marked "Fabric"
// are the ones docs/get-started/node.md shows: until zero-code Node.js capture ships, the
// agent's code reports its model and tool calls through the SDK's explicit API.

import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks"; // Fabric
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http"; // Fabric
import { BatchSpanProcessor, TracerProvider } from "@opentelemetry/sdk-trace"; // Fabric
import { Fabric, fabricExporterOptions, installDefaultProvider } from "@singleaxis/fabric"; // Fabric

const exporter = new OTLPTraceExporter(fabricExporterOptions()); // Fabric
const provider = new TracerProvider({ spanProcessors: [new BatchSpanProcessor({ exporter })] }); // Fabric
installDefaultProvider({ provider, contextManager: new AsyncLocalStorageContextManager() }); // Fabric
const fabric = Fabric.fromEnv(); // Fabric

const TOOLS = [
  {
    type: "function",
    function: {
      name: "get_weather",
      description: "Current weather for a city",
      parameters: { type: "object", properties: { city: { type: "string" } }, required: ["city"] },
    },
  },
];

function getWeather({ city }) {
  return { city, celsius: 18.5 };
}

async function chat(baseUrl, messages) {
  const response = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
    },
    body: JSON.stringify({ model: process.env.AGENT_MODEL ?? "fixture-model", messages, tools: TOOLS }),
  });
  if (!response.ok) throw new Error(`model call failed: ${response.status}`);
  return response.json();
}

async function main() {
  const baseUrl = (process.env.OPENAI_BASE_URL ?? process.env.AGENT_MODEL_URL).replace(/\/+$/, "");
  const messages = [{ role: "user", content: "What is the weather in Lisbon?" }];
  return fabric.decision({ sessionId: "ttfr-session", requestId: "ttfr-request" }, async (decision) => { // Fabric
    for (let turn = 0; turn < 4; turn += 1) {
      const reply = await decision.llmCall( // Fabric
        { provider: "openai", operationName: "chat", model: process.env.AGENT_MODEL ?? "fixture-model" }, // Fabric
        async (call) => { // Fabric
          const body = await chat(baseUrl, messages);
          call.setResponse({ model: body.model }); // Fabric
          return body.choices[0].message;
        },
      );
      if (!reply.tool_calls) {
        console.log(JSON.stringify({ answer: reply.content }));
        return 0;
      }
      messages.push(reply);
      for (const toolCall of reply.tool_calls) {
        const result = await decision.toolCall(toolCall.function.name, { callId: toolCall.id }, async () => // Fabric
          getWeather(JSON.parse(toolCall.function.arguments)),
        );
        messages.push({ role: "tool", tool_call_id: toolCall.id, content: JSON.stringify(result) });
      }
    }
    console.error("no answer after 4 turns");
    return 1;
  });
}

const code = await main();
await provider.shutdown(); // Fabric: flush before the process exits
process.exit(code);
