// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.5 (055-t17) production-profile end to end: an agent using the official
// `openai` client inside one Fabric run (the explicit run API of @singleaxis/fabric/wire),
// recorded by the preload and delivered to a real Fabric Node. A tool call (JSON), the
// tool result answered as JSON, then a streamed answer; the run ends with endRun and its
// resume token, so the reader can verify it complete and terminated.
//
//   OPENAI_BASE_URL=http://127.0.0.1:PORT/ok/v1 OPENAI_API_KEY=... node node-e2e.mjs

import { createRequire } from "node:module";

import OpenAI from "openai";

const wire = createRequire(import.meta.url)("@singleaxis/fabric/wire");
const client = new OpenAI({ maxRetries: 0 });
const tools = [{ type: "function", function: { name: "get_weather", parameters: { type: "object" } } }];

const token = await wire.run({ runId: process.env.E2E_RUN_ID }, async () => {
    const messages = [{ role: "user", content: process.env.E2E_PROMPT }];
    const first = await client.chat.completions.create({ model: "gpt-4o-mini", messages, tools });
    const call = first.choices[0].message;
    messages.push(call, { role: "tool", tool_call_id: call.tool_calls[0].id, content: process.env.E2E_TOOL_RESULT });
    const second = await client.chat.completions.create({ model: "gpt-4o-mini", messages });
    messages.push(second.choices[0].message, { role: "user", content: "Say it again." });
    let streamed = "";
    for await (const chunk of await client.chat.completions.create({ model: "gpt-4o-mini", messages, stream: true })) {
        streamed += chunk.choices[0]?.delta?.content ?? "";
    }
    process.stdout.write(JSON.stringify({ tool: call.tool_calls[0].function.name, streamed }) + "\n");
    return wire.resumeToken();
});
const ended = wire.endRun({ outcome: "completed", stopReason: "goal_reached", resume: token });
process.stdout.write(JSON.stringify({ ended }) + "\n");
