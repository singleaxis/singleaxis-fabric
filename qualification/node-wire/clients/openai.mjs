// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.3 official `openai` client row: an unmodified agent script (ES module). The
// client reads OPENAI_API_KEY and OPENAI_BASE_URL itself; it sends through global fetch.
// A tool loop: a Chat Completions call answered with a tool call, then the streamed answer.
// It knows nothing about Fabric.
//
//   OPENAI_BASE_URL=http://127.0.0.1:PORT/v1 OPENAI_API_KEY=... node openai.mjs

import OpenAI from "openai";

const client = new OpenAI();
const question = { role: "user", content: "What is the weather in Paris?" };
const first = await client.chat.completions.create({ model: "gpt-4o-mini", messages: [question] });
const call = first.choices[0].message;
const tool = call.tool_calls[0];
const stream = await client.chat.completions.create({
    model: "gpt-4o-mini",
    stream: true,
    messages: [question, call, { role: "tool", tool_call_id: tool.id, content: '{"celsius": 21}' }],
});
let answer = "";
for await (const chunk of stream) answer += chunk.choices[0]?.delta?.content ?? "";
process.stdout.write(JSON.stringify({ tool: tool.function.name, answer }) + "\n");
