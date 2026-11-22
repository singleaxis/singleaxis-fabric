// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.3 global `fetch` row: an unmodified agent script (ES module). A two-turn
// tool loop over global fetch: a question answered with a tool call (JSON), then the tool
// result, answered as a stream (SSE). It knows nothing about Fabric: capture comes only
// from NODE_OPTIONS=--import=@singleaxis/fabric/register and the environment.
//
//   MODEL_BASE_URL=http://127.0.0.1:PORT node fetch.mjs

const base = process.env.MODEL_BASE_URL;
const headers = { "content-type": "application/json", authorization: "Bearer sk-test-zero-code" };
const question = { role: "user", content: "What is the weather in Paris?" };

const first = await fetch(`${base}/v1/chat/completions`, {
    method: "POST",
    headers,
    body: JSON.stringify({ model: "gpt-4o-mini", messages: [question] }),
});
const call = (await first.json()).choices[0].message;
const tool = call.tool_calls[0];
const second = await fetch(`${base}/v1/chat/completions`, {
    method: "POST",
    headers,
    body: JSON.stringify({
        model: "gpt-4o-mini",
        stream: true,
        messages: [
            question,
            call,
            { role: "tool", tool_call_id: tool.id, content: '{"celsius": 21}' },
        ],
    }),
});
const text = await second.text();
process.stdout.write(JSON.stringify({ tool: tool.function.name, streamed: text.length }) + "\n");
