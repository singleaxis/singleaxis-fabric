// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.3 official `@anthropic-ai/sdk` client row: an unmodified agent script
// (CommonJS). The client reads ANTHROPIC_API_KEY and ANTHROPIC_BASE_URL itself; it sends
// through global fetch. A tool loop: a Messages call answered with a tool_use block, then
// the streamed answer. It knows nothing about Fabric.
//
//   ANTHROPIC_BASE_URL=http://127.0.0.1:PORT ANTHROPIC_API_KEY=... node anthropic.cjs
"use strict";

const Anthropic = require("@anthropic-ai/sdk");

async function main() {
    const client = new Anthropic();
    const question = { role: "user", content: "What is the weather in Paris?" };
    const tools = [
        {
            name: "get_weather",
            description: "Current weather in a city",
            input_schema: { type: "object", properties: { city: { type: "string" } } },
        },
    ];
    const first = await client.messages.create({
        model: "claude-haiku-4-5",
        max_tokens: 256,
        tools,
        messages: [question],
    });
    const use = first.content.find((block) => block.type === "tool_use");
    const stream = client.messages.stream({
        model: "claude-haiku-4-5",
        max_tokens: 256,
        tools,
        messages: [
            question,
            { role: "assistant", content: first.content },
            {
                role: "user",
                content: [{ type: "tool_result", tool_use_id: use.id, content: '{"celsius": 21}' }],
            },
        ],
    });
    let answer = "";
    stream.on("text", (text) => {
        answer += text;
    });
    await stream.finalMessage();
    process.stdout.write(JSON.stringify({ tool: use.name, answer }) + "\n");
}

main().catch((error) => {
    process.stderr.write(`agent failed: ${error && error.message}\n`);
    process.exitCode = 1;
});
