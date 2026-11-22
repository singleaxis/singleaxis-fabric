// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.3 official `@anthropic-ai/sdk` client row (CommonJS): Messages JSON and SSE
// with thinking, redacted thinking and a server tool; an error before headers (HTTP 400)
// and after headers (the connection closes mid-body); a cancel mid-stream. Prints every
// SDK event object it observed. Knows nothing about Fabric.
//
//   BASE=http://127.0.0.1:PORT node anthropic-surfaces.cjs
"use strict";

const Anthropic = require("@anthropic-ai/sdk");

const base = process.env.BASE;
const make = (scenario, options = {}) =>
    new Anthropic({ apiKey: "sk-test-matrix", baseURL: `${base}/${scenario}`, maxRetries: 0, ...options });
const describe = (error) => ({
    class: error && error.constructor && error.constructor.name,
    status: error && error.status,
    message: String((error && error.message) || error).replace(/\d+ms/g, "Nms"),
});
async function outcome(fn) {
    try {
        return { ok: await fn() };
    } catch (error) {
        return { error: describe(error) };
    }
}
const body = {
    model: "claude-haiku-4-5",
    max_tokens: 256,
    thinking: { type: "enabled", budget_tokens: 128 },
    tools: [{ type: "web_search_20250305", name: "web_search" }],
    messages: [{ role: "user", content: "What is the weather in Paris?" }],
};

async function main() {
    const ok = make("ok");
    const transcript = {
        messages_json: await outcome(() => ok.messages.create(body)),
        messages_sse: await outcome(async () => {
            const stream = ok.messages.stream(body);
            const events = [];
            for await (const event of stream) events.push(event);
            return { events, final: await stream.finalMessage() };
        }),
        messages_raw_sse: await outcome(async () => {
            const events = [];
            for await (const event of await ok.messages.create({ ...body, stream: true })) events.push(event);
            return events;
        }),
        error_before_headers: await outcome(() => make("bad").messages.create(body)),
        error_after_headers: await outcome(() => make("cut").messages.create(body)),
        cancelled: await outcome(async () => {
            const stream = ok.messages.stream(body);
            const events = [];
            for await (const event of stream) {
                events.push(event);
                if (events.length >= 2) stream.abort();
            }
            return events;
        }),
    };
    process.stdout.write(JSON.stringify(transcript) + "\n");
}

main().catch((error) => {
    process.stderr.write(`agent failed: ${error && error.message}\n`);
    process.exitCode = 1;
});
