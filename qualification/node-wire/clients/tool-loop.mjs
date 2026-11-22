// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.3 tool loop and fan-out row (TS-1D): a plain script, no framework. Inside
// one Fabric run (the explicit run API of @singleaxis/fabric/wire; with the preload off
// it simply calls the function): a three-turn tool loop over global fetch, 16 parallel
// requests joined, a streamed answer cancelled mid-turn, and a retry after a transport
// error (the first attempt's connection closes with no answer; the second succeeds).
// Every transport attempt must be one exchange of the one run, and its seals verify.
//
//   BASE=http://127.0.0.1:PORT node tool-loop.mjs

import { createRequire } from "node:module";

const wire = createRequire(import.meta.url)("@singleaxis/fabric/wire");
const base = process.env.BASE;
const headers = { "content-type": "application/json", authorization: "Bearer sk-test-matrix" };
const tools = [{ type: "function", function: { name: "get_weather", parameters: { type: "object" } } }];
const post = (scenario, payload, init = {}) =>
    fetch(`${base}/${scenario}/v1/chat/completions`, {
        method: "POST",
        headers,
        body: JSON.stringify({ model: "gpt-4o-mini", ...payload }),
        ...init,
    });

async function agent() {
    const out = {};
    // Multi-turn tool loop: the model asks for the tool twice, then answers.
    const messages = [{ role: "user", content: "Weather in Paris and Lyon?" }];
    out.turns = [];
    for (let turn = 0; turn < 3; turn++) {
        const r = await post("ok", { messages, tools: turn < 2 ? tools : undefined });
        const message = (await r.json()).choices[0].message;
        out.turns.push(message.tool_calls ? message.tool_calls[0].function.name : message.content);
        messages.push(message);
        if (message.tool_calls) {
            messages.push({ role: "tool", tool_call_id: message.tool_calls[0].id, content: '{"celsius":21}' });
        }
    }
    // Fan-out: 16 parallel requests joined.
    const fan = await Promise.all(
        Array.from({ length: 16 }, (_, i) =>
            post("ok", { messages: [{ role: "user", content: `city ${i}` }] }).then((r) => r.status),
        ),
    );
    out.fan_out = fan;
    // A streamed answer cancelled mid-turn.
    const controller = new AbortController();
    const streamed = await post("ok", { stream: true, messages }, { signal: controller.signal });
    const seen = [];
    try {
        for await (const chunk of streamed.body) {
            seen.push(chunk.length > 0);
            controller.abort();
        }
    } catch (error) {
        seen.push(error.name);
    }
    out.cancelled = seen;
    // A retry after a transport error: a second, separate attempt.
    const attempts = [];
    for (let attempt = 0; attempt < 2; attempt++) {
        try {
            const r = await post("reset-loop", { messages });
            attempts.push(r.status);
            break;
        } catch (error) {
            attempts.push(error.name);
        }
    }
    out.retry = attempts;
    return out;
}

const transcript = await wire.run({ runId: "matrix-tool-loop" }, agent);
const ended = wire.endRun({ outcome: "completed", stopReason: "goal_reached" });
// `fabric` is what the run API returned: it differs with the preload off by design.
process.stdout.write(JSON.stringify({ ...transcript, fabric: { ended } }) + "\n");
