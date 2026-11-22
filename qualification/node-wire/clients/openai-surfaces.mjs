// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.3 official `openai` client row: Chat Completions, Responses (a hosted tool
// call and a previous-response reference), legacy Completions and Embeddings, each JSON
// and SSE where the API streams; the SDK's retry of a 500, its timeout, a cancel
// mid-stream and an HTTP 400. Knows nothing about Fabric; prints what it observed.
//
//   BASE=http://127.0.0.1:PORT node openai-surfaces.mjs

import OpenAI from "openai";

const base = process.env.BASE;
const make = (scenario, options = {}) =>
    new OpenAI({ apiKey: "sk-test-matrix", baseURL: `${base}/${scenario}/v1`, maxRetries: 2, ...options });
const describe = (error) => ({
    class: error?.constructor?.name,
    status: error?.status,
    message: String(error?.message ?? error).replace(/\d+ms/g, "Nms"),
});
const outcome = async (fn) => {
    try {
        return { ok: await fn() };
    } catch (error) {
        return { error: describe(error) };
    }
};
const events = async (stream, stopAfter) => {
    const out = [];
    for await (const event of stream) {
        out.push(event);
        if (stopAfter !== undefined && out.length >= stopAfter) stream.controller.abort();
    }
    return out;
};
const messages = [{ role: "user", content: "What is the weather in Paris?" }];
const tools = [{ type: "function", function: { name: "get_weather", parameters: { type: "object" } } }];
const ok = make("ok");

const transcript = {
    chat_json: await outcome(() => ok.chat.completions.create({ model: "gpt-4o-mini", messages, tools })),
    chat_sse: await outcome(async () =>
        events(await ok.chat.completions.create({ model: "gpt-4o-mini", messages, stream: true })),
    ),
    responses_hosted_tool: await outcome(() =>
        ok.responses.create({ model: "gpt-4o-mini", input: "Weather in Paris?", tools: [{ type: "web_search" }] }),
    ),
    responses_previous: await outcome(() =>
        ok.responses.create({ model: "gpt-4o-mini", input: "And tomorrow?", previous_response_id: "resp_m_1" }),
    ),
    responses_sse: await outcome(async () =>
        events(await ok.responses.create({ model: "gpt-4o-mini", input: "Weather?", stream: true })),
    ),
    completions_json: await outcome(() =>
        ok.completions.create({ model: "gpt-3.5-turbo-instruct", prompt: "Paris is" }),
    ),
    completions_sse: await outcome(async () =>
        events(await ok.completions.create({ model: "gpt-3.5-turbo-instruct", prompt: "Paris is", stream: true })),
    ),
    embeddings: await outcome(() =>
        ok.embeddings.create({ model: "text-embedding-3-small", input: ["Paris", "weather"] }),
    ),
    error_400: await outcome(() => make("bad").chat.completions.create({ model: "m", messages })),
    retried_500: await outcome(() => make("flaky-openai").chat.completions.create({ model: "m", messages })),
    timed_out: await outcome(() =>
        make("never", { maxRetries: 0, timeout: 300 }).chat.completions.create({ model: "m", messages }),
    ),
    cancelled: await outcome(async () =>
        events(await ok.chat.completions.create({ model: "m", messages, stream: true }), 1),
    ),
};
process.stdout.write(JSON.stringify(transcript) + "\n");
