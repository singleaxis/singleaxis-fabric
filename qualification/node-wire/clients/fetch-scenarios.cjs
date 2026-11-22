// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.3 global `fetch` row: the scenarios, shared by the ES module and CommonJS
// entries (fetch-matrix.mjs, fetch-matrix.cjs). An application that knows nothing about
// Fabric; each scenario returns what the application observed, so the matrix compares
// the transcript with the preload on and off.
"use strict";

const { setTimeout: sleep } = require("node:timers/promises");

function describe(error) {
    return {
        class: error && error.constructor ? error.constructor.name : typeof error,
        name: error && error.name,
        message: String((error && error.message) || error).replace(/\d+ms/g, "Nms"),
        cause: error && error.cause ? describe(error.cause).class : undefined,
    };
}

async function outcome(fn) {
    try {
        return { ok: await fn() };
    } catch (error) {
        return { error: describe(error) };
    }
}

const JSON_HEADERS = { "content-type": "application/json", authorization: "Bearer sk-test" };
const question = [{ role: "user", content: "What is the weather in Paris?" }];
const chat = (stream) => JSON.stringify({ model: "gpt-4o-mini", stream, messages: question });

async function chunks(response, onChunk) {
    const decoder = new TextDecoder();
    const out = [];
    for await (const chunk of response.body) {
        out.push(decoder.decode(chunk, { stream: true }));
        if (onChunk) onChunk(out.length);
    }
    return out;
}

exports.run = async function run(base) {
    const url = (scenario, path = "/v1/chat/completions") => `${base}/${scenario}${path}`;
    const post = (scenario, body, init = {}) =>
        fetch(url(scenario, init.path), { method: "POST", headers: JSON_HEADERS, body, ...init });
    return {
        json_in_memory: await outcome(async () => {
            const r = await post("ok", chat(false));
            return { status: r.status, body: await r.text() };
        }),
        json_streamed_request_body: await outcome(async () => {
            const parts = [chat(false).slice(0, 20), chat(false).slice(20)];
            const body = new ReadableStream({
                pull(controller) {
                    const next = parts.shift();
                    if (next === undefined) controller.close();
                    else controller.enqueue(new TextEncoder().encode(next));
                },
            });
            const r = await post("ok", body, { duplex: "half" });
            return { status: r.status, body: await r.text() };
        }),
        // The text, not the chunk boundaries: where TCP splits a stream depends on timing
        // (the passivity job compares boundaries against a lockstep server).
        sse: await outcome(async () => {
            const r = await post("ok", chat(true));
            const text = (await chunks(r)).join("");
            return { status: r.status, text, events: text.split("\n\n").length - 1 };
        }),
        gzip_json: await outcome(async () => {
            const r = await post("gzip", chat(false));
            return { status: r.status, encoding: r.headers.get("content-encoding"), body: await r.text() };
        }),
        gzip_sse: await outcome(async () => {
            const r = await post("gzip", chat(true));
            return { status: r.status, text: (await chunks(r)).join("") };
        }),
        error_400: await outcome(async () => {
            const r = await post("bad", chat(false));
            return { status: r.status, body: await r.text() };
        }),
        error_after_headers: await outcome(async () => {
            const r = await post("cut", chat(false));
            return { status: r.status, body: await r.text() };
        }),
        abort_before_headers: await outcome(async () => {
            const r = await post("never", chat(false), { signal: AbortSignal.timeout(300) });
            return r.status;
        }),
        abort_mid_body: await outcome(async () => {
            const controller = new AbortController();
            const r = await post("ok", chat(true), { signal: controller.signal });
            return { status: r.status, chunks: await chunks(r, (n) => n >= 1 && controller.abort()) };
        }),
        abort_after_completion: await outcome(async () => {
            const controller = new AbortController();
            const r = await post("ok", chat(false), { signal: controller.signal });
            const body = await r.text();
            controller.abort();
            return { status: r.status, body, bodyUsed: r.bodyUsed };
        }),
        paused_consumer: await outcome(async () => {
            const r = await post("ok", chat(true));
            await sleep(250); // the application reads nothing while undici buffers
            return { status: r.status, text: (await chunks(r)).join("") };
        }),
        keep_alive_reuse: await outcome(async () => {
            const statuses = [];
            for (let i = 0; i < 3; i++) {
                const r = await post("ok", chat(false));
                statuses.push([r.status, (await r.text()).length]);
            }
            return statuses;
        }),
        non_matching: await outcome(async () => {
            const files = await post("ok", '{"purpose":"batch"}', { path: "/v1/files" });
            const models = await fetch(url("ok", "/v1/models"), { headers: JSON_HEADERS });
            return [files.status, await files.text(), models.status, await models.text()];
        }),
    };
};
