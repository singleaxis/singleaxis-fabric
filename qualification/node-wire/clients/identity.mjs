// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.2 behaviour identity, the global `fetch`, official `openai` and official
// `@anthropic-ai/sdk` rows of §9.3, run from the packed package: an application that knows
// nothing about Fabric runs the same scenarios with and without
// NODE_OPTIONS=--import=@singleaxis/fabric/register, and prints a transcript of what it
// observed. The test compares the two transcripts and the bytes the server received.
//
// Scenarios (the scripted provider decides each by the first path segment): a JSON call, a
// streamed call (each chunk or event as the application received it), an HTTP 400 error
// (class, status, message), a 500 the client retries, a stream the application aborts
// mid-body, and a request the client times out before headers.
//
//   BASE=http://127.0.0.1:PORT node identity.mjs fetch|openai|anthropic

import Anthropic from "@anthropic-ai/sdk";
import OpenAI from "openai";

const [kind] = process.argv.slice(2);
const base = process.env.BASE;
const key = "sk-test-identity";

function describe(error) {
    return {
        class: error?.constructor?.name ?? typeof error,
        name: error?.name,
        status: error?.status,
        message: String(error?.message ?? error).replace(/\d+ms/g, "Nms"),
    };
}

async function outcome(fn) {
    try {
        return { ok: await fn() };
    } catch (error) {
        return { error: describe(error) };
    }
}

const question = [{ role: "user", content: "Say hello" }];

const clients = {
    fetch: (scenario) => ({
        async json() {
            const r = await fetch(`${base}/${scenario}/v1/chat/completions`, {
                method: "POST",
                headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
                body: JSON.stringify({ model: "m", messages: question }),
            });
            return { status: r.status, body: await r.text() };
        },
        async stream(abortAfter) {
            const controller = new AbortController();
            const r = await fetch(`${base}/${scenario}/v1/chat/completions`, {
                method: "POST",
                headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
                body: JSON.stringify({ model: "m", stream: true, messages: question }),
                signal: controller.signal,
            });
            const chunks = [];
            const decoder = new TextDecoder();
            for await (const chunk of r.body) {
                chunks.push(decoder.decode(chunk));
                if (abortAfter !== undefined && chunks.length >= abortAfter) controller.abort();
            }
            return { status: r.status, chunks };
        },
        async timeout() {
            const r = await fetch(`${base}/${scenario}/v1/chat/completions`, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ model: "m", messages: question }),
                signal: AbortSignal.timeout(300),
            });
            return r.status;
        },
    }),
    openai: (scenario) => {
        const client = new OpenAI({ apiKey: key, baseURL: `${base}/${scenario}/v1`, maxRetries: 2 });
        return {
            async json() {
                const r = await client.chat.completions.create({ model: "m", messages: question });
                return r;
            },
            async stream(abortAfter) {
                const s = await client.chat.completions.create({
                    model: "m",
                    stream: true,
                    messages: question,
                });
                const events = [];
                for await (const event of s) {
                    events.push(event);
                    if (abortAfter !== undefined && events.length >= abortAfter) s.controller.abort();
                }
                return events;
            },
            async timeout() {
                const quick = new OpenAI({
                    apiKey: key,
                    baseURL: `${base}/${scenario}/v1`,
                    maxRetries: 0,
                    timeout: 300,
                });
                return quick.chat.completions.create({ model: "m", messages: question });
            },
        };
    },
    anthropic: (scenario) => {
        const client = new Anthropic({ apiKey: key, baseURL: `${base}/${scenario}`, maxRetries: 2 });
        const body = { model: "m", max_tokens: 64, messages: question };
        return {
            async json() {
                return client.messages.create(body);
            },
            async stream(abortAfter) {
                const s = client.messages.stream(body);
                const events = [];
                for await (const event of s) {
                    events.push(event);
                    if (abortAfter !== undefined && events.length >= abortAfter) s.abort();
                }
                return events;
            },
            async timeout() {
                const quick = new Anthropic({
                    apiKey: key,
                    baseURL: `${base}/${scenario}`,
                    maxRetries: 0,
                    timeout: 300,
                });
                return quick.messages.create(body);
            },
        };
    },
};

const make = clients[kind];
const transcript = {
    json: await outcome(() => make("ok").json()),
    stream: await outcome(() => make("ok").stream()),
    error_400: await outcome(() => make("bad").json()),
    retried_500: await outcome(() => make(`flaky-${kind}`).json()),
    aborted: await outcome(() => make("ok").stream(1)),
    timed_out: await outcome(() => make("never").timeout()),
};
process.stdout.write(JSON.stringify(transcript) + "\n");
