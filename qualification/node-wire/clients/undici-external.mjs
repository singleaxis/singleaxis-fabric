// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.3 external `undici` package row: the pinned undici of package.json through
// its `fetch`, `request`, `Client` (with pipelining) and `Pool`, an HTTP/2-capable
// dispatcher of it handed to global fetch (a negative row), and one plain global fetch
// call (scenario path /ok/; the external copy's own calls use /ext/). No external undici
// version is qualified in this release, so every call that copy publishes must be an
// `uninstrumented_client` loss, never captured and never guessed, and the process is
// not complete. Importing the undici package installs its Agent as the process-wide
// dispatcher, so the plain global fetch call goes through that copy too and is the
// seventh loss. Knows nothing about Fabric.
//
//   BASE=http://127.0.0.1:PORT node undici-external.mjs

import { Agent, Client, Pool, fetch as undiciFetch, request } from "undici";

const base = process.env.BASE;
const path = (scenario) => `/${scenario}/v1/chat/completions`;
const headers = { "content-type": "application/json", authorization: "Bearer sk-test-matrix" };
const body = (stream) =>
    JSON.stringify({ model: "m", stream, messages: [{ role: "user", content: "Weather in Paris?" }] });
const text = async (b) => Buffer.from(await b.arrayBuffer()).toString("utf8");
const outcome = async (fn) => {
    try {
        return { ok: await fn() };
    } catch (error) {
        return { error: { class: error?.constructor?.name, code: error?.code } };
    }
};

const transcript = {
    global_fetch: await outcome(async () => {
        const r = await fetch(base + path("ok"), { method: "POST", headers, body: body(false) });
        return [r.status, await r.text()];
    }),
    undici_fetch: await outcome(async () => {
        const r = await undiciFetch(base + path("ext"), { method: "POST", headers, body: body(true) });
        return [r.status, await r.text()];
    }),
    undici_request: await outcome(async () => {
        const r = await request(base + path("ext"), { method: "POST", headers, body: body(false) });
        return [r.statusCode, await text(r.body)];
    }),
    client_pipelining: await outcome(async () => {
        const client = new Client(base, { pipelining: 2 });
        try {
            const all = await Promise.all(
                [0, 1].map(() => client.request({ path: path("ext"), method: "POST", headers, body: body(false) })),
            );
            return Promise.all(all.map(async (r) => [r.statusCode, await text(r.body)]));
        } finally {
            await client.close();
        }
    }),
    pool: await outcome(async () => {
        const pool = new Pool(base, { connections: 2 });
        try {
            const r = await pool.request({ path: path("ext"), method: "POST", headers, body: body(false) });
            return [r.statusCode, await text(r.body)];
        } finally {
            await pool.close();
        }
    }),
    // Negative row: an HTTP/2-capable dispatcher handed to global fetch. The dispatcher's
    // own undici copy creates and publishes the request, so it is not qualified either.
    http2_dispatcher: await outcome(async () => {
        const dispatcher = new Agent({ allowH2: true });
        try {
            const r = await fetch(base + path("ext"), { method: "POST", headers, body: body(false), dispatcher });
            return [r.status, await r.text()];
        } finally {
            await dispatcher.close();
        }
    }),
};
process.stdout.write(JSON.stringify(transcript) + "\n");
