// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.3 custom `fetch` row: a `fetch` function passed to the official `openai`
// client. One wrapper delegates to global fetch (it adds a header and counts calls): its
// call must be captured once, never twice. Another sends through node:http and never
// reaches undici: it is not a qualified point, so its call is not captured, and the
// manifest declares the `node_http` class uncaptured instead of guessing. Knows nothing
// about Fabric.
//
//   BASE=http://127.0.0.1:PORT node custom-fetch.mjs

import { request } from "node:http";

import OpenAI from "openai";

const base = process.env.BASE;
let delegated = 0;
const delegating = (url, init) => {
    delegated++;
    const headers = new Headers(init?.headers);
    headers.set("x-wrapper", "1");
    return fetch(url, { ...init, headers });
};

/** A fetch-shaped function over node:http (a transport no qualified point observes). */
const coreHttp = async (url, init = {}) => {
    const body = typeof init.body === "string" ? init.body : init.body ? String(init.body) : "";
    const headers = Object.fromEntries(new Headers(init.headers).entries());
    return new Promise((resolve, reject) => {
        const req = request(String(url), { method: init.method ?? "GET", headers }, (res) => {
            const parts = [];
            res.on("data", (part) => parts.push(part));
            res.on("end", () =>
                resolve(
                    new Response(Buffer.concat(parts), {
                        status: res.statusCode,
                        headers: Object.entries(res.headers).map(([k, v]) => [k, String(v)]),
                    }),
                ),
            );
        });
        req.on("error", reject);
        req.end(body);
    });
};

const messages = [{ role: "user", content: "What is the weather in Paris?" }];
const client = (scenario, fetchFn) =>
    new OpenAI({ apiKey: "sk-test-matrix", baseURL: `${base}/${scenario}/v1`, fetch: fetchFn, maxRetries: 0 });
const transcript = {
    delegating: await client("ok", delegating).chat.completions.create({ model: "m", messages }),
    delegated_calls: delegated,
    core_http: await client("core", coreHttp).chat.completions.create({ model: "m", messages }),
};
process.stdout.write(JSON.stringify(transcript) + "\n");
