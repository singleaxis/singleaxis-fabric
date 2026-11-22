// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// A scripted model provider for the worker-thread tests (spec 055 unit 055-t19), served
// by the host process itself over node:http (which no capture point observes):
//   POST /ok/v1/chat/completions    a JSON chat completion
//   POST /hang/v1/chat/completions  headers and a first SSE event, then nothing until closed
"use strict";

const { createServer } = require("node:http");

const COMPLETION = JSON.stringify({
    id: "chatcmpl-isolate",
    object: "chat.completion",
    model: "gpt-4o-mini",
    choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
});

function startProvider() {
    const held = new Set();
    const server = createServer((req, res) => {
        const parts = [];
        req.on("data", (part) => parts.push(part));
        req.on("end", () => {
            if (req.url.startsWith("/hang/")) {
                res.writeHead(200, { "content-type": "text/event-stream" });
                res.write('data: {"choices":[{"delta":{"content":"o"}}]}\n\n');
                held.add(res);
                return;
            }
            res.writeHead(200, { "content-type": "application/json" }).end(COMPLETION);
        });
    });
    return new Promise((resolve) => {
        server.listen(0, "127.0.0.1", () => {
            const base = `http://127.0.0.1:${server.address().port}`;
            resolve({
                base,
                close: () =>
                    new Promise((done) => {
                        for (const res of held) res.destroy();
                        server.closeAllConnections();
                        server.close(() => done());
                    }),
            });
        });
    });
}

/** One chat completion through global fetch (undici): the body read to the end. */
async function chat(base, scenario, content) {
    const response = await fetch(`${base}/${scenario}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer sk-test-isolate" },
        body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content }] }),
    });
    return response.text();
}

module.exports = { startProvider, chat };
