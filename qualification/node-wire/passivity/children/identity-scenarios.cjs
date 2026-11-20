// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Behaviour identity (spec 055 §9.2), the global `fetch` row of §9.3: the scenarios an
// application runs, recorded as a transcript the orchestrator compares between capture
// off and capture on. Each records what the application and the server observe: bytes
// the server received, the response bytes and chunk boundaries the application read,
// thrown and rejected error identity and class, abort and backpressure behaviour, socket
// reuse and that the caller's request buffer is untouched. Chunk boundaries are made
// deterministic by lockstep: the server writes the next SSE event only after the
// application has read the previous one. Loaded by identity.mjs (ESM app) and
// identity.cjs (CommonJS app).

"use strict";

const http = require("node:http");
const zlib = require("node:zlib");

const MODEL = "/v1/chat/completions";
const b64 = (bytes) => Buffer.from(bytes).toString("base64");

async function scenarios() {
    const received = [];
    const sockets = [];
    let lockstep;
    let backpressured = false;
    const server = http.createServer((req, res) => {
        const parts = [];
        req.on("data", (part) => parts.push(part));
        req.on("end", () => {
            received.push(b64(Buffer.concat(parts)));
            sockets.push(req.socket.remotePort);
            const url = req.url;
            if (url.endsWith("?sse")) {
                res.writeHead(200, { "content-type": "text/event-stream" });
                let n = 0;
                lockstep = () => {
                    if (n === 5) return void res.end("data: [DONE]\n\n");
                    res.write(`data: {"n":${n++},"t":"é✓"}\n\n`);
                };
                lockstep();
            } else if (url.endsWith("?gzip")) {
                res.writeHead(200, {
                    "content-type": "application/json",
                    "content-encoding": "gzip",
                });
                res.end(zlib.gzipSync(Buffer.from('{"z":"compressed ✓"}')));
            } else if (url.endsWith("?hold")) {
                res.writeHead(200, { "content-type": "text/event-stream" });
                res.write("data: first\n\n");
            } else if (url.endsWith("?never")) {
                // never answers
            } else if (url.endsWith("?cut")) {
                res.writeHead(200);
                res.write("partial");
                setTimeout(() => req.socket.destroy(), 10);
            } else if (url.endsWith("?big")) {
                res.writeHead(200, { "content-type": "application/octet-stream" });
                let left = 64;
                const next = () => {
                    while (left-- > 0) {
                        if (!res.write(Buffer.alloc(64 * 1024, left))) {
                            backpressured = true;
                            return void res.once("drain", next);
                        }
                    }
                    res.end();
                };
                next();
            } else {
                res.writeHead(200, { "content-type": "application/json", "x-request-id": "r-1" });
                res.end(`{"echo":${Buffer.concat(parts).length}}`);
            }
        });
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const post = (query, init = {}) =>
        fetch(base + MODEL + query, { method: "POST", body: '{"q":1}', ...init });
    const out = {};
    const errorOf = (error) => ({
        ctor: error?.constructor?.name,
        name: error?.name,
        cause: error?.cause?.code ?? error?.cause?.name,
    });

    // JSON with a caller-owned buffer body: the buffer is never detached or changed.
    const body = new Uint8Array(Buffer.from('{"messages":[{"role":"user","content":"hé"}]}'));
    const copy = Buffer.from(body);
    const json = await post("", { body, headers: { "content-type": "application/json" } });
    out.json = {
        status: json.status,
        type: json.headers.get("content-type"),
        text: await json.text(),
        bodyIntact: body.byteLength === copy.length && Buffer.from(body).equals(copy),
    };

    // A streamed request body.
    const streamed = new ReadableStream({
        start(controller) {
            for (const part of ["a", "bb", "ccc", "dddd"])
                controller.enqueue(new TextEncoder().encode(part));
            controller.close();
        },
    });
    out.streamedRequest = await (await post("", { body: streamed, duplex: "half" })).text();

    // SSE in lockstep: chunk boundaries and chunk types as the application sees them.
    const sse = await post("?sse");
    const reader = sse.body.getReader();
    out.sse = [];
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        out.sse.push([value.constructor.name, b64(value)]);
        lockstep();
    }

    out.gzip = { encoding: null, text: "" };
    const gz = await post("?gzip");
    out.gzip = { encoding: gz.headers.get("content-encoding"), text: await gz.text() };

    // Abort before headers with the application's own reason: rejected as that object.
    const reason = { why: "user" };
    const before = new AbortController();
    const pending = post("?never", { signal: before.signal });
    setTimeout(() => before.abort(reason), 20);
    out.abortBefore = await pending.then(
        () => "resolved",
        (error) => (error === reason ? "same-reason-object" : errorOf(error)),
    );

    // Abort mid-body.
    const mid = new AbortController();
    const held = await post("?hold", { signal: mid.signal });
    const heldReader = held.body.getReader();
    const first = await heldReader.read();
    mid.abort();
    out.abortMid = {
        first: b64(first.value),
        then: await heldReader.read().then(
            () => "resolved",
            (error) => errorOf(error),
        ),
    };

    // Abort after completion changes nothing.
    const after = new AbortController();
    const done = await (await post("", { signal: after.signal })).text();
    after.abort();
    out.abortAfter = done;

    // A transport failure mid-body: the same error class and cause.
    out.cut = await (async () => {
        try {
            await (await post("?cut")).text();
            return "resolved";
        } catch (error) {
            return errorOf(error);
        }
    })();

    // A paused consumer: the server sees backpressure; every byte arrives once resumed.
    const big = await post("?big");
    const bigReader = big.body.getReader();
    let bytes = (await bigReader.read()).value.byteLength;
    await new Promise((resolve) => setTimeout(resolve, 150));
    out.pausedBackpressure = backpressured;
    for (;;) {
        const { done: end, value } = await bigReader.read();
        if (end) break;
        bytes += value.byteLength;
    }
    out.pausedBytes = bytes;

    // Keep-alive reuse and a non-matching request.
    const reuseFrom = sockets.length;
    await (await post("")).text();
    await (await post("")).text();
    out.keepAlive = sockets[reuseFrom] === sockets[reuseFrom + 1];
    out.unmatched = await (
        await fetch(`${base}/other`, { method: "POST", body: "not a model call" })
    ).text();

    out.serverReceived = received;
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    return out;
}

/** Runs the scenarios with or without capture and prints the transcript. */
async function main(config, startCapture) {
    let started;
    if (config.capture === "on") {
        // Matches every model path on 127.0.0.1 whatever the port: the server's port is
        // only known once it listens, so the capture uses the openai dialect with any port.
        started = startCapture({
            port: 0,
            mode: "enabled",
            workerEntry: config.worker,
            anyPort: true,
        });
    }
    const transcript = await scenarios();
    const stats = started?.hook.stats;
    await started?.stop();
    process.stdout.write(`${JSON.stringify({ transcript, hook: stats })}\n`);
    // The exit code is part of the behaviour compared.
    process.exitCode = 7;
}

module.exports = { main };
