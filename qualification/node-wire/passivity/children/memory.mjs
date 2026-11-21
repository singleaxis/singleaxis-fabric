// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Memory bound (spec 055 §9.2 "memory bound"), one arm in one process (run with
// --expose-gc): tiny-chunk storms (exchanges of 400 one-byte response chunks, as
// undici publishes them) and many zero-body requests (real global fetch POSTs with no
// body), in four equal batches. After each batch: RSS, heap, external and ArrayBuffer
// memory, and the pools' high-water marks. Arms: baseline (no capture), enabled (the
// Fabric worker drains), saturated (no Fabric worker: the ring and arena fill and every
// later exchange is a named loss). Small configured bounds make saturation reachable.

import { channel } from "node:diagnostics_channel";

import { loadCapture, localProvider } from "../lib/common.mjs";

const config = JSON.parse(process.argv[2]);
const RUNTIME = config.runtime;
const provider = await localProvider();
let started;
if (config.arm !== "baseline") {
    const { startCapture } = loadCapture(config.capture);
    started = startCapture({
        port: provider.port,
        mode: config.arm,
        workerEntry: config.worker,
        runtime: RUNTIME,
    });
}

const ch = (name) => channel(`undici:request:${name}`);
const [create, sent, headers, received, trailers] = [
    "create",
    "bodySent",
    "headers",
    "bodyChunkReceived",
    "trailers",
].map(ch);
const one = Buffer.from("x");
function tinyStorm(exchanges, chunks) {
    for (let e = 0; e < exchanges; e++) {
        const request = {
            method: "POST",
            origin: provider.base,
            path: "/v1/chat/completions",
            headers: [],
        };
        create.publish({ request });
        sent.publish({ request });
        headers.publish({ request, response: { statusCode: 200, headers: [] } });
        for (let c = 0; c < chunks; c++) received.publish({ request, chunk: one });
        trailers.publish({ request, trailers: [] });
    }
}
async function zeroBodies(count) {
    let left = count;
    await Promise.all(
        Array.from({ length: 16 }, async () => {
            while (left-- > 0) {
                await (
                    await fetch(`${provider.base}/v1/chat/completions`, { method: "POST" })
                ).arrayBuffer();
            }
        }),
    );
}

const batches = [];
for (let b = 0; b < (config.batches ?? 4); b++) {
    tinyStorm(config.exchanges ?? 500, 400);
    await zeroBodies(config.requests ?? 500);
    await new Promise((resolve) => setTimeout(resolve, 100));
    globalThis.gc();
    const memory = process.memoryUsage();
    batches.push({
        rss: memory.rss,
        heap_used: memory.heapUsed,
        external: memory.external,
        array_buffers: memory.arrayBuffers,
        shared_bytes: started?.sharedBytes() ?? 0,
        peaks: started?.peaks(),
    });
}
const out = {
    arm: config.arm,
    batches,
    open: started?.hook.open ?? 0,
    shared_max_bytes: started?.sharedMaxBytes() ?? 0,
    hook: started && { ...started.hook.stats },
    losses:
        started &&
        Object.fromEntries(
            Object.entries(started.runtime.stats().losses).map(([key, value]) => [
                key,
                Number(value),
            ]),
        ),
};
await started?.stop();
await provider.close();
console.log(JSON.stringify(out));
