// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Large shapes (spec 055 §9.2 "large shapes", unit 055-t8; 40 and 70 MiB from 055-t15):
// matched requests of 0 B, 64 KiB, 1 MiB and 32 MiB through real global fetch, sent once
// as one in-memory body (undici publishes it as one chunk: the largest single snapshot)
// and once streamed in 64 KiB chunks. Per shape and delivery: the bytes the hook copied,
// the publications and the longest synchronous time one publication spent in the hook
// (between subscribers placed before and after it on every channel). A report, never
// averaged into the small-body medians.

import diagnosticsChannel from "node:diagnostics_channel";

import { CHANNELS, loadCapture, localProvider } from "../lib/common.mjs";

const config = JSON.parse(process.argv[2]);
const KIB = 1024;
const MIB = 1024 * KIB;
const SHAPES = [
    ["0B", 0],
    ["64KiB", 64 * KIB],
    ["1MiB", MIB],
    ["32MiB", 32 * MIB],
];

const provider = await localProvider();
let started = 0;
const times = [];
for (const name of CHANNELS) diagnosticsChannel.subscribe(name, () => (started = performance.now()));
const { startCapture } = loadCapture(config.capture);
const capture = startCapture({ port: provider.port, mode: "enabled", workerEntry: config.worker });
for (const name of CHANNELS) diagnosticsChannel.subscribe(name, () => times.push(performance.now() - started));

async function drained() {
    const deadline = Date.now() + 10_000;
    while (capture.runtime.jobs.count > 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 1));
    }
}

function streamed(size) {
    let sent = 0;
    return new ReadableStream({
        pull(controller) {
            if (sent >= size) return controller.close();
            const part = Math.min(64 * KIB, size - sent);
            controller.enqueue(new Uint8Array(part).fill(0x61));
            sent += part;
        },
    });
}

const post = (body, streaming) =>
    fetch(`${provider.base}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
        ...(streaming ? { duplex: "half" } : {}),
    }).then((response) => response.arrayBuffer());

for (let i = 0; i < 20; i++) await post(Buffer.alloc(KIB, 0x61), false); // warm

const shapes = {};
for (const [label, size] of SHAPES) {
    shapes[label] = {};
    for (const delivery of ["in_memory", "streamed"]) {
        await drained();
        const stats = capture.hook.stats;
        const retainedBefore = stats.chunksRetained;
        const refusedBefore = stats.chunksNotRetained;
        times.length = 0;
        const streaming = delivery === "streamed";
        await post(streaming ? streamed(size) : Buffer.alloc(size, 0x61), streaming);
        // The bytes snapshotted are the request's when every chunk was retained.
        const refused = capture.hook.stats.chunksNotRetained - refusedBefore;
        shapes[label][delivery] = {
            request_bytes: size,
            publications: times.length,
            chunks_retained: capture.hook.stats.chunksRetained - retainedBefore,
            chunks_not_retained: refused,
            bytes_copied: refused === 0 ? size + KIB : null,
            total_hook_ms: times.reduce((sum, t) => sum + t, 0),
            max_single_ms: times.reduce((max, t) => Math.max(max, t), 0),
        };
    }
}
const losses = Object.fromEntries(
    Object.entries(capture.runtime.stats().losses).map(([k, v]) => [k, Number(v)]),
);
await capture.stop();
await provider.close();
console.log(JSON.stringify({ shapes, losses }));
