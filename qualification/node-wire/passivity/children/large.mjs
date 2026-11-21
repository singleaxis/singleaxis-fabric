// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Large shapes (spec 055 §9.2 "large shapes", unit 055-t8; 40 and 70 MiB from 055-t15):
// matched requests of 0 B, 64 KiB, 1 MiB and 32 MiB, a 40 MiB JSON request with one
// inline image (the shape the Fabric worker splits into a skeleton and a part) and a
// 70 MiB request over max_retain_bytes (64 MiB: the side is cut, truncated(body_cap)),
// through real global fetch, sent once as one in-memory body (undici publishes it as one
// chunk: the largest single snapshot) and once streamed in 64 KiB chunks. Per shape and
// delivery: the bytes the hook copied, the publications and the longest synchronous time
// one publication spent in the hook (between subscribers placed before and after it on
// every channel). A report, never averaged into the small-body medians.

import diagnosticsChannel from "node:diagnostics_channel";

import { CHANNELS, loadCapture, localProvider } from "../lib/common.mjs";

const config = JSON.parse(process.argv[2]);
const KIB = 1024;
const MIB = 1024 * KIB;
const CHUNK = 64 * KIB;
const MAX_RETAIN = 64 * MIB; // the runtime's default max_retain_bytes

/** A 40 MiB chat request: text around one ~30 MiB inline PNG data URL. */
function inlineMedia() {
    const image = Buffer.concat([Buffer.from("\x89PNG\r\n\x1a\n", "latin1"), Buffer.alloc(22.5 * MIB, 7)]);
    const head = Buffer.from(
        '{"model":"gpt-4o","messages":[{"role":"user","content":[{"type":"text","text":"',
    );
    const url = Buffer.from('"},{"type":"image_url","image_url":{"url":"data:image/png;base64,');
    const tail = Buffer.from('"}}]}]}');
    const b64 = Buffer.from(image.toString("base64"));
    const text = Buffer.alloc(40 * MIB - head.length - url.length - b64.length - tail.length, 0x61);
    return Buffer.concat([head, text, url, b64, tail]);
}

// [label, bytes, kind]: `whole` shapes are retained in full; `oversize` is over
// max_retain_bytes, so the hook stops retaining at the cap (streamed) or refuses the one
// chunk (in memory), and the side is truncated(body_cap).
const SHAPES = [
    ["0B", Buffer.alloc(0), "whole"],
    ["64KiB", Buffer.alloc(64 * KIB, 0x61), "whole"],
    ["1MiB", Buffer.alloc(MIB, 0x61), "whole"],
    ["32MiB", Buffer.alloc(32 * MIB, 0x61), "whole"],
    ["40MiB-inline-media", inlineMedia(), "whole"],
    ["70MiB-oversize", Buffer.alloc(70 * MIB, 0x61), "oversize"],
];

const provider = await localProvider();
let started = 0;
const times = [];
for (const name of CHANNELS) diagnosticsChannel.subscribe(name, () => (started = performance.now()));
const { startCapture } = loadCapture(config.capture);
const capture = startCapture({ port: provider.port, mode: "enabled", workerEntry: config.worker });
for (const name of CHANNELS) diagnosticsChannel.subscribe(name, () => times.push(performance.now() - started));
if (capture.runtime.shared.maxRetainBytes !== MAX_RETAIN) throw new Error("the oversize shape needs max_retain_bytes = 64 MiB");

async function drained() {
    const deadline = Date.now() + 10_000;
    while (capture.runtime.jobs.count > 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 1));
    }
}

function streamed(body) {
    let sent = 0;
    return new ReadableStream({
        pull(controller) {
            if (sent >= body.length) return controller.close();
            const part = Math.min(CHUNK, body.length - sent);
            controller.enqueue(new Uint8Array(body.subarray(sent, sent + part)));
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
for (const [label, body, kind] of SHAPES) {
    shapes[label] = {};
    for (const delivery of ["in_memory", "streamed"]) {
        await drained();
        const stats = capture.hook.stats;
        const retainedBefore = stats.chunksRetained;
        const refusedBefore = stats.chunksNotRetained;
        times.length = 0;
        const streaming = delivery === "streamed";
        await post(streaming ? streamed(body) : body, streaming);
        const retained = capture.hook.stats.chunksRetained - retainedBefore;
        const refused = capture.hook.stats.chunksNotRetained - refusedBefore;
        // The bytes snapshotted: the request's when every chunk was retained (plus the
        // 1 KiB response); for the oversize shape, the request chunks retained up to the
        // cap (whole 64 KiB chunks streamed, none in memory) plus the response.
        let copied = null;
        if (refused === 0) copied = body.length + KIB;
        else if (kind === "oversize") copied = (streaming ? Math.max(0, retained - 1) * CHUNK : 0) + KIB;
        shapes[label][delivery] = {
            kind,
            request_bytes: body.length,
            publications: times.length,
            chunks_retained: retained,
            chunks_not_retained: refused,
            bytes_copied: copied,
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
