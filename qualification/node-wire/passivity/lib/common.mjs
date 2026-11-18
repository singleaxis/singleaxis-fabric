// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Shared parts of the passivity harness (spec 055 §9.2): the pinned calibration workload,
// statistics, the hook-time markers, the deterministic transport fixtures and the
// loopback HTTP/SSE provider the children measure against.

import diagnosticsChannel from "node:diagnostics_channel";
import { readFileSync } from "node:fs";
import http from "node:http";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const PASSIVITY = join(HERE, "..");
export const REFERENCE = JSON.parse(readFileSync(join(PASSIVITY, "reference.json"), "utf8"));

/** The seven request channels the hook subscribes to (spec 055 §3.2). */
export const CHANNELS = [
    "undici:request:create",
    "undici:request:bodyChunkSent",
    "undici:request:bodySent",
    "undici:request:headers",
    "undici:request:bodyChunkReceived",
    "undici:request:trailers",
    "undici:request:error",
];

export const KIB = 1024;
export const MODEL_PATH = "/v1/chat/completions";

// ------------------------------------------------------------------------- statistics

export function median(values) {
    const sorted = [...values].sort((a, b) => a - b);
    const mid = sorted.length >> 1;
    return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

export const round = (value, places = 1) => Math.round(value * 10 ** places) / 10 ** places;

// ------------------------------------------------------------------------ calibration

/**
 * The pinned calibration workload (spec 055 §9.2): 20,000 map and property updates and
 * integer-to-string conversions. Its code is part of the reference: changing it means
 * remeasuring `reference.json` in a reviewed diff.
 */
export function workload() {
    const map = new Map();
    const object = {};
    let length = 0;
    for (let i = 0; i < 20_000; i++) {
        map.set(i & 1023, i);
        object[`k${i & 255}`] = i;
        length += String(i * 7919).length;
    }
    return length + map.size + Object.keys(object).length;
}

/** The minimum of `runs` timed runs of the workload, in ns, after a warm-up. */
export function calibrate(runs = REFERENCE.calibration.runs) {
    let sink = 0;
    for (let i = 0; i < 20; i++) sink += workload();
    let best = Infinity;
    for (let i = 0; i < runs; i++) {
        const start = process.hrtime.bigint();
        sink += workload();
        best = Math.min(best, Number(process.hrtime.bigint() - start));
    }
    if (sink === 0) throw new Error("unreachable");
    return best;
}

/** `clamp(min(before, after) / reference, 1, 4)` (047 §4.10). */
export function scaleFor(ns) {
    const { reference_ns: reference, max_scale: max } = REFERENCE.calibration;
    return Math.min(max, Math.max(1, ns / reference));
}

// ---------------------------------------------------------------------------- markers

/**
 * Times what runs between two marker subscribers. Subscribers run in subscription order,
 * so subscribing `begin` before the hook and `end` after it brackets exactly the hook's
 * work on each publication (and a stall injected between them).
 */
export function markers() {
    const totals = Object.fromEntries(CHANNELS.map((name) => [name, 0]));
    const counts = Object.fromEntries(CHANNELS.map((name) => [name, 0]));
    /** Each response-chunk publication's hook time (ms), for a per-chunk median. */
    const chunkTimes = [];
    let started = 0;
    let inside = false;
    const begins = CHANNELS.map((name) => [
        name,
        () => {
            inside = true;
            started = performance.now();
        },
    ]);
    const ends = CHANNELS.map((name) => [
        name,
        () => {
            const took = performance.now() - started;
            totals[name] += took;
            counts[name]++;
            if (name === "undici:request:bodyChunkReceived") chunkTimes.push(took);
            inside = false;
        },
    ]);
    return {
        totals,
        counts,
        chunkTimes,
        get inside() {
            return inside;
        },
        begin: () => begins.forEach(([n, f]) => diagnosticsChannel.subscribe(n, f)),
        end: () => ends.forEach(([n, f]) => diagnosticsChannel.subscribe(n, f)),
        reset() {
            for (const name of CHANNELS) totals[name] = counts[name] = 0;
            chunkTimes.length = 0;
        },
    };
}

/** Spins for `ns` nanoseconds on this thread. */
export function spin(ns) {
    const until = process.hrtime.bigint() + BigInt(Math.round(ns));
    while (process.hrtime.bigint() < until);
}

/**
 * An injectable stall, subscribed on every channel between the hook and the end marker
 * (the gate self-test). `set({ [channel]: ns })` stalls each publication on a channel by
 * that many ns; `set({})` stalls nothing. It does nothing else.
 */
export function stalls() {
    let plan = {};
    for (const name of CHANNELS) {
        diagnosticsChannel.subscribe(name, () => {
            const ns = plan[name];
            if (ns !== undefined) spin(ns);
        });
    }
    return { set: (next) => (plan = next) };
}

// --------------------------------------------------------------------------- fixtures

/**
 * Deterministic transport fixtures: undici's own publications for one request, built as
 * undici builds them (an internal request object, Buffer chunks, raw header Buffers), so
 * the hook's cost is measured with no network, scheduler or server noise.
 */
export function fixtures(port) {
    const ch = Object.fromEntries(CHANNELS.map((name) => [name, diagnosticsChannel.channel(name)]));
    const body = Buffer.alloc(KIB, 0x61);
    const chunk = Buffer.alloc(KIB, 0x62);
    const headers = [
        Buffer.from("content-type"),
        Buffer.from("application/json"),
        Buffer.from("content-length"),
        Buffer.from("1024"),
        Buffer.from("x-request-id"),
        Buffer.from("req_123"),
        Buffer.from("date"),
        Buffer.from("Tue, 18 Nov 2026 00:00:00 GMT"),
    ];
    const request = (origin) => ({
        method: "POST",
        origin,
        path: `${MODEL_PATH}?api-version=1`,
        contentType: "application/json",
        headers: ["authorization", "Bearer x", "content-type", "application/json"],
    });
    const matched = `http://127.0.0.1:${port}`;
    const unmatched = `http://127.0.0.1:${port + 1}`;
    const lifecycle = (origin) => {
        const r = request(origin);
        ch["undici:request:create"].publish({ request: r });
        ch["undici:request:bodyChunkSent"].publish({ request: r, chunk: body });
        ch["undici:request:bodySent"].publish({ request: r });
        ch["undici:request:headers"].publish({
            request: r,
            response: { statusCode: 200, headers, statusText: "OK" },
        });
        ch["undici:request:bodyChunkReceived"].publish({ request: r, chunk });
        ch["undici:request:trailers"].publish({ request: r, trailers: [] });
    };
    let stream;
    let streamed = 0;
    return {
        /** One matched non-streaming exchange with 1 KiB bodies. */
        matched: () => lifecycle(matched),
        /** One non-matching request, same shape. */
        unmatched: () => lifecycle(unmatched),
        /** One 1 KiB stream chunk of an open matched exchange (renewed every 4,096). */
        chunk: () => {
            if (stream === undefined || streamed === 4096) {
                if (stream !== undefined) {
                    ch["undici:request:trailers"].publish({ request: stream, trailers: [] });
                }
                stream = request(matched);
                ch["undici:request:create"].publish({ request: stream });
                ch["undici:request:bodySent"].publish({ request: stream });
                ch["undici:request:headers"].publish({
                    request: stream,
                    response: { statusCode: 200, headers, statusText: "OK" },
                });
                streamed = 0;
            }
            streamed++;
            ch["undici:request:bodyChunkReceived"].publish({ request: stream, chunk });
        },
    };
}

// ---------------------------------------------------------------------------- provider

/**
 * A loopback provider: `POST /v1/chat/completions` answers 1 KiB of JSON (after `delay`
 * ms with `?delay=<ms>`); with `?sse=<n>` it streams n 1 KiB SSE events, each written
 * after the previous one drained, or `gap` ms apart with `&gap=<ms>` (a model's pace),
 * or with `&lockstep=1` only after the client called `step()` for the previous one (so
 * each event is published as its own 1 KiB chunk; undici coalesces fast writes).
 */
const LIMITS = { sse: 100_000, delay: 1000, gap: 1000, lockstep: 1 };

export async function localProvider() {
    const json = Buffer.from(JSON.stringify({ id: "r", content: "y".repeat(KIB - 24) }));
    const event = Buffer.from(`data: ${"z".repeat(KIB - 8)}\n\n`);
    // Loopback-only harness parameters, bounded: no request can hold a timer longer than
    // a second or stream more than 100,000 events.
    const param = (url, name) => {
        const found = new RegExp(`[?&]${name}=(\\d{1,6})(?:&|$)`).exec(url);
        return found === null ? undefined : Math.min(Number(found[1]), LIMITS[name] ?? 0);
    };
    let step = () => undefined;
    const server = http.createServer((req, res) => {
        req.resume();
        req.on("end", () => {
            const url = req.url ?? "";
            const events = param(url, "sse");
            if (events === undefined) {
                const answer = () => {
                    res.writeHead(200, { "content-type": "application/json" });
                    res.end(json);
                };
                const delay = param(url, "delay");
                if (delay === undefined) answer();
                else setTimeout(answer, delay);
                return;
            }
            res.writeHead(200, { "content-type": "text/event-stream" });
            let left = events;
            const gap = param(url, "gap");
            if (param(url, "lockstep") === 1) {
                step = () => {
                    if (left-- > 0) res.write(event);
                    else {
                        step = () => undefined;
                        res.end();
                    }
                };
                step();
                return;
            }
            if (gap !== undefined) {
                const timer = setInterval(() => {
                    if (left-- > 0) res.write(event);
                    else {
                        clearInterval(timer);
                        res.end();
                    }
                }, gap);
                res.on("close", () => clearInterval(timer));
                return;
            }
            const next = () => {
                while (left-- > 0) {
                    if (!res.write(event)) return void res.once("drain", next);
                }
                res.end();
            };
            next();
        });
    });
    server.keepAliveTimeout = 5000;
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address();
    return {
        port,
        base: `http://127.0.0.1:${port}`,
        /** Lockstep streams: the client read the last event; write the next. */
        step: () => step(),
        close: () =>
            new Promise((resolve) => {
                server.closeAllConnections();
                server.close(resolve);
            }),
    };
}

/** The bundled capture (`build.mjs`), loaded from a child process. */
export function loadCapture(file) {
    return createRequire(import.meta.url)(file);
}

/** Children print one JSON line; parse the last. */
export function lastJson(text) {
    const lines = text.trim().split("\n");
    return JSON.parse(lines[lines.length - 1]);
}
