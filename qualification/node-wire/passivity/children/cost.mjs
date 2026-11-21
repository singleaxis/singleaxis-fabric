// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Hook cost, one arm in one isolated process (spec 055 §9.2 "hook cost"). Arms:
//   baseline  no capture loaded; the markers alone
//   disabled  the hook subscribed to a runtime that is not running
//   enabled   runtime running, Fabric worker draining, hook subscribed
//   stall     enabled, plus a stall of twice each scaled budget (the gate self-test)
// Two methods, three scenarios each (a matched non-streaming exchange, one stream chunk,
// one non-matching request; 1 KiB bodies and chunks):
//   fixtures  undici's own publications, built as undici builds them, timed per operation
//   server    real global fetch calls to a loopback HTTP/SSE provider, timing the work
//             done between marker subscribers placed before and after the hook
// Prints one JSON line: per-operation medians in ns.

import {
    CHANNELS,
    fixtures,
    loadCapture,
    localProvider,
    markers,
    median,
    stalls,
} from "../lib/common.mjs";

const config = JSON.parse(process.argv[2]);
const { arm } = config;
const SAMPLES = config.samples ?? 21;
const BATCH = { matched: 100, chunk: 1000, unmatched: 200 };

const provider = await localProvider();
const other = await localProvider();
const mark = markers();
mark.begin();
let started;
if (arm !== "baseline") {
    const { startCapture } = loadCapture(config.capture);
    started = startCapture({
        port: provider.port,
        mode: arm === "disabled" ? "disabled" : "enabled",
        workerEntry: config.worker,
    });
}
const stall = stalls();
mark.end();

const plans = {
    matched: { "undici:request:create": config.stallNs?.matched },
    chunk: { "undici:request:bodyChunkReceived": config.stallNs?.chunk },
    unmatched: { "undici:request:create": config.stallNs?.unmatched },
};
const plan = (scenario) => stall.set(arm === "stall" ? (plans[scenario] ?? {}) : {});

/**
 * Between samples (never inside one): lets the Fabric worker drain, so every measured
 * chunk is admitted and copied. A measurement where chunks were refused would time the
 * cheaper path; the orchestrator voids an enabled arm that refused any.
 */
async function drained() {
    if (started === undefined) return;
    const deadline = Date.now() + 2000;
    while (started.runtime.jobs.count > 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 1));
    }
}

// ------------------------------------------------------------------------ fixtures
const fixture = fixtures(provider.port);
const fixtureNs = {};
for (const scenario of ["matched", "chunk", "unmatched"]) {
    plan(scenario);
    const op = fixture[scenario];
    for (let i = 0; i < 2000; i++) {
        op(); // warm the JIT
        if (i % 100 === 99) await drained();
    }
    const samples = [];
    for (let s = 0; s < SAMPLES; s++) {
        await drained();
        const start = process.hrtime.bigint();
        for (let i = 0; i < BATCH[scenario]; i++) op();
        samples.push(Number(process.hrtime.bigint() - start) / BATCH[scenario]);
    }
    fixtureNs[scenario] = median(samples);
}
plan("none");

// -------------------------------------------------------------------------- server
// Hook time is taken per request (the requests run one at a time, so everything between
// the markers during a request is that request's) and per chunk, and the median is
// reported: a garbage-collection pause that a hook happens to trigger is the runtime's,
// paid by whichever allocation crosses the threshold, and would otherwise be charged in
// full to the sample it lands in.
const inHook = () => CHANNELS.reduce((sum, name) => sum + mark.totals[name], 0);
const serverNs = {};
const post = (base, query = "") =>
    fetch(`${base}/v1/chat/completions${query}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: Buffer.alloc(1024, 0x61),
    });
for (let i = 0; i < 30; i++) await (await post(provider.base)).arrayBuffer(); // warm
for (const [scenario, base] of [
    ["matched", provider.base],
    ["unmatched", other.base],
]) {
    plan(scenario);
    const perRequest = [];
    for (let s = 0; s < SAMPLES; s++) {
        await drained();
        for (let i = 0; i < 10; i++) {
            mark.reset();
            await (await post(base)).arrayBuffer();
            perRequest.push(inHook() * 1e6);
        }
    }
    serverNs[scenario] = median(perRequest);
}
plan("chunk");
const perChunk = [];
let chunkBytes = 0;
let chunks = 0;
for (let s = 0; s < SAMPLES; s++) {
    await drained();
    mark.reset();
    const response = await post(provider.base, "?sse=200&lockstep=1");
    for await (const part of response.body) {
        chunkBytes += part.byteLength;
        provider.step();
    }
    chunks += mark.chunkTimes.length;
    for (const took of mark.chunkTimes) perChunk.push(took * 1e6);
}
serverNs.chunk = median(perChunk);
plan("none");

const stats = started ? { ...started.hook.stats } : undefined;
const losses = started ? started.runtime.stats().losses : undefined;
await started?.stop();
await provider.close();
await other.close();
console.log(
    JSON.stringify({
        arm,
        fixtures_ns: fixtureNs,
        server_ns: serverNs,
        mean_chunk_bytes: Math.round(chunkBytes / Math.max(1, chunks)),
        hook: stats,
        losses:
            losses && Object.fromEntries(Object.entries(losses).map(([k, v]) => [k, Number(v)])),
    }),
);
