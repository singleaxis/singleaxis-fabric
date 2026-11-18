// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// The application event loop under capture (spec 055 §9.2 "event loop"), one arm in one
// process: a fan-out of 16 concurrent clients, each alternating a JSON call and an SSE
// stream of 1 KiB events, for a fixed time. Workloads:
//   paced   (gated) a model's pace: JSON answered after 10 ms, 40 SSE events 5 ms apart
//   stress  (reported, not gated) no pacing: the provider answers at once and streams 50
//           events as fast as the socket drains, about 100x any agent's call rate
// Measured on the application loop only: monitorEventLoopDelay({ resolution: 1 }) p99
// and maximum, eventLoopUtilization(), and a monotonic timer-drift probe (a synchronous
// workload cannot hide behind an empty histogram). Arms: baseline, enabled, stall (enabled plus a main-loop stall above the
// delay ceiling, the gate self-test). The sustained 60 s case is unit 055-t13's.

import { monitorEventLoopDelay, performance } from "node:perf_hooks";

import { loadCapture, localProvider, spin } from "../lib/common.mjs";

const config = JSON.parse(process.argv[2]);
const DURATION_MS = config.durationMs ?? 3000;
const PACED = config.workload !== "stress";
const JSON_QUERY = PACED ? "?delay=10" : "";
const SSE_QUERY = PACED ? "?sse=40&gap=5" : "?sse=50";
const STALL_EVERY = PACED ? 40 : 200;
const provider = await localProvider();
let started;
if (config.arm !== "baseline") {
    const { startCapture } = loadCapture(config.capture);
    started = startCapture({ port: provider.port, mode: "enabled", workerEntry: config.worker });
}
if (config.arm === "stall") {
    // Once every STALL_EVERY matched requests, a busy wait of twice the scaled maximum.
    const { subscribe } = await import("node:diagnostics_channel");
    let n = 0;
    subscribe("undici:request:create", () => {
        if (n++ % STALL_EVERY === STALL_EVERY >> 1) spin(config.stallNs);
    });
}

const post = (query = "") =>
    fetch(`${provider.base}/v1/chat/completions${query}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: Buffer.alloc(1024, 0x61),
    });
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Warm up, then measure.
for (let i = 0; i < 50; i++) await (await post()).arrayBuffer();
const histogram = monitorEventLoopDelay({ resolution: 1 });
let drift = 0;
let expected = performance.now() + 10;
const probe = setInterval(() => {
    const now = performance.now();
    drift = Math.max(drift, now - expected);
    expected = now + 10;
}, 10);
const elu = performance.eventLoopUtilization();
histogram.enable();
const deadline = performance.now() + DURATION_MS;
let requests = 0;
await Promise.all(
    Array.from({ length: 16 }, async () => {
        while (performance.now() < deadline) {
            await (await post(JSON_QUERY)).arrayBuffer();
            for await (const part of (await post(SSE_QUERY)).body) void part;
            requests += 2;
            if (!PACED) await pause(2);
        }
    }),
);
histogram.disable();
clearInterval(probe);
const utilization = performance.eventLoopUtilization(elu).utilization;
const stats = started?.hook.stats;
await started?.stop();
await provider.close();
console.log(
    JSON.stringify({
        arm: config.arm,
        workload: PACED ? "paced" : "stress",
        p99_ms: histogram.percentile(99) / 1e6,
        max_ms: histogram.max / 1e6,
        mean_ms: histogram.mean / 1e6,
        drift_max_ms: drift,
        utilization,
        requests,
        captured: stats?.matched,
        not_captured: stats?.notCaptured,
    }),
);
