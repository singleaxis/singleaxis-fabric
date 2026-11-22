// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.3 chaos: one agent process for the real-process cases. It knows nothing
// about Fabric (capture comes from NODE_OPTIONS and the environment). It makes CHAOS_CALLS
// chat calls over global fetch to CHAOS_BASE (the scripted provider; the scenario segment
// picks the provider's behaviour), then prints a line and, with CHAOS_HOLD_MS, stays alive
// that long so the test can SIGKILL it at a chosen point. With CHAOS_FORK=1 it first forks
// a child (this file again, CHAOS_FORK unset) that makes its own calls and stays alive
// until killed: the parent's preload is inherited through NODE_OPTIONS (spec 055 §6.4).
// With CHAOS_WORKER=terminate a worker thread makes one call to CHAOS_BASE, then one to
// CHAOS_HANG_BASE (a provider scenario that never answers), and the main thread terminates
// it with that call open (spec 055 §4.4: its position settles as a `shutdown` loss).
//
//   CHAOS_BASE=http://127.0.0.1:PORT/ok CHAOS_CALLS=3 node agent.mjs

import { fork } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Worker, isMainThread, parentPort } from "node:worker_threads";

const base = process.env.CHAOS_BASE;
const post = (url, content) =>
    fetch(`${url}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer sk-test-chaos" },
        body: JSON.stringify({ model: "m", tool_choice: "none", messages: [{ role: "user", content }] }),
    });
if (!isMainThread) {
    const first = await post(base, "worker call 0");
    await first.text();
    parentPort.postMessage({ sent: first.status });
    await post(process.env.CHAOS_HANG_BASE, "worker call 1 (never answered)");
} else if (process.env.CHAOS_WORKER === "terminate") {
    const thread = new Worker(new URL(import.meta.url));
    const sent = await new Promise((resolve) => thread.once("message", resolve));
    await new Promise((resolve) => setTimeout(resolve, 500)); // the second call is open
    await thread.terminate();
    process.stdout.write(JSON.stringify({ role: "worker", ...sent }) + "\n");
}
const calls = Number(process.env.CHAOS_CALLS ?? "1");
const hold = Number(process.env.CHAOS_HOLD_MS ?? "0");
if (process.env.CHAOS_FORK === "1") {
    const child = fork(fileURLToPath(import.meta.url), [], {
        env: { ...process.env, CHAOS_FORK: "", CHAOS_HOLD_MS: "60000", CHAOS_ROLE: "child" },
        stdio: ["ignore", "inherit", "inherit", "ipc"],
    });
    process.stdout.write(JSON.stringify({ child: child.pid }) + "\n");
}
const results = [];
for (let i = 0; i < (isMainThread ? calls : 0); i++) {
    try {
        const r = await fetch(`${base}/v1/chat/completions`, {
            method: "POST",
            headers: { "content-type": "application/json", authorization: "Bearer sk-test-chaos" },
            body: JSON.stringify({
                model: "m",
                tool_choice: "none",
                messages: [{ role: "user", content: `${process.env.CHAOS_ROLE ?? "agent"} call ${i}` }],
            }),
        });
        results.push(r.status);
        await r.text();
    } catch (error) {
        results.push(error.name);
    }
}
if (isMainThread) {
    process.stdout.write(JSON.stringify({ role: process.env.CHAOS_ROLE ?? "agent", pid: process.pid, results }) + "\n");
}
if (hold > 0) setTimeout(() => {}, hold);
