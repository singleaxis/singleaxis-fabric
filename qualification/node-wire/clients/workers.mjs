// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.3 worker_threads pools and cluster row (TS-1D, unit 055-t19): a plain
// script over global fetch that spreads its model calls across threads and processes.
// Knows nothing about Fabric.
// - a pool of 4 file Workers (one created with execArgv: []), 2 chat completions each:
//   they inherit the NODE_OPTIONS preload and attach to the process allocator;
// - an eval: true Worker and a Worker given env: {} (so no NODE_OPTIONS): the preload does
//   not reach them (qualification/node-wire/worker-reach.json), their calls are not
//   captured, and the record declares node_worker_unattached instead of guessing;
// - cluster.fork() twice: each child is a fresh process with its own epoch, and leaves with
//   cluster.worker.disconnect().
//
//   BASE=http://127.0.0.1:PORT node workers.mjs

import cluster from "node:cluster";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";

const base = process.env.BASE ?? workerData?.base;
const headers = { "content-type": "application/json", authorization: "Bearer sk-test-matrix" };

async function chat(scenario, content) {
    const response = await fetch(`${base}/${scenario}/v1/chat/completions`, {
        method: "POST",
        headers,
        body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content }] }),
    });
    return [response.status, (await response.json()).choices[0].finish_reason];
}

/** A Worker running this file (or `code` with eval) until it posts its answer and exits. */
function thread(data, options = {}) {
    const worker = options.eval
        ? new Worker(options.eval, { eval: true, workerData: { base, ...data } })
        : new Worker(new URL(import.meta.url), { ...options, workerData: { base, ...data } });
    const answer = new Promise((resolve, reject) => {
        worker.once("message", resolve);
        worker.once("error", reject);
    });
    const exited = new Promise((resolve) => worker.once("exit", resolve));
    return answer.then(async (value) => (await exited, value));
}

const EVAL = `
const { parentPort, workerData } = require("node:worker_threads");
fetch(workerData.base + "/unattached-eval/v1/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: "eval" }] }),
}).then(async (r) => parentPort.postMessage([r.status, (await r.json()).choices[0].finish_reason]));
`;

if (!isMainThread) {
    const { scenario, calls } = workerData;
    const out = [];
    for (let n = 0; n < calls; n++) out.push(await chat(scenario, `${scenario} ${n}`));
    parentPort.postMessage(out);
} else if (cluster.isWorker) {
    const answer = await chat("ok", `cluster child ${process.env.CHILD}`);
    // The graceful way out of a cluster worker: the process then ends when its work is done
    // (an unplanned process.disconnect() makes Node call process.exit() at once).
    process.send(answer, () => cluster.worker.disconnect());
} else {
    const transcript = {};
    transcript.pool = await Promise.all([
        thread({ scenario: "ok", calls: 2 }),
        thread({ scenario: "ok", calls: 2 }),
        thread({ scenario: "ok", calls: 2 }),
        thread({ scenario: "ok", calls: 2 }, { execArgv: [] }),
    ]);
    transcript.eval = await thread({}, { eval: EVAL });
    transcript.env_empty = await thread({ scenario: "unattached-env", calls: 1 }, { env: {} });
    const children = [1, 2].map((n) => {
        const child = cluster.fork({ CHILD: String(n), BASE: base });
        const answer = new Promise((resolve) => child.once("message", resolve));
        const exited = new Promise((resolve) => child.once("exit", resolve));
        return answer.then(async (value) => (await exited, value));
    });
    transcript.cluster = await Promise.all(children);
    transcript.main = await chat("ok", "main thread");
    process.stdout.write(JSON.stringify(transcript) + "\n");
}
