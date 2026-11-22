// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// The host process of the worker-thread tests (spec 055 unit 055-t19). It loads the wire
// core the test bundled (FABRIC_TEST_CORE), runs its own scripted provider and prints one
// JSON line. Modes (argv[2]):
//   pool       explicit install(); 8 Workers attach with install() and send 4 calls each
//   terminate  explicit install(); a Worker holds a stream open inside a run and is
//              terminated; how long until its position is a settled `shutdown` loss
//   reach      the preload (as the test launched it) installs; Workers of every kind
//              report whether the preload attached them; the status counts the others
//   preinstall a Worker runs install() before the process installs; explicit install()
//   overflow   explicit install() with the fault build; a Worker attaches and exits
//   cluster    the preload installs; cluster.fork() twice; every process sends one call
"use strict";

const cluster = require("node:cluster");
const { Worker } = require("node:worker_threads");

const { chat, startProvider } = require("./provider.cjs");

const core = process.env.FABRIC_TEST_CORE;
const wire = require(core);
const WORKER = require.resolve("./app-worker.cjs");
const mode = process.argv[2];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function worker(workerData, options = {}) {
    const thread = new Worker(WORKER, { ...options, workerData: { core, ...workerData } });
    const first = new Promise((resolve, reject) => {
        thread.once("message", resolve);
        thread.once("error", reject);
    });
    // Listened for at once: a thread may exit before the caller awaits it.
    const exited = new Promise((resolve) => thread.once("exit", resolve));
    return { thread, first, exited };
}

function evalWorker(workerData) {
    const code =
        'const { parentPort, workerData } = require("node:worker_threads");' +
        "const h = require(workerData.core).preloadedHandle();" +
        "parentPort.postMessage({ capturing: h !== undefined && h.capturing === true });";
    const thread = new Worker(code, { eval: true, workerData: { core, ...workerData } });
    return new Promise((resolve, reject) => {
        thread.once("message", resolve);
        thread.once("error", reject);
    });
}

async function until(done, timeoutMs) {
    const deadline = performance.now() + timeoutMs;
    while (!done() && performance.now() < deadline) await sleep(2);
    return done();
}

function print(report) {
    process.stdout.write(JSON.stringify(report) + "\n");
}

async function pool(provider) {
    const handle = wire.install();
    const workers = Array.from({ length: 8 }, (_, id) =>
        worker({ mode: "install", base: provider.base, id, count: 4 }),
    );
    await chat(provider.base, "ok", "main 0");
    const reports = await Promise.all(workers.map((w) => w.first));
    await Promise.all(workers.map((w) => w.exited));
    await chat(provider.base, "ok", "main 1");
    const installed = handle.status();
    await handle.close({ timeoutMs: 3000 });
    return {
        main: { epoch: String(handle.epoch), source: handle.sourceId },
        workers: reports,
        status: installed,
        exit: handle.status(),
    };
}

async function terminate(provider) {
    const handle = wire.install();
    const w = worker({ mode: "hang", base: provider.base });
    const open = await w.first;
    await wire.run({ runId: "main-run" }, () => chat(provider.base, "ok", "main"));
    const shutdown = () => Number(handle.status().status.worker_positions_shutdown ?? 0);
    const before = shutdown();
    const started = performance.now();
    await w.thread.terminate();
    const terminated = performance.now();
    const settled = await until(() => shutdown() > before, 5000);
    const elapsed = performance.now() - started;
    const installed = handle.status();
    await handle.close({ timeoutMs: 3000 });
    return {
        open,
        settled,
        elapsedMs: elapsed,
        terminateMs: terminated - started,
        status: installed,
        exit: handle.status(),
    };
}

async function reach(provider) {
    const handle = wire.preloadedHandle();
    const kinds = {};
    kinds.default = await worker({ mode: "report" }).first;
    kinds.nested = await worker({ mode: "nested" }).first;
    kinds.eval = await evalWorker({});
    kinds.execArgvEmpty = await worker({ mode: "report" }, { execArgv: [] }).first;
    kinds.envEmpty = await worker({ mode: "report" }, { env: {} }).first;
    // Every created thread is attached or counted within the grace period (2 s).
    const created = 6;
    const counted = () => {
        const status = handle?.status().status ?? {};
        return (status.workers_attached ?? 0) + (status.workers_unattached ?? 0);
    };
    await until(() => counted() >= created, 6000);
    await chat(provider.base, "ok", "main");
    const installed = handle?.status();
    if (handle !== undefined) await handle.close({ timeoutMs: 3000 });
    return {
        capturing: handle?.capturing === true,
        kinds,
        status: installed,
        exit: handle?.status(),
    };
}

async function preinstall(provider) {
    const w = worker({ mode: "preinstall" });
    const before = await w.first;
    const handle = wire.install();
    const counted = await until(
        () => Number(handle.status().status.workers_unattached ?? 0) >= 1,
        5000,
    );
    await chat(provider.base, "ok", "main");
    const installed = handle.status();
    w.thread.postMessage("exit");
    await handle.close({ timeoutMs: 3000 });
    return { before, counted, status: installed, exit: handle.status() };
}

async function overflow(provider) {
    const handle = wire.install();
    const w = worker({ mode: "install", base: provider.base, id: 0, count: 1 });
    const report = await w.first;
    await w.exited;
    await sleep(300); // a few Fabric worker ticks: the poll meets the overflow
    await handle.close({ timeoutMs: 3000 });
    return { worker: report, exit: handle.status() };
}

async function clustered(provider) {
    if (cluster.isPrimary) {
        const handle = wire.preloadedHandle();
        await chat(provider.base, "ok", "primary");
        const children = [
            cluster.fork({ BASE: provider.base }),
            cluster.fork({ BASE: provider.base }),
        ];
        const exits = children.map((child) => new Promise((r) => child.once("exit", r)));
        const answers = await Promise.all(
            children.map(
                (child) =>
                    new Promise((resolve) => {
                        child.once("message", resolve);
                    }),
            ),
        );
        await Promise.all(exits);
        const epoch = handle === undefined ? null : String(handle.epoch);
        if (handle !== undefined) await handle.close({ timeoutMs: 3000 });
        return { primary: { epoch }, children: answers };
    }
    return undefined;
}

async function child() {
    const handle = wire.preloadedHandle();
    await chat(process.env.BASE, "ok", "cluster child");
    const epoch = handle === undefined ? null : String(handle.epoch);
    if (handle !== undefined) await handle.close({ timeoutMs: 3000 });
    process.send({ epoch, capturing: handle?.capturing === true });
    process.disconnect();
}

async function run() {
    if (mode === "cluster" && !cluster.isPrimary) return child();
    const provider = await startProvider();
    try {
        const modes = { pool, terminate, reach, preinstall, overflow, cluster: clustered };
        print(await modes[mode](provider));
    } finally {
        await provider.close();
    }
}

run().catch((error) => {
    process.stderr.write(String(error?.stack ?? error) + "\n");
    process.exit(1);
});
