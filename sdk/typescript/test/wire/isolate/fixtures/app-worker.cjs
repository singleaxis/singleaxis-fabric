// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// An application worker thread of the worker-thread tests (spec 055 unit 055-t19). It
// knows the wire core only through workerData.core and does what workerData.mode says:
//   install     install() (attach), then `count` chat completions; reports the handle
//   hang        install(), then inside run(): one completion and one stream it holds open
//   reinstall   as hang, after install(), close() and install() again
//   report      no install(): reports whether the preload attached this thread
//   nested      as report, then starts a nested `report` Worker and relays its answer
//   preinstall  install() at once (before the process installs), then waits to be told
"use strict";

const { Worker, parentPort, workerData } = require("node:worker_threads");

const { chat } = require("./provider.cjs");

const { mode, base, core, count = 0 } = workerData;
const wire = require(core);

function handleReport(handle) {
    return {
        capturing: handle?.capturing === true,
        reason: handle?.reason ?? null,
        epoch: handle?.epoch === undefined ? null : String(handle.epoch),
        source: handle?.sourceId ?? null,
    };
}

async function main() {
    if (mode === "install") {
        const handle = wire.install();
        const report = handleReport(handle);
        for (let n = 0; n < count; n++) await chat(base, "ok", `worker ${workerData.id} call ${n}`);
        report.status = handle.status();
        parentPort.postMessage(report);
        return;
    }
    if (mode === "hang" || mode === "reinstall") {
        let handle = wire.install();
        if (mode === "reinstall") {
            // Attach, close this thread's handle, and attach again: still one row.
            await handle.close({ timeoutMs: 1000 });
            handle = wire.install();
        }
        await wire.run({ runId: "worker-run" }, async () => {
            await chat(base, "ok", "before the hang");
            const response = await fetch(`${base}/hang/v1/chat/completions`, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ model: "gpt-4o-mini", stream: true, messages: [] }),
            });
            await response.body.getReader().read();
            parentPort.postMessage({ open: true, ...handleReport(handle) });
            await new Promise(() => undefined); // held until terminated
        });
        return;
    }
    if (mode === "report" || mode === "nested") {
        const report = handleReport(wire.preloadedHandle());
        if (mode === "nested") {
            const nested = new Worker(__filename, {
                workerData: { ...workerData, mode: "report" },
            });
            report.nested = await new Promise((resolve, reject) => {
                nested.once("message", resolve);
                nested.once("error", reject);
            });
        }
        parentPort.postMessage(report);
        return;
    }
    if (mode === "preinstall") {
        parentPort.postMessage(handleReport(wire.install()));
        await new Promise((resolve) => parentPort.once("message", resolve));
        return;
    }
    throw new Error(`unknown mode ${mode}`);
}

main().catch((error) => {
    parentPort.postMessage({ error: String(error?.stack ?? error) });
});
