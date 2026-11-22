// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// The Node agent of the first verified record (spec 055 §9.5, unit 055-t13): a plain
// tool loop over global fetch, with explicit install() of the wire core built from the
// source tree (build.mjs). No agent framework, no model client library.
//
//   node agent.cjs '{"core": ..., "prebuilds": ..., "target": ..., "digest": ...,
//                    "base": "http://127.0.0.1:PORT", "runId": "...", "requests": ["{...}"],
//                    "qualification": {...}?, "flush": true, "closeTimeoutMs": 20000}'
//
// Prints one JSON line: what the application saw (statuses and response bodies) and what
// close() reported. A capture failure never changes what the application sees.
"use strict";

const args = JSON.parse(process.argv[2]);
const wire = require(args.core);

async function main() {
    const handle = wire.install({
        native: { prebuildsDir: args.prebuilds, digests: { [args.target]: args.digest } },
        ...(args.qualification === undefined ? {} : { qualification: args.qualification }),
    });
    if (!handle.capturing) throw new Error(`capture is not running: ${handle.reason}`);
    const seen = [];
    // The request bodies are the test's exact bytes (the parity test sends the same ones
    // through Python's capture); each turn is one fetch inside the run.
    const token = await wire.run({ runId: args.runId }, async () => {
        for (const body of args.requests) {
            const response = await fetch(`${args.base}/v1/chat/completions`, {
                method: "POST",
                headers: { "content-type": "application/json", authorization: "Bearer sk-test-e2e" },
                body,
            });
            seen.push({ status: response.status, body: await response.text() });
        }
        return wire.resumeToken();
    });
    const ended = wire.endRun({ outcome: "completed", stopReason: "goal_reached", resume: token });
    const flushed = args.flush === false ? null : await handle.flush({ timeoutMs: 20000 });
    const closed = await handle.close({ timeoutMs: args.closeTimeoutMs ?? 20000 });
    process.stdout.write(
        JSON.stringify({ seen, ended, flushed, closed, stop: handle.stopResult ?? null, sourceId: handle.sourceId }) + "\n",
    );
}

main().catch((error) => {
    process.stderr.write(`agent failed: ${error && error.message}\n`);
    process.exitCode = 1;
});
