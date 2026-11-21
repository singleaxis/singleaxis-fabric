// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// The whole recorder under load, one arm in one process (spec 055 §9.2, unit 055-t13):
// explicit install() with the capture pipeline and the sender delivering to a loopback
// Fabric Node, while the application runs a paced fan-out: each client alternates a JSON
// call and a 40-event SSE stream, and every fourth stream is cancelled after 5 events.
//
// Arms:
//   baseline          no capture
//   enabled           the recorder, a healthy Node
//   stall-fsync       every spool file fsync waits 200 ms (a stalled disk)
//   stall-sender      the Node accepts connections and never answers
//   stall-redaction   the response role is `redact` and the redaction service never answers
//   stall-admission   this thread holds the spool's admission lock (another writer stuck)
//   saturated         the capture worker takes 200 ms per exchange (its queue fills)
//   sustained         the recorder for 60 s with a 40 MiB mutable request (the sustained
//                     event-loop case); `sustained-baseline` is the same with no capture
//
// Measured on the application thread: event-loop p99, maximum, utilization and timer
// drift; requests completed; every response's bytes against the provider's; each
// cancelled stream's error name; any error, rejection or byte the recorder writes to the
// application's stderr. Prints one JSON line.

import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { monitorEventLoopDelay, performance } from "node:perf_hooks";

import { KIB, loadCapture, localProvider } from "../lib/common.mjs";

const config = JSON.parse(process.argv[2]);
const ARM = config.arm;
const CAPTURE = ARM !== "baseline" && ARM !== "sustained-baseline";
const SUSTAINED = ARM.startsWith("sustained");
const DURATION_MS = config.durationMs;
const CLIENTS = config.clients ?? 8;
const STALL_MS = config.stallMs ?? 200;

// Anything the recorder lets reach the application: errors and stderr bytes.
const escaped = [];
process.on("uncaughtException", (error) => escaped.push(`uncaught ${error?.name}`));
process.on("unhandledRejection", (error) => escaped.push(`unhandled ${error?.name}`));
let stderrBytes = 0;
const write = process.stderr.write.bind(process.stderr);
process.stderr.write = (chunk, ...rest) => {
    stderrBytes += Buffer.byteLength(chunk);
    return write(chunk, ...rest);
};

/** A loopback server answering every request with `status`, or never (`hang`). */
async function server(mode) {
    // Requests per path, in a Map: a path is never used as an object key.
    const seen = { requests: 0, paths: new Map() };
    const srv = http.createServer((req, res) => {
        req.resume();
        req.on("end", () => {
            seen.requests += 1;
            seen.paths.set(req.url, (seen.paths.get(req.url) ?? 0) + 1);
            if (mode === "hang") return; // never answers: a stalled Node or service
            res.writeHead(200, { "content-type": "application/x-protobuf" }).end();
        });
    });
    await new Promise((resolve) => srv.listen(0, "127.0.0.1", resolve));
    return {
        url: `http://127.0.0.1:${srv.address().port}`,
        seen,
        close: () =>
            new Promise((resolve) => {
                srv.closeAllConnections();
                srv.close(resolve);
            }),
    };
}

const provider = await localProvider();
const tmp = mkdtempSync(join(tmpdir(), "f055-t13-recorder-"));
const node = await server(ARM === "stall-sender" ? "hang" : "ok");
const redaction = ARM === "stall-redaction" ? await server("hang") : undefined;
let handle;
let releaseAdmission = () => undefined;
if (CAPTURE) {
    const recorder = loadCapture(config.recorder);
    const spool = join(tmp, "spool");
    const policy = join(tmp, "policy.json");
    const mode = (role) => (ARM === "stall-redaction" && role.endsWith("response") ? "redact" : "retain_original");
    const roles = ["model.exchange.request", "model.exchange.response"];
    writeFileSync(
        policy,
        JSON.stringify({
            schema_version: "fabric.deployment-policy/v1",
            policy_id: "passivity",
            policy_version: 1,
            tenant_id: "tenant-passivity",
            workload_id: "passivity",
            privacy: Object.fromEntries(roles.map((role) => [role, mode(role)])),
            storage: { backend: "local", region: "local", key_id: "k" },
            retention: { days: 1 },
            required_integrations: [],
            deployment: {
                profile: "production",
                image_digest: "sha256:" + "0".repeat(64),
                tls_required: true,
                encrypted_store_required: true,
            },
        }),
    );
    const faults = { "stall-fsync": { fsyncMs: STALL_MS }, saturated: { jobMs: STALL_MS } }[ARM] ?? {};
    const entry = join(tmp, "worker-entry.cjs");
    writeFileSync(
        entry,
        `globalThis.__f055t13Faults = ${JSON.stringify(faults)};\nrequire(${JSON.stringify(config.recorderWorker)});\n`,
    );
    const env = {
        FABRIC_TENANT_ID: "tenant-passivity",
        FABRIC_WIRE_ID_KEY: randomBytes(32).toString("hex"),
        FABRIC_WIRE_SPOOL_KEY: randomBytes(32).toString("base64"),
        FABRIC_WIRE_SPOOL_DIR: spool,
        FABRIC_CAPTURE_POLICY: policy,
        FABRIC_WIRE_ENDPOINTS: JSON.stringify([
            {
                endpoint_id: "harness",
                dialect: "openai",
                hosts: ["127.0.0.1"],
                ports: [provider.port],
                schemes: ["http"],
            },
        ]),
        FABRIC_WIRE_CONTENT_ENDPOINT: `${node.url}/v1/logs`,
        FABRIC_OTLP_ENDPOINT: node.url,
        ...(redaction === undefined ? {} : { FABRIC_REDACTION_ENDPOINT: redaction.url }),
    };
    handle = recorder.startRecorder({
        env,
        workerEntry: entry,
        native: { prebuildsDir: config.prebuilds, digests: { [config.target]: config.digest } },
        ...(config.qualification === undefined ? {} : { qualification: config.qualification }),
        ...(redaction === undefined
            ? {}
            : { transformations: { "model.exchange.response": { id: "mask", version: "1" } } }),
    });
    if (!handle.capturing) throw new Error(`the recorder did not start: ${handle.reason}`);
    if (ARM === "stall-admission") {
        releaseAdmission = recorder.holdAdmission(spool, config.prebuilds, config.digest);
    }
}

const post = (query, body = Buffer.alloc(KIB, 0x61), signal) =>
    fetch(`${provider.base}/v1/chat/completions${query}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
        signal,
    });
const digest = (parts) => {
    const hash = createHash("sha256");
    for (const part of parts) hash.update(part);
    return hash.digest("hex");
};
const EXPECTED_SSE = digest(Array.from({ length: 40 }, () => Buffer.from(`data: ${"z".repeat(KIB - 8)}\n\n`)));

// Warm up, then measure. The provider's JSON answer is the same every time.
let EXPECTED_JSON;
for (let i = 0; i < 20; i++) EXPECTED_JSON = digest([Buffer.from(await (await post("?paced")).arrayBuffer())]);
let big;
if (SUSTAINED) {
    // One 40 MiB request the application mutates as soon as fetch has it (spec 055 §9.2).
    const body = Buffer.alloc(40 * 1024 * 1024, 0x61);
    big = post("?paced", body).then(async (response) => {
        const bytes = (await response.arrayBuffer()).byteLength;
        return bytes;
    });
    body.fill(0x62);
}
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
let mismatches = 0;
const cancels = {};
let rss = process.memoryUsage().rss;
await Promise.all(
    Array.from({ length: CLIENTS }, async (_, client) => {
        let round = 0;
        while (performance.now() < deadline) {
            const json = Buffer.from(await (await post("?paced")).arrayBuffer());
            if (digest([json]) !== EXPECTED_JSON) mismatches += 1;
            requests += 1;
            if (++round % 4 === client % 4) {
                const controller = new AbortController();
                try {
                    let n = 0;
                    for await (const part of (await post("?sse=40&paced", undefined, controller.signal)).body) {
                        void part;
                        if (++n === 5) controller.abort();
                    }
                    cancels.not_cancelled = (cancels.not_cancelled ?? 0) + 1;
                } catch (error) {
                    cancels[error?.name ?? "unknown"] = (cancels[error?.name ?? "unknown"] ?? 0) + 1;
                }
            } else {
                const parts = [];
                for await (const part of (await post("?sse=40&paced")).body) parts.push(Buffer.from(part));
                if (digest([Buffer.concat(parts)]) !== EXPECTED_SSE) mismatches += 1;
            }
            requests += 1;
            rss = Math.max(rss, process.memoryUsage().rss);
        }
    }),
);
histogram.disable();
clearInterval(probe);
const utilization = performance.eventLoopUtilization(elu).utilization;
const bigBytes = big === undefined ? undefined : await big;
releaseAdmission();
const closeStarted = performance.now();
const closed = handle === undefined ? null : await handle.close({ timeoutMs: 2000 });
const closeMs = performance.now() - closeStarted;
await provider.close();
await node.close();
await redaction?.close();
rmSync(tmp, { recursive: true, force: true });
console.log(
    JSON.stringify({
        arm: ARM,
        p99_ms: histogram.percentile(99) / 1e6,
        max_ms: histogram.max / 1e6,
        utilization,
        drift_max_ms: drift,
        requests,
        mismatches,
        cancels,
        escaped,
        stderr_bytes: stderrBytes,
        big_response_bytes: bigBytes,
        rss_max_bytes: rss,
        closed,
        close_ms: closeMs,
        node_requests: Object.fromEntries(node.seen.paths),
        redaction_requests: redaction?.seen.requests,
    }),
);
