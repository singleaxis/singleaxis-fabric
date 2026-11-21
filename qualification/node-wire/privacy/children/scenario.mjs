// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// One privacy scenario in its own process (spec 055 §9.2 `ts-wire-privacy`): an agent
// that calls a local model provider through global fetch with canaries planted in the
// prompt, the tool schema, the response, the URL path and query, request and response
// headers (authorization, cookie, API key, set-cookie, request id), an inline image (a
// split request: a skeleton and a `model.exchange.part`, unit 055-t15), an abort reason's
// Error.name and message, a transport error, the clear run id, the resource attributes,
// the service name, the agent id and the environment. Capture runs with the policy mode
// of the scenario, into the scenario's spool. Prints one JSON line: the number of calls
// and the SHA-256 of every body as sent and received (never a canary).
//
//   node scenario.mjs '<json config>'

import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { createRequire } from "node:module";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

import { SPLIT_MAX_BODY_BYTES, splitRequest } from "../lib/part.mjs";

const config = JSON.parse(process.argv[2]);
const C = config.canaries;
const require = createRequire(import.meta.url);
const { startAgent } = require(config.agent);
const sha = (data) => createHash("sha256").update(data).digest("hex");
const digests = [];

// ------------------------------------------------------------------------- provider
const jsonAnswer = Buffer.from(
    JSON.stringify({
        id: "chatcmpl-1",
        model: "gpt-4o-2024-08-06",
        choices: [{ index: 0, finish_reason: "stop", message: { role: "assistant", content: C.response } }],
        usage: { prompt_tokens: 5, completion_tokens: 3 },
    }),
);
const sse = Buffer.from(`data: {"choices":[{"delta":{"content":"${C.response}"}}]}\n\ndata: [DONE]\n\n`);
const provider = http.createServer((req, res) => {
    const parts = [];
    req.on("data", (part) => parts.push(part));
    req.on("end", () => {
        digests.push(sha(Buffer.concat(parts)));
        const kind = new URL(req.url, "http://x").searchParams.get("kind");
        const headers = { "set-cookie": `session=${C.set_cookie}`, "x-request-id": C.request_id };
        if (kind === "sse") {
            res.writeHead(200, { ...headers, "content-type": "text/event-stream" });
            res.end(sse);
        } else if (kind === "gzip") {
            res.writeHead(200, { ...headers, "content-type": "application/json", "content-encoding": "gzip" });
            res.end(gzipSync(jsonAnswer));
        } else if (kind === "slow") {
            res.writeHead(200, { ...headers, "content-type": "text/event-stream" });
            res.write(sse.subarray(0, 20));
        } else if (kind === "broken") {
            res.writeHead(200, { ...headers, "content-type": "application/json", "content-length": "500" });
            res.write(jsonAnswer.subarray(0, 30));
            setTimeout(() => res.socket?.destroy(new Error(C.error_message)), 10);
        } else {
            res.writeHead(200, { ...headers, "content-type": "application/json" });
            res.end(jsonAnswer);
        }
    });
});
await new Promise((resolve) => provider.listen(0, "127.0.0.1", resolve));
const port = provider.address().port;

// ---------------------------------------------------------- customer redaction service
const inputs = join(config.dir, "inputs");
mkdirSync(inputs, { recursive: true, mode: 0o700 });
// A Unix socket path is at most 104 bytes on macOS: the socket gets a short directory.
const socketDir = mkdtempSync(join(existsSync("/tmp") ? "/tmp" : inputs, "f055-t8-rs-"));
const socket = join(socketDir, "r.sock");
const redaction = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => res.writeHead(200).end('{"masked":true}'));
});
await new Promise((resolve) => redaction.listen(socket, resolve));

// ---------------------------------------------------------------------- configuration
const roles = ["model.exchange.request", "model.exchange.response", "model.exchange.part"];
// `original_plus_masked_unreviewed`: original_plus_masked with no transformation, so every
// review copy fails and each pair is withheld (055-t15).
const policyMode =
    { disabled: "retain_original", original_plus_masked_unreviewed: "original_plus_masked" }[config.mode] ??
    config.mode;
const policy = {
    schema_version: "fabric.deployment-policy/v1",
    policy_id: "privacy-harness",
    policy_version: 1,
    tenant_id: "tenant-privacy",
    workload_id: "harness",
    privacy: Object.fromEntries(roles.map((role) => [role, policyMode])),
    storage: { backend: "local", region: "local", key_id: "kid-harness" },
    retention: { days: 1 },
    required_integrations: [],
    deployment: {
        profile: "production",
        image_digest: "sha256:" + "0".repeat(64),
        tls_required: true,
        encrypted_store_required: true,
    },
};
const policyFile = join(inputs, "policy.json");
writeFileSync(policyFile, JSON.stringify(policy));
chmodSync(policyFile, 0o600);
const env = {
    FABRIC_WIRE_ENDPOINTS: JSON.stringify([
        { endpoint_id: "harness", dialect: "openai", hosts: ["127.0.0.1"], schemes: ["http"] },
    ]),
    FABRIC_WIRE_CONTENT_ENDPOINT: "http://127.0.0.1:9/v1/logs",
    OTEL_EXPORTER_OTLP_ENDPOINT: "http://127.0.0.1:9",
    FABRIC_TENANT_ID: "tenant-privacy",
    FABRIC_WIRE_SPOOL_DIR: join(config.dir, "spool"),
    FABRIC_WIRE_SPOOL_KEY: config.spool_key_b64,
    FABRIC_CAPTURE_POLICY: policyFile,
    FABRIC_TOKENIZATION_KEY: Buffer.alloc(32, 0x42).toString("base64"),
    FABRIC_REDACTION_ENDPOINT: `unix://${socket}`,
    FABRIC_RUN_ID: C.run_id,
    FABRIC_AGENT_ID: C.agent_id,
    OTEL_SERVICE_NAME: C.service_name,
    OTEL_RESOURCE_ATTRIBUTES: `deployment.environment=${C.resource}`,
    FABRIC_HARNESS_SECRET: C.environment,
    // Small enough that the split call's request is over it (and split), large enough
    // for its image part and for every other call's whole body.
    FABRIC_WIRE_MAX_BODY_BYTES: String(SPLIT_MAX_BODY_BYTES),
};
// The disabled scenario: production without FABRIC_WIRE_ID_KEY (missing_id_key).
if (config.mode !== "disabled") env.FABRIC_WIRE_ID_KEY = Buffer.alloc(32, 0x24).toString("hex");
Object.assign(process.env, env);
const transform = { id: "harness-mask", version: "1" };
const agent = startAgent({
    env,
    workerEntry: config.worker,
    prebuilds: config.prebuilds,
    digest: config.digest,
    transformations: ["redact", "masked_only", "original_plus_masked"].includes(config.mode)
        ? Object.fromEntries(roles.map((role) => [role, transform]))
        : undefined,
    fault: config.fault,
    leaks: config.leaks,
});

// ------------------------------------------------------------------------- the agent
const body = JSON.stringify({
    model: "gpt-4o",
    messages: [{ role: "user", content: C.prompt }],
    tools: [{ type: "function", function: { name: "lookup", parameters: { description: C.tool_schema } } }],
});
const url = (kind) =>
    `http://127.0.0.1:${port}/proxy/${C.url_path}/v1/chat/completions?kind=${kind}&key=${C.url_query}`;
const headers = {
    "content-type": "application/json",
    authorization: `Bearer ${C.authorization}`,
    cookie: `sid=${C.cookie}`,
    "x-api-key": C.api_key,
};
let calls = 0;
const call = async (kind, init = {}, payload = body) => {
    calls++;
    digests.push(sha(Buffer.from(payload)));
    try {
        const response = await fetch(url(kind), { method: "POST", headers, body: payload, ...init });
        const received = Buffer.from(await response.arrayBuffer());
        digests.push(sha(received));
    } catch {
        // an aborted or failed call: the application's error, never Fabric's
    }
};
await call("json");
await call("json", {}, splitRequest(C.prompt, C.image));
await call("sse");
await call("gzip");
await call("broken");
const controller = new AbortController();
const aborted = call("slow", { signal: controller.signal });
setTimeout(() => {
    const reason = new Error(C.error_message);
    reason.name = C.error_name;
    controller.abort(reason);
}, 50);
await aborted;
await new Promise((resolve) => setTimeout(resolve, 50));
const drained = await agent.stop();
const stats = agent.runtime.stats();
provider.closeAllConnections();
provider.close();
redaction.close();
rmSync(socketDir, { recursive: true, force: true });
console.log(
    JSON.stringify({
        calls,
        drained,
        matched: agent.hook.stats.matched,
        losses: Object.fromEntries(Object.entries(stats.losses).map(([k, v]) => [k, Number(v)])),
        digests: [...new Set(digests)],
    }),
);
