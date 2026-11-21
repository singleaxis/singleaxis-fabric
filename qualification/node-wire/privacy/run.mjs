#!/usr/bin/env node
// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// The `ts-wire-privacy` gate of spec 055 §9.2 (unit 055-t8; extended by 055-t13, -t14, -t16,
// -t20, -t21): canary scan, scanner self-test and (055-t12) the network step.
//
//   node qualification/node-wire/privacy/run.mjs --out report.json
//
// Canary scan: one scenario per privacy mode (retain_original, metadata_only, omit,
// redact, masked_only, tokenize) and one with content capture disabled
// (missing_id_key) runs an agent in its own process (children/scenario.mjs) with
// canaries planted in the prompt, tool schema, response, URL path and query, request
// and response headers, an abort reason's Error.name and message, a transport error,
// the clear run id, the agent id, the service name, the resource attributes and the
// environment. The scanner then reads every byte Fabric produced: every file under the
// spool directory (records raw and decrypted, temps, quarantine, locks, ledger) and the
// agent process's own output; then (055-t13) the SDK's sender delivers the spool to a
// recording sink and every OTLP request it received is scanned too. A canary may appear
// only inside a content object whose
// role policy retains the original (`retain_original`), and only a body canary; under
// every other mode none appears anywhere, encrypted or not, and no digest, range or
// length of an original appears for a withheld or transformed object. Scenarios whose
// spool holds fewer exchange records than calls fail (a vacuous scan proves nothing).
//
// Network step (unit 055-t12, lib/network.mjs): Fabric's delivery clients and redaction
// client in a child with hostile HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY and Node's
// startup proxy mode; 301/302/303/307/308 from the delivery and redaction endpoints; a
// recording socket on every address that was not configured. No Fabric byte or header
// may reach a proxy, a redirect target or the provider.
//
// Artifact step (unit 055-t14, lib/artifact.mjs): with --artifact, the packed tarball's
// contents, the status file and exit note a preloaded agent leaves, and a self-test.
//
// Scanner self-test: the retain_original scenario again with a test-only fault in the
// harness's Fabric worker that leaks one canary into a span attribute and one into a
// spool header; the scanner must report both, or the gate fails. Then (055-t13) a
// span-only leak, whose record the sender delivers: the sink scan must report it.
//
// Exits 1 when any check fails. Writes a JSON report with `--out`.

import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmodSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { canaryScan, checkTarball, selfTest as artifactSelfTest } from "./lib/artifact.mjs";
import { REPO, build } from "./lib/build.mjs";
import { networkStep } from "./lib/network.mjs";
import { imageNeedle } from "./lib/part.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const OUT = args.includes("--out") ? args[args.indexOf("--out") + 1] : undefined;
// --network-only: the network step and its self-test alone (CI runs it again on a Node
// with the http/https startup proxy mode). --require-startup-proxy-mode: fail unless this
// Node has that mode (24.5 and later), so the run cannot pass without exercising it.
// --artifact TARBALL (unit 055-t14): the artifact step over the packed npm tarball (file
// list, package.json scripts and dependencies, dist/ and prebuilds/ strings, symbols and
// loaded modules) with its self-test, and the canary scan of the status file and exit
// note a preloaded agent leaves. --artifact-only: that step alone.
const ARTIFACT = args.includes("--artifact") ? args[args.indexOf("--artifact") + 1] : undefined;
const ARTIFACT_ONLY = args.includes("--artifact-only");
const NETWORK_ONLY = args.includes("--network-only");
const REQUIRE_PROXY_MODE = args.includes("--require-startup-proxy-mode");
const log = (line) => process.stderr.write(`${line}\n`);

const MODES = [
    "retain_original", "metadata_only", "omit", "redact", "masked_only", "tokenize",
    // 055-t15: the original and its masked review copy; and with no transformation, so
    // every review fails and each pair is withheld.
    "original_plus_masked", "original_plus_masked_unreviewed",
    "disabled",
]; // prettier-ignore
// Modes whose policy authorizes retaining the original bytes.
const RETAINING = new Set(["retain_original", "original_plus_masked"]);
// `image` is planted as the bytes of the split call's inline image (lib/part.mjs): the
// scan looks for a slice of its base64 text, the form in which it travels.
const BODY_CANARIES = ["prompt", "tool_schema", "response", "image"];
const OTHER_CANARIES = [
    "url_path", "url_query", "authorization", "cookie", "api_key", "set_cookie", "request_id",
    "error_name", "error_message", "run_id", "agent_id", "service_name", "resource", "environment",
    // planted only by the scanner self-test's fault
    "leak_attribute", "leak_header",
]; // prettier-ignore

/** The artifact step over the packed tarball, with its self-test; `undefined` without one. */
async function artifactStep() {
    if (ARTIFACT === undefined) return undefined;
    const tarball = isAbsolute(ARTIFACT) ? ARTIFACT : join(process.cwd(), ARTIFACT);
    const contents = checkTarball(tarball);
    log(`artifact: ${contents.violations.length === 0 ? "passed" : "FAILED"} (${contents.files} files, prebuilds ${contents.prebuilds.join(", ") || "none"}, ${contents.violations.length} violations)`);
    const canaries = await canaryScan(tarball);
    log(`artifact canary scan: ${canaries.passed ? "passed" : "FAILED"} (status file ${JSON.stringify(canaries.status_file)}, exit note ${canaries.exit_note_written ? "written" : "absent"}, ${canaries.violations.length} violations)`);
    const self = await artifactSelfTest(tarball);
    log(`artifact self-test: ${self.passed ? "reported every planted violation" : `missed ${self.missed.join(", ") || "the status-file leak"}`}`);
    return { contents, canaries, self };
}

if (ARTIFACT_ONLY) {
    const step = await artifactStep();
    const gates = {
        artifact: step !== undefined && step.contents.violations.length === 0 && step.canaries.passed,
        artifact_self_test: step?.self.passed === true,
    };
    const report = {
        schema: "fabric.node-wire-privacy-report/v1",
        spec: "055 §9.2 ts-wire-privacy (artifact step)",
        node: process.versions.node,
        artifact_only: true,
        gates,
        artifact: step,
        result: Object.values(gates).every(Boolean) ? "passed" : "failed",
    };
    if (OUT !== undefined) writeFileSync(OUT, `${JSON.stringify(report, null, 2)}\n`);
    log(`gates: ${JSON.stringify(gates)}`);
    log(`result: ${report.result}`);
    process.exit(report.result === "passed" ? 0 : 1);
}

const bundle = build();
const codec = loadCodec();

/** The spool codec (unseal, unframe) from the SDK source, bundled for this script. */
function loadCodec() {
    const require = createRequire(join(REPO, "sdk", "typescript", "package.json"));
    const { buildSync } = require("esbuild");
    const out = join(bundle.dir, "codec.cjs");
    buildSync({
        entryPoints: [join(REPO, "sdk", "typescript", "src", "wire", "spool-codec.ts")],
        outfile: out,
        bundle: true,
        platform: "node",
        format: "cjs",
        target: "node24",
        logLevel: "silent",
    });
    return createRequire(import.meta.url)(out);
}

function canaries() {
    const tag = randomBytes(4).toString("hex");
    return Object.fromEntries(
        [...BODY_CANARIES, ...OTHER_CANARIES].map((name) => [name, `FWCANARY.${name.replace(/_/g, "-")}.${tag}`]),
    );
}

function files(dir) {
    const out = [];
    for (const name of readdirSync(dir)) {
        const path = join(dir, name);
        const info = lstatSync(path);
        if (info.isDirectory()) out.push(...files(path));
        else if (info.isFile()) out.push(path);
    }
    return out;
}

/** Every place `needle` occurs in `haystack` as text or as its hex. */
function found(haystack, needle) {
    return haystack.includes(needle) || haystack.includes(Buffer.from(needle).toString("hex"));
}

/**
 * Scans every byte Fabric produced in one scenario. Returns the violations: where a
 * canary, an original digest or an original's range/length appeared that the mode does
 * not authorize.
 */
function scan({ dir, key, mode, C, output, digests }) {
    const violations = [];
    const stats = {
        files: 0, records: 0, exchanges: 0, retained_objects: 0, planted_found: [],
        // non-vacuity: what each mode is expected to have produced
        transformed_objects: 0, descriptor_only_objects: 0, store_reasons: [],
        // 055-t15: split requests (parts, and the parts' byte ranges)
        part_objects: 0, part_ranges: 0,
    }; // prettier-ignore
    const retain = RETAINING.has(mode);
    const check = (where, text, allowBody) => {
        for (const name of OTHER_CANARIES) if (found(text, C[name])) violations.push({ where, canary: name });
        for (const name of BODY_CANARIES) {
            if (!allowBody && found(text, C[name])) violations.push({ where, canary: name });
        }
    };
    const spool = join(dir, "spool");
    for (const path of files(spool)) {
        stats.files++;
        const where = relative(dir, path);
        const raw = readFileSync(path);
        check(`${where} (raw)`, raw.toString("latin1"), false);
        if (!raw.subarray(0, 8).equals(codec.ENVELOPE_MAGIC) && !raw.subarray(0, 8).equals(codec.MAGIC)) continue;
        let inner;
        try {
            inner = raw.subarray(0, 8).equals(codec.ENVELOPE_MAGIC)
                ? codec.unseal(raw, path.split("/").pop().replace(/\.corrupt$/, ""), key, codec.spoolKeyId(key))
                : raw;
        } catch (error) {
            violations.push({ where, error: `undecryptable record: ${error.constructor.name}` });
            continue;
        }
        // The plaintext as bytes first, whether or not it parses: no canary but a body
        // canary may appear in it at all (body canaries are placed by the structure below).
        const plain = inner.toString("latin1");
        for (const name of OTHER_CANARIES) {
            if (found(plain, C[name])) violations.push({ where: `${where} (decrypted)`, canary: name });
        }
        let records;
        try {
            records = codec.unframeAll(inner);
        } catch (error) {
            violations.push({ where, error: `unreadable record: ${error.constructor.name}` });
            check(`${where} (decrypted, unparsed)`, plain, false);
            continue;
        }
        for (const { doc, blob } of records) {
            stats.records++;
            if (doc.record_kind === "exchange") {
                stats.exchanges++;
                const reason = doc.span?.attributes?.["fabric.wire.store_reason"];
                if (reason !== undefined && !stats.store_reasons.includes(reason)) stats.store_reasons.push(reason);
            }
            const header = JSON.stringify(doc, (_k, v) => (typeof v === "bigint" ? v.toString() : v));
            check(`${where} header`, header, false);
            for (const digest of digests) {
                if (!retain && header.includes(digest)) violations.push({ where: `${where} header`, original_digest: digest });
            }
            const masked = Buffer.from(blob);
            for (const body of doc.bodies ?? []) {
                const d = body.descriptor;
                // An original the policy retains (never a review copy, which is redacted).
                const authorized =
                    retain && RETAINING.has(d.privacy_mode) && d.protection_status === "retained" && "stored_sha256" in d;
                if (authorized) stats.retained_objects++;
                // A part's byte_range lives in its part_of link.
                const ranged = "byte_range" in d || (d.links ?? []).some((link) => "byte_range" in link);
                if (d.role === "model.exchange.part") stats.part_objects++;
                if (ranged) stats.part_ranges++;
                // Transformed: redact, masked_only, tokenize and an original_plus_masked
                // review copy. None carries the original's digest, length or range.
                const transformed =
                    ["redact", "masked_only", "tokenize"].includes(d.privacy_mode) ||
                    (d.privacy_mode === "original_plus_masked" && d.protection_status === "redacted");
                if (transformed && ("source_sha256" in d || "source_byte_length" in d || ranged)) {
                    violations.push({ where: `${where} descriptor`, transformed_original_evidence: d.role });
                }
                // A withheld review pair keeps no digest, length or range of the original.
                if (d.status_reason === "protection_failed" && ("source_sha256" in d || "source_byte_length" in d || ranged)) {
                    violations.push({ where: `${where} descriptor`, withheld_original_evidence: d.role });
                }
                if (transformed && "stored_sha256" in d) {
                    stats.transformed_objects++;
                    const stored = blob.subarray(body.offset, body.offset + body.length).toString("latin1");
                    // a token is the HMAC text only; a masked object is the service's output
                    const expected = d.privacy_mode === "tokenize" ? /^fabric\.token\.v1:[0-9a-f]{64}$/ : /^\{"masked":true\}$/;
                    if (!expected.test(stored)) violations.push({ where: `${where} body ${d.role}`, unexpected_transformed_bytes: d.privacy_mode });
                }
                if (!("stored_sha256" in d)) stats.descriptor_only_objects++;
                if (!retain && ("source_sha256" in d || ranged)) {
                    violations.push({ where: `${where} descriptor`, original_digest_or_range: d.role });
                }
                if (["redact", "masked_only", "tokenize"].includes(d.privacy_mode) && "source_byte_length" in d) {
                    violations.push({ where: `${where} descriptor`, original_length: d.role });
                }
                const slice = blob.subarray(body.offset, body.offset + body.length).toString("latin1");
                check(`${where} body ${d.role}`, slice, authorized);
                if (authorized) {
                    for (const name of BODY_CANARIES) {
                        if (found(slice, C[name]) && !stats.planted_found.includes(name)) stats.planted_found.push(name);
                    }
                }
                if (authorized) masked.fill(0, body.offset, body.offset + body.length);
            }
            check(`${where} blob`, masked.toString("latin1"), false);
        }
    }
    check("agent output", output, false);
    return { violations, stats };
}

/**
 * Delivers a scenario's spool with the SDK's sender to a loopback sink that records every
 * request body, then scans them (055-t13): no canary in any span (`/v1/traces`); in the
 * content logs (`/v1/logs`) only a body canary, and only where the mode retains the
 * original; no original digest where the mode withholds or transforms it.
 */
async function deliverAndScan({ dir, key, mode, C, digests }) {
    const received = [];
    const sink = http.createServer((req, res) => {
        const parts = [];
        req.on("data", (part) => parts.push(part));
        req.on("end", () => {
            received.push({ path: req.url, body: Buffer.concat(parts) });
            res.writeHead(200, { "content-type": "application/x-protobuf" }).end();
        });
    });
    await new Promise((resolve) => sink.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${sink.address().port}`;
    let outcome;
    try {
        outcome = await createRequire(import.meta.url)(bundle.deliver).deliverSpool({
            spoolDir: join(dir, "spool"),
            key,
            prebuilds: bundle.prebuilds,
            digest: bundle.digest,
            url,
        });
    } finally {
        sink.closeAllConnections();
        sink.close();
    }
    const violations = [];
    const retain = RETAINING.has(mode);
    for (const { path, body } of received) {
        const text = body.toString("latin1");
        const where = `sink ${path}`;
        for (const name of OTHER_CANARIES) if (found(text, C[name])) violations.push({ where, canary: name });
        for (const name of BODY_CANARIES) {
            if (found(text, C[name]) && !(retain && path === "/v1/logs")) violations.push({ where, canary: name });
        }
        if (!retain) {
            for (const digest of digests) if (text.includes(digest)) violations.push({ where, original_digest: digest });
        }
    }
    return {
        violations,
        delivered: {
            left: outcome.left,
            trace_requests: received.filter((r) => r.path === "/v1/traces").length,
            content_requests: received.filter((r) => r.path === "/v1/logs").length,
            stats: outcome.stats,
        },
    };
}

async function scenario(mode, options = {}) {
    const dir = mkdtempSync(join(tmpdir(), `f055-t8-privacy-${mode}-`));
    chmodSync(dir, 0o700);
    const C = canaries();
    const spoolKey = randomBytes(32);
    const leaks = [C.leak_attribute, C.leak_header];
    const done = spawnSync(
        process.execPath,
        [
            join(HERE, "children", "scenario.mjs"),
            JSON.stringify({
                mode,
                dir,
                agent: bundle.agent,
                worker: bundle.worker,
                prebuilds: bundle.prebuilds,
                digest: bundle.digest,
                canaries: C,
                spool_key_b64: spoolKey.toString("base64"),
                fault: options.fault,
                leaks,
            }),
        ],
        { encoding: "utf8", timeout: 300_000, env: { PATH: process.env.PATH ?? "" } },
    );
    let result;
    try {
        result = JSON.parse(done.stdout.trim().split("\n").pop());
    } catch {
        result = undefined;
    }
    const output = `${done.stdout}\n${done.stderr}`;
    if (result === undefined) {
        rmSync(dir, { recursive: true, force: true });
        return { mode, passed: false, error: `scenario exited ${done.status}: ${done.stderr.slice(0, 2000)}` };
    }
    // The scenario's own JSON line carries only digests; everything else is the agent's.
    // The image canary travels as base64: the scan looks for a slice of that text.
    const needles = { ...C, image: imageNeedle(C.image) };
    const scanned = scan({ dir, key: spoolKey, mode, C: needles, output, digests: result.digests });
    // 055-t13: the spool delivered by the SDK's sender; every OTLP byte the sink received.
    const sent = await deliverAndScan({ dir, key: spoolKey, mode, C: needles, digests: result.digests });
    scanned.violations.push(...sent.violations);
    rmSync(dir, { recursive: true, force: true });
    // Not vacuous: every call left a record, and where retention is authorized the
    // planted body canaries were found inside the retained objects.
    const planted = !RETAINING.has(mode) || BODY_CANARIES.every((n) => scanned.stats.planted_found.includes(n));
    // Each mode must have done its work, or its scan proves nothing: every request (all
    // five complete) became a stored transformed object under redact, masked_only and
    // tokenize, a descriptor under metadata_only; the disabled run names its reason.
    // 055-t15: the split call became a skeleton and a part (with its range only where the
    // original is retained); under original_plus_masked every request has its original
    // and a review copy, and with no transformation every pair is withheld.
    const s = scanned.stats;
    const split = s.part_objects >= 1 && (RETAINING.has(mode) ? s.part_ranges >= 1 : s.part_ranges === 0);
    const worked = {
        retain_original: split,
        redact: s.transformed_objects >= result.calls && split,
        masked_only: s.transformed_objects >= result.calls && split,
        tokenize: s.transformed_objects >= result.calls && split,
        original_plus_masked: s.retained_objects >= result.calls && s.transformed_objects >= result.calls && split,
        original_plus_masked_unreviewed:
            s.retained_objects === 0 && s.transformed_objects === 0 && s.descriptor_only_objects >= 2 * result.calls,
        metadata_only: s.descriptor_only_objects >= result.calls,
        omit: s.descriptor_only_objects === 0 && s.transformed_objects === 0,
        disabled: s.store_reasons.length === 1 && s.store_reasons[0] === "missing_id_key",
    }[mode] ?? true;
    const enough = scanned.stats.exchanges >= result.calls && planted && worked;
    return {
        mode,
        calls: result.calls,
        matched: result.matched,
        drained: result.drained,
        losses: result.losses,
        ...scanned.stats,
        mode_did_its_work: worked,
        delivered: sent.delivered,
        violations: scanned.violations,
        passed:
            scanned.violations.length === 0 &&
            enough &&
            sent.delivered.left === 0 &&
            sent.delivered.trace_requests > 0 &&
            result.drained === true &&
            result.matched >= result.calls,
    };

}

const scenarios = [];
for (const mode of NETWORK_ONLY ? [] : MODES) {
    const row = await scenario(mode);
    log(`${mode}: ${row.passed ? "passed" : "FAILED"} (${row.exchanges ?? 0} exchange records, ${row.violations?.length ?? "?"} violations)`);
    scenarios.push(row);
}
// Scanner self-test: the leaked canaries must be reported, in a span attribute and in a
// spool header, or the scanner cannot be trusted.
const fault = NETWORK_ONLY ? undefined : await scenario("retain_original", { fault: "leak" });
const reported = new Set((fault?.violations ?? []).map((v) => v.canary));
// 055-t13: a span-only leak keeps the record valid, so the sender delivers it; the scan
// of the OTLP requests the sink received must report the canary there.
const sinkFault = NETWORK_ONLY ? undefined : await scenario("retain_original", { fault: "leak_span" });
const reportedAtSink = (sinkFault?.violations ?? []).some(
    (v) => v.canary === "leak_attribute" && v.where === "sink /v1/traces",
);
const selfTestDetected = reported.has("leak_attribute") && reported.has("leak_header") && reportedAtSink;
if (!NETWORK_ONLY) log(`scanner self-test: ${selfTestDetected ? "reported every leak (spool and sink)" : "did NOT report every leak"}`);
// Network step (055-t12): hostile proxy environment and startup proxy mode, redirects
// from the delivery and redaction endpoints, recording sockets on every other address.
const network = await networkStep(bundle.network);
log(`network: ${network.passed ? "passed" : "FAILED"} (${network.violations.length} violations)`);
// Its self-test: one body sent through the global fetch dispatcher (which honours the
// proxy environment and follows redirects) must be reported, or the step proves nothing.
const networkFault = await networkStep(bundle.network, { fault: "fetch" });
let networkSelfTest = networkFault.violations.some((v) => ["HTTP_PROXY", "redirect Location"].includes(v.where));
// Where this Node has the http/https startup proxy mode, a body sent on Node's global
// agent must reach HTTP_PROXY: that proves the mode Fabric's private agents ignore was
// live in the child, so the clean run's silence means something.
const proxyMode = network.startup_proxy_mode_active === true;
const globalAgentFault = proxyMode ? await networkStep(bundle.network, { fault: "global_agent" }) : undefined;
if (globalAgentFault !== undefined) {
    networkSelfTest &&= globalAgentFault.violations.some((v) => v.where === "HTTP_PROXY");
}
log(`network self-test: ${networkSelfTest ? "reported the leak" : "did NOT report the leak"}`);
log(`startup proxy mode: ${network.startup_proxy_mode}`);
if (REQUIRE_PROXY_MODE && !proxyMode) {
    log(`--require-startup-proxy-mode: Node ${process.versions.node} has no http/https startup proxy mode; run this step on Node 24.5 or later`);
}
rmSync(bundle.dir, { recursive: true, force: true });
const artifact = NETWORK_ONLY ? undefined : await artifactStep();

const canaryScanPassed = scenarios.every((row) => row.passed);
const report = {
    schema: "fabric.node-wire-privacy-report/v1",
    spec: "055 §9.2 ts-wire-privacy",
    node: process.versions.node,
    scanned: [
        "spool files raw (every file under FABRIC_WIRE_SPOOL_DIR: records, temps, quarantine, locks, ledger)",
        "spool records decrypted (headers, descriptors, every body)",
        "the agent process's output (stdout and stderr)",
        "the OTLP requests a sink received when the SDK's sender delivered the spool (content logs and spans)",
        "network: every byte and connection reaching a hostile proxy, a redirect target, the provider or the configured proxy",
        ...(artifact === undefined
            ? []
            : [
                  "the packed npm tarball: file list, package.json scripts and dependencies, dist/ and prebuilds/ strings, loaded modules, exported symbols",
                  "the status file and the spool's exit note a preloaded agent leaves",
              ]),
    ],
    not_yet_scanned: {
        "the Node's persistent queue and the store (e2e with the real Node)": "055-t17",
        "registration files and the loss ledger under faults": "055-t16",
        ...(artifact === undefined ? { "the status file, the exit note and the packed tarball": "run with --artifact" } : {}),
    },
    gates: {
        ...(NETWORK_ONLY ? {} : { canary_scan: canaryScanPassed, scanner_self_test: selfTestDetected }),
        ...(artifact === undefined
            ? {}
            : { artifact: artifact.contents.violations.length === 0 && artifact.canaries.passed, artifact_self_test: artifact.self.passed }),
        network: network.passed,
        network_self_test: networkSelfTest,
        ...(REQUIRE_PROXY_MODE ? { startup_proxy_mode: proxyMode } : {}),
    },
    ...(NETWORK_ONLY ? { network_only: true } : { scenarios, self_test: fault, self_test_sink: sinkFault }),
    ...(artifact === undefined ? {} : { artifact }),
    network,
    network_self_test: networkFault,
    ...(globalAgentFault === undefined ? {} : { network_self_test_global_agent: globalAgentFault }),
};
report.result = Object.values(report.gates).every(Boolean) ? "passed" : "failed";
if (OUT !== undefined) writeFileSync(OUT, `${JSON.stringify(report, null, 2)}\n`);
log(`gates: ${JSON.stringify(report.gates)}`);
log(`result: ${report.result}`);
process.exitCode = report.result === "passed" ? 0 : 1;
