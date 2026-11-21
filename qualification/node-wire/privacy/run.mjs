#!/usr/bin/env node
// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// The `ts-wire-privacy` gate of spec 055 §9.2 (unit 055-t8; extended by 055-t13, -t16,
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
// agent process's own output. A canary may appear only inside a content object whose
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
// Scanner self-test: the retain_original scenario again with a test-only fault in the
// harness's Fabric worker that leaks one canary into a span attribute and one into a
// spool header; the scanner must report both, or the gate fails.
//
// Exits 1 when any check fails. Writes a JSON report with `--out`.

import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmodSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { REPO, build } from "./lib/build.mjs";
import { networkStep } from "./lib/network.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const OUT = args.includes("--out") ? args[args.indexOf("--out") + 1] : undefined;
const log = (line) => process.stderr.write(`${line}\n`);

const MODES = ["retain_original", "metadata_only", "omit", "redact", "masked_only", "tokenize", "disabled"];
const BODY_CANARIES = ["prompt", "tool_schema", "response"];
const OTHER_CANARIES = [
    "url_path", "url_query", "authorization", "cookie", "api_key", "set_cookie", "request_id",
    "error_name", "error_message", "run_id", "agent_id", "service_name", "resource", "environment",
    // planted only by the scanner self-test's fault
    "leak_attribute", "leak_header",
]; // prettier-ignore

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
    }; // prettier-ignore
    const retain = mode === "retain_original";
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
                const authorized = d.privacy_mode === "retain_original" && retain && "stored_sha256" in d;
                if (authorized) stats.retained_objects++;
                if (["redact", "masked_only", "tokenize"].includes(d.privacy_mode) && "stored_sha256" in d) {
                    stats.transformed_objects++;
                    const stored = blob.subarray(body.offset, body.offset + body.length).toString("latin1");
                    // a token is the HMAC text only; a masked object is the service's output
                    const expected = d.privacy_mode === "tokenize" ? /^fabric\.token\.v1:[0-9a-f]{64}$/ : /^\{"masked":true\}$/;
                    if (!expected.test(stored)) violations.push({ where: `${where} body ${d.role}`, unexpected_transformed_bytes: d.privacy_mode });
                }
                if (!("stored_sha256" in d)) stats.descriptor_only_objects++;
                if (!retain && ("source_sha256" in d || "byte_range" in d)) {
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

function scenario(mode, options = {}) {
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
    const scanned = scan({ dir, key: spoolKey, mode, C, output, digests: result.digests });
    rmSync(dir, { recursive: true, force: true });
    // Not vacuous: every call left a record, and where retention is authorized the
    // planted body canaries were found inside the retained objects.
    const planted = mode !== "retain_original" || BODY_CANARIES.every((n) => scanned.stats.planted_found.includes(n));
    // Each mode must have done its work, or its scan proves nothing: every request (all
    // five complete) became a stored transformed object under redact, masked_only and
    // tokenize, a descriptor under metadata_only; the disabled run names its reason.
    const s = scanned.stats;
    const worked = {
        redact: s.transformed_objects >= result.calls,
        masked_only: s.transformed_objects >= result.calls,
        tokenize: s.transformed_objects >= result.calls,
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
        violations: scanned.violations,
        passed: scanned.violations.length === 0 && enough && result.drained === true && result.matched >= result.calls,
    };

}

const scenarios = MODES.map((mode) => {
    const row = scenario(mode);
    log(`${mode}: ${row.passed ? "passed" : "FAILED"} (${row.exchanges ?? 0} exchange records, ${row.violations?.length ?? "?"} violations)`);
    return row;
});
// Scanner self-test: the leaked canaries must be reported, in a span attribute and in a
// spool header, or the scanner cannot be trusted.
const fault = scenario("retain_original", { fault: "leak" });
const reported = new Set((fault.violations ?? []).map((v) => v.canary));
const selfTestDetected = reported.has("leak_attribute") && reported.has("leak_header");
log(`scanner self-test: ${selfTestDetected ? "reported both leaks" : "did NOT report both leaks"}`);
// Network step (055-t12): hostile proxy environment and startup proxy mode, redirects
// from the delivery and redaction endpoints, recording sockets on every other address.
const network = await networkStep(bundle.network);
log(`network: ${network.passed ? "passed" : "FAILED"} (${network.violations.length} violations)`);
// Its self-test: one body sent through the global fetch dispatcher (which honours the
// proxy environment and follows redirects) must be reported, or the step proves nothing.
const networkFault = await networkStep(bundle.network, { fault: "fetch" });
const networkSelfTest = networkFault.violations.some((v) => ["HTTP_PROXY", "redirect Location"].includes(v.where));
log(`network self-test: ${networkSelfTest ? "reported the leak" : "did NOT report the leak"}`);
rmSync(bundle.dir, { recursive: true, force: true });

const canaryScan = scenarios.every((row) => row.passed);
const report = {
    schema: "fabric.node-wire-privacy-report/v1",
    spec: "055 §9.2 ts-wire-privacy",
    node: process.versions.node,
    scanned: [
        "spool files raw (every file under FABRIC_WIRE_SPOOL_DIR: records, temps, quarantine, locks, ledger)",
        "spool records decrypted (headers, descriptors, every body)",
        "the agent process's output (stdout and stderr)",
        "network: every byte and connection reaching a hostile proxy, a redirect target, the provider or the configured proxy",
    ],
    not_yet_scanned: {
        "OTLP requests at the sink, the Node queue and the store": "055-t13",
        "registration files and the loss ledger under faults": "055-t16",
        "the status file and the exit note": "055-t14",
    },
    gates: { canary_scan: canaryScan, scanner_self_test: selfTestDetected, network: network.passed, network_self_test: networkSelfTest },
    scenarios,
    self_test: fault,
    network,
    network_self_test: networkFault,
};
report.result = Object.values(report.gates).every(Boolean) ? "passed" : "failed";
if (OUT !== undefined) writeFileSync(OUT, `${JSON.stringify(report, null, 2)}\n`);
log(`gates: ${JSON.stringify(report.gates)}`);
log(`result: ${report.result}`);
process.exitCode = report.result === "passed" ? 0 : 1;
