// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/* global Buffer, process */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { spawnSync } from "node:child_process";
import {
    existsSync,
    mkdtempSync,
    mkdirSync,
    readFileSync,
    renameSync,
    rmSync,
    writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { URL } from "node:url";

import {
    EXPECTED_PACKAGE_FILES,
    FORBIDDEN_RECORDER_TOKENS,
    PACKAGE_NAME,
    validatePackRecord,
    validateRecorderPayloads,
} from "../scripts/package-qualified.mjs";

function metadata(bytes, overrides = {}) {
    return {
        name: PACKAGE_NAME,
        version: "1.2.3-beta.1",
        size: bytes.length,
        shasum: createHash("sha1").update(bytes).digest("hex"),
        integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
        files: EXPECTED_PACKAGE_FILES.map((path) => ({ path, size: 1, mode: 0o644 })),
        ...overrides,
    };
}

test("accepts one exact, integrity-bound package allowlist", () => {
    const bytes = Buffer.from("qualified-artifact");
    const result = validatePackRecord(metadata(bytes), bytes, "1.2.3-beta.1");
    assert.equal(result.sha256, createHash("sha256").update(bytes).digest("hex"));
    assert.deepEqual(result.files, [...EXPECTED_PACKAGE_FILES].sort());
});

test("rejects an undeclared file even when npm metadata includes it", () => {
    const bytes = Buffer.from("qualified-artifact");
    const record = metadata(bytes);
    record.files.push({ path: "src/private.ts", size: 1, mode: 0o644 });
    assert.throws(
        () => validatePackRecord(record, bytes, "1.2.3-beta.1"),
        /unexpected=\[src\/private\.ts\]/,
    );
});

test("rejects altered bytes and version drift", () => {
    const original = Buffer.from("qualified-artifact");
    const record = metadata(original);
    assert.throws(
        () => validatePackRecord(record, Buffer.from("tampered-artifact"), "1.2.3-beta.1"),
        /SHA-1 does not match/,
    );
    assert.throws(() => validatePackRecord(record, original, "1.2.4"), /expected 1\.2\.4/);
});

test("rejects hidden control or evaluation code in packed JS and declarations", () => {
    for (const token of FORBIDDEN_RECORDER_TOKENS) {
        assert.throws(
            () => validateRecorderPayloads({ "dist/index.js": `class Decision { ${token}() {} }` }),
            /contains forbidden token/,
        );
    }
});

test("accepts recorder-only packed payloads", () => {
    assert.doesNotThrow(() =>
        validateRecorderPayloads({
            "dist/index.js": "class Decision { recordRetrieval() {} recordSideEffect() {} }",
            "dist/index.d.ts": "declare class Decision { recordRetrieval(): void }",
        }),
    );
});

test(
    "built local store rejects FIFO reads without blocking",
    { skip: process.platform === "win32" },
    () => {
        const root = mkdtempSync(join(tmpdir(), "fabric-fifo-"));
        try {
            const tenant = join(root, "acme");
            mkdirSync(tenant);
            const fifo = join(tenant, "fifo");
            const made = spawnSync("mkfifo", [fifo], { timeout: 2000, encoding: "utf8" });
            assert.equal(made.status, 0, made.stderr);
            const code = `
            import { LocalFilesystemContentStore } from ${JSON.stringify(new URL("../dist/index.js", import.meta.url).href)};
            const store = new LocalFilesystemContentStore(process.argv[1], "acme");
            try { store.read(process.argv[2]); process.exitCode = 2; }
            catch (error) { if (!/regular file/.test(error.message)) throw error; }
        `;
            const result = spawnSync(
                process.execPath,
                ["--input-type=module", "-e", code, root, `file://${fifo}`],
                { timeout: 2000, encoding: "utf8" },
            );
            assert.equal(result.error, undefined, result.error?.message);
            assert.equal(result.status, 0, result.stderr);
        } finally {
            rmSync(root, { recursive: true, force: true });
        }
    },
);

// ------------------------------------------------------------------------------------
// Spec 055 §9.4 / §9.5 (unit 055-t14): the packed tarball (FABRIC_TEST_NODE_TARBALL, from
// `npm run package:qualified`) installed into an application directory, as a customer
// installs it. Skipped without a tarball unless FABRIC_REQUIRE_NODE_E2E=1.

const TARBALL = process.env.FABRIC_TEST_NODE_TARBALL;
const REQUIRED = process.env.FABRIC_REQUIRE_NODE_E2E === "1";
const [MAJOR, MINOR] = process.versions.node.split(".").map(Number);
const CAPTURING_NODE = MAJOR > 24 || (MAJOR === 24 && MINOR >= 4);
const packaged = {
    skip: TARBALL === undefined && !REQUIRED ? "no FABRIC_TEST_NODE_TARBALL" : false,
};

let appDir;
function app() {
    if (appDir !== undefined) return appDir;
    assert.ok(TARBALL, "FABRIC_TEST_NODE_TARBALL=1 is required (FABRIC_REQUIRE_NODE_E2E=1)");
    appDir = mkdtempSync(join(tmpdir(), "f055-t14-artifact-"));
    writeFileSync(join(appDir, "package.json"), '{"name":"artifact-app","private":true}\n');
    const env = {
        ...process.env,
        npm_config_update_notifier: "false",
        npm_config_cache: join(appDir, ".npm"),
    };
    delete env.NODE_OPTIONS;
    const done = spawnSync(
        "npm",
        ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false", TARBALL],
        { cwd: appDir, env, encoding: "utf8", timeout: 300_000 },
    );
    assert.equal(done.status, 0, done.stderr);
    activateHere(join(appDir, "node_modules", "@singleaxis", "fabric"));
    return appDir;
}

test.after(() => {
    if (appDir !== undefined) rmSync(appDir, { recursive: true, force: true });
});

/** This build's native target, as the loader names it. */
function target() {
    if (process.platform === "darwin") return `darwin-${process.arch}`;
    const glibc = process.report?.getReport()?.header?.glibcVersionRuntime !== undefined;
    return `linux-${process.arch}-${glibc ? "glibc" : "musl"}`;
}

/**
 * Tests activate capture through the table (spec 055 §9.5): where the installed table
 * lists no active tuple for this build (a developer's laptop), its copy gains one. The
 * package's code is unchanged.
 */
function activateHere(root) {
    const path = join(root, "dist", "wire-qualification.json");
    const table = JSON.parse(readFileSync(path, "utf8"));
    const build = {
        node: process.versions.node,
        undici: process.versions.undici,
        platform: target(),
    };
    const listed = table.tuples.some(
        (t) =>
            t.point === "wire.ts.undici" &&
            t.claim === "active" &&
            t.node === build.node &&
            t.platform === build.platform &&
            t.undici === build.undici,
    );
    if (listed) return;
    table.tuples.push({
        point: "wire.ts.undici",
        ...build,
        undici_origin: "bundled",
        boundary: "pre_decompression",
        claim: "active",
        report_sha256: `sha256:${"0".repeat(64)}`,
    });
    writeFileSync(path, `${JSON.stringify(table, null, 2)}\n`);
}

/** Runs `source` (written as `name` in the app) with `env` only; returns its JSON line. */
function runApp(name, source, env = {}, args = []) {
    const dir = app();
    writeFileSync(join(dir, name), source);
    const spool = mkdtempSync(join(tmpdir(), "f055-t14-spool-"));
    const status = join(spool, "..", `${spool.split("/").pop()}-status.json`);
    const base = Object.fromEntries(
        Object.entries(process.env).filter(([k]) => !/^(FABRIC_|OTEL_|NODE_OPTIONS$)/.test(k)),
    );
    try {
        const done = spawnSync(process.execPath, [...args, name], {
            cwd: dir,
            encoding: "utf8",
            timeout: 60_000,
            env: {
                ...base,
                FABRIC_WIRE_SPOOL_DIR: spool,
                FABRIC_OTLP_ENDPOINT: "http://127.0.0.1:9",
                FABRIC_WIRE_STATUS_FILE: status,
                ...env,
            },
        });
        assert.equal(done.status, 0, done.stderr);
        const lines = done.stdout.trim().split("\n");
        let file;
        try {
            file = JSON.parse(readFileSync(status, "utf8"));
        } catch {
            file = undefined;
        }
        return { out: JSON.parse(lines[lines.length - 1]), stderr: done.stderr, status: file };
    } finally {
        rmSync(spool, { recursive: true, force: true });
        rmSync(status, { force: true });
    }
}

const PRELOAD = { FABRIC_WIRE_AUTOLOAD: "1", NODE_OPTIONS: "--import=@singleaxis/fabric/register" };

// One matched fetch to a local server; reports whether a hook is subscribed, whether
// install() returns one handle, and the handle's counters.
const PROBE_ESM = `
import diagnostics from "node:diagnostics_channel";
import { createServer } from "node:http";
import { install } from "@singleaxis/fabric/wire";
const server = createServer((req, res) => { req.resume(); req.on("end", () => res.end('{"ok":true}')); });
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const hooked = diagnostics.channel("undici:request:create").hasSubscribers;
const a = install(), b = install();
const port = server.address().port;
await (await fetch(\`http://127.0.0.1:\${port}/v1/chat/completions\`, { method: "POST", body: "{}" })).text();
server.close();
// One runtime: the preload and install() registered one epoch between them.
const { readdirSync } = await import("node:fs");
const epochs = readdirSync(process.env.FABRIC_WIRE_SPOOL_DIR + "/.epochs").filter((n) => n.endsWith(".reg")).length;
console.log(JSON.stringify({ hooked, same: a === b, capturing: a.capturing, reason: a.reason ?? null,
  matched: a.status().status?.matched ?? null, epochs }));
`;
const PROBE_CJS =
    PROBE_ESM.replace(
        /import diagnostics[^\n]*\nimport \{ createServer \}[^\n]*\nimport \{ install \}[^\n]*\n/,
        'const diagnostics = require("node:diagnostics_channel");\nconst { createServer } = require("node:http");\n' +
            'const { install } = require("@singleaxis/fabric/wire");\n(async () => {\n',
    ) + "})();\n";

function endpointEnv() {
    return {
        FABRIC_WIRE_ENDPOINTS: JSON.stringify([
            {
                endpoint_id: "artifact-model",
                dialect: "openai",
                hosts: ["127.0.0.1"],
                schemes: ["http"],
            },
        ]),
    };
}

test("packed: the tarball has no install script and no root binding.gyp", packaged, () => {
    const root = join(app(), "node_modules", "@singleaxis", "fabric");
    const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    for (const hook of [
        "preinstall",
        "install",
        "postinstall",
        "preprepare",
        "prepare",
        "postprepare",
    ]) {
        assert.equal(manifest.scripts?.[hook], undefined, hook);
    }
    assert.equal(manifest.gypfile, undefined);
    assert.equal(existsSync(join(root, "binding.gyp")), false);
    assert.equal(existsSync(join(root, "dist", "wire", "core.cjs")), true);
    assert.equal(manifest.bin, undefined); // spec 058 WP8-9 owns the bin key
    assert.deepEqual(Object.keys(manifest.exports), [
        ".",
        "./wire",
        "./register",
        "./wire-qualification.json",
    ]);
});

test("packed: the root import installs no hook, even with FABRIC_WIRE_AUTOLOAD=1", packaged, () => {
    const source = `
import diagnostics from "node:diagnostics_channel";
import * as fabric from "@singleaxis/fabric";
const names = ["undici:request:create", "undici:request:bodyChunkSent", "undici:request:bodyChunkReceived"];
console.log(JSON.stringify({ hooked: names.some((n) => diagnostics.channel(n).hasSubscribers),
  wire: "install" in fabric, slot: globalThis[Symbol.for("fabric.wire.runtime/1")] !== undefined }));
`;
    const { out, status } = runApp("root.mjs", source, { FABRIC_WIRE_AUTOLOAD: "1" });
    assert.deepEqual(out, { hooked: false, wire: false, slot: false });
    assert.equal(status, undefined); // nothing loaded the wire core: no status file
});

test("packed: without FABRIC_WIRE_AUTOLOAD the preload is inert (autoload_off)", packaged, () => {
    const source =
        'import diagnostics from "node:diagnostics_channel";\n' +
        'console.log(JSON.stringify({ hooked: diagnostics.channel("undici:request:create").hasSubscribers }));\n';
    const { out, stderr, status } = runApp("off.mjs", source, {
        NODE_OPTIONS: PRELOAD.NODE_OPTIONS,
        ...endpointEnv(),
    });
    assert.deepEqual(out, { hooked: false });
    assert.equal(stderr, "");
    assert.equal(status.capture, "disabled");
    assert.equal(status.status.capture_reason, "autoload_off");
    assert.deepEqual(status.notice_ids, ["FW-031"]);
});

for (const [label, file, source, args] of [
    ["--import, ES module app", "probe.mjs", PROBE_ESM, []],
    ["--import, CommonJS app", "probe.cjs", PROBE_CJS, []],
    [
        "--require, CommonJS app",
        "probe-r.cjs",
        PROBE_CJS,
        ["--require=@singleaxis/fabric/register"],
    ],
]) {
    test(
        `packed: the preload installs capture before the app (${label}); install() is the same runtime`,
        {
            ...packaged,
            skip: packaged.skip || (!CAPTURING_NODE && "needs Node.js 24.4 or newer"),
        },
        () => {
            const env =
                args.length > 0
                    ? { FABRIC_WIRE_AUTOLOAD: "1", ...endpointEnv() }
                    : { ...PRELOAD, ...endpointEnv() };
            const { out, stderr, status } = runApp(file, source, env, args);
            assert.deepEqual(out, {
                hooked: true,
                same: true,
                capturing: true,
                reason: null,
                matched: 1,
                epochs: 1,
            });
            assert.equal(stderr, ""); // silent by default (spec 055 §4.7)
            assert.equal(status.phase, "exit");
            assert.equal(status.capture, "closed");
            assert.equal(status.stats.matched, 1); // one hook, one capture: never duplicated
        },
    );
}

test(
    "packed: an install() with different settings after the preload throws fixed text",
    {
        ...packaged,
        skip: packaged.skip || (!CAPTURING_NODE && "needs Node.js 24.4 or newer"),
    },
    () => {
        const source = `
import { install } from "@singleaxis/fabric/wire";
let error = null;
try { install({ undici: false }); } catch (e) { error = { name: e.name, message: e.message }; }
console.log(JSON.stringify({ error }));
`;
        const { out } = runApp("conflict.mjs", source, { ...PRELOAD, ...endpointEnv() });
        assert.equal(out.error.name, "WireConfigError");
        assert.match(
            out.error.message,
            /already installed in this process with a different configuration/,
        );
    },
);

test(
    "packed: after close(), install() with other settings installs again; while capturing, " +
        "its own transformations throw",
    {
        ...packaged,
        skip: packaged.skip || (!CAPTURING_NODE && "needs Node.js 24.4 or newer"),
    },
    () => {
        const source = `
import { install } from "@singleaxis/fabric/wire";
const a = install();
let conflict = null;
try { install({ transformations: { "model.exchange.request": {} } }); } catch (e) { conflict = e.name; }
await a.close({ timeoutMs: 1000 });
const b = install({ undici: false });
console.log(JSON.stringify({ first: a.capturing, conflict, fresh: a !== b, again: install() === b,
  reason: b.reason ?? null }));
`;
        const { out } = runApp("reinstall.mjs", source, { ...PRELOAD, ...endpointEnv() });
        assert.deepEqual(out, {
            first: true,
            conflict: "WireConfigError",
            fresh: true,
            again: true,
            reason: "hook_disabled",
        });
    },
);

test(
    "packed: a model-looking request to an unconfigured host is listed with its fix (FW-006)",
    {
        ...packaged,
        skip: packaged.skip || (!CAPTURING_NODE && "needs Node.js 24.4 or newer"),
    },
    () => {
        const source = `
import { createServer } from "node:http";
const server = createServer((req, res) => { req.resume(); req.on("end", () => res.end("{}")); });
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
// The endpoint covers 127.0.0.1 only: localhost is a host no matcher covers.
await fetch(\`http://localhost:\${port}/v1/messages\`, { method: "POST", body: "{}" }).then((r) => r.text(), () => null);
server.close();
const { install } = await import("@singleaxis/fabric/wire");
const live = install().status();
console.log(JSON.stringify({ port, live: live.status.unmatched_model_hosts, ids: live.warning_ids }));
`;
        const { out, status } = runApp("unmatched.mjs", source, { ...PRELOAD, ...endpointEnv() });
        const row = {
            host: "localhost",
            port: out.port,
            count: 1,
            fix:
                `export FABRIC_WIRE_ENDPOINTS='[{"endpoint_id":"my-model","dialect":"anthropic",` +
                `"hosts":["localhost"],"ports":[${out.port}],"schemes":["http"]}]'`,
        };
        assert.deepEqual(out.live, [row]);
        assert.ok(out.ids.includes("FW-006"), out.ids);
        // The exit document the Fabric worker wrote lists it too.
        assert.equal(status.phase, "exit");
        assert.deepEqual(status.unmatched_model_hosts, [row]);
        assert.ok(status.warning_ids.includes("FW-006"), status.warning_ids);
    },
);

test("packed: a missing prebuild is a status, never a throw", packaged, () => {
    const root = join(app(), "node_modules", "@singleaxis", "fabric");
    const prebuilds = join(root, "prebuilds");
    const aside = join(root, "prebuilds-aside");
    renameSync(prebuilds, aside);
    try {
        const source = `
import { envStatus, install } from "@singleaxis/fabric/wire";
const handle = install();
console.log(JSON.stringify({ capturing: handle.capturing, reason: handle.reason,
  warnings: handle.status().warning_ids, env: envStatus().status.capture_reason }));
`;
        const { out, stderr, status } = runApp("missing.mjs", source, {
            ...PRELOAD,
            ...endpointEnv(),
        });
        assert.equal(out.capturing, false);
        assert.equal(out.reason, "native_missing");
        assert.ok(out.warnings.includes("FW-028") || out.warnings.includes("FW-027"), out.warnings);
        assert.equal(out.env, "native_missing");
        assert.equal(stderr, "");
        assert.equal(status.capture, "disabled");
        assert.equal(status.status.capture_reason, "native_missing");
    } finally {
        renameSync(aside, prebuilds);
    }
});

test(
    "packed: malformed configuration under the preload is a not_installed status, the agent runs",
    packaged,
    () => {
        const { out, stderr, status } = runApp(
            "bad.mjs",
            "console.log(JSON.stringify({ ran: true }));\n",
            { ...PRELOAD, FABRIC_WIRE_ENDPOINTS: "not json", FABRIC_WIRE_DIAGNOSTICS: "stderr" },
        );
        assert.deepEqual(out, { ran: true });
        assert.equal(status.capture, "not_installed");
        assert.equal(status.reason_id, "FW-014");
        assert.deepEqual(status.warning_ids, ["FW-025"]);
        // With FABRIC_WIRE_DIAGNOSTICS=stderr the reason and its fix are printed once.
        assert.match(stderr, /FABRIC_WIRE_ENDPOINTS is not valid JSON\. Fix: .*\[FW-014\]/);
        assert.doesNotMatch(stderr, /not json/);
    },
);

test(
    "packed: a late install() captures the calls made after it, never the ones before",
    {
        ...packaged,
        skip: packaged.skip || (!CAPTURING_NODE && "needs Node.js 24.4 or newer"),
    },
    () => {
        const source = `
import { createServer } from "node:http";
const server = createServer((req, res) => { req.resume(); req.on("end", () => res.end("{}")); });
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const url = \`http://127.0.0.1:\${server.address().port}/v1/chat/completions\`;
await (await fetch(url, { method: "POST", body: "{}" })).text();
const { install } = await import("@singleaxis/fabric/wire");
const handle = install();
await (await fetch(url, { method: "POST", body: "{}" })).text();
server.close();
console.log(JSON.stringify({ capturing: handle.capturing, matched: handle.status().status.matched }));
`;
        const { out } = runApp("late.mjs", source, endpointEnv());
        assert.deepEqual(out, { capturing: true, matched: 1 });
    },
);

test(
    "packed: with the application's own OpenTelemetry tracing, both record unchanged",
    {
        ...packaged,
        skip: packaged.skip || (!CAPTURING_NODE && "needs Node.js 24.4 or newer"),
    },
    () => {
        const dir = app();
        const env = {
            ...process.env,
            npm_config_update_notifier: "false",
            npm_config_cache: join(dir, ".npm"),
        };
        delete env.NODE_OPTIONS;
        const versions = JSON.parse(
            readFileSync(new URL("../package.json", import.meta.url), "utf8"),
        ).devDependencies;
        const added = spawnSync(
            "npm",
            [
                "install",
                "--no-save",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--package-lock=false",
                `@opentelemetry/sdk-trace-node@${versions["@opentelemetry/sdk-trace-node"]}`,
                `@opentelemetry/context-async-hooks@${versions["@opentelemetry/context-async-hooks"]}`,
                TARBALL,
            ],
            { cwd: dir, env, encoding: "utf8", timeout: 300_000 },
        );
        assert.equal(added.status, 0, added.stderr);
        activateHere(join(dir, "node_modules", "@singleaxis", "fabric"));
        const source = `
import { createServer } from "node:http";
import { trace } from "@opentelemetry/api";
import { BasicTracerProvider, InMemorySpanExporter, SimpleSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
const exporter = new InMemorySpanExporter();
const provider = new NodeTracerProvider({ spanProcessors: [new SimpleSpanProcessor(exporter)] });
provider.register();
void BasicTracerProvider;
const { install } = await import("@singleaxis/fabric/wire");
const server = createServer((req, res) => { req.resume(); req.on("end", () => res.end("{}")); });
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const url = \`http://127.0.0.1:\${server.address().port}/v1/chat/completions\`;
await trace.getTracer("app").startActiveSpan("agent.turn", async (span) => {
  await (await fetch(url, { method: "POST", body: "{}" })).text();
  span.end();
});
server.close();
await provider.forceFlush();
console.log(JSON.stringify({ spans: exporter.getFinishedSpans().map((s) => s.name),
  matched: install().status().status.matched }));
`;
        const { out, stderr } = runApp("otel.mjs", source, { ...PRELOAD, ...endpointEnv() });
        // The application's exporter sees only its own span: Fabric's records never go
        // through the host's tracer provider; the call is still captured once.
        assert.deepEqual(out, { spans: ["agent.turn"], matched: 1 });
        assert.equal(stderr, "");
    },
);
