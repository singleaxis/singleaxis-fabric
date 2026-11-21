// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// The `ts-wire-privacy` artifact step of spec 055 §9.2 (unit 055-t14), over the packed
// npm tarball a customer installs:
//
// - file list: exactly the qualified allowlist (sdk/typescript/scripts/package-qualified.mjs);
// - package.json: no install-time script (npm runs preinstall/install/postinstall and the
//   prepare family on install), no gypfile, no root binding.gyp, no dependency, and only
//   the declared optional peers;
// - dist/: no source map embeds source, every module it loads is a Node builtin, a file
//   of the package or a declared peer (so no framework or other package is pulled in),
//   and no forbidden OSS-boundary term of scripts/tests/test_recorder_release_boundary.py
//   (its component list, and the recorder's forbidden API tokens) appears;
// - prebuilds/: each file has the SHA-256 the loader embeds (the typescript-native job
//   checked those exact bytes export nothing beyond spec 055 §4.4) and, where `nm` reads
//   its format, exports exactly the two Node-API entry points; no forbidden term in its
//   strings;
// - the status file and the spool's exit note an installed, preloaded agent leaves behind
//   (canaries planted in the request body, headers, URL path and query and the
//   environment): no canary in either, nor on the agent's own output.
//
// `selfTest` plants one of each violation in a copy of the tarball and requires the step
// to report every one.

import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import {
    cpSync,
    existsSync,
    mkdtempSync,
    readFileSync,
    readdirSync,
    rmSync,
    statSync,
    writeFileSync,
} from "node:fs";
import http from "node:http";
import { builtinModules } from "node:module";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";

import { REPO } from "./build.mjs";

const SDK = join(REPO, "sdk", "typescript");
const packaging = await import(join(SDK, "scripts", "package-qualified.mjs"));
const boundary = JSON.parse(
    readFileSync(
        join(REPO, "scripts", "tests", "fixtures", "forbidden_components.json"),
        "utf8",
    ),
);
const POLICY_TERMS = JSON.parse(
    readFileSync(
        join(REPO, "scripts", "release", "release-policy.json"),
        "utf8",
    ),
).forbidden_capability_terms.patterns;

/** Scripts npm runs when a package is installed. */
const INSTALL_SCRIPTS = [
    "preinstall",
    "install",
    "postinstall",
    "preprepare",
    "prepare",
    "postprepare",
];
/** The optional peers the package declares; nothing else may be loaded from node_modules. */
const PEERS = new Set(["@opentelemetry/api", "@aws-sdk/client-s3"]);
const EXPORTED = [
    "napi_register_module_v1",
    "node_api_module_get_api_version_v1",
];

const FORBIDDEN_TERMS = [
    ...boundary.forbidden_components,
    ...boundary.forbidden_chart_names,
    ...packaging.FORBIDDEN_RECORDER_TOKENS,
];

function run(command, args, options = {}) {
    return spawnSync(command, args, {
        encoding: "utf8",
        maxBuffer: 1 << 28,
        ...options,
    });
}

function extract(tarball) {
    const dir = mkdtempSync(join(tmpdir(), "f055-t14-artifact-"));
    const done = run("tar", ["-xzf", tarball, "-C", dir]);
    if (done.status !== 0)
        throw new Error(`tar could not read ${tarball}: ${done.stderr}`);
    return { dir, root: join(dir, "package") };
}

function walk(root, dir = root) {
    const out = [];
    for (const name of readdirSync(dir)) {
        const path = join(dir, name);
        if (statSync(path).isDirectory()) out.push(...walk(root, path));
        else out.push(relative(root, path));
    }
    return out.sort();
}

/** Printable ASCII runs of at least 4 bytes (the `strings` of a binary). */
function strings(bytes) {
    return (
        bytes
            .toString("latin1")
            .match(/[\x20-\x7e]{4,}/g)
            ?.join("\n") ?? ""
    );
}

/** The modules a bundled file loads: `require("x")`, `import("x")`, `from "x"`. */
function loadedModules(text) {
    const found = new Set();
    for (const m of text.matchAll(/\brequire\(\s*["']([^"']+)["']\s*\)/g))
        found.add(m[1]);
    for (const m of text.matchAll(/\bimport\(\s*["']([^"']+)["']\s*\)/g))
        found.add(m[1]);
    for (const m of text.matchAll(
        /^\s*(?:import|export)\s[^;]*?\sfrom\s+["']([^"']+)["']/gm,
    ))
        found.add(m[1]);
    for (const m of text.matchAll(/^\s*import\s+["']([^"']+)["']/gm))
        found.add(m[1]);
    return [...found];
}

function allowedModule(name) {
    if (name.startsWith("./") || name.startsWith("../")) return true;
    // The package itself (its catalogue's fix text names `require('@singleaxis/fabric/wire')`).
    if (
        name === packaging.PACKAGE_NAME ||
        name.startsWith(`${packaging.PACKAGE_NAME}/`)
    )
        return true;
    const bare = name.startsWith("node:") ? name.slice(5) : name;
    if (
        builtinModules.includes(bare) ||
        builtinModules.includes(bare.split("/")[0])
    )
        return true;
    return (
        PEERS.has(name) ||
        [...PEERS].some((peer) => name.startsWith(`${peer}/`))
    );
}

function exportedSymbols(file) {
    const args =
        statSync(file) && process.platform === "darwin"
            ? ["-gU"]
            : ["-D", "--defined-only"];
    const done = run("nm", [...args, file]);
    if (done.error !== undefined || done.status !== 0) return undefined; // a format this nm cannot read
    return done.stdout
        .split("\n")
        .filter((line) => line.trim() !== "")
        .map((line) => line.trim().split(/\s+/).pop().replace(/^_/, ""))
        .sort();
}

/** Every violation of the static checks in an extracted package root. */
export function checkPackage(root) {
    const violations = [];
    const add = (kind, where, detail) =>
        violations.push({ kind, where, detail });
    const files = walk(root);
    const targets = files
        .filter((f) => f.startsWith("prebuilds/"))
        .map((f) => f.split("/")[1]);
    const expected = [...packaging.expectedPackageFiles(targets)].sort();
    for (const f of files)
        if (!expected.includes(f))
            add("unexpected_file", f, "not in the qualified allowlist");
    for (const f of expected)
        if (!files.includes(f))
            add("missing_file", f, "in the allowlist, not in the tarball");

    const manifest = JSON.parse(
        readFileSync(join(root, "package.json"), "utf8"),
    );
    for (const script of INSTALL_SCRIPTS) {
        if (manifest.scripts?.[script] !== undefined)
            add("install_script", "package.json", script);
    }
    if (manifest.gypfile !== undefined)
        add("install_script", "package.json", "gypfile");
    if (existsSync(join(root, "binding.gyp")))
        add("install_script", "binding.gyp", "npm runs node-gyp for it");
    for (const field of [
        "dependencies",
        "optionalDependencies",
        "bundleDependencies",
        "bundledDependencies",
    ]) {
        for (const name of Object.keys(manifest[field] ?? {}))
            add("dependency", `package.json ${field}`, name);
    }
    for (const name of Object.keys(manifest.peerDependencies ?? {})) {
        if (!PEERS.has(name))
            add("dependency", "package.json peerDependencies", name);
    }
    const metadata = [
        manifest.description ?? "",
        ...(manifest.keywords ?? []),
    ].join("\n");
    for (const pattern of POLICY_TERMS) {
        if (new RegExp(pattern, "i").test(metadata))
            add("boundary_term", "package.json metadata", pattern);
    }

    for (const f of files.filter((name) => name.startsWith("dist/"))) {
        const text = readFileSync(join(root, f), "utf8");
        if (f.endsWith(".map")) {
            const map = JSON.parse(text);
            if (
                (map.sourcesContent ?? []).some(
                    (s) => s !== null && s !== undefined,
                )
            ) {
                add("source_map_content", f, "embeds source");
            }
            continue;
        }
        for (const term of FORBIDDEN_TERMS)
            if (text.includes(term)) add("boundary_term", f, term);
        if (/\.(c?js)$/.test(f)) {
            for (const name of loadedModules(text)) {
                if (!allowedModule(name)) add("module", f, name);
            }
        }
    }

    const digests = packaging.nativeDigests();
    for (const f of files.filter((name) => name.startsWith("prebuilds/"))) {
        const bytes = readFileSync(join(root, f));
        const target = f.split("/")[1];
        const sha = createHash("sha256").update(bytes).digest("hex");
        if (sha !== digests[target])
            add(
                "prebuild_digest",
                f,
                `${sha} is not the loader's ${digests[target]}`,
            );
        const text = strings(bytes);
        for (const term of FORBIDDEN_TERMS)
            if (text.includes(term)) add("boundary_term", f, term);
        const symbols = exportedSymbols(join(root, f));
        if (
            symbols !== undefined &&
            JSON.stringify(symbols) !== JSON.stringify(EXPORTED)
        ) {
            add("prebuild_symbols", f, symbols.join(","));
        }
    }
    return { files: files.length, prebuilds: targets, violations };
}

// ------------------------------------------------------------------ canary scan

const CANARIES = {
    body: "cnry-artifact-body-7f3a",
    header: "cnry-artifact-header-91be",
    path: "cnry-artifact-path-c04d",
    query: "cnry-artifact-query-55e1",
    env: "cnry-artifact-env-2b96",
};

function install(tarball) {
    const dir = mkdtempSync(join(tmpdir(), "f055-t14-artifact-app-"));
    writeFileSync(
        join(dir, "package.json"),
        '{"name":"artifact-canary","private":true}\n',
    );
    const env = {
        ...process.env,
        npm_config_cache: join(dir, ".npm"),
        npm_config_update_notifier: "false",
    };
    delete env.NODE_OPTIONS;
    const done = run(
        "npm",
        [
            "install",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--package-lock=false",
            tarball,
        ],
        {
            cwd: dir,
            env,
        },
    );
    if (done.status !== 0)
        throw new Error(`npm install of the tarball failed: ${done.stderr}`);
    activateHere(join(dir, "node_modules", "@singleaxis", "fabric"));
    return dir;
}

/** Tests activate capture through the table (spec 055 §9.5); the code is unchanged. */
function activateHere(root) {
    const glibc =
        process.report?.getReport()?.header?.glibcVersionRuntime !== undefined;
    const platform =
        process.platform === "darwin"
            ? `darwin-${process.arch}`
            : `linux-${process.arch}-${glibc ? "glibc" : "musl"}`;
    const path = join(root, "dist", "wire-qualification.json");
    const table = JSON.parse(readFileSync(path, "utf8"));
    const build = {
        node: process.versions.node,
        undici: process.versions.undici,
        platform,
    };
    if (
        table.tuples.some(
            (t) =>
                t.claim === "active" &&
                t.node === build.node &&
                t.platform === platform &&
                t.undici === build.undici,
        )
    )
        return;
    table.tuples.push({
        point: "wire.ts.undici",
        ...build,
        undici_origin: "bundled",
        claim: "active",
        report_sha256: `sha256:${"0".repeat(64)}`,
    });
    writeFileSync(path, JSON.stringify(table));
}

const AGENT = `
const body = JSON.stringify({ model: "m", messages: [{ role: "user", content: process.env.CANARY_BODY }] });
const url = \`\${process.env.BASE}/\${process.env.CANARY_PATH}/v1/chat/completions?k=\${process.env.CANARY_QUERY}\`;
const r = await fetch(url, { method: "POST", body, headers: { "x-api-key": process.env.CANARY_HEADER } });
await r.text();
console.log(JSON.stringify({ status: r.status }));
`;

/** The status file and exit note a preloaded agent leaves: no canary may appear in them. */
export async function canaryScan(tarball, { leak = false } = {}) {
    const app = install(tarball);
    const spool = mkdtempSync(join(tmpdir(), "f055-t14-artifact-spool-"));
    const statusFile = join(app, "status.json");
    const server = http.createServer((req, res) => {
        req.resume();
        req.on("end", () => res.end(`{"echo":"${CANARIES.body}"}`));
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
        writeFileSync(join(app, "agent.mjs"), AGENT);
        const port = server.address().port;
        const base = Object.fromEntries(
            Object.entries(process.env).filter(
                ([k]) => !/^(FABRIC_|OTEL_|NODE_OPTIONS$)/.test(k),
            ),
        );
        // Asynchronous: the provider answers from this process.
        const done = await new Promise((resolve) => {
            const child = spawn(process.execPath, ["agent.mjs"], {
                cwd: app,
                timeout: 60_000,
                env: {
                    ...base,
                    NODE_OPTIONS: "--import=@singleaxis/fabric/register",
                    FABRIC_WIRE_AUTOLOAD: "1",
                    FABRIC_WIRE_DIAGNOSTICS: "stderr",
                    FABRIC_WIRE_SPOOL_DIR: spool,
                    // Nothing listens there: the records stay, so the exit note is written.
                    FABRIC_OTLP_ENDPOINT: "http://127.0.0.1:9",
                    FABRIC_WIRE_STATUS_FILE: statusFile,
                    FABRIC_WIRE_ENDPOINTS: JSON.stringify([
                        {
                            endpoint_id: "artifact-model",
                            dialect: "openai",
                            hosts: ["127.0.0.1"],
                            ports: [port],
                            schemes: ["http"],
                        },
                    ]),
                    BASE: `http://127.0.0.1:${port}`,
                    CANARY_BODY: CANARIES.body,
                    CANARY_HEADER: CANARIES.header,
                    CANARY_PATH: CANARIES.path,
                    CANARY_QUERY: CANARIES.query,
                    CANARY_ENV_ONLY: CANARIES.env,
                },
            });
            let stdout = "";
            let stderr = "";
            child.stdout.on("data", (d) => (stdout += d));
            child.stderr.on("data", (d) => (stderr += d));
            child.on("close", (status) => resolve({ status, stdout, stderr }));
        });
        if (leak) {
            // Self-test: a leak the scan must report.
            const doc = JSON.parse(readFileSync(statusFile, "utf8"));
            doc.status = { leaked: CANARIES.query };
            writeFileSync(statusFile, JSON.stringify(doc));
        }
        const scanned = {
            "status file": existsSync(statusFile)
                ? readFileSync(statusFile, "utf8")
                : undefined,
            "exit note": existsSync(join(spool, ".exit-backlog"))
                ? readFileSync(join(spool, ".exit-backlog"), "utf8")
                : undefined,
            "agent stdout": done.stdout,
            "agent stderr (FABRIC_WIRE_DIAGNOSTICS=stderr)": done.stderr,
        };
        const violations = [];
        for (const [where, text] of Object.entries(scanned)) {
            for (const [canary, value] of Object.entries(CANARIES)) {
                if (text?.includes(value)) violations.push({ canary, where });
            }
        }
        const status =
            scanned["status file"] === undefined
                ? undefined
                : JSON.parse(scanned["status file"]);
        return {
            exit_code: done.status,
            status_file:
                status === undefined
                    ? null
                    : { phase: status.phase, capture: status.capture },
            exit_note_written: scanned["exit note"] !== undefined,
            matched: status?.stats?.matched ?? 0,
            violations,
            // Vacuous unless the agent ran, capture matched its call and both files exist.
            passed:
                done.status === 0 &&
                violations.length === 0 &&
                status?.capture === "closed" &&
                (status?.stats?.matched ?? 0) === 1 &&
                scanned["exit note"] !== undefined,
        };
    } finally {
        server.close();
        rmSync(app, { recursive: true, force: true });
        rmSync(spool, { recursive: true, force: true });
    }
}

/** The static checks over a tarball. */
export function checkTarball(tarball) {
    const { dir, root } = extract(tarball);
    try {
        return checkPackage(root);
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
}

/**
 * Plants one violation of each static kind in a copy of the extracted tarball; the step
 * must report every kind, and the canary scan must report a planted leak.
 */
export async function selfTest(tarball) {
    const { dir, root } = extract(tarball);
    try {
        const manifest = JSON.parse(
            readFileSync(join(root, "package.json"), "utf8"),
        );
        manifest.scripts = { ...manifest.scripts, postinstall: "node x.js" };
        manifest.dependencies = { "left-pad": "1.3.0" };
        writeFileSync(join(root, "package.json"), JSON.stringify(manifest));
        const mapPath = join(root, "dist", "wire.js.map");
        const map = JSON.parse(readFileSync(mapPath, "utf8"));
        map.sourcesContent = ["export const secret = 1;"];
        writeFileSync(mapPath, JSON.stringify(map));
        const core = join(root, "dist", "wire", "core.cjs");
        writeFileSync(
            core,
            `${readFileSync(core, "utf8")}\nrequire("left-pad");\n// ${FORBIDDEN_TERMS[0]}\n`,
        );
        cpSync(core, join(root, "dist", "extra.cjs"));
        const prebuilds = join(root, "prebuilds");
        const target = existsSync(prebuilds)
            ? readdirSync(prebuilds)[0]
            : undefined;
        if (target !== undefined) {
            const file = join(prebuilds, target, "fabric_wire.node");
            writeFileSync(
                file,
                Buffer.concat([readFileSync(file), Buffer.from("x")]),
            );
        }
        const kinds = new Set(checkPackage(root).violations.map((v) => v.kind));
        const wanted = [
            "install_script",
            "dependency",
            "source_map_content",
            "module",
            "boundary_term",
            "unexpected_file",
            ...(target === undefined ? [] : ["prebuild_digest"]),
        ];
        const leak = await canaryScan(tarball, { leak: true });
        const missed = wanted.filter((kind) => !kinds.has(kind));
        return {
            planted: wanted,
            missed,
            canary_leak_reported: leak.violations.some(
                (v) => v.where === "status file",
            ),
            passed:
                missed.length === 0 &&
                leak.violations.some((v) => v.where === "status file"),
        };
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
}
