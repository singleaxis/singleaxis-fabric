// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/* global Buffer, clearTimeout, console, process, setTimeout */

/**
 * Fresh-install test: run the README's own commands, in a clean directory,
 * against the package built from this tree.
 *
 * For every `<!-- fresh-install: install <set> -->` block in README.md:
 *   1. a new empty project directory outside the repository;
 *   2. the README's `npm install` line exactly, except that
 *      `@singleaxis/fabric` resolves to the tarball `npm pack` makes from
 *      this tree (the registry copy is the previous release);
 *   3. `npm ls --all`, which fails on a missing or invalid peer;
 *   4. the README's example, saved under the name the README gives it, run
 *      with `node` against a loopback OTLP receiver: it must exit 0 and its
 *      decision, model-call and tool-call spans must arrive;
 *   5. the README's status command, for a loopback and a plaintext
 *      non-loopback endpoint;
 *   6. the example again with plain HTTP to a non-loopback address of this
 *      machine that reaches the same receiver: it must exit 0 and deliver
 *      nothing (the span delivery rule).
 *
 * Needs `npm run build` first and registry access. Usage:
 *   node scripts/fresh-install.mjs [--set current|otel-2]
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { networkInterfaces, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SDK = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGE = "@singleaxis/fabric";
// The decision span, the model-call span (GenAI `{operation} {model}`) and the
// tool-call span (`execute_tool`: without an id key the tool name is omitted)
// the README example records.
const SPAN_NAMES = ["fabric.decision", "chat model-example", "execute_tool"];

/** `{ label: body }` for every fenced block preceded by a fresh-install marker. */
export function readmeBlocks(text) {
    const blocks = {};
    const pattern = /<!-- fresh-install: ([^>]+?) -->\n+```[a-z]*\n([\s\S]*?)\n```/g;
    for (const match of text.matchAll(pattern)) {
        assert.equal(blocks[match[1]], undefined, `duplicate README block ${match[1]}`);
        blocks[match[1]] = match[2];
    }
    return blocks;
}

/** The README install line with the SDK resolved to `tarball`. */
export function localInstallCommand(command, tarball) {
    const lines = command.split("\n").filter((line) => line.trim() !== "");
    assert.equal(lines.length, 1, "an install block is one command");
    const words = lines[0].trim().split(/\s+/);
    assert.deepEqual(words.slice(0, 2), ["npm", "install"], "an install block runs npm install");
    assert.equal(
        words.filter((word) => word === PACKAGE).length,
        1,
        `the install line names ${PACKAGE} once, unpinned`,
    );
    for (const word of words.slice(2)) {
        if (word === PACKAGE) continue;
        assert.match(word, /^@opentelemetry\/[a-z-]+@\d+\.\d+\.\d+$/, `exact pin: ${word}`);
    }
    return words.map((word) => (word === PACKAGE ? tarball : word));
}

/** Run a child without blocking this process (the OTLP receiver lives here). */
function run(command, args, options = {}) {
    return new Promise((done) => {
        const child = spawn(command, args, { ...options, stdio: ["ignore", "pipe", "pipe"] });
        let stdout = "";
        let stderr = "";
        child.stdout.setEncoding("utf8").on("data", (chunk) => (stdout += chunk));
        child.stderr.setEncoding("utf8").on("data", (chunk) => (stderr += chunk));
        const timer = setTimeout(() => child.kill("SIGKILL"), 300_000);
        child.on("error", (error) => {
            clearTimeout(timer);
            done({ status: null, stdout, stderr, error });
        });
        child.on("close", (status) => {
            clearTimeout(timer);
            done({ status, stdout, stderr, error: undefined });
        });
    });
}

function must(result, what) {
    if (result.status !== 0) {
        throw new Error(
            `${what} failed (exit ${result.status}${result.error ? `, ${result.error.message}` : ""})\n` +
                `--- stdout\n${result.stdout}\n--- stderr\n${result.stderr}`,
        );
    }
    return result;
}

/** The environment a fresh shell would give the agent: no inherited OTel/Fabric settings. */
function cleanEnv(extra) {
    const env = {};
    for (const [name, value] of Object.entries(process.env)) {
        if (name.startsWith("OTEL_") || name.startsWith("FABRIC_")) continue;
        if (name.startsWith("npm_")) continue;
        env[name] = value;
    }
    return {
        ...env,
        npm_config_audit: "false",
        npm_config_fund: "false",
        npm_config_update_notifier: "false",
        ...extra,
    };
}

/** An OTLP/HTTP receiver that records every request body it accepts. */
async function receiver(hosts) {
    const bodies = [];
    const servers = [];
    let port = 0;
    for (const host of hosts) {
        const server = createServer((request, response) => {
            const chunks = [];
            request.on("data", (chunk) => chunks.push(chunk));
            request.on("end", () => {
                bodies.push({ path: request.url, body: Buffer.concat(chunks).toString("latin1") });
                response.writeHead(200, { "content-type": "application/json" });
                response.end("{}");
            });
        });
        await new Promise((ok, fail) => {
            server.once("error", fail);
            server.listen(port, host, () => ok());
        });
        port = server.address().port;
        servers.push(server);
    }
    return {
        port,
        bodies,
        close: () => Promise.all(servers.map((s) => new Promise((ok) => s.close(() => ok())))),
    };
}

function nonLoopbackAddress() {
    for (const addresses of Object.values(networkInterfaces())) {
        for (const address of addresses ?? []) {
            if (address.family === "IPv4" && !address.internal) return address.address;
        }
    }
    return undefined;
}

async function pack(destination) {
    if (!existsSync(join(SDK, "dist/index.js"))) {
        throw new Error("dist/ is missing: run `npm run build` first");
    }
    const result = must(
        await run("npm", ["pack", "--json", "--pack-destination", destination], {
            cwd: SDK,
            env: cleanEnv({}),
        }),
        "npm pack",
    );
    const [record] = JSON.parse(result.stdout);
    return join(destination, record.filename);
}

async function checkSet(set, blocks, tarball) {
    const install = blocks[`install ${set}`];
    assert.ok(install, `README has no "fresh-install: install ${set}" block`);
    const exampleLabel = Object.keys(blocks).find((label) => label.startsWith("example "));
    assert.ok(exampleLabel, 'README has no "fresh-install: example <file>" block');
    const exampleFile = exampleLabel.slice("example ".length).trim();
    const status = blocks.status;
    assert.ok(status, 'README has no "fresh-install: status" block');

    const project = mkdtempSync(join(tmpdir(), `fabric-fresh-install-${set}-`));
    try {
        // A new, empty project: what `npm init -y` leaves behind.
        writeFileSync(
            join(project, "package.json"),
            `${JSON.stringify({ name: "fresh-install", version: "1.0.0", private: true }, null, 2)}\n`,
        );
        const [npm, ...args] = localInstallCommand(install, tarball);
        must(await run(npm, args, { cwd: project, env: cleanEnv({}) }), `[${set}] README install`);
        must(
            await run("npm", ["ls", "--all"], { cwd: project, env: cleanEnv({}) }),
            `[${set}] npm ls`,
        );

        writeFileSync(join(project, exampleFile), `${blocks[exampleLabel]}\n`);
        const lan = nonLoopbackAddress();
        const sink = await receiver(lan ? ["127.0.0.1", lan] : ["127.0.0.1"]);
        try {
            const agentEnv = { FABRIC_TENANT_ID: "acme", FABRIC_AGENT_ID: "support-agent" };
            const loopback = `http://127.0.0.1:${sink.port}`;
            must(
                await run("node", [exampleFile], {
                    cwd: project,
                    env: cleanEnv({ ...agentEnv, OTEL_EXPORTER_OTLP_ENDPOINT: loopback }),
                }),
                `[${set}] README example`,
            );
            const delivered = sink.bodies.map((entry) => entry.body).join("\n");
            assert.ok(
                sink.bodies.some((entry) => entry.path === "/v1/traces"),
                `[${set}] no OTLP traces request`,
            );
            for (const name of SPAN_NAMES) {
                assert.ok(delivered.includes(name), `[${set}] span ${name} not delivered`);
            }

            if (lan === undefined) {
                console.log(
                    `[${set}] no non-loopback IPv4 address: plaintext delivery check skipped`,
                );
            } else {
                const before = sink.bodies.length;
                const plaintext = must(
                    await run("node", [exampleFile], {
                        cwd: project,
                        env: cleanEnv({
                            ...agentEnv,
                            OTEL_EXPORTER_OTLP_ENDPOINT: `http://${lan}:${sink.port}`,
                            FABRIC_WIRE_DIAGNOSTICS: "stderr",
                        }),
                    }),
                    `[${set}] README example, plaintext non-loopback endpoint`,
                );
                assert.equal(
                    sink.bodies.length,
                    before,
                    `[${set}] spans were sent in plaintext to a non-loopback address`,
                );
                assert.match(plaintext.stderr, /capture off: OTEL_EXPORTER_OTLP_ENDPOINT requires/);
                assert.ok(!plaintext.stderr.includes(lan), "diagnostic echoed the endpoint");
            }

            const enabled = must(
                await run("sh", ["-c", status], {
                    cwd: project,
                    env: cleanEnv({ OTEL_EXPORTER_OTLP_ENDPOINT: loopback }),
                }),
                `[${set}] README status (loopback)`,
            );
            assert.deepEqual(JSON.parse(enabled.stdout), { capture: "enabled" });
            const disabled = must(
                await run("sh", ["-c", status], {
                    cwd: project,
                    env: cleanEnv({ OTEL_EXPORTER_OTLP_ENDPOINT: "http://fabric-node:4318" }),
                }),
                `[${set}] README status (plaintext)`,
            );
            const verdict = JSON.parse(disabled.stdout);
            assert.equal(verdict.capture, "disabled");
            assert.match(verdict.reason, /OTEL_EXPORTER_OTLP_ENDPOINT/);
            assert.ok(!disabled.stdout.includes("fabric-node"), "status echoed the endpoint");
        } finally {
            await sink.close();
        }
        console.log(`[${set}] fresh install, example and status: ok`);
    } finally {
        rmSync(project, { recursive: true, force: true });
    }
}

async function main(argv) {
    const only = argv[0] === "--set" ? argv[1] : undefined;
    const blocks = readmeBlocks(readFileSync(join(SDK, "README.md"), "utf8"));
    const sets = Object.keys(blocks)
        .filter((label) => label.startsWith("install "))
        .map((label) => label.slice("install ".length));
    assert.ok(sets.includes("current"), 'README has no "fresh-install: install current" block');
    const selected = only === undefined ? sets : sets.filter((set) => set === only);
    assert.ok(selected.length > 0, `no README install set ${only}`);
    const scratch = mkdtempSync(join(tmpdir(), "fabric-fresh-install-pack-"));
    try {
        const tarball = await pack(scratch);
        for (const set of selected) await checkSet(set, blocks, tarball);
    } finally {
        rmSync(scratch, { recursive: true, force: true });
    }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    await main(process.argv.slice(2));
}
