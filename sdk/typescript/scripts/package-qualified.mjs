// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/* global process */

/**
 * Build and qualify the exact npm tarball used by every release consumer.
 *
 * This script intentionally invokes `npm pack` once. Publication and the
 * GitHub release must consume the resulting tarball as an immutable workflow
 * artifact; neither step is allowed to rebuild the package.
 */

import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(SCRIPT_DIR, "..");

export const PACKAGE_NAME = "@singleaxis/fabric";

export const EXPECTED_PACKAGE_FILES = Object.freeze([
    "LICENSE",
    "README.md",
    "dist/index.cjs",
    "dist/index.cjs.map",
    "dist/index.d.cts",
    "dist/index.d.ts",
    "dist/index.js",
    "dist/index.js.map",
    "package.json",
]);

export const FORBIDDEN_RECORDER_TOKENS = Object.freeze([
    "recordGuardrail",
    "recordBlock",
    "requestEscalation",
    "recordEval",
    "queueJudge",
    "recordPolicyEvaluation",
    "recordToolAuthorization",
    "fabric.guardrail",
    "fabric.judge",
    "fabric.eval",
    "fabric.policy",
    "fabric.tool.authorization",
    "fabric.escalation",
]);

function fail(message) {
    throw new Error(`npm artifact qualification failed: ${message}`);
}

function digest(buffer, algorithm, encoding) {
    return createHash(algorithm).update(buffer).digest(encoding);
}

function compareExactFiles(observed) {
    const expected = [...EXPECTED_PACKAGE_FILES].sort();
    const actual = [...observed].sort();
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        const missing = expected.filter((path) => !actual.includes(path));
        const unexpected = actual.filter((path) => !expected.includes(path));
        fail(
            `tarball file allowlist mismatch; missing=[${missing.join(", ")}], ` +
                `unexpected=[${unexpected.join(", ")}]`,
        );
    }
}

export function validatePackRecord(record, artifactBytes, expectedVersion) {
    if (record.name !== PACKAGE_NAME) {
        fail(`package name is ${String(record.name)}, expected ${PACKAGE_NAME}`);
    }
    if (record.version !== expectedVersion) {
        fail(`package version is ${String(record.version)}, expected ${expectedVersion}`);
    }
    if (!Array.isArray(record.files)) {
        fail("npm pack metadata has no files list");
    }

    const paths = record.files.map((entry) => entry?.path);
    if (paths.some((path) => typeof path !== "string" || path.length === 0)) {
        fail("npm pack metadata contains an invalid file path");
    }
    if (new Set(paths).size !== paths.length) {
        fail("npm pack metadata contains duplicate file paths");
    }
    compareExactFiles(paths);

    const sha1 = digest(artifactBytes, "sha1", "hex");
    const integrity = `sha512-${digest(artifactBytes, "sha512", "base64")}`;
    if (record.shasum !== sha1) {
        fail("tarball SHA-1 does not match npm pack metadata");
    }
    if (record.integrity !== integrity) {
        fail("tarball SHA-512 integrity does not match npm pack metadata");
    }
    if (!Number.isSafeInteger(record.size) || record.size !== artifactBytes.length) {
        fail("tarball byte size does not match npm pack metadata");
    }

    return {
        sha1,
        sha256: digest(artifactBytes, "sha256", "hex"),
        integrity,
        files: [...paths].sort(),
    };
}

function run(command, args, options = {}) {
    const result = spawnSync(command, args, {
        cwd: options.cwd ?? PACKAGE_ROOT,
        encoding: "utf8",
        stdio: options.capture ? "pipe" : "inherit",
        env: options.env ?? process.env,
    });
    if (result.error) {
        throw result.error;
    }
    if (result.status !== 0) {
        const detail = options.capture
            ? `\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`
            : "";
        fail(`${command} exited with status ${String(result.status)}${detail}`);
    }
    return result.stdout ?? "";
}

function verifyArchiveMembers(artifact, expectedFiles) {
    const listing = run("tar", ["-tzf", artifact], { capture: true }).split("\n").filter(Boolean);
    const expected = expectedFiles.map((path) => `package/${path}`).sort();
    const observed = listing.sort();
    if (JSON.stringify(observed) !== JSON.stringify(expected)) {
        fail("exact tar archive members differ from npm pack metadata");
    }
}

export function validateRecorderPayloads(payloads) {
    for (const [path, content] of Object.entries(payloads)) {
        for (const token of FORBIDDEN_RECORDER_TOKENS) {
            if (content.includes(token)) {
                fail(`recorder artifact ${path} contains forbidden token ${token}`);
            }
        }
    }
}

function verifyRecorderBoundary(artifact) {
    const payloads = {};
    for (const path of EXPECTED_PACKAGE_FILES.filter((name) => name.startsWith("dist/"))) {
        payloads[path] = run("tar", ["-xOzf", artifact, `package/${path}`], { capture: true });
    }
    validateRecorderPayloads(payloads);
}

function smokeInstall(artifact) {
    const fixture = mkdtempSync(join(tmpdir(), "singleaxis-fabric-npm-smoke-"));
    try {
        writeFileSync(
            join(fixture, "package.json"),
            `${JSON.stringify({ name: "fabric-artifact-smoke", private: true, type: "module" }, null, 2)}\n`,
        );
        run(
            "npm",
            [
                "install",
                "--save-exact",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--package-lock=false",
                artifact,
            ],
            {
                env: {
                    ...process.env,
                    npm_config_cache: join(fixture, ".npm-cache"),
                    npm_config_update_notifier: "false",
                },
                cwd: fixture,
            },
        );

        writeFileSync(
            join(fixture, "smoke.mjs"),
            [
                'import { Fabric, TRACER_NAME, attributes, sha256Hex } from "@singleaxis/fabric";',
                'if (TRACER_NAME !== "@singleaxis/fabric") throw new Error("bad ESM export");',
                'if (sha256Hex("fabric") !== "ad2a542c84c7060f1f2ec92f6f7d2d675cf1fc8b47e0c75071d86380efabbb53") throw new Error("bad ESM runtime");',
                'new Fabric({ tenantId: "artifact-smoke", agentId: "artifact-smoke" });',
                'if (attributes.ATTR_DECISION_ID !== "fabric.decision_id") throw new Error("missing recorder attributes");',
                'if (Object.keys(attributes).some((name) => /GUARDRAIL|JUDGE|POLICY|TOOL_AUTH|ESCALAT/.test(name) || name.startsWith("ATTR_EVAL") || name === "EVENT_NAME_EVAL")) throw new Error("legacy attributes exported");',
            ].join("\n"),
        );
        writeFileSync(
            join(fixture, "smoke.cjs"),
            [
                'const { Fabric, TRACER_NAME, attributes, sha256Hex } = require("@singleaxis/fabric");',
                'if (TRACER_NAME !== "@singleaxis/fabric") throw new Error("bad CJS export");',
                'if (sha256Hex("fabric") !== "ad2a542c84c7060f1f2ec92f6f7d2d675cf1fc8b47e0c75071d86380efabbb53") throw new Error("bad CJS runtime");',
                'new Fabric({ tenantId: "artifact-smoke", agentId: "artifact-smoke" });',
                'if (attributes.ATTR_DECISION_ID !== "fabric.decision_id") throw new Error("missing recorder attributes");',
                'if (Object.keys(attributes).some((name) => /GUARDRAIL|JUDGE|POLICY|TOOL_AUTH|ESCALAT/.test(name) || name.startsWith("ATTR_EVAL") || name === "EVENT_NAME_EVAL")) throw new Error("legacy attributes exported");',
            ].join("\n"),
        );
        writeFileSync(
            join(fixture, "smoke.ts"),
            [
                'import { Fabric, type FabricConfig, type DecisionIds } from "@singleaxis/fabric";',
                'const config: FabricConfig = { tenantId: "artifact-smoke", agentId: "artifact-smoke" };',
                'const ids: DecisionIds = { sessionId: "session", requestId: "request" };',
                "const client: Fabric = new Fabric(config);",
                "client.decision(ids, (decision) => void decision);",
            ].join("\n"),
        );
        writeFileSync(
            join(fixture, "tsconfig.json"),
            `${JSON.stringify(
                {
                    compilerOptions: {
                        module: "NodeNext",
                        moduleResolution: "NodeNext",
                        target: "ES2022",
                        strict: true,
                        noEmit: true,
                        skipLibCheck: false,
                    },
                    files: ["smoke.ts"],
                },
                null,
                2,
            )}\n`,
        );

        run(process.execPath, [join(fixture, "smoke.mjs")]);
        run(process.execPath, [join(fixture, "smoke.cjs")]);
        run(join(PACKAGE_ROOT, "node_modules", ".bin", "tsc"), [
            "--project",
            join(fixture, "tsconfig.json"),
        ]);
    } finally {
        rmSync(fixture, { recursive: true, force: true });
    }
}

function parseArgs(argv) {
    const options = { destination: undefined, expectedVersion: undefined, smoke: false };
    for (let index = 0; index < argv.length; index += 1) {
        const arg = argv[index];
        if (arg === "--destination") options.destination = argv[++index];
        else if (arg === "--expected-version") options.expectedVersion = argv[++index];
        else if (arg === "--smoke") options.smoke = true;
        else fail(`unknown argument: ${String(arg)}`);
    }
    const packageJson = JSON.parse(readFileSync(join(PACKAGE_ROOT, "package.json"), "utf8"));
    options.expectedVersion ??= packageJson.version;
    options.destination ??= "dist-package";
    if (typeof options.expectedVersion !== "string" || options.expectedVersion.length === 0) {
        fail("--expected-version must be non-empty");
    }
    return options;
}

export function main(argv = process.argv.slice(2)) {
    const options = parseArgs(argv);
    const destination = resolve(PACKAGE_ROOT, options.destination);
    mkdirSync(destination, { recursive: true });
    const npmCache = mkdtempSync(join(tmpdir(), "singleaxis-fabric-npm-pack-"));
    let rawMetadata;
    try {
        rawMetadata = run(
            "npm",
            ["pack", "--ignore-scripts", "--json", "--pack-destination", destination],
            {
                capture: true,
                env: {
                    ...process.env,
                    npm_config_cache: npmCache,
                    npm_config_update_notifier: "false",
                },
            },
        );
    } finally {
        rmSync(npmCache, { recursive: true, force: true });
    }
    let records;
    try {
        records = JSON.parse(rawMetadata);
    } catch (error) {
        fail(`npm pack did not emit valid JSON: ${error.message}`);
    }
    if (!Array.isArray(records) || records.length !== 1) {
        fail("npm pack must emit exactly one artifact record");
    }
    const record = records[0];
    const artifact = resolve(destination, record.filename);
    const artifactBytes = readFileSync(artifact);
    const verified = validatePackRecord(record, artifactBytes, options.expectedVersion);
    verifyArchiveMembers(artifact, verified.files);
    verifyRecorderBoundary(artifact);
    if (options.smoke) smokeInstall(artifact);

    const qualification = {
        schema_version: "fabric.npm-package-qualification/v1",
        name: PACKAGE_NAME,
        version: options.expectedVersion,
        release_channel: "beta",
        filename: record.filename,
        sha256: verified.sha256,
        integrity: verified.integrity,
        package_size: record.size,
        unpacked_size: record.unpackedSize,
        files: verified.files,
        smoke: options.smoke ? ["esm", "cjs", "types"] : [],
    };
    writeFileSync(
        join(destination, "typescript-package.json"),
        `${JSON.stringify(qualification, null, 2)}\n`,
    );
    writeFileSync(
        join(destination, "SHA256SUMS.typescript"),
        `${verified.sha256}  ${record.filename}\n`,
    );
    writeFileSync(join(destination, "npm-pack-metadata.json"), `${rawMetadata.trim()}\n`);
    process.stdout.write(`${JSON.stringify(qualification, null, 2)}\n`);
    return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        process.exitCode = main();
    } catch (error) {
        process.stderr.write(`${error.stack ?? error}\n`);
        process.exitCode = 1;
    }
}
