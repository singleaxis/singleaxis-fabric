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
import {
    copyFileSync,
    existsSync,
    mkdtempSync,
    mkdirSync,
    readFileSync,
    rmSync,
    writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(SCRIPT_DIR, "..");

export const PACKAGE_NAME = "@singleaxis/fabric";

/** The six native prebuild targets of spec 055 §4.4, shipped as prebuilds/<target>/. */
export const NATIVE_TARGETS = Object.freeze([
    "darwin-arm64",
    "darwin-x64",
    "linux-arm64-glibc",
    "linux-arm64-musl",
    "linux-x64-glibc",
    "linux-x64-musl",
]);

export const NATIVE_FILE = "fabric_wire.node";

/** The tarball's files besides the prebuilds (spec 055 §9.4: the wire entry points). */
export const BASE_PACKAGE_FILES = Object.freeze([
    "LICENSE",
    "README.md",
    "dist/index.cjs",
    "dist/index.cjs.map",
    "dist/index.d.cts",
    "dist/index.d.ts",
    "dist/index.js",
    "dist/index.js.map",
    "dist/register.cjs",
    "dist/register.cjs.map",
    "dist/register.js",
    "dist/register.js.map",
    "dist/wire-qualification.json",
    "dist/wire.cjs",
    "dist/wire.cjs.map",
    "dist/wire.d.cts",
    "dist/wire.d.ts",
    "dist/wire.js",
    "dist/wire.js.map",
    "dist/wire/core.cjs",
    "dist/wire/core.cjs.map",
    "package.json",
]);

/** The exact file list of a tarball carrying the prebuilds of `targets`. */
export function expectedPackageFiles(targets = NATIVE_TARGETS) {
    return Object.freeze([
        ...BASE_PACKAGE_FILES,
        ...targets.map((target) => `prebuilds/${target}/${NATIVE_FILE}`),
    ]);
}

/** A release tarball: every prebuild. */
export const EXPECTED_PACKAGE_FILES = expectedPackageFiles();

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

function compareExactFiles(observed, expectedFiles = EXPECTED_PACKAGE_FILES) {
    const expected = [...expectedFiles].sort();
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

export function validatePackRecord(
    record,
    artifactBytes,
    expectedVersion,
    expectedFiles = EXPECTED_PACKAGE_FILES,
) {
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
    compareExactFiles(paths, expectedFiles);

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

/** The loader's embedded SHA-256 table (`src/wire/native-digests.generated.ts`). */
export function nativeDigests(
    source = readFileSync(join(PACKAGE_ROOT, "src", "wire", "native-digests.generated.ts"), "utf8"),
) {
    const table = {};
    for (const match of source.matchAll(/"([a-z0-9-]+)":\s*"([0-9a-f]{64})"/g))
        table[match[1]] = match[2];
    return table;
}

/**
 * Copies the prebuilds from `source` (laid out as <target>/fabric_wire.node, as the
 * `fabric-wire-prebuilds` artifact of typescript-native-prebuilds.yml is) into the
 * package's prebuilds/ directory. Each file must have the digest the loader embeds: a
 * prebuild the loader would refuse is never shipped. Returns the staged targets. With
 * `requireAll`, every one of the six targets must be present (a release tarball).
 */
export function stagePrebuilds(source, { requireAll = true, root = PACKAGE_ROOT } = {}) {
    const digests = nativeDigests();
    const destination = join(root, "prebuilds");
    rmSync(destination, { recursive: true, force: true });
    const staged = [];
    for (const target of NATIVE_TARGETS) {
        const file = join(source, target, NATIVE_FILE);
        if (!existsSync(file)) {
            if (requireAll) {
                fail(
                    `prebuild ${target}/${NATIVE_FILE} is missing from ${source}: download the ` +
                        "fabric-wire-prebuilds artifact of typescript-native-prebuilds.yml into it",
                );
            }
            continue;
        }
        const actual = digest(readFileSync(file), "sha256", "hex");
        if (actual !== digests[target]) {
            fail(
                `prebuild ${target}/${NATIVE_FILE} has SHA-256 ${actual}, not the loader's ` +
                    `${String(digests[target])}: build it with scripts/typescript/prebuild/prebuild.mjs ` +
                    "or use the fabric-wire-prebuilds artifact of the same commit",
            );
        }
        mkdirSync(join(destination, target), { recursive: true });
        copyFileSync(file, join(destination, target, NATIVE_FILE));
        staged.push(target);
    }
    return staged;
}

function verifyRecorderBoundary(artifact, files) {
    const payloads = {};
    for (const path of files.filter((name) => name.startsWith("dist/"))) {
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
                'import { mkdtempSync } from "node:fs";',
                'import { tmpdir } from "node:os";',
                'import { join } from "node:path";',
                "import {",
                "  CONTENT_ROLES,",
                "  ContentResolver,",
                "  Fabric,",
                "  LocalFilesystemContentStore,",
                "  ResolveStatus,",
                "  S3ContentStore,",
                "  TRACER_NAME,",
                "  attributes,",
                "  sha256Hex,",
                "  validateContentCaptureConfig,",
                '} from "@singleaxis/fabric";',
                'if (TRACER_NAME !== "@singleaxis/fabric") throw new Error("bad ESM export");',
                'if (sha256Hex("fabric") !== "ad2a542c84c7060f1f2ec92f6f7d2d675cf1fc8b47e0c75071d86380efabbb53") throw new Error("bad ESM runtime");',
                'new Fabric({ tenantId: "artifact-smoke", agentId: "artifact-smoke" });',
                'if (attributes.ATTR_DECISION_ID !== "fabric.decision_id") throw new Error("missing recorder attributes");',
                'if (Object.keys(attributes).some((name) => /GUARDRAIL|JUDGE|POLICY|TOOL_AUTH|ESCALAT/.test(name) || name.startsWith("ATTR_EVAL") || name === "EVENT_NAME_EVAL")) throw new Error("legacy attributes exported");',
                "// Governed-content surface: local capture + resolution from the packed artifact.",
                'const root = mkdtempSync(join(tmpdir(), "fabric-gov-"));',
                'const store = new LocalFilesystemContentStore(root, "artifact-smoke");',
                'validateContentCaptureConfig({ store, roles: "all", durability: "inline" }, CONTENT_ROLES);',
                "const gov = new Fabric({",
                '  tenantId: "artifact-smoke",',
                '  agentId: "artifact-smoke",',
                '  contentCapture: { store, roles: "all", durability: "inline" },',
                "});",
                "let manifestUri;",
                'await gov.decision({ sessionId: "s", requestId: "r" }, async (d) => {',
                '  d.recordContext("note.txt", "artifact smoke content");',
                "  manifestUri = d.contentManifestUri;",
                "});",
                'if (!manifestUri) throw new Error("no manifest URI from packed artifact");',
                "// Inline writes settle off the caller's stack; read after flush.",
                "await gov.flushContent(5);",
                "const resolver = new ContentResolver([store]);",
                "const doc = await resolver.exportTranscript(manifestUri, { materialize: true });",
                'if (doc.schema_version !== "fabric.transcript-export/v1") throw new Error("bad export schema");',
                'if (!doc.integrity.verified) throw new Error("integrity verification failed");',
                'const ctx = doc.steps.flatMap((s) => s.entries).find((e) => e.role === "context.file");',
                'if (!ctx || ctx.text !== "artifact smoke content") throw new Error("captured content unreadable");',
                "const ref = ctx.ref;",
                "const resolved = await resolver.resolve(ref);",
                'if (resolved.status !== ResolveStatus.AVAILABLE) throw new Error("resolve not available");',
                "await gov.close();",
                "// Optional AWS peer: absent SDK must not break install or import.",
                'const s3 = new S3ContentStore("smoke-bucket", "artifact-smoke");',
                "let hinted = false;",
                'try { await s3.read(s3.refFor("a".repeat(64))); } catch (e) { hinted = /aws-sdk/.test(String(e)); }',
                'if (!hinted) throw new Error("S3 without optional peer did not raise the hint");',
            ].join("\n"),
        );
        writeFileSync(
            join(fixture, "smoke.cjs"),
            [
                'const { mkdtempSync } = require("node:fs");',
                'const { tmpdir } = require("node:os");',
                'const { join } = require("node:path");',
                "const {",
                "  CONTENT_ROLES,",
                "  ContentResolver,",
                "  Fabric,",
                "  LocalFilesystemContentStore,",
                "  ResolveStatus,",
                "  TRACER_NAME,",
                "  attributes,",
                "  sha256Hex,",
                "  validateContentCaptureConfig,",
                '} = require("@singleaxis/fabric");',
                'if (TRACER_NAME !== "@singleaxis/fabric") throw new Error("bad CJS export");',
                'if (sha256Hex("fabric") !== "ad2a542c84c7060f1f2ec92f6f7d2d675cf1fc8b47e0c75071d86380efabbb53") throw new Error("bad CJS runtime");',
                'new Fabric({ tenantId: "artifact-smoke", agentId: "artifact-smoke" });',
                'if (attributes.ATTR_DECISION_ID !== "fabric.decision_id") throw new Error("missing recorder attributes");',
                'if (Object.keys(attributes).some((name) => /GUARDRAIL|JUDGE|POLICY|TOOL_AUTH|ESCALAT/.test(name) || name.startsWith("ATTR_EVAL") || name === "EVENT_NAME_EVAL")) throw new Error("legacy attributes exported");',
                "(async () => {",
                '  const root = mkdtempSync(join(tmpdir(), "fabric-gov-"));',
                '  const store = new LocalFilesystemContentStore(root, "artifact-smoke");',
                '  validateContentCaptureConfig({ store, roles: "all", durability: "inline" }, CONTENT_ROLES);',
                "  const gov = new Fabric({",
                '    tenantId: "artifact-smoke",',
                '    agentId: "artifact-smoke",',
                '    contentCapture: { store, roles: "all", durability: "inline" },',
                "  });",
                "  let manifestUri;",
                '  await gov.decision({ sessionId: "s", requestId: "r" }, async (d) => {',
                '    d.recordContext("note.txt", "artifact smoke content");',
                "    manifestUri = d.contentManifestUri;",
                "  });",
                "  // Inline writes settle off the caller's stack; read after flush.",
                "  await gov.flushContent(5);",
                "  const doc = await new ContentResolver([store]).exportTranscript(manifestUri, { materialize: true });",
                '  if (!doc.integrity.verified) throw new Error("integrity verification failed");',
                '  const ctx = doc.steps.flatMap((s) => s.entries).find((e) => e.role === "context.file");',
                '  if (!ctx || ctx.text !== "artifact smoke content") throw new Error("captured content unreadable");',
                "  const resolved = await new ContentResolver([store]).resolve(ctx.ref);",
                '  if (resolved.status !== ResolveStatus.AVAILABLE) throw new Error("resolve not available");',
                "  await gov.close();",
                "})().catch((e) => { console.error(e); process.exit(1); });",
            ].join("\n"),
        );
        writeFileSync(
            join(fixture, "smoke.ts"),
            [
                "import {",
                "  Fabric,",
                "  LocalFilesystemContentStore,",
                "  ContentResolver,",
                "  type ContentCaptureConfig,",
                "  type FabricConfig,",
                "  type DecisionIds,",
                "  type GovernedStore,",
                '} from "@singleaxis/fabric";',
                'const config: FabricConfig = { tenantId: "artifact-smoke", agentId: "artifact-smoke" };',
                'const ids: DecisionIds = { sessionId: "session", requestId: "request" };',
                "const client: Fabric = new Fabric(config);",
                "client.decision(ids, (decision) => void decision);",
                'const store: GovernedStore = new LocalFilesystemContentStore("/tmp/x", "artifact-smoke");',
                'const capture: ContentCaptureConfig = { store, roles: "all", durability: "inline" };',
                'import { envStatus, type StatusDocument, type WireHandle } from "@singleaxis/fabric/wire";',
                "const status: StatusDocument = envStatus();",
                "const handle: WireHandle | undefined = undefined;",
                "void status;",
                "void handle;",
                "const resolver: ContentResolver = new ContentResolver([store]);",
                "void capture;",
                "void resolver;",
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

        // Spec 055 §9.4: the wire entry loads in both formats, the root import installs
        // nothing, and envStatus() answers without installing.
        writeFileSync(
            join(fixture, "wire.mjs"),
            [
                'import * as root from "@singleaxis/fabric";',
                'import { envStatus, install, run } from "@singleaxis/fabric/wire";',
                'import diagnostics from "node:diagnostics_channel";',
                'if (typeof install !== "function" || typeof run !== "function") throw new Error("bad wire ESM export");',
                'if (diagnostics.channel("undici:request:create").hasSubscribers) throw new Error("the root import installed a hook");',
                'if ("install" in root) throw new Error("the root package exports the wire API");',
                "const doc = envStatus({});",
                'if (doc.schema !== "fabric.wire-status/v1" || doc.sdk_language !== "typescript") throw new Error("bad status document");',
            ].join("\n"),
        );
        writeFileSync(
            join(fixture, "wire.cjs"),
            [
                'const wire = require("@singleaxis/fabric/wire");',
                'if (typeof wire.envStatus !== "function") throw new Error("bad wire CJS export");',
                'if (wire.envStatus({}).capture === undefined) throw new Error("bad status document");',
            ].join("\n"),
        );
        run(process.execPath, [join(fixture, "wire.mjs")]);
        run(process.execPath, [join(fixture, "wire.cjs")]);
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
    const options = {
        destination: undefined,
        expectedVersion: undefined,
        smoke: false,
        prebuilds: "prebuilds-build",
        partialPrebuilds: false,
    };
    for (let index = 0; index < argv.length; index += 1) {
        const arg = argv[index];
        if (arg === "--destination") options.destination = argv[++index];
        else if (arg === "--expected-version") options.expectedVersion = argv[++index];
        else if (arg === "--smoke") options.smoke = true;
        else if (arg === "--prebuilds") options.prebuilds = argv[++index];
        // Development only: pack whichever prebuilds are present (none on a machine that
        // built none). A release tarball carries all six.
        else if (arg === "--allow-partial-prebuilds") options.partialPrebuilds = true;
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
    const targets = stagePrebuilds(resolve(PACKAGE_ROOT, options.prebuilds), {
        requireAll: !options.partialPrebuilds,
    });
    const expectedFiles = expectedPackageFiles(targets);
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
    const verified = validatePackRecord(
        record,
        artifactBytes,
        options.expectedVersion,
        expectedFiles,
    );
    verifyArchiveMembers(artifact, verified.files);
    verifyRecorderBoundary(artifact, verified.files);
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
        prebuilds: targets,
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
