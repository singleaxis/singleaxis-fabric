#!/usr/bin/env node
// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Builds the wire core of the source tree for the parity job and the Node e2e (spec 055
// §9.2 `ts-wire-parity`, unit 055-t13): `sdk/typescript/src/wire/core.ts` bundled into
// one CommonJS file (`fabric-wire.cjs`, which is also the Fabric worker's entry) with the
// esbuild version the SDK locks, and the native lock module compiled for this machine by
// the maintainers' script. Unit 055-t14 replaces this with the packed package.
//
//   node qualification/node-wire/parity/build.mjs OUT_DIR   # prints {core, prebuilds, digest, target}

import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const SDK = join(REPO, "sdk", "typescript");

function target() {
    const arch = { x64: "x64", arm64: "arm64" }[process.arch];
    if (arch === undefined) throw new Error(`no native target for ${process.arch}`);
    if (process.platform === "darwin") return `darwin-${arch}`;
    if (process.platform !== "linux") throw new Error(`no native target for ${process.platform}`);
    const glibc = process.report?.getReport()?.header?.glibcVersionRuntime !== undefined;
    return `linux-${arch}-${glibc ? "glibc" : "musl"}`;
}

export function build(outdir = mkdtempSync(join(tmpdir(), "f055-t13-parity-"))) {
    mkdirSync(outdir, { recursive: true });
    const require = createRequire(join(SDK, "package.json"));
    const { buildSync } = require("esbuild");
    buildSync({
        entryPoints: { "fabric-wire": join(SDK, "src", "wire", "core.ts") },
        outdir,
        outExtension: { ".js": ".cjs" },
        bundle: true,
        platform: "node",
        format: "cjs",
        target: "node24",
        logLevel: "silent",
        nodePaths: [join(SDK, "node_modules")],
    });
    const name = target();
    const prebuilds = join(outdir, "prebuilds");
    const file = join(prebuilds, name, "fabric_wire.node");
    const compile = join(REPO, "scripts", "typescript", "prebuild", "compile.sh");
    const done = spawnSync("sh", [compile, name, file, "release"], { encoding: "utf8" });
    if (done.status !== 0) {
        throw new Error(
            `could not compile the native lock module for ${name}: ${done.stderr || done.error?.message}. ` +
                "Install a C compiler (cc) and run 'npm ci' in sdk/typescript.",
        );
    }
    return {
        core: join(outdir, "fabric-wire.cjs"),
        prebuilds,
        target: name,
        digest: createHash("sha256").update(readFileSync(file)).digest("hex"),
        qualification: join(SDK, "wire-qualification.json"),
    };
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    process.stdout.write(JSON.stringify(build(process.argv[2])) + "\n");
}
