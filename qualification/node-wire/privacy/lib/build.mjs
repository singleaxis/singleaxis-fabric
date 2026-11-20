// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Builds what the privacy harness runs: the capture (lib/agent.ts) and the Fabric worker
// (lib/fabric-worker.ts) bundled from the SDK source with the esbuild version the SDK
// locks, and the native lock module compiled for this machine by the maintainers' script
// (scripts/typescript/prebuild/compile.sh). Unit 055-t14 replaces the bundles with the
// packed package and its prebuilds.

import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO = join(HERE, "..", "..", "..", "..");
const SDK = join(REPO, "sdk", "typescript");

function target() {
    const arch = { x64: "x64", arm64: "arm64" }[process.arch];
    if (arch === undefined) throw new Error(`no native target for ${process.arch}`);
    if (process.platform === "darwin") return `darwin-${arch}`;
    if (process.platform !== "linux") throw new Error(`no native target for ${process.platform}`);
    const glibc = process.report?.getReport()?.header?.glibcVersionRuntime !== undefined;
    return `linux-${arch}-${glibc ? "glibc" : "musl"}`;
}

/** Bundles and compiles into a new temporary directory; returns the paths and digest. */
export function build(outdir = mkdtempSync(join(tmpdir(), "f055-t8-privacy-build-"))) {
    const require = createRequire(join(SDK, "package.json"));
    const { buildSync } = require("esbuild");
    buildSync({
        entryPoints: [join(HERE, "agent.ts"), join(HERE, "fabric-worker.ts")],
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
        dir: outdir,
        agent: join(outdir, "agent.cjs"),
        worker: join(outdir, "fabric-worker.cjs"),
        prebuilds,
        digest: createHash("sha256").update(readFileSync(file)).digest("hex"),
    };
}
