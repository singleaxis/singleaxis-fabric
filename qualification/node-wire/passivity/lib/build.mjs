// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Bundles the harness's capture (lib/capture.ts) and Fabric worker (lib/fabric-worker.ts)
// from the SDK source into CommonJS files, with the esbuild version the SDK locks (the
// one tsup builds the package with). Unit 055-t14 replaces this with the packed package.

import { mkdtempSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO = join(HERE, "..", "..", "..", "..");
const SDK = join(REPO, "sdk", "typescript");

/** Returns the paths of the two bundles, in a new temporary directory. */
export function build(outdir = mkdtempSync(join(tmpdir(), "f055-t6-passivity-"))) {
    const require = createRequire(join(SDK, "package.json"));
    const { buildSync } = require("esbuild");
    buildSync({
        entryPoints: [join(HERE, "capture.ts"), join(HERE, "fabric-worker.ts")],
        outdir,
        outExtension: { ".js": ".cjs" },
        bundle: true,
        platform: "node",
        format: "cjs",
        target: "node24",
        logLevel: "silent",
        nodePaths: [join(SDK, "node_modules")],
    });
    return {
        dir: outdir,
        capture: join(outdir, "capture.cjs"),
        worker: join(outdir, "fabric-worker.cjs"),
    };
}
