// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Bundles the harness's capture (lib/capture.ts), its Fabric worker (lib/fabric-worker.ts)
// and, from unit 055-t13, the whole recorder (lib/recorder.ts, with the stalled-recorder
// worker lib/recorder-worker.ts) from the SDK source into CommonJS files, with the
// esbuild version the SDK locks (the one tsup builds the package with), and compiles the
// native lock module for this machine with the maintainers' script. Unit 055-t14
// replaces this with the packed package.

import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { platformName } from "../../../../scripts/typescript/audit-undici-channels.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO = join(HERE, "..", "..", "..", "..");
const SDK = join(REPO, "sdk", "typescript");

/** Returns the paths of the bundles and the native module, in a new temporary directory. */
export function build(outdir = mkdtempSync(join(tmpdir(), "f055-t6-passivity-"))) {
    const require = createRequire(join(SDK, "package.json"));
    const { buildSync } = require("esbuild");
    buildSync({
        entryPoints: ["capture.ts", "fabric-worker.ts", "recorder.ts", "recorder-worker.ts"].map((f) =>
            join(HERE, f),
        ),
        outdir,
        outExtension: { ".js": ".cjs" },
        bundle: true,
        platform: "node",
        format: "cjs",
        target: "node24",
        logLevel: "silent",
        nodePaths: [join(SDK, "node_modules")],
    });
    const target = platformName();
    const prebuilds = join(outdir, "prebuilds");
    const file = join(prebuilds, target, "fabric_wire.node");
    const compile = join(REPO, "scripts", "typescript", "prebuild", "compile.sh");
    const done = spawnSync("sh", [compile, target, file, "release"], { encoding: "utf8" });
    if (done.status !== 0) {
        throw new Error(
            `could not compile the native lock module for ${target}: ${done.stderr || done.error?.message}. ` +
                "Install a C compiler (cc) and run 'npm ci' in sdk/typescript.",
        );
    }
    return {
        dir: outdir,
        capture: join(outdir, "capture.cjs"),
        worker: join(outdir, "fabric-worker.cjs"),
        recorder: join(outdir, "recorder.cjs"),
        recorderWorker: join(outdir, "recorder-worker.cjs"),
        prebuilds,
        target,
        digest: createHash("sha256").update(readFileSync(file)).digest("hex"),
        qualification: join(SDK, "wire-qualification.json"),
    };
}
