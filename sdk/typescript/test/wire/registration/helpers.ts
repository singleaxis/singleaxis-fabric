// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Helpers of the epoch registration tests (spec 055 §9.5, unit 055-t5): the native
 * module, private spool directories, a bundled TypeScript holder process and a Python
 * interpreter that imports this repository's `fabric` package.
 */
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildSync } from "esbuild";

import { parseJson } from "../../../src/wire/codec.js";
import { type NativeAddon, loadNative } from "../../../src/wire/native.js";
import { REPO } from "../helpers.js";
import { type NativeBuild, nativeBuild, sha256 } from "../native/build.js";

const HERE = dirname(fileURLToPath(import.meta.url));

export interface Native {
  readonly build: NativeBuild;
  readonly addon: NativeAddon;
  readonly digest: string;
}

/** Compiles (or finds) the native module and loads it in this isolate. */
export function native(): Native {
  const build = nativeBuild();
  const digest = sha256(build.release);
  const loaded = loadNative({ prebuildsDir: build.dir, digests: { [build.target]: digest } });
  if (!loaded.ok) throw new Error(`${loaded.reason}: ${loaded.message}`);
  return { build, addon: loaded.addon, digest };
}

/** A fresh private directory (mode 0700), as the spool directory is. */
export function spoolDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "f055-t5-spool-"));
  chmodSync(dir, 0o700);
  return dir;
}

/** A source id Python's `SourceAllocator` accepts (an opaque `s-` id). */
export function sourceId(fill: string): string {
  return `s-${fill.repeat(32).slice(0, 32)}`;
}

/** Bundles the holder fixture into a temporary CommonJS file. */
export function bundleHolder(): { file: string; cleanup(): void } {
  const dir = mkdtempSync(join(tmpdir(), "f055-t5-holder-"));
  buildSync({
    entryPoints: [join(HERE, "fixtures", "holder.ts")],
    outdir: dir,
    outExtension: { ".js": ".cjs" },
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node22",
    logLevel: "silent",
  });
  return {
    file: join(dir, "holder.cjs"),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

let python: string | undefined;

/**
 * A Python 3 interpreter that imports `fabric` from this repository: the
 * `FABRIC_TEST_PYTHON` interpreter, else `sdk/python/.venv/bin/python`. Throws with the
 * fix when neither works; the cross-language tests never skip.
 */
export function pythonWithFabric(): string {
  if (python !== undefined) return python;
  const local = join(REPO, "sdk", "python", ".venv", "bin", "python");
  const candidate = process.env.FABRIC_TEST_PYTHON ?? (existsSync(local) ? local : "python3");
  const probe = spawnSync(candidate, ["-c", "import fabric.wire._registration"], {
    encoding: "utf8",
    env: pythonEnv(),
  });
  if (probe.status !== 0) {
    throw new Error(
      `'${candidate}' cannot import fabric.wire._registration ` +
        `(${probe.error?.message ?? probe.stderr.trim().split("\n").pop() ?? "no output"}). ` +
        "These tests run Python's registration against TypeScript's: run 'uv sync' in " +
        "sdk/python, or set FABRIC_TEST_PYTHON to a Python 3.11+ interpreter with " +
        "sdk/python installed ('pip install -e sdk/python')",
    );
  }
  python = candidate;
  return python;
}

function pythonEnv(): typeof process.env {
  return { ...process.env, PYTHONPATH: join(REPO, "sdk", "python", "src") };
}

/** Runs a Python script to completion; its stdout is one JSON value (exact integers). */
export function runPython(script: string, args: readonly string[]): any {
  const result = spawnSync(pythonWithFabric(), ["-c", script, ...args], {
    encoding: "utf8",
    env: pythonEnv(),
    timeout: 60_000,
  });
  if (result.status !== 0) {
    throw new Error(`python exited ${result.status ?? result.signal}: ${result.stderr}`);
  }
  return parseJson(result.stdout.trim());
}

/** A started process and the first JSON line it printed (exact integers). */
export interface Running {
  readonly process: ChildProcess;
  readonly first: any;
  /** SIGKILL, then wait for the exit. */
  kill(): Promise<void>;
}

/** Starts a process that prints one JSON line and then stays alive. */
export function start(command: string, args: readonly string[], python = false): Promise<Running> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, [...args], {
      stdio: ["ignore", "pipe", "pipe"],
      env: python ? pythonEnv() : process.env,
    });
    let out = "";
    let err = "";
    const exited = new Promise<void>((done) => child.once("exit", () => done()));
    child.stderr.on("data", (chunk: Buffer) => (err += chunk.toString()));
    child.stdout.on("data", (chunk: Buffer) => {
      out += chunk.toString();
      const line = out.indexOf("\n");
      if (line < 0) return;
      resolve({
        process: child,
        first: parseJson(out.slice(0, line)),
        kill: async () => {
          if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
          await exited;
        },
      });
    });
    child.once("exit", (code, signal) => {
      if (!out.includes("\n")) reject(new Error(`${command} exited ${code ?? signal}: ${err}`));
    });
  });
}

/** Python: register an allocator of `<source>` on `<spool>`, allocate `<n>`, then stay alive. */
export const PY_HOLD = `
import json, sys, time
from fabric._sequence import SourceAllocator
from fabric.wire import _registration as reg
from fabric.wire._spool import Spool
spool = Spool(sys.argv[1], 1 << 26)
allocator = SourceAllocator(sys.argv[2])
if len(sys.argv) > 4:
    allocator.epoch = int(sys.argv[4])  # a forced collision
drawn = allocator.epoch
registration = reg.register(spool, allocator.source_id, allocator.epoch, allocator=allocator)
for _ in range(int(sys.argv[3])):
    allocator.allocate()
print(json.dumps({"status": registration.status, "reason": registration.reason,
                  "epoch": registration.epoch, "drawn": drawn,
                  "next": allocator._next}), flush=True)
while True:
    time.sleep(60)
`;

/** Python: the drainer's scan of \`<spool>\`, and every registration file decoded. */
export const PY_SCAN = `
import json, os, sys
from fabric.wire import _registration as reg
from fabric.wire._spool import Spool
spool = Spool(sys.argv[1], 1 << 26)
try:
    orphans = reg.scan_orphans(spool)
    directory = os.path.join(sys.argv[1], reg.EPOCHS_DIR)
    files = {}
    for name in sorted(os.listdir(directory)):
        with open(os.path.join(directory, name), "rb") as handle:
            found = reg.decode(handle.read())
        files[name] = found
    print(json.dumps({"orphans": [[o.source_id, o.epoch, o.next_sequence] for o in orphans],
                      "files": files}))
finally:
    spool.release()
`;
