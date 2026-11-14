// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The native lock module under test (spec 055 §4.4).
 *
 * The prebuild workflow sets `FABRIC_WIRE_NATIVE_BUILD` (a directory holding
 * `<target>/fabric_wire.node` and `faults/<target>/fabric_wire.node`) and
 * `FABRIC_WIRE_NATIVE_TARGET`, and the tests run against those exact files. Without
 * them (`npm test` on a developer machine or in the SDK job) the tests compile both
 * variants for this machine with the C compiler on PATH. Nothing is ever compiled when
 * the package is installed or loaded.
 */
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { NATIVE_FILE, nativeTarget, type NativeTarget } from "../../../src/wire/native.js";
import { REPO } from "../helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));
export const CHILD = join(HERE, "child.mjs");

export interface NativeBuild {
  /** Holds `<target>/fabric_wire.node`: a `prebuildsDir` for the loader. */
  readonly dir: string;
  readonly target: NativeTarget;
  /** The module as shipped. */
  readonly release: string;
  /** The test-only variant with fault injection (`FABRIC_WIRE_TEST_FAULT`). */
  readonly faults: string;
  /** True when the files come from the prebuild workflow, not a local compile. */
  readonly prebuilt: boolean;
  /** Removes what the helper created. */
  cleanup(): void;
}

export function sha256(file: string): string {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

/** A fresh private directory (mode 0700), as the spool directory is. */
export function privateDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), `f055-t3-${prefix}-`));
  chmodSync(dir, 0o700);
  return dir;
}

export function nativeBuild(): NativeBuild {
  const fromEnv = process.env.FABRIC_WIRE_NATIVE_BUILD;
  if (fromEnv !== undefined && fromEnv !== "") {
    const target = process.env.FABRIC_WIRE_NATIVE_TARGET as NativeTarget;
    return {
      dir: fromEnv,
      target,
      release: join(fromEnv, target, NATIVE_FILE),
      faults: join(fromEnv, "faults", target, NATIVE_FILE),
      prebuilt: true,
      cleanup: () => undefined,
    };
  }
  const target = nativeTarget();
  if (target === null) {
    throw new Error(
      `the native lock module has no target for ${process.platform}-${process.arch}; ` +
        "run these tests on Linux or macOS, x64 or arm64",
    );
  }
  const dir = mkdtempSync(join(tmpdir(), "f055-t3-native-"));
  const release = join(dir, target, NATIVE_FILE);
  const faults = join(dir, "faults", target, NATIVE_FILE);
  const compile = join(REPO, "scripts", "typescript", "prebuild", "compile.sh");
  for (const [out, variant] of [
    [release, "release"],
    [faults, "faults"],
  ] as const) {
    const result = spawnSync("sh", [compile, target, out, variant], { encoding: "utf8" });
    if (result.status !== 0) {
      throw new Error(
        `could not compile the native lock module for ${target} (${variant}): ` +
          `${result.stderr || result.error?.message || "no output"}\n` +
          "Install a C compiler (cc) and run 'npm ci' in sdk/typescript, or set " +
          "FABRIC_WIRE_NATIVE_BUILD and FABRIC_WIRE_NATIVE_TARGET to a directory built by " +
          "scripts/typescript/prebuild/prebuild.mjs",
      );
    }
  }
  return {
    dir,
    target,
    release,
    faults,
    prebuilt: false,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/** Runs `child.mjs` to completion and returns its JSON line. */
export function runChild(
  file: string,
  op: string,
  dir: string,
  args: readonly string[] = [],
  fault?: string,
): Record<string, number> {
  const env = { ...process.env };
  delete env.FABRIC_WIRE_TEST_FAULT;
  if (fault !== undefined) env.FABRIC_WIRE_TEST_FAULT = fault;
  const result = spawnSync(process.execPath, [CHILD, file, op, dir, ...args], {
    encoding: "utf8",
    env,
    timeout: 60_000,
  });
  if (result.status !== 0) {
    throw new Error(`child ${op} exited ${result.status ?? result.signal}: ${result.stderr}`);
  }
  return JSON.parse(result.stdout) as Record<string, number>;
}

/** A started process and the first JSON line it printed. */
export interface Held {
  readonly process: ChildProcess;
  readonly first: Record<string, number>;
}

/** Starts a process that prints one JSON line and then stays alive. */
export function startHolder(command: string, args: readonly string[]): Promise<Held> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, [...args], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stderr.on("data", (chunk: Buffer) => (err += chunk.toString()));
    child.stdout.on("data", (chunk: Buffer) => {
      out += chunk.toString();
      const line = out.indexOf("\n");
      if (line >= 0) {
        resolve({
          process: child,
          first: JSON.parse(out.slice(0, line)) as Record<string, number>,
        });
      }
    });
    child.once("error", (error: Error & { code?: string }) =>
      reject(
        error.code === "ENOENT"
          ? new Error(`'${command}' is not on PATH; this test needs it installed`)
          : error,
      ),
    );
    child.once("exit", (code, signal) =>
      reject(new Error(`${command} exited early (${code ?? signal}): ${err}`)),
    );
  });
}

/** Kills a process with SIGKILL and waits until the kernel has reaped it. */
export function kill(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    child.once("exit", () => resolve());
    child.kill("SIGKILL");
  });
}
