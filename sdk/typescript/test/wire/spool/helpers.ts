// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Helpers of the wire spool tests (spec 055 §9.5, unit 055-t7): the shared vectors,
 * private spool directories, sample records, a bundled TypeScript writer process and a
 * Python interpreter that imports this repository's `fabric` package.
 */
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { type ChildProcess, spawn, spawnSync } from "node:child_process";

import { buildSync } from "esbuild";

import { parseJson } from "../../../src/wire/codec.js";
import type { SpoolIo } from "../../../src/wire/spool.js";

import { REPO, contract } from "../helpers.js";

import { pythonWithFabric } from "../registration/helpers.js";

export { native, pythonWithFabric, runPython, start } from "../registration/helpers.js";
export type { Native, Running } from "../registration/helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));

/** `contracts/capture/v1/fixtures/vectors/spool-bytes-v1.json`, exact integers. */
export const VECTORS = contract("contracts/capture/v1/fixtures/vectors/spool-bytes-v1.json");
export const KEY = Buffer.from(VECTORS.spool_key_hex as string, "hex");
export const OTHER_KEY = Buffer.alloc(32, 0x5a);

/** The `spool-record-*.json` fixtures of one directory (`valid` or `invalid`). */
export function fixtures(kind: "valid" | "invalid"): [string, string][] {
  const dir = join(REPO, "contracts", "capture", "v1", "fixtures", kind);
  return readdirSync(dir)
    .filter((name) => name.startsWith("spool-record-") && name.endsWith(".json"))
    .sort()
    .map((name) => [name.replace(/\.json$/, ""), join(dir, name)]);
}

/** A vector record by name: its header and body bytes. */
export function vectorRecord(name: string): { doc: any; bodies: Buffer[] } {
  const found = (VECTORS.records as any[]).find((record) => record.name === name);
  if (found === undefined) throw new Error(`no vector record ${name}`);
  return {
    doc: found.header,
    bodies: (found.bodies_hex as string[]).map((hex) => Buffer.from(hex, "hex")),
  };
}

/** The header fields a writer passes (the spool sets schema, order and time). */
export function entryOf(name: string): { doc: Record<string, unknown>; bodies: Buffer[] } {
  const { doc, bodies } = vectorRecord(name);
  const rest = { ...doc };
  for (const key of ["schema_version", "order", "written_at_unix_nano"]) delete rest[key];
  return { doc: rest, bodies };
}

const dirs: string[] = [];

/** A fresh private directory (mode 0700) holding a `spool` path that does not exist yet. */
export function spoolDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "f055-t7-spool-"));
  chmodSync(dir, 0o700);
  dirs.push(dir);
  return join(dir, "spool");
}

/** Removes every directory {@link spoolDir} made. */
export function cleanupDirs(): void {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
}

/** Bundles `fixtures/<name>.ts` into a temporary CommonJS file `<name>.cjs`. */
export function bundleFixture(name: string): { file: string; cleanup(): void } {
  const dir = mkdtempSync(join(tmpdir(), `f055-t7-${name}-`));
  buildSync({
    entryPoints: [join(HERE, "fixtures", `${name}.ts`)],
    outdir: dir,
    outExtension: { ".js": ".cjs" },
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node22",
    logLevel: "silent",
  });
  return {
    file: join(dir, `${name}.cjs`),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/** An exchange entry whose one body is `size` bytes of `fill` (its header updated). */
export function sized(
  size: number,
  fill = 0x61,
): { doc: Record<string, unknown>; bodies: Buffer[] } {
  const doc = globalThis.structuredClone(entryOf("exchange").doc) as any;
  const first = doc.bodies[0];
  first.length = size;
  first.descriptor.stored_byte_length = size;
  doc.bodies = [first];
  return { doc, bodies: [Buffer.alloc(size, fill)] };
}

/** A spawned process read line by line (each line one JSON value, exact integers). */
export interface Lines {
  readonly child: ChildProcess;
  next(): Promise<any>;
  kill(): Promise<void>;
}

export function spawnLines(
  command: string,
  args: readonly string[],
  env: typeof process.env = process.env,
): Lines {
  const child = spawn(command, [...args], { stdio: ["ignore", "pipe", "pipe"], env });
  let out = "";
  let err = "";
  const waiting: ((line: string | Error) => void)[] = [];
  const lines: string[] = [];
  let ended = false;
  const exited = new Promise<void>((done) => child.once("exit", () => done()));
  const flush = (): void => {
    for (;;) {
      const at = out.indexOf("\n");
      if (at < 0) break;
      lines.push(out.slice(0, at));
      out = out.slice(at + 1);
    }
    while (waiting.length > 0 && lines.length > 0) waiting.shift()!(lines.shift()!);
    if (ended) {
      for (const wait of waiting.splice(0)) wait(new Error(`${command} exited: ${err}`));
    }
  };
  child.stdout!.on("data", (chunk: Buffer) => {
    out += chunk.toString();
    flush();
  });
  child.stderr!.on("data", (chunk: Buffer) => (err += chunk.toString()));
  child.once("exit", () => {
    ended = true;
    flush();
  });
  return {
    child,
    next: () =>
      new Promise((resolve, reject) => {
        waiting.push((line) => (line instanceof Error ? reject(line) : resolve(parseJson(line))));
        flush();
      }),
    kill: async () => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      await exited;
    },
  };
}

/**
 * The Python interpreter of the cross-language tests, checked to read and write sealed
 * (`FWSPENC1`) records: Python's spool envelope needs the `cryptography` package, which
 * the SDK's `otlp` extra installs. Fails at once, naming the fix, when it is missing.
 */
export function pythonWithSpoolKey(): string {
  const python = pythonWithFabric();
  const probe = spawnSync(python, ["-c", "import cryptography"], {
    encoding: "utf8",
    env: pythonEnv(),
  });
  if (probe.status !== 0) {
    throw new Error(
      `'${python}' cannot import cryptography, which Python's sealed wire spool ` +
        "(FWSPENC1) needs. Fix: run 'uv sync --extra otlp' in sdk/python, or install " +
        "'sdk/python[otlp]' into FABRIC_TEST_PYTHON ('pip install -e \"sdk/python[otlp]\"')",
    );
  }
  return python;
}

/** The environment a Python child needs to import this repository's `fabric`. */
export function pythonEnv(): typeof process.env {
  return { ...process.env, PYTHONPATH: join(REPO, "sdk", "python", "src") };
}

export function read(path: string): Buffer {
  return readFileSync(path);
}

// ---------------------------------------------------------------------- fault injection

export type Op = keyof SpoolIo;

/** A {@link SpoolIo} that records calls and fails the `nth` call of `op` (0-based). */
export function faulty(base: SpoolIo): {
  io: SpoolIo;
  calls: Op[];
  arm(op: Op, nth: number, code?: string): void;
  disarm(): void;
} {
  const calls: Op[] = [];
  let armed: { op: Op; nth: number; code: string } | undefined;
  const counts = new Map<Op, number>();
  const io = Object.fromEntries(
    (Object.keys(base) as Op[]).map((op) => [
      op,
      (...args: unknown[]) => {
        calls.push(op);
        const seen = counts.get(op) ?? 0;
        counts.set(op, seen + 1);
        if (armed !== undefined && armed.op === op && armed.nth === seen) {
          const code = armed.code;
          armed = undefined;
          throw Object.assign(new Error(`injected ${code} at ${op}`), { code });
        }
        return (base[op] as (...a: unknown[]) => unknown)(...args);
      },
    ]),
  ) as unknown as SpoolIo;
  return {
    io,
    calls,
    arm(op, nth, code = "EIO") {
      counts.clear();
      armed = { op, nth, code };
    },
    disarm() {
      armed = undefined;
    },
  };
}
