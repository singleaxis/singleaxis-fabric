// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The native lock module itself (spec 055 §4.4): every function, every result code,
 * locks across processes and languages, fork/exec inheritance, Worker teardown and the
 * exported symbols.
 */
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  linkSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { Worker } from "node:worker_threads";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  FLOCK_EXCLUSIVE,
  FLOCK_SHARED,
  FLOCK_UNLOCK,
  NATIVE_ABI_VERSION,
  NATIVE_FUNCTIONS,
  NativeCode,
  RECORD_READ,
  RECORD_UNLOCK,
  RECORD_WRITE,
  loadNative,
  nativeCodeName,
  type NativeAddon,
  type NativeCodeName,
} from "../../../src/wire/native.js";
import { REPO } from "../helpers.js";
import {
  kill,
  nativeBuild,
  privateDir,
  runChild,
  sha256,
  startHolder,
  type NativeBuild,
} from "./build.js";

const C = NativeCode;
let build: NativeBuild;
let n: NativeAddon;
let dir: string;
let d: number;
/** Codes a JavaScript test has seen the module return. */
const seen = new Set<NativeCodeName>();

function saw<T extends number | bigint>(code: T): T {
  if (Number(code) < 0) seen.add(nativeCodeName(code));
  return code;
}

function open(name: string, create = true): number {
  return saw(n.openFile(d, name, create));
}

beforeAll(() => {
  build = nativeBuild();
  const loaded = loadNative({
    prebuildsDir: build.dir,
    digests: { [build.target]: sha256(build.release) },
  });
  if (!loaded.ok) throw new Error(`${loaded.reason}: ${loaded.message}`);
  n = loaded.addon;
  dir = privateDir("addon");
  d = n.openDir(dir);
  expect(d).toBeGreaterThan(0);
}, 120_000);

afterAll(() => {
  if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
  build?.cleanup();
});

describe("the ABI header and the loader agree", () => {
  const header = readFileSync(join(REPO, "sdk/typescript/native/fabric_wire_abi.h"), "utf8");

  it("NativeCode holds the header's codes", () => {
    const codes: Record<string, number> = { OK: 0 };
    for (const m of header.matchAll(/^#define FABRIC_WIRE_([A-Z_]+) \((-\d+)\)/gm)) {
      codes[m[1] as string] = Number(m[2]);
    }
    expect(codes).toEqual({ ...C });
  });

  it("NATIVE_FUNCTIONS is the header's function list, in order", () => {
    const names = [...header.matchAll(/^ {2}X\(([A-Za-z0-9]+), \d\)/gm)].map((m) => m[1]);
    expect(names).toEqual([...NATIVE_FUNCTIONS]);
    expect(Object.keys(n)).toEqual([...NATIVE_FUNCTIONS]);
  });
});

describe("functions", () => {
  it("abiVersion returns 1", () => {
    expect(n.abiVersion()).toBe(1);
    expect(NATIVE_ABI_VERSION).toBe(1);
  });

  it("openDir accepts only a private directory owned by this user", () => {
    expect(saw(n.openDir(join(dir, "absent")))).toBe(C.NOT_FOUND);
    const shared = join(dir, "group-readable");
    mkdirSync(shared, { mode: 0o700 });
    chmodSync(shared, 0o750);
    expect(saw(n.openDir(shared))).toBe(C.UNSAFE_PATH);
    symlinkSync(dir, join(dir, "dir-link"));
    expect(n.openDir(join(dir, "dir-link"))).toBe(C.UNSAFE_PATH);
    writeFileSync(join(dir, "plain"), "");
    expect(n.openDir(join(dir, "plain"))).toBe(C.UNSAFE_PATH);
    expect(saw(n.openDir(""))).toBe(C.BAD_ARGUMENT);
    expect(n.openDir("a\0b")).toBe(C.BAD_ARGUMENT);
    expect(n.openDir(7 as unknown as string)).toBe(C.BAD_ARGUMENT);
  });

  it("openFile creates 0600 files and refuses unsafe names and files", () => {
    const h = open("created");
    expect(h).toBeGreaterThan(0);
    expect(statSync(join(dir, "created")).mode & 0o777).toBe(0o600);
    expect(n.close(h)).toBe(0);
    expect(open("absent", false)).toBe(C.NOT_FOUND);
    for (const name of ["", ".", "..", "a/b", "x".repeat(256), "a\0b"]) {
      expect(open(name)).toBe(C.BAD_ARGUMENT);
    }
    expect(n.openFile(d, "x", 1 as unknown as boolean)).toBe(C.BAD_ARGUMENT);
    expect(saw(n.openFile(123456, "x", true))).toBe(C.BAD_HANDLE);
    symlinkSync(join(dir, "created"), join(dir, "file-link"));
    expect(open("file-link", false)).toBe(C.UNSAFE_PATH);
    linkSync(join(dir, "created"), join(dir, "hard-link"));
    expect(open("created", false)).toBe(C.UNSAFE_PATH); // two links
    rmSync(join(dir, "hard-link"));
    chmodSync(join(dir, "created"), 0o644);
    expect(open("created", false)).toBe(C.UNSAFE_PATH);
    mkdirSync(join(dir, "subdir"));
    expect(open("subdir", false)).toBeLessThan(0);
  });

  it("flock never blocks: a second handle gets WOULD_BLOCK", () => {
    const a = open("flock");
    const b = open("flock", false);
    expect(n.flock(a, FLOCK_EXCLUSIVE)).toBe(0);
    expect(saw(n.flock(b, FLOCK_EXCLUSIVE))).toBe(C.WOULD_BLOCK);
    expect(n.flock(b, FLOCK_SHARED)).toBe(C.WOULD_BLOCK);
    expect(n.flock(a, FLOCK_SHARED)).toBe(0);
    expect(n.flock(b, FLOCK_SHARED)).toBe(0);
    expect(n.flock(a, FLOCK_UNLOCK)).toBe(0);
    expect(n.flock(b, FLOCK_UNLOCK)).toBe(0);
    expect(n.flock(a, 3 as 0)).toBe(C.BAD_ARGUMENT);
    expect(n.flock(a, 1.5 as 0)).toBe(C.BAD_ARGUMENT);
    expect(n.close(a)).toBe(0);
    expect(n.close(b)).toBe(0);
  });

  it("recordLock takes bigint ranges and each operation", () => {
    const h = open("record");
    expect(n.recordLock(h, 0n, 10n, RECORD_WRITE)).toBe(0);
    expect(n.recordLock(h, 0n, 10n, RECORD_UNLOCK)).toBe(0);
    expect(n.recordLock(h, 2n ** 40n, 1n, RECORD_READ)).toBe(0);
    expect(n.recordLock(h, 2n ** 40n, 1n, RECORD_UNLOCK)).toBe(0);
    expect(n.recordLock(h, 0 as unknown as bigint, 1n, RECORD_WRITE)).toBe(C.BAD_ARGUMENT);
    expect(n.recordLock(h, -1n, 1n, RECORD_WRITE)).toBe(C.BAD_ARGUMENT);
    expect(n.recordLock(h, 0n, 2n ** 64n, RECORD_WRITE)).toBe(C.BAD_ARGUMENT);
    expect(n.recordLock(h, 0n, 1n, 4 as 0)).toBe(C.BAD_ARGUMENT);
    expect(n.close(h)).toBe(0);
  });

  it("pwrite and pread move bytes at an offset, at most 1 MiB a call", () => {
    const h = open("io");
    const text = new TextEncoder().encode("fabric-wire");
    expect(n.pwrite(h, text, 5n)).toBe(11);
    const back = new Uint8Array(16);
    expect(n.pread(h, back, 0n)).toBe(16);
    expect(new TextDecoder().decode(back.subarray(5))).toBe("fabric-wire");
    expect(n.pread(h, back, 1000n)).toBe(0);
    expect(n.pread(h, back.subarray(0, 4), 5n)).toBe(4); // a view's own range
    expect(new TextDecoder().decode(back.subarray(0, 4))).toBe("fabr");
    const big = new Uint8Array(1024 * 1024 + 1);
    expect(n.pwrite(h, big.subarray(1), 0n)).toBe(1024 * 1024);
    expect(n.pwrite(h, big, 0n)).toBe(C.BAD_ARGUMENT);
    expect(n.pread(h, big, 0n)).toBe(C.BAD_ARGUMENT);
    expect(n.pread(h, back, 0 as unknown as bigint)).toBe(C.BAD_ARGUMENT);
    expect(n.pwrite(h, [1, 2] as unknown as Uint8Array, 0n)).toBe(C.BAD_ARGUMENT);
    expect(n.pwrite(h, new Uint16Array(2) as unknown as Uint8Array, 0n)).toBe(C.BAD_ARGUMENT);
    expect(n.close(h)).toBe(0);
  });

  it("fsync succeeds on a live handle only", () => {
    const h = open("fsync");
    expect(n.fsync(h)).toBe(0);
    expect(n.close(h)).toBe(0);
    expect(n.fsync(h)).toBe(C.BAD_HANDLE);
  });

  it("allocate reserves real blocks and never shrinks", () => {
    const h = open("reserve");
    expect(n.allocate(h, 0n)).toBe(C.BAD_ARGUMENT);
    expect(n.allocate(h, 4096 as unknown as bigint)).toBe(C.BAD_ARGUMENT);
    expect(n.allocate(h, 262144n)).toBe(0);
    const stat = statSync(join(dir, "reserve"));
    expect(stat.size).toBe(262144);
    expect(stat.blocks * 512).toBeGreaterThanOrEqual(262144);
    expect(n.allocate(h, 4096n)).toBe(0);
    expect(statSync(join(dir, "reserve")).size).toBe(262144);
    expect(n.close(h)).toBe(0);
  });

  it("mapShared, store64, load64 and retire share 8-byte words with the file", () => {
    const h = open("mirror");
    expect(n.mapShared(h, 4096)).toBe(C.BAD_ARGUMENT); // longer than the file
    expect(n.allocate(h, 4096n)).toBe(0);
    expect(n.mapShared(h, 0)).toBe(C.BAD_ARGUMENT);
    expect(n.mapShared(h, 65537)).toBe(C.BAD_ARGUMENT);
    expect(n.mapShared(h, 4096n as unknown as number)).toBe(C.BAD_ARGUMENT);
    const m = n.mapShared(h, 4096);
    expect(m).toBeGreaterThan(0);
    const value = 0x0123456789abcdefn;
    expect(n.store64(m, 16, value)).toBe(0);
    expect(n.load64(m, 16)).toBe(value);
    const onDisk = new Uint8Array(8);
    expect(n.pread(h, onDisk, 16n)).toBe(8);
    expect(new BigUint64Array(onDisk.buffer)[0]).toBe(value); // MAP_SHARED
    expect(n.store64(m, 4, 1n)).toBe(C.BAD_ARGUMENT); // not aligned
    expect(n.store64(m, 4096, 1n)).toBe(C.BAD_ARGUMENT); // past the end
    expect(n.store64(m, 0, -1n)).toBe(C.BAD_ARGUMENT);
    expect(n.store64(m, 0, 1 as unknown as bigint)).toBe(C.BAD_ARGUMENT);
    expect(n.load64(m, 4090)).toBe(BigInt(C.BAD_ARGUMENT));
    expect(n.store64(h, 0, 1n)).toBe(C.BAD_HANDLE); // an fd handle is not a map handle
    expect(n.load64(0, 0)).toBe(BigInt(C.BAD_HANDLE));
    expect(n.retire(999999)).toBe(C.BAD_HANDLE);
    expect(n.store64(m, 0, 7n)).toBe(0);
    expect(n.retire(m)).toBe(0);
    expect(saw(n.store64(m, 0, 8n))).toBe(C.RETIRED);
    expect(n.close(h)).toBe(0);
    expect(n.load64(m, 0)).toBe(7n); // the mapping outlives retire and the descriptor
    expect(n.retire(m)).toBe(0);
  });

  it("close is idempotent and a stale handle never reaches a reused slot", () => {
    const h = open("handles");
    expect(n.close(h)).toBe(0);
    expect(n.close(h)).toBe(C.BAD_HANDLE);
    const again = open("handles", false);
    expect(again).not.toBe(h);
    expect(again & 0xff).toBe(h & 0xff); // the same slot, a new generation
    expect(n.fsync(h)).toBe(C.BAD_HANDLE);
    expect(n.close(again)).toBe(0);
  });

  it("envAttach returns one id per environment", () => {
    const id = n.envAttach();
    expect(id).toBeGreaterThan(0);
    expect(n.envAttach()).toBe(id);
  });

  it("takeDetachedEnvs fills a Uint32Array only", () => {
    expect(n.takeDetachedEnvs(new Uint32Array(0))).toBe(0);
    expect(n.takeDetachedEnvs(new Uint8Array(4) as unknown as Uint32Array)).toBe(C.BAD_ARGUMENT);
    expect(n.takeDetachedEnvs([] as unknown as Uint32Array)).toBe(C.BAD_ARGUMENT);
  });

  it("no function throws on missing or wrong arguments", () => {
    const wrong: unknown[][] = [[], [undefined], [null, null, null, null], [{}, [], "x", 1n]];
    for (const name of NATIVE_FUNCTIONS) {
      if (name === "abiVersion" || name === "envAttach") continue;
      const fn = n[name] as (...args: unknown[]) => number | bigint;
      for (const args of wrong) {
        const result = fn(...args);
        expect([C.BAD_ARGUMENT, C.BAD_HANDLE], `${name}(${args.length} args)`).toContain(
          Number(result),
        );
        expect(typeof result).toBe(name === "load64" ? "bigint" : "number");
      }
    }
  });
});

describe("codes that need a failing kernel call (the fault-injection build)", () => {
  const rows: [string, string, NativeCodeName][] = [
    ["openDir=EACCES", "openDir", "PERMISSION"],
    ["openFile=EEXIST", "openFile", "EXISTS"],
    ["flock=EOPNOTSUPP", "flock", "UNSUPPORTED"],
    ["recordLock=EOPNOTSUPP", "recordLock", "UNSUPPORTED"],
    ["pread=EIO", "pread", "IO"],
    ["pwrite=ENOSPC", "pwrite", "NO_SPACE"],
    ["pwrite=EDQUOT", "pwrite", "QUOTA"],
    ["fsync=EIO", "fsync", "IO"],
    ["fsync=ENOSPC", "fsync", "NO_SPACE"],
    ["allocate=ENOSPC", "allocate", "NO_SPACE"],
    ["allocate=EDQUOT", "allocate", "QUOTA"],
    ["mapShared=EXDEV", "mapShared", "OTHER"],
    ["ring=overflow", "takeDetachedEnvs", "OVERFLOW"],
  ];
  it.each(rows)("%s makes %s return %s", (fault, fn, code) => {
    const fdir = privateDir("fault");
    try {
      expect(saw(runChild(build.faults, "fault", fdir, [fn], fault).code as number)).toBe(C[code]);
    } finally {
      rmSync(fdir, { recursive: true, force: true });
    }
  });

  it("OVERFLOW is reported once", () => {
    // The C unit tests fill the 1,024-entry ring for real; here the flag is preset.
    const fdir = privateDir("fault");
    try {
      expect(runChild(build.faults, "fault", fdir, ["takeDetachedEnvs"]).code).toBe(0);
    } finally {
      rmSync(fdir, { recursive: true, force: true });
    }
  });

  it("every function returns FORKED in a child forked without exec", () => {
    const fdir = privateDir("fault");
    try {
      const result = runChild(build.faults, "forked", fdir, [], "forked=1");
      expect(result.abiVersion).toBe(1);
      for (const name of NATIVE_FUNCTIONS) {
        if (name !== "abiVersion") expect(saw(result[name] as number), name).toBe(C.FORKED);
      }
    } finally {
      rmSync(fdir, { recursive: true, force: true });
    }
  });

  it("LIMIT: the 65th descriptor handle and the 9th map handle", () => {
    const fdir = privateDir("limit");
    try {
      const result = runChild(build.release, "limits", fdir);
      expect(result.fds).toBe(64);
      expect(saw(result.fdCode as number)).toBe(C.LIMIT);
      expect(result.maps).toBe(8);
      expect(result.mapCode).toBe(C.LIMIT);
    } finally {
      rmSync(fdir, { recursive: true, force: true });
    }
  });

  it("every code of §4.4 was returned to a JavaScript test", () => {
    const all = (Object.keys(C) as NativeCodeName[]).filter((name) => name !== "OK");
    expect([...seen].sort()).toEqual(all.sort());
  });
});

describe("locks across processes", () => {
  it("a second process conflicts on flock and on the locked record range only", async () => {
    const held = await startHolder(process.execPath, [
      join(REPO, "sdk/typescript/test/wire/native/child.mjs"),
      build.release,
      "hold",
      dir,
      "two-process",
    ]);
    try {
      expect(held.first).toEqual({ flock: 0, record: 0 });
      // Another process: both locks conflict.
      expect(runChild(build.release, "try", dir, ["two-process"])).toEqual({
        flockExclusive: C.WOULD_BLOCK,
        flockShared: C.WOULD_BLOCK,
        recordInside: C.WOULD_BLOCK,
        recordReadInside: C.WOULD_BLOCK,
        recordOutside: 0,
      });
      // This process too.
      const h = open("two-process", false);
      const r = open("two-process.rec", false);
      expect(n.flock(h, FLOCK_EXCLUSIVE)).toBe(C.WOULD_BLOCK);
      expect(n.recordLock(r, 9n, 1n, RECORD_WRITE)).toBe(C.WOULD_BLOCK);
      expect(n.recordLock(r, 10n, 1n, RECORD_WRITE)).toBe(0);
      await kill(held.process);
      // The kernel released a killed process's locks.
      expect(n.flock(h, FLOCK_EXCLUSIVE)).toBe(0);
      expect(n.recordLock(r, 0n, 10n, RECORD_WRITE)).toBe(0);
      expect(n.close(h)).toBe(0);
      expect(n.close(r)).toBe(0);
    } finally {
      await kill(held.process);
    }
  });

  it("a fork/exec child holds no inherited lock after the parent is SIGKILLed", async () => {
    const held = await startHolder(process.execPath, [
      join(REPO, "sdk/typescript/test/wire/native/child.mjs"),
      build.release,
      "hold-with-child",
      dir,
      "inherit",
    ]);
    const grandchild = held.first.child as number;
    try {
      expect(held.first).toMatchObject({ flock: 0, record: 0 });
      const h = open("inherit", false);
      const r = open("inherit.rec", false);
      expect(n.flock(h, FLOCK_EXCLUSIVE)).toBe(C.WOULD_BLOCK);
      expect(n.recordLock(r, 0n, 10n, RECORD_WRITE)).toBe(C.WOULD_BLOCK);
      await kill(held.process);
      expect(() => process.kill(grandchild, 0)).not.toThrow(); // the child is still running
      // O_CLOEXEC: the child never had the descriptor, so the flock died with the parent.
      expect(n.flock(h, FLOCK_EXCLUSIVE)).toBe(0);
      expect(n.recordLock(r, 0n, 10n, RECORD_WRITE)).toBe(0);
      expect(n.close(h)).toBe(0);
      expect(n.close(r)).toBe(0);
    } finally {
      await kill(held.process);
      try {
        process.kill(grandchild, "SIGKILL");
      } catch {
        // Already gone.
      }
    }
  });
});

describe("Python interop (fcntl.flock and fcntl.lockf)", () => {
  const python = process.env.FABRIC_TEST_PYTHON ?? "python3";

  it("a lock Python holds blocks the module", async () => {
    const script = [
      "import fcntl, os, sys, time",
      "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)",
      "rec = os.open(sys.argv[1] + '.rec', os.O_RDWR | os.O_CREAT, 0o600)",
      "fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)",
      "fcntl.lockf(rec, fcntl.LOCK_EX | fcntl.LOCK_NB, 10, 0)",
      "print('{\"held\": 1}', flush=True)",
      "time.sleep(600)",
    ].join("\n");
    const held = await startHolder(python, ["-c", script, join(dir, "python-holds")]);
    try {
      expect(held.first).toEqual({ held: 1 });
      const h = open("python-holds", false);
      const r = open("python-holds.rec", false);
      expect(h).toBeGreaterThan(0);
      expect(r).toBeGreaterThan(0);
      expect(n.flock(h, FLOCK_EXCLUSIVE)).toBe(C.WOULD_BLOCK);
      expect(n.flock(h, FLOCK_SHARED)).toBe(C.WOULD_BLOCK);
      expect(n.recordLock(r, 0n, 10n, RECORD_WRITE)).toBe(C.WOULD_BLOCK);
      expect(n.recordLock(r, 5n, 1n, RECORD_READ)).toBe(C.WOULD_BLOCK);
      expect(n.recordLock(r, 10n, 5n, RECORD_WRITE)).toBe(0);
      await kill(held.process);
      expect(n.flock(h, FLOCK_EXCLUSIVE)).toBe(0);
      expect(n.recordLock(r, 0n, 10n, RECORD_WRITE)).toBe(0);
      expect(n.close(h)).toBe(0);
      expect(n.close(r)).toBe(0);
    } finally {
      await kill(held.process);
    }
  });

  it("a lock the module holds blocks Python", () => {
    const h = open("node-holds");
    const r = open("node-holds.rec");
    expect(n.flock(h, FLOCK_EXCLUSIVE)).toBe(0);
    expect(n.recordLock(r, 0n, 10n, RECORD_WRITE)).toBe(0);
    const script = [
      "import fcntl, json, os, sys",
      "def attempt(fn, *args):",
      "    fd = os.open(sys.argv[1] + ('.rec' if fn is fcntl.lockf else ''), os.O_RDWR)",
      "    try:",
      "        fn(fd, *args)",
      "        return 'acquired'",
      "    except OSError:",
      "        return 'blocked'",
      "    finally:",
      "        os.close(fd)",
      "print(json.dumps({",
      "    'flock': attempt(fcntl.flock, fcntl.LOCK_EX | fcntl.LOCK_NB),",
      "    'flock_shared': attempt(fcntl.flock, fcntl.LOCK_SH | fcntl.LOCK_NB),",
      "    'lockf_inside': attempt(fcntl.lockf, fcntl.LOCK_EX | fcntl.LOCK_NB, 2, 4),",
      "    'lockf_shared_inside': attempt(fcntl.lockf, fcntl.LOCK_SH | fcntl.LOCK_NB, 1, 0),",
      "    'lockf_outside': attempt(fcntl.lockf, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 100),",
      "}))",
    ].join("\n");
    const run = (): unknown => {
      const result = spawnSync(python, ["-c", script, join(dir, "node-holds")], {
        encoding: "utf8",
      });
      if (result.error !== undefined || result.status !== 0) {
        throw new Error(
          `'${python}' failed (${result.error?.message ?? result.stderr}); this test needs ` +
            "python3 on PATH, or FABRIC_TEST_PYTHON set to a Python 3 interpreter",
        );
      }
      return JSON.parse(result.stdout);
    };
    expect(run()).toEqual({
      flock: "blocked",
      flock_shared: "blocked",
      lockf_inside: "blocked",
      lockf_shared_inside: "blocked",
      lockf_outside: "acquired",
    });
    expect(n.flock(h, FLOCK_UNLOCK)).toBe(0);
    expect(n.recordLock(r, 0n, 10n, RECORD_UNLOCK)).toBe(0);
    expect(run()).toMatchObject({ flock: "acquired", lockf_inside: "acquired" });
    expect(n.close(h)).toBe(0);
    expect(n.close(r)).toBe(0);
  });
});

describe("Worker teardown", () => {
  const source = `
    const { parentPort, workerData } = require("node:worker_threads");
    const holder = { exports: {} };
    process.dlopen(holder, workerData.file);
    parentPort.postMessage(holder.exports.envAttach());
    if (workerData.stay) setInterval(() => {}, 1000);
  `;

  async function detachedAfter(stay: boolean): Promise<{ id: number; taken: number[] }> {
    const worker = new Worker(source, { eval: true, workerData: { file: build.release, stay } });
    const id = await new Promise<number>((resolve, reject) => {
      worker.once("message", resolve);
      worker.once("error", reject);
    });
    if (stay) await worker.terminate();
    else await new Promise((resolve) => worker.once("exit", resolve));
    const taken: number[] = [];
    const dst = new Uint32Array(8);
    for (let i = 0; i < 100 && !taken.includes(id); i++) {
      const count = n.takeDetachedEnvs(dst);
      expect(count).toBeGreaterThanOrEqual(0);
      taken.push(...dst.subarray(0, count));
      if (!taken.includes(id)) await new Promise((resolve) => setTimeout(resolve, 20));
    }
    return { id, taken };
  }

  it("worker.terminate() reaches takeDetachedEnvs", async () => {
    const main = n.envAttach();
    const { id, taken } = await detachedAfter(true);
    expect(id).toBeGreaterThan(0);
    expect(id).not.toBe(main);
    expect(taken).toContain(id);
    expect(taken).not.toContain(main);
    expect(n.takeDetachedEnvs(new Uint32Array(8))).toBe(0); // each id is delivered once
  });

  it("a Worker that exits on its own reaches takeDetachedEnvs", async () => {
    const { id, taken } = await detachedAfter(false);
    expect(taken).toContain(id);
  });

  it("a Worker's teardown closes no descriptor and releases no lock", async () => {
    const h = open("survives-worker");
    expect(n.flock(h, FLOCK_EXCLUSIVE)).toBe(0);
    await detachedAfter(true);
    expect(n.fsync(h)).toBe(0);
    const other = open("survives-worker", false);
    expect(n.flock(other, FLOCK_EXCLUSIVE)).toBe(C.WOULD_BLOCK);
    expect(n.close(other)).toBe(0);
    expect(n.close(h)).toBe(0);
  });
});

describe("exported symbols", () => {
  it("the shared object exports only the two Node-API entry points", () => {
    const args = process.platform === "darwin" ? ["-gU"] : ["-D", "--defined-only"];
    const result = spawnSync("nm", [...args, build.release], { encoding: "utf8" });
    if (result.error !== undefined || result.status !== 0) {
      throw new Error(
        `'nm' failed (${result.error?.message ?? result.stderr}); install binutils (Linux) ` +
          "or the Xcode command line tools (macOS) to run this test",
      );
    }
    const symbols = result.stdout
      .split("\n")
      .filter((line) => line.trim() !== "")
      .map((line) => (line.trim().split(/\s+/).pop() as string).replace(/^_/, ""))
      .sort();
    expect(symbols).toEqual(["napi_register_module_v1", "node_api_module_get_api_version_v1"]);
  });
});
