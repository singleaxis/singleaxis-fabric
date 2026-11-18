// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 unit 055-t5 (§6.1, 050 §3.2): epoch registration files and the allocator's
// registration mirror, in one process. The cross-language and SIGKILL cases are in
// cross-language.test.ts. Ports Python's tests/test_epoch_registration.py and
// tests/test_epoch_registration_unenforced_locks.py case for case.
import { randomBytes } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { Worker } from "node:worker_threads";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { ExchangeTable, REQUEST, RESPONSE } from "../../../src/wire/exchange.js";
import { FLOCK_EXCLUSIVE, NativeCode, type NativeAddon } from "../../../src/wire/native.js";
import {
  ADMIT_LOCK,
  EPOCHS_DIR,
  HEADER_BYTES,
  MAX_REDRAWS,
  OFF_FINAL,
  OFF_NEXT_SEQUENCE,
  ORPHAN_SUFFIX,
  REG_MAGIC,
  REG_SIZE,
  type Registration,
  type RegisterOptions,
  UNENFORCED_LOCKS_WARNING,
  attachMirror,
  declaredOrphans,
  decode,
  encode,
  epochName,
  epochOf,
  newEpoch,
  orphanBeat,
  register,
  retireOrphan,
  scanOrphans,
  unsealedPriorEpochs,
} from "../../../src/wire/registration.js";
import { WireRuntime, createRuntimeShared } from "../../../src/wire/runtime.js";
import { REPO, contract } from "../helpers.js";
import { type Native, bundleFixture, native, sourceId, spoolDir } from "./helpers.js";

let lib: Native;
/** The module as shipped: real shared mappings (8 per process, never unmapped, §4.4). */
let real: NativeAddon;
/**
 * The module with test-only mappings that store through `pwrite` into the same file, so
 * one test process can make more registrations than the module has map handles. The
 * tests of the mirror itself, of hooks, and every subprocess test use {@link real}.
 */
let addon: NativeAddon;
const dirs: string[] = [];

function virtualMaps(base: NativeAddon): NativeAddon {
  const maps = new Map<number, { file: number; retired: boolean }>();
  let next = 1 << 20;
  return {
    ...base,
    mapShared: (file, length) => {
      const probe = Buffer.alloc(length);
      const read = base.pread(file, probe, 0n);
      if (read < 0) return read;
      if (read < length) return NativeCode.BAD_ARGUMENT;
      maps.set(next, { file, retired: false });
      return next++;
    },
    store64: (map, offset, value) => {
      const entry = maps.get(map);
      if (entry === undefined) return NativeCode.BAD_HANDLE;
      if (entry.retired) return NativeCode.RETIRED;
      const bytes = Buffer.alloc(8);
      bytes.writeBigUInt64LE(value);
      const wrote = base.pwrite(entry.file, bytes, BigInt(offset));
      return wrote === 8 ? NativeCode.OK : wrote < 0 ? wrote : NativeCode.IO;
    },
    retire: (map) => {
      const entry = maps.get(map);
      if (entry === undefined) return NativeCode.BAD_HANDLE;
      entry.retired = true;
      return NativeCode.OK;
    },
  };
}

beforeAll(() => {
  lib = native();
  real = lib.addon;
  addon = virtualMaps(real);
});
afterAll(() => lib?.build.cleanup());
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function spool(): string {
  const dir = spoolDir();
  dirs.push(dir);
  return dir;
}

function runtime(epoch?: bigint): WireRuntime {
  return new WireRuntime(
    createRuntimeShared({
      maxInflightBytes: 64 * 64 * 1024,
      queueMaxItems: 16,
      maxExchanges: 16,
      maxVectors: 64,
      ...(epoch === undefined ? {} : { epoch }),
    }),
    "installer",
  );
}

function reg(dir: string, rt: WireRuntime, extra: Partial<RegisterOptions> = {}): Registration {
  return register({ addon, spoolDir: dir, sourceId: sourceId("a"), runtime: rt, ...extra });
}

function file(dir: string, epoch: bigint, suffix = ".reg"): string {
  return join(dir, EPOCHS_DIR, epochName(epoch, suffix));
}

function fields(path: string) {
  const found = decode(readFileSync(path));
  if (found === null) throw new Error(`${path} does not decode`);
  return found;
}

function names(dir: string): string[] {
  return readdirSync(join(dir, EPOCHS_DIR)).sort();
}

function done(...registrations: Registration[]): void {
  for (const registration of registrations) {
    registration.final();
    registration.close();
  }
}

/** The module with some functions replaced (Python's monkeypatching). */
function patched(overrides: Partial<NativeAddon>): NativeAddon {
  return { ...addon, ...overrides };
}

const random = (() => {
  let seed = 0x5eed_0055n;
  return (limit: bigint): bigint => {
    seed = (seed * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
    return (seed >> 1n) % limit;
  };
})();

describe("the file", () => {
  it("is byte-identical with Python's for the same inputs (spool-bytes-v1.json)", () => {
    const vectors = contract("contracts/capture/v1/fixtures/vectors/spool-bytes-v1.json")
      .registrations as any[];
    expect(vectors.length).toBeGreaterThanOrEqual(3);
    for (const v of vectors) {
      const data = encode(
        BigInt(v.epoch),
        v.source_id,
        Number(v.pid),
        BigInt(v.registered_at_unix_nano),
      );
      expect(data.toString("hex")).toBe(v.file_hex);
      expect(decode(data)).toEqual({
        epoch: BigInt(v.epoch),
        pid: Number(v.pid),
        registeredAtUnixNano: BigInt(v.registered_at_unix_nano),
        sourceId: v.source_id,
        nextSequence: 0n,
        final: false,
      });
    }
  });

  it("round-trips every valid header and detects a flipped header bit", () => {
    for (let n = 0; n < 300; n++) {
      const epoch = 1n + random((1n << 63n) - 1n);
      const source = `s-${randomBytes(80)
        .toString("hex")
        .slice(0, Number(random(158n)))}`;
      const pid = Number(random(1n << 32n));
      const at = random(1n << 64n);
      const data = encode(epoch, source, pid, at);
      expect(data.length).toBe(REG_SIZE);
      expect(data.subarray(0, 8).equals(REG_MAGIC)).toBe(true);
      const expected = {
        epoch,
        pid,
        registeredAtUnixNano: at,
        sourceId: source,
        nextSequence: 0n,
        final: false,
      };
      expect(decode(data)).toEqual(expected);
      const corrupt = Buffer.from(data);
      corrupt[Number(random(BigInt(HEADER_BYTES)))]! ^= 1 << Number(random(8n));
      expect(decode(corrupt)).toBeNull(); // the header digest covers bytes 0..255
      const mutable = Buffer.from(data); // the mirror and final bytes are outside it
      mutable.writeBigUInt64LE(7n, OFF_NEXT_SEQUENCE);
      mutable[OFF_FINAL] = 1;
      expect(decode(mutable)).toEqual({ ...expected, nextSequence: 7n, final: true });
    }
    expect(decode(Buffer.alloc(0))).toBeNull();
    expect(decode(Buffer.alloc(REG_SIZE, "x"))).toBeNull();
    expect(() => encode(0n, "s-a", 1, 1n)).toThrow(/range/);
    expect(() => encode(1n << 63n, "s-a", 1, 1n)).toThrow(/range/);
    expect(() => encode(1n, "s".repeat(161), 1, 1n)).toThrow(/range/);
  });

  it("refuses a source id that is not UTF-8 when decoding, as Python's strict decode does", () => {
    const data = encode(5n, "s-\ud800", 1, 1n); // surrogatepass on the way in
    expect(decode(data)).toBeNull();
  });

  it("keeps a leading U+FEFF in the source id, as Python's decode does", () => {
    // TextDecoder drops a leading byte-order mark unless told not to; Python keeps it.
    const source = "﻿s-bom";
    expect(decode(encode(5n, source, 1, 1n))?.sourceId).toBe(source);
  });

  it("names epochs with 20 digits and reads back only registration names", () => {
    expect(epochName(1n)).toBe("00000000000000000001.reg");
    expect(epochName((1n << 63n) - 1n, ORPHAN_SUFFIX)).toBe("09223372036854775807.orphan");
    expect(epochOf("00000000000000000042.corrupt")).toBe(42n);
    for (const name of [
      "00000000000000000000.reg",
      "09223372036854775808.reg",
      "0000000000000000042.reg",
      "00000000000000000042.tmp",
      "unrelated.txt",
      "00000000000000000042",
    ]) {
      expect(epochOf(name)).toBeUndefined();
    }
  });

  it("draws non-zero 63-bit CSPRNG epochs that use the top bits", () => {
    const drawn = Array.from({ length: 5000 }, () => newEpoch());
    expect(drawn.every((e) => e > 0n && e < 1n << 63n)).toBe(true);
    expect(new Set(drawn).size).toBe(drawn.length);
    expect(drawn.some((e) => e >= 1n << 60n)).toBe(true);
    expect(runtime().epoch).toBeGreaterThan(0n); // the runtime starts in a drawn epoch
  });
});

describe("registration (rule 2) and the mirror (rule 3)", () => {
  it("holds a private, flocked file and mirrors the next sequence on every allocation", () => {
    const dir = spool();
    const rt = runtime();
    const registration = reg(dir, rt, { addon: real });
    expect(registration.status).toBe("registered");
    expect(registration.reason).toBeUndefined();
    expect(registration.locksEnforced).toBe(true);
    expect(registration.epoch).toBe(rt.epoch);
    const path = file(dir, rt.epoch);
    const info = lstatSync(path);
    expect(info.mode & 0o777).toBe(0o600);
    expect(info.size).toBe(REG_SIZE);
    expect(lstatSync(join(dir, EPOCHS_DIR)).mode & 0o777).toBe(0o700);
    const found = fields(path);
    expect([found.epoch, found.sourceId, found.pid]).toEqual([
      rt.epoch,
      sourceId("a"),
      process.pid,
    ]);
    // Held for the writer's lifetime: a second open description cannot take the lock.
    const d = addon.openDir(join(dir, EPOCHS_DIR));
    const h = addon.openFile(d, epochName(rt.epoch), false);
    expect(addon.flock(h, FLOCK_EXCLUSIVE)).toBe(NativeCode.WOULD_BLOCK);
    addon.close(h);
    addon.close(d);
    for (let expected = 1n; expected <= 3n; expected++) {
      rt.allocate();
      expect(fields(path).nextSequence).toBe(expected);
    }
    rt.allocate(0); // with a run slot (under the control-block lock)
    expect(fields(path).nextSequence).toBe(4n);
    registration.mirror(9n);
    expect(fields(path).nextSequence).toBe(9n);
    expect(scanOrphans({ addon, spoolDir: dir })).toEqual([]); // alive: never an orphan
    registration.final();
    expect(fields(path).final).toBe(true);
    registration.close();
    expect(() => lstatSync(path)).toThrow(); // final, then closed: removed
    registration.close(); // idempotent
    expect(rt.mirror).toBeUndefined();
    expect(rt.mirrorHandle).toBe(-1);
    expect(registration.fileHandle).toBe(-1);
    expect(rt.allocate().sequence).toBe(4n); // no mirror any more: still allocates
  });

  it("publishes the mirror handle so an attaching isolate mirrors through it", () => {
    const dir = spool();
    const rt = runtime();
    const registration = reg(dir, rt, { addon: real });
    expect(rt.mirrorHandle).toBeGreaterThan(0);
    // Only the map handle is published (spec 055 §4.4): the control block, which every
    // application isolate shares, never carries the registration's fd handle.
    expect(registration.fileHandle).toBeGreaterThan(0);
    const words = new BigInt64Array(rt.shared.control);
    expect(words.includes(BigInt(registration.fileHandle))).toBe(false);
    const other = new WireRuntime(rt.shared, "application");
    expect(other.mirror).toBeUndefined();
    attachMirror(other, real);
    other.allocate();
    other.allocate();
    expect(fields(file(dir, rt.epoch)).nextSequence).toBe(2n);
    done(registration);
    attachMirror(other, real); // after close: nothing to mirror
    expect(other.mirror).toBeUndefined();
  });

  it("repairs a stale mirror store that landed after a newer one, in at most 8 rounds", () => {
    const dir = spool();
    const rt = runtime();
    const registration = reg(dir, rt, { addon: real });
    const other = new WireRuntime(rt.shared, "application");
    attachMirror(other, real);
    const store = rt.mirror!;
    // Isolate A allocates 0; before its store of 1 lands, isolate B allocates 1 and
    // stores 2. A's late store of 1 must not be the last word.
    let interleave = true;
    rt.mirror = (next) => {
      if (interleave) {
        interleave = false;
        other.allocate();
        expect(fields(file(dir, rt.epoch)).nextSequence).toBe(2n);
      }
      store(next);
    };
    expect(rt.allocate().sequence).toBe(0n);
    expect(fields(file(dir, rt.epoch)).nextSequence).toBe(2n);
    // An isolate that keeps losing the race stops after 8 stores: bounded, never a hang.
    const stores: bigint[] = [];
    rt.mirror = (next) => {
      stores.push(next);
      other.allocate(); // a newer allocation in another isolate, every round
      store(next);
    };
    rt.allocate();
    expect(stores).toHaveLength(8);
    rt.mirror = store;
    rt.allocate(); // the next allocation repairs whatever the bounded one left
    expect(fields(file(dir, rt.epoch)).nextSequence).toBe(rt.nextSequence);
    done(registration);
  });

  it("brings the mirror up to date when it binds a runtime that already allocated", () => {
    const dir = spool();
    const rt = runtime();
    rt.allocate();
    rt.allocate();
    const registration = reg(dir, rt);
    expect(registration.status).toBe("registered");
    expect(fields(file(dir, rt.epoch)).nextSequence).toBe(2n);
    done(registration);
  });

  it("redraws a held epoch and the runtime adopts the drawn one", () => {
    const dir = spool();
    const first = runtime();
    const held = reg(dir, first);
    const second = runtime(first.epoch); // a forced collision on one spool
    const got = register({ addon, spoolDir: dir, sourceId: sourceId("b"), runtime: second });
    expect(got.status).toBe("registered");
    expect(got.epoch).not.toBe(first.epoch);
    expect(second.epoch).toBe(got.epoch);
    expect(fields(file(dir, got.epoch)).sourceId).toBe(sourceId("b"));
    expect(fields(file(dir, first.epoch)).sourceId).toBe(sourceId("a"));
    done(held, got);
  });

  it("redraws an unheld epoch without final and leaves it for the scan", () => {
    const dir = spool();
    const dead = runtime();
    const gone = reg(dir, dead);
    dead.allocate();
    gone.close(); // without final: the writer is gone
    const fresh = runtime(dead.epoch);
    const got = reg(dir, fresh);
    expect(got.status).toBe("registered");
    expect(fresh.epoch).not.toBe(dead.epoch);
    expect(fields(file(dir, dead.epoch)).nextSequence).toBe(1n); // kept for the scan
    expect(scanOrphans({ addon, spoolDir: dir })).toEqual([
      { sourceId: sourceId("a"), epoch: dead.epoch, nextSequence: 1n },
    ]);
    done(got);
  });

  it("clears a finished writer's leftover and redraws", () => {
    const dir = spool();
    const epoch = newEpoch();
    mkdirSync(join(dir, EPOCHS_DIR), { mode: 0o700 });
    const data = encode(epoch, sourceId("a"), 1, 1n);
    data[OFF_FINAL] = 1; // crashed between final and the unlink
    writeFileSync(file(dir, epoch), data, { mode: 0o600 });
    const again = runtime(epoch);
    const got = reg(dir, again);
    expect(got.status).toBe("registered");
    expect(got.epoch).not.toBe(epoch);
    expect(() => lstatSync(file(dir, epoch))).toThrow();
    done(got);
  });

  it("never reuses a declared orphan's epoch", () => {
    const dir = spool();
    const dead = runtime();
    reg(dir, dead).close();
    expect(scanOrphans({ addon, spoolDir: dir }).map((o) => o.epoch)).toEqual([dead.epoch]);
    const reuse = runtime(dead.epoch);
    const got = reg(dir, reuse);
    expect(got.status).toBe("registered");
    expect(got.epoch).not.toBe(dead.epoch);
    done(got);
  });

  it("redraws a forced collision at most 8 times", () => {
    const dir = spool();
    const held = reg(dir, runtime());
    // Seven more held epochs: each of the first seven redraws collides, the eighth is free.
    const taken = [held, ...Array.from({ length: 7 }, () => reg(dir, runtime()))];
    const free = newEpoch();
    const draws = [...taken.slice(1).map((r) => r.epoch), free];
    let calls = 0;
    const late = runtime(held.epoch);
    const got = reg(dir, late, { newEpoch: () => draws[calls++]! });
    expect(got.status).toBe("registered");
    expect(calls).toBe(MAX_REDRAWS);
    expect(got.epoch).toBe(free);
    expect(late.epoch).toBe(free);
    // Every redraw collides: exactly 8 redraws, then an explicit failure and no file.
    calls = 0;
    const before = names(dir);
    const unlucky = runtime(held.epoch);
    const failed = reg(dir, unlucky, {
      newEpoch: () => {
        calls++;
        return held.epoch;
      },
    });
    expect([failed.status, failed.reason]).toEqual(["failed", "redraws_exhausted"]);
    expect(calls).toBe(MAX_REDRAWS);
    expect(unlucky.epoch).toBe(held.epoch);
    expect(unlucky.mirrorHandle).toBe(-1);
    expect(names(dir)).toEqual(before);
    done(...taken, got);
  });

  it("reports every failure explicitly and never throws", () => {
    const dir = spool();
    const held = reg(dir, runtime());
    expect(
      register({ addon, spoolDir: undefined, sourceId: sourceId("a"), runtime: runtime() }).status,
    ).toBe("unregistered_direct");
    const full = reg(dir, runtime(), { maxRegistrations: 1 });
    expect([full.status, full.reason]).toEqual(["registration_full", "registration_full"]);
    // Another holder of the admission lock (another process, or this one's drainer).
    const d = addon.openDir(dir);
    const admit = addon.openFile(d, ADMIT_LOCK, true);
    expect(addon.flock(admit, FLOCK_EXCLUSIVE)).toBe(NativeCode.OK);
    const started = performance.now();
    const busy = reg(dir, runtime(), { admitTimeoutMs: 50 });
    expect(performance.now() - started).toBeGreaterThanOrEqual(50);
    expect([busy.status, busy.reason]).toEqual(["failed", "admission_timeout"]);
    expect(scanOrphans({ addon, spoolDir: dir, admitTimeoutMs: 20 })).toEqual([]);
    addon.close(admit);
    addon.close(d);
    const broken = reg(dir, runtime(), {
      addon: patched({ fsync: () => NativeCode.IO }), // the registration fsync fails
    });
    expect([broken.status, broken.reason]).toEqual(["failed", "io_error"]);
    const mapless = reg(dir, runtime(), { addon: patched({ mapShared: () => NativeCode.LIMIT }) });
    expect([mapless.status, mapless.reason]).toEqual(["failed", "io_error"]);
    const forkedChild = reg(dir, runtime(), {
      addon: patched({ openDir: () => NativeCode.FORKED }),
    });
    expect(forkedChild.status).toBe("unregistered_fork");
    expect(names(dir)).toEqual([epochName(held.epoch)]); // no failed attempt left a file
    const warned: string[] = [];
    const quiet = reg(dir, runtime(), {
      warn: (message) => {
        warned.push(message);
        throw new Error("a warning sink that throws");
      },
    });
    expect(quiet.status).toBe("registered");
    expect(warned).toEqual([]); // this filesystem enforces locks
    done(held, quiet);
  });

  it("refuses a redraw once positions exist in the colliding epoch, leaving nothing", () => {
    const dir = spool();
    const first = runtime();
    const held = reg(dir, first);
    const late = runtime(first.epoch);
    late.allocate(); // positions already exist in the colliding epoch: no redraw possible
    const got = reg(dir, late);
    expect([got.status, got.reason]).toEqual(["failed", "epoch_in_use"]);
    expect(late.epoch).toBe(first.epoch);
    expect(late.mirrorHandle).toBe(-1);
    expect(names(dir)).toEqual([epochName(first.epoch)]);
    done(held);
  });

  it("fails when the registration path is not a directory", () => {
    const dir = spool();
    writeFileSync(join(dir, EPOCHS_DIR), "");
    const got = reg(dir, runtime());
    expect([got.status, got.reason]).toEqual(["failed", "io_error"]);
    expect(scanOrphans({ addon, spoolDir: dir })).toEqual([]);
    expect(unsealedPriorEpochs(addon, dir)).toEqual({ epochs: [], count: 0 });
    expect(declaredOrphans(addon, dir)).toEqual([]);
  });
});

describe("the orphan scan (rule 5)", () => {
  it("declares, renames and retires orphans", () => {
    const dir = spool();
    expect(scanOrphans({ addon, spoolDir: dir })).toEqual([]); // no directory yet
    const dead = runtime();
    const gone = register({ addon, spoolDir: dir, sourceId: "s-dead", runtime: dead });
    for (let n = 0; n < 5; n++) dead.allocate();
    gone.close();
    const idle = runtime();
    register({ addon, spoolDir: dir, sourceId: "s-idle", runtime: idle }).close();
    const live = runtime();
    const alive = register({ addon, spoolDir: dir, sourceId: "s-live", runtime: live });
    const orphans = scanOrphans({ addon, spoolDir: dir });
    const bySource = [...orphans].sort((a, b) => a.sourceId.localeCompare(b.sourceId));
    expect(bySource).toEqual([
      { sourceId: "s-dead", epoch: dead.epoch, nextSequence: 5n },
      { sourceId: "s-idle", epoch: idle.epoch, nextSequence: 0n },
    ]);
    expect(bySource.map(orphanBeat)).toEqual([
      { sourceId: "s-dead", epoch: dead.epoch, sequence: 4n, kind: "periodic" },
      undefined,
    ]);
    expect(scanOrphans({ addon, spoolDir: dir, admitted: true })).toEqual([]); // each once
    expect(lstatSync(file(dir, dead.epoch, ORPHAN_SUFFIX)).isFile()).toBe(true);
    const order = (a: { epoch: bigint }, b: { epoch: bigint }) => (a.epoch < b.epoch ? -1 : 1);
    expect(declaredOrphans(addon, dir)).toEqual([...orphans].sort(order));
    const sorted = [dead.epoch, idle.epoch].sort((a, b) => (a < b ? -1 : 1));
    expect(unsealedPriorEpochs(addon, dir)).toEqual({ epochs: sorted, count: 2 });
    expect(retireOrphan(addon, dir, dead.epoch, 3600)).toBe(false); // not yet due
    expect(retireOrphan(addon, dir, dead.epoch, 3600, Date.now() / 1000 + 3601)).toBe(true);
    expect(unsealedPriorEpochs(addon, dir)).toEqual({ epochs: [idle.epoch], count: 1 });
    expect(retireOrphan(addon, dir, dead.epoch, 0)).toBe(false);
    done(alive);
  });

  it("quarantines corrupt files and clears finished ones", () => {
    const dir = spool();
    const held = reg(dir, runtime());
    const epochs = join(dir, EPOCHS_DIR);
    writeFileSync(join(epochs, epochName(12345n)), "FWEPOCH1 torn", { mode: 0o600 });
    const finished = encode(777n, sourceId("a"), 1, 1n);
    finished[OFF_FINAL] = 1;
    writeFileSync(join(epochs, epochName(777n)), finished, { mode: 0o600 });
    writeFileSync(join(epochs, "unrelated.txt"), "", { mode: 0o600 });
    writeFileSync(join(epochs, epochName(0n)), "", { mode: 0o600 }); // never an epoch
    expect(scanOrphans({ addon, spoolDir: dir })).toEqual([]);
    expect(lstatSync(join(epochs, epochName(12345n, ".corrupt"))).isFile()).toBe(true);
    expect(() => lstatSync(join(epochs, epochName(777n)))).toThrow();
    expect(unsealedPriorEpochs(addon, dir)).toEqual({ epochs: [12345n], count: 1 });
    expect(declaredOrphans(addon, dir)).toEqual([]);
    expect(retireOrphan(addon, dir, 12345n, 0)).toBe(true);
    done(held);
  });

  it("bounds the declared list at 64 and keeps the count exact", () => {
    const dir = spool();
    const epochs = join(dir, EPOCHS_DIR);
    mkdirSync(epochs, { mode: 0o700 });
    for (let epoch = 1n; epoch <= 70n; epoch++) {
      writeFileSync(join(epochs, epochName(epoch, ORPHAN_SUFFIX)), encode(epoch, "node-1", 1, 1n), {
        mode: 0o600,
      });
    }
    const { epochs: listed, count } = unsealedPriorEpochs(addon, dir);
    expect(listed).toEqual(Array.from({ length: 64 }, (_, n) => BigInt(n + 1)));
    expect(count).toBe(70);
    expect(unsealedPriorEpochs(addon, undefined)).toEqual({ epochs: [], count: 0 });
  });
});

describe("a filesystem that does not enforce flock (a Docker Desktop bind mount)", () => {
  // Every lock attempt succeeds, as Python's tests simulate it.
  const unenforced = () => patched({ flock: () => NativeCode.OK });

  it("never declares this process's own live epoch", () => {
    const dir = spool();
    const rt = runtime();
    const registration = reg(dir, rt, { addon: unenforced(), warn: () => undefined });
    expect(registration.status).toBe("registered");
    expect(registration.locksEnforced).toBe(false);
    for (let n = 0; n < 3; n++) rt.allocate();
    expect(scanOrphans({ addon: unenforced(), spoolDir: dir })).toEqual([]);
    // A drainer in another isolate knows the epoch from the control block alone.
    expect(scanOrphans({ addon: unenforced(), spoolDir: dir, runtime: rt })).toEqual([]);
    expect(names(dir)).toEqual([epochName(rt.epoch)]);
    done(registration);
    expect(names(dir)).toEqual([]); // a clean close leaves nothing
  });

  it("never declares it from another isolate that knows the runtime, as the Fabric worker", async () => {
    // The scan in this isolate is protected by this isolate's held list; the Fabric
    // worker's isolate has none, so only the published mirror handle protects the epoch.
    const dir = spool();
    const rt = runtime();
    const registration = reg(dir, rt, { addon: unenforced(), warn: () => undefined });
    expect(registration.status).toBe("registered");
    rt.allocate();
    const scanner = bundleFixture("scanner");
    try {
      const result = await new Promise<{ withRuntime: string[][]; withoutRuntime: string[][] }>(
        (resolve, reject) => {
          const worker = new Worker(scanner.file, {
            workerData: {
              shared: rt.shared,
              prebuilds: lib.build.dir,
              digest: lib.digest,
              spool: dir,
            },
          });
          worker.once("message", resolve);
          worker.once("error", reject);
        },
      );
      expect(result.withRuntime).toEqual([]);
      // Without the runtime, that isolate takes the live epoch for an orphan: the check
      // above is what protects it, not this isolate's held list.
      expect(result.withoutRuntime).toEqual([[sourceId("a"), String(rt.epoch)]]);
    } finally {
      scanner.cleanup();
    }
    done(registration);
  }, 60_000);

  it("removes a finished writer's file that another process declared", () => {
    const dir = spool();
    const rt = runtime();
    const registration = reg(dir, rt, { addon: unenforced(), warn: () => undefined });
    rt.allocate();
    // Another process's scan took the unenforced lock and renamed the live file.
    renameSync(file(dir, rt.epoch), file(dir, rt.epoch, ORPHAN_SUFFIX));
    registration.final();
    expect(fields(file(dir, rt.epoch, ORPHAN_SUFFIX)).final).toBe(true);
    registration.close();
    expect(names(dir)).toEqual([]);
  });

  it("keeps another writer's declared orphan when closing", () => {
    const dir = spool();
    const dead = runtime();
    const gone = reg(dir, dead, { addon: unenforced(), warn: () => undefined });
    dead.allocate();
    gone.close(); // no final: a killed writer
    const live = runtime();
    const alive = register({
      addon: unenforced(),
      spoolDir: dir,
      sourceId: sourceId("d"),
      runtime: live,
      warn: () => undefined,
    });
    expect(scanOrphans({ addon: unenforced(), spoolDir: dir })).toEqual([
      { sourceId: sourceId("a"), epoch: dead.epoch, nextSequence: 1n },
    ]);
    done(alive); // removes only its own file
    expect(names(dir)).toEqual([epochName(dead.epoch, ORPHAN_SUFFIX)]);
  });

  it("warns once per spool directory, naming the cause and the fix, never the path", () => {
    const dir = spool();
    const warned: string[] = [];
    const warn = (message: string) => warned.push(message);
    const enforced = reg(dir, runtime(), { warn });
    expect(warned).toEqual([]);
    const first = reg(dir, runtime(), { addon: unenforced(), warn });
    const second = reg(dir, runtime(), { addon: unenforced(), warn });
    expect(warned).toEqual([UNENFORCED_LOCKS_WARNING]);
    expect(warned[0]).toMatch(/does not enforce file locks/);
    expect(warned[0]).toMatch(/put the spool \(FABRIC_WIRE_SPOOL_DIR\) on a local disk/);
    expect(warned[0]).not.toContain(dir);
    done(enforced, first, second);
    expect(names(dir)).toEqual([]);
  });
});

describe("registration never happens in a hook", () => {
  it("leaves only the mirror's store64 on the allocation and exchange path", () => {
    const calls: string[] = [];
    const recording = Object.fromEntries(
      Object.entries(real).map(([name, fn]) => [
        name,
        (...args: unknown[]) => {
          calls.push(name);
          return (fn as (...a: unknown[]) => unknown)(...args);
        },
      ]),
    ) as unknown as NativeAddon;
    const dir = spool();
    const rt = runtime();
    const registration = register({
      addon: recording,
      spoolDir: dir,
      sourceId: sourceId("a"),
      runtime: rt,
    });
    expect(registration.status).toBe("registered");
    // Install did the file work: open, lock, write, fsync, map.
    for (const name of ["openDir", "openFile", "flock", "pwrite", "fsync", "mapShared"]) {
      expect(calls).toContain(name);
    }
    calls.length = 0;
    // What hooks do: allocate (with and without a run), and whole exchanges.
    const table = new ExchangeTable(rt);
    for (let n = 0; n < 10; n++) {
      rt.allocate(n % 2 === 0 ? 0 : -1);
      const handle = table.begin({ runSlot: 0 });
      table.admit(handle, REQUEST, Buffer.alloc(1000, n));
      table.responseStarted(handle);
      table.admit(handle, RESPONSE, "text", "utf8");
      table.finish(handle, "complete");
    }
    expect(calls.length).toBeGreaterThanOrEqual(20);
    expect(new Set(calls)).toEqual(new Set(["store64"]));
    expect(fields(file(dir, rt.epoch)).nextSequence).toBe(rt.nextSequence);
    calls.length = 0;
    done(registration);
  });

  it("opens registration and admission files only through the native module", () => {
    // Spec 055 §4.4: closing any descriptor of a file releases the process's record locks
    // on it, so node:fs may only name files (list, lstat, rename, remove), never open them.
    const source = readFileSync(join(REPO, "sdk/typescript/src/wire/registration.ts"), "utf8");
    const imports = [...source.matchAll(/import\s*\{([^}]*)\}\s*from\s*"node:fs"/g)];
    expect(imports).toHaveLength(1);
    const names = imports[0]![1]!
      .split(",")
      .map((name) => name.trim())
      .filter(Boolean);
    const allowed = new Set([
      "chmodSync",
      "lstatSync",
      "mkdirSync",
      "readdirSync",
      "renameSync",
      "unlinkSync",
      "utimesSync",
    ]);
    expect(names.filter((name) => !allowed.has(name))).toEqual([]);
    expect(source).not.toMatch(/from\s+"node:fs\/promises"|require\("(node:)?fs"\)/);
    expect(source).not.toMatch(/\bimport\s+\*\s+as\s+\w+\s+from\s+"node:fs"/);
  });

  it("is not reachable from the hook-path modules", () => {
    for (const name of ["runtime", "arena", "queue", "exchange"]) {
      const source = readFileSync(join(REPO, "sdk/typescript/src/wire", `${name}.ts`), "utf8");
      expect(source).not.toMatch(/from\s+"\.\/registration\.js"/);
      expect(source).not.toMatch(/from\s+"node:fs"/);
    }
  });
});
