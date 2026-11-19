// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 unit 055-t7 (§9.5): the spool's commit sequence, admission bound, drain lock,
// stable-order recovery scan and quarantine; a fault at every write, fsync and rename;
// a property test that disk accounting stays within bound + reserve after every
// operation and that the ledger equals what is on disk.
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  FLOCK_EXCLUSIVE,
  FLOCK_UNLOCK,
  type NativeAddon,
  NativeCode,
} from "../../../src/wire/native.js";
import {
  ENVELOPE_MAGIC,
  MAGIC,
  OverBoundError,
  spoolKeyId,
} from "../../../src/wire/spool-codec.js";
import {
  ADMIT_LOCK,
  LEDGER,
  LEDGER_BYTES,
  NativeSpoolError,
  QUARANTINE_SUFFIX,
  RESERVE_BYTES,
  Spool,
  SpoolConfigError,
  type SpoolIo,
  SpoolIoError,
  type SpoolOptions,
  TMP_PREFIX,
  diskFull,
  nodeSpoolIo,
} from "../../../src/wire/spool.js";
import { norm } from "../helpers.js";
import {
  KEY,
  OTHER_KEY,
  type Native,
  cleanupDirs,
  entryOf,
  native,
  sized,
  spoolDir,
} from "./helpers.js";

let lib: Native;
let addon: NativeAddon;

beforeAll(() => {
  lib = native();
  addon = lib.addon;
}, 120_000);
afterAll(() => lib?.build.cleanup());

const open: Spool[] = [];
afterEach(() => {
  for (const spool of open.splice(0)) spool.close();
  cleanupDirs();
});

let nextPid = 70_000;

/** A spool; each gets its own pid, as each writer process has one. */
function make(dir: string, options: Partial<SpoolOptions> = {}): Spool {
  nextPid += 1;
  const spool = new Spool(dir, { maxBytes: 1 << 20, addon, pid: nextPid, ...options });
  open.push(spool);
  return spool;
}

const exchange = entryOf("exchange");
const record = entryOf("record");
const loss = entryOf("loss");
const seal = entryOf("segment_seal");

function files(dir: string): string[] {
  return readdirSync(dir).sort();
}

describe("commit", () => {
  it("writes owner-only record files in drain order, readable by the drainer", () => {
    const dir = spoolDir();
    const spool = make(dir);
    const names = [
      spool.write(exchange.doc, exchange.bodies),
      spool.write(record.doc, record.bodies),
      spool.write(loss.doc, [], true),
      spool.write(seal.doc, [], true),
    ];
    expect(names.every((name) => typeof name === "string")).toBe(true);
    expect([...names].sort()).toEqual(names);
    expect(lstatSync(dir).mode & 0o777).toBe(0o700);
    for (const name of names) expect(lstatSync(join(dir, name!)).mode & 0o777).toBe(0o600);
    expect(files(dir).filter((name) => name.startsWith(TMP_PREFIX))).toEqual([]);
    expect(spool.bytes).toBe(spool.diskTotal());
    expect(spool.tryLock()).toBe(true);
    const scan = spool.recover();
    expect(scan.files.map((file) => file.name)).toEqual(names);
    const [first] = scan.files[0]!.records;
    expect(norm(first!.doc.span)).toEqual(norm(exchange.doc.span));
    expect(first!.doc.order).toBe(0);
    expect(first!.blob.equals(Buffer.concat(exchange.bodies))).toBe(true);
    expect(scan.files.map((file) => file.records[0]!.doc.record_kind)).toEqual([
      "exchange",
      "record",
      "loss",
      "marker",
    ]);
  });

  it("seals every record under the key: no plaintext header or body on disk", () => {
    const dir = spoolDir();
    const spool = make(dir, { key: KEY });
    const name = spool.write(exchange.doc, exchange.bodies)!;
    const raw = readFileSync(join(dir, name));
    expect(raw.subarray(0, 8).equals(ENVELOPE_MAGIC)).toBe(true);
    expect(raw.subarray(8, 20).toString("ascii")).toBe(spoolKeyId(KEY));
    expect(raw.includes(Buffer.from("travel-agent"))).toBe(false);
    expect(raw.includes(exchange.bodies[0]!)).toBe(false);
    expect(raw.includes(MAGIC)).toBe(false);
    spool.tryLock();
    expect(spool.recover().files[0]!.records[0]!.blob.equals(Buffer.concat(exchange.bodies))).toBe(
      true,
    );
  });

  it("refuses a record over its body bound before writing anything (R6)", () => {
    const dir = spoolDir();
    const spool = make(dir);
    const doc = {
      ...exchange.doc,
      bodies: Array.from({ length: 261 }, () => (exchange.doc as any).bodies[0]),
    };
    const [refused, written] = spool.writeBatch([{ doc }, exchange]);
    expect(refused).toBeInstanceOf(OverBoundError);
    expect(typeof written).toBe("string");
    expect(spool.names()).toEqual([written]);
  });
});

describe("commit safety", () => {
  it("never renames over an existing record (two writers sharing a pid and an epoch)", () => {
    const dir = spoolDir();
    const first = make(dir, { pid: 4242 });
    const second = make(dir, { pid: 4242 });
    const name = first.write(exchange.doc, exchange.bodies)!;
    const before = readFileSync(join(dir, name));
    let error: unknown;
    try {
      second.write(record.doc, record.bodies);
    } catch (caught) {
      error = caught;
    }
    expect((error as { code?: string }).code).toBe("EEXIST");
    expect(readFileSync(join(dir, name)).equals(before)).toBe(true);
    expect(files(dir).filter((n) => n.startsWith(TMP_PREFIX))).toEqual([]);
    expect(second.bytes).toBe(second.diskTotal());
  });

  it("loops over short writes: the record on disk is whole", () => {
    const dir = spoolDir();
    const base = nodeSpoolIo(addon);
    const io: SpoolIo = {
      ...base,
      writev: (fd, data, position) => {
        const first = data[0]!;
        return base.write(fd, first.subarray(0, Math.min(7, first.length)), position);
      },
    };
    const spool = make(dir, { io, key: KEY });
    const name = spool.write(exchange.doc, exchange.bodies)!;
    spool.tryLock();
    const scan = spool.recover();
    expect(scan.files.map((file) => file.name)).toEqual([name]);
    expect(scan.files[0]!.records[0]!.blob.equals(Buffer.concat(exchange.bodies))).toBe(true);
  });
});

describe("admission bound", () => {
  it("refuses a record that does not fit, counting full encoded size; loss and marker use the reserve", () => {
    const dir = spoolDir();
    const one = sized(1000);
    const probe = make(spoolDir(), { key: KEY });
    const size = (() => {
      const name = probe.write(one.doc, one.bodies)!;
      return probe.charge(name)!;
    })();
    const spool = make(dir, { key: KEY, maxBytes: size * 3 + 10 });
    expect(spool.write(one.doc, one.bodies)).not.toBeNull();
    expect(spool.write(one.doc, one.bodies)).not.toBeNull();
    expect(spool.write(one.doc, one.bodies)).not.toBeNull();
    expect(spool.write(one.doc, one.bodies)).toBeNull(); // queue_full
    expect(spool.diskTotal()).toBeLessThanOrEqual(spool.maxBytes);
    expect(spool.write(loss.doc, [], true)).not.toBeNull(); // the reserve
    expect(spool.diskTotal()).toBeLessThanOrEqual(spool.maxBytes + RESERVE_BYTES);
    expect(files(dir).some((name) => name.startsWith(TMP_PREFIX))).toBe(false);
  });

  it("a shared loss ledger lives inside the reserve: disk stays within bound + 1 MiB", () => {
    const big = sized(200_000);
    const fill = (dir: string): number => {
      const spool = make(dir, { maxBytes: 1000 });
      let written = 0;
      while (spool.write(big.doc, big.bodies, true) !== null) written += 1;
      expect(spool.diskTotal()).toBeLessThanOrEqual(spool.maxBytes + spool.reserveBytes);
      return written;
    };
    // Without a ledger the whole reserve is usable: five 200 KB records fit.
    expect(fill(spoolDir())).toBe(5);
    // A Python writer's preallocated ledger (260 KiB) takes its share of the reserve.
    const dir = spoolDir();
    mkdirSync(dir, 0o700);
    writeFileSync(join(dir, LEDGER), Buffer.alloc(LEDGER_BYTES), { mode: 0o600 });
    expect(fill(dir)).toBe(3);
    const spool = make(dir, { maxBytes: 1000 });
    expect(spool.ledgerSeen).toBe(true);
    expect(spool.reserveBytes).toBe(RESERVE_BYTES - LEDGER_BYTES);
    expect(spool.diskTotal() + LEDGER_BYTES).toBeLessThanOrEqual(1000 + RESERVE_BYTES);
  });

  it("a ledger created after the writer opened is seen at the next admission", () => {
    const dir = spoolDir();
    const spool = make(dir, { maxBytes: 1000 });
    expect(spool.reserveBytes).toBe(RESERVE_BYTES);
    writeFileSync(join(dir, LEDGER), Buffer.alloc(LEDGER_BYTES), { mode: 0o600 });
    expect(spool.write(loss.doc, [], true)).not.toBeNull();
    expect(spool.reserveBytes).toBe(RESERVE_BYTES - LEDGER_BYTES);
  });

  it("counts other processes' leftovers: temps, quarantined records and receipts", () => {
    const dir = spoolDir();
    const spool = make(dir, { maxBytes: 4000 });
    writeFileSync(join(dir, `${TMP_PREFIX}dead-writer.rec`), Buffer.alloc(1500), { mode: 0o600 });
    writeFileSync(join(dir, `x.rec${QUARANTINE_SUFFIX}`), Buffer.alloc(1500), { mode: 0o600 });
    writeFileSync(join(dir, "y.rec.ack"), Buffer.alloc(0), { mode: 0o600 });
    const one = sized(800);
    expect(spool.write(one.doc, one.bodies)).toBeNull();
    expect(spool.sharedBytes).toBe(1500 + 1500 + 128);
    spool.rescan();
    expect(spool.bytes).toBe(3128);
  });

  it("a busy admission lock refuses after the deadline and reserves nothing", () => {
    const dir = spoolDir();
    const spool = make(dir, { admitTimeoutMs: 30 });
    const dirHandle = addon.openDir(dir);
    const other = addon.openFile(dirHandle, ADMIT_LOCK, false);
    expect(addon.flock(other, FLOCK_EXCLUSIVE)).toBe(0);
    try {
      expect(spool.write(exchange.doc, exchange.bodies)).toBeNull();
      expect(spool.admissionTimeouts).toBe(1);
      expect(spool.bytes).toBe(0);
      expect(
        files(dir).filter((name) => name.endsWith(".rec") || name.startsWith(TMP_PREFIX)),
      ).toEqual([]);
    } finally {
      addon.flock(other, FLOCK_UNLOCK);
      addon.close(other);
      addon.close(dirHandle);
    }
    expect(spool.write(exchange.doc, exchange.bodies)).not.toBeNull();
  });
});

describe("drain lock and recovery", () => {
  it("one drainer at a time; a probe never takes the lock", () => {
    const dir = spoolDir();
    const a = make(dir);
    const b = make(dir);
    expect(a.tryLock()).toBe(true);
    expect(b.drainedElsewhere()).toBe(true);
    expect(b.tryLock()).toBe(false);
    expect(() => b.recover()).toThrow(/drain lock holder/);
    a.release();
    expect(b.drainedElsewhere()).toBe(false);
    expect(b.tryLock()).toBe(true);
    expect(a.drainedElsewhere()).toBe(true);
  });

  it("quarantines corrupt, renamed, plaintext-under-key and symlinked records; keeps unknown-key records pending", () => {
    const dir = spoolDir();
    const writer = make(dir, { key: KEY });
    const good = writer.write(exchange.doc, exchange.bodies)!;
    const flipped = writer.write(record.doc, record.bodies)!;
    const renamedFrom = writer.write(loss.doc, [], true)!;
    const bytes = readFileSync(join(dir, flipped));
    bytes[bytes.length - 3]! ^= 1;
    writeFileSync(join(dir, flipped), bytes);
    const renamed = renamedFrom.replace(/-(\d{12})\.rec$/, "-999999999999.rec");
    renameSync(join(dir, renamedFrom), join(dir, renamed));
    const plain = make(dir).write(seal.doc, [], true)!; // written without the key
    const foreign = make(dir, { key: OTHER_KEY }).write(exchange.doc, exchange.bodies)!;
    symlinkSync(join(dir, good), join(dir, "00000000000000000000-0000000001-000000000000.rec"));

    const drainer = make(dir, { key: KEY });
    expect(drainer.tryLock()).toBe(true);
    const scan = drainer.recover();
    expect(scan.files.map((file) => file.name)).toEqual([good]);
    expect(scan.undecryptable).toEqual([foreign]);
    const quarantined = scan.quarantined.map((entry) => entry.name).sort();
    expect(quarantined).toEqual(
      [flipped, renamed, plain, "00000000000000000000-0000000001-000000000000.rec"].sort(),
    );
    // The plaintext record's header parsed: its sequence is an explained loss.
    expect(scan.quarantined.find((entry) => entry.name === plain)!.docs).toHaveLength(1);
    for (const name of quarantined)
      expect(existsSync(join(dir, name + QUARANTINE_SUFFIX))).toBe(true);
    expect(existsSync(join(dir, foreign))).toBe(true);
    // Quarantined and unknown-key files stay charged against the bound.
    expect(drainer.bytes).toBe(drainer.diskTotal());
    expect(drainer.charge(foreign)).toBeGreaterThan(0);
    expect(drainer.charge(flipped + QUARANTINE_SUFFIX)).toBeGreaterThan(0);
    // A second scan is stable: same order, nothing re-quarantined.
    const again = drainer.recover();
    expect(again.files.map((file) => file.name)).toEqual([good]);
    expect(again.quarantined).toEqual([]);
    expect(again.undecryptable).toEqual([foreign]);
  });

  it("an own quarantined record is a failure; an own delivered record retires", () => {
    const dir = spoolDir();
    const spool = make(dir);
    const kept = spool.write(exchange.doc, exchange.bodies)!;
    const bad = spool.write(record.doc, record.bodies)!;
    writeFileSync(join(dir, bad), Buffer.from("garbage"));
    spool.tryLock();
    const scan = spool.recover();
    expect(spool.failed).toBe(1);
    expect(scan.files.map((file) => file.name)).toEqual([kept]);
    spool.retireOwn(kept);
    expect(existsSync(join(dir, kept))).toBe(false);
    expect(spool.mine.size).toBe(0);
    expect(spool.bytes).toBe(spool.diskTotal());
    expect(() => spool.retireOwn("someone-else.rec")).toThrow(/receipt/);
  });

  it("the drainer sweeps temps of writers that exited an hour ago; a fresh temp stays counted", () => {
    const dir = spoolDir();
    make(dir);
    const old = join(dir, `${TMP_PREFIX}old.rec`);
    const fresh = join(dir, `${TMP_PREFIX}fresh.rec`);
    writeFileSync(old, Buffer.alloc(100), { mode: 0o600 });
    writeFileSync(fresh, Buffer.alloc(100), { mode: 0o600 });
    const past = new Date(Date.now() - 2 * 3600 * 1000);
    utimesSync(old, past, past);
    const writer = make(dir);
    expect(writer.bytes).toBe(200); // a writer never sweeps
    const drainer = make(dir);
    drainer.tryLock();
    drainer.rescan();
    expect(existsSync(old)).toBe(false);
    expect(existsSync(fresh)).toBe(true);
    expect(drainer.bytes).toBe(100);
  });
});

describe("bounded reads", () => {
  it("a record larger than this spool's bound plus reserve stays pending and charged, never quarantined", () => {
    const dir = spoolDir();
    const big = sized(64 * 1024);
    const name = make(dir, { maxBytes: 1 << 22 }).write(big.doc, big.bodies)!;
    const small = make(dir, { maxBytes: 1024 });
    // 64 KiB fits under 1 KiB + the 1 MiB reserve: read normally.
    small.tryLock();
    expect(small.recover().files.map((file) => file.name)).toEqual([name]);
    const huge = sized(RESERVE_BYTES + 4096);
    const second = make(dir, { maxBytes: 1 << 22 }).write(huge.doc, huge.bodies)!;
    const scan = small.recover();
    expect(scan.files.map((file) => file.name)).toEqual([name]);
    expect(scan.deferred).toEqual([second]);
    expect(scan.quarantined).toEqual([]);
    expect(existsSync(join(dir, second))).toBe(true);
    expect(small.charge(second)).toBeGreaterThan(RESERVE_BYTES);
  });
});

describe("configuration errors name the cause and the fix", () => {
  it("refuses a directory holding foreign files, a symlink, a bad bound and a short key", () => {
    const dir = spoolDir();
    mkdirSync(dir, 0o700);
    writeFileSync(join(dir, "notes.txt"), "x");
    expect(() => make(dir)).toThrow(SpoolConfigError);
    expect(() => make(dir)).toThrow(
      /does not own.*fix: give the wire spool its own empty directory/,
    );
    const link = `${dir}-link`;
    const target = spoolDir();
    mkdirSync(target, 0o700);
    symlinkSync(target, link);
    expect(() => make(link)).toThrow(/real directory.*fix:/);
    expect(() => make(spoolDir(), { maxBytes: 0 })).toThrow(/FABRIC_WIRE_SPOOL_MAX_BYTES/);
    expect(() => make(spoolDir(), { key: Buffer.alloc(16) })).toThrow(/32 bytes/);
  });

  const root = process.getuid?.() === 0; // root ignores the permission bits these tests use

  it.skipIf(root)("a failed file-system call names its code and fix, never the spool path", () => {
    const dir = spoolDir();
    const spool = make(dir);
    chmodSync(dir, 0o500); // the agent's user can no longer create files in it
    let error: unknown;
    try {
      spool.write(exchange.doc, exchange.bodies);
    } catch (caught) {
      error = caught;
    } finally {
      chmodSync(dir, 0o700);
    }
    expect(error).toBeInstanceOf(SpoolIoError);
    const { message, code } = error as SpoolIoError;
    expect(code).toBe("EACCES");
    expect(message).toMatch(/^wire spool open failed \(EACCES\); fix: .*FABRIC_WIRE_SPOOL_DIR/);
    expect(message).not.toContain(dir);
    expect(message).not.toContain(".rec");
    expect(diskFull(error)).toBe(false);
    expect(spool.bytes).toBe(spool.diskTotal());
    expect(spool.write(exchange.doc, exchange.bodies)).not.toBeNull();
  });

  it.skipIf(root)("a spool directory that cannot be created names the cause, not the path", () => {
    const parent = spoolDir();
    mkdirSync(parent, 0o700);
    chmodSync(parent, 0o500);
    try {
      const dir = join(parent, "spool");
      expect(() => make(dir)).toThrow(SpoolIoError);
      expect(() => make(dir)).toThrow(/^wire spool mkdir failed \(EACCES\); fix: /);
      try {
        make(dir);
      } catch (error) {
        expect((error as Error).message).not.toContain(parent);
      }
    } finally {
      chmodSync(parent, 0o700);
    }
  });

  it("a failed native call names its code and fix", () => {
    const error = new NativeSpoolError("openDir", NativeCode.UNSAFE_PATH);
    expect(error.message).toBe(
      "wire spool openDir failed (UNSAFE_PATH); fix: point FABRIC_WIRE_SPOOL_DIR at a real " +
        "directory owned by the agent's user, with no symlink in the spool",
    );
    const full = new NativeSpoolError("fsync", NativeCode.NO_SPACE);
    expect(diskFull(full)).toBe(true);
    expect(full.message).toMatch(/\(NO_SPACE\); fix: free space/);
    expect(new NativeSpoolError("openFile", NativeCode.LIMIT).message).toMatch(/handles/);
  });

  it("creates missing parents owner-only and tightens a loose directory", () => {
    const dir = join(spoolDir(), "a", "b");
    make(dir);
    expect(lstatSync(dir).mode & 0o777).toBe(0o700);
    const loose = spoolDir();
    mkdirSync(loose, 0o755);
    chmodSync(loose, 0o755);
    make(loose);
    expect(lstatSync(loose).mode & 0o777).toBe(0o700);
  });
});

// ---------------------------------------------------------------------- fault injection

type Op = keyof SpoolIo;
const FAULT_OPS: readonly Op[] = [
  "openExclusive",
  "write",
  "writev",
  "fsync",
  "rename",
  "syncDir",
  "unlink",
];

/** A {@link SpoolIo} that records calls and fails the `nth` call of `op` (0-based). */
function faulty(base: SpoolIo): {
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

describe("a fault at every write, fsync and rename", () => {
  /** The commit's calls of each fault op, from one clean write. */
  function stepsOfOneWrite(key?: Buffer): [Op, number][] {
    const dir = spoolDir();
    const harness = faulty(nodeSpoolIo(addon));
    const spool = make(dir, { io: harness.io, ...(key === undefined ? {} : { key }) });
    harness.calls.length = 0;
    spool.write(exchange.doc, exchange.bodies);
    const steps: [Op, number][] = [];
    const counts = new Map<Op, number>();
    for (const op of harness.calls) {
      const n = counts.get(op) ?? 0;
      counts.set(op, n + 1);
      if (FAULT_OPS.includes(op)) steps.push([op, n]);
    }
    return steps;
  }

  const steps = (): [Op, number][] => stepsOfOneWrite(KEY);

  it("the commit is exclusive temp -> reserve -> write -> fsync -> rename -> directory fsync", () => {
    expect(steps().map(([op]) => op)).toEqual([
      "openExclusive",
      "write",
      "writev",
      "fsync",
      "rename",
      "syncDir",
    ]);
  });

  for (const code of ["EIO", "ENOSPC"]) {
    it(`${code}: the write fails cleanly, the ledger equals the disk, the next write succeeds`, () => {
      for (const [op, nth] of steps()) {
        const dir = spoolDir();
        const harness = faulty(nodeSpoolIo(addon));
        const spool = make(dir, { io: harness.io, key: KEY });
        harness.arm(op, nth, code);
        let error: unknown;
        try {
          spool.write(exchange.doc, exchange.bodies);
        } catch (caught) {
          error = caught;
        }
        expect(error, `${op}#${nth}`).toBeInstanceOf(Error);
        expect(diskFull(error)).toBe(code === "ENOSPC");
        expect(spool.bytes, `${op}#${nth}`).toBe(spool.diskTotal());
        expect(
          files(dir).filter((name) => name.startsWith(TMP_PREFIX)),
          `${op}#${nth}`,
        ).toEqual([]);
        expect(spool.mine.size).toBe(0); // never counted as written
        const pending = spool.names();
        // Only a failed directory fsync can leave the renamed record (delivered at least once).
        expect(pending.length, `${op}#${nth}`).toBe(op === "syncDir" ? 1 : 0);
        expect(spool.write(exchange.doc, exchange.bodies), `${op}#${nth}`).not.toBeNull();
        spool.tryLock();
        const scan = spool.recover();
        expect(scan.quarantined, `${op}#${nth}`).toEqual([]);
        expect(scan.files.length).toBe(pending.length + 1);
      }
    });
  }

  it("a failed write whose temp file cannot be removed stays charged as the temp", () => {
    for (const [op, nth] of steps().filter(([o]) => o !== "openExclusive" && o !== "syncDir")) {
      const dir = spoolDir();
      const harness = faulty(nodeSpoolIo(addon));
      const spool = make(dir, { io: harness.io });
      harness.arm(op, nth);
      const base = harness.io.unlink;
      (harness.io as { unlink: SpoolIo["unlink"] }).unlink = (path) => {
        if (path.includes(TMP_PREFIX)) throw Object.assign(new Error("injected"), { code: "EIO" });
        base(path);
      };
      expect(() => spool.write(exchange.doc, exchange.bodies)).toThrow();
      const temps = files(dir).filter((name) => name.startsWith(TMP_PREFIX));
      if (op === "rename") expect(temps).toHaveLength(1);
      expect(spool.bytes, `${op}#${nth}`).toBe(spool.diskTotal());
      expect(spool.diskTotal()).toBeLessThanOrEqual(spool.maxBytes);
    }
  });

  it("a fault in quarantine keeps the record charged and retried", () => {
    const dir = spoolDir();
    const harness = faulty(nodeSpoolIo(addon));
    const spool = make(dir, { io: harness.io });
    const name = spool.write(record.doc, record.bodies)!;
    writeFileSync(join(dir, name), Buffer.from("garbage"));
    spool.tryLock();
    harness.arm("rename", 0);
    const first = spool.recover();
    expect(first.deferred).toEqual([name]);
    expect(spool.bytes).toBe(spool.diskTotal());
    harness.arm("syncDir", 0);
    const second = spool.recover();
    expect(second.deferred).toEqual([name]); // renamed, but the directory fsync failed
    expect(existsSync(join(dir, name + QUARANTINE_SUFFIX))).toBe(true);
    expect(spool.bytes).toBe(spool.diskTotal());
    expect(spool.recover().quarantined).toEqual([]);
  });
});

// ------------------------------------------------------------------------ property test

/** A small deterministic PRNG (mulberry32). */
function prng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe("property: disk accounting within bound + reserve after every operation", () => {
  for (const seed of [1, 2, 3, 4, 5]) {
    it(`seed ${seed}`, () => {
      const random = prng(seed);
      const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)]!;
      const dir = spoolDir();
      const harness = faulty(nodeSpoolIo(addon));
      const maxBytes = 30_000;
      const key = seed % 2 === 0 ? KEY : undefined;
      const spool = make(dir, { io: harness.io, maxBytes, ...(key === undefined ? {} : { key }) });
      const other = make(dir, { maxBytes, ...(key === undefined ? {} : { key }) });
      spool.tryLock();
      const log: string[] = [];
      let dirty = false;
      for (let step = 0; step < 300; step += 1) {
        const roll = random();
        let op: string;
        try {
          if (roll < 0.35) {
            op = "write";
            const entry = sized(Math.floor(random() * 3000));
            spool.write(entry.doc, entry.bodies);
          } else if (roll < 0.45) {
            op = "batch";
            spool.writeBatch(
              Array.from({ length: 1 + Math.floor(random() * 4) }, () =>
                sized(Math.floor(random() * 1500)),
              ),
            );
          } else if (roll < 0.5) {
            op = "reserve";
            spool.write(pick([loss, seal]).doc, [], true);
          } else if (roll < 0.58) {
            op = "other-writer";
            const entry = sized(Math.floor(random() * 2000));
            other.write(entry.doc, entry.bodies);
          } else if (roll < 0.68) {
            op = "fault-write";
            harness.arm(
              pick(FAULT_OPS.filter((o) => o !== "unlink")),
              random() < 0.5 ? 0 : 1,
              pick(["EIO", "ENOSPC"]),
            );
            const entry = sized(Math.floor(random() * 2000));
            spool.write(entry.doc, entry.bodies);
          } else if (roll < 0.76) {
            op = "corrupt+recover";
            const names = spool.names();
            if (names.length > 0) {
              const victim = join(dir, pick(names));
              const bytes = readFileSync(victim);
              bytes[Math.floor(random() * bytes.length)]! ^= 0xff;
              writeFileSync(victim, bytes);
            }
            spool.recover();
          } else if (roll < 0.88) {
            op = "retire";
            const own = [...spool.mine].filter((name) => existsSync(join(dir, name)));
            if (own.length > 0) spool.retireOwn(pick(own));
          } else if (roll < 0.94) {
            op = "rescan";
            spool.rescan();
          } else {
            op = "operator-clears-quarantine";
            for (const name of files(dir).filter((n) => n.endsWith(QUARANTINE_SUFFIX))) {
              harness.io.unlink(join(dir, name));
            }
            spool.rescan();
          }
        } catch (error) {
          op = `threw ${(error as Error).message}`;
        } finally {
          harness.disarm();
        }
        log.push(op);
        const disk = spool.diskTotal();
        expect(disk, log.slice(-5).join(" | ")).toBeLessThanOrEqual(maxBytes + RESERVE_BYTES);
        other.rescan();
        expect(other.bytes, `other at step ${step}`).toBe(disk);
        if (op === "other-writer") dirty = true;
        if (["corrupt+recover", "rescan", "operator-clears-quarantine"].includes(op)) dirty = false;
        // The own ledger equals the disk exactly, unless another writer wrote since it last
        // rescanned (it never sees that write until a rescan): then it is below, never above.
        if (dirty) expect(spool.bytes).toBeLessThanOrEqual(disk);
        else expect(spool.bytes, `${log.slice(-3).join(" | ")} at step ${step}`).toBe(disk);
      }
    });
  }
});
