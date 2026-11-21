// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §6.3, §9.5 row `055-t16`: `disk_full` (ENOSPC, EDQUOT) versus `queue_full`
// (the shared bound or a busy admission lock) at admission; batch files (`FWSPOOLB`, D4)
// that Python reads; records sealed under an unknown key retained for their key holder;
// and the explicit local-profile plaintext migration.
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { LedgerError } from "../../../src/wire/ledger.js";
import { LossTable } from "../../../src/wire/loss.js";
import { FLOCK_EXCLUSIVE, NativeCode } from "../../../src/wire/native.js";
import { Sender } from "../../../src/wire/sender.js";
import { BATCH_MAGIC, ENVELOPE_MAGIC, MAGIC, unframeAll } from "../../../src/wire/spool-codec.js";
import {
  ADMIT_LOCK,
  QUARANTINE_SUFFIX,
  Spool,
  type SpoolOptions,
  WRITE_BATCH,
  diskFull,
  nodeSpoolIo,
} from "../../../src/wire/spool.js";
import { admitEntries } from "../../../src/wire/writer.js";

import { norm } from "../helpers.js";
import {
  KEY,
  OTHER_KEY,
  type Native,
  cleanupDirs,
  entryOf,
  native,
  runPython,
  sized,
  spoolDir,
} from "../spool/helpers.js";

let lib: Native;
beforeAll(() => {
  lib = native();
}, 120_000);
afterAll(() => lib?.build.cleanup());

const opened: Spool[] = [];
afterEach(() => {
  for (const spool of opened.splice(0)) spool.close();
  cleanupDirs();
});

let nextPid = 98_000;
function make(dir: string, options: Partial<SpoolOptions> = {}): Spool {
  nextPid += 1;
  const spool = new Spool(dir, { maxBytes: 1 << 20, addon: lib.addon, pid: nextPid, ...options });
  opened.push(spool);
  return spool;
}

const exchange = entryOf("exchange");
const recordEntry = entryOf("record");
const failing = (code: string) => (): never => {
  throw Object.assign(new Error(`injected ${code}`), { code });
};

const PY_READ = `
import json, sys
from fabric.wire._spool import Spool, UndecryptableRecordError, unframe_all
key = None if sys.argv[2] == "-" else bytes.fromhex(sys.argv[2])
spool = Spool(sys.argv[1], 1 << 20, key=key)
try:
    files = []
    for name in spool.names():
        try:
            files.append({"name": name, "docs": [doc for doc, _ in unframe_all(spool.read(name))]})
        except UndecryptableRecordError:
            files.append({"name": name, "error": "undecryptable"})
        except ValueError as error:  # corrupt, or plaintext under a key
            files.append({"name": name, "error": type(error).__name__})
    print(json.dumps({"files": files}))
finally:
    spool.release()
`;

describe("disk_full versus queue_full", () => {
  for (const [code, expected] of [
    ["ENOSPC", "disk_full"],
    ["EDQUOT", "disk_full"],
    ["EIO", "internal_error"],
  ] as const) {
    it(`${code} at a record write is ${expected}, for a single entry and a batch file`, () => {
      const io = nodeSpoolIo(lib.addon);
      const spool = make(spoolDir(), {
        io: { ...io, writev: failing(code), write: failing(code) },
      });
      expect(admitEntries(spool, [exchange])).toEqual([expected]);
      expect(admitEntries(spool, [exchange, recordEntry])).toEqual([expected, expected]);
      expect(spool.names()).toEqual([]);
      expect(spool.bytes).toBe(spool.diskTotal());
    });
  }

  it("ENOSPC at the temp file's creation or its fsync is disk_full too", () => {
    for (const op of ["openExclusive", "fsync"] as const) {
      const io = nodeSpoolIo(lib.addon);
      const spool = make(spoolDir(), { io: { ...io, [op]: failing("ENOSPC") } });
      expect(admitEntries(spool, [exchange]), op).toEqual(["disk_full"]);
    }
  });

  it("over the shared bound, or with the admission lock held, is queue_full", () => {
    const big = sized(4000);
    const small = make(spoolDir(), { maxBytes: 1000 });
    expect(admitEntries(small, [big])).toEqual(["queue_full"]);
    const dir = spoolDir();
    const spool = make(dir, { admitTimeoutMs: 20 });
    const handle = lib.addon.openFile(lib.addon.openDir(dir), ADMIT_LOCK, true);
    const other = lib.addon; // another writer's lock: a separate open file description
    expect(other.flock(handle, FLOCK_EXCLUSIVE)).toBe(NativeCode.OK);
    try {
      expect(admitEntries(spool, [exchange])).toEqual(["queue_full"]);
    } finally {
      other.close(handle);
    }
    expect(admitEntries(spool, [exchange])).toEqual(["spooled"]);
  });

  it("the ledger's own I/O errors tell a full volume apart", () => {
    expect(diskFull(new LedgerError("pwrite", NativeCode.NO_SPACE))).toBe(true);
    expect(diskFull(new LedgerError("pwrite", NativeCode.QUOTA))).toBe(true);
    expect(diskFull(new LedgerError("pwrite", NativeCode.IO))).toBe(false);
    expect(new LedgerError("allocate", NativeCode.NO_SPACE).message).toMatch(
      /allocate failed \(NO_SPACE\); fix: check the local volume holding FABRIC_WIRE_SPOOL_DIR/,
    );
  });

  it("a loss of a full disk keeps its reason in the spool and on the span", () => {
    const table = new LossTable();
    table.record("s-" + "cd".repeat(16), 3n, "disk_full", 5n);
    const spool = make(spoolDir());
    expect(table.pump(spool)).toBe(true);
    const [name] = spool.names();
    const [{ doc }] = unframeAll(spool.read(name!)) as any;
    expect(doc.loss.reason).toBe("disk_full");
  });
});

describe("batch files (FWSPOOLB, D4)", { timeout: 60_000 }, () => {
  it("a group is one file, one fsync and one rename; Python reads every record of it", () => {
    for (const key of [undefined, KEY]) {
      const dir = spoolDir();
      const spool = make(dir, key === undefined ? {} : { key });
      const outcomes = spool.writeGroup([exchange, recordEntry]);
      expect(outcomes[0]).toBe(outcomes[1]);
      expect(spool.names()).toEqual([outcomes[0]]);
      const raw = readFileSync(join(dir, outcomes[0] as string));
      expect(raw.subarray(0, 8).equals(key === undefined ? BATCH_MAGIC : ENVELOPE_MAGIC)).toBe(
        true,
      );
      const python = runPython(PY_READ, [dir, key === undefined ? "-" : KEY.toString("hex")]);
      expect(python.files).toHaveLength(1);
      expect(python.files[0].docs.map((d: any) => d.record_kind)).toEqual(["exchange", "record"]);
      expect(norm(python.files[0].docs)).toEqual(
        norm(unframeAll(spool.read(outcomes[0] as string)).map((r) => r.doc)),
      );
    }
  });

  it("a group over the bound as one file is written one record per file, as many as fit", () => {
    const one = sized(3000);
    const size = (() => {
      const probe = make(spoolDir());
      const name = probe.write(one.doc, one.bodies)!;
      return readFileSync(join(probe.dir, name)).length;
    })();
    const spool = make(spoolDir(), { maxBytes: size + 100 });
    const outcomes = spool.writeGroup([one, one]);
    expect(typeof outcomes[0]).toBe("string");
    expect(outcomes[1]).toBeNull();
    expect(
      readFileSync(join(spool.dir, outcomes[0] as string))
        .subarray(0, 8)
        .equals(MAGIC),
    ).toBe(true);
  });

  it("loss records go to batch files of at most 64, in order, in the reserve", () => {
    const table = new LossTable();
    for (let i = 0; i < WRITE_BATCH + 6; i++) {
      // a source each: ranges of one source would merge
      table.record("s-" + (i + 1).toString(16).padStart(32, "c"), 3n, "queue_full", BigInt(i + 1));
    }
    const spool = make(spoolDir(), { maxBytes: 1 });
    expect(table.pump(spool)).toBe(true);
    const files = spool.names();
    expect(files).toHaveLength(2);
    const counts = files.map((name) => unframeAll(spool.read(name)).length);
    expect(counts).toEqual([WRITE_BATCH, 6]);
    const firsts = files.flatMap((name) =>
      unframeAll(spool.read(name)).map((r) => Number((r.doc as any).loss.first_sequence)),
    );
    expect(firsts).toEqual([...firsts].sort((a, b) => a - b));
  });
});

describe("unknown-key retention", () => {
  it("a record sealed under another key is never read, quarantined or retired: it waits, charged, for its key holder", async () => {
    const dir = spoolDir();
    const foreign = make(dir, { key: OTHER_KEY });
    const name = foreign.write(exchange.doc, exchange.bodies)!;
    const spool = make(dir, { key: KEY });
    expect(spool.tryLock()).toBe(true);
    const warned: string[] = [];
    const sender = new Sender({
      spool,
      content: undefined,
      serviceName: "svc",
      traces: { export: async () => ({ outcome: "ok", status: 200 }) },
      warn: (text) => warned.push(text),
    });
    let state = await sender.drain();
    for (let pass = 0; pass < 5 && state !== "idle"; pass++) state = await sender.drain();
    expect(state).toBe("idle");
    expect(readdirSync(dir)).toContain(name);
    expect(readdirSync(dir).some((n) => n.endsWith(QUARANTINE_SUFFIX))).toBe(false);
    expect(sender.stats().spool_undecryptable).toBe(1);
    expect(warned).toEqual([
      "fabric.wire: a spool record sealed under another key was left for its key holder",
    ]);
    spool.rescan();
    expect(spool.bytes).toBe(spool.diskTotal());
    expect(spool.bytes).toBeGreaterThan(0);
  });
});

describe("the plaintext migration (local profile, explicit)", () => {
  it("seals intact plaintext records in place under the key; a damaged one is left for quarantine", () => {
    const dir = spoolDir();
    const plain = make(dir);
    const name = plain.write(exchange.doc, exchange.bodies)!;
    const before = readFileSync(join(dir, name));
    const damaged = plain.write(recordEntry.doc, recordEntry.bodies)!;
    const bytes = readFileSync(join(dir, damaged));
    bytes[bytes.length - 1]! ^= 0xff;
    writeFileSync(join(dir, damaged), bytes);
    plain.close();
    const keyed = make(dir, { key: KEY, migratePlaintext: true });
    expect(keyed.migrate).toBe(true);
    expect(keyed.plaintextRecords()).toBe(2);
    expect(keyed.tryLock()).toBe(true);
    expect(keyed.migratePlaintext()).toBe(1);
    const after = readFileSync(join(dir, name));
    expect(after.subarray(0, 8).equals(ENVELOPE_MAGIC)).toBe(true);
    expect(after.includes(before.subarray(12, 40))).toBe(false); // no plaintext header left
    expect(keyed.read(name).equals(before)).toBe(true);
    expect(keyed.plaintextRecords()).toBe(1); // the damaged one, for quarantine
    expect(keyed.bytes).toBe(keyed.diskTotal());
    const python = runPython(PY_READ, [dir, KEY.toString("hex")]);
    expect(python.files.find((f: any) => f.name === name).docs[0].record_kind).toBe("exchange");
  });

  it("the drainer runs it once, before it reads any record, and counts it", async () => {
    const dir = spoolDir();
    const plain = make(dir);
    const name = plain.write(exchange.doc, exchange.bodies)!;
    plain.close();
    const keyed = make(dir, { key: KEY, migratePlaintext: true });
    expect(keyed.tryLock()).toBe(true);
    const sender = new Sender({
      spool: keyed,
      content: undefined,
      serviceName: "svc",
      traces: { export: async () => ({ outcome: "ok", status: 200 }) },
    });
    await sender.drain();
    expect(sender.stats().spool_migrated).toBe(1);
    expect(keyed.migrate).toBe(false);
    // Whatever the drain did with the record, no plaintext of it is left at rest.
    for (const file of readdirSync(dir).filter((n) => n.startsWith(name))) {
      const bytes = readFileSync(join(dir, file)); // pending (sealed) or an empty receipt
      if (bytes.length > 0) expect(bytes.subarray(0, 8).equals(ENVELOPE_MAGIC), file).toBe(true);
    }
    expect(keyed.plaintextRecords()).toBe(0);
    await sender.drain();
    expect(sender.stats().spool_migrated).toBe(1); // once
  });

  it("an I/O error stops the migration before any read; the next drain retries it", async () => {
    const dir = spoolDir();
    const plain = make(dir);
    plain.write(exchange.doc, exchange.bodies);
    plain.close();
    let fail = true;
    const base = nodeSpoolIo(lib.addon);
    const keyed = make(dir, {
      key: KEY,
      migratePlaintext: true,
      io: {
        ...base,
        openExclusive: (path) => {
          if (fail) throw Object.assign(new Error("injected EIO"), { code: "EIO" });
          return base.openExclusive(path);
        },
      },
    });
    expect(keyed.tryLock()).toBe(true);
    const exported: unknown[] = [];
    const sender = new Sender({
      spool: keyed,
      content: undefined,
      serviceName: "svc",
      traces: {
        export: async (spans) => {
          exported.push(...spans);
          return { outcome: "ok", status: 200 };
        },
      },
    });
    await expect(sender.drain()).rejects.toThrow(/EIO/);
    expect(keyed.migrate).toBe(true);
    expect(exported).toEqual([]); // nothing read, nothing delivered
    expect(keyed.plaintextRecords()).toBe(1);
    fail = false;
    await sender.drain();
    expect(keyed.migrate).toBe(false);
    expect(sender.stats().spool_migrated).toBe(1);
  });

  it("is off unless asked for, and needs a key", () => {
    const dir = spoolDir();
    make(dir).write(exchange.doc, exchange.bodies);
    expect(make(dir, { key: KEY }).migrate).toBe(false);
    expect(make(dir, { migratePlaintext: true }).migrate).toBe(false);
    expect(make(dir, { migratePlaintext: true }).migratePlaintext()).toBe(0);
  });
});
