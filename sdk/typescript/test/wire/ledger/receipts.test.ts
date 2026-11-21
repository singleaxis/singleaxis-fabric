// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §6.3, §9.5 row `055-t16`: `.ack` delivery receipts for other writers (at
// least 128 bytes each, at most 4,096 and an eighth of the bound, expired after the
// Python 3,600 s TTL), an expired or missing receipt never turning a writer's flush into
// success, and conservative accounting under a fault at every receipt create (rename),
// truncate, directory fsync and unlink, including while another process rescans.
import { lstatSync, readdirSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { Sender } from "../../../src/wire/sender.js";
import {
  ACK_SUFFIX,
  DEFAULT_MAX_RECEIPTS,
  RECEIPT_OVERHEAD,
  STALE_MS,
  Spool,
  type SpoolOptions,
  nodeSpoolIo,
} from "../../../src/wire/spool.js";

import {
  type Native,
  type Op,
  cleanupDirs,
  entryOf,
  faulty,
  native,
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

let nextPid = 95_000;
function make(dir: string, options: Partial<SpoolOptions> = {}): Spool {
  nextPid += 1;
  const spool = new Spool(dir, {
    maxBytes: 1 << 20,
    addon: lib.addon,
    pid: nextPid,
    ledger: false,
    ...options,
  });
  opened.push(spool);
  return spool;
}

const exchange = entryOf("exchange");
const acks = (dir: string): string[] =>
  readdirSync(dir)
    .filter((n) => n.endsWith(ACK_SUFFIX))
    .sort();

/** A writer with `n` records and the drainer (holding the lock) of the same directory. */
function pair(
  n: number,
  drainer: Partial<SpoolOptions> = {},
  writerOptions: Partial<SpoolOptions> = {},
) {
  const dir = spoolDir();
  const writer = make(dir, writerOptions);
  const names = Array.from({ length: n }, () => writer.write(exchange.doc, exchange.bodies)!);
  const drain = make(dir, drainer);
  expect(drain.tryLock()).toBe(true);
  return { dir, writer, drain, names };
}

function sender(spool: Spool): Sender {
  return new Sender({
    spool,
    content: undefined,
    serviceName: "svc",
    traces: { export: async () => ({ outcome: "ok", status: 200 }) },
  });
}

describe("receipts for other writers", () => {
  it("a delivered record of another writer becomes its empty receipt, charged 128 bytes, consumed by its writer", () => {
    const { dir, writer, drain, names } = pair(1);
    const size = lstatSync(join(dir, names[0]!)).size;
    expect(drain.retireMany(names)).toEqual({ retired: 1, error: undefined });
    expect(acks(dir)).toEqual([names[0] + ACK_SUFFIX]);
    expect(lstatSync(join(dir, names[0] + ACK_SUFFIX)).size).toBe(0);
    expect(drain.receipts).toBe(1);
    expect(drain.bytes).toBe(RECEIPT_OVERHEAD);
    expect(drain.bytes).toBe(drain.diskTotal());
    expect(RECEIPT_OVERHEAD).toBeLessThan(size); // a receipt never grows the total
    expect(writer.settle()).toBe(0);
    expect(writer.failed).toBe(0);
    expect(acks(dir)).toEqual([]);
  });

  it("at most 4,096 receipts, and never more than an eighth of the bound", () => {
    expect(DEFAULT_MAX_RECEIPTS).toBe(4096);
    expect(make(spoolDir()).maxReceipts).toBe(1024); // 1 MiB / (8 x 128)
    expect(make(spoolDir(), { maxBytes: 1 << 30 }).maxReceipts).toBe(4096);
    expect(make(spoolDir(), { maxBytes: 4096 }).maxReceipts).toBe(4);
    expect(make(spoolDir(), { maxBytes: 100 }).maxReceipts).toBe(1);
    expect(make(spoolDir(), { maxReceipts: 7 }).maxReceipts).toBe(7);
  });

  it("the oldest receipts over the cap expire; their writer counts those records failed", () => {
    const { dir, writer, drain, names } = pair(5, { maxReceipts: 2 });
    names.forEach((name, i) => {
      expect(drain.retireMany([name]).retired).toBe(1);
      // distinct ages, oldest first
      const at = new Date(Date.now() - (names.length - i) * 1000);
      utimesSync(join(dir, name + ACK_SUFFIX), at, at);
    });
    drain.rescan();
    expect(acks(dir)).toEqual(names.slice(3).map((n) => n + ACK_SUFFIX));
    expect(drain.receipts).toBe(2);
    expect(drain.bytes).toBe(drain.diskTotal());
    expect(writer.settle()).toBe(0);
    expect(writer.failed).toBe(3);
  });

  it("the drainer removes receipts older than the TTL (3,600 s); the writer counts them failed", () => {
    expect(STALE_MS).toBe(3600 * 1000);
    let clock = Date.now();
    const { dir, writer, drain, names } = pair(2, { now: () => clock });
    expect(drain.retireMany(names).retired).toBe(2);
    clock += STALE_MS - 60_000;
    drain.rescan();
    expect(acks(dir)).toHaveLength(2); // not yet expired
    const old = new Date(Date.now() - STALE_MS - 1000);
    utimesSync(join(dir, names[0] + ACK_SUFFIX), old, old);
    clock = Date.now();
    drain.rescan();
    expect(acks(dir)).toEqual([names[1] + ACK_SUFFIX]);
    expect(writer.settle()).toBe(0);
    expect(writer.failed).toBe(1);
  });

  it("an expired or missing receipt never turns the writer's flush into success", async () => {
    const { dir, writer, drain, names } = pair(1);
    const flusher = sender(writer);
    expect(drain.retireMany(names).retired).toBe(1);
    // The receipt is gone (expired, removed by anyone): delivery is not provable.
    const io = nodeSpoolIo(lib.addon);
    io.unlink(join(dir, names[0] + ACK_SUFFIX));
    expect(await flusher.flush(performance.now() + 2000)).toBe(false);
    expect(writer.failed).toBe(1);
    // A later record delivered with its receipt flushes again.
    const next = writer.write(exchange.doc, exchange.bodies)!;
    drain.rescan();
    expect(drain.retireMany([next]).retired).toBe(1);
    expect(await flusher.flush(performance.now() + 2000)).toBe(true);
  });

  it("a receipt that cannot be removed keeps the record pending, never failed", () => {
    const harness = faulty(nodeSpoolIo(lib.addon));
    const { writer, drain, names } = pair(1, {}, { io: harness.io });
    expect(drain.retireMany(names).retired).toBe(1);
    harness.arm("unlink", 0, "EIO");
    expect(writer.settle()).toBe(1);
    expect(writer.failed).toBe(0);
    expect(writer.settle()).toBe(0); // the next settle consumes it
    expect(writer.failed).toBe(0);
  });
});

describe("conservative accounting under a fault at every receipt step", () => {
  /** The receipt steps of one retirement of another writer's record, then one settle. */
  const STEPS: [Op, number][] = [
    ["rename", 0],
    ["truncate", 0],
    ["syncDir", 0],
  ];

  for (const code of ["EIO", "ENOSPC"]) {
    for (const [op, nth] of STEPS) {
      it(`${code} at ${op}: never below the disk, settled by a retry, never a false delivery`, () => {
        const dir = spoolDir();
        const writer = make(dir);
        const name = writer.write(exchange.doc, exchange.bodies)!;
        const harness = faulty(nodeSpoolIo(lib.addon));
        const drain = make(dir, { io: harness.io });
        expect(drain.tryLock()).toBe(true);
        harness.arm(op, nth, code);
        const result = drain.retireMany([name]);
        expect(result.error, op).toBeInstanceOf(Error);
        expect(result.retired).toBe(0);
        // Conservative: the drainer charges at least what is on disk.
        expect(drain.bytes, op).toBeGreaterThanOrEqual(drain.diskTotal());
        // Another process rescanning meanwhile counts the same bytes as the disk.
        writer.rescan();
        expect(writer.bytes, op).toBe(writer.diskTotal());
        // The writer never counts it failed while it, or its receipt, is on disk.
        writer.settle();
        expect(writer.failed, op).toBe(0);
        // The retry finishes the receipt (idempotent), and the writer consumes it.
        expect(drain.retireMany([name]), op).toEqual({ retired: 1, error: undefined });
        drain.rescan();
        // finished, or already consumed by its writer (the rename made it a delivery)
        for (const ack of acks(dir)) expect(lstatSync(join(dir, ack)).size, op).toBe(0);
        expect(drain.bytes).toBe(drain.diskTotal());
        expect(writer.settle()).toBe(0);
        expect(writer.failed, op).toBe(0);
        drain.rescan();
        expect(drain.bytes).toBe(0);
      });
    }

    it(`${code} at expiry's unlink: the receipt stays counted until removed`, () => {
      const dir = spoolDir();
      const writer = make(dir);
      const names = [0, 1, 2].map(() => writer.write(exchange.doc, exchange.bodies)!);
      const harness = faulty(nodeSpoolIo(lib.addon));
      const drain = make(dir, { io: harness.io, maxReceipts: 1 });
      expect(drain.tryLock()).toBe(true);
      expect(drain.retireMany([names[0]!]).retired).toBe(1);
      harness.arm("unlink", 0, code);
      expect(drain.retireMany([names[1]!]).retired).toBe(1); // the trim's unlink fails
      expect(acks(dir)).toHaveLength(2);
      expect(drain.receipts).toBe(2);
      expect(drain.bytes).toBe(drain.diskTotal());
      expect(drain.retireMany([names[2]!]).retired).toBe(1); // the next trim succeeds
      expect(acks(dir)).toEqual([names[2] + ACK_SUFFIX]);
      expect(drain.bytes).toBe(drain.diskTotal());
    });
  }

  for (const code of ["EIO", "EACCES"]) {
    it(`${code} at the TTL's unlink: the stale receipt stays counted, and the writer never counts it failed meanwhile`, () => {
      let clock = Date.now();
      const harness = faulty(nodeSpoolIo(lib.addon));
      const { dir, writer, drain, names } = pair(1, { io: harness.io, now: () => clock });
      expect(drain.retireMany(names).retired).toBe(1);
      clock += STALE_MS + 60_000;
      harness.arm("unlink", 0, code);
      drain.rescan();
      expect(acks(dir)).toEqual([names[0] + ACK_SUFFIX]); // still on disk, still counted
      expect(drain.receipts).toBe(1);
      expect(drain.bytes).toBe(RECEIPT_OVERHEAD);
      drain.rescan(); // the next rescan removes it
      expect(acks(dir)).toEqual([]);
      expect(drain.bytes).toBe(0);
      expect(writer.settle()).toBe(0);
      expect(writer.failed).toBe(1); // expired before its writer consumed it
    });
  }

  it("a ledger creation that died (a stale .ledger-new-*) is swept by the drainer only, once stale", () => {
    let clock = Date.now();
    const dir = spoolDir();
    const drain = make(dir, { now: () => clock });
    const leftover = join(dir, ".ledger-new-4242-deadbeef");
    writeFileSync(leftover, Buffer.alloc(4096), { mode: 0o600 });
    clock += STALE_MS + 60_000;
    drain.rescan();
    expect(readdirSync(dir)).toContain(".ledger-new-4242-deadbeef"); // not the drainer: kept
    clock = Date.now();
    expect(drain.tryLock()).toBe(true);
    drain.rescan();
    expect(readdirSync(dir)).toContain(".ledger-new-4242-deadbeef"); // not stale yet
    clock += STALE_MS + 60_000;
    drain.rescan();
    expect(readdirSync(dir)).not.toContain(".ledger-new-4242-deadbeef");
    expect(drain.bytes).toBe(0); // within the reserve, as Python's: never charged
  });

  it("a crash between rename and truncate: rescans count the full receipt; the drainer finishes it", () => {
    const dir = spoolDir();
    const writer = make(dir);
    const name = writer.write(exchange.doc, exchange.bodies)!;
    const size = lstatSync(join(dir, name)).size;
    const harness = faulty(nodeSpoolIo(lib.addon));
    const drain = make(dir, { io: harness.io });
    expect(drain.tryLock()).toBe(true);
    harness.arm("truncate", 0, "EIO");
    drain.retireMany([name]);
    expect(lstatSync(join(dir, name + ACK_SUFFIX)).size).toBe(size);
    writer.rescan();
    expect(writer.bytes).toBe(size); // the untruncated receipt, at its size
    const next = make(dir); // a fresh drainer after the crash
    drain.close();
    expect(next.tryLock()).toBe(true);
    next.rescan();
    expect(lstatSync(join(dir, name + ACK_SUFFIX)).size).toBe(0);
    expect(next.bytes).toBe(RECEIPT_OVERHEAD);
    writer.rescan();
    expect(writer.bytes).toBe(RECEIPT_OVERHEAD);
    expect(writer.settle()).toBe(0);
    expect(writer.failed).toBe(0);
  });
});
