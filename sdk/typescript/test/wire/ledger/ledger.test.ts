// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §6.3, §9.5 row `055-t16`: the spool's loss ledger (`FWLEDGR1`/`FWLSLOT1`, the
// layout of Python's `_ledger.py`), dead-owner slot recovery across processes and
// languages, ledger exhaustion and torn slots (coverage stays partial, never complete),
// and a Python drainer recovering the losses of a TypeScript writer that died on a full
// disk.
import { cpSync, openSync, writeFileSync, closeSync, writeSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { encodeJson } from "../../../src/wire/codec.js";
import {
  HEADER_BYTES,
  LEDGER,
  LEDGER_SIZE,
  LossLedger,
  MAX_OWN_SLOTS,
  SLOTS,
  SLOT_BYTES,
  decodeSlot,
  encodeSlot,
  ledgerHeader,
  ledgerProblem,
} from "../../../src/wire/ledger.js";
import type { OtlpSpan } from "../../../src/wire/otlp.js";
import { Sender } from "../../../src/wire/sender.js";
import { SCHEMA } from "../../../src/wire/spool-codec.js";
import { Spool, type SpoolOptions, nodeSpoolIo } from "../../../src/wire/spool.js";
import { CapturePipeline, LedgerMirror } from "../../../src/wire/worker.js";

import { norm } from "../helpers.js";
import { pipelineConfig, segment } from "../seal/helpers.js";
import {
  type Native,
  VECTORS,
  bundleFixture,
  cleanupDirs,
  faulty,
  native,
  pythonWithFabric,
  runPython,
  spoolDir,
  start,
  vectorRecord,
} from "../spool/helpers.js";

let lib: Native;
let writer: { file: string; cleanup(): void };
beforeAll(() => {
  lib = native();
  writer = bundleFixture("ledger-writer");
}, 120_000);
afterAll(() => {
  writer?.cleanup();
  lib?.build.cleanup();
});

const opened: { close(): void }[] = [];
const killers: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const kill of killers.splice(0)) await kill();
  for (const one of opened.splice(0)) one.close();
  cleanupDirs();
});

let nextPid = 90_000;
function makeSpool(dir: string, options: Partial<SpoolOptions> = {}): Spool {
  nextPid += 1;
  const spool = new Spool(dir, { maxBytes: 1 << 20, addon: lib.addon, pid: nextPid, ...options });
  opened.push(spool);
  return spool;
}

function ledgerOf(dir: string): LossLedger {
  const ledger = new LossLedger(dir, lib.addon);
  opened.push(ledger);
  return ledger;
}

/** A fresh spool directory that exists (owner-only), ledger-free. */
function freshDir(): string {
  const dir = spoolDir();
  makeSpool(dir, { ledger: false }).close();
  return dir;
}

/** A complete spool record header as the ledger stores it (Python `_record`). */
function record(doc: Record<string, unknown>, order: number): Record<string, unknown> {
  return { ...doc, schema_version: SCHEMA, order, written_at_unix_nano: 1000 + order };
}

const SOURCE = "s-" + "ab".repeat(16);
const SEG = segment(3);
const LOSS = record(
  {
    record_kind: "loss",
    source: { source_id: SOURCE, source_epoch: 7 },
    loss: {
      reason: "disk_full",
      count: 7,
      first_sequence: 3,
      last_sequence: 9,
      segment_id: SEG.id,
    },
  },
  0,
);
const SEAL = vectorRecord("segment_seal").doc as Record<string, unknown>;

/** Starts the bundled TypeScript ledger writer; it is killed after the test. */
async function tsWriter(dir: string, mode: string, input: unknown): Promise<any> {
  const file = join(dir, "..", `input-${mode}.json`);
  writeFileSync(file, encodeJson(input));
  const running = await start(process.execPath, [
    writer.file,
    lib.build.dir,
    lib.digest,
    dir,
    mode,
    file,
  ]);
  killers.push(running.kill);
  return { ...running.first, kill: running.kill };
}

const PY_STORE = `
import json, sys, time
from fabric.wire._ledger import LossLedger
ledger = LossLedger(sys.argv[1])
with open(sys.argv[2]) as handle:
    ok = ledger.store(json.load(handle))
print(json.dumps({"stored": ok, "used": ledger.used()}), flush=True)
while True:
    time.sleep(60)
`;

const PY_ORPHANS = `
import json, sys
from fabric.wire._ledger import LossLedger
ledger = LossLedger(sys.argv[1])
found = ledger.orphans()
if len(sys.argv) > 2 and sys.argv[2] == "clear":
    for index, _ in found:
        ledger.clear(index)
print(json.dumps({"orphans": [[index, records] for index, records in found],
                  "corrupt": ledger.corrupt}))
`;

/** Python's drainer: the ledger slots of dead writers exported as spans (D1). */
const PY_RECOVER = `
import json, sys
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from fabric._loss import LossEmitter
from fabric.wire._sender import Sender
from fabric.wire._spool import Spool

class Exporter(SpanExporter):
    def __init__(self):
        self.spans = []
    def export(self, spans):
        self.spans += list(spans)
        return SpanExportResult.SUCCESS
    def shutdown(self):
        return None

spool = Spool(sys.argv[1], 1 << 20)
assert spool.try_lock()
exporter = Exporter()
sender = Sender(spool, exporter, LossEmitter(), content=None, service_name="svc")
sender._recover_orphans()
spans = [{"name": s.name, "attributes": {k: list(v) if isinstance(v, tuple) else v
                                          for k, v in s.attributes.items()}}
         for s in exporter.spans]
print(json.dumps({"spans": spans, "recovered": sender.stats()["ledger_recovered"],
                  "ledger_corrupt": sender.stats()["ledger_corrupt"]}))
spool.release()
`;

async function pythonOwner(dir: string, records: unknown[]): Promise<() => Promise<void>> {
  const file = join(dir, "..", "py-records.json");
  writeFileSync(file, encodeJson(records));
  const running = await start(pythonWithFabric(), ["-c", PY_STORE, dir, file], true);
  expect(running.first).toEqual({ stored: true, used: 1 });
  killers.push(running.kill);
  return running.kill;
}

/** A TypeScript drainer's recovery: the spans it exported and its health counters. */
async function tsRecover(
  dir: string,
): Promise<{ spans: OtlpSpan[]; recovered: number; corrupt: number }> {
  const spool = makeSpool(dir);
  expect(spool.tryLock()).toBe(true);
  const spans: OtlpSpan[] = [];
  const sender = new Sender({
    spool,
    content: undefined,
    serviceName: "svc",
    traces: {
      export: async (batch) => {
        spans.push(...batch);
        return { outcome: "ok", status: 200 };
      },
    },
  });
  const recovered = await sender.recoverOrphans();
  return { spans, recovered, corrupt: sender.health().ledger_corrupt };
}

// ------------------------------------------------------------------------------ layout

describe("FWLEDGR1/FWLSLOT1 layout equals Python's (spool-bytes-v1.json)", () => {
  const vector = VECTORS.ledger as any;

  it("header, slot count and slot size", () => {
    expect([HEADER_BYTES, SLOT_BYTES, SLOTS]).toEqual([
      vector.header_bytes,
      vector.slot_bytes,
      vector.slots,
    ]);
    expect(LEDGER_SIZE).toBe(260 * 1024);
    const head = ledgerHeader();
    expect(head.length).toBe(HEADER_BYTES);
    expect(head.subarray(0, 16).toString("hex")).toBe(vector.header_hex);
    expect(head.subarray(16).every((byte) => byte === 0)).toBe(true);
  });

  it("a slot is Python's bytes, and decodes to the same records", () => {
    const names = new Map((VECTORS.records as any[]).map((r) => [r.name, r.header]));
    const records = (vector.slot.records as string[]).map((name) => names.get(name));
    const slot = encodeSlot(vector.slot.owner, records)!;
    expect(slot.toString("hex")).toBe(vector.slot.slot_hex);
    expect(norm(decodeSlot(Buffer.from(vector.slot.slot_hex, "hex")))).toEqual(norm(records));
  });

  it("an empty slot is zeros; a slot that does not verify is torn, never misread", () => {
    expect(decodeSlot(Buffer.alloc(SLOT_BYTES))).toEqual([]);
    const slot = Buffer.from(vector.slot.slot_hex, "hex");
    for (const at of [0, 9, 20, 200]) {
      const torn = Buffer.from(slot);
      torn[at]! ^= 0xff;
      expect(decodeSlot(torn), `byte ${at}`).toBeUndefined();
    }
    const half = Buffer.alloc(SLOT_BYTES);
    slot.copy(half, 0, 0, 100); // a write that stopped part way
    expect(decodeSlot(half)).toBeUndefined();
    expect(encodeSlot("o", [{ x: "y".repeat(SLOT_BYTES) }])).toBeUndefined();
  });

  it("the file TypeScript creates is Python's: fully allocated, opened by Python's LossLedger", () => {
    const dir = freshDir();
    ledgerOf(dir);
    const bytes = readFileSync(join(dir, LEDGER));
    expect(bytes.length).toBe(LEDGER_SIZE);
    expect(
      bytes.equals(Buffer.concat([ledgerHeader(), Buffer.alloc(LEDGER_SIZE - HEADER_BYTES)])),
    ).toBe(true);
    expect(runPython(PY_ORPHANS, [dir])).toEqual({ orphans: [], corrupt: 0 });
    // And a ledger Python created is one TypeScript opens.
    const other = freshDir();
    runPython(PY_ORPHANS, [other]);
    expect(readFileSync(join(other, LEDGER)).equals(bytes)).toBe(true);
    expect(ledgerOf(other).orphans()).toEqual([]);
  });

  it("a foreign or resized ledger is not used (the spool runs without one)", async () => {
    const dir = freshDir();
    writeFileSync(join(dir, LEDGER), Buffer.alloc(LEDGER_SIZE), { mode: 0o600 });
    expect(() => new LossLedger(dir, lib.addon)).toThrow(/not one this version wrote; fix: remove/);
    const spool = makeSpool(dir);
    expect(spool.ledger).toBeUndefined();
    // Never silent: the sender names the cause and the fix once, without a path.
    expect(spool.ledgerProblem).toMatch(/not one this version wrote; fix: remove/);
    const warned: string[] = [];
    const sender = new Sender({
      spool,
      content: undefined,
      serviceName: "svc",
      traces: { export: async () => ({ outcome: "ok", status: 200 }) },
      warn: (text) => warned.push(text),
    });
    sender.start();
    expect(warned.filter((text) => text.includes("loss ledger"))).toEqual([
      "fabric.wire: the spool loss ledger is not one this version wrote; fix: remove " +
        "FABRIC_WIRE_SPOOL_DIR/.ledger while no process uses the spool (it is recreated). Until " +
        "it is fixed, a loss that cannot be spooled (full disk) is kept in memory only and is " +
        "lost with this process",
    ]);
    expect(warned.join("\n")).not.toContain(dir);
    await sender.close(performance.now() + 200);
    expect(await sender.stopped(2000)).toBe(true);
    // An operating-system error keeps only its code: its message carries the path.
    expect(
      ledgerProblem(
        Object.assign(new Error(`EACCES: permission denied, open '${dir}'`), {
          code: "EACCES",
        }),
      ),
    ).toBe(
      "the spool loss ledger could not be opened (EACCES); fix: check the local volume holding " +
        "FABRIC_WIRE_SPOOL_DIR (free space, permissions, disk errors)",
    );
    // A spool that did not ask for a ledger has no problem to report.
    expect(makeSpool(freshDir(), { ledger: false }).ledgerProblem).toBeUndefined();
  });
});

// --------------------------------------------------------------- dead-owner recovery

describe("dead-owner slot recovery", { timeout: 60_000 }, () => {
  it("a live owner's slots are never taken; a dead owner's are recovered once", async () => {
    const dir = freshDir();
    const owner = await tsWriter(dir, "store", [LOSS, SEAL]);
    expect(owner).toMatchObject({ stored: true, used: 1 });
    const drainer = ledgerOf(dir);
    expect(drainer.orphans()).toEqual([]); // its record lock holds
    expect(runPython(PY_ORPHANS, [dir]).orphans).toEqual([]);
    await owner.kill();
    const found = drainer.orphans();
    expect(found).toHaveLength(1);
    expect(norm(found[0]!.records)).toEqual(norm([LOSS, SEAL]));
    // Held by this drainer: another drainer does not see it meanwhile.
    expect(runPython(PY_ORPHANS, [dir]).orphans).toEqual([]);
    expect(drainer.clear(found[0]!.index)).toBe(true);
    expect(drainer.orphans()).toEqual([]);
    const slots = readFileSync(join(dir, LEDGER)).subarray(HEADER_BYTES);
    expect(slots.every((byte) => byte === 0)).toBe(true);
  });

  it("a slot whose export failed is released for a later attempt", async () => {
    const dir = freshDir();
    await (await tsWriter(dir, "store", [LOSS])).kill();
    const drainer = ledgerOf(dir);
    const [first] = drainer.orphans();
    drainer.releaseSlot(first!.index);
    const again = drainer.orphans();
    expect(again.map((slot) => slot.index)).toEqual([first!.index]);
    expect(drainer.clear(first!.index)).toBe(true);
  });

  it("Python recovers a dead TypeScript owner's records exactly", async () => {
    const dir = freshDir();
    await (await tsWriter(dir, "store", [LOSS, SEAL])).kill();
    const python = runPython(PY_ORPHANS, [dir, "clear"]);
    expect(python.orphans).toHaveLength(1);
    expect(norm(python.orphans[0][1])).toEqual(norm([LOSS, SEAL]));
    expect(ledgerOf(dir).orphans()).toEqual([]);
  });

  it("TypeScript recovers a dead Python owner's records exactly", async () => {
    const dir = freshDir();
    const kill = await pythonOwner(dir, [LOSS, SEAL]);
    const drainer = ledgerOf(dir);
    expect(drainer.orphans()).toEqual([]);
    await kill();
    const found = drainer.orphans();
    expect(found).toHaveLength(1);
    expect(norm(found[0]!.records)).toEqual(norm([LOSS, SEAL]));
  });

  it("two handles of one process share its locks: neither takes the other's slots", () => {
    const dir = freshDir();
    const one = ledgerOf(dir);
    const two = ledgerOf(dir);
    expect(one.store([LOSS])).toBe(true);
    expect(two.store([SEAL])).toBe(true);
    expect(one.orphans()).toEqual([]);
    expect(two.orphans()).toEqual([]);
    // Closing one releases its slots (a drainer's now) but keeps the other's lock.
    one.close();
    const python = runPython(PY_ORPHANS, [dir]);
    expect(python.orphans.map((o: any) => norm(o[1]))).toEqual([norm([LOSS])]);
  });

  it("store rewrites in place, clears with [] and releases its slots", () => {
    const dir = freshDir();
    const ledger = ledgerOf(dir);
    expect(ledger.store([LOSS, SEAL])).toBe(true);
    expect(ledger.used()).toBe(1);
    expect(ledger.store([LOSS])).toBe(true);
    expect(ledger.used()).toBe(1);
    expect(ledger.store([])).toBe(true);
    expect(ledger.used()).toBe(0);
    expect(readFileSync(join(dir, LEDGER)).length).toBe(LEDGER_SIZE);
  });
});

// ---------------------------------------------------- exhaustion and torn slots

describe(
  "ledger exhaustion and torn slots leave coverage partial, never complete",
  { timeout: 60_000 },
  () => {
    /** A loss record of `n` filler bytes in its source id field (one per slot). */
    const bulky = (order: number): Record<string, unknown> =>
      record(
        {
          record_kind: "loss",
          source: { source_id: SOURCE, source_epoch: 7, pad: "p".repeat(3000) },
          loss: {
            reason: "queue_full",
            count: 1,
            first_sequence: order + 1,
            last_sequence: order + 1,
          },
        },
        order,
      );

    it("an owner never holds more than its share; the newest records stay in memory, counted", () => {
      const ledger = ledgerOf(freshDir());
      const records = Array.from({ length: MAX_OWN_SLOTS + 2 }, (_, i) => bulky(i));
      expect(ledger.store(records)).toBe(false);
      expect(ledger.used()).toBe(MAX_OWN_SLOTS);
      expect(ledger.stats().overflows).toBe(1);
    });

    it("a full ledger refuses the next owner (counted), and the pipeline never closes", () => {
      const dir = freshDir();
      for (let i = 0; i < SLOTS / MAX_OWN_SLOTS; i++) {
        const holder = ledgerOf(dir);
        expect(holder.store(Array.from({ length: MAX_OWN_SLOTS }, (_, n) => bulky(n)))).toBe(true);
      }
      // The capture pipeline on a full disk: nothing reaches the spool, nothing the ledger.
      const harness = faulty(nodeSpoolIo(lib.addon));
      const full = (): never => {
        throw Object.assign(new Error("full"), { code: "ENOSPC" });
      };
      const spool = makeSpool(dir, { io: { ...harness.io, write: full, writev: full } });
      expect(spool.ledger).toBeDefined();
      const pipeline = new CapturePipeline(pipelineConfig(), spool, { lose: () => undefined });
      pipeline.lost(
        { reason: "queue_full", sequence: 1n, segmentHi: SEG.hi, segmentLo: SEG.lo },
        5n,
      );
      pipeline.tick(5n, 1n);
      expect(pipeline.closeEpoch(5n, 1n)).toBe(false);
      expect(pipeline.closed).toBe(false);
      expect(pipeline.losses.pending).toBe(true);
      expect(spool.names()).toEqual([]);
      expect(spool.ledger!.used()).toBe(0);
      expect(spool.ledger!.stats().overflows).toBeGreaterThan(0);
      const sender = new Sender({
        spool,
        content: undefined,
        serviceName: "svc",
        traces: { export: async () => ({ outcome: "ok", status: 200 }) },
      });
      expect(sender.health().ledger_overflows).toBeGreaterThan(0);
    });

    it("on a full disk with ledger room the losses and final survive the process, yet the epoch is not closed", () => {
      const dir = freshDir();
      const full = (): never => {
        throw Object.assign(new Error("full"), { code: "EDQUOT" });
      };
      const spool = makeSpool(dir, {
        io: { ...nodeSpoolIo(lib.addon), write: full, writev: full },
      });
      const pipeline = new CapturePipeline(pipelineConfig(), spool, { lose: () => undefined });
      pipeline.lost(
        { reason: "queue_full", sequence: 1n, segmentHi: SEG.hi, segmentLo: SEG.lo },
        5n,
      );
      expect(pipeline.closeEpoch(5n, 1n)).toBe(false);
      expect(spool.names()).toEqual([]);
      const mirrored = runPython(PY_ORPHANS, [dir]); // this process is alive: its slots are held
      expect(mirrored.orphans).toEqual([]);
      spool.ledger!.close(); // as at death: the slots are released, not cleared
      const found = runPython(PY_ORPHANS, [dir]).orphans.flatMap((o: any) => o[1]);
      const kinds = found.map((r: any) => r.marker?.kind ?? r.record_kind);
      expect(kinds).toContain("loss");
      expect(kinds).toContain("final");
      const loss = found.find((r: any) => r.record_kind === "loss");
      expect(loss.loss).toMatchObject({
        reason: "queue_full",
        first_sequence: 1,
        segment_id: SEG.id,
      });
    });

    it("a torn slot is cleared and counted, never exported, and reported by both drainers", async () => {
      for (const drainer of ["ts", "python"] as const) {
        const dir = freshDir();
        await (await tsWriter(dir, "store", [LOSS])).kill();
        // Tear the slot: its digest no longer covers its bytes.
        const fd = openSync(join(dir, LEDGER), "r+");
        try {
          writeSync(fd, Buffer.from("torn"), 0, 4, HEADER_BYTES + 40);
        } finally {
          closeSync(fd);
        }
        if (drainer === "ts") {
          const result = await tsRecover(dir);
          expect(result.spans).toEqual([]);
          expect(result.recovered).toBe(0);
          expect(result.corrupt).toBe(1);
        } else {
          const result = runPython(PY_RECOVER, [dir]);
          expect(result.spans).toEqual([]);
          expect(result.ledger_corrupt).toBe(1);
        }
        const slots = readFileSync(join(dir, LEDGER)).subarray(HEADER_BYTES);
        expect(
          slots.every((byte) => byte === 0),
          drainer,
        ).toBe(true);
      }
    });

    it("a header lock another process holds fails the claim within its deadline, counted; the records stay in memory", async () => {
      const dir = freshDir();
      const ledger = ledgerOf(dir);
      const holder = await start(
        pythonWithFabric(),
        [
          "-c",
          "import fcntl, json, os, sys, time\n" +
            "fd = os.open(sys.argv[1], os.O_RDWR)\n" +
            "fcntl.lockf(fd, fcntl.LOCK_EX, 4096, 0, os.SEEK_SET)\n" +
            "print(json.dumps({'held': True}), flush=True)\n" +
            "time.sleep(3600)\n",
          join(dir, LEDGER),
        ],
        true,
      );
      killers.push(holder.kill);
      expect(holder.first).toEqual({ held: true });
      const began = performance.now();
      expect(ledger.store([LOSS])).toBe(false);
      const waited = performance.now() - began;
      // Python blocks in lockf; this claim gives up after about a second (rev 3.16 dev. 3).
      expect(waited).toBeGreaterThanOrEqual(900);
      expect(waited).toBeLessThan(5000);
      expect(ledger.stats()).toMatchObject({ slots: 0, failures: 1, overflows: 1 });
      expect(ledger.used()).toBe(0);
      // Once the holder is gone, the next store claims a slot.
      await holder.kill();
      expect(ledger.store([LOSS])).toBe(true);
      expect(ledger.used()).toBe(1);
    });

    it("a mirror without a ledger, or with no room, never claims the records are durable", () => {
      const loss = {
        sourceId: SOURCE,
        epoch: 7n,
        reason: "disk_full" as const,
        segmentId: SEG.id,
        first: 1n,
        last: 1n,
        count: 1n,
      };
      expect(new LedgerMirror().mirror(undefined, [loss], [])).toBe(false);
      expect(new LedgerMirror().mirror(undefined, [], [])).toBe(true);
      const ledger = ledgerOf(freshDir());
      const mirror = new LedgerMirror();
      expect(mirror.mirror(ledger, [loss], [])).toBe(true);
      expect(ledger.used()).toBe(1);
      expect(mirror.mirror(ledger, [], [])).toBe(true);
      expect(ledger.used()).toBe(0);
    });
  },
);

// ------------------------------------------- Python drains a spool TS wrote, disk full

describe(
  "Python drains a spool TypeScript wrote under a full disk and reports the same losses",
  { timeout: 90_000 },
  () => {
    it("every unspooled loss and marker is exported once, identically by both drainers", async () => {
      const dir = freshDir();
      const other = segment(4);
      const input = {
        losses: [
          { sourceId: SOURCE, epoch: 7, reason: "disk_full", sequence: 3, segmentId: SEG.id },
          { sourceId: SOURCE, epoch: 7, reason: "disk_full", sequence: 4, segmentId: SEG.id },
          { sourceId: SOURCE, epoch: 7, reason: "queue_full", sequence: 5, segmentId: other.id },
          { sourceId: SOURCE, epoch: 7, reason: "internal_error", sequence: 9 },
        ],
        markers: [
          Object.fromEntries(
            Object.entries(SEAL).filter(
              ([field]) => !["schema_version", "order", "written_at_unix_nano"].includes(field),
            ),
          ),
        ],
      };
      const child = await tsWriter(dir, "disk-full", input);
      expect(child).toMatchObject({ spooled: 0, mirrored: true, used: 1, markers: 1 });
      const pending = child.pending as any[];
      expect(pending.map((p) => [p.reason, p.first, p.last])).toEqual([
        ["disk_full", 3, 4],
        ["queue_full", 5, 5],
        ["internal_error", 9, 9],
      ]);
      await child.kill(); // dies with its records unspooled: only the ledger holds them
      const copy = join(dir, "..", "copy");
      cpSync(dir, copy, { recursive: true });

      const python = runPython(PY_RECOVER, [dir]);
      const ts = await tsRecover(copy);
      expect(python.recovered).toBe(pending.length + 1);
      expect(ts.recovered).toBe(python.recovered);
      const lossesOf = (spans: { name: string; attributes: Record<string, unknown> }[]) =>
        spans
          .filter((span) => span.name === "fabric.capture_loss")
          .map((span) => ({
            reason: span.attributes["fabric.loss.reason"],
            first: span.attributes["fabric.loss.first_sequence"],
            last: span.attributes["fabric.loss.last_sequence"],
            count: span.attributes["fabric.loss.count"],
            segment: span.attributes["fabric.run.segment_id"] ?? null,
          }));
      // The losses the writer knew it lost are the losses each drainer reports.
      expect(norm(lossesOf(python.spans))).toEqual(norm(pending));
      expect(norm(lossesOf(ts.spans as any))).toEqual(norm(pending));
      // Every span, losses and the marker, is the same in both languages.
      const named = (spans: any[]) =>
        spans.map((span) => ({ name: span.name, attributes: norm(span.attributes) }));
      expect(named(ts.spans)).toEqual(named(python.spans));
      // Exported once: the slots are clear for every later drainer.
      expect(runPython(PY_RECOVER, [dir]).recovered).toBe(0);
      expect(runPython(PY_ORPHANS, [copy]).orphans).toEqual([]);
    });
  },
);
