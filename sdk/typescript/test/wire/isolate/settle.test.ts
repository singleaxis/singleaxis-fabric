// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §4.4, §4.5, §6.4, unit 055-t19: what the Fabric worker does for application
 * isolates, on one control block with simulated isolates (each its own isolate-table row):
 * a torn-down isolate's open exchanges become `shutdown` losses in their own segments and
 * nothing else's; OVERFLOW leaves them to `close()`; run slots are shared and released;
 * a lock or a ring cell a dead isolate held is freed; created threads that never attach are
 * counted after the grace period and declared once.
 */
import { BroadcastChannel } from "node:worker_threads";

import { describe, expect, it } from "vitest";

import { ExchangeTable, REQUEST } from "../../../src/wire/exchange.js";
import {
  IsolateWatch,
  ISOLATE_CHANNEL,
  STALE_LOCK_MS,
  STUCK_MS,
} from "../../../src/wire/isolate.js";
import { NativeCode, type NativeAddon } from "../../../src/wire/native.js";
import { RING_VOID, Ring, createRing } from "../../../src/wire/queue.js";
import { STATE_CLOSING, WireRuntime } from "../../../src/wire/runtime.js";
import { SegmentTable } from "../../../src/wire/segments.js";

import { drain, isolate } from "../runtime/helpers.js";

/** An application isolate on `installer`'s control block, attached as `envId`. */
function attachAs(installer: WireRuntime, envId: number, threadId = envId) {
  const row = installer.claimIsolateRow(envId, threadId);
  expect(row).toBeGreaterThanOrEqual(2);
  const runtime = new WireRuntime(installer.shared, "application", row);
  return { row, runtime, table: new ExchangeTable(runtime) };
}

/** A native module whose detached ring is scripted: each call returns the next answer. */
function fakeAddon(answers: (number[] | "overflow")[]): NativeAddon {
  return {
    takeDetachedEnvs(dst: Uint32Array): number {
      const next = answers.shift();
      if (next === undefined) return 0;
      if (next === "overflow") return NativeCode.OVERFLOW;
      dst.set(next);
      return next.length;
    },
  } as unknown as NativeAddon;
}

function clock(start = 1000) {
  const time = { now: start };
  return { time, now: () => time.now };
}

describe("settling a torn-down isolate", () => {
  it("loses its open exchanges as shutdown in their own segments, and nothing else", () => {
    const { runtime: installer, table: main } = isolate();
    const a = attachAs(installer, 11);
    const b = attachAs(installer, 12);
    // Isolate A: one exchange in a run segment, one outside a run, one provisional
    // (owned by a live explicit scope: no position), each with retained bytes.
    a.runtime.setRunSegment(3, 0x11n, 0x22n);
    const inRun = a.table.begin({ runSlot: 3 });
    a.table.admit(inRun, REQUEST, Buffer.alloc(70_000, 1));
    a.table.begin(); // outside any run
    const provisional = a.table.begin({ ownership: { ended: false, withheld: false } });
    a.table.admit(provisional, REQUEST, Buffer.alloc(100, 2));
    // Isolate B and the installing thread keep theirs.
    const kept = b.table.begin();
    const mine = main.begin();
    const slabs = a.table.arena.slabs.inUse;
    expect(slabs).toBeGreaterThan(0);

    const settled = a.table.settleDetached(a.runtime.ownerTag);
    expect(settled).toEqual({ shutdown: 2, released: 1, abandoned: 0 });
    const losses = drain(main).losses.sort((x, y) => (x.sequence < y.sequence ? -1 : 1));
    expect(losses.map((l) => [l.reason, l.sequence, l.segmentHi])).toEqual([
      ["shutdown", 0n, 0x11n],
      ["shutdown", 1n, 0n],
    ]);
    expect(losses[0]).toMatchObject({ segmentLo: 0x22n });
    // A's bytes are released; B's and the installer's exchanges finish as usual.
    expect(a.table.arena.slabs.inUse).toBe(0);
    expect(b.table.finish(kept, "complete")).toBe("enqueued");
    expect(main.finish(mine, "complete")).toBe("enqueued");
    // Every handle A held is stale now: a late finish from anywhere changes nothing.
    expect(a.table.finish(inRun, "complete")).toBe("already_finished");
    expect(a.table.finish(provisional, "complete")).toBe("already_finished");
  });

  it("an isolate cut off inside begin or finish: a named loss, or a gap it never fills", () => {
    const { runtime: installer, table: main } = isolate();
    const a = attachAs(installer, 21);
    const beginning = a.table.begin();
    const finishing = a.table.begin();
    // Simulate the two cut-off points on the slots' state words (state in the low 3 bits:
    // 6 = inside begin with a position allocated, 5 = inside finish).
    const word = (handle: number) => (handle % 65536) * 512;
    const i32 = a.table.pool.i32;
    Atomics.store(i32, word(beginning), (Atomics.load(i32, word(beginning)) & ~7) | 6);
    Atomics.store(i32, word(finishing), (Atomics.load(i32, word(finishing)) & ~7) | 5);
    expect(a.table.settleDetached(a.runtime.ownerTag)).toEqual({
      shutdown: 1,
      released: 0,
      abandoned: 1,
    });
    expect(drain(main).losses.map((l) => [l.reason, l.sequence])).toEqual([["shutdown", 0n]]);
  });

  it("frees the lock and the run slots it held; the row is free for the next isolate", () => {
    const { runtime: installer } = isolate();
    const a = attachAs(installer, 31);
    const b = attachAs(installer, 32);
    expect(a.runtime.claimRunSlot()).toBe(0);
    expect(b.runtime.claimRunSlot()).toBe(1);
    expect(a.runtime.claimRunSlot()).toBe(2);
    a.runtime.setRunSegment(0, 5n, 6n);
    expect(a.runtime.tryLock()).toBe(true);
    expect(installer.lockHolder).toBe(a.runtime.ownerTag);
    expect(installer.detachIsolate(a.row)).toBe(2);
    expect(installer.lockHolder).toBe(0);
    expect(installer.runSegment(0)).toEqual([0n, 0n]);
    expect(b.runtime.claimRunSlot()).toBe(0);
    expect(installer.rowOfEnv(31)).toBe(-1);
    expect(installer.claimIsolateRow(33, 33)).toBe(a.row);
  });

  it("run tables of two isolates on one control block never share a run slot", () => {
    const { runtime: installer } = isolate();
    const tables = [attachAs(installer, 41), attachAs(installer, 42)].map(
      ({ runtime }) =>
        new SegmentTable({
          runtime,
          sourceId: "s-" + "a".repeat(32),
          send: () => true,
          manifest: () => undefined,
        }),
    );
    const slots = tables.map((t) => t.enter(t.prepare({ runId: "same-run" }, true))!.run.slot);
    expect(new Set(slots).size).toBe(2);
  });
});

describe("the Fabric worker's isolate poll", () => {
  it("settles an isolate the detached ring names, within the poll, and wakes the loop", () => {
    const { runtime: installer, table: main } = isolate();
    const a = attachAs(installer, 51);
    a.table.begin();
    const before = Atomics.load(installer.jobs.wakeWords, installer.jobs.wakeIndex);
    const watch = new IsolateWatch(installer, main, fakeAddon([[51, 99]]));
    expect(watch.poll()).toEqual({ detached: 1, shutdown: 1, overflow: false });
    expect(Atomics.load(installer.jobs.wakeWords, installer.jobs.wakeIndex)).not.toBe(before);
    expect(installer.stats().isolates).toMatchObject({ detached: 1n, shutdownPositions: 1n });
    watch.close();
  });

  it("OVERFLOW is counted; the dropped isolate's positions settle as shutdown at close()", () => {
    const { runtime: installer, table: main } = isolate();
    const a = attachAs(installer, 61);
    a.table.begin();
    const watch = new IsolateWatch(installer, main, fakeAddon(["overflow"]));
    expect(watch.poll()).toEqual({ detached: 0, shutdown: 0, overflow: true });
    expect(installer.stats().isolates.overflows).toBe(1n);
    expect(drain(main).losses).toEqual([]); // nothing is settled yet: its seal waits
    installer.setState(STATE_CLOSING);
    expect(main.shutdown()).toBe(1);
    expect(drain(main).losses.map((l) => l.reason)).toEqual(["shutdown"]);
    watch.close();
  });

  it("counts a created thread unattached after the grace period, and declares once", () => {
    const { runtime: installer, table: main } = isolate();
    const { time, now } = clock();
    const cuts: bigint[] = [];
    const watch = new IsolateWatch(installer, main, fakeAddon([]), {
      graceMs: 2000,
      now,
      onUnattached: (cut) => cuts.push(cut),
    });
    expect(installer.notePendingThread(7)).toBe(true); // never attaches
    expect(installer.notePendingThread(8)).toBe(true); // attaches in time
    watch.poll();
    attachAs(installer, 81, 8);
    time.now += 1999;
    watch.poll();
    expect(installer.stats().isolates.unattached).toBe(0n);
    main.begin();
    time.now += 1;
    watch.poll();
    expect(installer.stats().isolates.unattached).toBe(1n);
    expect(cuts).toEqual([0n]);
    expect(installer.notePendingThread(9)).toBe(true);
    watch.poll();
    time.now += 2000;
    watch.poll();
    expect(installer.stats().isolates.unattached).toBe(2n);
    expect(cuts).toHaveLength(1);
    watch.close();
  });

  it("a thread that attached and exited before any scan is never counted", () => {
    const { runtime: installer, table: main } = isolate();
    const { time, now } = clock();
    const watch = new IsolateWatch(installer, main, fakeAddon([]), { graceMs: 10, now });
    expect(installer.notePendingThread(5)).toBe(true);
    const a = attachAs(installer, 91, 5);
    installer.detachIsolate(a.row);
    time.now += 100;
    watch.poll();
    expect(installer.stats().isolates.unattached).toBe(0n);
    watch.close();
  });

  it("frees a lock one application isolate kept for a second; never the installing thread's", () => {
    const { runtime: installer, table: main } = isolate();
    const { time, now } = clock();
    const watch = new IsolateWatch(installer, main, fakeAddon([]), { now });
    expect(installer.tryLock()).toBe(true);
    watch.poll();
    time.now += STALE_LOCK_MS * 3;
    watch.poll();
    expect(installer.lockHolder).toBe(1);
    installer.unlock();
    const a = attachAs(installer, 101);
    expect(a.runtime.tryLock()).toBe(true);
    watch.poll();
    time.now += STALE_LOCK_MS - 1;
    watch.poll();
    expect(installer.lockHolder).toBe(a.runtime.ownerTag);
    time.now += 1;
    watch.poll();
    expect(installer.lockHolder).toBe(0);
    expect(installer.stats().isolates.locksBroken).toBe(1n);
    watch.close();
  });

  it("skips a job-ring cell a dead producer claimed and never published", () => {
    const { runtime: installer, table: main } = isolate();
    const { time, now } = clock();
    const watch = new IsolateWatch(installer, main, fakeAddon([]), { now });
    claimWithoutPublishing(installer.jobs);
    watch.poll();
    time.now += STUCK_MS;
    watch.poll();
    expect(installer.stats().isolates.ringVoided).toBe(1n);
    expect(installer.jobs.peek()?.kind).toBe(RING_VOID);
    installer.jobs.commit();
    // The ring goes on: the next exchange is handled as usual.
    const handle = main.begin();
    expect(main.finish(handle, "complete")).toBe("enqueued");
    expect(drain(main).jobs).toHaveLength(1);
    watch.close();
  });

  it("counts a thread that ran Fabric without the runtime once, from its own report", async () => {
    const { runtime: installer, table: main } = isolate();
    const watch = new IsolateWatch(installer, main, fakeAddon([]));
    const thread = new BroadcastChannel(ISOLATE_CHANNEL);
    try {
      thread.postMessage({ unattached: 777 });
      thread.postMessage({ unattached: 777 });
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(installer.stats().isolates.unattached).toBe(1n);
    } finally {
      thread.close();
      watch.close();
    }
  });

  it("a thread counted after its grace period is not counted again by a late report", async () => {
    const { runtime: installer, table: main } = isolate();
    const { time, now } = clock();
    const watch = new IsolateWatch(installer, main, fakeAddon([]), { graceMs: 10, now });
    const thread = new BroadcastChannel(ISOLATE_CHANNEL);
    try {
      expect(installer.notePendingThread(4242)).toBe(true);
      watch.poll();
      time.now += 10;
      watch.poll();
      expect(installer.stats().isolates.unattached).toBe(1n);
      // Its own report arrives late (it ran Fabric without the runtime): one thread.
      thread.postMessage({ unattached: 4242 });
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(installer.stats().isolates.unattached).toBe(1n);
    } finally {
      thread.close();
      watch.close();
    }
  });

  it("a row claimed by an attach that failed is freed and never counted attached", () => {
    const { runtime: installer } = isolate();
    const row = installer.claimIsolateRow(131, 13);
    // The claim alone is not an attach: counted only once the hook is installed.
    expect(installer.stats().isolates.attached).toBe(0n);
    expect(installer.threadAttached(13)).toBe(true);
    installer.freeIsolateRow(row);
    expect(installer.threadAttached(13)).toBe(false);
    expect(installer.rowOfEnv(131)).toBe(-1);
    expect(installer.stats().isolates.detached).toBe(0n);
    expect(installer.claimIsolateRow(132, 14)).toBe(row);
  });
});

/** The first steps of `Ring.push` by a producer that is torn down before it publishes. */
function claimWithoutPublishing(ring: Ring): void {
  const words = new Int32Array(ring.shared.buffer);
  Atomics.add(words, 2, 1); // count
  const tail = Atomics.load(words, 0);
  expect(Atomics.compareExchange(words, 0, tail, tail + 1)).toBe(tail);
}

describe("the ring's void path", () => {
  it("a voided head is a record to commit; recovery does not skip it; the ring goes on", () => {
    const ring = new Ring(createRing(64, 4));
    claimWithoutPublishing(ring);
    expect(ring.push(1, new Uint8Array([9]))).toBe(true); // behind the stuck cell
    expect(ring.peek()).toBeUndefined();
    const head = ring.stuckHead();
    expect(head).toBe(0);
    expect(ring.voidStuck(head!)).toBe(true);
    expect(ring.voidStuck(head!)).toBe(false);
    expect(ring.recover()).toBe(false);
    expect(ring.peek()?.kind).toBe(RING_VOID);
    ring.commit();
    expect(ring.peek()?.kind).toBe(1);
    ring.commit();
    expect(ring.count).toBe(0);
    for (let lap = 0; lap < 9; lap++) {
      expect(ring.push(2, new Uint8Array([lap]))).toBe(true);
      expect(ring.peek()?.body[0]).toBe(lap);
      ring.commit();
    }
  });

  it("a producer that publishes after its cell was voided reports the record undelivered", () => {
    const ring = new Ring(createRing(64, 4));
    const consumer = new Ring(ring.shared);
    const bytes = (ring as unknown as { bytes: Uint8Array }).bytes;
    // The producer stalls between its claim and its publish; the consumer voids the cell.
    (ring as unknown as { bytes: { set(b: Uint8Array, at: number): void } }).bytes = {
      set(body, at) {
        expect(consumer.voidStuck(consumer.stuckHead()!)).toBe(true);
        bytes.set(body, at);
      },
    };
    expect(ring.push(1, new Uint8Array([1]))).toBe(false);
    expect(consumer.peek()?.kind).toBe(RING_VOID);
    consumer.commit();
    expect(consumer.count).toBe(0);
  });
});
