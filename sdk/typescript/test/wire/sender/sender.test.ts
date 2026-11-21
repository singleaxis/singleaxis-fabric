// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §7.1, §9.5 (unit 055-t13): the spool sender. Files are drained in name order;
 * every body of a file is settled before its spans are exported; accepted bodies are never
 * sent again; a body refused for good is counted, warned about once per epoch and settled,
 * and its span still goes out; a trace export refused for good never blocks the spool;
 * retries back off and a wake-up never cuts the backoff short; another writer's record is
 * retired as its receipt; flush and close keep their deadlines; the exit note is the one
 * Python reads. Restart: records a killed process admitted are delivered by the next one
 * with the same ids and bytes.
 */
import { existsSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { NodeContentClient } from "../../../src/wire/node-content.js";
import { TraceClient } from "../../../src/wire/delivery.js";
import { encodeTraceRequest, spanOfRecord } from "../../../src/wire/otlp.js";
import { BACKOFF_MS } from "../../../src/wire/delivery.js";
import { Sender } from "../../../src/wire/sender.js";
import { unframeAll } from "../../../src/wire/spool-codec.js";
import { EXIT_NOTE, Spool } from "../../../src/wire/spool.js";
import { encodeJson } from "../../../src/wire/codec.js";
import { SDK_VERSION } from "../../../src/version.js";

import {
  KEY,
  bundleFixture,
  cleanupDirs,
  native,
  runPython,
  spawnLines,
  spoolDir,
} from "../spool/helpers.js";
import { FakeDelivery, exchangeAt, fakeNode, newSpool, target } from "./helpers.js";

afterAll(() => cleanupDirs());

const SERVICE = "svc-sender-test";

function sender(spool = newSpool(), delivery = new FakeDelivery(), extra = {}) {
  const warnings: string[] = [];
  const s = new Sender({
    spool,
    traces: delivery.traces,
    content: delivery.content,
    serviceName: SERVICE,
    batchBodies: 32,
    concurrency: 4,
    warn: (text) => warnings.push(text),
    ...extra,
  });
  return { s, spool, delivery, warnings };
}

function write(spool: ReturnType<typeof newSpool>, ...sequences: number[]): string[] {
  return sequences.map((n) => {
    const { doc, bodies } = exchangeAt(n);
    return spool.write(doc, bodies)!;
  });
}

describe("drain", { timeout: 60_000 }, () => {
  it("delivers files in name order, every body before its file's span, then retires them", async () => {
    const { s, spool, delivery } = sender();
    spool.tryLock();
    write(spool, 0, 1, 2);
    expect(await s.drain()).toBe("more");
    expect(await s.drain()).toBe("idle");
    const kinds = delivery.timeline.map((e) => e.kind);
    expect(kinds.lastIndexOf("content")).toBeLessThan(kinds.indexOf("traces"));
    const sent = delivery.timeline.filter((e) => e.kind === "content");
    expect(sent.flatMap((e) => (e.kind === "content" ? e.sequences : []))).toEqual([
      0, 0, 1, 1, 2, 2,
    ]);
    const exported = delivery.timeline.find((e) => e.kind === "traces")!;
    expect(exported).toEqual({
      kind: "traces",
      spans: ["fabric.model_call:0", "fabric.model_call:1", "fabric.model_call:2"],
    });
    expect(spool.names()).toEqual([]);
    expect(s.stats()).toMatchObject({ delivered: 3, content_rejected: 0, quarantined: 0 });
  });

  it("remembers accepted bodies per file and never sends them again", async () => {
    const delivery = new FakeDelivery();
    let refuse = true;
    delivery.contentScript = (item) =>
      refuse && item.descriptor.role === "model.exchange.response" ? "retry" : "ok";
    const { s, spool } = sender(newSpool(), delivery, { batchBodies: 1, concurrency: 1 });
    spool.tryLock();
    write(spool, 0);
    expect(await s.drain()).toBe("retry");
    expect(delivery.timeline.filter((e) => e.kind === "traces")).toEqual([]);
    refuse = false;
    expect(await s.drain()).toBe("more");
    const roles = delivery.timeline.flatMap((e) => (e.kind === "content" ? e.roles : []));
    // request accepted once; response refused once, then accepted: the request never again
    expect(roles).toEqual([
      "model.exchange.request",
      "model.exchange.response",
      "model.exchange.response",
    ]);
    expect(spool.names()).toEqual([]);
  });

  it("a later file never goes out before an earlier one whose bodies are pending", async () => {
    const delivery = new FakeDelivery();
    let down = true;
    delivery.contentScript = (item) =>
      down && item.descriptor.source_sequence === 0 ? "retry" : "ok";
    const { s, spool } = sender(newSpool(), delivery, { batchBodies: 2, concurrency: 1 });
    spool.tryLock();
    write(spool, 0, 1);
    expect(await s.drain()).toBe("retry");
    expect(delivery.exported).toEqual([]);
    expect(spool.names()).toHaveLength(2);
    down = false;
    await s.drain();
    expect(
      delivery.exported.flat().map((span) => span.attributes["fabric.source.sequence"]),
    ).toEqual([0, 1]);
  });

  it("settles a body the Node refused for good: counted, warned once per epoch, span exported, file retired", async () => {
    const delivery = new FakeDelivery();
    delivery.contentScript = (item) =>
      item.descriptor.role === "model.exchange.response" ? "rejected" : "ok";
    const { s, spool, warnings } = sender(newSpool(), delivery);
    spool.tryLock();
    const [name] = write(spool, 0, 1);
    const span = spanOfRecord(unframeAll(spool.read(name!))[0]!.doc, {
      serviceName: SERVICE,
      version: SDK_VERSION,
    });
    await s.drain();
    await s.drain();
    expect(s.stats().content_rejected).toBe(2);
    expect(warnings.filter((w) => w.includes("refused a content record"))).toHaveLength(1);
    expect(warnings.join("\n")).not.toMatch(/sha256|tenant-|object_id|http:/);
    // The span is exported unchanged: its digests were fixed at spool time.
    expect(delivery.exported.flat()[0]).toEqual(span);
    expect(spool.names()).toEqual([]);
  });

  it("with no Node configured every body is settled as rejected (Python's rule)", async () => {
    const delivery = new FakeDelivery();
    const spool = newSpool();
    const s = new Sender({
      spool,
      traces: delivery.traces,
      content: undefined,
      serviceName: SERVICE,
    });
    spool.tryLock();
    write(spool, 0);
    await s.drain();
    expect(s.stats()).toMatchObject({ content_rejected: 2, delivered: 1 });
  });

  it("a trace export refused for good is sent file by file; the file refused alone is quarantined as internal_error losses", async () => {
    const delivery = new FakeDelivery();
    delivery.traceScript = (spans) =>
      spans.some((span) => span.attributes["fabric.source.sequence"] === 1)
        ? { outcome: "rejected", status: 400 }
        : { outcome: "ok", status: 200 };
    const quarantined: unknown[] = [];
    const { s, spool } = sender(newSpool(), delivery, {
      quarantined: (docs: unknown[]) => quarantined.push(...docs),
    });
    spool.tryLock();
    write(spool, 0, 1, 2);
    expect(await s.drain()).toBe("more");
    expect(
      delivery.exported.map((b) => b.map((x) => x.attributes["fabric.source.sequence"])),
    ).toEqual([[0], [2]]);
    expect(spool.names()).toEqual([]);
    expect(readdirSync(spool.dir).filter((n) => n.endsWith(".corrupt"))).toHaveLength(1);
    expect(s.stats()).toMatchObject({ traces_rejected: 1, quarantined: 1, delivered: 2 });
    expect((quarantined[0] as any).span.attributes["fabric.source.sequence"]).toBe(1);
  });

  it("a file sealed under another key is left for its key holder and does not block the spool", async () => {
    const dir = spoolDir();
    const other = new Spool(dir, {
      maxBytes: 1 << 24,
      addon: native().addon,
      key: Buffer.alloc(32, 9),
      pid: 4_000_002,
    });
    write(other, 0);
    other.close();
    const { s, spool, delivery } = sender(newSpool(dir));
    spool.tryLock();
    write(spool, 1);
    await s.drain();
    await s.drain();
    expect(delivery.exported.flat().map((x) => x.attributes["fabric.source.sequence"])).toEqual([
      1,
    ]);
    expect(spool.names()).toHaveLength(1);
    expect(s.stats().spool_undecryptable).toBe(1);
    expect(s.backlog()).toEqual({ deliverable: 0, skipped: 1 });
  });
});

describe("the delivery loop", { timeout: 60_000 }, () => {
  it("backs off 0.5 s doubling to 30 s, raised to a bounded Retry-After", async () => {
    const delivery = new FakeDelivery();
    let calls = 0;
    delivery.traceScript = () =>
      ++calls === 3
        ? { outcome: "retry", status: 503, retryAfterMs: 7000 }
        : { outcome: "retry", status: 503 };
    const delays: number[] = [];
    const spool = newSpool();
    let release!: () => void;
    const done = new Promise<void>((resolve) => (release = resolve));
    const s = new Sender({
      spool,
      traces: delivery.traces,
      content: delivery.content,
      serviceName: SERVICE,
      sleep: async (ms) => {
        delays.push(ms);
        if (delays.length === 5) release();
        await new Promise((r) => setTimeout(r, 1));
      },
    });
    write(spool, 0);
    s.start();
    await done;
    await s.close(performance.now() + 50);
    expect(delays.slice(0, 5)).toEqual([BACKOFF_MS, 1000, 7000, 4000, 8000]);
  });

  it("a wake-up never cuts a retry backoff short (no retry storm while the Node is down)", async () => {
    const delivery = new FakeDelivery();
    delivery.traceScript = () => ({ outcome: "retry", status: 503 });
    const { s, spool } = sender(newSpool(), delivery);
    write(spool, 0);
    s.start();
    for (let i = 0; i < 40; i++) {
      s.wake();
      await new Promise((r) => setTimeout(r, 10));
    }
    await s.close(performance.now() + 100);
    // 400 ms of wake-ups: the first attempt, then one after the 0.5 s backoff at most.
    expect(delivery.timeline.filter((e) => e.kind === "traces").length).toBeLessThanOrEqual(2);
    expect(spool.names()).toHaveLength(1);
  });

  it("flush settles this process's records within its deadline; false after a loss", async () => {
    let lost = 0;
    const { s, spool } = sender(newSpool(), new FakeDelivery(), { failures: () => lost });
    write(spool, 0, 1);
    s.start();
    expect(await s.flush(performance.now() + 10_000)).toBe(true);
    expect(spool.names()).toEqual([]);
    expect(spool.mine.size).toBe(0);
    lost = 1;
    write(spool, 2);
    expect(await s.flush(performance.now() + 10_000)).toBe(false);
    expect(await s.flush(performance.now() + 10_000)).toBe(true);
    expect(await s.close(performance.now() + 1000)).toBe(false); // a loss since start
  });

  it("close keeps its deadline while the Node is down, and the exit note is the one Python reads", async () => {
    const delivery = new FakeDelivery();
    delivery.traceScript = () => ({ outcome: "retry", status: 503 });
    const { s, spool } = sender(newSpool(), delivery);
    write(spool, 0, 1, 2);
    s.start();
    const started = performance.now();
    expect(await s.close(performance.now() + 300)).toBe(false);
    expect(performance.now() - started).toBeLessThan(2000);
    expect(s.exitBacklog()).toBe(3);
    spool.writeExitNote(3, 0.5);
    const note = runPython(
      "import json, sys\nfrom fabric.wire._spool import read_exit_note\nprint(json.dumps(read_exit_note(sys.argv[1])))",
      [spool.dir],
    ) as any;
    expect(note.records_left).toBe(3);
    expect(Number(note.drain_on_exit_s.value ?? note.drain_on_exit_s)).toBe(0.5);
    // The next drainer delivers the backlog and clears the note.
    const next = sender(newSpool(spool.dir));
    next.spool.tryLock();
    await next.s.drain();
    await next.s.drain();
    expect(existsSync(join(spool.dir, EXIT_NOTE))).toBe(false);
  });

  it("an exiting process that does not drain leaves its records durable for the drainer", async () => {
    const dir = spoolDir();
    const holder = newSpool(dir);
    expect(holder.tryLock()).toBe(true);
    const { s, spool } = sender(newSpool(dir));
    write(spool, 0);
    const started = performance.now();
    expect(await s.close(performance.now() + 5000, { exiting: true })).toBe(true);
    expect(performance.now() - started).toBeLessThan(1000);
    expect(spool.names()).toHaveLength(1);
    expect(s.exitBacklog()).toBe(0); // a live drainer holds the lock
    holder.close();
  });
});

describe("another writer's records", { timeout: 60_000 }, () => {
  it("are retired as receipts their writer settles as delivered", async () => {
    const dir = spoolDir();
    const writer = newSpool(dir, 4_000_001);
    const [name] = write(writer, 0);
    const { s, spool } = sender(newSpool(dir));
    spool.tryLock();
    await s.drain();
    expect(readdirSync(dir)).toContain(`${name}.ack`);
    expect(writer.settle()).toBe(0);
    expect(writer.failed).toBe(0);
    expect(readdirSync(dir)).not.toContain(`${name}.ack`);
  });

  it("restart: what a killed process admitted is delivered by the next one with the same ids and bytes", async () => {
    const node = await fakeNode();
    const writer = bundleFixture("writer");
    const n = native();
    const dir = spoolDir();
    const entries = [0, 1, 2].map((seq) => {
      const { doc, bodies } = exchangeAt(seq);
      return { doc, bodies_hex: bodies.map((b) => b.toString("hex")) };
    });
    const file = join(dir + "-entries.json");
    writeFileSync(file, encodeJson(entries));
    // Process A admits three exchanges, then is killed.
    const proc = spawnLines(process.execPath, [
      writer.file,
      n.build.dir,
      n.digest,
      dir,
      String(1 << 24),
      KEY.toString("hex"),
      "hold",
      file,
    ]);
    try {
      const { names } = await proc.next();
      expect(names).toHaveLength(3);
      await proc.kill();
      const reader = newSpool(dir);
      const spooled: { doc: Record<string, unknown>; blob: Buffer }[] = names.map(
        (name: string) => unframeAll(reader.read(name))[0]!,
      );
      reader.close();

      // Process B's first drainer: content goes out, the trace endpoint is down; it dies.
      node.status = (path) => (path === "/v1/traces" ? 503 : 200);
      const first = new Sender({
        spool: newSpool(dir),
        traces: new TraceClient(target(`${node.url}/v1/traces`)),
        content: new NodeContentClient(target(`${node.url}/v1/logs`), { serviceName: SERVICE }),
        serviceName: SERVICE,
      });
      first.spool.tryLock();
      expect(await first.drain()).toBe("retry");
      first.spool.close();
      const attempted = node.bodies.filter((b) => b.path === "/v1/traces").map((b) => b.body);

      // Process C delivers everything.
      node.status = () => 200;
      const second = new Sender({
        spool: newSpool(dir),
        traces: new TraceClient(target(`${node.url}/v1/traces`)),
        content: new NodeContentClient(target(`${node.url}/v1/logs`), { serviceName: SERVICE }),
        serviceName: SERVICE,
      });
      second.spool.tryLock();
      await second.drain();
      await second.drain();
      const delivered = node.bodies.filter((b) => b.path === "/v1/traces").map((b) => b.body);
      // The same spans, byte for byte: ids derive from the record, never from the sender.
      expect(delivered.at(-1)).toEqual(attempted[0]);
      const expected = encodeTraceRequest(
        spooled.map(({ doc }) => spanOfRecord(doc, { serviceName: SERVICE, version: SDK_VERSION })),
      );
      expect(delivered.at(-1)).toEqual(expected);
      // Every body went out with the exact spooled bytes (a resend is an idempotent replay).
      const logs = Buffer.concat(
        node.bodies.filter((b) => b.path === "/v1/logs").map((b) => b.body),
      );
      for (const { blob } of spooled) {
        expect(logs.includes(blob.subarray(0, 64))).toBe(true);
      }
      for (const { doc } of spooled) {
        const id = (doc.span as any).attributes["fabric.wire.exchange_id"] as string;
        expect(delivered.at(-1)!.includes(Buffer.from(id))).toBe(true);
      }
      // Another writer's records: retired as receipts for it.
      expect(second.spool.names()).toEqual([]);
      expect(readdirSync(dir).filter((name) => name.endsWith(".ack"))).toHaveLength(3);
    } finally {
      await proc.kill();
      writer.cleanup();
      await node.close();
    }
  });
});
