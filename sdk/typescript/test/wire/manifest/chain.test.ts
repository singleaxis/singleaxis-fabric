// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The manifest chain on the real allocator (spec 055 §7.2, §9.5 055-t9): manifest 0
 * before position 0, the contiguous counter and digest chain, state changes at exact
 * allocator boundaries (also under 8 concurrent producer isolates), post-final epochs,
 * prior unsealed epochs (bounded, exact count), heartbeats and the marker queue.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";

import { buildSync } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  CLASS_ORDER,
  HEARTBEAT_INTERVAL_MS,
  Heartbeats,
  MAX_LISTED_UNSEALED,
  MAX_PENDING_BEATS,
  ManifestChain,
  type MarkerEntry,
  MarkerQueue,
  emittedAt,
  finalMarker,
  markerSpan,
  unsealedPrior,
  withClass,
} from "../../../src/wire/manifest.js";
import { checkValue, manifestDigest, spanToManifest } from "../../../src/wire/p1.js";
import { WireRuntime, createRuntimeShared } from "../../../src/wire/runtime.js";
import { validHeader } from "../../../src/wire/spool-codec.js";
import { TELEMETRY_KEYS } from "../../../src/wire/telemetry-keys.generated.js";

import { norm, vector } from "../helpers.js";
import { runPython, templateOf } from "./helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const M0 = vector("manifest-chain-v1").manifests[0];
const header = (doc: Record<string, unknown>) => ({
  schema_version: "fabric.wire-spool-record/v1",
  order: 0,
  written_at_unix_nano: 0,
  ...doc,
});
const fieldsOf = (marker: MarkerEntry | undefined): Record<string, any> =>
  marker!.doc.marker as Record<string, any>;
const manifestOf = (marker: MarkerEntry | undefined): Record<string, any> =>
  spanToManifest(fieldsOf(marker).manifest);

function setup(epoch = 7n) {
  const runtime = new WireRuntime(createRuntimeShared({ epoch }), "installer");
  const chain = new ManifestChain(templateOf(M0));
  return { runtime, chain, epoch };
}

describe("manifest 0 and the chain on the allocator", () => {
  it("issues manifest 0 before position 0, at after_source_sequence -1", () => {
    const { runtime, chain, epoch } = setup();
    const zero = chain.initial(epoch);
    expect(runtime.nextSequence).toBe(0n);
    expect(fieldsOf(zero).last_sequence).toBe(-1);
    const doc = manifestOf(zero);
    expect(doc.manifest_seq).toBe(0);
    expect(doc.after_source_sequence).toBe(-1);
    expect(doc.previous_manifest_sha256).toBe(undefined);
    expect(doc.manifest_id).toMatch(UUID4);
    expect(doc.event_id).toMatch(UUID4);
    expect(doc.event_id).not.toBe(doc.manifest_id);
    expect(fieldsOf(zero).event_id).toBe(doc.event_id);
    expect(runtime.allocate().sequence).toBe(0n); // the first position follows it
  });

  it("chains a contiguous counter and digests at exact allocator boundaries", () => {
    const { runtime, chain, epoch } = setup();
    const markers = [chain.initial(epoch)];
    for (let n = 0; n < 5; n++) runtime.allocate();
    markers.push(chain.pointChanged(epoch, "mcp.client", "active", undefined, runtime.cut()!));
    for (let n = 0; n < 3; n++) runtime.allocate(0);
    markers.push(
      chain.pointChanged(epoch, "wire.py.httpx", "failed", "internal_error", runtime.cut()!),
    );
    // No allocation in between: the next change shares the cut, never goes back.
    markers.push(
      chain.pointChanged(epoch, "mcp.client", "disabled", "hook_disabled", runtime.cut()!),
    );
    const docs = markers.map(manifestOf);
    expect(docs.map((d) => d.manifest_seq)).toEqual([0, 1, 2, 3]);
    expect(docs.map((d) => d.after_source_sequence)).toEqual([-1, 4, 7, 7]);
    expect(markers.map((m) => fieldsOf(m).last_sequence)).toEqual([-1, 4, 7, 7]);
    for (let i = 1; i < docs.length; i++) {
      expect(docs[i]!.previous_manifest_sha256).toBe(manifestDigest(docs[i - 1]));
    }
    expect(chain.ref!.digest).toBe(manifestDigest(docs[3]));
    expect(new Set(docs.map((d) => d.event_id)).size).toBe(4);
    for (const marker of markers) expect(validHeader(header(marker!.doc), 0)).toBe(true);
  });

  it("never moves the effective position back for a stale cut", () => {
    const { chain, epoch } = setup();
    chain.initial(epoch);
    chain.pointChanged(epoch, "mcp.client", "active", undefined, 40n);
    const late = chain.pointChanged(epoch, "wire.py.httpx", "failed", "internal_error", 12n);
    expect(manifestOf(late).after_source_sequence).toBe(40);
  });

  it("starts a post-final epoch with its own manifest 0", () => {
    const { chain, epoch } = setup();
    chain.initial(epoch);
    chain.pointChanged(epoch, "mcp.client", "active", undefined, 3n);
    const next = chain.initial(epoch + 1n);
    const doc = manifestOf(next);
    expect([doc.source_epoch, doc.manifest_seq, doc.after_source_sequence]).toEqual([8, 0, -1]);
    expect(doc.previous_manifest_sha256).toBe(undefined);
    // The state in force carries over; a change in an epoch with no manifest 0 is that
    // epoch's manifest 0.
    expect(doc.capture_points.find((p: any) => p.id === "mcp.client").state).toBe("active");
    const other = chain.pointChanged(9n, "wire.py.httpx", "failed", "internal_error", 2n);
    expect([manifestOf(other).manifest_seq, manifestOf(other).after_source_sequence]).toEqual([
      0, -1,
    ]);
  });

  it("refuses an unknown point, state or reason without throwing", () => {
    const { chain, epoch } = setup();
    chain.initial(epoch);
    expect(chain.pointChanged(epoch, "wire.ts.undici", "active", undefined, 1n)).toBe(undefined);
    expect(chain.pointChanged(epoch, "mcp.client", "sleeping" as never, undefined, 1n)).toBe(
      undefined,
    );
    expect(chain.pointChanged(epoch, "mcp.client", "failed", "because", 1n)).toBe(undefined);
    expect(chain.internalErrors).toBe(3);
    expect(chain.ref!.manifestSeq).toBe(0);
  });

  it("keeps no state change that no manifest stated", () => {
    const { chain, epoch } = setup();
    chain.initial(epoch);
    // An epoch outside int64 cannot be assembled: the change is refused, not kept.
    const bad = 1n << 63n;
    expect(chain.pointChanged(bad, "mcp.client", "active", undefined, 3n)).toBe(undefined);
    expect(chain.classUncaptured(bad, "node_worker_unattached", 3n)).toBe(undefined);
    expect(chain.internalErrors).toBe(2);
    const later = manifestOf(
      chain.pointChanged(epoch, "wire.py.httpx", "failed", "internal_error", 9n),
    );
    const mcp = later.capture_points.find((p: any) => p.id === "mcp.client");
    expect([mcp.state, mcp.reason]).toEqual(["disabled", "hook_disabled"]); // as manifest 0
    expect(later.uncaptured_classes).not.toContain("node_worker_unattached");
  });

  it("a change that throws is no cut and never reaches the caller", () => {
    const { runtime } = setup();
    runtime.allocate();
    const cut = runtime.cut(() => {
      throw new Error("state word unavailable");
    });
    expect(cut).toBe(undefined);
    expect(runtime.nextSequence).toBe(1n); // the read-modify-write never ran
    expect(runtime.cut()).toBe(0n);
  });

  it("orders uncaptured classes as the manifest lists them", () => {
    expect(withClass(["node_http", "axios", "websocket"], "node_worker_unattached")).toEqual([
      "node_http",
      "node_worker_unattached",
      "axios",
      "websocket",
    ]);
    expect(withClass(["axios"], "node_http")).toEqual(["node_http", "axios"]);
    expect(withClass(["requests", "grpc"], "node_worker_unattached")).toEqual([
      "requests",
      "grpc",
      "node_worker_unattached",
    ]);
    expect(CLASS_ORDER).toContain("node_worker_unattached");
  });

  it("formats emitted_at as Python does (UTC, microseconds)", () => {
    expect(emittedAt(1_791_331_203_123_456_789n)).toBe("2026-10-07T00:00:03.123456Z"); // Python `_emitted_at`
    expect(emittedAt(0n)).toBe("1970-01-01T00:00:00.000000Z");
  });
});

describe("state changes at exact boundaries under concurrent producer isolates", () => {
  let dir: string;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "f055-t9-manifest-"));
    buildSync({
      entryPoints: [join(HERE, "fixtures", "boundary-producer.ts")],
      outdir: dir,
      outExtension: { ".js": ".cjs" },
      bundle: true,
      platform: "node",
      format: "cjs",
      target: "node22",
      logLevel: "silent",
    });
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("every position above the cut was allocated under the new state", async () => {
    const shared = createRuntimeShared({ epoch: 11n });
    const runtime = new WireRuntime(shared, "installer");
    const chain = new ManifestChain(templateOf(M0));
    chain.initial(11n);
    const start = new SharedArrayBuffer(8);
    const state = new SharedArrayBuffer(4);
    const each = 50_000;
    const producers = Array.from({ length: 8 }, () => {
      const worker = new Worker(join(dir, "boundary-producer.cjs"), {
        workerData: { shared, start, state, count: each },
      });
      return new Promise<{ sequences: BigInt64Array; seen: Int8Array }>((resolve, reject) => {
        worker.once("message", resolve);
        worker.once("error", reject);
      });
    });
    const words = new Int32Array(start);
    while (Atomics.load(words, 1) < 8) await new Promise((r) => setTimeout(r, 1));
    Atomics.store(words, 0, 1);
    // Let the producers run, then change the state while they allocate.
    while (runtime.nextSequence < 40_000n) await new Promise((r) => setImmediate(r));
    const cut = runtime.cut(() => Atomics.store(new Int32Array(state), 0, 1))!;
    const marker = chain.pointChanged(11n, "wire.py.httpx", "failed", "internal_error", cut);
    const results = await Promise.all(producers);

    expect(manifestOf(marker).after_source_sequence).toBe(Number(cut));
    expect(cut).toBeGreaterThanOrEqual(39_999n);
    expect(cut).toBeLessThan(BigInt(8 * each) - 1n); // the change landed mid-stream
    let above = 0;
    const all: bigint[] = [];
    for (const { sequences, seen } of results) {
      for (let n = 0; n < sequences.length; n++) {
        all.push(sequences[n]!);
        if (sequences[n]! > cut) {
          above++;
          expect(seen[n]).toBe(1);
        }
      }
    }
    expect(new Set(all).size).toBe(8 * each);
    expect(above).toBe(8 * each - Number(cut) - 1);
  }, 60_000);
});

describe("prior unsealed epochs", () => {
  it("lists at most 64, ascending and unique, with the exact count", () => {
    const epochs = Array.from({ length: 70 }, (_, i) => BigInt(1000 - i));
    const prior = unsealedPrior([...epochs, 990n], 71, 999n);
    expect(prior.epochs.length).toBe(MAX_LISTED_UNSEALED);
    expect(prior.epochs[0]).toBe(931n);
    expect(prior.epochs).toEqual([...prior.epochs].sort((a, b) => (a < b ? -1 : 1)));
    expect(prior.epochs).not.toContain(999n);
    expect(prior.count).toBe(69); // 70 epochs, the duplicate and the current one removed
  });

  it("keeps an exact count beyond what the scan listed", () => {
    // The registration scan lists 64 and counts every declaration (registration.ts).
    const listed = Array.from({ length: 64 }, (_, i) => BigInt(i + 1));
    const { chain } = setup();
    const doc = manifestOf(chain.initial(500n, { epochs: listed, count: 200 }));
    expect(doc.unsealed_prior_epochs.length).toBe(64);
    expect(doc.unsealed_prior_epoch_count).toBe(200);
    // Only manifest 0 declares them.
    const next = manifestOf(chain.pointChanged(500n, "mcp.client", "active", undefined, 0n));
    expect([next.unsealed_prior_epochs, next.unsealed_prior_epoch_count]).toEqual([[], 0]);
  });

  it("writes epochs above 2^53 as exact integers", () => {
    const big = (1n << 62n) + 1n;
    const { chain } = setup();
    const marker = chain.initial(5n, { epochs: [big], count: 1 });
    expect(fieldsOf(marker).manifest["fabric.manifest.unsealed_prior_epochs"]).toEqual([
      big.toString(),
    ]);
    expect(chain.document!.unsealed_prior_epochs).toEqual([big]);
  });
});

describe("heartbeats", () => {
  function clocked(intervalMs = HEARTBEAT_INTERVAL_MS) {
    const { chain, epoch } = setup();
    let now = 0;
    const beats = new Heartbeats(chain, { nowMs: () => now, intervalMs });
    return { chain, epoch, beats, advance: (ms: number) => (now += ms) };
  }

  it("beats every 30 s by default, only for a source that allocated", () => {
    const { chain, epoch, beats, advance } = clocked();
    chain.initial(epoch);
    beats.noteActivity();
    expect(beats.tick(epoch, 4n)).toBe(undefined); // not due yet
    advance(HEARTBEAT_INTERVAL_MS);
    const beat = beats.tick(epoch, 4n)!;
    expect([beat.kind, beat.lastSequence, beat.manifestSeq]).toEqual(["periodic", 4n, 0]);
    expect(beat.eventId).toMatch(UUID4);
    advance(HEARTBEAT_INTERVAL_MS);
    expect(beats.tick(epoch, 4n)).toBe(undefined); // no activity since
    expect(beats.tick(epoch, 4n, true)?.kind).toBe("periodic"); // a flush beats anyway
  });

  it("makes a source eligible when it allocated, spooled or not (Python note_activity)", () => {
    const { chain, epoch, beats, advance } = clocked();
    chain.initial(epoch);
    expect(beats.tick(epoch, -1n)).toBe(undefined); // nothing allocated yet
    advance(HEARTBEAT_INTERVAL_MS);
    expect(beats.tick(epoch, -1n)).toBe(undefined); // due, but no position: no beat
    // Positions 0..2 were allocated and lost (never spooled): still a beat at 2.
    advance(HEARTBEAT_INTERVAL_MS);
    expect(beats.tick(epoch, 2n)).toMatchObject({ kind: "periodic", lastSequence: 2n });
    advance(HEARTBEAT_INTERVAL_MS);
    expect(beats.tick(epoch, 2n)).toBe(undefined); // nothing allocated since
    // A new epoch with no position yet is not activity; its first position is.
    advance(HEARTBEAT_INTERVAL_MS);
    expect(beats.tick(epoch + 1n, -1n)).toBe(undefined);
    advance(HEARTBEAT_INTERVAL_MS);
    expect(beats.tick(epoch + 1n, 0n)).toMatchObject({ epoch: epoch + 1n, lastSequence: 0n });
  });

  it("carries the latest manifest_seq", () => {
    const { chain, epoch, beats, advance } = clocked();
    chain.initial(epoch);
    chain.pointChanged(epoch, "mcp.client", "active", undefined, 2n);
    beats.noteActivity();
    advance(HEARTBEAT_INTERVAL_MS);
    expect(beats.tick(epoch, 9n)!.manifestSeq).toBe(1);
    expect(beats.final(epoch, 9n)!.doc.marker).toMatchObject({ manifest_seq: 1 });
  });

  it("keeps each pending beat's event id until delivered, bounded", () => {
    const { chain, epoch, beats } = clocked(0);
    chain.initial(epoch);
    const first = beats.tick(epoch, 1n, true)!;
    const second = beats.tick(epoch, 2n, true)!;
    expect(beats.pending.map((b) => b.eventId)).toEqual([first.eventId, second.eventId]);
    beats.delivered(1);
    expect(beats.pending.map((b) => b.eventId)).toEqual([second.eventId]);
    for (let n = 0; n < MAX_PENDING_BEATS + 5; n++) beats.tick(epoch, 3n, true);
    expect(beats.pending.length).toBe(MAX_PENDING_BEATS);
    expect(beats.dropped).toBe(6);
  });

  it("spools one final heartbeat per epoch, never a periodic one", () => {
    const { chain, epoch, beats } = clocked();
    chain.initial(epoch);
    const final = beats.final(epoch, 41n)!;
    const fields = fieldsOf(final);
    expect(Object.keys(fields)).toEqual(["kind", "last_sequence", "manifest_seq", "event_id"]);
    expect(fields).toMatchObject({ kind: "final", last_sequence: 41, manifest_seq: 0 });
    expect(fields.event_id).toMatch(UUID4);
    expect(validHeader(header(final.doc), 0)).toBe(true);
    expect(beats.final(epoch, 41n)).toBe(undefined);
    const periodic = beats.tick(epoch, 41n, true)!;
    expect(() => finalMarker(periodic)).toThrow(/only a final/);
    // A spooled periodic marker is refused by the spool readers (055 §6.2).
    const doc = header({
      record_kind: "marker",
      source: { source_id: M0.source_id, source_epoch: 7 },
      marker: { kind: "periodic", last_sequence: 1, event_id: periodic.eventId },
    });
    expect(validHeader(doc, 0)).toBe(false);
  });

  it("exports heartbeats as Python's marker_span does, with the registry's checks", () => {
    const { chain, epoch, beats } = clocked();
    chain.initial(epoch);
    const all = [
      fieldsOf(beats.final(epoch, 3n)),
      {
        kind: "periodic",
        last_sequence: 3,
        manifest_seq: 0,
        event_id: beats.tick(epoch, 3n, true)!.eventId,
      },
    ];
    const python = runPython(
      "import json, sys\nfrom fabric._loss import marker_span\n" +
        "out = [marker_span(sys.argv[1], int(sys.argv[2]), f) for f in json.loads(sys.stdin.read())]\n" +
        "print(json.dumps(out))",
      [M0.source_id, String(epoch)],
      JSON.stringify(all),
    );
    all.forEach((fields, index) => {
      const [name, attributes] = markerSpan(M0.source_id, epoch, fields);
      expect([name, norm(attributes)]).toEqual(norm(python[index]));
      expect(attributes["fabric.capture.manifest_seq"]).toBe(0);
      for (const [key, value] of Object.entries(attributes)) {
        const check = TELEMETRY_KEYS[key]?.check;
        if (check !== undefined) expect(checkValue(check, value), key).toBe(true);
      }
      expect("fabric.capture.input" in attributes).toBe(false);
    });
  });
});

describe("the marker queue", () => {
  const marker = (n: number): MarkerEntry => ({ doc: { n }, bodies: [] });

  it("spools a prefix, in order, into the reserve, and retries the rest", () => {
    const queue = new MarkerQueue();
    for (let n = 0; n < 4; n++) queue.queue(marker(n));
    const written: number[] = [];
    let refuse = 2;
    const spool = {
      writeBatch(records: readonly { doc: Record<string, unknown> }[], reserve?: boolean) {
        expect(reserve).toBe(true);
        expect(records.length).toBe(1);
        const n = records[0]!.doc.n as number;
        if (n === refuse) return [null];
        written.push(n);
        return [`rec-${n}`];
      },
    };
    expect(queue.pump(spool as never)).toBe(2);
    expect(written).toEqual([0, 1]); // 3 never overtakes the refused 2
    refuse = -1;
    expect(queue.pump(spool as never)).toBe(2);
    expect(written).toEqual([0, 1, 2, 3]);
    expect([queue.held.length, queue.spooled]).toEqual([0, 4]);
  });

  it("holds a marker whose write failed and survives a throwing spool", () => {
    const queue = new MarkerQueue();
    queue.queue(marker(0));
    const failing = { writeBatch: () => [new Error("EIO")] };
    expect(queue.pump(failing as never)).toBe(0);
    const throwing = {
      writeBatch: () => {
        throw new Error("boom");
      },
    };
    expect(queue.pump(throwing as never)).toBe(0);
    expect(queue.held.length).toBe(1);
    expect(queue.queue(undefined)).toBe(false);
  });
});
