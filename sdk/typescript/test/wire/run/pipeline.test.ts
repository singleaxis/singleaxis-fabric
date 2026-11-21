// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §9.5 (unit 055-t11) through the Fabric worker: run markers and seal requests
 * cross the run ring, the pipeline spools the markers and builds the seals, and Python's
 * drainer reads every record; a model call made inside `run()` carries the run's id and
 * scope and settles in the run's segment; the worker rolls a segment at the forced bound;
 * Python continues a run from a TypeScript token.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { sealDigest } from "../../../src/wire/p1.js";
import { captureScope, endRun, resumeToken, run } from "../../../src/wire/run-api.js";
import type { WireRuntime } from "../../../src/wire/runtime.js";
import { exchangeSealEntry, segmentIdOf } from "../../../src/wire/seal.js";
import { Spool } from "../../../src/wire/spool.js";
import { CapturePipeline, pipelineHandlers, runtimeSink } from "../../../src/wire/worker.js";
import type { ExchangeTable } from "../../../src/wire/exchange.js";

import { isolate } from "../runtime/helpers.js";
import { pipelineConfig, pythonReads, spooledDocs } from "../seal/helpers.js";
import { KEY, cleanupDirs, native, runPython, spoolDir } from "../spool/helpers.js";
import {
  CHAT,
  PUBLISHES_BODIES,
  type Capture,
  type Provider,
  capture,
  provider,
  settle,
} from "../undici/helpers.js";
import { SOURCE, VECTOR_KEY, entryOf, harness, unbind } from "./helpers.js";

let server: Provider;
let cap: Capture | undefined;
beforeAll(async () => {
  server = await provider();
  server.route(CHAT, (_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"choices":[]}');
  });
});
afterAll(async () => {
  await server.close();
  cleanupDirs();
});
afterEach(() => {
  unbind();
  cap?.close();
  cap = undefined;
});

function newPipeline(runtime: WireRuntime, overrides: Parameters<typeof pipelineConfig>[0] = {}) {
  const dir = spoolDir();
  const spool = new Spool(dir, { maxBytes: 1 << 22, addon: native().addon, key: KEY });
  const pipeline = new CapturePipeline(pipelineConfig(overrides), spool, runtimeSink(runtime));
  return { dir, spool, pipeline };
}

/** One pass of the Fabric worker's loop over what is queued, as `consume` runs it. */
async function workerPass(pipeline: CapturePipeline, runtime: WireRuntime, table: ExchangeTable) {
  const handlers = pipelineHandlers(pipeline);
  const context = { runtime, exchanges: table, snapshot: undefined };
  const ring = runtime.runRing!;
  const runs = async () => {
    for (let r = ring.peek(); r !== undefined; r = ring.peek()) {
      await handlers.run!(r.body, context);
      ring.commit();
    }
  };
  await runs();
  for (let record = runtime.jobs.peek(); record !== undefined; record = runtime.jobs.peek()) {
    await runs();
    const job = table.job(record.byteOffset);
    await handlers.job!(job, context);
    table.arena.release(job.request.words);
    table.arena.release(job.response.words);
    runtime.jobs.commit();
  }
  await runs();
  for (let loss = runtime.peekLoss(); loss !== undefined; loss = runtime.peekLoss()) {
    await handlers.loss!(loss, context);
    runtime.commitLoss();
  }
  await handlers.tick!(context);
}

/**
 * Python's segment graph (`fabric.reconstruct._graph`) over the run markers and seals in
 * the spool: one entry per run with its state, deciding rule and gap reasons.
 */
const PY_GRAPH = `
import datetime, json, sys
from fabric.wire._spool import Spool, unframe_all
from fabric.reconstruct._graph import SegmentNode, build_run_graphs
spool = Spool(sys.argv[1], 1 << 20, key=bytes.fromhex(sys.argv[2]))
starts, seals = {}, {}
try:
    for name in spool.names():
        for doc, _ in unframe_all(spool.read(name)):
            marker = doc.get("marker") or {}
            if marker.get("kind") == "run_start":
                starts[marker["segment_id"]] = (doc["source"], marker)
            elif marker.get("kind") == "segment_seal":
                seals[marker["segment_id"]] = marker
finally:
    spool.release()
nodes = []
for i, (segment, (source, m)) in enumerate(sorted(starts.items())):
    seal = seals.get(segment)
    nodes.append(SegmentNode(
        segment_id=segment, run_id=m["run_id"], source_id=source["source_id"],
        epoch=source["source_epoch"], predecessors=tuple(m.get("predecessors", ())),
        id_basis=m.get("id_basis"), branch_ids=tuple(m.get("branch_ids", ())),
        start_ns=1 + i, start_resumable=m.get("resumable"),
        last_sequence=None if seal is None else seal["seal"]["last_sequence"],
        terminal=None if seal is None else seal["terminal"],
        resumable=None if seal is None else seal.get("resumable", False),
        issued_branch_ids=() if seal is None else tuple(seal["seal"].get("branch_ids", ())),
        manifest_digest=None if seal is None else seal["seal"]["manifest_digest"],
        sealed_ns=None if seal is None else 100 + i,
    ))
graphs = build_run_graphs(nodes, evaluated_at=datetime.datetime(2026, 1, 1))
print(json.dumps([{"run_id": g.run_id, "state": g.run_state, "rule": g.rule,
                   "gaps": [gap.reason for gap in g.gaps]} for g in graphs]))
`;

function pythonRunGraphs(dir: string): any[] {
  return runPython(PY_GRAPH, [dir, KEY.toString("hex")]) as any[];
}

describe("run markers and seals through the Fabric worker", { timeout: 60_000 }, () => {
  it("are spooled as Python writes them, and Python's drainer reads every record", async () => {
    const { runtime, table } = isolate();
    const h = harness({ runtime, key: VECTOR_KEY, manifest: undefined });
    const { dir, spool, pipeline } = newPipeline(runtime);
    await workerPass(pipeline, runtime, table); // manifest 0, published to the control block
    const token = run({ runId: "trip", sessionId: "s-1" }, () => resumeToken()!);
    expect(endRun({ outcome: "completed", stopReason: "goal_reached", resume: token })).toBe(
      "ended",
    );
    await workerPass(pipeline, runtime, table);
    expect(pipeline.closeEpoch(runtime.epoch, runtime.nextSequence - 1n)).toBe(true);
    const docs = spooledDocs(spool);
    const kinds = docs.map((d) => d.marker?.kind ?? d.record_kind);
    // The continuation resumeToken() opened stayed empty, so the block's exit dropped it:
    // no run_start, no seal (as Python, which opens none), and its run_end names none.
    expect(kinds).toEqual([
      "manifest",
      "run_start",
      "run_end",
      "run_start",
      "run_end",
      "segment_seal",
      "segment_seal",
      "final",
    ]);
    expect(docs[2]!.marker.segment_id).toBeUndefined();
    expect(pipeline.stats().runs.held_discarded).toBe(1);
    // The run table named the manifest the worker published (no NO_MANIFEST digest).
    const manifestId = docs[0]!.marker.manifest["fabric.capture.manifest_id"];
    expect(docs[1]!.marker.manifest_id).toBe(manifestId);
    expect(docs[1]!.marker.manifest_digest).toBe(entryOf(token).split("/").at(-1));
    expect(h.table.stats().messages_dropped).toBe(0);
    // Every marker event id is a persisted uuid4, distinct.
    const ids = docs.map((d) => d.marker.event_id);
    expect(new Set(ids).size).toBe(ids.length);
    // Python's drainer accepts each record and exports the run keys.
    const read = pythonReads(dir);
    expect(read.every((r) => r.ok)).toBe(true);
    const spans = read.filter((r) => r.marker === "run_start").map((r) => r.span[1]);
    expect(spans[0]).toMatchObject({
      "fabric.run.id": docs[1]!.marker.run_id,
      "fabric.run.id_basis": "caller",
      "fabric.run.predecessors": ["none"],
      "fabric.session_id": expect.stringMatching(/^sess-[0-9a-f]{32}$/),
    });
    const seals = read.filter((r) => r.marker === "segment_seal").map((r) => r.span[1]);
    expect(seals.map((s) => s["fabric.run.terminal"])).toEqual([false, true]);
    // An empty segment seals [] (zero-width).
    expect(seals[1]["fabric.segment.seal_digest"]).toBe(sealDigest([]));
    // Python's segment graph (049 §2.10 G1-G10) reads the run as terminated by G5.
    expect(pythonRunGraphs(dir)).toEqual([
      { run_id: docs[1]!.marker.run_id, state: "terminated", rule: "G5", gaps: [] },
    ]);
  });

  it("a run_start naming 64 predecessors crosses the ring in parts", async () => {
    const { runtime, table } = isolate();
    harness({ runtime, manifest: undefined });
    const { spool, pipeline } = newPipeline(runtime);
    await workerPass(pipeline, runtime, table);
    const tokens = Array.from({ length: 64 }, (_, i) =>
      run({ runId: `agent-${i}` }, () => resumeToken()!),
    );
    run({ resume: tokens, runId: "fan-in" }, () => undefined);
    await workerPass(pipeline, runtime, table);
    const join = spooledDocs(spool).find(
      (d) => d.marker?.kind === "run_start" && d.marker.id_basis === "caller_join",
    );
    expect(join!.marker.predecessors).toEqual(tokens.map(entryOf));
  });

  it.skipIf(!PUBLISHES_BODIES)(
    "a model call inside run() carries the run's id and scope and settles in its segment",
    async () => {
      cap = capture(server.port, { scope: captureScope });
      const { runtime, table } = cap;
      const h = harness({ runtime, manifest: undefined });
      const { spool, pipeline } = newPipeline(runtime);
      await workerPass(pipeline, runtime, table);
      await run({ runId: "agent" }, async () => {
        const response = await fetch(`${server.base}${CHAT}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: '{"model":"gpt-4o"}',
        });
        await response.arrayBuffer();
        await settle();
      });
      await workerPass(pipeline, runtime, table);
      await workerPass(pipeline, runtime, table);
      const docs = spooledDocs(spool);
      const [start] = h.markers("run_start");
      const [end] = h.markers("run_end");
      const exchange = docs.find((d) => d.record_kind === "exchange")!;
      expect(exchange.span.attributes).toMatchObject({
        "fabric.run.id": start!.run_id,
        "fabric.run.scope_id": end!.scope_id,
        "fabric.run.segment_id": start!.segment_id,
      });
      const seal = docs.find((d) => d.marker?.kind === "segment_seal")!;
      expect(seal.marker.seal.seal_digest).toBe(
        sealDigest([
          [exchange.span.attributes["fabric.source.sequence"], exchangeSealEntry(exchange.span)],
        ]),
      );
      expect(seal.marker).toMatchObject({ terminal: true, segment_id: start!.segment_id });
    },
  );

  it("the worker rolls a segment at the forced bound; the run continues in the new one", async () => {
    const { runtime, table } = isolate();
    const h = harness({ runtime, manifest: undefined });
    const { spool, pipeline } = newPipeline(runtime, { forcedSealPositions: 3 });
    await workerPass(pipeline, runtime, table);
    await run({ runId: "long" }, async () => {
      const first = [h.alloc(), h.alloc(), h.alloc(), h.alloc()];
      // Each position is settled (here as a loss) by the worker's loss funnel.
      for (const a of first)
        runtime.lose("internal_error", a.sequence, ...segmentHalves(a.segment!));
      await workerPass(pipeline, runtime, table); // the tick sees 4 >= 3 and rolls
      const next = h.alloc();
      expect(next.segment).not.toBe(first[0]!.segment);
      runtime.lose("internal_error", next.sequence, ...segmentHalves(next.segment!));
    });
    await workerPass(pipeline, runtime, table);
    expect(pipeline.stats().runs.forced_rolls).toBe(1);
    const docs = spooledDocs(spool).filter((d) => d.record_kind === "marker");
    const starts = docs.filter((d) => d.marker.kind === "run_start");
    const seals = docs.filter((d) => d.marker.kind === "segment_seal");
    expect(starts).toHaveLength(2);
    expect(starts[1]!.marker.predecessors[0]).toMatch(
      new RegExp(`^${starts[0]!.marker.segment_id}/`),
    );
    expect(starts[1]!.marker).toMatchObject({
      run_id: starts[0]!.marker.run_id,
      id_basis: "caller",
    });
    expect(seals.map((s) => [s.marker.segment_id, s.marker.terminal])).toEqual([
      [starts[0]!.marker.segment_id, false],
      [starts[1]!.marker.segment_id, true],
    ]);
    expect(seals[0]!.marker.seal.seal_digest).toBe(
      sealDigest([0n, 1n, 2n, 3n].map((s) => [s, "loss:internal_error"] as const)),
    );
  });

  it("a held continuation's run_start is spooled with the first record of its segment", async () => {
    const { runtime, table } = isolate();
    const h = harness({ runtime, manifest: undefined });
    const { dir, spool, pipeline } = newPipeline(runtime);
    await workerPass(pipeline, runtime, table);
    const startsSpooled = (): Record<string, any>[] =>
      spooledDocs(spool).filter((d) => d.marker?.kind === "run_start");
    await run({ runId: "relay" }, async () => {
      resumeToken();
      await workerPass(pipeline, runtime, table);
      expect(startsSpooled()).toHaveLength(1); // the continuation's is held
      const call = h.alloc();
      runtime.lose("internal_error", call.sequence, ...segmentHalves(call.segment!));
      await workerPass(pipeline, runtime, table); // the loss names it: spooled now
      expect(startsSpooled().map((d) => d.marker.segment_id)).toEqual([
        expect.any(String),
        call.segment,
      ]);
    });
    await workerPass(pipeline, runtime, table);
    const starts = startsSpooled();
    expect(starts).toHaveLength(2);
    const seals = spooledDocs(spool).filter((d) => d.marker?.kind === "segment_seal");
    expect(seals.map((d) => [d.marker.segment_id, d.marker.terminal])).toEqual([
      [starts[0]!.marker.segment_id, false],
      [starts[1]!.marker.segment_id, false],
    ]);
    expect(pipeline.stats().runs.held_discarded).toBe(0);
    // A linear chain: no conflict or missing segment for Python's graph (the run is
    // resumable and has no terminal, so it is open or unterminated, by the deadline).
    const [graph] = pythonRunGraphs(dir);
    expect(graph.rule).toBe("G10");
    expect(graph.gaps).toEqual(["deadline_passed"]); // G10 only: start times are 1970
  });

  it("Python continues a run from a TypeScript token: same run id, the sealed segment as predecessor", () => {
    harness();
    const token = run({ runId: "cross-language" }, () => resumeToken()!);
    const out = runPython(
      `
import json, sys
from fabric._segments import parse_token, resolve_identity
t = parse_token(sys.argv[1])
i = resolve_identity([sys.argv[1]], None, map_run=lambda v: v, mint=lambda: "r-" + "0" * 32)
print(json.dumps({"ok": t is not None, "run_id": i.run_id, "basis": i.id_basis, "preds": list(i.predecessors)}))
`,
      [token],
    );
    expect(out).toEqual({
      ok: true,
      run_id: token.split("/")[1],
      basis: "token",
      preds: [entryOf(token)],
    });
    expect(token.split("/")[3]).toBe(SOURCE);
  });
});

function segmentHalves(segment: string): [bigint, bigint] {
  const hex = segment.slice(4);
  const out: [bigint, bigint] = [
    BigInt.asIntN(64, BigInt("0x" + hex.slice(0, 16))),
    BigInt.asIntN(64, BigInt("0x" + hex.slice(16))),
  ];
  if (segmentIdOf(...out) !== segment) throw new Error("bad segment");
  return out;
}
