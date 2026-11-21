// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §9.5 (unit 055-t11): one test per seal-trigger row of spec 050 §3.6, every
 * `endRun` status literal of §4.3, the D30 outcome on the outermost `run_end`, and the
 * run table's fail-open bounds (slot exhaustion, lock timeout).
 */
import { spawnSync } from "node:child_process";

import { afterEach, describe, expect, it } from "vitest";

import { parseToken } from "../../../src/wire/p1.js";
import {
  activeRunTable,
  endRun,
  resumeToken,
  resumeTokens,
  run,
  setRunOutcome,
} from "../../../src/wire/run-api.js";
import { MAX_RUNS } from "../../../src/wire/runtime.js";

import { isolate } from "../runtime/helpers.js";
import { MANIFEST, SOURCE, TOKEN_VECTORS, entryOf, harness, unbind } from "./helpers.js";

afterEach(unbind);

describe("seal triggers (spec 050 §3.6, one test per row)", () => {
  it("resumeToken(): non-terminal, resumable, the run continues here after it", () => {
    const h = harness();
    const result = run({ runId: "trip" }, () => {
      const first = [h.alloc(), h.alloc()];
      const token = resumeToken()!;
      const after = h.alloc();
      return { first, token, after };
    });
    const [seal, last] = h.seals();
    const sealed = result.first[0]!.segment!;
    expect(result.first[1]!.segment).toBe(sealed);
    expect(seal).toMatchObject({
      segment: sealed,
      terminal: false,
      resumable: true,
      positions: "2",
      lastSequence: "1",
      branchIds: [],
      manifestDigest: MANIFEST.digest,
    });
    // The token names the sealed segment, the run's correlation id and this source.
    const parsed = parseToken(result.token)!;
    expect(parsed).toMatchObject({
      version: 3,
      correlation_id: seal!.runId,
      segment_id: sealed,
      source_id: SOURCE,
      epoch: h.runtime.epoch,
      last_sequence: 1n,
      manifest_digest: MANIFEST.digest,
    });
    // The continuation segment names the sealed one, and later calls belong to it.
    const [, continuation] = h.markers("run_start");
    expect(continuation!.predecessors).toEqual([entryOf(result.token)]);
    expect(result.after.segment).toBe(continuation!.segment_id);
    // The block exit then seals the continuation, non-terminal (a token made it resumable).
    expect(last).toMatchObject({
      segment: continuation!.segment_id,
      terminal: false,
      positions: "1",
    });
  });

  it("resumeTokens(n): one seal listing n branch ids, one token per branch", () => {
    const h = harness();
    const tokens = run({}, () => resumeTokens(3));
    const [seal] = h.seals();
    expect(tokens).toHaveLength(3);
    expect(seal!.branchIds).toEqual(tokens.map((t) => parseToken(t)!.branch_id));
    expect(new Set(tokens.map(entryOf))).toEqual(new Set([entryOf(tokens[0]!)]));
    expect(seal!.branchIds.every((b) => /^br-[0-9a-f]{32}$/.test(b))).toBe(true);
  });

  it("fork: a child process inherits nothing; it continues the run only from a token the app passes", () => {
    const parent = harness();
    const token = run({ runId: "pipeline" }, () => {
      const before = parent.seals().length;
      // child_process.fork/spawn start a fresh process: no seal, no inherited segment, and
      // the child's argv and environment are exactly what the application passed.
      const child = spawnSync(
        process.execPath,
        [
          "-e",
          "process.stdout.write(JSON.stringify({argv: process.argv.slice(1), env: process.env}))",
          "x",
        ],
        { env: { ONLY: "this" }, encoding: "utf8" },
      );
      const seen = JSON.parse(child.stdout) as { argv: string[]; env: Record<string, string> };
      expect(seen.argv).toEqual(["x"]);
      expect(Object.keys(seen.env).filter((k) => k !== "__CF_USER_TEXT_ENCODING")).toEqual([
        "ONLY",
      ]);
      expect(parent.seals()).toHaveLength(before);
      return resumeToken()!;
    });
    // The child process: its own runtime and epoch, given the token in FABRIC_RUN_RESUME_TOKEN.
    const child = harness({ runtime: isolate().runtime, envTokens: [token] });
    run({}, () => undefined);
    const [start] = child.markers("run_start");
    expect(start).toMatchObject({
      run_id: parseToken(token)!.correlation_id,
      id_basis: "token",
      predecessors: [entryOf(token)],
    });
    expect(child.runtime.epoch).not.toBe(parent.runtime.epoch);
  });

  it("outermost exit of a resumable run: non-terminal, unless the block is final", () => {
    const h = harness();
    run({ runId: "a", resumable: true }, () => {
      run({ runId: "a" }, () => h.alloc()); // an inner block of the same run seals nothing
      expect(h.seals()).toHaveLength(0);
    });
    expect(h.seals()).toHaveLength(1);
    expect(h.seals()[0]).toMatchObject({ terminal: false, resumable: true, positions: "1" });
    run({ runId: "b", resumable: true, final: true }, () => undefined);
    expect(h.seals()[1]).toMatchObject({ terminal: true, positions: "0" });
    // The root run_start carries the root-only fields.
    expect(h.markers("run_start")[0]).toMatchObject({ resumable: true, predecessors: ["none"] });
  });

  it("outermost exit of a non-resumable run: terminal; a later block is post-terminal, never a second root", () => {
    const h = harness();
    run({ runId: "once" }, () => h.alloc());
    expect(h.seals()[0]).toMatchObject({ terminal: true, resumable: false, positions: "1" });
    run({ runId: "once" }, () => h.alloc());
    const starts = h.markers("run_start");
    expect(starts[1]!.predecessors).toEqual([
      `${h.seals()[0]!.segment}/${SOURCE}/${h.runtime.epoch}/0/${MANIFEST.digest}`,
    ]);
    expect(h.table.stats().post_terminal_allocations).toBe(1);
  });

  it("endRun: a zero-width segment, run_start naming the tokens, run_end with the outcome, terminal seal", () => {
    const h = harness();
    const token = run({ runId: "job" }, () => resumeToken())!;
    h.messages.length = 0;
    expect(endRun({ outcome: "completed", stopReason: "goal_reached", resume: [token] })).toBe(
      "ended",
    );
    const [start] = h.markers("run_start");
    const [end] = h.markers("run_end");
    const [seal] = h.seals();
    expect(start).toMatchObject({ predecessors: [entryOf(token)], id_basis: "token" });
    expect(end).toMatchObject({
      outcome: "completed",
      stop_reason: "goal_reached",
      scope_status: "ok",
      segment_id: start!.segment_id,
      scope_id: start!.scope_id,
    });
    expect(seal).toMatchObject({ segment: start!.segment_id, terminal: true, positions: "0" });
  });

  it("final(): every open segment seals non-terminally, and nothing is accounted after it", () => {
    const h = harness();
    run({ runId: "open" }, () => {
      h.alloc();
      h.table.onFinal();
      expect(h.seals()).toEqual([expect.objectContaining({ terminal: false, positions: "1" })]);
    });
    // The block's exit after final adds nothing, and new blocks run uncaptured.
    expect(h.seals()).toHaveLength(1);
    expect(activeRunTable()).toBeUndefined();
    expect(run({ runId: "late" }, () => 7)).toBe(7);
    expect(h.markers("run_start")).toHaveLength(1);
  });
});

describe("endRun statuses (each literal of §4.3)", () => {
  const C1 = TOKEN_VECTORS.tokens[0]!.token;
  const C2 = TOKEN_VECTORS.run_identity.find((v) => v.rule === 3)!.inputs.tokens;

  it("ended: queued, from tokens of one run", () => {
    harness();
    expect(endRun({ outcome: "failed", resume: C1 })).toBe("ended");
  });
  it("refused_no_token: no valid token, nothing emitted", () => {
    const h = harness();
    expect(endRun({ outcome: "completed", resume: [] })).toBe("refused_no_token");
    expect(endRun({ outcome: "completed", resume: ["fr1/nope"] })).toBe("refused_no_token");
    expect(h.messages).toEqual([]);
  });
  it("refused_bad_token: resume is not tokens", () => {
    harness();
    expect(endRun({ outcome: "completed", resume: [1, 2] as never })).toBe("refused_bad_token");
  });
  it("refused_conflicting_tokens: tokens of different runs and no runId; a runId joins them", () => {
    const h = harness();
    expect(endRun({ outcome: "completed", resume: C2 })).toBe("refused_conflicting_tokens");
    expect(h.messages).toEqual([]);
    expect(endRun({ outcome: "completed", resume: C2, runId: "joined" })).toBe("ended");
    expect(h.markers("run_start")[0]!.id_basis).toBe("caller_join");
  });
  it("not_capturing: no run table bound", () => {
    expect(endRun({ outcome: "completed", resume: C1 })).toBe("not_capturing");
  });
  it("failed: a Fabric failure, never thrown to the caller", () => {
    const h = harness();
    h.table.end = () => {
      throw new Error("internal");
    };
    expect(endRun({ outcome: "completed", resume: C1 })).toBe("failed");
  });
  it("an outcome or stop reason outside D30 is misuse: failed, nothing emitted", () => {
    const h = harness();
    expect(endRun({ outcome: "done" as never, resume: C1 })).toBe("failed");
    expect(endRun({ outcome: "completed", stopReason: "bored" as never, resume: C1 })).toBe(
      "failed",
    );
    expect(h.messages).toEqual([]);
  });
});

describe("the D30 run outcome (setRunOutcome, internal)", () => {
  it("rides only on the outermost run_end of the run here; the last call wins", () => {
    const h = harness();
    run({ runId: "r" }, () => {
      run({ runId: "r" }, () => {
        expect(setRunOutcome("failed")).toBe(true);
      });
      expect(setRunOutcome("completed", "goal_reached")).toBe(true);
    });
    const [inner, outer] = h.markers("run_end");
    expect(inner!.outcome).toBeUndefined();
    expect(inner!.stop_reason).toBeUndefined();
    expect(outer).toMatchObject({ outcome: "completed", stop_reason: "goal_reached" });
    expect(setRunOutcome("completed")).toBe(false); // no open run
  });
});

describe("fail-open bounds of the run table", () => {
  it("past 256 live runs a block runs uncaptured and is counted", () => {
    const h = harness();
    const depth = (n: number): number =>
      n === 0 ? run({ runId: "extra" }, () => 42) : run({ runId: `r${n}` }, () => depth(n - 1));
    expect(depth(MAX_RUNS)).toBe(42);
    expect(h.table.stats().run_slots_exhausted).toBe(1);
    expect(h.markers("run_start")).toHaveLength(MAX_RUNS);
  });

  it("a run-table lock that cannot be taken leaves the segment unsealed, never sealed with a wrong count", () => {
    const h = harness();
    run({ runId: "busy" }, () => {
      h.alloc();
      // Another isolate holds the lock for longer than the try-lock spins.
      const held = h.runtime.i32;
      Atomics.store(held, 65, 99);
      try {
        expect(resumeToken()).toMatch(/^fr3\//);
      } finally {
        Atomics.store(held, 65, 0);
      }
    });
    const stats = h.table.stats();
    expect(stats.lock_timeouts).toBeGreaterThan(0);
    expect(stats.seals_unrequested).toBe(1);
    expect(h.seals()).toHaveLength(1); // only the exit's seal, taken with the lock
  });
});
