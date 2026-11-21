// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §9.5 (unit 055-t11), §4.3 "Run identity", "Tokens": the five identity rules
 * with `id_basis` (the shared vectors, then through `run()`), token accept/reject vectors
 * through `run({resume})`, fan-in, and same-host `FABRIC_RUN_ID` /
 * `FABRIC_RUN_RESUME_TOKEN`.
 */
import { afterEach, describe, expect, it } from "vitest";

import { resolveConfig } from "../../../src/wire/config.js";
import { runPseudonym } from "../../../src/wire/p1.js";
import {
  bindRunTable,
  createRunTable,
  endRun,
  resumeToken,
  resumeTokens,
  run,
} from "../../../src/wire/run-api.js";
import {
  IdentityRule,
  TOKEN_DROPPED_WARNING,
  resolveIdentity,
} from "../../../src/wire/segments.js";

import { isolate } from "../runtime/helpers.js";
import {
  SOURCE,
  TOKEN_VECTORS,
  VECTOR_KEY,
  entryOf,
  harness,
  ringMessages,
  unbind,
} from "./helpers.js";

afterEach(unbind);

const TOKEN = (name: string): string => TOKEN_VECTORS.tokens.find((t) => t.name === name)!.token;
const C1 = TOKEN("pseudonymous correlation id");
const LEGACY = TOKEN("legacy fr2 token (parsed for one release)");

describe("the five run-identity rules (resume-token-v2 run_identity)", () => {
  for (const vector of TOKEN_VECTORS.run_identity) {
    it(`rule ${vector.rule}: ${vector.name}`, () => {
      const { inputs, expected } = vector;
      const rule = new IdentityRule({
        key: inputs.key === null ? undefined : Buffer.from(inputs.key, "utf8"),
        mode: inputs.identity_mode,
      });
      const identity = resolveIdentity(
        inputs.tokens,
        inputs.run_id ?? undefined,
        (value) => (inputs.run_id_emitted ? value : rule.run(value)),
        () => inputs.minted,
      );
      expect({
        run_id: identity.runId,
        id_basis: identity.idBasis,
        predecessors: identity.predecessors,
        branch_ids: identity.branchIds,
        tokens_rejected: identity.tokensRejected,
      }).toEqual(expected);
    });
  }
});

describe("run() decides its run id once, at segment open, and emits id_basis", () => {
  it("(1) tokens of one correlation id: that id verbatim, a clear runId ignored (token)", () => {
    const h = harness();
    run({ resume: [C1], runId: "clear-order-id" }, () => undefined);
    const [start] = h.markers("run_start");
    expect(start).toMatchObject({
      run_id: "r-7caf7c2d19b76858b22ffcd4ce3fcbde",
      id_basis: "token",
    });
    expect(start!.predecessors).toEqual([entryOf(C1)]);
    expect(JSON.stringify(h.messages)).not.toContain("clear-order-id");
  });

  it("(2) caller_join and (3) token_conflict through run()", () => {
    const a = harness();
    const tokenA = run({ runId: "agent-a" }, () => resumeToken())!;
    const tokenB = run({ runId: "agent-b" }, () => resumeToken())!;
    a.messages.length = 0;
    run({ resume: [tokenA, tokenB], runId: "fan-in" }, () => undefined);
    const [join] = a.markers("run_start");
    expect(join).toMatchObject({
      run_id: runPseudonym("fan-in", VECTOR_KEY),
      id_basis: "caller_join",
      predecessors: [entryOf(tokenA), entryOf(tokenB)],
    });
    a.messages.length = 0;
    run({ resume: [tokenA, tokenB] }, () => undefined);
    const [conflict] = a.markers("run_start");
    const lowest = [
      runPseudonym("agent-a", VECTOR_KEY),
      runPseudonym("agent-b", VECTOR_KEY),
    ].sort()[0];
    expect(conflict).toMatchObject({ run_id: lowest, id_basis: "token_conflict" });
  });

  it("(4) no valid token, a clear runId: the mapped clear id (caller), never the clear value", () => {
    const h = harness();
    run({ runId: "run-travel-42" }, () => undefined);
    const [start] = h.markers("run_start");
    expect(start).toMatchObject({
      run_id: "r-93347307304ecb0a9bb1b51ae90ac326", // the vector's mapping
      id_basis: "caller",
      predecessors: ["none"],
      resumable: false,
    });
    expect(JSON.stringify(h.messages)).not.toContain("run-travel-42");
  });

  it("(5) neither: a minted r- id from the CSPRNG (minted)", () => {
    const h = harness();
    run({}, () => undefined);
    run({}, () => undefined);
    const ids = h.markers("run_start").map((m) => m.run_id);
    expect(h.markers("run_start").map((m) => m.id_basis)).toEqual(["minted", "minted"]);
    for (const id of ids) expect(id).toMatch(/^r-[0-9a-f]{32}$/);
    expect(ids[0]).not.toBe(ids[1]);
  });

  it("clear mode emits a caller id as given, an h- form outside the opaque pattern, and still mints", () => {
    const h = harness({ identityMode: "clear" });
    run({ runId: "run-travel-42" }, () => undefined);
    run({ runId: "orders/42" }, () => undefined);
    run({}, () => undefined);
    expect(h.markers("run_start").map((m) => [m.run_id, m.id_basis])).toEqual([
      ["run-travel-42", "caller"],
      ["h-c4dd165f06c35f87f80d9c755d8703efce751ab5", "caller"],
      [expect.stringMatching(/^r-[0-9a-f]{32}$/), "minted"],
    ]);
  });

  it("a run's correlation id is copied into every token, so A -> B -> C keeps one run id", () => {
    const h = harness();
    const fromA = run({ runId: "trip" }, () => resumeToken())!;
    const fromB = run({ resume: fromA }, () => resumeToken())!; // B could be lost entirely
    run({ resume: fromB }, () => undefined);
    const ids = new Set(h.markers("run_start").map((m) => m.run_id));
    expect(ids).toEqual(new Set([runPseudonym("trip", VECTOR_KEY)]));
    expect(fromB.split("/")[1]).toBe(runPseudonym("trip", VECTOR_KEY));
  });
});

describe("token accept/reject vectors through run({resume})", () => {
  for (const vector of TOKEN_VECTORS.tokens) {
    it(`${vector.parsed === null ? "rejects" : "accepts"}: ${vector.name}`, () => {
      const clear = vector.name.startsWith("clear-mode");
      const h = harness(clear ? { identityMode: "clear" } : {});
      run({ resume: [vector.token], runId: "fallback-run" }, () => undefined);
      const [start] = h.markers("run_start");
      const stats = h.table.stats();
      if (vector.parsed === null) {
        expect(start!.predecessors).toEqual(["none"]);
        expect(start!.id_basis).toBe("caller");
        expect(stats.tokens_rejected).toBe(vector.token === "" ? 0 : 1);
      } else {
        expect(start!.predecessors).toEqual([entryOf(vector.token)]);
        expect(stats.tokens_rejected).toBe(0);
        const legacy = vector.parsed.version === 2;
        expect(start!.id_basis).toBe(legacy ? "legacy" : "token");
        if (!legacy) expect(start!.run_id).toBe(vector.parsed.correlation_id);
        if (vector.parsed.branch_id !== null)
          expect(start!.branch_ids).toEqual([vector.parsed.branch_id]);
      }
    });
  }

  it("a pseudonymous consumer refuses a clear correlation id (R8); a clear one takes it", () => {
    const clearToken = TOKEN("clear-mode correlation id");
    const pseudonymous = harness();
    run({ resume: clearToken }, () => undefined);
    expect(pseudonymous.markers("run_start")[0]).toMatchObject({
      predecessors: ["none"],
      id_basis: "minted",
    });
    expect(pseudonymous.table.stats().tokens_rejected).toBe(1);
    const clear = harness({ identityMode: "clear" });
    run({ resume: clearToken }, () => undefined);
    expect(clear.markers("run_start")[0]).toMatchObject({
      run_id: "billing-run.42:eu",
      id_basis: "token",
    });
  });

  it("a dropped token is counted and warned about once, by class and fix, never by value", async () => {
    const h = harness();
    const bad = "fr3/r-" + "ee".repeat(16) + "/not-a-segment";
    run({ resume: bad }, () => undefined);
    run({ resume: [bad, "fr9/x"] }, () => undefined);
    expect(endRun({ outcome: "completed", resume: bad })).toBe("refused_no_token");
    expect(h.table.stats().tokens_rejected).toBe(4);
    expect(h.warnings).toEqual([TOKEN_DROPPED_WARNING]);
    expect(TOKEN_DROPPED_WARNING).toMatch(/MalformedResumeToken/);
    expect(TOKEN_DROPPED_WARNING).toMatch(/resumeToken\(\)/); // the fix
    expect(h.warnings.join()).not.toContain("ee".repeat(16));
    // The default goes to process.emitWarning (a FabricWarning), never thrown.
    const seen: Error[] = [];
    const listener = (w: Error): void => void seen.push(w);
    process.on("warning", listener);
    try {
      const d = harness({ warn: undefined });
      run({ resume: bad }, () => undefined);
      expect(d.table.stats().tokens_rejected).toBe(1);
      await new Promise((resolve) => setImmediate(resolve));
    } finally {
      process.off("warning", listener);
    }
    expect(seen.map((x) => [x.name, (x as { code?: string }).code, x.message])).toEqual([
      ["FabricWarning", "FABRIC_RESUME_TOKEN_DROPPED", TOKEN_DROPPED_WARNING],
    ]);
    const w = harness({ warn: () => { throw new Error("listener"); } });
    expect(run({ resume: bad }, () => 5)).toBe(5);
    expect(w.table.stats().tokens_rejected).toBe(1);
  });

  it("a comma-separated join is split as the reference does; one entry counts once", () => {
    const h = harness();
    const zero = TOKEN("zero-width segment");
    run({ resume: `${C1}, ${zero},${LEGACY}` }, () => undefined);
    // LEGACY names C1's segment: one predecessor entry, whatever the token's version.
    expect(h.markers("run_start")[0]!.predecessors).toEqual([entryOf(C1), entryOf(zero)]);
  });

  it("issued tokens and branch tokens parse back to the sealed segment", () => {
    const h = harness();
    const [one, branches] = run({ runId: "issuer" }, () => [resumeToken()!, resumeTokens(3)]);
    expect(one).toMatch(/^fr3\/r-[0-9a-f]{32}\/seg-[0-9a-f]{32}\//);
    expect(new Set(branches.map(entryOf)).size).toBe(1);
    expect(branches.map((t) => t.split("/").at(-1))).toEqual(h.seals()[1]!.branchIds);
  });
});

describe("FABRIC_RUN_ID and FABRIC_RUN_RESUME_TOKEN (same host, read once at install)", () => {
  const env = (extra: Record<string, string>) => ({
    FABRIC_WIRE_ID_KEY: VECTOR_KEY.toString("utf8"),
    ...extra,
  });

  it("FABRIC_RUN_ID is taken by every run() without a runId, mapped, never emitted clear", () => {
    const settings = resolveConfig({}, env({ FABRIC_RUN_ID: "clear-order-id" }));
    const { runtime } = isolate();
    bindRunTable(createRunTable(runtime, settings, { sourceId: SOURCE }));
    run({}, () => undefined);
    run({ runId: "explicit" }, () => undefined);
    const sent = ringMessages(runtime);
    const starts = sent.flatMap((m) =>
      m.t === "marker" && m.fields.kind === "run_start" ? [m.fields] : [],
    );
    expect(starts.map((m) => [m.run_id, m.id_basis])).toEqual([
      [runPseudonym("clear-order-id", VECTOR_KEY), "caller"],
      [runPseudonym("explicit", VECTOR_KEY), "caller"],
    ]);
    expect(JSON.stringify(sent)).not.toContain("clear-order-id");
  });

  it("FABRIC_RUN_RESUME_TOKEN is consumed once, by the first outermost run() without resume", () => {
    const settings = resolveConfig({}, env({ FABRIC_RUN_RESUME_TOKEN: `${C1},not-a-token` }));
    expect(settings.resumeTokens).toEqual([C1, "not-a-token"]);
    const h = harness({ envTokens: settings.resumeTokens });
    run({}, () => run({}, () => undefined)); // the nested block does not consume it
    run({}, () => undefined);
    const starts = h.markers("run_start");
    expect(starts[0]).toMatchObject({ id_basis: "token", predecessors: [entryOf(C1)] });
    expect(starts[1]).toMatchObject({ id_basis: "minted", predecessors: ["none"] });
    expect(starts[2]).toMatchObject({ id_basis: "minted", predecessors: ["none"] });
    expect(h.table.stats().tokens_rejected).toBe(1);
  });

  it("an explicit resume leaves the environment tokens for a later root", () => {
    const h = harness({ envTokens: [C1] });
    run({ resume: [] }, () => undefined);
    run({}, () => undefined);
    expect(h.markers("run_start").map((m) => m.id_basis)).toEqual(["minted", "token"]);
  });
});
