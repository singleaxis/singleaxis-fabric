// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 049 §8.2 TS-0, spec 055 §4.3 and §6.1 (unit 055-t2): the audit and regression gate
// for today's explicit producers (decision.ts, calls.ts, byte-evidence.ts) before the
// records bridge (055-t20) routes them through the wire runtime.
//
// - identity parity: the decision line emits the ids Python computes for the same caller
//   values (shared vectors pseudonym-v2 and spool-bytes-v1), clear only in clear mode;
// - new-key parity: every registered key the decision line emits passes the key's
//   registry check (what the Fabric Node admits), and no explicit producer stamps a key
//   only the wire or records input may set (an unsequenced span never claims a position);
// - the inventory of automatic String()/JSON.stringify of application values (R9);
// - cross-language id privacy canaries: a clear caller id never leaves through the
//   decision line or the P1 run-identity functions, and the mapped value is Python's.
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  AlwaysOnSampler,
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-node";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Fabric, type Decision } from "../../../src/index.js";
import { checkValue, runIdentity } from "../../../src/wire/p1.js";
import { TELEMETRY_KEYS } from "../../../src/wire/telemetry-keys.generated.js";
import { REPO, cases, contract, vector } from "../helpers.js";

const providers: BasicTracerProvider[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(providers.splice(0).map((p) => p.shutdown()));
});

function harness(options: {
  identityMode: "pseudonymous" | "clear";
  idKey?: string;
  agentName?: string;
}) {
  vi.stubEnv("FABRIC_WIRE_ID_KEY", "");
  vi.stubEnv("FABRIC_WIRE_LABELS", "");
  const exporter = new InMemorySpanExporter();
  const provider = new BasicTracerProvider({
    sampler: new AlwaysOnSampler(),
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
  providers.push(provider);
  const fabric = new Fabric({
    tenantId: "acme",
    agentId: "bot",
    tracerProvider: provider,
    ...options,
  });
  return { fabric, exporter };
}

function spans(exporter: InMemorySpanExporter): ReadableSpan[] {
  return exporter.getFinishedSpans() as ReadableSpan[];
}

function telemetry(exporter: InMemorySpanExporter): string {
  return JSON.stringify(
    spans(exporter).map((s) => ({
      name: s.name,
      attributes: s.attributes,
      events: s.events.map((e) => ({ name: e.name, attributes: e.attributes })),
    })),
  );
}

/** One decision with a session, a user, an agent name, a tool call and an LLM call. */
function exercise(fabric: Fabric, ids: { sessionId: string; userId?: string }): void {
  fabric.decision({ ...ids, requestId: "req-1" }, (d: Decision) => {
    d.toolCall("lookup", { callId: "call-1" }, (tool) => {
      tool.setArguments('{"q":"x"}');
      tool.setResult('{"r":1}');
    });
    d.llmCall({ provider: "openai", model: "gpt-4o" }, (llm) => {
      llm.setResponse({ responseId: "resp-1" });
    });
  });
}

const KEYS: Record<string, string> = {
  sess: "fabric.session_id",
  usr: "fabric.user_id",
  agt: "gen_ai.agent.name",
};

// ----------------------------------------------------------------- identity parity

describe("identity parity: the decision line emits Python's ids", () => {
  const shared = vector("pseudonym-v2").cases.filter(
    (c: any) => c.function === "v2" && c.prefix in KEYS && c.key !== null,
  );
  const bytes = contract("contracts/capture/v1/fixtures/vectors/spool-bytes-v1.json")
    .ids.filter((c: any) => c.function === "pseudonym_v2" && JSON.parse(c.value) !== "")
    .map((c: any) => ({
      ...c,
      name: `sess of ${c.value}`,
      value: JSON.parse(c.value),
      pseudonym: c.expected,
    }));

  it.each(cases([...shared, ...bytes]))("%s", async (_name, c: any) => {
    const h = harness({
      identityMode: "pseudonymous",
      idKey: c.key,
      ...(c.prefix === "agt" ? { agentName: c.value } : {}),
    });
    exercise(h.fabric, {
      sessionId: c.prefix === "sess" ? c.value : "session-other",
      ...(c.prefix === "usr" ? { userId: c.value } : {}),
    });
    await h.fabric.close();
    const root = spans(h.exporter).find((s) => KEYS[c.prefix]! in s.attributes);
    expect(root?.attributes[KEYS[c.prefix]!]).toBe(c.pseudonym);
    if (c.value.length >= 4)
      expect(telemetry(h.exporter)).not.toContain(JSON.stringify(c.value).slice(1, -1));
  });

  it("clear mode emits the caller's ids as given (the explicit opt-in)", async () => {
    const h = harness({ identityMode: "clear", idKey: "fabric-test-id-key-not-a-secret" });
    exercise(h.fabric, { sessionId: "session-8c1f", userId: "user-42" });
    await h.fabric.close();
    const attrs = Object.assign({}, ...spans(h.exporter).map((s) => s.attributes));
    expect([attrs["fabric.session_id"], attrs["fabric.user_id"]]).toEqual([
      "session-8c1f",
      "user-42",
    ]);
  });
});

// ----------------------------------------------------------------- new keys

/** Keys only the wire or records input sets (Python `_records.py` FABRIC_OWNED_KEYS). */
const INPUT_OWNED = [
  "fabric.capture.input",
  "fabric.capture.source",
  "fabric.capture.point",
  "fabric.source_id",
  "fabric.source.epoch",
  "fabric.source.sequence",
  "fabric.event_id",
  "fabric.attempt.uid",
  "fabric.run.id",
  "fabric.run.scope_id",
  "fabric.run.segment_id",
  "fabric.step.kind",
  "fabric.step.lifecycle_state",
  "fabric.step.status",
  "fabric.content.object_ids",
];

describe("new-key parity: what the decision line emits on registered keys", () => {
  for (const keyed of [true, false]) {
    it(`every registered key passes its registry check (${keyed ? "keyed" : "no key"})`, async () => {
      const h = harness({
        identityMode: "pseudonymous",
        agentName: "planner",
        ...(keyed ? { idKey: "fabric-test-id-key-not-a-secret" } : {}),
      });
      exercise(h.fabric, { sessionId: "session-8c1f", userId: "user-42" });
      await h.fabric.close();
      const checked = new Set<string>();
      for (const span of spans(h.exporter)) {
        for (const [key, value] of Object.entries(span.attributes)) {
          const row = TELEMETRY_KEYS[key];
          const check = row?.check;
          // A const check names the one span it applies to (the manifest's schema_version).
          if (
            check === undefined ||
            (check.type === "const" && check.span !== undefined && check.span !== span.name)
          ) {
            continue;
          }
          checked.add(key);
          expect(checkValue(check, value, { labels: "pseudonymous" }), `${span.name} ${key}`).toBe(
            true,
          );
        }
      }
      // Without a key the caller ids are omitted (no unkeyed hash stands in for them).
      if (keyed)
        expect([...checked]).toEqual(
          expect.arrayContaining(["fabric.session_id", "fabric.user_id"]),
        );
      else expect([...checked]).toEqual([]);
    });
  }

  it("no explicit producer stamps a key only the wire or records input sets", async () => {
    const h = harness({ identityMode: "pseudonymous", idKey: "fabric-test-id-key-not-a-secret" });
    exercise(h.fabric, { sessionId: "session-8c1f" });
    await h.fabric.close();
    for (const span of spans(h.exporter)) {
      for (const key of INPUT_OWNED)
        expect(span.attributes, `${span.name} ${key}`).not.toHaveProperty(key);
    }
    for (const file of ["decision.ts", "calls.ts", "byte-evidence.ts"]) {
      const source = readFileSync(join(REPO, "sdk", "typescript", "src", file), "utf8");
      for (const key of INPUT_OWNED) expect(source, `${file} ${key}`).not.toContain(`"${key}"`);
    }
  });
});

// ----------------------------------------------------------------- R9 inventory

const SITE =
  /String\(|\.toString\(|JSON\.stringify\(|(?:^|[^\w"'.])[A-Za-z_]\w*\.(?:message|stack)\b|inspect\(|\$\{/;

describe("R9 inventory: automatic stringification in the explicit producers", () => {
  const inventory = JSON.parse(
    readFileSync(
      join(REPO, "sdk", "typescript", "test", "wire", "ts0", "stringify-inventory.json"),
      "utf8",
    ),
  );
  const found: { file: string; code: string }[] = [];
  for (const file of ["decision.ts", "calls.ts", "byte-evidence.ts"]) {
    const source = readFileSync(join(REPO, "sdk", "typescript", "src", file), "utf8");
    for (const line of source.split("\n")) {
      const code = line.trim();
      if (!code.startsWith("//") && !code.startsWith("*") && SITE.test(code))
        found.push({ file, code });
    }
  }

  it("every site is audited, and every audited site still exists", () => {
    const key = (s: { file: string; code: string }): string => `${s.file}: ${s.code}`;
    expect(found.map(key).sort()).toEqual(inventory.sites.map(key).sort());
  });

  it("every site has a verdict of the closed set", () => {
    const verdicts = new Set(["fabric_computed", "mapped", "local_only", "reported", "follow_up"]);
    for (const site of inventory.sites) expect(verdicts.has(site.verdict), site.code).toBe(true);
  });
});

// ----------------------------------------------------------------- cross-language canaries

describe("cross-language id privacy canaries", () => {
  const CANARY = "CANARY-order-jane.doe@example.com-q8z";
  const KEY = "fabric-test-id-key-not-a-secret";

  it("a clear run id never leaves through the run identity rules; its mapping is Python's", () => {
    const python = contract("contracts/capture/v1/fixtures/vectors/spool-bytes-v1.json").ids;
    for (const c of python.filter((x: any) => x.function === "run_pseudonym")) {
      const got = runIdentity([], JSON.parse(c.value), "r-" + "0".repeat(32), { key: c.key });
      expect(got.run_id).toBe(c.expected);
      expect(got.id_basis).toBe("caller");
    }
    const mapped = runIdentity([], CANARY, "r-" + "0".repeat(32), { key: KEY });
    expect(JSON.stringify(mapped)).not.toContain("CANARY");
    expect(mapped.run_id).toMatch(/^r-[0-9a-f]{32}$/);
    // Clear mode is the explicit opt-in; an id outside the opaque pattern is still h- encoded.
    const clear = runIdentity([], CANARY, "r-" + "0".repeat(32), { identityMode: "clear" });
    expect(clear.run_id).toMatch(/^h-[0-9a-f]{40}$/);
  });

  it("a clear session, user and agent id never leave through the decision line", async () => {
    for (const keyed of [true, false]) {
      const h = harness({
        identityMode: "pseudonymous",
        agentName: `${CANARY}-agent`,
        ...(keyed ? { idKey: KEY } : {}),
      });
      exercise(h.fabric, { sessionId: `${CANARY}-session`, userId: `${CANARY}-user` });
      await h.fabric.close();
      expect(telemetry(h.exporter)).not.toContain("CANARY");
    }
  });
});
