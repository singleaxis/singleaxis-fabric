// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Spec 049 §2.9 pseudonym v2: golden vectors shared with Python, the
 * identity-mode / id-key configuration, and how `decision()` emits
 * externally meaningful ids in pseudonymous (keyed and unkeyed) and clear
 * mode, plus a privacy canary over every exported attribute, log line and
 * spool record's metadata.
 */

import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AlwaysOnSampler,
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-node";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  Fabric,
  LocalFilesystemContentStore,
  MemoryKind,
  extract,
  sha256Hex,
  type Decision,
} from "../src/index.js";
import {
  ENV_ID_KEY,
  ENV_IDENTITY_MODE,
  IdentityPolicy,
  V2_TYPES,
  checkIdKey,
  identityModeFromEnv,
  keyId,
  labelPseudonym,
  operatorLabel,
  pseudonymV2,
  resetIdentityWarningsForTesting,
  utf8SurrogatePass,
} from "../src/identity.js";
import { resetIdentifierWarningsForTesting } from "../src/id-validators.js";

interface VectorCase {
  name: string;
  function: "v2" | "v1" | "legacy_provider";
  prefix: string;
  type?: string;
  value: string;
  key: string | null;
  pseudonym: string | null;
}
interface Vectors {
  cases: VectorCase[];
  key_ids: { key: string; key_id: string }[];
  distinct: [string, string][];
}

const vectors = JSON.parse(
  readFileSync(
    new URL("../../../contracts/coverage/v1/fixtures/vectors/pseudonym-v2.json", import.meta.url),
    "utf8",
  ),
) as Vectors;

function compute(c: VectorCase): string | undefined {
  switch (c.function) {
    case "v2":
      return pseudonymV2(c.prefix, c.value, c.key ?? undefined);
    case "v1":
      return c.prefix === "lbl"
        ? operatorLabel(c.value, c.key ?? undefined)
        : labelPseudonym(c.prefix, c.value, c.key ?? undefined);
    case "legacy_provider":
      return "p-" + sha256Hex(c.value).slice(0, 16);
  }
}

const hexPart = (pseudonym: string): string => pseudonym.slice(pseudonym.indexOf("-") + 1);

describe("pseudonym-v2 golden vectors", () => {
  it.each(vectors.cases.map((c) => [c.name, c] as const))("%s", (_name, c) => {
    expect(compute(c) ?? null).toBe(c.pseudonym);
  });

  it("covers every v2 prefix with its pinned type", () => {
    for (const c of vectors.cases.filter((v) => v.function === "v2" && v.type !== undefined)) {
      expect(V2_TYPES[c.prefix]).toBe(c.type);
    }
    const covered = new Set(vectors.cases.filter((c) => c.function === "v2").map((c) => c.prefix));
    expect([...covered].sort()).toEqual(Object.keys(V2_TYPES).sort());
  });

  it("IdentityPolicy.id agrees with pseudonymV2 for every keyed v2 case", () => {
    for (const c of vectors.cases.filter((v) => v.function === "v2" && v.key !== null)) {
      const policy = new IdentityPolicy("pseudonymous", utf8SurrogatePass(c.key!));
      expect(policy.id(c.prefix, c.value)).toBe(c.pseudonym);
      expect(new IdentityPolicy("clear", utf8SurrogatePass(c.key!)).id(c.prefix, c.value)).toBe(
        c.value,
      );
    }
    expect(new IdentityPolicy("pseudonymous").id("sess", "x")).toBeUndefined();
  });

  it.each(vectors.key_ids.map((k) => [k.key, k.key_id] as const))(
    "key_id of %j",
    (key, expected) => {
      expect(keyId(key)).toBe(expected);
    },
  );

  it.each(vectors.distinct)("%s differs from %s", (a, b) => {
    const byName = new Map(vectors.cases.map((c) => [c.name, c]));
    const left = byName.get(a)!;
    const right = byName.get(b)!;
    expect(compute(left)).toBe(left.pseudonym);
    expect(compute(right)).toBe(right.pseudonym);
    expect(hexPart(left.pseudonym!)).not.toBe(hexPart(right.pseudonym!));
  });

  it("encodes a lone surrogate like Python's surrogatepass", () => {
    expect([...utf8SurrogatePass("a\ud800b")]).toEqual([0x61, 0xed, 0xa0, 0x80, 0x62]);
    expect(utf8SurrogatePass("conversación-Ω🚀")).toEqual(Buffer.from("conversación-Ω🚀", "utf-8"));
  });

  it("operator labels pass through only in clear mode", () => {
    expect(operatorLabel("refund-approvals", undefined, { clear: true })).toBe("refund-approvals");
    expect(operatorLabel("refund-approvals")).toBe(
      "lbl-" + sha256Hex("refund-approvals").slice(0, 32),
    );
  });
});

const KEY = "fabric-test-id-key-not-a-secret";
const SECRET_MODE = "cleartext-please";

describe("identity configuration", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("defaults to pseudonymous and accepts clear", () => {
    expect(identityModeFromEnv({})).toBe("pseudonymous");
    expect(identityModeFromEnv({ [ENV_IDENTITY_MODE]: "" })).toBe("pseudonymous");
    expect(identityModeFromEnv({ [ENV_IDENTITY_MODE]: " clear " })).toBe("clear");
  });

  it("rejects an unknown mode with fixed text that never echoes the value", () => {
    expect(() => identityModeFromEnv({ [ENV_IDENTITY_MODE]: SECRET_MODE })).toThrow(
      "FABRIC_IDENTITY_MODE must be 'pseudonymous' or 'clear'",
    );
    let message = "";
    try {
      new Fabric({
        tenantId: "t",
        agentId: "a",
        identityMode: SECRET_MODE as "clear",
      });
    } catch (err) {
      message = (err as Error).message;
    }
    expect(message).toBe("identityMode must be 'pseudonymous' or 'clear'");
    vi.stubEnv(ENV_IDENTITY_MODE, SECRET_MODE);
    expect(() => new Fabric({ tenantId: "t", agentId: "a" })).toThrow(/^FABRIC_IDENTITY_MODE/);
    expect(() => Fabric.fromEnv({ FABRIC_TENANT_ID: "t", FABRIC_AGENT_ID: "a" })).not.toThrow();
  });

  it("rejects a short key without echoing it", () => {
    const shortKey = "short-key-xyz";
    const messages: string[] = [];
    for (const build of [
      () => checkIdKey(shortKey),
      () => new Fabric({ tenantId: "t", agentId: "a", idKey: shortKey }),
      () => Fabric.fromEnv({ FABRIC_TENANT_ID: "t", FABRIC_AGENT_ID: "a", [ENV_ID_KEY]: shortKey }),
    ]) {
      try {
        build();
      } catch (err) {
        messages.push((err as Error).message);
      }
    }
    expect(messages).toEqual(Array(3).fill("FABRIC_WIRE_ID_KEY must be at least 16 bytes"));
    vi.stubEnv(ENV_ID_KEY, shortKey);
    expect(() => new Fabric({ tenantId: "t", agentId: "a" })).toThrow(
      "FABRIC_WIRE_ID_KEY must be at least 16 bytes",
    );
  });

  it("never exposes the key through the policy object", () => {
    const policy = IdentityPolicy.resolve(undefined, KEY, {});
    expect(JSON.stringify(policy)).toBe('{"mode":"pseudonymous","keyed":true}');
    expect(Object.values(policy).join(" ")).not.toContain(KEY);
  });

  it("warns once, without values, when pseudonymous has no key", () => {
    resetIdentityWarningsForTesting();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    try {
      IdentityPolicy.resolve(undefined, undefined, {});
      IdentityPolicy.resolve(undefined, undefined, {});
      IdentityPolicy.resolve("clear", undefined, {});
      expect(warn).toHaveBeenCalledTimes(1);
      expect(String(warn.mock.calls[0]![0])).toContain("FABRIC_WIRE_ID_KEY is not set");
    } finally {
      warn.mockRestore();
    }
  });
});

// -- decision behaviour --------------------------------------------------

type Harness = { fabric: Fabric; exporter: InMemorySpanExporter; provider: BasicTracerProvider };
const providers: BasicTracerProvider[] = [];

function harness(config: Partial<ConstructorParameters<typeof Fabric>[0]> = {}): Harness {
  const exporter = new InMemorySpanExporter();
  const provider = new BasicTracerProvider({
    sampler: new AlwaysOnSampler(),
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
  providers.push(provider);
  const fabric = new Fabric({
    tenantId: "acme",
    agentId: "support-bot",
    tracerProvider: provider,
    ...config,
  });
  return { fabric, exporter, provider };
}

afterEach(async () => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  await Promise.all(providers.splice(0).map((p) => p.shutdown()));
});

// Distinctive values: "q8z" cannot occur in hex, uuids or the SDK's own keys.
const CANARY = {
  session: "CANARY-SESSION-q8z",
  user: "canary.user.q8z@example.com",
  agent: "CANARY-AGENT-q8z",
  target: "CANARY-TARGET-q8z",
  path: "/srv/CANARY-PATH-q8z/secret.txt",
  memoryKey: "CANARY-MKEY-q8z",
  memoryOld: "CANARY-MKEY-OLD-q8z",
  conversation: "CANARY-CONV-q8z",
};

/** Exercise every id-bearing decision surface; returns the delegation carrier. */
function exercise(d: Decision): Record<string, string> {
  d.llmCall({ provider: "openai", model: "m" }, () => undefined);
  d.llmCall(
    { provider: "openai", model: "m", conversationId: CANARY.conversation },
    () => undefined,
  );
  d.remember({
    kind: MemoryKind.SEMANTIC,
    content: "remembered",
    key: CANARY.memoryKey,
    invalidates: CANARY.memoryOld,
  });
  d.recall({ kind: MemoryKind.SEMANTIC, key: CANARY.memoryKey, content: "recalled" });
  d.forget(MemoryKind.SEMANTIC, CANARY.memoryKey);
  d.recordFileAccess(CANARY.path, "read", { redactPath: false });
  d.recordFileAccess(CANARY.path, "write");
  d.recordInteraction("slack.post", CANARY.target, { redactTarget: false });
  d.recordInteraction("slack.post", CANARY.target);
  let carrier: Record<string, string> = {};
  d.delegate(CANARY.agent, (sub) => {
    carrier = sub.carrier;
  });
  return carrier;
}

function run(h: Harness): { spans: ReadableSpan[]; carrier: Record<string, string> } {
  let carrier: Record<string, string> = {};
  h.fabric.decision({ sessionId: CANARY.session, requestId: "req-1", userId: CANARY.user }, (d) => {
    carrier = exercise(d);
  });
  return { spans: h.exporter.getFinishedSpans() as ReadableSpan[], carrier };
}

function allAttributes(spans: ReadableSpan[]): Record<string, unknown>[] {
  return spans.flatMap((s) => [s.attributes, ...s.events.map((e) => e.attributes ?? {})]);
}

function exported(spans: ReadableSpan[]): string {
  return JSON.stringify(
    spans.map((s) => ({
      name: s.name,
      attributes: s.attributes,
      events: s.events.map((e) => ({ name: e.name, attributes: e.attributes })),
    })),
  );
}

const span = (spans: ReadableSpan[], name: string) => spans.find((s) => s.name === name)!;
const events = (spans: ReadableSpan[], name: string) =>
  spans.flatMap((s) => s.events.filter((e) => e.name === name)).map((e) => e.attributes ?? {});
const llmSpans = (spans: ReadableSpan[]) => spans.filter((s) => s.name.startsWith("chat"));

describe("decision() in pseudonymous mode with a key", () => {
  it("emits the golden-vector pseudonyms for session and user", () => {
    const h = harness({ idKey: KEY });
    h.fabric.decision(
      { sessionId: "session-8c1f", requestId: "r", userId: "jane.doe@example.com" },
      (d) => {
        d.recordInteraction("chat", "#support-escalations", { redactTarget: false });
        d.recall({ kind: MemoryKind.EPISODIC, key: "user:42:preferences", content: "c" });
        d.delegate("billing-agent", () => undefined);
      },
    );
    const spans = h.exporter.getFinishedSpans() as ReadableSpan[];
    const decision = span(spans, "fabric.decision");
    expect(decision.attributes["fabric.session_id"]).toBe("sess-59ed1f5d6b14409a864fc485d982decf");
    expect(decision.attributes["gen_ai.conversation.id"]).toBe(
      "sess-59ed1f5d6b14409a864fc485d982decf",
    );
    expect(decision.attributes["fabric.user_id"]).toBe("usr-ba0f37872e36c3cfe3692a57a52c7a62");
    expect(events(spans, "fabric.interaction")[0]!["fabric.interaction.target"]).toBe(
      "tgt-762ddcb6b0fb91ec56e08e230f9d416a",
    );
    expect(events(spans, "fabric.memory")[0]!["fabric.memory.key"]).toBe(
      "mkey-e9686c7937396299d907191384769920",
    );
    expect(events(spans, "fabric.delegation")[0]!["fabric.delegation.to_agent"]).toBe(
      "agt-9155b54c2ec713a9cf5c16ce8cbd5b13",
    );
  });

  it("pseudonymises every id attribute with its prefix", () => {
    const h = harness({ idKey: KEY });
    const { spans } = run(h);
    const v2 = (prefix: string, value: string) => pseudonymV2(prefix, value, KEY);
    const decision = span(spans, "fabric.decision").attributes;
    expect(decision["fabric.session_id"]).toBe(v2("sess", CANARY.session));
    expect(decision["gen_ai.conversation.id"]).toBe(v2("sess", CANARY.session));
    expect(decision["fabric.user_id"]).toBe(v2("usr", CANARY.user));
    const [defaulted, explicit] = llmSpans(spans);
    expect(defaulted!.attributes["gen_ai.conversation.id"]).toBe(v2("sess", CANARY.session));
    expect(explicit!.attributes["gen_ai.conversation.id"]).toBe(v2("conv", CANARY.conversation));
    const [write, read, erase] = events(spans, "fabric.memory");
    expect(write!["fabric.memory.key"]).toBe(v2("mkey", CANARY.memoryKey));
    expect(write!["fabric.memory.invalidates"]).toBe(v2("mkey", CANARY.memoryOld));
    expect(read!["fabric.memory.key"]).toBe(v2("mkey", CANARY.memoryKey));
    expect(erase!["fabric.memory.key"]).toBe(v2("mkey", CANARY.memoryKey));
    for (const file of events(spans, "fabric.file")) {
      expect(file["fabric.file.path_redacted"]).toBe(true);
      expect(file["fabric.file.path_hash"]).toBe(sha256Hex(CANARY.path));
      expect(file).not.toHaveProperty("fabric.file.path");
    }
    const [clearTarget, hashedTarget] = events(spans, "fabric.interaction");
    expect(clearTarget!["fabric.interaction.target"]).toBe(v2("tgt", CANARY.target));
    expect(clearTarget!["fabric.interaction.target_redacted"]).toBe(false);
    expect(hashedTarget!["fabric.interaction.target_hash"]).toBe(sha256Hex(CANARY.target));
    expect(hashedTarget).not.toHaveProperty("fabric.interaction.target");
    expect(events(spans, "fabric.delegation")[0]!["fabric.delegation.to_agent"]).toBe(
      v2("agt", CANARY.agent),
    );
  });

  it("keeps the propagation carrier and application getters clear", () => {
    const h = harness({ idKey: KEY });
    let seen: { session?: string; user?: string } = {};
    const { carrier } = (() => {
      let c: Record<string, string> = {};
      h.fabric.decision(
        { sessionId: CANARY.session, requestId: "req-1", userId: CANARY.user },
        (d) => {
          seen = { session: d.sessionId, user: d.userId };
          d.delegate(CANARY.agent, (sub) => {
            c = sub.carrier;
          });
        },
      );
      return { carrier: c };
    })();
    expect(seen).toEqual({ session: CANARY.session, user: CANARY.user });
    expect(extract(carrier)?.sessionId).toBe(CANARY.session);
  });
});

describe("decision() in pseudonymous mode without a key", () => {
  it("omits every v2 id attribute", () => {
    const h = harness();
    const { spans } = run(h);
    const decision = span(spans, "fabric.decision").attributes;
    for (const key of ["fabric.session_id", "fabric.user_id", "gen_ai.conversation.id"]) {
      expect(decision).not.toHaveProperty(key);
    }
    // v0.8.1: the caller's request id is a caller id too (`lbl-`), omitted without a key.
    expect(decision).not.toHaveProperty("fabric.request_id");
    for (const llm of llmSpans(spans)) {
      expect(llm.attributes).not.toHaveProperty("gen_ai.conversation.id");
    }
    for (const memory of events(spans, "fabric.memory")) {
      expect(memory).not.toHaveProperty("fabric.memory.key");
      expect(memory).not.toHaveProperty("fabric.memory.invalidates");
    }
    for (const file of events(spans, "fabric.file")) {
      expect(file["fabric.file.path_redacted"]).toBe(true);
      expect(file).not.toHaveProperty("fabric.file.path");
    }
    const [clearTarget, hashedTarget] = events(spans, "fabric.interaction");
    expect(clearTarget).not.toHaveProperty("fabric.interaction.target");
    expect(clearTarget).not.toHaveProperty("fabric.interaction.target_hash");
    expect(hashedTarget!["fabric.interaction.target_hash"]).toBe(sha256Hex(CANARY.target));
    const delegation = events(spans, "fabric.delegation")[0]!;
    expect(delegation).not.toHaveProperty("fabric.delegation.to_agent");
    expect(delegation["fabric.delegation.protocol"]).toBeDefined();
  });

  it("still requires a session id and still warns on PII-shaped ids", () => {
    resetIdentifierWarningsForTesting();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const h = harness();
    expect(() => h.fabric.decision({ sessionId: "", requestId: "r" }, () => undefined)).toThrow(
      "sessionId is required",
    );
    h.fabric.decision({ sessionId: "s", requestId: "r", userId: CANARY.user }, () => undefined);
    const text = warn.mock.calls.flat().join(" ");
    expect(text).toContain("user_id looks like an email");
    expect(text).not.toContain(CANARY.user);
  });
});

describe("decision() in clear mode", () => {
  for (const [label, config, env] of [
    ["identityMode option", { identityMode: "clear" as const, idKey: KEY }, undefined],
    ["FABRIC_IDENTITY_MODE env", {}, "clear"],
  ] as const) {
    it(`reproduces the pre-049 output (${label})`, () => {
      if (env !== undefined) vi.stubEnv(ENV_IDENTITY_MODE, env);
      const h = harness(config);
      const { spans } = run(h);
      const decision = span(spans, "fabric.decision").attributes;
      expect(decision["fabric.session_id"]).toBe(CANARY.session);
      expect(decision["gen_ai.conversation.id"]).toBe(CANARY.session);
      expect(decision["fabric.user_id"]).toBe(CANARY.user);
      const [defaulted, explicit] = llmSpans(spans);
      expect(defaulted!.attributes["gen_ai.conversation.id"]).toBe(CANARY.session);
      expect(explicit!.attributes["gen_ai.conversation.id"]).toBe(CANARY.conversation);
      const [write, read, erase] = events(spans, "fabric.memory");
      expect(write!["fabric.memory.key"]).toBe(CANARY.memoryKey);
      expect(write!["fabric.memory.invalidates"]).toBe(CANARY.memoryOld);
      expect(Object.keys(read!)).toEqual([
        "fabric.schema_version",
        "fabric.memory.direction",
        "fabric.memory.kind",
        "fabric.memory.key",
        "fabric.memory.content_hash",
      ]);
      expect(erase!["fabric.memory.key"]).toBe(CANARY.memoryKey);
      const [clearFile, hashedFile] = events(spans, "fabric.file");
      expect(clearFile!["fabric.file.path"]).toBe(CANARY.path);
      expect(clearFile!["fabric.file.path_redacted"]).toBe(false);
      expect(clearFile).not.toHaveProperty("fabric.file.path_hash");
      expect(hashedFile!["fabric.file.path_hash"]).toBe(sha256Hex(CANARY.path));
      const [clearTarget] = events(spans, "fabric.interaction");
      expect(clearTarget!["fabric.interaction.target"]).toBe(CANARY.target);
      const delegation = events(spans, "fabric.delegation")[0]!;
      expect(Object.keys(delegation).slice(0, 4)).toEqual([
        "fabric.schema_version",
        "fabric.delegation.to_agent",
        "fabric.delegation.protocol",
        "fabric.delegation.depth",
      ]);
      expect(delegation["fabric.delegation.to_agent"]).toBe(CANARY.agent);
    });
  }
});

describe("privacy canary (pseudonymous mode)", () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "fabric-identity-canary-"));
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  for (const keyed of [true, false]) {
    it(`no clear id reaches a span or event attribute, a log line or spool metadata (${
      keyed ? "keyed" : "no key"
    })`, async () => {
      resetIdentityWarningsForTesting();
      const lines: string[] = [];
      const capture = (...args: unknown[]) => {
        lines.push(args.map(String).join(" "));
      };
      for (const method of ["warn", "error", "log", "info", "debug"] as const) {
        vi.spyOn(console, method).mockImplementation(capture);
      }
      vi.spyOn(process.stderr, "write").mockImplementation((chunk: unknown) => {
        lines.push(String(chunk));
        return true;
      });
      const store = new LocalFilesystemContentStore(join(root, "store"), "acme");
      const spoolDir = join(root, "spool");
      const h = harness({
        ...(keyed ? { idKey: KEY } : {}),
        contentCapture: { store, roles: "all", durability: "spooled", spoolDir },
      });
      const spoolMetadata: Record<string, unknown>[] = [];
      let carrier: Record<string, string> = {};
      h.fabric.decision(
        { sessionId: CANARY.session, requestId: "req-1", userId: CANARY.user },
        (d) => {
          carrier = exercise(d);
          d.recordInteraction("webhook", CANARY.target, { payload: "payload body" });
          // Spooled records are written synchronously; read them before the
          // async drain delivers and removes them.
          for (const name of readdirSync(spoolDir)) {
            const record = JSON.parse(readFileSync(join(spoolDir, name), "utf8")) as Record<
              string,
              unknown
            >;
            // `manifest`, `descriptor` and `content_b64` are content (the
            // clear session binding lives there by design, spec 049 line 279).
            for (const content of ["manifest", "descriptor", "content_b64"]) delete record[content];
            spoolMetadata.push(record);
          }
        },
      );
      await h.fabric.close();
      const spans = h.exporter.getFinishedSpans() as ReadableSpan[];
      expect(spans.length).toBeGreaterThan(1);
      expect(spoolMetadata.length).toBeGreaterThan(0);
      const haystack = [exported(spans), JSON.stringify(spoolMetadata), ...lines].join("\n");
      for (const value of Object.values(CANARY)) {
        expect(haystack).not.toContain(value);
      }
      expect(haystack.toLowerCase()).not.toContain("q8z");
      expect(haystack).not.toContain(KEY);
      for (const attrs of allAttributes(spans)) {
        for (const value of Object.values(attrs)) {
          expect(JSON.stringify(value)).not.toMatch(/q8z/i);
        }
      }
      // The carrier is not telemetry: sub-agents still receive the clear id.
      expect(extract(carrier)?.sessionId).toBe(CANARY.session);
    });
  }
});
