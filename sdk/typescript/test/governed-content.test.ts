// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Governed-content suite (specs 028/029/032/033/034) — the TypeScript
 * mirror of `sdk/python/tests/test_governed_content.py`.
 *
 * Covers: explicit opt-in + fail-closed config, the env restriction
 * (which can only DISABLE), canonical byte parity, UTF-8-safe
 * truncation, the tenant-namespaced local store, bounded writer
 * delivery (inline/process/spooled), every capture surface, the
 * per-decision transcript manifest, authorized resolution with
 * integrity verification, and the transcript export.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { context, trace } from "@opentelemetry/api";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import {
  AlwaysOnSampler,
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-node";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  CONTENT_ROLES,
  ContentResolver,
  ContentRole,
  ContentStatus,
  ENV_CONTENT_MODE,
  Fabric,
  LocalFilesystemContentStore,
  Representation,
  ResolveStatus,
  buildContentDescriptor,
  canonicalBytes,
  canonicalJson,
  truncateBytes,
  validateContentCaptureConfig,
  type ContentCaptureConfig,
  type ContentDescriptor,
} from "../src/index.js";
import { ContentWriter } from "../src/content-writer.js";
import type { ContentRef, GovernedStore } from "../src/content-store.js";

/**
 * Store whose puts never settle quickly — wraps the local store behind a
 * delayed async `putObject` so `process`/`spooled` paths prove they do
 * not wait on remote storage.
 */
class SlowStore implements GovernedStore {
  readonly synchronous = false;
  readonly tenantId = "acme";
  private readonly inner: LocalFilesystemContentStore;
  constructor(
    root: string,
    private readonly delayMs: number,
  ) {
    this.inner = new LocalFilesystemContentStore(root, "acme");
  }
  refFor(digest: string): string {
    return this.inner.refFor(digest);
  }
  async putObject(descriptor: Record<string, unknown>, content: string): Promise<ContentRef> {
    await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    return this.inner.putObject(descriptor, content);
  }
  writeManifest(manifest: Record<string, unknown>, decisionId: string, manifestId: string): string {
    return this.inner.writeManifest(manifest, decisionId, manifestId);
  }
  manifestUriFor(manifestId: string): string {
    return this.inner.manifestUriFor(manifestId);
  }
  manifestUriForDecision(decisionId: string): string {
    return this.inner.manifestUriForDecision(decisionId);
  }
  ownsUri(uri: string): boolean {
    return this.inner.ownsUri(uri);
  }
  exists(uri: string): boolean {
    return this.inner.exists(uri);
  }
  read(uri: string): Uint8Array {
    return this.inner.read(uri);
  }
  readDescriptor(uri: string): Record<string, unknown> {
    return this.inner.readDescriptor(uri);
  }
  readManifest(uri: string): Record<string, unknown> {
    return this.inner.readManifest(uri);
  }
  listObjectUris(): string[] {
    return this.inner.listObjectUris();
  }
}

/** Store whose puts always fail — proves failures stay out of the agent path. */
class FailingStore extends LocalFilesystemContentStore {
  constructor(root: string) {
    super(root, "acme");
  }
  override putObject(): never {
    throw new Error("disk full");
  }
}

const exporter = new InMemorySpanExporter();
let provider: BasicTracerProvider;
const contextManager = new AsyncLocalStorageContextManager();

beforeAll(() => {
  contextManager.enable();
  context.setGlobalContextManager(contextManager);
  provider = new BasicTracerProvider({
    sampler: new AlwaysOnSampler(),
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
  trace.setGlobalTracerProvider(provider);
});

afterAll(async () => {
  await provider.shutdown();
  trace.disable();
  context.disable();
});

beforeEach(() => {
  exporter.reset();
  delete process.env[ENV_CONTENT_MODE];
});

function tmpRoot(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "fabric-governed-"));
}

function store(root: string, tenant = "acme"): LocalFilesystemContentStore {
  return new LocalFilesystemContentStore(root, tenant);
}

function governedFabric(root: string, overrides: Partial<ContentCaptureConfig> = {}): Fabric {
  return new Fabric({
    tenantId: "acme",
    agentId: "agent-g",
    profile: "permissive-dev",
    contentCapture: {
      store: store(root),
      roles: "all",
      durability: "inline",
      ...overrides,
    },
  });
}

function spanByName(name: string): ReadableSpan {
  const span = exporter.getFinishedSpans().find((s) => s.name === name);
  expect(span, `expected finished span ${name}`).toBeDefined();
  return span as ReadableSpan;
}

// -- configuration & gating ------------------------------------------------

describe("content capture configuration", () => {
  it("metadata mode stays the zero-configuration default", () => {
    const fabric = new Fabric({ tenantId: "acme", agentId: "a", profile: "permissive-dev" });
    expect(fabric.contentCaptureConfig).toBeUndefined();
    expect(fabric.writer).toBeUndefined();
  });

  it("rejects a config without a governed store (fail closed)", () => {
    expect(
      () =>
        new Fabric({
          tenantId: "acme",
          agentId: "a",
          profile: "permissive-dev",
          contentCapture: { roles: "all" } as unknown as ContentCaptureConfig,
        }),
    ).toThrow(/store/);
  });

  it("rejects unknown roles", () => {
    expect(() =>
      validateContentCaptureConfig(
        { store: store(tmpRoot()), roles: new Set(["model.request.messages", "bogus"]) },
        CONTENT_ROLES,
      ),
    ).toThrow(/unknown roles/);
  });

  it("rejects inline durability for an async store", () => {
    const asyncStore: GovernedStore = {
      tenantId: "acme",
      synchronous: false,
      refFor: (d) => `s3://bucket/prefix/acme/${d}`,
      putObject: async () => ({ uri: "s3://x", contentHash: "0".repeat(64) }),
      writeManifest: async () => "s3://bucket/m",
      manifestUriFor: (id) => `s3://bucket/m/${id}`,
      manifestUriForDecision: () => "s3://bucket/m/d",
      ownsUri: () => true,
      exists: async () => false,
      read: async () => new Uint8Array(),
      readDescriptor: async () => ({}),
      readManifest: async () => ({}),
      listObjectUris: async () => [],
    };
    expect(() =>
      validateContentCaptureConfig(
        { store: asyncStore, roles: "all", durability: "inline" },
        CONTENT_ROLES,
      ),
    ).toThrow(/synchronous/);
  });

  it("env FABRIC_CONTENT_MODE=metadata disables a configured capture", () => {
    process.env[ENV_CONTENT_MODE] = "metadata";
    const fabric = governedFabric(tmpRoot());
    expect(fabric.contentCaptureConfig).toBeUndefined();
    expect(fabric.writer).toBeUndefined();
  });

  it("env vars cannot enable governed mode", () => {
    process.env[ENV_CONTENT_MODE] = "governed-reference";
    const fabric = new Fabric({
      tenantId: "acme",
      agentId: "a",
      profile: "permissive-dev",
    });
    expect(fabric.contentCaptureConfig).toBeUndefined();
  });
});

// -- content primitives -----------------------------------------------------

describe("canonical bytes", () => {
  it("serializes JSON sorted, compact, literal UTF-8", () => {
    const { data } = canonicalBytes({ b: "é", a: 1 }, "application/json");
    expect(new TextDecoder().decode(data)).toBe('{"a":1,"b":"é"}');
  });

  it("re-serializes a JSON string input canonically", () => {
    const { data, representation } = canonicalBytes('{"b":2,"a":1}', "application/json");
    expect(new TextDecoder().decode(data)).toBe('{"a":1,"b":2}');
    expect(representation).toBe(Representation.CANONICALIZED);
  });

  it("stores text/plain verbatim", () => {
    const { data, representation } = canonicalBytes("héllo\n", "text/plain");
    expect(new TextDecoder().decode(data)).toBe("héllo\n");
    expect(representation).toBe(Representation.CAPTURED);
  });

  it("rejects binary input in v1", () => {
    expect(() => canonicalBytes(new Uint8Array([1, 2]), "application/octet-stream")).toThrow(
      /text\/JSON/,
    );
  });

  it("truncates at a UTF-8 boundary and records the original length", () => {
    const { descriptor, data } = buildContentDescriptor({
      tenantId: "acme",
      role: ContentRole.MODEL_REQUEST_MESSAGES,
      content: "aé中🙂x".repeat(4),
      mediaType: "text/plain",
      source: "caller",
      status: ContentStatus.PENDING,
      bindings: {},
      payloadMaxBytes: 9,
    });
    // Byte 9 may split a multi-byte rune; the stored prefix must decode.
    expect(data.length).toBeLessThanOrEqual(9);
    expect(() => new TextDecoder("utf-8", { fatal: true }).decode(data)).not.toThrow();
    expect(descriptor.representation).toBe(Representation.TRUNCATED);
    expect(descriptor.original_byte_length).toBeGreaterThan(9);
    expect(descriptor.byte_length).toBe(data.length);
    expect(descriptor.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it.each(["é", "中", "🙂"])(
    "preserves complete UTF-8 characters at the byte limit: %s",
    (rune) => {
      const prefix = `a${rune}`;
      const encoded = new TextEncoder().encode(`${prefix}z`);
      const limit = new TextEncoder().encode(prefix).length;
      const out = truncateBytes(encoded, limit);
      expect(new TextDecoder("utf-8", { fatal: true }).decode(out)).toBe(prefix);
      expect(out.length).toBe(limit);
    },
  );

  it("truncateBytes never splits a rune", () => {
    const encoded = new TextEncoder().encode("ééé");
    const out = truncateBytes(encoded, 3);
    expect(new TextDecoder().decode(out)).toBe("é");
  });
});

// -- local store --------------------------------------------------------------

describe("LocalFilesystemContentStore", () => {
  it("writes objects tenant-namespaced + descriptor sidecar + ref", () => {
    const root = tmpRoot();
    const s = store(root);
    const { descriptor, data } = buildContentDescriptor({
      tenantId: "acme",
      role: ContentRole.MODEL_REQUEST_MESSAGES,
      content: { m: 1 },
      mediaType: "application/json",
      source: "caller",
      status: ContentStatus.PENDING,
      bindings: {},
      payloadMaxBytes: 1024,
    });
    const ref = s.putObject(
      descriptor as unknown as Record<string, unknown>,
      new TextDecoder().decode(data),
    );
    expect(ref.uri).toMatch(/^file:\/\/.*\/acme\/[0-9a-f]{64}$/);
    const digest = descriptor.digest.slice(7);
    expect(fs.existsSync(path.join(root, "acme", digest))).toBe(true);
    expect(fs.existsSync(path.join(root, "acme", "meta", `${digest}.json`))).toBe(true);
    expect(fs.statSync(path.join(root, "acme", digest)).mode & 0o777 & 0o077).toBe(0);
  });

  it("verifies a corrupted pre-existing object instead of trusting it", () => {
    const root = tmpRoot();
    const s = store(root);
    const { descriptor, data } = buildContentDescriptor({
      tenantId: "acme",
      role: ContentRole.MODEL_REQUEST_MESSAGES,
      content: "payload",
      mediaType: "text/plain",
      source: "caller",
      status: ContentStatus.PENDING,
      bindings: {},
      payloadMaxBytes: 1024,
    });
    const digest = descriptor.digest.slice(7);
    fs.mkdirSync(path.join(root, "acme"), { recursive: true });
    fs.writeFileSync(path.join(root, "acme", digest), "tampered");
    expect(() =>
      s.putObject(descriptor as unknown as Record<string, unknown>, new TextDecoder().decode(data)),
    ).toThrow(/digest verification/);
  });

  it("writes the manifest plus a by-decision alias", () => {
    const root = tmpRoot();
    const s = store(root);
    const uri = s.writeManifest({ manifest_id: "m1" }, "decision-1", "m1");
    expect(uri).toMatch(/manifests\/m1\.json$/);
    const alias = path.join(root, "acme", "manifests", "by-decision", "decision-1.json");
    expect(fs.existsSync(alias)).toBe(true);
    const pointer = JSON.parse(fs.readFileSync(alias, "utf-8")) as { manifest_uri: string };
    expect(pointer.manifest_uri).toBe(uri);
  });

  it("keeps governed directories owner-only", () => {
    const root = tmpRoot();
    const s = store(root);
    const { descriptor, data } = buildContentDescriptor({
      tenantId: "acme",
      role: ContentRole.INTERACTION_PAYLOAD,
      content: "payload",
      mediaType: "text/plain",
      source: "caller",
      status: ContentStatus.PENDING,
      bindings: {},
      payloadMaxBytes: 1024,
    });
    s.putObject(descriptor as unknown as Record<string, unknown>, new TextDecoder().decode(data));
    s.writeManifest({ manifest_id: "m-mode" }, "d-mode", "m-mode");
    for (const directory of [
      path.join(root, "acme"),
      path.join(root, "acme", "meta"),
      path.join(root, "acme", "manifests"),
      path.join(root, "acme", "manifests", "by-decision"),
    ]) {
      expect(fs.statSync(directory).mode & 0o777).toBe(0o700);
    }
  });

  it("confines reads to the tenant namespace", () => {
    const root = tmpRoot();
    const acme = store(root, "acme");
    const other = store(root, "other");
    const foreign = path.join(root, "other", "abc");
    fs.mkdirSync(path.dirname(foreign), { recursive: true });
    fs.writeFileSync(foreign, "x");
    expect(acme.ownsUri(`file://${foreign}`)).toBe(false);
    expect(other.ownsUri(`file://${foreign}`)).toBe(true);
    expect(() => acme.read(`file://${foreign}`)).toThrow(/escapes/);
    expect(() => acme.read(`file://${path.join(root, "acme", "..", "x")}`)).toThrow();
    expect(acme.ownsUri("https://evil.example/x")).toBe(false);
  });
});

// -- writer ---------------------------------------------------------------------

describe("ContentWriter", () => {
  function descriptorFor(content: unknown): {
    descriptor: ReturnType<typeof buildContentDescriptor>["descriptor"];
    text: string;
  } {
    const { descriptor, data } = buildContentDescriptor({
      tenantId: "acme",
      role: ContentRole.MODEL_REQUEST_MESSAGES,
      content,
      mediaType: "application/json",
      source: "caller",
      status: ContentStatus.PENDING,
      bindings: {},
      payloadMaxBytes: 1024 * 1024,
    });
    return { descriptor, text: new TextDecoder().decode(data) };
  }

  it("inline durability stores synchronously", async () => {
    const root = tmpRoot();
    const writer = new ContentWriter({
      store: store(root),
      roles: "all",
      durability: "inline",
    });
    const { descriptor, text } = descriptorFor({ m: 1 });
    expect(writer.submit(descriptor, text)).toBe(ContentStatus.STORED);
    const result = await writer.close();
    expect(result.stored).toBe(1);
    expect(result?.pending).toBe(0);
  });

  it("process durability enqueues then flushes", async () => {
    const root = tmpRoot();
    const writer = new ContentWriter({
      store: store(root),
      roles: "all",
      durability: "process",
    });
    const { descriptor, text } = descriptorFor({ m: 2 });
    expect(writer.submit(descriptor, text)).toBe(ContentStatus.PENDING);
    const result = await writer.flush(5);
    expect(result.stored).toBe(1);
    expect(result?.pending).toBe(0);
    await writer.close();
  });

  it("queue bound drops honestly", async () => {
    const root = tmpRoot();
    const writer = new ContentWriter({
      store: new SlowStore(root, 20),
      roles: "all",
      durability: "process",
      queueMaxItems: 1,
      // No timer-driven drain during the test: the queue stays full.
      workerFlushIntervalMs: 60000,
    });
    const a = descriptorFor({ m: "a" });
    const b = descriptorFor({ m: "b" });
    expect(writer.submit(a.descriptor, a.text)).toBe(ContentStatus.PENDING);
    expect(writer.submit(b.descriptor, b.text)).toBe(ContentStatus.DROPPED);
    const result = await writer.close();
    expect(result.dropped).toBe(1);
    expect(result.stored).toBe(1);
  });

  it("store failures map to failed, never throw", async () => {
    const writer = new ContentWriter({
      store: new FailingStore(tmpRoot()),
      roles: "all",
      durability: "inline",
    });
    const { descriptor, text } = descriptorFor({ m: 3 });
    expect(writer.submit(descriptor, text)).toBe(ContentStatus.FAILED);
    const result = await writer.close();
    expect(result.failed).toBe(1);
  });

  it("spooled durability recovers entries on restart", async () => {
    const root = tmpRoot();
    const spoolDir = path.join(root, "spool");
    // First writer dies with entries still spooled (store never drained).
    const dying = new ContentWriter({
      store: new SlowStore(root, 60000),
      roles: "all",
      durability: "spooled",
      spoolDir,
      workerFlushIntervalMs: 60000,
    });
    const { descriptor, text } = descriptorFor({ m: "spooled" });
    expect(dying.submit(descriptor, text)).toBe(ContentStatus.PENDING);
    expect(fs.readdirSync(spoolDir).filter((f) => f.endsWith(".json")).length).toBe(1);
    // "Crash": abandon the writer without close.
    const recovered = new ContentWriter({
      store: store(root),
      roles: "all",
      durability: "spooled",
      spoolDir,
    });
    const result = await recovered.flush(5);
    expect(result.stored).toBe(1);
    await recovered.close();
  });
});

// -- capture surfaces -----------------------------------------------------------

describe("governed capture surfaces", () => {
  it("captures an llm request and output end to end", async () => {
    const root = tmpRoot();
    const fabric = governedFabric(root);
    fabric.decision({ sessionId: "s1", requestId: "r1" }, (d) => {
      d.llmCall(
        {
          model: "m-x",
          provider: "test-provider",
          systemInstructions: "be terse",
          inputMessages: [{ role: "user", content: "hi" }],
          toolDefinitions: [{ name: "lookup" }],
        },
        (call) => {
          call.setResponse({ outputMessages: [{ role: "assistant", content: "yo" }] });
        },
      );
    });
    const result = await fabric.flushContent(5);
    expect(result?.stored).toBeGreaterThanOrEqual(4);
    const llm = spanByName("chat m-x");
    expect(llm.attributes["fabric.content.request_ref"]).toMatch(/^file:\/\//);
    expect(llm.attributes["fabric.content.result_ref"]).toMatch(/^file:\/\//);
    // Raw content never lands on the span.
    expect(llm.attributes["gen_ai.output.messages"]).toBeUndefined();
    const decision = spanByName("fabric.decision");
    expect(decision.attributes["fabric.content.manifest_ref"]).toMatch(/manifests\//);
  });

  it("captures tool arguments and results", async () => {
    const root = tmpRoot();
    const fabric = governedFabric(root);
    fabric.decision({ sessionId: "s1", requestId: "r1" }, (d) => {
      d.toolCall("lookup", { callId: "call-9" }, (t) => {
        t.setArguments(JSON.stringify({ q: "x" }));
        t.setResult(JSON.stringify({ rows: 3 }));
      });
    });
    await fabric.flushContent(5);
    const tool = spanByName("lookup");
    expect(tool.attributes["fabric.content.request_ref"]).toMatch(/^file:\/\//);
    expect(tool.attributes["fabric.content.result_ref"]).toMatch(/^file:\/\//);
  });

  it("captures retrieval, memory, side-effect, context, and interaction", async () => {
    const root = tmpRoot();
    const fabric = governedFabric(root);
    fabric.decision({ sessionId: "s1", requestId: "r1" }, (d) => {
      d.recordRetrieval({
        source: "rag",
        query: "refund policy",
        resultCount: 2,
        results: [{ doc: "a" }, { doc: "b" }],
      });
      d.remember({ kind: "semantic", content: "pref=tea" });
      d.recall({ kind: "semantic", key: "pref", content: "pref=tea" });
      d.recordSideEffect({
        type: "api_mutation",
        targetSystem: "crm",
        operation: "update",
        requestPayload: JSON.stringify({ id: 1 }),
        resultPayload: JSON.stringify({ ok: true }),
      });
      d.recordContext("notes.txt", "call notes");
      d.recordInteraction("http.request", "https://api.example", { payload: '{"q":1}' });
    });
    const result = await fabric.flushContent(5);
    // retrieval query+results, memory write+read, side effect req+res,
    // context file, interaction payload = 8 objects; the writer's
    // `stored` counter also includes the manifest delivery = 9.
    expect(result?.stored).toBe(9);
    const events = spanByName("fabric.decision").events;
    const retrieval = events.find((e) => e.name === "fabric.retrieval");
    expect(retrieval?.attributes?.["fabric.content.request_ref"]).toBeDefined();
    expect(retrieval?.attributes?.["fabric.content.result_ref"]).toBeDefined();
    const sideEffect = events.find((e) => e.name === "fabric.side_effect");
    expect(sideEffect?.attributes?.["fabric.content.request_ref"]).toBeDefined();
    const interactions = events.filter((e) => e.name === "fabric.interaction");
    expect(interactions.some((e) => e.attributes?.["fabric.content.ref"] !== undefined)).toBe(true);
  });

  it("records filtered roles as not_captured, not absent", async () => {
    const root = tmpRoot();
    const fabric = governedFabric(root, {
      roles: new Set([ContentRole.MODEL_REQUEST_MESSAGES]),
    });
    let manifestItems: { role: string; status: string }[] | undefined;
    fabric.decision({ sessionId: "s1", requestId: "r1" }, (d) => {
      d.llmCall(
        {
          model: "m",
          provider: "test-provider",
          systemInstructions: "x",
          inputMessages: [{ role: "user", content: "hi" }],
        },
        () => {},
      );
      manifestItems = d.contentManifest?.items.map((i) => ({ role: i.role, status: i.status }));
    });
    await fabric.flushContent(5);
    const instructions = manifestItems?.find((i) => i.role === "model.request.instructions");
    expect(instructions?.status).toBe(ContentStatus.NOT_CAPTURED);
    const messages = manifestItems?.find((i) => i.role === "model.request.messages");
    expect(messages?.status).toBe(ContentStatus.STORED);
  });

  it("partial output uses representation=assembled with a status reason", async () => {
    const root = tmpRoot();
    const fabric = governedFabric(root);
    let itemStatus: string | undefined;
    let repr: string | undefined;
    let reason: string | undefined;
    fabric.decision({ sessionId: "s1", requestId: "r1" }, (d) => {
      d.llmCall({ model: "m", provider: "test-provider" }, (call) => {
        call.recordPartialOutput("hel");
      });
      const item = d.contentManifest?.items.find((i) => i.role === "model.output.messages");
      itemStatus = item?.status;
      repr = item?.descriptor?.representation;
      reason = item?.descriptor?.status_reason;
    });
    await fabric.flushContent(5);
    expect(itemStatus).toBe(ContentStatus.STORED);
    expect(repr).toBe("assembled");
    expect(reason).toBe("partial output");
  });

  it("a failing store never breaks the monitored call", async () => {
    const fabric = new Fabric({
      tenantId: "acme",
      agentId: "a",
      profile: "permissive-dev",
      contentCapture: {
        store: new FailingStore(tmpRoot()),
        roles: "all",
        durability: "inline",
      },
    });
    // The model path still completes and produces its output.
    const out = fabric.decision({ sessionId: "s1", requestId: "r1" }, (d) =>
      d.llmCall(
        { model: "m", provider: "test-provider", inputMessages: [{ role: "user", content: "hi" }] },
        () => "answer",
      ),
    );
    expect(out).toBe("answer");
    const result = await fabric.flushContent(2);
    expect(result?.failed).toBe(1);
  });
});

// -- manifest & export ---------------------------------------------------------

describe("transcript manifest and export", () => {
  it("stores the manifest and exports a verified transcript", async () => {
    const root = tmpRoot();
    const fabric = governedFabric(root);
    fabric.decision({ sessionId: "s1", requestId: "r1" }, (d) => {
      d.llmCall(
        { model: "m", provider: "test-provider", inputMessages: [{ role: "user", content: "hi" }] },
        (call) => {
          call.setResponse({ outputMessages: [{ role: "assistant", content: "hello" }] });
        },
      );
    });
    await fabric.flushContent(5);
    const decisionSpan = spanByName("fabric.decision");
    const ref = decisionSpan.attributes["fabric.content.manifest_ref"] as string;
    expect(ref).toMatch(/manifests\//);
    const resolver = new ContentResolver([store(root)]);
    const exportDoc = (await resolver.exportTranscript(ref, {
      materialize: true,
    })) as {
      steps: { entries: { role: string; status: string; text?: unknown }[] }[];
      integrity: { verified: boolean; objects_checked: number; failures: unknown[] };
    };
    expect(exportDoc.integrity.verified).toBe(true);
    expect(exportDoc.integrity.objects_checked).toBeGreaterThanOrEqual(2);
    const roles = exportDoc.steps.flatMap((s) => s.entries.map((e) => e.role));
    expect(roles).toContain("model.request.messages");
    expect(roles).toContain("model.output.messages");
  });

  it("resolves pending and missing refs honestly", async () => {
    const root = tmpRoot();
    const s = store(root);
    const resolver = new ContentResolver([s]);
    const pendingRef = s.refFor("a".repeat(64));
    const result = await resolver.resolve(pendingRef);
    expect(result.status).toBe(ResolveStatus.MISSING);
    const denied = await resolver.resolve("file:///etc/passwd");
    expect(denied.status).toBe(ResolveStatus.DENIED);
    const foreignScheme = await resolver.resolve("s3://other-bucket/x/y");
    expect(foreignScheme.status).toBe(ResolveStatus.DENIED);
  });

  it("flags corrupted bytes on resolve", async () => {
    const root = tmpRoot();
    const s = store(root);
    const { descriptor, data } = buildContentDescriptor({
      tenantId: "acme",
      role: ContentRole.MODEL_REQUEST_MESSAGES,
      content: "original",
      mediaType: "text/plain",
      source: "caller",
      status: ContentStatus.STORED,
      bindings: {},
      payloadMaxBytes: 1024,
    });
    const ref = s.putObject(
      descriptor as unknown as Record<string, unknown>,
      new TextDecoder().decode(data),
    );
    const filePath = ref.uri.replace("file://", "");
    fs.writeFileSync(filePath, "tampered");
    const resolver = new ContentResolver([s]);
    const result = await resolver.resolve(
      ref.uri,
      descriptor as unknown as Record<string, unknown>,
    );
    expect(result.status).toBe(ResolveStatus.CORRUPTED);
  });

  it("materializes stored content verbatim on export", async () => {
    const root = tmpRoot();
    const s = store(root);
    const { descriptor, data } = buildContentDescriptor({
      tenantId: "acme",
      role: ContentRole.MODEL_REQUEST_MESSAGES,
      content: { text: "héllo" },
      mediaType: "application/json",
      source: "caller",
      status: ContentStatus.STORED,
      bindings: {},
      payloadMaxBytes: 1024,
    });
    s.putObject(descriptor as unknown as Record<string, unknown>, new TextDecoder().decode(data));
    const resolver = new ContentResolver([s]);
    const result = await resolver.resolve(
      s.refFor(descriptor.digest.slice(7)),
      descriptor as unknown as Record<string, unknown>,
    );
    expect(result.status).toBe(ResolveStatus.AVAILABLE);
    expect(new TextDecoder().decode(result.content)).toBe(canonicalJson({ text: "héllo" }));
  });
});

// -- spec 033 §2.1 — safe tenant identifiers + client/store agreement --------

describe("tenant isolation", () => {
  const badTenants = [
    "../escaped",
    "..",
    ".",
    "/absolute",
    "a/b",
    "a\\b",
    "..%2f..%2fetc",
    "%2e%2e",
    "tenant%00x",
    "",
    " ",
    "a b",
    "a;b",
    "a$b",
  ];
  for (const bad of badTenants) {
    it(`rejects unsafe tenant ${JSON.stringify(bad)}`, () => {
      expect(() => new LocalFilesystemContentStore(tmpRoot(), bad)).toThrow();
    });
  }

  for (const good of ["acme", "acme-prod", "acme.prod", "tenant_01", "T3nant"]) {
    it(`accepts safe tenant ${good}`, () => {
      expect(new LocalFilesystemContentStore(tmpRoot(), good).tenantId).toBe(good);
    });
  }

  it("rejects a client whose store tenant differs", () => {
    expect(
      () =>
        new Fabric({
          tenantId: "acme",
          agentId: "a",
          profile: "permissive-dev",
          contentCapture: {
            store: store(tmpRoot(), "other"),
            roles: "all",
            durability: "inline",
          },
        }),
    ).toThrow(/tenant/);
  });

  it("rejects unsafe S3 tenant and prefix", async () => {
    const { S3ContentStore } = await import("../src/index.js");
    expect(() => new S3ContentStore("acme-evidence", "a/b")).toThrow();
    expect(() => new S3ContentStore("acme-evidence", "..")).toThrow();
    expect(() => new S3ContentStore("acme-evidence", "acme", "fabric/../x/")).toThrow();
  });

  it("keeps identical content in two tenants isolated", async () => {
    const root = tmpRoot();
    const a = store(root, "tenant-a");
    const b = store(root, "tenant-b");
    const { descriptor } = buildContentDescriptor({
      tenantId: "tenant-a",
      role: ContentRole.INTERACTION_PAYLOAD,
      content: "same-bytes",
      mediaType: "text/plain",
      source: "caller",
      status: ContentStatus.STORED,
      bindings: {},
      payloadMaxBytes: 1024,
    });
    const ra = a.putObject(
      descriptor as unknown as Record<string, unknown>,
      "same-bytes",
    ) as ContentRef;
    const rb = b.putObject(
      { ...(descriptor as unknown as Record<string, unknown>), tenant_id: "tenant-b" },
      "same-bytes",
    ) as ContentRef;
    expect(ra.uri).not.toBe(rb.uri);
    const resolverA = new ContentResolver([a]);
    expect((await resolverA.resolve(ra.uri)).status).toBe(ResolveStatus.AVAILABLE);
    expect((await resolverA.resolve(rb.uri)).status).toBe(ResolveStatus.DENIED);
  });
});

// -- spec 033 §3 — verified resolution ----------------------------------------

describe("verified resolution", () => {
  function plant(root: string, digest: string, bytes: Uint8Array): string {
    const dir = path.join(root, "acme");
    fs.mkdirSync(dir, { recursive: true });
    const target = path.join(dir, digest);
    fs.writeFileSync(target, bytes);
    return `file://${target}`;
  }

  it("returns unverified when the descriptor sidecar is missing", async () => {
    const root = tmpRoot();
    const s = store(root);
    const uri = plant(root, "b".repeat(64), new TextEncoder().encode("payload"));
    const result = await new ContentResolver([s]).resolve(uri);
    expect(result.status).not.toBe(ResolveStatus.AVAILABLE);
    expect(result.content).toBeUndefined();
  });

  it("returns unverified when the descriptor is unreadable", async () => {
    const root = tmpRoot();
    const s = store(root);
    const digest = "b".repeat(64);
    const uri = plant(root, digest, new TextEncoder().encode("payload"));
    const meta = path.join(root, "acme", "meta");
    fs.mkdirSync(meta, { recursive: true });
    fs.writeFileSync(path.join(meta, `${digest}.json`), "{ not json");
    const result = await new ContentResolver([s]).resolve(uri);
    expect(result.status).not.toBe(ResolveStatus.AVAILABLE);
    expect(result.content).toBeUndefined();
  });

  it("denies a descriptor whose tenant differs from the store", async () => {
    const root = tmpRoot();
    const s = store(root);
    const { descriptor, data } = buildContentDescriptor({
      tenantId: "tenant-b",
      role: ContentRole.INTERACTION_PAYLOAD,
      content: "payload",
      mediaType: "text/plain",
      source: "caller",
      status: ContentStatus.STORED,
      bindings: {},
      payloadMaxBytes: 1024,
    });
    const digest = descriptor.digest.slice(7);
    const uri = plant(root, digest, data);
    const meta = path.join(root, "acme", "meta");
    fs.mkdirSync(meta, { recursive: true });
    fs.writeFileSync(path.join(meta, `${digest}.json`), JSON.stringify(descriptor, null, 2));
    const result = await new ContentResolver([s]).resolve(uri);
    expect([ResolveStatus.DENIED, ResolveStatus.CORRUPTED]).toContain(result.status);
    expect(result.content).toBeUndefined();
  });
});

// ----------------------------------------------------------------------- //
// spec 032 §5 — passive manifest/object delivery
// ----------------------------------------------------------------------- //

describe("passive delivery", () => {
  it("decision close does not wait on object delivery", async () => {
    const root = tmpRoot();
    const slow = new SlowStore(root, 400);
    const fabric = governedFabric(root, { store: slow, durability: "process" });
    const start = Date.now();
    await fabric.decision({ sessionId: "s", requestId: "r" }, async (d) => {
      d.recordContext("a.txt", "body");
    });
    expect(Date.now() - start).toBeLessThan(350);
    await fabric.flushContent(5);
    await fabric.close();
  });

  it("manifest_ref is computable before bytes land", async () => {
    const root = tmpRoot();
    const slow = new SlowStore(root, 400);
    const fabric = governedFabric(root, { store: slow, durability: "process" });
    let uri: string | undefined;
    await fabric.decision({ sessionId: "s", requestId: "r" }, async (d) => {
      d.recordContext("a.txt", "body");
      uri = d.contentManifestUri;
    });
    expect(uri).toMatch(/^file:\/\//);
    await fabric.flushContent(5);
    await fabric.close();
  });

  it("manifest bytes arrive via the writer, resolvable at the stamped URI", async () => {
    const root = tmpRoot();
    const s = store(root);
    const fabric = governedFabric(root, { store: s, durability: "process" });
    let uri: string | undefined;
    let decisionId = "";
    await fabric.decision({ sessionId: "s", requestId: "r" }, async (d) => {
      d.recordContext("a.txt", "body");
      uri = d.contentManifestUri;
      decisionId = d.decisionId;
    });
    await fabric.flushContent(5);
    await fabric.close();
    const manifest = s.readManifest(uri as string) as {
      decision_id: string;
      items: unknown[];
    };
    expect(manifest.decision_id).toBe(decisionId);
    expect(manifest.items.length).toBeGreaterThan(0);
  });

  it("keeps concurrent decisions and their content distinct", async () => {
    const root = tmpRoot();
    const s = store(root);
    const fabric = governedFabric(root, { store: s, durability: "process" });
    const records = await Promise.all(
      Array.from({ length: 16 }, async (_, index) => {
        let uri: string | undefined;
        let decisionId = "";
        await fabric.decision(
          { sessionId: "shared", requestId: `request-${index}` },
          async (decision) => {
            decision.recordContext(`context-${index}.txt`, `payload-${index}`);
            await Promise.resolve();
            uri = decision.contentManifestUri;
            decisionId = decision.decisionId;
          },
        );
        expect(uri).toBeDefined();
        return { index, uri: uri as string, decisionId };
      }),
    );
    const result = await fabric.flushContent(10);
    await fabric.close();
    expect(result?.pending).toBe(0);
    expect(new Set(records.map((record) => record.uri)).size).toBe(records.length);
    const resolver = new ContentResolver([s]);
    for (const record of records) {
      const manifest = s.readManifest(record.uri) as { decision_id: string };
      expect(manifest.decision_id).toBe(record.decisionId);
      const exported = (await resolver.exportTranscript(record.uri, { materialize: true })) as {
        steps: Array<{ entries: Array<{ role: string; text?: unknown }> }>;
      };
      const contextEntry = exported.steps
        .flatMap((step) => step.entries)
        .find((entry) => entry.role === ContentRole.CONTEXT_FILE);
      expect(contextEntry?.text).toBe(`payload-${record.index}`);
    }
  });
});

// ----------------------------------------------------------------------- //
// spec 032 §4 — durable spool records and recovery
// ----------------------------------------------------------------------- //

describe("durable spool", () => {
  function spoolConfig(root: string, overrides: Partial<ContentCaptureConfig> = {}) {
    return {
      store: store(root),
      roles: "all" as const,
      durability: "spooled" as const,
      spoolDir: path.join(root, "spool"),
      ...overrides,
    };
  }

  function descriptor(): ContentDescriptor {
    const { descriptor } = buildContentDescriptor({
      tenantId: "acme",
      role: ContentRole.INTERACTION_PAYLOAD,
      content: "payload",
      mediaType: "text/plain",
      source: "caller",
      status: ContentStatus.PENDING,
      bindings: {},
      payloadMaxBytes: 1024 * 1024,
    });
    return descriptor;
  }

  it("spool record carries full identity and a checksum", () => {
    const root = tmpRoot();
    const writer = new ContentWriter(spoolConfig(root));
    writer.submit(descriptor(), "payload", "d-9", "m-9", 3);
    const files = fs.readdirSync(path.join(root, "spool")).filter((f) => f.endsWith(".json"));
    // The worker may have drained already; if a record exists, inspect it.
    if (files.length > 0) {
      const record = JSON.parse(
        fs.readFileSync(path.join(root, "spool", files[0] as string), "utf-8"),
      ) as Record<string, unknown>;
      for (const key of [
        "schema_version",
        "kind",
        "key",
        "tenant_id",
        "decision_id",
        "manifest_id",
        "manifest_item_sequence",
        "descriptor",
        "content_b64",
        "attempts",
        "first_enqueued",
        "ref",
        "checksum",
      ]) {
        expect(record, `spool record missing ${key}`).toHaveProperty(key);
      }
      expect(record["tenant_id"]).toBe("acme");
      expect(record["decision_id"]).toBe("d-9");
      expect(record["manifest_id"]).toBe("m-9");
      expect(record["manifest_item_sequence"]).toBe(3);
    }
    void writer.close();
  });

  it("recovers more records than the in-memory queue capacity", async () => {
    const root = tmpRoot();
    const cfg = spoolConfig(root, { queueMaxItems: 2 });
    // Plant 5 valid records via a throwaway writer's spool path.
    const plant = new ContentWriter(cfg);
    for (let index = 0; index < 5; index += 1) {
      const d = descriptor();
      const task = {
        kind: "object" as const,
        key: `obj-${index}`,
        descriptor: { ...d, object_id: `obj-${index}` },
        content: "payload",
        decisionId: "d-r",
        tenantId: "acme",
        attempts: 0,
        firstEnqueued: Date.now() / 1000,
      };
      (plant as unknown as { spool(t: unknown): boolean }).spool(task);
    }
    await plant.close();
    const planted = fs
      .readdirSync(path.join(root, "spool"))
      .filter((f) => f.endsWith(".json")).length;
    expect(planted).toBe(5);
    const recovered = new ContentWriter(cfg);
    const result = await recovered.flush(10);
    await recovered.close();
    expect(result.stored).toBe(5);
    const remaining = fs.readdirSync(path.join(root, "spool")).filter((f) => f.endsWith(".json"));
    expect(remaining).toHaveLength(0);
  });

  it("quarantines a corrupt spool entry explicitly", async () => {
    const root = tmpRoot();
    const spoolDir = path.join(root, "spool");
    fs.mkdirSync(spoolDir, { recursive: true });
    fs.writeFileSync(
      path.join(spoolDir, "tampered.json"),
      JSON.stringify({ schema_version: 1, kind: "object", checksum: "0".repeat(64) }),
    );
    const writer = new ContentWriter(spoolConfig(root));
    expect(writer.stats()["corrupt"]).toBe(1);
    expect(fs.existsSync(path.join(spoolDir, "tampered.json"))).toBe(false);
    expect(fs.existsSync(path.join(spoolDir, "tampered.json.corrupt"))).toBe(true);
    await writer.close();
  });

  it("rejects queueMaxItems=0", () => {
    const root = tmpRoot();
    expect(() =>
      validateContentCaptureConfig(
        { store: store(root), roles: "all", queueMaxItems: 0 },
        CONTENT_ROLES,
      ),
    ).toThrow(/queueMaxItems must be positive/);
  });

  it("reconciles a recovered manifest after restart", async () => {
    const root = tmpRoot();
    const cfg = spoolConfig(root);
    const writer = new ContentWriter(cfg);
    const doc = {
      schema_version: "fabric.transcript-manifest/v1",
      manifest_id: "m-restart",
      decision_id: "d-restart",
      tenant_id: "acme",
    };
    writer.submitManifest(doc, "d-restart", "m-restart", "acme");
    await writer.close();
    // Delivered or still spooled — a recovered writer converges either way.
    const recovered = new ContentWriter(cfg);
    await recovered.flush(10);
    await recovered.close();
    const manifestPath = path.join(root, "acme", "manifests", "m-restart.json");
    const doc2 = JSON.parse(fs.readFileSync(manifestPath, "utf-8")) as {
      manifest_id: string;
    };
    expect(doc2.manifest_id).toBe("m-restart");
  });

  it("reconciles a recovered object into its owning manifest", async () => {
    const root = tmpRoot();
    const cfg = spoolConfig(root, { workerFlushIntervalMs: 60000 });
    const d = descriptor();
    const manifestId = "m-object-restart";
    const decisionId = "d-object-restart";
    const manifest = {
      schema_version: "fabric.transcript-manifest/v1",
      manifest_id: manifestId,
      tenant_id: "acme",
      agent_id: "bot",
      decision_id: decisionId,
      producer: { name: "test", version: "1", language: "typescript" },
      items: [
        {
          sequence: 0,
          role: d.role,
          status: "pending",
          descriptor: d,
          ref: cfg.store.refFor(d.digest.slice(7)),
        },
      ],
      completeness: { pending: 1 },
      coverage: { roles_enabled: [d.role], roles_observed: [d.role] },
    };
    const plant = new ContentWriter(cfg);
    const spool = (plant as unknown as { spool(task: unknown): boolean }).spool.bind(plant);
    expect(
      spool({
        kind: "manifest",
        key: `manifest:${manifestId}`,
        manifest,
        manifestId,
        manifestRevision: 1,
        decisionId,
        tenantId: "acme",
        attempts: 0,
        firstEnqueued: Date.now() / 1000,
      }),
    ).toBe(true);
    expect(
      spool({
        kind: "object",
        key: d.object_id,
        descriptor: d,
        content: "payload",
        manifestId,
        manifestItemSequence: 0,
        decisionId,
        tenantId: "acme",
        attempts: 0,
        firstEnqueued: Date.now() / 1000,
      }),
    ).toBe(true);
    await plant.close();

    const recovered = new ContentWriter(cfg);
    const result = await recovered.flush(10);
    await recovered.close();
    const doc = cfg.store.readManifest(cfg.store.manifestUriFor(manifestId)) as {
      items: Array<{ status: string; descriptor: { status: string } }>;
      completeness: Record<string, number>;
    };
    expect(result.pending).toBe(0);
    expect(doc.items[0]?.status).toBe("stored");
    expect(doc.items[0]?.descriptor.status).toBe("stored");
    expect(doc.completeness).toEqual({ stored: 1 });
    expect(fs.readdirSync(path.join(root, "spool")).filter((f) => f.endsWith(".json"))).toEqual([]);
  });

  it("does not let a stale manifest revision delete the latest spool", async () => {
    const root = tmpRoot();
    const cfg = spoolConfig(root, { workerFlushIntervalMs: 60000 });
    const writer = new ContentWriter(cfg);
    const first = {
      kind: "manifest" as const,
      key: "manifest:m-revision",
      manifest: { manifest_id: "m-revision", generation: 1 },
      manifestId: "m-revision",
      manifestRevision: 1,
      decisionId: "d-revision",
      tenantId: "acme",
      attempts: 0,
      firstEnqueued: Date.now() / 1000,
    };
    const latest = {
      ...first,
      manifest: { manifest_id: "m-revision", generation: 2 },
      manifestRevision: 2,
    };
    const internals = writer as unknown as {
      spool(task: unknown): boolean;
      spoolPath(task: unknown): string;
      deliver(task: unknown): Promise<void>;
      manifestRevisions: Map<string, number>;
    };
    expect(internals.spool(first)).toBe(true);
    expect(internals.spool(latest)).toBe(true);
    internals.manifestRevisions.set("m-revision", 2);
    const spoolPath = internals.spoolPath(latest);
    await internals.deliver(first);
    expect(fs.existsSync(spoolPath)).toBe(true);
    await internals.deliver(latest);
    expect(fs.existsSync(spoolPath)).toBe(false);
    const doc = await cfg.store.readManifest(cfg.store.manifestUriFor("m-revision"));
    expect(doc["generation"]).toBe(2);
    await writer.close();
  });

  it("does not suppress an accepted manifest when a newer rewrite drops", async () => {
    const root = tmpRoot();
    const cfg = {
      store: store(root),
      roles: "all" as const,
      durability: "process" as const,
      queueMaxItems: 1,
      workerFlushIntervalMs: 60000,
    };
    const writer = new ContentWriter(cfg);
    expect(
      writer.submitManifest(
        { manifest_id: "m-pressure", generation: 1 },
        "d-pressure",
        "m-pressure",
        "acme",
      ),
    ).toBe(ContentStatus.PENDING);
    expect(
      writer.submitManifest(
        { manifest_id: "m-pressure", generation: 2 },
        "d-pressure",
        "m-pressure",
        "acme",
      ),
    ).toBe(ContentStatus.DROPPED);
    await writer.close();
    const doc = cfg.store.readManifest(cfg.store.manifestUriFor("m-pressure"));
    expect(doc["generation"]).toBe(1);
  });
});
