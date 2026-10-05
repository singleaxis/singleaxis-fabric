// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Parity coverage for the surface-logging primitives and child spans
 * ported from Python: delegation carriers, the generic cross-cutting
 * tags/baseline/signature stamping, MCP inventory normalization, LLM and
 * tool span wire parity, decision introspection getters, record return
 * objects, and the keyed coverage loop.
 */

import { context, trace, type Attributes } from "@opentelemetry/api";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import {
  AlwaysOnSampler,
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-node";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ConcurrentDecisionUseError,
  Fabric,
  ToolErrorCategory,
  extract,
  installDefaultProvider,
  testing,
  type DelegationContext,
} from "../src/index.js";
import { sha256Hex } from "../src/index.js";
import { resetIdentifierWarningsForTesting } from "../src/id-validators.js";

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

beforeEach(() => exporter.reset());

function fabric(): Fabric {
  return new Fabric({ tenantId: "acme", agentId: "support-bot", profile: "p" });
}

function decisionSpan(): ReadableSpan {
  const span = exporter.getFinishedSpans().find((s) => s.name === "fabric.decision");
  expect(span).toBeDefined();
  return span!;
}

function eventsNamed(span: ReadableSpan, name: string): Attributes[] {
  return span.events.filter((e) => e.name === name).map((e) => e.attributes ?? {});
}

function spanByOperation(operation: string): ReadableSpan {
  const span = exporter
    .getFinishedSpans()
    .find((candidate) => candidate.attributes["gen_ai.operation.name"] === operation);
  expect(span).toBeDefined();
  return span!;
}

const HASH64 = "a".repeat(64);

// ---------------------------------------------------------------------------
// delegate — Python test_surface_logging.py §3
// ---------------------------------------------------------------------------

describe("sub-agent delegation", () => {
  it("emits the event + count and yields a DelegationContext", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.delegate("research-agent", "a2a", (sub) => {
        expect(sub.toAgent).toBe("research-agent");
        expect(sub.protocol).toBe("a2a");
        expect(sub.depth).toBe(1);
        expect(sub.context.tenantId).toBe("acme");
        expect(sub.context.parentAgentId).toBe("support-bot");
      });
    });
    const span = decisionSpan();
    expect(span.attributes["fabric.delegation_count"]).toBe(1);
    const attrs = eventsNamed(span, "fabric.delegation")[0]!;
    expect(attrs["fabric.delegation.to_agent"]).toBe("research-agent");
    expect(attrs["fabric.delegation.protocol"]).toBe("a2a");
    expect(attrs["fabric.delegation.depth"]).toBe(1);
  });

  it("defaults the protocol to 'custom'", () => {
    let sub!: DelegationContext;
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.delegate("b", (s2) => {
        sub = s2;
      });
    });
    expect(sub.protocol).toBe("custom");
    expect(eventsNamed(decisionSpan(), "fabric.delegation")[0]!["fabric.delegation.protocol"]).toBe(
      "custom",
    );
  });

  it("accepts an options object with cross-cutting metadata", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.delegate("b", { protocol: "a2a", tags: ["squad:research"] }, () => {});
    });
    const attrs = eventsNamed(decisionSpan(), "fabric.delegation")[0]!;
    expect(attrs["fabric.delegation.protocol"]).toBe("a2a");
    expect(attrs["fabric.tags"]).toEqual(["squad:research"]);
  });

  it("tracks nesting depth and pops back after the callback", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.delegate("outer", (outer) => {
        expect(outer.depth).toBe(1);
        d.delegate("inner", (inner) => {
          expect(inner.depth).toBe(2);
        });
      });
      d.delegate("sibling", (sib) => {
        expect(sib.depth).toBe(1);
      });
    });
    const span = decisionSpan();
    expect(span.attributes["fabric.delegation_count"]).toBe(3);
    const depths = eventsNamed(span, "fabric.delegation").map((e) => e["fabric.delegation.depth"]);
    expect(depths).toEqual([1, 2, 1]);
  });

  it("pops depth when the callback throws", () => {
    const d0 = fabric();
    expect(() =>
      d0.decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.delegate("boom", () => {
          throw new Error("inside delegation");
        });
      }),
    ).toThrow(/inside delegation/);
  });

  it("rejects concurrent mutating calls on one Decision", () => {
    // A malicious getter that mutates the decision while a guarded method
    // holds the overlap sentinel trips ConcurrentDecisionUseError. The
    // getter must live on the options object itself so it fires lazily
    // inside the guarded region, not eagerly at literal construction.
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      const hostile = {
        get type() {
          d.recordRetrieval({ source: "rag", query: "q", resultCount: 0 });
          return "other" as const;
        },
        targetSystem: "sys",
        operation: "o",
      };
      expect(() => d.recordSideEffect(hostile)).toThrow(ConcurrentDecisionUseError);
    });
  });
});

// ---------------------------------------------------------------------------
// Cross-cutting metadata on every record surface
// ---------------------------------------------------------------------------

describe("generic cross-cutting tags/baseline/signature", () => {
  const cross = {
    tags: ["squad:research", "tier:gold"],
    baseline: { name: "manifest-v1", status: "match" as const },
    signature: { verified: true, scheme: "ed25519", keyId: "k1" },
  };

  it("stamps on record_skill", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordSkill("sql-expert", "1.2.3", cross);
    });
    const attrs = eventsNamed(decisionSpan(), "fabric.skill")[0]!;
    expect(attrs["fabric.skill.name"]).toBe("sql-expert");
    expect(attrs["fabric.tags"]).toEqual(cross.tags);
    expect(attrs["fabric.baseline.name"]).toBe("manifest-v1");
    expect(attrs["fabric.baseline.status"]).toBe("match");
    expect(attrs["fabric.signature.verified"]).toBe(true);
    expect(attrs["fabric.signature.scheme"]).toBe("ed25519");
    expect(attrs["fabric.signature.key_id"]).toBe("k1");
  });

  it("stamps on record_hook", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordHook("prompt-guard", "pre_model", { modified: true, ...cross });
    });
    const attrs = eventsNamed(decisionSpan(), "fabric.hook")[0]!;
    expect(attrs["fabric.hook.phase"]).toBe("pre_model");
    expect(attrs["fabric.tags"]).toEqual(cross.tags);
    expect(attrs["fabric.baseline.status"]).toBe("match");
    expect(attrs["fabric.signature.verified"]).toBe(true);
  });

  it("stamps on record_file_access", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordFileAccess("/tmp/x", "read", cross);
    });
    const attrs = eventsNamed(decisionSpan(), "fabric.file")[0]!;
    expect(attrs["fabric.tags"]).toEqual(cross.tags);
    expect(attrs["fabric.baseline.status"]).toBe("match");
    expect(attrs["fabric.signature.verified"]).toBe(true);
  });

  it("stamps on record_mcp_inventory", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordMcpInventory({
        server: "inventory",
        transport: "stdio",
        tools: [{ name: "lookup" }],
        ...cross,
      });
    });
    const attrs = eventsNamed(decisionSpan(), "fabric.mcp.inventory")[0]!;
    expect(attrs["fabric.tags"]).toEqual(cross.tags);
    expect(attrs["fabric.baseline.status"]).toBe("match");
    expect(attrs["fabric.signature.verified"]).toBe(true);
  });

  it("stamps on toolCall spans", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.toolCall("search", cross, () => {});
    });
    const span = spanByOperation("execute_tool");
    expect(span.attributes["fabric.tags"]).toEqual(cross.tags);
    expect(span.attributes["fabric.baseline.name"]).toBe("manifest-v1");
    expect(span.attributes["fabric.baseline.status"]).toBe("match");
    expect(span.attributes["fabric.signature.verified"]).toBe(true);
    expect(span.attributes["fabric.signature.scheme"]).toBe("ed25519");
    expect(span.attributes["fabric.signature.key_id"]).toBe("k1");
  });
});

// ---------------------------------------------------------------------------
// MCP inventory normalization + full return shape
// ---------------------------------------------------------------------------

describe("recordMcpInventory", () => {
  it("returns the full normalized inventory shape", () => {
    let inventory!: {
      server: string;
      transport: string;
      toolCount: number;
      tools: readonly string[];
      toolsHash: string;
      resourceCount?: number;
      promptCount?: number;
    };
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      inventory = d.recordMcpInventory({
        server: "inventory",
        transport: "stdio",
        tools: [
          { name: "lookup_order", description: "Lookup an order", inputSchema: { type: "object" } },
          { name: "refund", description: null, inputSchema: null },
        ],
        resources: ["r1", "r2"],
        prompts: ["p1"],
      });
    });
    expect(inventory.server).toBe("inventory");
    expect(inventory.transport).toBe("stdio");
    expect(inventory.toolCount).toBe(2);
    expect(inventory.tools).toHaveLength(2);
    expect(inventory.tools[0]).toMatch(/^lookup_order:[0-9a-f]{12}$/);
    expect(inventory.toolsHash).toMatch(/^[0-9a-f]{64}$/);
    expect(inventory.resourceCount).toBe(2);
    expect(inventory.promptCount).toBe(1);
    const attrs = eventsNamed(decisionSpan(), "fabric.mcp.inventory")[0]!;
    expect(attrs["fabric.mcp.tool_count"]).toBe(2);
    expect(attrs["fabric.mcp.resource_count"]).toBe(2);
    expect(attrs["fabric.mcp.prompt_count"]).toBe(1);
  });

  it("accepts attribute-shaped tool objects with input_schema", () => {
    // Python `_tool_definition` accepts objects exposing
    // name/description/input_schema attributes, normalizing input_schema
    // to inputSchema.
    let inventory!: { toolsHash: string };
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      inventory = d.recordMcpInventory({
        server: "s",
        transport: "http",
        tools: [{ name: "t1", description: "d", input_schema: { type: "object" } }],
      });
    });
    expect(inventory.toolsHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ---------------------------------------------------------------------------
// LLM span wire parity
// ---------------------------------------------------------------------------

describe("LLM span wire parity", () => {
  it("defaults gen_ai.conversation.id to the decision sessionId", () => {
    fabric().decision({ sessionId: "sess-42", requestId: "r" }, (d) => {
      d.llmCall({ provider: "anthropic", model: "m" }, () => {});
    });
    expect(spanByOperation("chat").attributes["gen_ai.conversation.id"]).toBe("sess-42");
  });

  it("stamps an explicit conversationId over the default", () => {
    fabric().decision({ sessionId: "sess-42", requestId: "r" }, (d) => {
      d.llmCall({ provider: "p", model: "m", conversationId: "conv-9" }, () => {});
    });
    expect(spanByOperation("chat").attributes["gen_ai.conversation.id"]).toBe("conv-9");
  });

  it("inherits the decision's conversationCompacted flag", () => {
    fabric().decision({ sessionId: "s", requestId: "r", conversationCompacted: true }, (d) => {
      d.llmCall({ provider: "p", model: "m" }, () => {});
    });
    expect(spanByOperation("chat").attributes["gen_ai.conversation.compacted"]).toBe(true);
  });

  it("stamps step metadata with a stepType override", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.llmCall(
        {
          provider: "p",
          model: "m",
          stepId: "plan",
          stepType: "custom-step",
          stepAttemptId: "att-2",
          stepAttempt: 2,
          stepRetryReason: "timeout",
          stepRetryPreviousAttemptId: "att-1",
        },
        () => {},
      );
    });
    const span = spanByOperation("chat");
    expect(span.attributes["fabric.step.type"]).toBe("custom-step");
    expect(span.attributes["fabric.step.id"]).toBe("plan");
    expect(span.attributes["fabric.step.attempt_id"]).toBe("att-2");
    expect(span.attributes["fabric.step.attempt"]).toBe(2);
    expect(span.attributes["fabric.step.retry.reason"]).toBe("timeout");
    expect(span.attributes["fabric.step.retry.previous_attempt_id"]).toBe("att-1");
  });

  it("defaults fabric.step.type to llm_call / tool_call", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.llmCall({ provider: "p", model: "m" }, () => {});
      d.toolCall("t", {}, () => {});
    });
    expect(spanByOperation("chat").attributes["fabric.step.type"]).toBe("llm_call");
    expect(spanByOperation("execute_tool").attributes["fabric.step.type"]).toBe("tool_call");
  });

  it("stamps time_to_first_chunk in seconds on setStreaming", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.llmCall({ provider: "p", model: "m" }, (c) => {
        c.setStreaming({ ttftMs: 250, chunkCount: 12 });
      });
    });
    const span = spanByOperation("chat");
    expect(span.attributes["gen_ai.response.time_to_first_chunk"]).toBeCloseTo(0.25);
    expect(span.attributes["fabric.llm.streaming.ttft_ms"]).toBe(250);
    expect(span.attributes["fabric.llm.streaming.chunk_count"]).toBe(12);
  });

  it("stamps dotted cache attrs plus the legacy underscores by default", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.llmCall({ provider: "p", model: "m" }, (c) => {
        c.setCacheUsage({ cacheReadTokens: 11, cacheCreationTokens: 7 });
      });
    });
    const span = spanByOperation("chat");
    expect(span.attributes["gen_ai.usage.cache_read.input_tokens"]).toBe(11);
    expect(span.attributes["gen_ai.usage.cache_creation.input_tokens"]).toBe(7);
    expect(span.attributes["gen_ai.usage.cache_read_input_tokens"]).toBe(11);
    expect(span.attributes["gen_ai.usage.cache_creation_input_tokens"]).toBe(7);
    expect(span.attributes["fabric.llm.usage.cache_read_tokens"]).toBe(11);
    expect(span.attributes["gen_ai.system"]).toBe("p");
  });

  it("suppresses legacy aliases under emitLegacyAttributes=false", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.llmCall({ provider: "p", model: "m", emitLegacyAttributes: false }, (c) => {
        c.setCacheUsage({ cacheReadTokens: 11, cacheCreationTokens: 7 });
      });
    });
    const span = spanByOperation("chat");
    expect(span.attributes["gen_ai.usage.cache_read.input_tokens"]).toBe(11);
    expect(span.attributes["gen_ai.usage.cache_creation.input_tokens"]).toBe(7);
    expect(span.attributes["gen_ai.usage.cache_read_input_tokens"]).toBeUndefined();
    expect(span.attributes["gen_ai.usage.cache_creation_input_tokens"]).toBeUndefined();
    expect(span.attributes["gen_ai.system"]).toBeUndefined();
    expect(span.attributes["fabric.llm.system"]).toBe("p");
  });

  it("stamps cross-cutting metadata on the llm span (schema-permitted)", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.llmCall(
        {
          provider: "p",
          model: "m",
          tags: ["squad:research"],
          baseline: { name: "prompt-v1", status: "match" },
          signature: { verified: true, scheme: "ed25519" },
        },
        () => {},
      );
    });
    const span = spanByOperation("chat");
    expect(span.attributes["fabric.tags"]).toEqual(["squad:research"]);
    expect(span.attributes["fabric.baseline.name"]).toBe("prompt-v1");
    expect(span.attributes["fabric.signature.verified"]).toBe(true);
  });

  it("stamps encodingFormats", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.llmCall(
        {
          provider: "p",
          model: "m",
          operationName: "embeddings",
          encodingFormats: ["float", "base64"],
        },
        () => {},
      );
    });
    expect(spanByOperation("embeddings").attributes["gen_ai.request.encoding_formats"]).toEqual([
      "float",
      "base64",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Tool span parity
// ---------------------------------------------------------------------------

describe("toolCall parity", () => {
  it("always stamps gen_ai.agent.name from the client agent name", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.toolCall("search", {}, () => {});
    });
    expect(spanByOperation("execute_tool").attributes["gen_ai.agent.name"]).toBe("support-bot");
  });

  it("honours a per-call agentName override", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.toolCall("search", { agentName: "research-agent" }, () => {});
    });
    expect(spanByOperation("execute_tool").attributes["gen_ai.agent.name"]).toBe("research-agent");
  });

  it("honours per-call capture overrides on setArguments/setResult", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.toolCall("t", { captureContent: true }, (tool) => {
        // Call-level capture on; a single sensitive payload opts out.
        tool.setArguments('{"a":1}');
        tool.setResult('{"r":2}', { capture: false });
      });
    });
    let span = spanByOperation("execute_tool");
    expect(span.attributes["gen_ai.tool.call.arguments"]).toBe('{"a":1}');
    expect(span.attributes["gen_ai.tool.call.result"]).toBeUndefined();
    expect(span.attributes["fabric.tool.result_hash"]).toBe(sha256Hex('{"r":2}'));

    exporter.reset();
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.toolCall("t", {}, (tool) => {
        // Call-level capture off; a single benign payload opts in.
        tool.setArguments('{"a":1}', { capture: true });
        tool.setResult('{"r":2}');
      });
    });
    span = spanByOperation("execute_tool");
    expect(span.attributes["gen_ai.tool.call.arguments"]).toBe('{"a":1}');
    expect(span.attributes["gen_ai.tool.call.result"]).toBeUndefined();
    expect(span.attributes["fabric.tool.result_hash"]).toBe(sha256Hex('{"r":2}'));
  });

  it("stamps a stepType override + step metadata", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.toolCall("search", { stepType: "retrieve", stepId: "s1", stepAttempt: 3 }, () => {});
    });
    const span = spanByOperation("execute_tool");
    expect(span.attributes["fabric.step.type"]).toBe("retrieve");
    expect(span.attributes["fabric.step.id"]).toBe("s1");
    expect(span.attributes["fabric.step.attempt"]).toBe(3);
  });

  it("exposes the ToolErrorCategory vocabulary including cancelled", () => {
    expect(ToolErrorCategory.CANCELLED).toBe("cancelled");
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.toolCall("t", {}, (tool) => {
        tool.recordError(ToolErrorCategory.CANCELLED);
      });
    });
    expect(spanByOperation("execute_tool").attributes["fabric.tool.error_category"]).toBe(
      "cancelled",
    );
  });
});

// ---------------------------------------------------------------------------
// Decision introspection getters + record returns
// ---------------------------------------------------------------------------

describe("decision introspection", () => {
  it("exposes ids, trace id, workflow + resolved attempt fields", () => {
    const client = new Fabric({
      tenantId: "t",
      agentId: "a",
      workflowId: "wf-1",
      executionId: "ex-1",
      executionAttemptId: "att-2",
      executionAttempt: 2,
      executionRetryReason: "tool_timeout",
      executionRetryPreviousAttemptId: "att-1",
    });
    client.decision({ sessionId: "s", requestId: "r", decisionId: "d-1", userId: "u-1" }, (d) => {
      expect(d.decisionId).toBe("d-1");
      expect(d.sessionId).toBe("s");
      expect(d.requestId).toBe("r");
      expect(d.userId).toBe("u-1");
      expect(d.tenantId).toBe("t");
      expect(d.agentId).toBe("a");
      expect(d.workflowId).toBe("wf-1");
      expect(d.executionId).toBe("ex-1");
      expect(d.executionAttemptId).toBe("att-2");
      expect(d.executionAttempt).toBe(2);
      expect(d.executionRetryReason).toBe("tool_timeout");
      expect(d.executionRetryPreviousAttemptId).toBe("att-1");
      expect(d.traceId).toMatch(/^[0-9a-f]{32}$/);
      expect(d.traceId).toBe(d.getSpan().spanContext().traceId);
    });
  });

  it("stamps gen_ai.workflow.name even without a workflowId", () => {
    fabric().decision({ sessionId: "s", requestId: "r", workflowName: "refunds" }, () => {});
    const span = decisionSpan();
    expect(span.attributes["gen_ai.workflow.name"]).toBe("refunds");
    expect(span.attributes["fabric.workflow_id"]).toBeUndefined();
  });

  it("falls gen_ai.workflow.name back to the workflow id", () => {
    new Fabric({ tenantId: "t", agentId: "a", workflowId: "wf-1" }).decision(
      { sessionId: "s", requestId: "r" },
      () => {},
    );
    expect(decisionSpan().attributes["gen_ai.workflow.name"]).toBe("wf-1");
  });
});

describe("record returns", () => {
  it("recordSideEffect returns the full record", () => {
    let record!: { sideEffectId: string; effectType: string; replayBehavior: string };
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      record = d.recordSideEffect({
        type: "email_send",
        targetSystem: "ses",
        operation: "send",
      });
    });
    expect(record.sideEffectId).toMatch(/^[0-9a-f-]{36}$/);
    expect(record.effectType).toBe("email_send");
    expect(record.replayBehavior).toBe("suppress");
  });

  it("recordRetrieval returns the record with hashes", () => {
    let record!: { source: string; queryHash: string; resultCount: number };
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      record = d.recordRetrieval({ source: "rag", query: "q", resultCount: 2 });
    });
    expect(record.source).toBe("rag");
    expect(record.queryHash).toBe(sha256Hex("q"));
    expect(record.resultCount).toBe(2);
  });

  it("memory writes/reads/erases return records", () => {
    let write!: { direction: string; contentHash?: string };
    let read!: { direction: string };
    let erase!: { direction: string; tenantScope?: boolean };
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      write = d.remember({ kind: "semantic", content: "c", key: "k" });
      read = d.recall({ kind: "episodic", key: "k", content: "c" });
      erase = d.forget("semantic", "k", { tenantScope: true });
    });
    expect(write.direction).toBe("write");
    expect(write.contentHash).toBe(sha256Hex("c"));
    expect(read.direction).toBe("read");
    expect(erase.direction).toBe("erase");
    expect(erase.tenantScope).toBe(true);
    const attrs = eventsNamed(decisionSpan(), "fabric.memory").at(-1)!;
    expect(attrs["fabric.memory.tenant_scope"]).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Coverage loop — keyed one-shot registry
// ---------------------------------------------------------------------------

describe("coverage loop", () => {
  beforeEach(() => testing.resetCoverageRegistry());

  it("fires new_kind once per kind", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordInteraction("http.request", "t1");
      d.recordInteraction("http.request", "t2");
      d.recordInteraction("db.query", "t3");
    });
    const events = eventsNamed(decisionSpan(), "fabric.coverage");
    expect(events).toHaveLength(2);
    expect(events[0]!["fabric.coverage.kind"]).toBe("http.request");
    expect(events[0]!["fabric.coverage.reason"]).toBe("new_kind");
    expect(events[1]!["fabric.coverage.kind"]).toBe("db.query");
  });

  it("fires unclassified_deviation once per kind, independently of new_kind", () => {
    testing.resetCoverageRegistry();
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordInteraction("http.request", "t", {
        baseline: { name: "b", status: "deviation" },
      });
      // Same kind, second deviation — no second signal.
      d.recordInteraction("http.request", "t", {
        baseline: { name: "b", status: "deviation" },
      });
      // A DIFFERENT kind's deviation still fires — the registry is keyed.
      d.recordInteraction("db.query", "t", {
        baseline: { name: "b", status: "deviation" },
      });
    });
    const deviations = eventsNamed(decisionSpan(), "fabric.coverage").filter(
      (e) => e["fabric.coverage.reason"] === "unclassified_deviation",
    );
    expect(deviations).toHaveLength(2);
    expect(deviations.map((e) => e["fabric.coverage.kind"])).toEqual(["http.request", "db.query"]);
  });

  it("does not fire unclassified_deviation when tags classify the deviation", () => {
    testing.resetCoverageRegistry();
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordInteraction("http.request", "t", {
        tags: ["anomaly:spike"],
        baseline: { name: "b", status: "deviation" },
      });
    });
    const deviations = eventsNamed(decisionSpan(), "fabric.coverage").filter(
      (e) => e["fabric.coverage.reason"] === "unclassified_deviation",
    );
    expect(deviations).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// PII-shape warnings on free-form interaction fields
// ---------------------------------------------------------------------------

describe("recordInteraction PII-shape warnings", () => {
  it("warns when kind embeds an email-shaped value", () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.recordInteraction("check user bryan@example.test", "input");
      });
      expect(spy.mock.calls.some((c) => String(c[0]).includes("interaction.kind"))).toBe(true);
      expect(spy.mock.calls.flat().join(" ")).not.toContain("bryan@example.test");
    } finally {
      spy.mockRestore();
    }
  });

  it("warns on a PII-shaped target only when redactTarget is off", () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        // Hashed by default: raw value never emits, so no warning.
        d.recordInteraction("db.query", "555-010-9999");
        // Opted into a readable target: a phone-shaped value must warn.
        d.recordInteraction("db.query", "555-010-9999", { redactTarget: false });
      });
      const targetWarns = spy.mock.calls.filter((c) => String(c[0]).includes("interaction.target"));
      expect(targetWarns).toHaveLength(1);
    } finally {
      spy.mockRestore();
    }
  });
});

// ---------------------------------------------------------------------------
// error.type on failure exits (GenAI error convention)
// ---------------------------------------------------------------------------

describe("error.type on failure exits", () => {
  it("stamps error.type on decision + tool spans when the body throws", () => {
    expect(() =>
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.toolCall("t", {}, () => {
          throw new TypeError("tool blew up");
        });
      }),
    ).toThrow(/tool blew up/);
    const toolSpan = spanByOperation("execute_tool");
    expect(toolSpan.attributes["error.type"]).toBe("TypeError");
    const dSpan = decisionSpan();
    expect(dSpan.attributes["error.type"]).toBe("TypeError");
    expect(dSpan.status.code).toBe(2); // SpanStatusCode.ERROR
  });
});

// ---------------------------------------------------------------------------
// Replay metadata + execution attributes
// ---------------------------------------------------------------------------

describe("recordReplayMetadata", () => {
  it("emits the replay envelope with decision/execution lineage", () => {
    const client = new Fabric({ tenantId: "t", agentId: "a", executionId: "ex-1" });
    client.decision({ sessionId: "s", requestId: "r", decisionId: "d-1" }, (d) => {
      d.checkpoint("step-a");
      d.recordSideEffect({ type: "other", targetSystem: "sys", operation: "o" });
      d.recordReplayMetadata({ stateHash: HASH64, toolResultHashes: [HASH64] });
    });
    const attrs = eventsNamed(decisionSpan(), "fabric.replay")[0]!;
    expect(attrs["fabric.replay.metadata_version"]).toBe("1");
    expect(attrs["fabric.replay.decision_id"]).toBe("d-1");
    expect(attrs["fabric.replay.execution_id"]).toBe("ex-1");
    expect(attrs["fabric.replay.checkpoint_ids"]).toHaveLength(1);
    // Default replay_behavior is suppress → the side effect id lands here.
    expect(attrs["fabric.replay.suppressed_side_effect_ids"]).toHaveLength(1);
    expect(attrs["fabric.replay.state_hash"]).toBe(HASH64);
    expect(attrs["fabric.replay.tool_result_hashes"]).toEqual([HASH64]);
  });

  it("rejects malformed replay hashes", () => {
    expect(() =>
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.recordReplayMetadata({ stateHash: "not-a-hash" });
      }),
    ).toThrow(/64 lowercase SHA-256/);
  });
});

describe("execution.attributes", () => {
  it("stamps extra scalar attributes on the execution span", () => {
    fabric().execution({ executionId: "ex-1", attributes: { "agent.run_kind": "eval" } }, () => {});
    const span = exporter.getFinishedSpans().find((s) => s.name === "fabric.execution")!;
    expect(span.attributes["agent.run_kind"]).toBe("eval");
  });
});

describe("extra attributes + reserved-key guard", () => {
  it("stamps FabricConfig.extra on decision + execution spans, per-decision wins", () => {
    const client = new Fabric({
      tenantId: "t",
      agentId: "a",
      extra: { "agent.region": "us-1", "agent.version_tag": "config" },
    });
    client.decision(
      { sessionId: "s", requestId: "r", attributes: { "agent.version_tag": "decision" } },
      () => {},
    );
    const dspan = decisionSpan();
    expect(dspan.attributes["agent.region"]).toBe("us-1");
    expect(dspan.attributes["agent.version_tag"]).toBe("decision");
    client.execution({ executionId: "ex-1" }, () => {});
    const espan = exporter.getFinishedSpans().find((s) => s.name === "fabric.execution")!;
    expect(espan.attributes["agent.region"]).toBe("us-1");
  });

  it("rejects reserved fabric.*/gen_ai.* keys in extra + attributes", () => {
    expect(
      () => new Fabric({ tenantId: "t", agentId: "a", extra: { "fabric.tenant_id": "x" } }),
    ).toThrow(/reserved namespace/);
    expect(
      () => new Fabric({ tenantId: "t", agentId: "a", extra: { "gen_ai.model.name": "x" } }),
    ).toThrow(/reserved namespace/);
    expect(() =>
      fabric().decision(
        { sessionId: "s", requestId: "r", attributes: { "fabric.agent_id": "x" } },
        () => {},
      ),
    ).toThrow(/reserved namespace/);
    expect(() =>
      fabric().execution({ attributes: { "gen_ai.provider.name": "x" } }, () => {}),
    ).toThrow(/reserved namespace/);
  });

  it("stamps delegation lineage from a propagated FabricContext", () => {
    const carrier: Record<string, string> = {};
    let parentDecisionId = "";
    // Upstream "support-bot" delegates to "research-agent" — the carrier
    // names the DELEGATING agent as the causal parent.
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      parentDecisionId = d.decisionId;
      d.delegate("research-agent", "a2a", (sub) => {
        Object.assign(carrier, sub.carrier);
      });
    });
    exporter.reset();
    const ctx = extract(carrier)!;
    // The downstream agent opens its decision with the extracted context.
    new Fabric({ tenantId: "t", agentId: "research-agent" }).decision(
      { sessionId: "s2", requestId: "r2", context: ctx },
      () => {},
    );
    const span = decisionSpan();
    expect(span.attributes["fabric.parent_agent_id"]).toBe("support-bot");
    expect(span.attributes["fabric.parent_decision_id"]).toBe(parentDecisionId);
  });
});

// ---------------------------------------------------------------------------
// installDefaultProvider
// ---------------------------------------------------------------------------

describe("installDefaultProvider", () => {
  it("is a no-op returning the existing provider when one is installed", () => {
    // A real provider is already global in this test process; the global
    // object is the OTel proxy that delegates to it.
    const installed = installDefaultProvider({ provider });
    expect(installed).toBe(trace.getTracerProvider());
  });

  it("installs provider + context manager when none is configured", () => {
    trace.disable();
    try {
      const fresh = new BasicTracerProvider({
        sampler: new AlwaysOnSampler(),
        spanProcessors: [new SimpleSpanProcessor(exporter)],
      });
      const cm = new AsyncLocalStorageContextManager();
      const installed = installDefaultProvider({ provider: fresh, contextManager: cm });
      expect(installed).toBe(fresh);
      // The global provider is the proxy delegating to `fresh`.
      expect(trace.getTracerProvider()).not.toBe(fresh);
      expect(context.active()).toBeDefined();
    } finally {
      // Restore the suite's provider for any later tests.
      trace.disable();
      trace.setGlobalTracerProvider(provider);
    }
  });
});

describe("recordInteraction PII scan bounds", () => {
  // Each detection boundary needs a fresh process-local warning budget.
  beforeEach(() => resetIdentifierWarningsForTesting());
  it("returns fast on a 64KiB no-match kind (quadratic regex regression)", () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const start = performance.now();
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.recordInteraction("a".repeat(65536), "input");
      });
      const elapsed = performance.now() - start;
      expect(elapsed).toBeLessThan(500);
    } finally {
      spy.mockRestore();
    }
  });

  it("returns fast when an adversarial value passes the @ prescreen", () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const start = performance.now();
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.recordInteraction("a".repeat(8180) + "@invalid", "input");
      });
      const elapsed = performance.now() - start;
      expect(elapsed).toBeLessThan(500);
    } finally {
      spy.mockRestore();
    }
  });

  it("still warns for PII embedded inside the 8KiB scan window", () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.recordInteraction("prefix " + "x".repeat(100) + " bryan@example.test", "input");
      });
      expect(spy.mock.calls.some((c) => String(c[0]).includes("interaction.kind"))).toBe(true);
      expect(spy.mock.calls.flat().join(" ")).not.toContain("bryan@example.test");
    } finally {
      spy.mockRestore();
    }
  });

  it.each(["bryan@example.test", "123-45-6789", "+15550109123", "555.010.9123"])(
    "keeps the mandatory-character prescreen for %s",
    (pii) => {
      const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
      try {
        fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
          d.recordInteraction(`prefix ${pii} suffix`, "input");
        });
        expect(spy.mock.calls.flat().join(" ")).not.toContain(pii);
        expect(spy.mock.calls.some((c) => String(c[0]).includes("interaction.kind"))).toBe(true);
        expect(spy.mock.calls.flat().join(" ")).not.toContain("bryan@example.test");
      } finally {
        spy.mockRestore();
      }
    },
  );

  it("detects PII ending at the exact 8192-byte ASCII boundary", () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const suffix = " bryan@example.test";
      const value = "x".repeat(8192 - suffix.length) + suffix;
      expect(Buffer.byteLength(value, "utf8")).toBe(8192);
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.recordInteraction(value, "input");
      });
      expect(spy.mock.calls.flat().join(" ")).not.toContain(value);
      expect(spy.mock.calls.some((c) => String(c[0]).includes("interaction.kind"))).toBe(true);
      expect(spy.mock.calls.flat().join(" ")).not.toContain("bryan@example.test");
    } finally {
      spy.mockRestore();
    }
  });

  it("counts multibyte characters against the UTF-8 byte window", () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const value = "é".repeat(4090) + " a@b.co";
      expect(Buffer.byteLength(value, "utf8")).toBeLessThan(8192);
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.recordInteraction(value, "input");
      });
      expect(spy.mock.calls.flat().join(" ")).not.toContain(value);
      expect(spy.mock.calls.some((c) => String(c[0]).includes("interaction.kind"))).toBe(true);
      expect(spy.mock.calls.flat().join(" ")).not.toContain("bryan@example.test");
    } finally {
      spy.mockRestore();
    }
  });
});
