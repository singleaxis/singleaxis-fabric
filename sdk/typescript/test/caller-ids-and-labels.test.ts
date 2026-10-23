// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * v0.8.1 round-2 review F4 (spec 049 §2.9, §4.2), in parity with Python
 * `tests/test_caller_ids_and_labels.py`: the caller's execution, workflow,
 * decision, attempt and step ids, the workflow, prompt and skill names and the
 * agent name are mapped in pseudonymous mode, like `fabric.request_id`.
 *
 * - Caller ids are the keyed `lbl-` form, omitted without a key. An execution
 *   or decision id Fabric minted (uuid4) stays as is; a caller's is mapped,
 *   whatever its shape. A parent decision id arrives in a carrier: caller input.
 * - Workflow, prompt and skill names and versions are operator labels: `lbl-`,
 *   or as given with `FABRIC_WIRE_LABELS=clear`.
 * - The agent name is an agent identity: the keyed v2 `agt-` form.
 * - The tool description is free text with no identity value: omitted.
 * Clear mode reproduces v0.8.0.
 */

import {
  AlwaysOnSampler,
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-node";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Fabric } from "../src/index.js";
import { labelPseudonym, pseudonymV2 } from "../src/identity.js";

const KEY = "fabric-test-id-key-not-a-secret";
const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const IDS: Record<string, string> = {
  "fabric.execution_id": "exec-4711",
  "fabric.workflow_id": "wf-claims",
  "fabric.decision_id": "dec-4711",
  "fabric.parent_decision_id": "dec-parent-4711",
  "fabric.execution.attempt_id": "attempt-2",
  "fabric.execution.retry.previous_attempt_id": "attempt-1",
  "fabric.step.id": "step-lookup",
  "fabric.step.attempt_id": "step-attempt-2",
  "fabric.step.retry.previous_attempt_id": "step-attempt-1",
};
const LABELS: Record<string, string> = {
  "gen_ai.workflow.name": "claims-triage",
  "gen_ai.prompt.name": "triage-prompt",
  "gen_ai.prompt.version": "v7",
  "fabric.skill.name": "pdf-reader",
  "fabric.skill.version": "1.2.0",
};
const AGENT_NAME = "Jane's claims bot";
const DESCRIPTION = "Looks up the claim of the named patient";
const lbl = (value: string) => labelPseudonym("lbl", value, KEY);

const providers: BasicTracerProvider[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(providers.splice(0).map((p) => p.shutdown()));
});

function run(identityMode: "pseudonymous" | "clear", idKey?: string, minted = false) {
  const exporter = new InMemorySpanExporter();
  const provider = new BasicTracerProvider({
    sampler: new AlwaysOnSampler(),
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
  providers.push(provider);
  const fabric = new Fabric({
    tenantId: "acme",
    agentId: "bot",
    agentName: AGENT_NAME,
    tracerProvider: provider,
    identityMode,
    ...(idKey !== undefined ? { idKey } : {}),
  });
  fabric.execution(
    {
      workflowId: IDS["fabric.workflow_id"],
      executionAttemptId: IDS["fabric.execution.attempt_id"],
      executionRetryPreviousAttemptId: IDS["fabric.execution.retry.previous_attempt_id"],
      ...(minted ? {} : { executionId: IDS["fabric.execution_id"] }),
    },
    () =>
      fabric.decision(
        {
          sessionId: "s",
          requestId: "r",
          workflowName: LABELS["gen_ai.workflow.name"],
          context: {
            tenantId: "acme",
            agentId: "up",
            decisionId: IDS["fabric.parent_decision_id"],
          },
          ...(minted ? {} : { decisionId: IDS["fabric.decision_id"] }),
        },
        (d) => {
          d.recordSkill(LABELS["fabric.skill.name"]!, LABELS["fabric.skill.version"]!);
          d.llmCall(
            {
              provider: "openai",
              model: "m",
              promptName: LABELS["gen_ai.prompt.name"],
              promptVersion: LABELS["gen_ai.prompt.version"],
            },
            () => undefined,
          );
          d.toolCall(
            "lookup",
            {
              description: DESCRIPTION,
              stepId: IDS["fabric.step.id"],
              stepAttemptId: IDS["fabric.step.attempt_id"],
              stepRetryPreviousAttemptId: IDS["fabric.step.retry.previous_attempt_id"],
            },
            () => undefined,
          );
          d.recordReplayMetadata();
        },
      ),
  );
  const spans = exporter.getFinishedSpans();
  return (key: string): Set<unknown> =>
    new Set(
      spans
        .flatMap((s) => [s.attributes, ...s.events.map((e) => e.attributes ?? {})])
        .filter((a) => key in a)
        .map((a) => a[key]),
    );
}

describe("caller ids and labels (round-2 review F4)", () => {
  it("maps them with a key", () => {
    vi.stubEnv("FABRIC_WIRE_LABELS", "");
    const values = run("pseudonymous", KEY);
    for (const [key, value] of Object.entries({ ...IDS, ...LABELS })) {
      expect(values(key), key).toEqual(new Set([lbl(value)]));
    }
    expect(values("fabric.replay.decision_id")).toEqual(new Set([lbl(IDS["fabric.decision_id"]!)]));
    expect(values("fabric.replay.execution_id")).toEqual(
      new Set([lbl(IDS["fabric.execution_id"]!)]),
    );
    expect(values("gen_ai.agent.name")).toEqual(new Set([pseudonymV2("agt", AGENT_NAME, KEY)]));
    expect(values("gen_ai.tool.description")).toEqual(new Set());
  });

  it("keeps minted execution and decision ids as is", () => {
    const values = run("pseudonymous", KEY, true);
    for (const key of [
      "fabric.execution_id",
      "fabric.decision_id",
      "fabric.replay.decision_id",
      "fabric.replay.execution_id",
    ]) {
      const found = [...values(key)];
      expect(found, key).toHaveLength(1);
      expect(String(found[0]), key).toMatch(UUID4);
    }
    expect(values("fabric.execution_id")).toEqual(values("fabric.replay.execution_id"));
  });

  it("keeps labels clear with FABRIC_WIRE_LABELS=clear, ids still mapped", () => {
    vi.stubEnv("FABRIC_WIRE_LABELS", "clear");
    const values = run("pseudonymous", KEY);
    for (const [key, value] of Object.entries(LABELS)) {
      expect(values(key), key).toEqual(new Set([value]));
    }
    for (const [key, value] of Object.entries(IDS)) {
      expect(values(key), key).toEqual(new Set([lbl(value)]));
    }
    expect(values("gen_ai.agent.name")).toEqual(new Set([pseudonymV2("agt", AGENT_NAME, KEY)]));
  });

  it("omits them without a key", () => {
    vi.stubEnv("FABRIC_WIRE_ID_KEY", "");
    vi.stubEnv("FABRIC_WIRE_LABELS", "");
    const values = run("pseudonymous");
    for (const key of [
      ...Object.keys(IDS),
      ...Object.keys(LABELS),
      "gen_ai.agent.name",
      "gen_ai.tool.description",
      "fabric.replay.decision_id",
      "fabric.replay.execution_id",
    ]) {
      expect(values(key), key).toEqual(new Set());
    }
  });

  it("reproduces v0.8.0 in clear mode", () => {
    const values = run("clear", KEY);
    for (const [key, value] of Object.entries({ ...IDS, ...LABELS })) {
      expect(values(key), key).toEqual(new Set([value]));
    }
    expect(values("gen_ai.agent.name")).toEqual(new Set([AGENT_NAME]));
    expect(values("gen_ai.tool.description")).toEqual(new Set([DESCRIPTION]));
  });
});
