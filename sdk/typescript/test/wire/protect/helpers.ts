// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Helpers of the PROTECT tests (spec 055 §9.5, unit 055-t8): deployment policies, one
 * completed exchange as the Fabric worker reads it, and the normalization that replaces
 * minted ids (object ids, span and trace ids) by their position, as §7.3's substitution.
 */
import { DeploymentPolicy } from "../../../src/deployment-policy.js";
import {
  LOCAL_DEFAULT,
  Protector,
  type CapturePolicy,
  type ContentGate,
  capturePolicyOf,
  decideGate,
} from "../../../src/wire/protect.js";
import type { CapturedExchange, Enrichment, PreparedExchange } from "../../../src/wire/writer.js";

export const TENANT = "tenant-a";
export const SOURCE = "s-" + "ab".repeat(16);
export const EPOCH = 1791331200000000000n;
export const TOKEN_KEY = Buffer.alloc(32, 7);
export const ID_KEY = Buffer.alloc(32, 3);

/** A valid deployment-policy/v1 document with this privacy map. */
export function policyDoc(
  privacy: Record<string, string>,
  profile: "local" | "production" = "local",
): Record<string, unknown> {
  return {
    schema_version: "fabric.deployment-policy/v1",
    policy_id: "wire-policy",
    policy_version: 3,
    tenant_id: TENANT,
    workload_id: "agent-workload",
    privacy,
    storage: { backend: "local", region: "local", key_id: "kid-test" },
    retention: { days: 30 },
    required_integrations: [],
    deployment: {
      profile,
      image_digest: profile === "production" ? "sha256:" + "0".repeat(64) : "local",
      tls_required: profile === "production",
      encrypted_store_required: profile === "production",
    },
  };
}

/** The capture policy giving both exchange roles `mode` (or the local default). */
export function policyFor(mode: string | undefined): CapturePolicy {
  if (mode === undefined) return LOCAL_DEFAULT;
  return capturePolicyOf(
    new DeploymentPolicy(
      policyDoc({ "model.exchange.request": mode, "model.exchange.response": mode }),
    ),
  );
}

export function enabledGate(policy: CapturePolicy): ContentGate {
  return {
    ...decideGate({
      node: true,
      store: false,
      policy: undefined,
      idKey: true,
      spool: true,
      spoolKey: true,
    }),
    policy,
  };
}

export const ENRICHMENT: Enrichment = {
  points: { "wire.ts.undici": "wire.ts.undici@1.0.0" },
  endpointIds: { openai: "openai.default" },
  identity: {},
  requestIdKey: undefined,
  modelAllowlist: [],
};

export const CHAT_REQUEST = Buffer.from(
  '{"model":"gpt-4o","messages":[{"role":"user","content":"PROMPT-CANARY-1"}]}',
);
export const CHAT_RESPONSE = Buffer.from(
  '{"id":"chatcmpl-1","model":"gpt-4o-2024-08-06","choices":[{"index":0,"finish_reason":"tool_calls",' +
    '"message":{"role":"assistant","content":"RESPONSE-CANARY-1"}}],"usage":{"prompt_tokens":12,"completion_tokens":7}}',
);

/** A completed chat completion with these bodies (deterministic ids and times). */
export function exchange(overrides: Partial<CapturedExchange> = {}): CapturedExchange {
  const side = (data: Buffer) => ({
    pieces: [data],
    observed: data.byteLength,
    truncated: false,
    cutReason: undefined,
    mediaType: "application/json",
    contentEncoding: "identity",
  });
  return {
    exchangeId: "6f1d2c3e-8a4b-4c5d-9e6f-0a1b2c3d4e5f",
    eventId: "6a1f0c3e-8b2d-4f5a-9c7e-1d2b3a4c5e6f",
    spanId: "a3ce929d0e0e4736",
    parent: {
      traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
      spanId: "00f067aa0ba902b7",
      remote: false,
    },
    api: "openai.chat_completions",
    providerName: "openai",
    endpointId: "openai",
    point: "wire.ts.undici",
    sourceId: SOURCE,
    sourceEpoch: EPOCH,
    sequence: 1n,
    segmentId: undefined,
    runId: undefined,
    scopeId: undefined,
    startNs: 1791331201120000000n,
    endNs: 1791331202050000000n,
    request: side(CHAT_REQUEST),
    response: side(CHAT_RESPONSE),
    responseState: "complete",
    statusCode: 200,
    errorType: undefined,
    firstChunkOffsetNs: 182000n,
    providerRequestId: undefined,
    withheld: false,
    ...overrides,
  };
}

export function protector(
  policy: CapturePolicy,
  options: Partial<ConstructorParameters<typeof Protector>[1]> = {},
): Protector {
  return new Protector(policy, {
    maxBodyBytes: 32 * 1024 * 1024,
    tokenizationKey: TOKEN_KEY,
    ...options,
  });
}

/**
 * The prepared exchange with every minted id replaced by its position: object ids by
 * `<object N>` (references to them too), descriptors and span as plain JSON values.
 */
export function normalized(prepared: PreparedExchange): { span: any; descriptors: any[] } {
  const ids = new Map<string, string>();
  prepared.objects.forEach((object, index) =>
    ids.set(String(object.descriptor.object_id), `<object ${index}>`),
  );
  const swap = (value: unknown): unknown => {
    if (typeof value === "bigint") return value;
    if (typeof value === "string") return ids.get(value) ?? value;
    if (Array.isArray(value)) return value.map(swap);
    if (value !== null && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, swap(v)]));
    }
    return value;
  };
  return {
    span: swap(prepared.span),
    descriptors: prepared.objects.map((object) => swap(object.descriptor)),
  };
}
