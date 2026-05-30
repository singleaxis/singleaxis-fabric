// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * The `Fabric` client — the entry point tenant agents construct once and
 * reuse. Safe to share across the process. Per-turn {@link Decision}
 * instances are NOT shareable.
 */

import { trace, type Tracer, type TracerProvider } from "@opentelemetry/api";

import {
  Decision,
  runDecision,
  startDecision,
  type DecisionClientIdentity,
  type DecisionIds,
} from "./decision.js";

/** Tracer name used for all Fabric spans. */
export const TRACER_NAME = "@singleaxis/fabric";

/** Construction config for {@link Fabric}. */
export interface FabricConfig {
  /** Tenant identifier. Required. */
  tenantId: string;
  /** Agent identifier. Required. */
  agentId: string;
  /** Governance profile. Defaults to `"default"`. */
  profile?: string;
  workflowId?: string;
  executionId?: string;
  /**
   * Optional explicit TracerProvider. Defaults to the global provider
   * (set via `@opentelemetry/sdk-trace-node` `NodeTracerProvider`).
   */
  tracerProvider?: TracerProvider;
}

/** The Fabric capture client. */
export class Fabric {
  private readonly identity: DecisionClientIdentity;
  private readonly tracer: Tracer;

  constructor(config: FabricConfig) {
    if (!config.tenantId) {
      throw new Error("FabricConfig: tenantId is required");
    }
    if (!config.agentId) {
      throw new Error("FabricConfig: agentId is required");
    }
    this.identity = {
      tenantId: config.tenantId,
      agentId: config.agentId,
      profile: config.profile ?? "default",
      workflowId: config.workflowId,
      executionId: config.executionId,
    };
    const provider = config.tracerProvider ?? trace.getTracerProvider();
    this.tracer = provider.getTracer(TRACER_NAME);
  }

  /**
   * Open a decision for one agent turn. Primary (callback) form: the
   * decision span is started, made active for `fn`, then ended. Returns
   * whatever `fn` returns.
   *
   * ```ts
   * fabric.decision({ sessionId, requestId }, (d) => {
   *   d.llmCall({ system: "anthropic", model: "..." }, (call) => {
   *     call.setUsage({ inputTokens: 42, outputTokens: 210 });
   *   });
   * });
   * ```
   */
  decision<T>(ids: DecisionIds, fn: (d: Decision) => T): T {
    return runDecision(this.tracer, this.identity, ids, fn);
  }

  /**
   * Explicit form: start a decision span and return the {@link Decision}.
   * The caller MUST call `d.end()`. Prefer {@link decision} (the callback
   * form) so child spans parent under the decision automatically.
   */
  startDecision(ids: DecisionIds): Decision {
    return startDecision(this.tracer, this.identity, ids);
  }
}
