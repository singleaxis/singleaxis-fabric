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
import { runExecution, type Execution, type ExecutionOptions } from "./execution.js";

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
  executionAttemptId?: string;
  executionAttempt?: number;
  executionRetryReason?: string;
  executionRetryPreviousAttemptId?: string;
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
    for (const [field, value] of [
      ["executionAttemptId", config.executionAttemptId],
      ["executionRetryReason", config.executionRetryReason],
      ["executionRetryPreviousAttemptId", config.executionRetryPreviousAttemptId],
    ] as const) {
      if (value !== undefined && value.trim() === "") {
        throw new Error(`FabricConfig: ${field} must be non-empty when set`);
      }
    }
    if (config.executionAttempt !== undefined) {
      if (!Number.isInteger(config.executionAttempt)) {
        throw new TypeError("FabricConfig: executionAttempt must be an integer");
      }
      if (config.executionAttempt < 1) {
        throw new RangeError("FabricConfig: executionAttempt must be >= 1");
      }
    }
    this.identity = {
      tenantId: config.tenantId,
      agentId: config.agentId,
      profile: config.profile ?? "default",
      workflowId: config.workflowId,
      executionId: config.executionId,
      executionAttemptId: config.executionAttemptId,
      executionAttempt: config.executionAttempt,
      executionRetryReason: config.executionRetryReason,
      executionRetryPreviousAttemptId: config.executionRetryPreviousAttemptId,
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

  /**
   * Open an optional outer correlation + lifecycle `fabric.execution` span
   * for the duration of `fn`. Callback form (mirrors {@link decision}): the
   * span is started, made active, its correlation metadata is published for
   * inheritance, then it is ended with `fabric.execution.status` stamped
   * `completed` (or `failed` + error on throw). Each attempt/retry param
   * defaults to the corresponding {@link FabricConfig} value.
   *
   * A {@link Decision} opened inside `fn` inherits the execution's
   * `execution_id` / `workflow_id` + attempt metadata (precedence: explicit
   * DecisionIds value > active execution > FabricConfig).
   *
   * ```ts
   * fabric.execution({ executionId, workflowId }, (e) => {
   *   fabric.decision({ sessionId, requestId }, (d) => { ... });
   * });
   * ```
   */
  execution<T>(options: ExecutionOptions, fn: (e: Execution) => T): T {
    return runExecution(this.tracer, this.identity, options, fn);
  }
}
