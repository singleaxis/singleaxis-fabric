// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * The {@link Fabric} client — the entry point for recording decisions.
 *
 * One `Fabric` is shared across an agent's lifetime (its identity fields
 * are fixed at construction). Per turn it produces a {@link Decision} via
 * the callback form `fabric.decision(ids, (d) => ...)`. For multi-step
 * scopes, `fabric.execution(ids, (e) => ...)` groups one outer unit of
 * work so its decisions inherit the same `executionId`/`workflowId`.
 */

import { type Tracer, type TracerProvider } from "@opentelemetry/api";

import {
  Decision,
  runDecision,
  startDecision,
  type DecisionClientIdentity,
  type DecisionIds,
} from "./decision.js";
import { Execution, runExecution, type ExecutionOptions } from "./execution.js";
import { checkAttributeKeys } from "./attributes.js";
import { CONTENT_ROLES } from "./content.js";
import {
  ContentWriter,
  validateContentCaptureConfig,
  type ContentCaptureConfig,
  type FlushResult,
} from "./content-writer.js";
import { checkIdentifier, warnIfPiiShaped } from "./id-validators.js";
import { TRACER_NAME, getTracer } from "./tracing.js";

// Re-exported so `import { TRACER_NAME } from "@singleaxis/fabric"` keeps
// resolving through this module for callers that imported it from here.
export { TRACER_NAME };

/** Default `profile` when the caller supplies none (mirrors Python). */
export const DEFAULT_PROFILE = "shadow";

/** Environment variable naming the tenant identifier. */
export const ENV_TENANT = "FABRIC_TENANT_ID";
/** Environment variable naming the agent identifier. */
export const ENV_AGENT = "FABRIC_AGENT_ID";
/** Environment variable naming the profile. */
export const ENV_PROFILE = "FABRIC_PROFILE";
/**
 * Environment variable that can only RESTRICT content capture: set to
 * `"metadata"` to force-disable a configured governed capture. It can
 * never enable governed mode by itself (spec 028).
 */
export const ENV_CONTENT_MODE = "FABRIC_CONTENT_MODE";

/** Configuration for one {@link Fabric} client. */
export interface FabricConfig {
  /** Owning tenant identifier — multi-tenant partition key. */
  tenantId: string;
  /** Stable identifier for this agent within the tenant. */
  agentId: string;
  /** Human-readable agent name; defaults to `agentId`. */
  agentName?: string;
  /** Optional semantic agent version. */
  agentVersion?: string;
  /** Optional semantic agent description. */
  agentDescription?: string;
  /** Runtime posture tag; defaults to `"shadow"`. */
  profile?: string;
  /** Optional owning workflow id. */
  workflowId?: string;
  /** Optional execution-correlation id. */
  executionId?: string;
  /** Per-attempt id for the logical task's retry chain. */
  executionAttemptId?: string;
  /** One-based attempt number for the current try. */
  executionAttempt?: number;
  /** Why this attempt is running (e.g. `"tool_timeout"`). */
  executionRetryReason?: string;
  /** The failed prior attempt id. */
  executionRetryPreviousAttemptId?: string;
  /**
   * Extra scalar attributes stamped on every decision and execution span.
   * Keys under the reserved `fabric.`/`gen_ai.` namespaces are rejected at
   * config build — they are SDK-owned. Per-span `attributes` sit on top
   * (explicit keys win on collision). Mirrors Python `FabricConfig.extra`.
   */
  extra?: Record<string, string>;
  /** Optional explicit tracer provider; otherwise the global provider. */
  tracerProvider?: TracerProvider;
  /**
   * Governed content capture (spec 028): explicit opt-in. Requires a
   * tenant-namespaced governed store, a role policy, and a durability
   * mode — anything missing fails closed at construction. `metadata`
   * remains the zero-configuration default: omit this field and no
   * content objects are written.
   */
  contentCapture?: ContentCaptureConfig;
}

/**
 * A Fabric recorder client. Identity is fixed at construction; share it
 * across the agent's lifetime.
 */
export class Fabric {
  private readonly tracer: Tracer;
  private readonly identity: DecisionClientIdentity;
  private readonly contentWriter?: ContentWriter;
  private readonly contentCapture?: ContentCaptureConfig;

  constructor(config: FabricConfig) {
    const tenantId = config.tenantId?.trim();
    const agentId = config.agentId?.trim();
    if (!tenantId) {
      throw new Error("tenantId is required");
    }
    if (!agentId) {
      throw new Error("agentId is required");
    }
    // Placeholder / copy-paste guards on the two partition-key fields.
    // These silently merge unrelated tenants if left bogus, so they fail
    // loud (sentinels) or warn (copy-paste markers), matching Python.
    checkIdentifier("tenant_id", tenantId);
    checkIdentifier("agent_id", agentId);
    const profile = config.profile === undefined ? DEFAULT_PROFILE : config.profile.trim();
    if (profile === "") {
      throw new Error("profile must be non-empty when provided");
    }
    // `extra` keys become default attributes on every decision / execution
    // span. Reserved `fabric.*`/`gen_ai.*` keys are rejected here — fail
    // fast at config build rather than letting a deployment-level extra
    // silently clobber SDK-owned identity.
    const extra = checkAttributeKeys({ ...(config.extra ?? {}) });
    this.identity = {
      tenantId,
      agentId,
      agentName: config.agentName?.trim() || agentId,
      agentVersion: config.agentVersion?.trim() || undefined,
      agentDescription: config.agentDescription?.trim() || undefined,
      profile,
      workflowId: config.workflowId,
      executionId: config.executionId,
      executionAttemptId: config.executionAttemptId,
      executionAttempt: config.executionAttempt,
      executionRetryReason: config.executionRetryReason,
      executionRetryPreviousAttemptId: config.executionRetryPreviousAttemptId,
      extra,
    };
    if (
      config.executionAttempt !== undefined &&
      (!Number.isInteger(config.executionAttempt) || config.executionAttempt < 1)
    ) {
      throw new Error("executionAttempt must be an integer >= 1");
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
    // PII shape warnings on the always-on identity fields + the
    // attempt-id fields that ride along with them.
    warnIfPiiShaped("tenant_id", tenantId);
    warnIfPiiShaped("agent_id", agentId);
    warnIfPiiShaped("execution_attempt_id", config.executionAttemptId);
    warnIfPiiShaped("execution_retry_previous_attempt_id", config.executionRetryPreviousAttemptId);
    this.tracer = getTracer(config.tracerProvider);
    // Governed content capture (spec 028): explicit opt-in. The only
    // environment influence is restrictive — `FABRIC_CONTENT_MODE`
    // set to `metadata` force-disables a configured capture; it can
    // never enable one.
    const env = typeof process !== "undefined" ? process.env : {};
    let contentCapture = config.contentCapture;
    if ((env[ENV_CONTENT_MODE] ?? "").toLowerCase() === "metadata") {
      contentCapture = undefined;
    }
    if (contentCapture !== undefined) {
      const roles = validateContentCaptureConfig(contentCapture, CONTENT_ROLES);
      if (contentCapture.store.tenantId !== tenantId) {
        throw new Error(
          `contentCapture.store.tenantId (${JSON.stringify(contentCapture.store.tenantId)}) ` +
            `must equal the Fabric client tenantId (${JSON.stringify(tenantId)}) — ` +
            "a mismatched namespace is a silent cross-tenant leak",
        );
      }
      this.contentCapture = contentCapture;
      this.contentWriter = new ContentWriter(contentCapture);
      this.identity.contentRoles = roles;
      this.identity.contentCapture = contentCapture;
      this.identity.contentWriter = this.contentWriter;
    }
  }

  /**
   * Build a Fabric client from environment variables.
   *
   * Reads `FABRIC_TENANT_ID`, `FABRIC_AGENT_ID` (required) and
   * `FABRIC_PROFILE` (optional; defaults to `"shadow"`). Missing required
   * values throw — fail loud at startup, not mid-request (mirrors
   * Python's `Fabric.from_env`). Values are whitespace-stripped and
   * placeholder-checked by the constructor exactly like the explicit
   * `new Fabric(...)` path.
   */
  static fromEnv(env: Record<string, string | undefined> = process.env): Fabric {
    const tenantId = env[ENV_TENANT];
    const agentId = env[ENV_AGENT];
    // Empty strings count as unset, matching Python's falsy check.
    if (!tenantId || !agentId) {
      const missing = [!tenantId ? ENV_TENANT : undefined, !agentId ? ENV_AGENT : undefined]
        .filter((name): name is string => name !== undefined)
        .join(" and ");
      throw new Error(`${missing} is not set`);
    }
    const profile = env[ENV_PROFILE];
    return new Fabric({ tenantId, agentId, profile });
  }

  /** Record one agent turn. See {@link Decision}. */
  decision<T>(ids: DecisionIds, fn: (decision: Decision) => T): T {
    return runDecision(this.tracer, this.identity, ids, fn);
  }

  /**
   * Record an agent turn without the callback form.
   *
   * Returns a live `Decision` whose span is open; call `decision.end()`
   * when the turn completes. Prefer the callback form: it guarantees the
   * span is ended exactly once (even on throw) and makes it the active
   * context so child spans parent correctly.
   */
  startDecision(ids: DecisionIds): Decision {
    return startDecision(this.tracer, this.identity, ids);
  }

  /** Record one outer unit of work — a task or workflow attempt. See {@link Execution}. */
  execution<T>(ids: ExecutionOptions, fn: (execution: Execution) => T): T {
    return runExecution(this.tracer, this.identity, ids, fn);
  }

  /** The configured governed-capture config, or `undefined` (metadata mode). */
  get contentCaptureConfig(): ContentCaptureConfig | undefined {
    return this.contentCapture;
  }

  /** The shared governed content writer, or `undefined` (metadata mode). */
  get writer(): ContentWriter | undefined {
    return this.contentWriter;
  }

  /**
   * Awaitable flush of buffered governed content — for tests and
   * graceful shutdown. Returns exact per-status counts; a `pending`
   * remainder is an honest gap. `undefined` in metadata mode.
   */
  async flushContent(timeoutS?: number): Promise<FlushResult | undefined> {
    return this.contentWriter?.flush(timeoutS);
  }

  /** Flush governed content and stop the writer. Idempotent. */
  async close(): Promise<void> {
    await this.contentWriter?.close();
  }
}
