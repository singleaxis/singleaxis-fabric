// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The run API (spec 055 §4.2, §4.3): `run`, `resumeToken`, `resumeTokens`, `endRun` and
 * the internal run-outcome hook `setRunOutcome` (D30; unexported until TS-2).
 *
 * Fail open (R9): every function catches every Fabric failure. `run()` always runs the
 * callback exactly once and returns what it returns: a synchronous value as is, a thrown
 * object as the same object; for a native Promise the promise `run()` returns settles
 * with the same value or the same rejection object (the scope ends when it settles). A
 * rejection the application never handles stays unhandled. A misused argument is
 * dropped and counted (`api_misuse`); `FABRIC_RECORDS_STRICT=1` throws a fixed-text
 * `Error` instead, before the callback runs. Nothing reads or prints an application
 * object: an error's class is read from an allowlist (`undici.ts` `errorType`).
 *
 * Fabric never injects baggage, never changes a child process's argv or environment and
 * never joins a parent and child run by itself (R1, §6.4): within a host the application
 * passes the clear run id (`FABRIC_RUN_ID`) or a token, across hosts only a token.
 */
import { types } from "node:util";

import { splitTokens } from "./p1.js";
import {
  MAX_BRANCHES,
  OPAQUE_ID_RE,
  type EndRunStatus,
  type RunOutcome,
  type ScopeStatus,
  type StopReason,
} from "./p1-types.js";
import type { WireRuntime } from "./runtime.js";
import { currentRunScope, withScope, type RunScope } from "./scope.js";
import {
  RUN_COUNTERS,
  RunApiMisuse,
  type RunOptions,
  SegmentTable,
  checkOutcome,
  misuse,
  strictMode,
} from "./segments.js";
import type { WireSettings } from "./types.js";
import { ERROR_TYPES, errorType, type CaptureScope } from "./undici.js";

export type { RunOptions } from "./segments.js";

let TABLE: SegmentTable | undefined;

/** Binds the installed run table (install, `055-t14`); `undefined` unbinds it. */
export function bindRunTable(table: SegmentTable | undefined): void {
  TABLE = table;
}

/** The run table while it captures. */
export function activeRunTable(): SegmentTable | undefined {
  const table = TABLE;
  return table !== undefined && table.active ? table : undefined;
}

/**
 * A Fabric failure inside a run-API function: misuse counts `api_misuse`, anything else
 * `internal_errors`; strict mode throws a fixed-text `Error` (never the original object,
 * which may carry application data).
 */
function failed(error: unknown): void {
  const isMisuse = error instanceof RunApiMisuse;
  if (isMisuse) RUN_COUNTERS.apiMisuse++;
  else RUN_COUNTERS.internalErrors++;
  if (!strictMode()) return;
  if (isMisuse) throw error;
  throw new Error("fabric run API internal error (FABRIC_RECORDS_STRICT=1)");
}

/** S34 of a block that threw: `cancelled` for an abort, else `error`. */
function statusOf(error: unknown): ScopeStatus {
  const name = ERROR_TYPES[errorType(error)];
  return name === "AbortError" ? "cancelled" : "error";
}

function exitQuietly(table: SegmentTable, scope: RunScope, status: ScopeStatus): void {
  try {
    table.exit(scope, status);
  } catch {
    RUN_COUNTERS.internalErrors++; // the block's outcome is never changed by Fabric
  }
}

/**
 * Runs `fn` in a run scope (spec 050 §3.6): its model calls, and the calls of promises,
 * timers and microtasks it starts, belong to one segment of the run. Every option is
 * optional (R1); see `RunOptions`. Returns what `fn` returns.
 */
export function run<T>(options: RunOptions, fn: () => T): T {
  let table: SegmentTable | undefined;
  let scope: RunScope | undefined;
  try {
    let opts: RunOptions = {};
    if (options !== undefined && options !== null) {
      if (typeof options === "object") opts = options;
      else misuse("run options must be an object");
    }
    const runId: unknown = opts.runId;
    if (runId !== undefined && typeof runId !== "string") {
      misuse("runId must be a string"); // R9: the callback then runs uncaptured
    } else {
      if (typeof runId === "string" && !OPAQUE_ID_RE.test(runId) && strictMode()) {
        throw new RunApiMisuse("runId must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$");
      }
      table = activeRunTable();
      if (table !== undefined) {
        const plan = table.prepare(opts, currentRunScope() === undefined);
        scope = table.enter(plan);
      }
    }
  } catch (error) {
    failed(error);
    scope = undefined;
  }
  if (table === undefined || scope === undefined) return fn();
  let result: T;
  try {
    result = withScope(scope, fn);
  } catch (error) {
    exitQuietly(table, scope, statusOf(error));
    throw error;
  }
  if (types.isPromise(result)) {
    const bound = table;
    const open = scope;
    return Promise.prototype.then.call(
      result,
      (value: unknown) => {
        exitQuietly(bound, open, "ok");
        return value;
      },
      (error: unknown) => {
        exitQuietly(bound, open, statusOf(error));
        throw error;
      },
    ) as T;
  }
  exitQuietly(table, scope, "ok");
  return result;
}

/**
 * Seals the current run's open segment (non-terminal, `resumable=true`) and returns its
 * `fr3/` token, at once (it does not wait for the seal to be durable; `flush()` does).
 * `undefined` outside a run or when not capturing. Pass the token to `run({resume})`
 * here, to a child through `FABRIC_RUN_RESUME_TOKEN`, or across services as the
 * `fabric.resume` baggage entry or a message attribute, which the application sets.
 */
export function resumeToken(): string | undefined {
  try {
    const table = activeRunTable();
    const scope = currentRunScope();
    if (table === undefined || scope === undefined) return undefined;
    const tokens = table.issue(scope, 0);
    return tokens.length === 1 && tokens[0] !== "" ? tokens[0] : undefined;
  } catch (error) {
    failed(error);
    return undefined;
  }
}

/**
 * `branches` (1..64) branch tokens of one seal, each naming its own `br-` id (each
 * belongs to exactly one consumer); `[]` outside a run or when not capturing.
 */
export function resumeTokens(branches: number): readonly string[] {
  try {
    if (!Number.isInteger(branches) || branches < 1 || branches > MAX_BRANCHES) {
      throw new RunApiMisuse("branches must be an integer from 1 to 64");
    }
    const table = activeRunTable();
    const scope = currentRunScope();
    if (table === undefined || scope === undefined) return Object.freeze([]);
    const tokens = table.issue(scope, branches);
    return Object.freeze(tokens.every((t) => t !== "") ? tokens : []);
  } catch (error) {
    failed(error);
    return Object.freeze([]);
  }
}

export interface EndRunOptions {
  /** The clear run id; absent: the tokens' correlation id. */
  readonly runId?: string;
  readonly outcome: RunOutcome;
  readonly resume: string | readonly string[];
  readonly stopReason?: StopReason;
}

/**
 * Ends a run from its tokens with a zero-width terminal segment whose `run_end` carries
 * `outcome` (spec 050 §3.6). `ended` means queued, not durable. `refused_no_token`
 * without a valid token (nothing is emitted); `refused_conflicting_tokens` for tokens of
 * different runs and no `runId`; `refused_bad_token` when `resume` is not tokens;
 * `not_capturing` when capture is off; `failed` on a Fabric failure.
 */
export function endRun(options: EndRunOptions): EndRunStatus {
  try {
    if (options === null || typeof options !== "object") {
      throw new RunApiMisuse("endRun takes { outcome, resume, runId?, stopReason? }");
    }
    checkOutcome(options.outcome, options.stopReason);
    const runId: unknown = options.runId;
    if (runId !== undefined && typeof runId !== "string") {
      throw new RunApiMisuse("runId must be a string");
    }
    const table = activeRunTable();
    if (table === undefined) return "not_capturing";
    const resume: unknown = options.resume;
    let tokens: string[];
    if (typeof resume === "string") tokens = splitTokens(resume);
    else if (Array.isArray(resume) && resume.every((t) => typeof t === "string")) {
      tokens = (resume as string[]).flatMap((item) => splitTokens(item));
    } else {
      misuse("resume must be a token or an array of tokens");
      return "refused_bad_token";
    }
    return table.end(runId, options.outcome, tokens, options.stopReason);
  } catch (error) {
    failed(error);
    return "failed";
  }
}

/**
 * The D30 run-level hook (R4): kept on the run entry (of `runId`, mapped by the identity
 * rule, else of the innermost open scope's run) and carried by that run's outermost
 * `run_end` here; the last call before that block closes wins. `false` when there is no
 * open run or capture is off. Internal until TS-2.
 */
export function setRunOutcome(
  outcome: RunOutcome,
  stopReason?: StopReason,
  options: { readonly runId?: string } = {},
): boolean {
  try {
    checkOutcome(outcome, stopReason);
    const runId: unknown = options?.runId;
    if (runId !== undefined && (typeof runId !== "string" || runId === "")) {
      throw new RunApiMisuse("runId must be a non-empty string");
    }
    const table = activeRunTable();
    if (table === undefined) return false;
    return table.setOutcome(outcome, stopReason, runId, currentRunScope());
  } catch (error) {
    failed(error);
    return false;
  }
}

/**
 * The transport hooks' view of the calling context (`undici.ts` `scope` option): the
 * innermost open run's slot and scope id. One `AsyncLocalStorage` read; never throws.
 */
export function captureScope(): CaptureScope | undefined {
  const scope = currentRunScope();
  if (scope === undefined || scope.run.slot < 0) return undefined;
  return { runSlot: scope.run.slot, scopeId: scope.scopeBytes };
}

/**
 * The run table of an install from its configuration (`resolveConfig`): the id key and
 * identity mode, the label mode, and the same-host `FABRIC_RUN_ID` and
 * `FABRIC_RUN_RESUME_TOKEN` the configuration read once (§4.2). `production` is the
 * deployment policy's profile (049 §2.9 rule 5).
 */
export function createRunTable(
  runtime: WireRuntime,
  settings: Pick<WireSettings, "runId" | "resumeTokens" | "identityMode" | "labels" | "secrets">,
  options: { readonly sourceId: string; readonly production?: boolean },
): SegmentTable {
  return new SegmentTable({
    runtime,
    sourceId: options.sourceId,
    key: settings.secrets.idKey,
    identityMode: settings.identityMode,
    labels: settings.labels,
    production: options.production,
    envRunId: settings.runId,
    envTokens: settings.resumeTokens,
  });
}
