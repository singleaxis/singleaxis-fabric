// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Segments and run structure (spec 055 §4.3, §6.4; spec 050 §3.6): the run table, the
 * seal triggers, resume tokens, `endRun` and the run-outcome hook. A port of Python's
 * `fabric._segments`.
 *
 * A segment is one contiguous piece of a run recorded by one `(source, epoch)`. The run
 * table lives on the installing thread; the canonical open segment of each live run, and
 * the count of positions allocated in it, live in the control block's run table
 * (`runtime.ts`), where the allocator reads and counts them under the try-lock, so
 * segment membership is decided with the allocation. Scopes (`scope.ts`) carry only a
 * reference to the run's slot.
 *
 * Run identity (R1) is decided once per segment open by the first rule that applies
 * ({@link resolveIdentity}, pinned by `resume-token-v2.json`): one correlation id among
 * the valid tokens (`token`); differing ids and a clear run id (`caller_join`); differing
 * ids, none (`token_conflict`); a clear run id (`caller`); else a minted `r-` id
 * (`minted`). Rules 4 and 5 report `legacy` when only `fr2/` tokens were valid.
 *
 * Run markers and seal requests are built here and handed to the Fabric worker through
 * the runtime's run ring ({@link encodeRunMessage}); the worker spools the markers and
 * gives the requests to its seal accumulator (`seal.ts`). A token never waits for its
 * seal to be durable: `flush()` is the durability call.
 *
 * What differs from Python, and why:
 * - A segment is opened eagerly: after `resumeToken()` seals the open segment, the run's
 *   continuation segment is opened at once (Python opens it at the run's next
 *   allocation), because the allocation hook must not build markers. A run that makes no
 *   call after its last token therefore seals one more, empty, segment at exit.
 * - The Fabric worker rolls a segment that reached the forced bound itself, under the
 *   same lock (`worker.ts`), and writes the continuation `run_start`: the open segment of
 *   a run is always read from its slot, never cached here.
 * - At most 256 runs are live at once (the run table's slots). A block of a 257th run
 *   runs uncaptured and is counted (`run_slots_exhausted`): its calls are recorded outside
 *   any run rather than in a run whose seal would miss them.
 * - Node has no fork of a live process: `child_process` and `cluster` start fresh
 *   processes with their own epoch (§6.4), so the fork trigger has no hook here. A child
 *   continues a run only from a token or `FABRIC_RUN_ID` the application passes.
 *
 * Passivity (R9): nothing here does I/O or waits; the run-table lock is the bounded
 * try-lock; when it cannot be taken the transition still happens and its seal is not
 * requested, so the segment is reported unsealed, never complete. Every public function
 * fails open and throws only under `FABRIC_RECORDS_STRICT=1`.
 */
import { randomBytes, randomUUID } from "node:crypto";

import { pseudonymV2 } from "../identity.js";
import {
  checkValue,
  encodeOpaqueId,
  formatEntry,
  formatToken,
  parseToken,
  recordChecks,
  runPseudonym,
  splitTokens,
  type ResumeToken,
} from "./p1.js";
import {
  BRANCH_ID_RE,
  MAX_BRANCHES,
  MAX_RUN_LINKS,
  OPAQUE_ID_RE,
  RUN_OUTCOMES,
  STOP_REASONS,
  type EndRunStatus,
  type IdBasis,
  type RunOutcome,
  type ScopeStatus,
  type StopReason,
} from "./p1-types.js";
import { MAX_RUNS, RUN_FLAG_RESUMABLE, RUN_RECORD_BYTES, type WireRuntime } from "./runtime.js";
import { segmentIdOf } from "./seal.js";
import { newScope, type RunRef, type RunScope } from "./scope.js";

export const SEGMENT_PREFIX = "seg-";
export const BRANCH_PREFIX = "br-";
export const RUN_ID_ENV = "FABRIC_RUN_ID";
export const RESUME_TOKEN_ENV = "FABRIC_RUN_RESUME_TOKEN";
export const STRICT_ENV = "FABRIC_RECORDS_STRICT";
/** A run_start names at most 64 predecessors (capture/v1). */
export const MAX_PREDECESSORS = MAX_BRANCHES;
/** Runs whose outermost block exited here, remembered (LRU) for local continuation (K2). */
export const MAX_RETIRED_RUNS = 1024;
/** "No manifest in force": the token grammar needs one; the verifier reports the epoch. */
export const NO_MANIFEST_DIGEST = "sha256:" + "0".repeat(64);
export const OPEN_DEADLINE_RANGE = [60, 31_536_000] as const;
const ROOT: readonly string[] = Object.freeze(["none"]);

// ------------------------------------------------------------------------- misuse

/** A misused argument (050 §3.4, OD-11): counted and dropped; thrown only in strict mode. */
export class RunApiMisuse extends Error {
  constructor(what: string) {
    super(`fabric run API misuse: ${what}`);
    this.name = "RunApiMisuse";
  }
}

/** Process counters of the run API (status reads them). */
export const RUN_COUNTERS = { apiMisuse: 0, internalErrors: 0 };

let strictOverride: boolean | undefined;

/** `FABRIC_RECORDS_STRICT=1`, read only on a failure path (as Python's `strict()`). */
export function strictMode(): boolean {
  if (strictOverride !== undefined) return strictOverride;
  return typeof process !== "undefined" && process.env[STRICT_ENV] === "1";
}

/** Tests: pin the strict flag (`undefined` reads the environment again). */
export function setStrictModeForTesting(value: boolean | undefined): void {
  strictOverride = value;
}

/**
 * One misused input that is dropped while the call proceeds; throws only when strict
 * (the run API's failure path then counts it, once).
 */
export function misuse(what: string): void {
  if (strictMode()) throw new RunApiMisuse(what);
  RUN_COUNTERS.apiMisuse++;
}

/** The one class-only warning of a dropped resume token (050 §3.6); never the token. */
export const TOKEN_DROPPED_WARNING =
  "fabric.wire: a resume token was dropped (MalformedResumeToken): pass each token exactly " +
  "as resumeToken() or resumeTokens() returned it (percent-decode a fabric.resume baggage " +
  "value first); a pseudonymous consumer also drops a token issued in the clear identity mode";

function emitWarning(text: string): void {
  try {
    process.emitWarning(text, { type: "FabricWarning", code: "FABRIC_RESUME_TOKEN_DROPPED" });
  } catch {
    // a warning never reaches the agent as an error
  }
}

// ------------------------------------------------------------------- run identity

/** What {@link resolveIdentity} decided for one segment open. */
export interface Identity {
  readonly runId: string;
  readonly idBasis: IdBasis;
  /** `["none"]` for a root. */
  readonly predecessors: readonly string[];
  readonly branchIds: readonly string[];
  readonly tokensRejected: number;
  /** Of the valid `fr3/` tokens, in byte order. */
  readonly correlationIds: readonly string[];
  readonly validTokens: number;
}

const byUtf8 = (a: string, b: string): number => Buffer.compare(Buffer.from(a), Buffer.from(b));

/** The tokens a consumer accepts: well formed, with a correlation id it may emit (R8). */
export function acceptedTokens(
  tokens: readonly string[],
  correlationOk?: (id: string) => boolean,
): ResumeToken[] {
  const out: ResumeToken[] = [];
  for (const token of tokens) {
    const parsed = parseToken(token);
    if (parsed === undefined) continue;
    const id = parsed.correlation_id;
    if (id !== null && correlationOk !== undefined && !correlationOk(id)) continue;
    out.push(parsed);
  }
  return out;
}

/**
 * Run identity at segment open (050 §3.6, the five rules). `mapRun` is the identity rule
 * for a clear run id; `mint` draws a fresh `r-` id and is called only by rule 5.
 * `correlationOk` drops a token whose correlation id this consumer may not emit.
 */
export function resolveIdentity(
  tokens: readonly string[],
  runId: string | undefined,
  mapRun: (value: string) => string,
  mint: () => string,
  correlationOk?: (id: string) => boolean,
): Identity {
  const parsed = acceptedTokens(tokens, correlationOk);
  const correlations = [
    ...new Set(parsed.flatMap((p) => (p.correlation_id === null ? [] : [p.correlation_id]))),
  ].sort(byUtf8);
  let out: string;
  let basis: IdBasis;
  if (correlations.length === 1) [out, basis] = [correlations[0]!, "token"];
  else if (correlations.length > 0 && runId !== undefined)
    [out, basis] = [mapRun(runId), "caller_join"];
  else if (correlations.length > 0) [out, basis] = [correlations[0]!, "token_conflict"];
  else if (runId !== undefined)
    [out, basis] = [mapRun(runId), parsed.length > 0 ? "legacy" : "caller"];
  else [out, basis] = [mint(), parsed.length > 0 ? "legacy" : "minted"];
  const predecessors: string[] = [];
  const branches: string[] = [];
  for (const p of parsed) {
    const entry = formatEntry(
      p.segment_id,
      p.source_id,
      p.epoch,
      p.last_sequence,
      p.manifest_digest,
    );
    if (!predecessors.includes(entry)) predecessors.push(entry);
    if (p.branch_id !== null && !branches.includes(p.branch_id)) branches.push(p.branch_id);
  }
  return {
    runId: out,
    idBasis: basis,
    predecessors: predecessors.length > 0 ? predecessors : ROOT,
    branchIds: branches,
    tokensRejected: tokens.length - parsed.length,
    correlationIds: correlations,
    validTokens: parsed.length,
  };
}

export interface IdentityRuleOptions {
  readonly key?: Uint8Array | undefined;
  readonly mode?: "pseudonymous" | "clear";
  /** The production profile: without a key nothing derived from a caller id leaves. */
  readonly production?: boolean;
  /** The generated source fallback (`source:<id>:<epoch>`, opaque-encoded). */
  readonly fallback?: () => string;
}

/**
 * The identity rule (R8) for the ids `run()` and `endRun` take: pseudonymous by default
 * (every caller value mapped, whatever its shape), `clear` only as an explicit opt-in.
 * Run ids use the v1 function (`r-`), session and user ids v2 (`sess-`, `usr-`, omitted
 * without a key). In the production profile without a key a run id is the generated
 * source fallback and links and v2 ids are omitted (049 §2.9 rule 5).
 */
export class IdentityRule {
  readonly key: Uint8Array | undefined;
  readonly mode: "pseudonymous" | "clear";
  readonly productionWithoutKey: boolean;
  readonly #fallback: (() => string) | undefined;

  constructor(options: IdentityRuleOptions = {}) {
    this.key = options.key;
    this.mode = options.mode ?? "pseudonymous";
    this.productionWithoutKey = options.production === true && options.key === undefined;
    this.#fallback = options.fallback;
  }

  /** `clear` only as the explicit opt-in and never in production without a key. */
  get effectiveMode(): "pseudonymous" | "clear" {
    return this.mode === "clear" && !this.productionWithoutKey ? "clear" : "pseudonymous";
  }

  /** Rule 5: `r-` + 32 CSPRNG hex, never derived from caller input. */
  mintRun(): string {
    return "r-" + randomBytes(16).toString("hex");
  }

  /** A clear run id as emitted (rules 2 and 4). */
  run(value: string): string {
    if (this.productionWithoutKey && this.#fallback !== undefined) return this.#fallback();
    if (this.mode === "clear") return encodeOpaqueId(value);
    return runPseudonym(value, this.key);
  }

  /** `parentRunId`, `resumedFrom`, `links`: the run-id rule, omitted in production w/o key. */
  link(value: string): string | undefined {
    if (this.productionWithoutKey) return undefined;
    if (this.mode === "clear") return encodeOpaqueId(value);
    return runPseudonym(value, this.key);
  }

  /** `sess-`/`usr-` v2 pseudonyms (omitted without a key); clear: as given. */
  v2(prefix: string, value: string): string | undefined {
    if (this.productionWithoutKey) return undefined;
    if (this.mode === "clear") return encodeOpaqueId(value);
    return pseudonymV2(prefix, value, this.key);
  }
}

// ------------------------------------------------------- run messages (to the worker)

/** A run marker for the worker to spool (Python `marker_fields`; `last_sequence` as text). */
export interface MarkerMessage {
  readonly t: "marker";
  readonly source: string;
  readonly epoch: string;
  readonly fields: Record<string, unknown>;
}

/** A seal request for the worker's accumulator (bigints as decimal text). */
export interface SealMessage {
  readonly t: "seal";
  readonly segment: string;
  readonly runId: string;
  readonly source: string;
  readonly epoch: string;
  readonly lastSequence: string;
  readonly positions: string;
  readonly manifestDigest: string;
  readonly terminal: boolean;
  readonly resumable: boolean;
  readonly branchIds: readonly string[];
}

export type RunMessage = MarkerMessage | SealMessage;

/** Ring record kind of one part of a run message. */
export const RUN_MESSAGE_PART = 1;
const PART_HEADER = 12; // part length (u32), message id (u32), part index (u16), parts (u16)
const PART_PAYLOAD = RUN_RECORD_BYTES - 8 - PART_HEADER;
const MAX_PARTS = 16;

/**
 * Hands `message` to the Fabric worker through the run ring, split into parts when it
 * is longer than one record. `false` when it did not fit (the ring is full): a part
 * already pushed is discarded by the reader, never delivered alone.
 */
export function encodeRunMessage(runtime: WireRuntime, message: RunMessage): boolean {
  const payload = Buffer.from(JSON.stringify(message), "utf8");
  const parts = Math.max(1, Math.ceil(payload.length / PART_PAYLOAD));
  if (parts > MAX_PARTS) return false;
  const id = randomBytes(4).readUInt32LE(0);
  for (let part = 0; part < parts; part++) {
    const chunk = payload.subarray(part * PART_PAYLOAD, (part + 1) * PART_PAYLOAD);
    const record = Buffer.allocUnsafe(PART_HEADER + chunk.length);
    record.writeUInt32LE(chunk.length, 0);
    record.writeUInt32LE(id, 4);
    record.writeUInt16LE(part, 8);
    record.writeUInt16LE(parts, 10);
    chunk.copy(record, PART_HEADER);
    if (!runtime.pushRun(RUN_MESSAGE_PART, record)) return false;
  }
  return true;
}

/** The Fabric worker's side: reassembles parts (bounded) into messages. */
export class RunMessages {
  readonly #partial = new Map<number, (Buffer | undefined)[]>();
  dropped = 0;

  /** One ring record; the message it completes, if any. Never throws. */
  take(body: Uint8Array): RunMessage | undefined {
    try {
      const view = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
      const length = view.readUInt32LE(0);
      const id = view.readUInt32LE(4);
      const part = view.readUInt16LE(8);
      const parts = view.readUInt16LE(10);
      if (length > PART_PAYLOAD || parts === 0 || parts > MAX_PARTS || part >= parts) {
        this.dropped++;
        return undefined;
      }
      const chunk = Buffer.from(view.subarray(PART_HEADER, PART_HEADER + length));
      let payload: Buffer;
      if (parts === 1) {
        payload = chunk;
      } else {
        let held = this.#partial.get(id);
        if (held === undefined || held.length !== parts) {
          held = new Array<Buffer | undefined>(parts).fill(undefined);
          this.#partial.set(id, held);
          while (this.#partial.size > 64) {
            this.#partial.delete(this.#partial.keys().next().value as number);
            this.dropped++;
          }
        }
        held[part] = chunk;
        if (held.some((p) => p === undefined)) return undefined;
        this.#partial.delete(id);
        payload = Buffer.concat(held as Buffer[]);
      }
      const message = JSON.parse(payload.toString("utf8")) as RunMessage;
      if (message.t !== "marker" && message.t !== "seal") throw new Error("unknown message");
      return message;
    } catch {
      this.dropped++;
      return undefined;
    }
  }
}

// --------------------------------------------------------------------- the run table

interface Run {
  readonly runId: string;
  readonly correlationId: string;
  readonly idBasis: IdBasis;
  readonly ref: RunRef;
  /** The open segment of a run with no slot (`endRun`'s zero-width segment). */
  slotless: string | undefined;
  depth: number;
  resumable: boolean;
  terminalSealed: boolean;
  finalBlock: boolean;
  openDeadlineS: number | undefined;
  outcome: RunOutcome | undefined;
  stopReason: StopReason | undefined;
  openBasis: IdBasis | undefined;
  pendingPredecessors: readonly string[];
  pendingBranchIds: readonly string[];
  /** The predecessor entry of the last segment sealed here. */
  lastEntry: string | undefined;
}

interface SealOrder {
  readonly segmentId: string;
  readonly runId: string;
  readonly lastSequence: bigint;
  readonly manifestDigest: string;
  readonly positions: bigint;
  readonly terminal: boolean;
  readonly resumable: boolean;
  readonly branchIds: readonly string[];
  /** Decided under the run-table lock: only then is its position count exact. */
  readonly exact: boolean;
}

/** Block entry, prepared outside the lock: the identity and the root fields. */
export interface RunPlan {
  readonly identity: Identity;
  readonly resumable: boolean;
  readonly final: boolean;
  readonly openDeadlineS: number | undefined;
  readonly sessionId: string | undefined;
  readonly userId: string | undefined;
  readonly parentRunId: string | undefined;
  readonly resumedFrom: string | undefined;
  readonly links: readonly string[];
}

/** `run()`'s options (spec 055 §4.3); every one optional (R1). */
export interface RunOptions {
  readonly runId?: string;
  readonly sessionId?: string;
  readonly userId?: string;
  readonly parentRunId?: string;
  readonly resumedFrom?: string;
  readonly links?: readonly string[];
  /** Tokens: one string (comma-separated for a join) or a list. */
  readonly resume?: string | readonly string[];
  readonly resumable?: boolean;
  readonly final?: boolean;
  /** 60..31536000 seconds. */
  readonly openDeadlineS?: number;
}

export interface BindOptions {
  readonly runtime: WireRuntime;
  readonly sourceId: string;
  readonly key?: Uint8Array | undefined;
  readonly identityMode?: "pseudonymous" | "clear";
  readonly production?: boolean;
  readonly labels?: "pseudonymous" | "clear";
  /** Same-host `FABRIC_RUN_ID` and `FABRIC_RUN_RESUME_TOKEN`, read once at install. */
  readonly envRunId?: string | undefined;
  readonly envTokens?: readonly string[];
  /** The manifest in force (default: the one the Fabric worker published). */
  readonly manifest?: () => { readonly manifestId: string; readonly digest: string } | undefined;
  /** Hands a message to the worker (default: the run ring). Tests observe it. */
  readonly send?: (message: RunMessage) => boolean;
  /** The once-per-table warning of a dropped token (default: `process.emitWarning`). */
  readonly warn?: (text: string) => void;
}

const STAT_NAMES = [
  "segments_opened",
  "segments_sealed",
  "tokens_issued",
  "tokens_rejected",
  "end_runs",
  "post_terminal_allocations",
  "predecessors_dropped",
  "run_slots_exhausted",
  "messages_dropped",
  "lock_timeouts",
  "seals_unrequested",
  "internal_errors",
] as const;
export type RunStatName = (typeof STAT_NAMES)[number];

/**
 * The process run table, bound at install to the shared runtime. Every method is
 * fail-open; only misuse throws, and only under strict mode (run-api.ts catches the rest).
 */
export class SegmentTable {
  readonly rule: IdentityRule;
  readonly sourceId: string;
  readonly #runtime: WireRuntime;
  readonly #runs = new Map<string, Run>();
  readonly #retired = new Map<string, Run>();
  readonly #freeSlots: number[] = [];
  readonly #correlationOk: (id: string) => boolean;
  readonly #manifest: () => { readonly manifestId: string; readonly digest: string } | undefined;
  readonly #send: (message: RunMessage) => boolean;
  readonly #warn: (text: string) => void;
  #warned = false;
  #envRunId: string | undefined;
  #envTokens: string[] | undefined;
  #closed = false;
  readonly #stats = Object.fromEntries(STAT_NAMES.map((n) => [n, 0])) as Record<
    RunStatName,
    number
  >;

  constructor(options: BindOptions) {
    const runtime = options.runtime;
    this.#runtime = runtime;
    this.sourceId = options.sourceId;
    this.rule = new IdentityRule({
      key: options.key,
      mode: options.identityMode,
      production: options.production,
      fallback: () => encodeOpaqueId(`source:${this.sourceId}:${runtime.epoch}`),
    });
    for (let slot = MAX_RUNS - 1; slot >= 0; slot--) this.#freeSlots.push(slot);
    // R8: a token's correlation id becomes this process's run id, so it must be one this
    // process may emit as fabric.run.id in its effective identity mode.
    const check = recordChecks().get("fabric.run.id");
    const modes = { labels: options.labels ?? "pseudonymous", identity: this.rule.effectiveMode };
    this.#correlationOk = (id) => check !== undefined && checkValue(check, id, modes);
    this.#manifest =
      options.manifest ??
      (() => {
        const published = runtime.publishedManifest();
        return published !== undefined && published.epoch === runtime.epoch ? published : undefined;
      });
    this.#send = options.send ?? ((message) => encodeRunMessage(runtime, message));
    this.#warn = options.warn ?? emitWarning;
    this.#envRunId = options.envRunId?.trim() || undefined;
    this.#envTokens =
      options.envTokens !== undefined && options.envTokens.length > 0
        ? [...options.envTokens]
        : undefined;
  }

  get active(): boolean {
    return !this.#closed && this.#runtime.running;
  }

  /** Counters only (`status().runs`). */
  stats(): Readonly<Record<RunStatName | "open_runs", number>> {
    let open = 0;
    for (const run of this.#runs.values()) if (run.depth > 0) open++;
    return { ...this.#stats, open_runs: open };
  }

  /** Whether `id` passes this consumer's identity rule for a token correlation id. */
  correlationOk(id: string): boolean {
    return this.#correlationOk(id);
  }

  // ------------------------------------------------------------------ locking

  /**
   * Runs `fn` under the run-table lock (the bounded try-lock). When it cannot be taken
   * `fn` still runs, told so: its seals are then not requested (counted), because their
   * position counts may be off; the segments stay unsealed, never complete.
   */
  #locked<T>(fn: (exact: boolean) => T): T {
    const runtime = this.#runtime;
    const exact = runtime.tryLock();
    if (!exact) this.#stats.lock_timeouts++;
    try {
      return fn(exact);
    } finally {
      if (exact) runtime.unlock();
    }
  }

  #last(): bigint {
    return this.#runtime.nextSequence - 1n;
  }

  #segmentOf(run: Run): string | undefined {
    if (run.ref.slot < 0) return run.slotless;
    const [hi, lo] = this.#runtime.runSegment(run.ref.slot);
    return segmentIdOf(hi, lo);
  }

  #setSegment(run: Run, segmentId: string | undefined): void {
    if (run.ref.slot < 0) {
      run.slotless = segmentId;
      return;
    }
    if (segmentId === undefined) {
      this.#runtime.setRunSegment(run.ref.slot, 0n, 0n);
      return;
    }
    const hex = segmentId.slice(SEGMENT_PREFIX.length);
    this.#runtime.setRunSegment(
      run.ref.slot,
      BigInt.asIntN(64, BigInt("0x" + hex.slice(0, 16))),
      BigInt.asIntN(64, BigInt("0x" + hex.slice(16))),
    );
    this.#runtime.setRunFlags(run.ref.slot, run.resumable ? RUN_FLAG_RESUMABLE : 0n);
  }

  #retire(run: Run): void {
    if (run.depth > 0 || this.#segmentOf(run) !== undefined) return;
    if (this.#runs.get(run.runId) !== run) return;
    this.#runs.delete(run.runId);
    if (run.ref.slot >= 0) {
      this.#runtime.setRunFlags(run.ref.slot, 0n);
      this.#freeSlots.push(run.ref.slot);
      run.ref.slot = -1;
    }
    this.#retired.delete(run.runId);
    this.#retired.set(run.runId, run);
    while (this.#retired.size > MAX_RETIRED_RUNS) {
      this.#retired.delete(this.#retired.keys().next().value as string);
    }
  }

  /** The live run of `runId`, taking a remembered ended run back (a new slot). */
  #revive(runId: string): Run | undefined | null {
    const live = this.#runs.get(runId);
    if (live !== undefined) return live;
    const run = this.#retired.get(runId);
    if (run === undefined) return undefined;
    const slot = this.#freeSlots.pop();
    if (slot === undefined) return null;
    this.#retired.delete(runId);
    run.ref.slot = slot;
    this.#runs.set(runId, run);
    return run;
  }

  // ------------------------------------------------------------ markers and seals

  #queue(fields: Record<string, unknown>): void {
    const message: MarkerMessage = {
      t: "marker",
      source: this.sourceId,
      epoch: this.#runtime.epoch.toString(),
      fields: { ...fields, event_id: randomUUID() },
    };
    let sent: boolean;
    try {
      sent = this.#send(message);
    } catch {
      sent = false;
    }
    if (!sent) this.#stats.messages_dropped++;
  }

  #runStart(
    run: Run,
    scopeId: string,
    last: bigint,
    segmentId: string,
    extra: {
      predecessors?: readonly string[];
      branchIds?: readonly string[];
      basis?: IdBasis;
      root?: RunPlan;
    } = {},
  ): Record<string, unknown> {
    const ref = this.#manifest();
    const fields: Record<string, unknown> = { kind: "run_start", last_sequence: last.toString() };
    const put = (name: string, value: unknown): void => {
      if (value === undefined || (Array.isArray(value) && value.length === 0)) return;
      fields[name] = Array.isArray(value) ? [...(value as unknown[])] : value;
    };
    const root = extra.root !== undefined && extra.predecessors === ROOT ? extra.root : undefined;
    put("branch_ids", extra.branchIds);
    put("id_basis", extra.basis ?? run.openBasis ?? run.idBasis);
    put("links", root?.links);
    put("manifest_digest", ref?.digest);
    put("manifest_id", ref?.manifestId);
    put("open_deadline_s", root?.openDeadlineS);
    put("parent_run_id", root?.parentRunId);
    put("predecessors", extra.predecessors);
    put("resumable", root === undefined ? undefined : run.resumable);
    put("resumed_from", root?.resumedFrom);
    put("run_id", run.runId);
    put("scope_id", scopeId);
    put("segment_id", segmentId);
    put("session_id", root?.sessionId);
    put("user_id", root?.userId);
    return fields;
  }

  /**
   * Opens a segment of `run` (minted `seg-` id) and queues its `run_start`: the given
   * predecessors, else the pending ones (local continuation), else the run's last sealed
   * segment here, else `none` (the run's root).
   */
  #open(
    run: Run,
    scopeId: string,
    last: bigint,
    options: {
      predecessors?: readonly string[];
      branchIds?: readonly string[];
      basis?: IdBasis;
      root?: RunPlan;
    } = {},
  ): string {
    const segmentId = SEGMENT_PREFIX + randomBytes(16).toString("hex");
    let preds =
      (options.predecessors !== undefined && options.predecessors.length > 0
        ? options.predecessors
        : undefined) ??
      (run.pendingPredecessors.length > 0 ? run.pendingPredecessors : undefined) ??
      (run.lastEntry !== undefined ? [run.lastEntry] : ROOT);
    if (preds.length > MAX_PREDECESSORS) {
      this.#stats.predecessors_dropped += preds.length - MAX_PREDECESSORS;
      preds = preds.slice(0, MAX_PREDECESSORS);
    }
    const given = options.branchIds !== undefined && options.branchIds.length > 0;
    const branches = (given ? options.branchIds! : run.pendingBranchIds).slice(0, MAX_BRANCHES);
    run.openBasis = options.basis ?? run.openBasis ?? run.idBasis;
    const fields = this.#runStart(run, scopeId, last, segmentId, {
      predecessors: preds,
      branchIds: branches,
      basis: run.openBasis,
      root: options.root,
    });
    this.#setSegment(run, segmentId);
    run.pendingPredecessors = [];
    run.pendingBranchIds = [];
    this.#stats.segments_opened++;
    this.#queue(fields);
    return segmentId;
  }

  /**
   * Seals `run`'s open segment: its position count (read with the segment, under the
   * lock), the allocator's last position, the manifest in force. It becomes the pending
   * predecessor of the run's next segment here.
   */
  #seal(
    run: Run,
    terminal: boolean,
    exact: boolean,
    branchIds: readonly string[] = [],
  ): SealOrder | undefined {
    const segmentId = this.#segmentOf(run);
    if (segmentId === undefined) return undefined;
    const positions = run.ref.slot >= 0 ? this.#runtime.runPositions(run.ref.slot) : 0n;
    const last = this.#last();
    const digest = this.#manifest()?.digest ?? NO_MANIFEST_DIGEST;
    const order: SealOrder = {
      segmentId,
      runId: run.runId,
      lastSequence: last,
      manifestDigest: digest,
      positions,
      terminal,
      resumable: run.resumable,
      branchIds,
      exact,
    };
    this.#setSegment(run, undefined);
    run.lastEntry = formatEntry(segmentId, this.sourceId, this.#runtime.epoch, last, digest);
    run.pendingPredecessors = [run.lastEntry];
    run.terminalSealed = run.terminalSealed || terminal;
    this.#stats.segments_sealed++;
    return order;
  }

  /** Asks the worker's accumulator for the `segment_seal` (written once settled, §3.7). */
  #request(order: SealOrder | undefined): void {
    if (order === undefined) return;
    if (!order.exact) {
      this.#stats.seals_unrequested++;
      return;
    }
    const message: SealMessage = {
      t: "seal",
      segment: order.segmentId,
      runId: order.runId,
      source: this.sourceId,
      epoch: this.#runtime.epoch.toString(),
      lastSequence: order.lastSequence.toString(),
      positions: order.positions.toString(),
      manifestDigest: order.manifestDigest,
      terminal: order.terminal,
      resumable: order.resumable,
      branchIds: [...order.branchIds],
    };
    let sent: boolean;
    try {
      sent = this.#send(message);
    } catch {
      sent = false;
    }
    if (!sent) this.#stats.messages_dropped++;
  }

  // ------------------------------------------------------------ block entry and exit

  /**
   * Resolves one block entry's run identity and root fields (outside the lock). A
   * malformed optional argument is dropped (`api_misuse`); strict mode throws.
   */
  prepare(options: RunOptions, outermost: boolean): RunPlan {
    let tokens = tokenList(options.resume);
    if (options.resume === undefined && outermost && this.#envTokens !== undefined) {
      tokens = this.#envTokens;
      this.#envTokens = undefined; // consumed once, by the first outermost run()
    }
    const clear = typeof options.runId === "string" ? options.runId : this.#envRunId;
    const identity = resolveIdentity(
      tokens,
      clear,
      (value) => this.rule.run(value),
      () => this.rule.mintRun(),
      this.#correlationOk,
    );
    this.#rejected(identity.tokensRejected);
    let deadline: number | undefined;
    if (options.openDeadlineS !== undefined) {
      const [low, high] = OPEN_DEADLINE_RANGE;
      const value = options.openDeadlineS;
      if (Number.isInteger(value) && value >= low && value <= high) deadline = value;
      else misuse("openDeadlineS outside 60..31536000");
    }
    return {
      identity,
      resumable: flag(options.resumable, "resumable"),
      final: flag(options.final, "final"),
      openDeadlineS: deadline,
      sessionId: this.#v2("sess", options.sessionId),
      userId: this.#v2("usr", options.userId),
      parentRunId: this.#link(options.parentRunId),
      resumedFrom: this.#link(options.resumedFrom),
      links: this.#links(options.links),
    };
  }

  #rejected(count: number): void {
    if (count === 0) return;
    // Counted, with one class-only warning per process that names the fix; the token is
    // never printed (it may carry a clear-mode run id or label).
    this.#stats.tokens_rejected += count;
    if (this.#warned) return;
    this.#warned = true;
    try {
      this.#warn(TOKEN_DROPPED_WARNING);
    } catch {
      // never the agent's problem
    }
  }

  #v2(prefix: string, value: unknown): string | undefined {
    if (value === undefined) return undefined;
    if (typeof value !== "string" || value === "") {
      misuse(`${prefix === "sess" ? "sessionId" : "userId"} must be a non-empty string`);
      return undefined;
    }
    return this.rule.v2(prefix, value);
  }

  #link(value: unknown): string | undefined {
    if (value === undefined) return undefined;
    if (typeof value !== "string" || value === "") {
      misuse("a run link must be a non-empty string");
      return undefined;
    }
    return this.rule.link(value);
  }

  #links(values: unknown): string[] {
    if (values === undefined) return [];
    if (typeof values === "string" || !Array.isArray(values)) {
      misuse("links must be an array of strings");
      return [];
    }
    const out: string[] = [];
    for (const value of values as unknown[]) {
      const mapped = this.#link(value);
      if (mapped !== undefined && !out.includes(mapped)) out.push(mapped);
    }
    if (out.length > MAX_RUN_LINKS) {
      misuse("at most 16 run links");
      out.length = MAX_RUN_LINKS;
    }
    return out;
  }

  /**
   * Block entry (§3.6): the run's entry (new or re-entered), its depth and the block's
   * `run_start`. The scope to make current, or `undefined` when the block runs
   * uncaptured (no run slot is free: counted).
   */
  enter(plan: RunPlan): RunScope | undefined {
    if (!this.active) return undefined;
    const identity = plan.identity;
    const resumed = identity.validTokens > 0;
    return this.#locked((exact) => {
      const last = this.#last();
      let run = this.#revive(identity.runId);
      if (run === null) {
        this.#stats.run_slots_exhausted++;
        return undefined;
      }
      const isNew = run === undefined;
      if (run === undefined) {
        const slot = this.#freeSlots.pop();
        if (slot === undefined) {
          this.#stats.run_slots_exhausted++;
          return undefined;
        }
        run = newRun(identity.runId, identity.idBasis, { slot });
        run.openDeadlineS = plan.openDeadlineS;
        this.#runs.set(run.runId, run);
      } else if (run.terminalSealed && run.depth === 0) {
        this.#stats.post_terminal_allocations++; // K2: one run id, one run
      }
      const scope = newScope(run.runId, run.ref);
      run.depth++;
      run.resumable = run.resumable || plan.resumable || resumed;
      run.finalBlock = run.finalBlock || plan.final;
      const open = this.#segmentOf(run);
      if (resumed && open !== undefined) {
        // A join into an open segment: seal it, and open one naming it and the tokens.
        this.#request(this.#seal(run, false, exact));
        this.#open(run, scope.scopeId, last, {
          predecessors: [...run.pendingPredecessors, ...identity.predecessors],
          branchIds: identity.branchIds,
          basis: identity.idBasis,
        });
      } else if (open === undefined) {
        let preds: readonly string[] | undefined = resumed ? identity.predecessors : undefined;
        if (preds === undefined && isNew) preds = ROOT;
        this.#open(run, scope.scopeId, last, {
          predecessors: preds,
          branchIds: identity.branchIds,
          basis: identity.idBasis,
          root: isNew ? plan : undefined,
        });
      } else {
        this.#queue(this.#runStart(run, scope.scopeId, last, open));
      }
      return scope;
    });
  }

  /**
   * Block exit (§3.6 trigger table): the block's `run_end`; at the run's outermost exit
   * here the open segment seals, terminal for a non-resumable run or a `final` block,
   * else non-terminal. The outermost `run_end` carries the run outcome (D30) when set.
   */
  exit(scope: RunScope, status: ScopeStatus = "ok"): void {
    this.#locked((exact) => {
      scope.closed = true;
      if (this.#closed) return;
      const last = this.#last();
      const run = this.#runs.get(scope.runId);
      if (run === undefined || run.depth <= 0) {
        this.#queue({
          kind: "run_end",
          last_sequence: last.toString(),
          run_id: scope.runId,
          scope_id: scope.scopeId,
          scope_status: status,
        });
        return;
      }
      run.depth--;
      const outermost = run.depth === 0;
      const terminal = outermost && (!run.resumable || run.finalBlock);
      if (outermost && terminal && this.#segmentOf(run) === undefined) {
        this.#open(run, scope.scopeId, last); // the seal needs a segment: a zero-width one
      }
      const fields: Record<string, unknown> = {
        kind: "run_end",
        last_sequence: last.toString(),
        run_id: run.runId,
        scope_id: scope.scopeId,
        scope_status: status,
      };
      const segmentId = this.#segmentOf(run);
      if (segmentId !== undefined) fields.segment_id = segmentId;
      if (outermost && run.outcome !== undefined) fields.outcome = run.outcome;
      if (outermost && run.stopReason !== undefined) fields.stop_reason = run.stopReason;
      this.#queue(fields);
      if (outermost) {
        this.#request(this.#seal(run, terminal, exact));
        run.finalBlock = false;
        run.outcome = undefined;
        run.stopReason = undefined;
        this.#retire(run);
      }
    });
  }

  /**
   * `final()` (epoch end, at `close()`): seal every open segment, non-terminal, except
   * a non-resumable run whose outermost block already exited (terminal). Nothing more is
   * accounted after it.
   */
  onFinal(): void {
    this.#locked((exact) => {
      if (this.#closed) return;
      this.#closed = true;
      for (const run of this.#runs.values()) {
        if (this.#segmentOf(run) === undefined) continue;
        const terminal = run.depth === 0 && !run.resumable;
        this.#request(this.#seal(run, terminal, exact));
      }
    });
  }

  // ---------------------------------------------------------- tokens, outcome, endRun

  /**
   * Seals the run's open segment (non-terminal, `resumable=true`) and returns its token
   * (`branches === 0`) or `branches` branch tokens, each naming its own `br-` id, all
   * listed in the seal. The run continues here in a new segment opened at once.
   */
  issue(scope: RunScope, branches: number): string[] {
    if (!this.active) return [];
    let order: SealOrder | undefined;
    let correlation = "";
    let ids: string[] = [];
    this.#locked((exact) => {
      const run = this.#runs.get(scope.runId);
      if (run === undefined || run.depth <= 0) return;
      if (!OPAQUE_ID_RE.test(run.correlationId)) {
        throw new RunApiMisuse("the run id cannot be carried in a token");
      }
      const last = this.#last();
      if (this.#segmentOf(run) === undefined) this.#open(run, scope.scopeId, last);
      ids = Array.from({ length: branches }, () => BRANCH_PREFIX + randomBytes(16).toString("hex"));
      run.resumable = true;
      order = this.#seal(run, false, exact, ids);
      this.#request(order);
      correlation = run.correlationId;
      this.#open(run, scope.scopeId, last); // the local continuation
    });
    const sealed = order as SealOrder | undefined;
    if (sealed === undefined) return [];
    const entry = formatEntry(
      sealed.segmentId,
      this.sourceId,
      this.#runtime.epoch,
      sealed.lastSequence,
      sealed.manifestDigest,
    );
    const tokens = (ids.length > 0 ? ids : [undefined]).map(
      (branch) => formatToken(correlation, entry, branch) ?? "",
    );
    this.#stats.tokens_issued += tokens.length;
    return tokens;
  }

  /** D30 (R4): kept on the run entry; its outermost `run_end` here carries it. */
  setOutcome(
    outcome: RunOutcome,
    stopReason: StopReason | undefined,
    runId: string | undefined,
    current: RunScope | undefined,
  ): boolean {
    if (!this.active) return false;
    const emitted = runId === undefined ? current?.runId : this.rule.run(runId);
    if (emitted === undefined) return false;
    const run = this.#runs.get(emitted);
    if (run === undefined || run.depth <= 0) return false;
    run.outcome = outcome;
    run.stopReason = stopReason;
    return true;
  }

  /**
   * `endRun` (§3.6): a zero-width segment, `run_start` (predecessors = the tokens),
   * `run_end` with the outcome, and a terminal `segment_seal`.
   */
  end(
    runId: string | undefined,
    outcome: RunOutcome,
    tokens: readonly string[],
    stopReason: StopReason | undefined,
  ): EndRunStatus {
    if (!this.active) return "not_capturing";
    const parsed = acceptedTokens(tokens, this.#correlationOk);
    this.#rejected(tokens.length - parsed.length);
    if (parsed.length === 0) return "refused_no_token";
    const kept = tokens.filter((t) => {
      const p = parseToken(t);
      return (
        p !== undefined && (p.correlation_id === null || this.#correlationOk(p.correlation_id))
      );
    });
    const correlations = new Set(
      parsed.flatMap((p) => (p.correlation_id === null ? [] : [p.correlation_id])),
    );
    if (runId === undefined && correlations.size > 1) return "refused_conflicting_tokens";
    const identity = resolveIdentity(
      kept,
      runId,
      (value) => this.rule.run(value),
      () => this.rule.mintRun(),
    );
    return this.#locked((exact) => {
      if (this.#closed) return "not_capturing";
      const last = this.#last();
      const run = newRun(identity.runId, identity.idBasis, { slot: -1 });
      run.resumable = true;
      const scopeId = randomUUID();
      const segmentId = this.#open(run, scopeId, last, {
        predecessors: identity.predecessors,
        branchIds: identity.branchIds,
        basis: identity.idBasis,
      });
      const fields: Record<string, unknown> = {
        kind: "run_end",
        last_sequence: last.toString(),
        outcome,
        run_id: run.runId,
        scope_id: scopeId,
        scope_status: "ok",
        segment_id: segmentId,
      };
      if (stopReason !== undefined) fields.stop_reason = stopReason;
      this.#queue(fields);
      this.#request(this.#seal(run, true, exact || run.ref.slot < 0));
      const local = this.#runs.get(identity.runId) ?? this.#retired.get(identity.runId);
      if (local !== undefined) local.terminalSealed = true; // later activity is post-terminal
      this.#stats.end_runs++;
      return "ended" as const;
    });
  }
}

function newRun(runId: string, basis: IdBasis, ref: RunRef): Run {
  return {
    runId,
    correlationId: runId,
    idBasis: basis,
    ref,
    slotless: undefined,
    depth: 0,
    resumable: false,
    terminalSealed: false,
    finalBlock: false,
    openDeadlineS: undefined,
    outcome: undefined,
    stopReason: undefined,
    openBasis: undefined,
    pendingPredecessors: [],
    pendingBranchIds: [],
    lastEntry: undefined,
  };
}

function flag(value: unknown, what: string): boolean {
  if (value === undefined) return false;
  if (typeof value === "boolean") return value;
  misuse(`${what} must be a boolean`);
  return false;
}

/**
 * `resume`: a token string (comma-separated for a join) or an array of tokens. A
 * non-string entry is dropped (`api_misuse`).
 */
export function tokenList(resume: unknown): string[] {
  if (resume === undefined || resume === null) return [];
  if (typeof resume === "string") return splitTokens(resume);
  if (!Array.isArray(resume)) {
    misuse("resume must be a token or an array of tokens");
    return [];
  }
  const out: string[] = [];
  for (const item of resume as unknown[]) {
    if (typeof item === "string") out.push(...splitTokens(item));
    else misuse("resume tokens are strings");
  }
  return out;
}

/** D30 checks shared by `endRun` and `setRunOutcome`. */
export function checkOutcome(outcome: unknown, stopReason: unknown): void {
  if (typeof outcome !== "string" || !(RUN_OUTCOMES as ReadonlySet<string>).has(outcome)) {
    throw new RunApiMisuse(
      "outcome must be one of completed, failed, cancelled, suspended, unknown",
    );
  }
  if (
    stopReason !== undefined &&
    (typeof stopReason !== "string" || !(STOP_REASONS as ReadonlySet<string>).has(stopReason))
  ) {
    throw new RunApiMisuse("stopReason is outside the D30 stop reasons");
  }
}

export { BRANCH_ID_RE };
