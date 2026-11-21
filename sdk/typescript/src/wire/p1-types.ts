// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * TypeScript port of spec 050's frozen P1 interface types (spec 055 §4.3; Python
 * `fabric/_capture_types.py`): the vocabularies, bounds, identifier patterns, the phase
 * table with its three status inputs (R4) and the typed record bodies (R5). Nothing here
 * does I/O or reads content; later units (the seal accumulator, the run table, the records
 * input) speak these types. A test pins every vocabulary to the Python literals.
 */

/** Builds a closed vocabulary: the literal union type and its frozen member set. */
function vocabulary<const T extends readonly string[]>(values: T): ReadonlySet<T[number]> {
  return Object.freeze(new Set(values));
}

export const PHASES = vocabulary(["start", "data", "update", "end"] as const);
export type Phase = "start" | "data" | "update" | "end";

export const LIFECYCLES = vocabulary([
  "queued",
  "running",
  "suspended",
  "deferred",
  "completed",
  "cancelled",
  "unknown",
] as const);
export type Lifecycle =
  "queued" | "running" | "suspended" | "deferred" | "completed" | "cancelled" | "unknown";

export const RESULT_STATUSES = vocabulary([
  "ok",
  "error",
  "cancelled",
  "timeout",
  "unknown",
] as const);
export type ResultStatus = "ok" | "error" | "cancelled" | "timeout" | "unknown";

export const OTLP_STATUSES = vocabulary(["unset", "ok", "error"] as const);
export type OtlpStatus = "unset" | "ok" | "error";

/** X27, `fabric.capture.source`. */
export const PROVENANCES = vocabulary(["reported", "observed"] as const);
export type Provenance = "reported" | "observed";

export const CONTENT_PROVENANCES = vocabulary(["caller_reported", "protocol"] as const);
export type ContentProvenance = "caller_reported" | "protocol";

/** X06; hooks never add a third class (R7). */
export const CAPTURE_INPUTS = vocabulary(["wire", "records"] as const);
export type CaptureInput = "wire" | "records";

/** `begin(kind, ...)`: the registry step_kind vocabulary plus `agent_turn` (050 §4.1). */
export const STEP_KINDS = vocabulary([
  "run",
  "model_call",
  "embedding",
  "input",
  "message",
  "tool_call",
  "provider_tool_call",
  "mcp_call",
  "retrieval",
  "memory",
  "terminal",
  "remote_exec",
  "database",
  "network",
  "file",
  "ui_action",
  "media_stream",
  "delegation",
  "workflow_node",
  "checkpoint",
  "control",
  "context_change",
  "selection",
  "side_effect",
  "outcome",
  "hook",
  "skill",
  "interaction",
  "extension",
  "agent_turn",
] as const);
export type StepKind = typeof STEP_KINDS extends ReadonlySet<infer T> ? T : never;

export const DESCRIPTOR_STATUSES = vocabulary(["not_captured", "unsupported"] as const);
export type DescriptorStatus = "not_captured" | "unsupported";

export const DESCRIPTOR_REASONS = vocabulary([
  "payload_too_large",
  "parse_failed",
  "not_exact_bytes",
  "encoding_failed",
] as const);
export type DescriptorReason =
  "payload_too_large" | "parse_failed" | "not_exact_bytes" | "encoding_failed";

export const MARKER_KINDS = vocabulary([
  "periodic",
  "run_start",
  "run_end",
  "final",
  "segment_seal",
  "manifest",
] as const);
export type MarkerKind =
  "periodic" | "run_start" | "run_end" | "final" | "segment_seal" | "manifest";

/** X49, `fabric.run.id_basis`. */
export const ID_BASES = vocabulary([
  "caller",
  "caller_join",
  "token",
  "token_conflict",
  "minted",
  "legacy",
] as const);
export type IdBasis = "caller" | "caller_join" | "token" | "token_conflict" | "minted" | "legacy";

/** D30. */
export const RUN_OUTCOMES = vocabulary([
  "completed",
  "failed",
  "cancelled",
  "suspended",
  "unknown",
] as const);
export type RunOutcome = "completed" | "failed" | "cancelled" | "suspended" | "unknown";

export const STOP_REASONS = vocabulary([
  "goal_reached",
  "max_steps",
  "max_tokens",
  "error",
  "cancelled",
  "handoff",
  "awaiting_input",
  "other",
  "unknown",
] as const);
export type StopReason =
  | "goal_reached"
  | "max_steps"
  | "max_tokens"
  | "error"
  | "cancelled"
  | "handoff"
  | "awaiting_input"
  | "other"
  | "unknown";

/** S34. */
export const SCOPE_STATUSES = vocabulary(["ok", "error", "cancelled"] as const);
export type ScopeStatus = "ok" | "error" | "cancelled";

/** `endRun` results (050 §3.6; the literal strings of the Python API). */
export const END_RUN_STATUSES = vocabulary([
  "ended",
  "refused_no_token",
  "refused_bad_token",
  "refused_conflicting_tokens",
  "not_capturing",
  "failed",
] as const);
export type EndRunStatus =
  | "ended"
  | "refused_no_token"
  | "refused_bad_token"
  | "refused_conflicting_tokens"
  | "not_capturing"
  | "failed";

export const REGISTRATION_STATUSES = vocabulary([
  "registered",
  "failed",
  "registration_full",
  "unregistered_fork",
  "unregistered_direct",
] as const);
export type RegistrationStatus =
  "registered" | "failed" | "registration_full" | "unregistered_fork" | "unregistered_direct";

/** A record digest (`sha256:<64 hex>`) or `loss:<reason>` (050 §3.7). */
export type SealEntry = string;

// ----------------------------------------------------------------- bounds

/** Bodies, descriptor-only bodies and the evidence object of one record (R6). */
export const MAX_RECORD_BODIES = 8;
/** Objects of one exchange: 2 sides x (primary + 64 parts + 64 part reviews + 1 review). */
export const MAX_EXCHANGE_BODIES = 260;
export const MAX_EVENT_IDS = 64;
/** `resumeTokens(n)` and predecessors of one `run_start`. */
export const MAX_BRANCHES = 64;
export const MAX_RUN_LINKS = 16;
export const EVIDENCE_ROLE = "record.evidence";
export const EVIDENCE_MEDIA_TYPE = "application/vnd.fabric.record-evidence+json";
export const EVIDENCE_SCHEMA_VERSION = "fabric.record-evidence/v1";
export const EVIDENCE_MAX_BYTES = 1 << 20;
export const EVIDENCE_MAX_ITEMS = 4096;
export const EVIDENCE_MAX_DEPTH = 4;
export const EVIDENCE_MAX_STRING = 256;
/** Keys only the receiving Node sets; never part of a record digest. */
export const RECEIVER_OWNED_KEYS: ReadonlySet<string> = Object.freeze(
  new Set(["fabric.source.authenticated"]),
);

// ----------------------------------------------------------------- identifier patterns

export const OPAQUE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
export const UUID4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const SEGMENT_ID_RE = /^seg-[0-9a-f]{32}$/;
export const BRANCH_ID_RE = /^br-[0-9a-f]{32}$/;
export const MINTED_RUN_ID_RE = /^r-[0-9a-f]{32}$/;
export const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

// ----------------------------------------------------------------- phase table (R4)

export interface PhaseRule {
  /** Empty: `lifecycle` must be absent (`update` stamps none). */
  readonly lifecycles: ReadonlySet<Lifecycle>;
  readonly defaultLifecycle: Lifecycle | undefined;
  readonly resultAllowed: boolean;
  readonly defaultResult: ResultStatus | undefined;
  readonly otlpMustBeUnset: boolean;
}

function rule(
  lifecycles: readonly Lifecycle[],
  defaultLifecycle: Lifecycle | undefined,
  resultAllowed: boolean,
  defaultResult: ResultStatus | undefined,
  otlpMustBeUnset: boolean,
): PhaseRule {
  return Object.freeze({
    lifecycles: Object.freeze(new Set(lifecycles)),
    defaultLifecycle,
    resultAllowed,
    defaultResult,
    otlpMustBeUnset,
  });
}

/** 050 §3.4: the phase table. */
export const PHASE_TABLE: Readonly<Record<Phase, PhaseRule>> = Object.freeze({
  start: rule(["running", "queued", "suspended"], "running", false, undefined, false),
  data: rule(["running", "suspended"], "running", false, undefined, false),
  update: rule([], undefined, false, undefined, true),
  end: rule(["completed", "cancelled", "deferred", "unknown"], "completed", true, "unknown", false),
});

/** The resolved three inputs of one `emit`; `dropped` names inputs outside the table. */
export interface StatusInputs {
  readonly lifecycle: Lifecycle | undefined;
  readonly resultStatus: ResultStatus | undefined;
  readonly otlpStatus: OtlpStatus;
  readonly dropped: readonly ("lifecycle" | "result_status" | "otlp_status")[];
}

/**
 * Apply the phase table. None of the three inputs is derived from another; only the
 * table's defaults fill a missing one (`end` never infers `ok`). An unknown phase returns
 * `undefined` (nothing can be emitted: `api_misuse`); any other value outside the table is
 * dropped and named in `dropped`.
 */
export function resolveStatusInputs(
  phase: unknown,
  lifecycle?: unknown,
  resultStatus?: unknown,
  otlpStatus: unknown = "unset",
): StatusInputs | undefined {
  if (typeof phase !== "string" || !PHASES.has(phase as Phase)) {
    return undefined;
  }
  const table = PHASE_TABLE[phase as Phase];
  const dropped: ("lifecycle" | "result_status" | "otlp_status")[] = [];
  let resolvedLifecycle = table.defaultLifecycle;
  if (lifecycle !== undefined && lifecycle !== null) {
    if (table.lifecycles.has(lifecycle as Lifecycle)) {
      resolvedLifecycle = lifecycle as Lifecycle;
    } else {
      dropped.push("lifecycle");
    }
  }
  let resolvedResult = table.defaultResult;
  if (resultStatus !== undefined && resultStatus !== null) {
    if (table.resultAllowed && RESULT_STATUSES.has(resultStatus as ResultStatus)) {
      resolvedResult = resultStatus as ResultStatus;
    } else {
      dropped.push("result_status");
    }
  }
  let resolvedOtlp: OtlpStatus = "unset";
  if (otlpStatus !== "unset") {
    if (OTLP_STATUSES.has(otlpStatus as OtlpStatus) && !table.otlpMustBeUnset) {
      resolvedOtlp = otlpStatus as OtlpStatus;
    } else {
      dropped.push("otlp_status");
    }
  }
  return Object.freeze({
    lifecycle: resolvedLifecycle,
    resultStatus: resolvedResult,
    otlpStatus: resolvedOtlp,
    dropped: Object.freeze(dropped),
  });
}

// ----------------------------------------------------------------- bodies (R5)

/** A captured body: exact bytes (or a string the producer encodes as UTF-8). */
export interface RecordBody {
  readonly kind: "body";
  readonly role: string;
  readonly mediaType: string;
  readonly data: Uint8Array | string;
  readonly contentProvenance: ContentProvenance;
}

/** A body that was not captured: a descriptor with a status and reason, never bytes. */
export interface DescriptorOnlyBody {
  readonly kind: "descriptor_only";
  readonly role: string;
  readonly mediaType: string;
  readonly status: DescriptorStatus;
  readonly reason: DescriptorReason;
}

export type AnyRecordBody = RecordBody | DescriptorOnlyBody;

// ----------------------------------------------------------------- allocation and seals

/** One allocated position (050 §3.3); `segmentId` absent outside any run. */
export interface Allocation {
  readonly epoch: bigint;
  readonly sequence: bigint;
  readonly segmentId?: string;
  readonly manifestSeq?: bigint;
}

/** A sealed segment as the run table keeps it. */
export interface SealedSegment {
  readonly segmentId: string;
  readonly lastSequence: bigint;
  readonly manifestDigest: string | undefined;
  readonly terminal: boolean;
  readonly resumable: boolean;
  readonly branchIds: readonly string[];
}
