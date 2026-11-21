// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The content writer of wire capture (spec 055 §5, §7.1; Python `wire/_pipeline.py`,
 * `wire/_attrs.py` and `wire/_spool.py` `exchange_doc`), run by the Fabric worker.
 *
 * One completed exchange becomes one spool record: the resolved `fabric.model_call` span,
 * whose attributes are Python's exact keys (ids, digests of the *stored* objects, enums and
 * labels; never content, a host, a path, a header or an original digest a mode forbids),
 * and the protected content objects with their descriptors (roles
 * `model.exchange.request` / `model.exchange.response`, `provenance: protocol`,
 * `boundary: provider_bound`). PROTECT ({@link Protector}) runs before anything is
 * written. The record's object count is checked against 050's bounds (260 per exchange,
 * 8 per record) before admission; a record over them is an `internal_error` loss, never a
 * shortened list.
 */
import { diskFull, type Spool } from "./spool.js";
import { pseudonymV2 } from "../identity.js";
import { parseJson } from "./codec.js";
import { OPERATION_NAMES } from "./match.js";
import { exposeModel } from "./model-names.js";
import { MAX_EXCHANGE_BODIES, MAX_RECORD_BODIES, SEGMENT_ID_RE, UUID4_RE } from "./p1-types.js";
import { encodeOpaqueId } from "./p1.js";
import {
  type ContentGate,
  type ContentObject,
  type Protector,
  ROLE_REQUEST,
  ROLE_RESPONSE,
  type SideResult,
} from "./protect.js";
import type { WireApi } from "./types.js";

/** The exchange span's name (047 §8). */
export const SPAN_EXCHANGE = "fabric.model_call";
const METADATA_MAX_BYTES = 256 * 1024;
const INT64_LIMIT = 1n << 63n;
const ERROR_RE = /^[A-Za-z_][A-Za-z0-9_.]{0,127}$/;
const POINT_RE = /^[a-z][a-z0-9_.]{0,63}@[0-9A-Za-z.+-]{1,32}$/;
const MAX_PROVIDER_REQUEST_ID_CHARS = 256;
/** Closed `gen_ai.response.finish_reasons` vocabulary; any other value is `other`. */
export const FINISH_REASONS: ReadonlySet<string> = new Set([
  "stop", "length", "tool_calls", "content_filter", "function_call", "end_turn", "max_tokens",
  "stop_sequence", "tool_use", "pause_turn", "refusal", "completed", "incomplete", "failed",
]); // prettier-ignore
const FINISH_KEY: Readonly<Partial<Record<WireApi, string>>> = {
  "openai.responses": "status",
  "anthropic.messages": "stop_reason",
};
// A side's reason as the span's store_reason (X40), and the order that picks one.
const SPAN_REASON: Readonly<Record<string, string>> = { part_cap: "body_cap" };
const REASON_ORDER = [
  "protection_failed",
  "store_failed",
  "privacy_policy",
  "body_cap",
  "inflight_budget",
  "transport_incomplete",
] as const;

/** One side of a completed exchange, as the Fabric worker read it from the arena. */
export interface CapturedSide {
  /** The retained bytes in order (arena pieces, read in place). */
  readonly pieces: readonly Uint8Array[];
  /** Every forwarded byte, when known (an exact side); the hook stops counting at a cut. */
  readonly observed: number | undefined;
  readonly truncated: boolean;
  readonly cutReason: string | undefined;
  readonly mediaType: string;
  readonly contentEncoding: string;
}

export type ResponseState = "complete" | "closed_early" | "error" | "abandoned";

/** A completed exchange (Python `WireJob`), with ids as their emitted text forms. */
export interface CapturedExchange {
  readonly exchangeId: string;
  readonly eventId: string;
  /** 16 lowercase hex. */
  readonly spanId: string;
  /** The clean parent (ids, flags, remoteness only), when the host had one. */
  readonly parent:
    { readonly traceId: string; readonly spanId: string; readonly remote: boolean } | undefined;
  readonly api: WireApi;
  readonly providerName: string;
  /** The matcher's configured id; emitted through {@link Enrichment.endpointIds}. */
  readonly endpointId: string;
  /** The capture point id (`wire.ts.undici`). */
  readonly point: string;
  readonly sourceId: string;
  readonly sourceEpoch: bigint;
  readonly sequence: bigint;
  readonly segmentId: string | undefined;
  /** The run scope's id (unit 055-t11); absent outside a run scope. */
  readonly runId: string | undefined;
  readonly scopeId: string | undefined;
  readonly startNs: bigint;
  readonly endNs: bigint;
  readonly request: CapturedSide;
  /** Absent: no response started. */
  readonly response: CapturedSide | undefined;
  readonly responseState: ResponseState;
  readonly statusCode: number | undefined;
  readonly errorType: string | undefined;
  readonly firstChunkOffsetNs: bigint | undefined;
  /** C40: the one header value, read only when opted in; mapped here, never kept. */
  readonly providerRequestId: string | undefined;
  /** Adopted from an explicit scope that withheld content (§4.6). */
  readonly withheld: boolean;
}

/** Per-install P1 enrichment (Python `WireEnrichment`), resolved on the installing thread. */
export interface Enrichment {
  /** Point id -> `id@version`. */
  readonly points: Readonly<Record<string, string>>;
  /** Configured endpoint id -> emitted C35 value. */
  readonly endpointIds: Readonly<Record<string, string>>;
  /** X05: `fabric.agent_id` ... as operator labels. */
  readonly identity: Readonly<Record<string, string>>;
  /** C40: the id key, set only when the opt-in is on. */
  readonly requestIdKey: Uint8Array | undefined;
  readonly modelAllowlist: readonly string[];
}

/** A span as the spool record carries it (Python `_span_record`). */
export interface SpanDoc {
  readonly name: string;
  readonly kind: "client";
  readonly trace_flags: 1;
  readonly trace_id: string;
  readonly span_id: string;
  readonly parent_span_id?: string;
  readonly parent_is_remote?: boolean;
  readonly start_time_unix_nano: bigint;
  readonly end_time_unix_nano: bigint;
  readonly status: "unset" | "error";
  readonly attributes: Readonly<Record<string, unknown>>;
}

/** What the writer made of one exchange: the span and the protected objects, in order. */
export interface PreparedExchange {
  readonly span: SpanDoc;
  readonly objects: readonly ContentObject[];
}

// -------------------------------------------------------------------- span values

/** S08 by the 049 §2.3 mapping (Python `step_status`). */
export function stepStatus(state: ResponseState, status: number | undefined): string {
  if (state === "complete") {
    if (status === undefined) return "unknown";
    if (status >= 200 && status < 300) return "ok";
    return status >= 400 && status < 600 ? "error" : "unknown";
  }
  return state === "error" ? "error" : state === "closed_early" ? "cancelled" : "unknown";
}

/** S09 of an `error` step: `provider` for HTTP >= 400, else `transport`. */
export function errorDomain(status: number | undefined): string {
  return status !== undefined && status >= 400 && status < 600 ? "provider" : "transport";
}

const isError = (job: CapturedExchange): boolean =>
  job.responseState === "error" || (job.statusCode !== undefined && job.statusCode >= 400);

/** The P1 keys of an exchange span (Python `p1_attributes`): ids, enums and labels only. */
export function p1Attributes(
  job: CapturedExchange,
  enrichment: Enrichment,
): Record<string, unknown> {
  const status = stepStatus(job.responseState, job.statusCode);
  const attrs: Record<string, unknown> = {
    "fabric.capture.input": "wire",
    "fabric.capture.source": "observed",
    "fabric.step.kind": job.api === "openai.embeddings" ? "embedding" : "model_call",
    "fabric.actor.type": "agent",
    "fabric.step.lifecycle_state": job.responseState === "closed_early" ? "cancelled" : "completed",
    "fabric.step.status": status,
  };
  if (status === "error") attrs["fabric.error.domain"] = errorDomain(job.statusCode);
  if (UUID4_RE.test(job.eventId)) attrs["fabric.event_id"] = job.eventId;
  if (job.segmentId !== undefined && SEGMENT_ID_RE.test(job.segmentId)) {
    attrs["fabric.run.segment_id"] = job.segmentId;
  }
  const offset = job.firstChunkOffsetNs;
  if (offset !== undefined && offset >= 0n && offset < INT64_LIMIT) {
    attrs["fabric.wire.first_chunk_offset_ns"] = offset;
  }
  const point = enrichment.points[job.point];
  if (point !== undefined && POINT_RE.test(point)) attrs["fabric.capture.point"] = point;
  const endpoint = enrichment.endpointIds[job.endpointId];
  if (endpoint !== undefined) attrs["fabric.wire.endpoint_id"] = endpoint;
  const requestId = job.providerRequestId;
  if (
    requestId !== undefined &&
    requestId.length > 0 &&
    requestId.length <= MAX_PROVIDER_REQUEST_ID_CHARS
  ) {
    const mapped = pseudonymV2("p", requestId, enrichment.requestIdKey);
    if (mapped !== undefined) attrs["fabric.wire.provider_request_id"] = mapped;
  }
  Object.assign(attrs, enrichment.identity);
  return attrs;
}

/**
 * Model (048 §7 exposure), finish reasons and usage, only from a complete, plain JSON
 * response of at most 256 KiB that the policy retained as is (Python `response_metadata`).
 */
export function responseMetadata(
  job: CapturedExchange,
  stored: Uint8Array | undefined,
  allowlist: readonly string[],
): {
  model?: string;
  finishReasons?: string[];
  inputTokens?: number | bigint;
  outputTokens?: number | bigint;
} {
  const body = job.response;
  if (
    body === undefined ||
    stored === undefined ||
    body.truncated ||
    job.responseState !== "complete"
  )
    return {};
  if (body.contentEncoding !== "identity" || body.mediaType !== "application/json") return {};
  if (stored.byteLength > METADATA_MAX_BYTES) return {};
  let doc: unknown;
  try {
    doc = parseJson(
      Buffer.from(stored.buffer, stored.byteOffset, stored.byteLength).toString("utf8"),
    );
  } catch {
    return {};
  }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) return {};
  const record = doc as Record<string, unknown>;
  const found: ReturnType<typeof responseMetadata> = {};
  const model = exposeModel(record.model, allowlist);
  if (model !== undefined) found.model = model;
  const key = FINISH_KEY[job.api];
  const choices = Array.isArray(record.choices) ? record.choices : [];
  const reasons =
    key !== undefined
      ? [record[key]]
      : choices.map((c) =>
          c !== null && typeof c === "object" && !Array.isArray(c)
            ? (c as Record<string, unknown>).finish_reason
            : undefined,
        );
  const strings = reasons.filter((r): r is string => typeof r === "string").slice(0, 64);
  if (strings.length > 0)
    found.finishReasons = strings.map((r) => (FINISH_REASONS.has(r) ? r : "other"));
  const usage =
    record.usage !== null && typeof record.usage === "object" && !Array.isArray(record.usage)
      ? (record.usage as Record<string, unknown>)
      : {};
  const native = key !== undefined;
  const count = (name: string): number | bigint | undefined => {
    const value = usage[name];
    if (typeof value === "number" && Number.isInteger(value) && value >= 0) return value;
    if (typeof value === "bigint" && value >= 0n && value < INT64_LIMIT) return value;
    return undefined;
  };
  const input = count(native ? "input_tokens" : "prompt_tokens");
  const output = count(native ? "output_tokens" : "completion_tokens");
  if (input !== undefined) found.inputTokens = input;
  if (output !== undefined) found.outputTokens = output;
  return found;
}

// --------------------------------------------------------------------- descriptors

/**
 * `datetime.fromtimestamp(ns / 1e9, UTC).isoformat()` exactly as Python prints it: the
 * float division, microseconds rounded half to even, `.ffffff` only when non-zero.
 */
export function pyIsoformat(ns: bigint): string {
  const seconds = Number(ns) / 1e9;
  let whole = Math.trunc(seconds);
  const scaled = (seconds - whole) * 1e6;
  const floor = Math.floor(scaled);
  const diff = scaled - floor;
  let micros = diff > 0.5 ? floor + 1 : diff < 0.5 ? floor : floor % 2 === 0 ? floor : floor + 1;
  if (micros >= 1_000_000) {
    micros -= 1_000_000;
    whole += 1;
  }
  const date = new Date(whole * 1000).toISOString().slice(0, 19);
  return date + (micros === 0 ? "" : "." + String(micros).padStart(6, "0")) + "+00:00";
}

/** The run id of an exchange outside a run scope (Python `resolve_run_id`). */
export function defaultRunId(job: CapturedExchange): string {
  if (job.runId !== undefined) return job.runId;
  if (
    job.parent !== undefined &&
    /^[0-9a-f]{32}$/.test(job.parent.traceId) &&
    /[1-9a-f]/.test(job.parent.traceId)
  ) {
    return `trace:${job.parent.traceId}`;
  }
  return encodeOpaqueId(`source:${job.sourceId}:${job.sourceEpoch}`);
}

/** The identity fields every descriptor of one side carries (Python `_base`). */
export function descriptorBase(
  job: CapturedExchange,
  side: CapturedSide,
  role: string,
  tenantId: string | undefined,
): Record<string, unknown> {
  return {
    schema_version: "fabric.content-object/v2",
    tenant_id: tenantId,
    media_type: side.mediaType,
    content_encoding: side.contentEncoding,
    provenance: "protocol",
    boundary: "provider_bound",
    source_id: job.sourceId,
    source_epoch: job.sourceEpoch,
    source_sequence: job.sequence,
    captured_at: pyIsoformat(role === ROLE_REQUEST ? job.startNs : job.endNs),
    run_id: defaultRunId(job),
    operation_id: job.exchangeId,
  };
}

// --------------------------------------------------------------------- the exchange

export interface WriterContext {
  readonly gate: ContentGate;
  /** Undefined while content capture is not enabled (049 §7.3). */
  readonly protector: Protector | undefined;
  readonly tenantId: string | undefined;
  readonly enrichment: Enrichment;
}

/**
 * PROTECT both sides, then the span (Python `_prepare` + `exchange_attributes` +
 * `_span_record`). `traceId` is used when the exchange has no parent (a root span).
 */
export async function prepareExchange(
  job: CapturedExchange,
  context: WriterContext,
  traceId: string,
): Promise<PreparedExchange> {
  const sides: [CapturedSide, string][] = [[job.request, ROLE_REQUEST]];
  if (job.response !== undefined) sides.push([job.response, ROLE_RESPONSE]);
  const objects: ContentObject[] = [];
  let digests: (string | undefined)[] = [undefined, undefined];
  let refs: (string | undefined)[] = [undefined, undefined];
  let storeStatus: string;
  let storeReason: string | undefined;
  let truncated: boolean;
  let responseStored: Uint8Array | undefined;
  const protector = context.protector;
  if (job.withheld || protector === undefined) {
    // An adopted call its explicit scope withheld stores nothing and no digest (§4.6);
    // with content not enabled only safe metadata is emitted.
    truncated = sides.some(([side]) => side.truncated);
    storeStatus = "disabled";
    storeReason = job.withheld ? "explicit_withheld" : context.gate.reason;
  } else {
    const results: SideResult[] = [];
    for (const [side, role] of sides) {
      const result = await protector.side(
        descriptorBase(job, side, role, context.tenantId),
        role,
        side.pieces,
        {
          observed: side.observed,
          cutReason: side.cutReason ?? (side.truncated ? "body_cap" : undefined),
          partial: role === ROLE_RESPONSE && job.responseState !== "complete",
        },
      );
      objects.push(...result.objects);
      results.push(result);
    }
    truncated = results.some((r) => r.truncated);
    const stored = results.filter((r) => r.primary !== undefined).length;
    storeStatus = stored === results.length ? "stored" : stored > 0 ? "partial" : "disabled";
    const reasons = new Set(
      results.flatMap((r) => (r.reason === undefined ? [] : [SPAN_REASON[r.reason] ?? r.reason])),
    );
    storeReason = REASON_ORDER.find((r) => reasons.has(r));
    digests = results.map(
      (r) => String(r.primary?.descriptor.stored_sha256 ?? "").slice(7) || undefined,
    );
    refs = results.map((r) => r.primary?.descriptor.object_id as string | undefined);
    const response = results[1]?.primary;
    // Metadata only from bytes the policy retained as they are (never a masked copy).
    if (response?.descriptor.privacy_mode === "retain_original") responseStored = response.data;
  }
  const metadata = responseMetadata(job, responseStored, context.enrichment.modelAllowlist);
  let error = job.errorType;
  if (job.responseState === "error")
    error = error !== undefined && ERROR_RE.test(error) ? error : "UnknownError";
  const status = job.statusCode;
  const attributes: Record<string, unknown> = {
    "fabric.wire.exchange_id": job.exchangeId,
    "fabric.run.id": defaultRunId(job),
    "fabric.run.scope_id": job.scopeId,
    "fabric.source_id": job.sourceId,
    "fabric.source.epoch": job.sourceEpoch,
    "fabric.source.sequence": job.sequence,
    "fabric.wire.api": job.api,
    "fabric.wire.request_sha256": digests[0],
    "fabric.wire.response_state": job.responseState,
    "fabric.wire.truncated": truncated,
    "fabric.wire.store_status": storeStatus,
    "fabric.wire.store_reason": storeReason,
    "http.request.method": "POST",
    "gen_ai.operation.name": OPERATION_NAMES[job.api],
    "gen_ai.provider.name": job.providerName,
    "fabric.wire.response_sha256": digests[1],
    "fabric.content.request_ref": refs[0],
    "fabric.content.result_ref": refs[1],
    "http.response.status_code":
      status !== undefined && status >= 100 && status < 600 ? status : undefined,
    "error.type": job.responseState === "error" ? error : undefined,
    "gen_ai.response.model": metadata.model,
    "gen_ai.response.finish_reasons": metadata.finishReasons,
    "gen_ai.usage.input_tokens": metadata.inputTokens,
    "gen_ai.usage.output_tokens": metadata.outputTokens,
  };
  try {
    Object.assign(attributes, p1Attributes(job, context.enrichment));
  } catch {
    // 050 §3.9: the P1 keys never cost the record.
  }
  for (const key of Object.keys(attributes))
    if (attributes[key] === undefined) delete attributes[key];
  const span: SpanDoc = {
    name: SPAN_EXCHANGE,
    kind: "client",
    trace_flags: 1,
    trace_id: job.parent?.traceId ?? traceId,
    span_id: job.spanId,
    ...(job.parent === undefined
      ? {}
      : { parent_span_id: job.parent.spanId, parent_is_remote: job.parent.remote }),
    start_time_unix_nano: job.startNs,
    end_time_unix_nano: job.endNs > job.startNs ? job.endNs : job.startNs,
    status: isError(job) ? "error" : "unset",
    attributes,
  };
  return { span, objects };
}

// ------------------------------------------------------------------------ the spool

/** A spool entry over 050's object bound (R6): refused before anything is written. */
export class ObjectBoundError extends Error {
  constructor() {
    super("a spool entry over its object bound (260 per exchange, 8 per record) is never written");
  }
}

/** Whether `count` objects exceed the bound of `kind` (260 per exchange, 8 per record). */
export function overObjectBound(kind: "exchange" | "record", count: number): boolean {
  return count > (kind === "exchange" ? MAX_EXCHANGE_BODIES : MAX_RECORD_BODIES);
}

/** The spool `exchange` entry (Python `exchange_doc`): span and body ranges, in order. */
export function exchangeEntry(
  sourceId: string,
  epoch: bigint,
  serviceName: string,
  prepared: PreparedExchange,
): { doc: Record<string, unknown>; bodies: Uint8Array[] } {
  if (overObjectBound("exchange", prepared.objects.length)) throw new ObjectBoundError();
  let offset = 0;
  const bodies = prepared.objects.map((object) => {
    const entry = { descriptor: object.descriptor, length: object.data.byteLength, offset };
    offset += object.data.byteLength;
    return entry;
  });
  return {
    doc: {
      record_kind: "exchange",
      source: { source_id: sourceId, source_epoch: epoch },
      service_name: serviceName,
      span: prepared.span,
      bodies,
    },
    bodies: prepared.objects.map((object) => object.data),
  };
}

/** What admission did with one record (Python `spool_exchanges`). */
export type AdmitOutcome = "spooled" | "queue_full" | "disk_full" | "internal_error";

/**
 * Admits entries to the spool in one batch: `spooled`, `queue_full` (over the shared bound
 * or the admission lock stayed busy), `disk_full` (ENOSPC/EDQUOT) or `internal_error`
 * (anything else, including an entry over its object bound).
 */
export function admitEntries(
  spool: Spool,
  entries: readonly { doc: Record<string, unknown>; bodies: readonly Uint8Array[] }[],
): AdmitOutcome[] {
  let results: (string | null | Error)[];
  try {
    results = spool.writeBatch(entries);
  } catch (error) {
    return entries.map(() => (diskFull(error) ? "disk_full" : "internal_error"));
  }
  return results.map((result) => {
    if (typeof result === "string") return "spooled";
    if (result === null) return "queue_full";
    return diskFull(result) ? "disk_full" : "internal_error";
  });
}
