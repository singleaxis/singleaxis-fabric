// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Capture manifests and heartbeats (spec 050 §3.8, spec 055 §7.2): the TypeScript port of
 * Python's `fabric/_manifest.py` and of the heartbeat half of `_loss.py`.
 *
 * A manifest is a `fabric.capture-manifest/v1` document per `(source, epoch)` that says
 * what this Node process could and could not capture. Manifest 0 precedes position 0
 * (`after_source_sequence = -1`); every later manifest of the epoch is a state change
 * with the next `manifest_seq`, `previous_manifest_sha256` = the canonical digest of its
 * predecessor, and `after_source_sequence` = the last position allocated when the change
 * took effect ({@link WireRuntime.cut}: the change first, then the counter, so every
 * later position was allocated under the new state).
 *
 * Everything but capture-point state (and the uncaptured classes, see
 * {@link ManifestChain.classUncaptured}) is fixed per epoch and read once at install into
 * a {@link ManifestTemplate}: plain, structured-cloneable data, built on the installing
 * thread by {@link manifestTemplate} and used by the Fabric worker, which spools. It never
 * holds a path, a key, a token, a host name or a dependency inventory: only enumerated
 * values, versions, digests, key ids and numbers.
 *
 * Each manifest is spooled as a `marker` of kind `manifest` whose attributes are the
 * manifest-span-v1 mapping (`fabric.capture_manifest`), with the manifest's own uuid4
 * event id. A `final` heartbeat is spooled the same way at orderly close; `periodic`
 * heartbeats go to the sender's export path with an event id minted once and kept until
 * they are delivered ({@link Heartbeats}), because both spool readers refuse a spooled
 * `periodic` marker (Python `wire/_spool.py` `_marker_ok`; 055 §6.2). Every heartbeat
 * carries the latest `manifest_seq`. Nothing here throws into the application.
 */
import { randomUUID } from "node:crypto";

import { keyId } from "../identity.js";
import { SDK_VERSION } from "../version.js";

import { INT64_MAX, type JsonValue, sha256Prefixed } from "./codec.js";
import {
  FIELD_REGISTRY_REVISION,
  MANIFEST_FIELDS,
  MANIFEST_POINTS,
} from "./manifest-fields.generated.js";
import { heartbeatSpan } from "./loss.js";
import { manifestDigest, manifestToSpan } from "./p1.js";
import { ROLE_TABLE_VERSION } from "./roles.generated.js";
import type { ContentGate } from "./protect.js";
import { type Spool, writePrefix } from "./spool.js";
import type { EndpointMatcher, WireSettings } from "./types.js";

export { FIELD_REGISTRY_REVISION, MANIFEST_FIELDS, MANIFEST_POINTS };

export const SPAN_MANIFEST = "fabric.capture_manifest";
export const SPAN_HEARTBEAT = "fabric.capture_heartbeat";
export const SCHEMA_VERSION = "fabric.capture-manifest/v1";
/** 049 decision 1: the first-release coverage profile. */
export const COVERAGE_PROFILE = "fabric.profile.model-calls/v1";
export const SEQUENCE_UNIT = "record";
export const CLOCK_DOMAIN = "wall_utc";
/** `unsealed_prior_epochs` lists at most 64; `unsealed_prior_epoch_count` is exact. */
export const MAX_LISTED_UNSEALED = 64;
/** Python's periodic heartbeat interval (`LossEmitter(heartbeat_interval_s=30.0)`). */
export const HEARTBEAT_INTERVAL_MS = 30_000;
/** Periodic heartbeats kept for the sender before the oldest is dropped (counted). */
export const MAX_PENDING_BEATS = 64;
/** Markers held for the spool (Python `MAX_QUEUED_MARKERS`, `MAX_QUEUED_MARKER_BYTES`). */
export const MAX_HELD_MARKERS = 16384;
export const MAX_HELD_MARKER_BYTES = 16 * 1024 * 1024;

export const UNDICI_POINT = "wire.ts.undici";
export const NODE_HTTP_POINT = "wire.ts.node_http";
export const WIRE_POINTS: readonly string[] = Object.freeze([UNDICI_POINT, NODE_HTTP_POINT]);

export type PointState = "active" | "installed_inactive" | "disabled" | "unsupported" | "failed";
export const POINT_STATES: ReadonlySet<string> = new Set<PointState>([
  "active",
  "installed_inactive",
  "disabled",
  "unsupported",
  "failed",
]);
/** A point's state and its reason (`undefined`: none). */
export type StateEntry = readonly [PointState, string | undefined];

/** capture-manifest-v1 `capture_points[].reason` (a test pins it to the schema). */
export const POINT_REASONS: ReadonlySet<string> = new Set([
  "not_instrumented", "hook_disabled", "not_configured", "unsupported_api",
  "unsupported_runtime", "unsupported_version", "parse_failed", "body_cap", "part_cap",
  "inflight_budget", "queue_full", "disk_full", "shutdown", "internal_error", "span_dropped",
  "store_failed", "destination_rejected", "transport_incomplete", "stream_closed_early",
  "privacy_policy", "protection_failed", "missing_capture_policy", "missing_id_key",
  "missing_spool_key", "provider_redacted", "provider_encrypted", "provider_summarised",
  "provider_not_returned", "provider_held", "caller_omitted", "deferred_to_explicit",
  "explicit_withheld", "not_exposed", "source_lost", "segment_missing", "segment_conflict",
  "run_unterminated", "post_terminal_activity", "clock_uncertain", "source_unauthenticated",
  "unsealed_epoch", "seal_mismatch", "uninstrumented_client", "sampling",
  "retention_expired", "deleted", "unattributed_effect", "ambiguous_attribution",
  "tool_result_missing", "exchange_gap", "source_gap", "anchor_missing",
  "unexplained_host_event", "channel_disabled", "no_effect_channel", "none_in_window",
  "remote_sandbox",
]); // prettier-ignore

/**
 * The registry points this Node runtime has, in manifest order: the two wire tees, the
 * records input (`055-t20`) and run scopes (`055-t11`), with the self and install points.
 */
export const RUNTIME_POINTS: readonly string[] = Object.freeze([
  "fabric.self",
  "install.config",
  UNDICI_POINT,
  NODE_HTTP_POINT,
  "sdk.records",
  "run.scope",
]);

/**
 * Initial states of the points whose state does not come from the wire status. The
 * records input and the run API are not built in this release of the TypeScript wire
 * core, so they report `unsupported(unsupported_version)` until their units land.
 */
export const DEFAULT_STATES: Readonly<Record<string, StateEntry>> = Object.freeze({
  "fabric.self": ["active", undefined],
  "install.config": ["active", undefined],
  "sdk.records": ["unsupported", "unsupported_version"],
  "run.scope": ["unsupported", "unsupported_version"],
});
const UNKNOWN_STATE: StateEntry = ["installed_inactive", "not_instrumented"];

/**
 * The uncaptured classes a Node manifest may declare, in the order it lists them. Model
 * traffic through axios adapters, WebSockets, non-POST or unmatched endpoints is never
 * teed by this build.
 */
export const CLASS_ORDER: readonly string[] = Object.freeze([
  "node_http",
  "custom_fetch",
  "node_below_24",
  "node_worker_unattached",
  "axios",
  "websocket",
  "non_post_endpoints",
  "unmatched_endpoints",
]);
const ALWAYS_UNCAPTURED = ["axios", "websocket", "non_post_endpoints", "unmatched_endpoints"];

/** store_reason -> the manifest's `content_capture_reason` (Python `_policy._CAPTURE_REASON`). */
const CAPTURE_REASON: Readonly<Record<string, string>> = {
  no_store: "not_configured",
  missing_capture_policy: "missing_capture_policy",
  missing_id_key: "missing_id_key",
  missing_spool_key: "missing_spool_key",
};

// Document key order: the fixed head, then the optional keys (Python `_manifest._ORDER`).
const ORDER: readonly string[] = [
  "schema_version", "manifest_id", "event_id", "source_id", "source_epoch", "emitted_at",
  "sdk", "runtime", "profile", "coverage_profile", "identity_mode", "pseudonym_mode",
  "key_id", "capture_policy", "content_capture", "role_table_version", "limits",
  "sequence_unit", "clock", "endpoint_set_sha256", "explicit_wins", "capture_points",
  "uncaptured_classes", "inputs", "manifest_seq", "after_source_sequence",
  "chunk_boundaries_retained", "spool_encrypted", "unsealed_prior_epochs",
  "unsealed_prior_epoch_count", "source_auth", "previous_manifest_sha256",
  "content_capture_reason", "spool_key_id",
]; // prettier-ignore

/** Thrown only by the pure builders, for Fabric's own misuse; never reaches the agent. */
export class ManifestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ManifestError";
  }
}

// ------------------------------------------------------------------ the per-build facts

/** A version as the schema admits it (`[0-9A-Za-z.+-]`, bounded; Python `_version_text`). */
export function versionText(value: string, limit = 64): string {
  return (value.replace(/[^0-9A-Za-z.+-]/g, "-") || "0").slice(0, limit);
}

/**
 * What this build and runtime are, independent of configuration (Python `BuildFacts`).
 * Tests override the versions and the point set to reproduce the shared vectors.
 */
export interface BuildFacts {
  readonly sdkLanguage: string;
  readonly sdkVersion: string;
  readonly runtimeName: string;
  readonly runtimeVersion: string;
  readonly points: readonly string[];
  readonly fields: Readonly<Record<string, readonly string[]>>;
  readonly pointVersions: Readonly<Record<string, string>>;
  readonly clockMaxUncertaintyNs: bigint | undefined;
}

export function buildFacts(overrides: Partial<BuildFacts> = {}): BuildFacts {
  return {
    sdkLanguage: "typescript",
    sdkVersion: versionText(SDK_VERSION),
    runtimeName: "nodejs",
    runtimeVersion: versionText(process.versions.node),
    points: RUNTIME_POINTS,
    fields: MANIFEST_FIELDS,
    pointVersions: {},
    clockMaxUncertaintyNs: undefined,
    ...overrides,
  };
}

/** The version this build reports for a point (also the `<v>` of `fabric.capture.point`). */
export function pointVersion(point: string, facts: BuildFacts = buildFacts()): string {
  return facts.pointVersions[point] ?? versionText(facts.sdkVersion, 32);
}

/**
 * `sha256:` of the configured endpoint host set (Python `endpoint_set_digest`): each
 * endpoint's sorted hosts then sorted host suffixes, built-in endpoints first, then the
 * configured ones, joined by `|`. The manifest carries only this digest, never a host.
 */
export function endpointSetDigest(endpoints: Iterable<EndpointMatcher>): string {
  const parts: string[] = [];
  for (const matcher of endpoints) {
    parts.push(...[...matcher.hosts].sort(), ...[...matcher.hostSuffixes].sort());
  }
  // Hosts are ASCII after configuration, so UTF-16 order is Python's code-point order.
  return sha256Prefixed(parts.join("|"));
}

// -------------------------------------------------------------- qualification and state

/** One tuple of `wire-qualification.json` (spec 055 §9.4). */
export interface QualificationTuple {
  readonly point: string;
  readonly node: string;
  readonly undici?: string;
  readonly platform: string;
  readonly claim?: string;
  readonly report_sha256?: string;
}

/** The parts of the qualification table a manifest reads. */
export interface QualificationTable {
  readonly tuples: readonly QualificationTuple[];
}

/** The runtime build a point state is decided for. */
export interface RuntimeBuild {
  /** `process.versions.node`. */
  readonly node: string;
  /** `process.versions.undici` (the bundled undici), when known. */
  readonly undici: string | undefined;
  /** The native prebuild target (`linux-x64-glibc`), or `null` for an unsupported platform. */
  readonly platform: string | null;
}

export function currentRuntime(platform: string | null): RuntimeBuild {
  return {
    node: process.versions.node,
    undici: (process.versions as Record<string, string | undefined>).undici,
    platform,
  };
}

/** What decides one wire point's state at install (spec 055 §7.2). */
export interface PointStatusInputs {
  readonly runtime: RuntimeBuild;
  readonly table: QualificationTable;
  /** Whether the native module loaded and passed its self-test. */
  readonly nativeOk: boolean;
  /** `FABRIC_WIRE_UNDICI` / `FABRIC_WIRE_NODE_HTTP` (and the install options). */
  readonly enabled: Readonly<Record<string, boolean>>;
  /** Points whose hook is subscribed. */
  readonly installed: Readonly<Record<string, boolean>>;
  /** Configured endpoint matchers; with none, an installed point has nothing to match. */
  readonly endpoints: number;
  /** The runtime failed (`worker_crash_loop`, `worker_start_failed`). */
  readonly failed?: boolean;
}

function nodeMajor(version: string): number {
  const major = Number.parseInt(version.split(".")[0] ?? "", 10);
  return Number.isFinite(major) ? major : 0;
}

/** Whether the table lists any tuple, of any point or claim, for this Node patch and platform. */
function runtimeListed(table: QualificationTable, runtime: RuntimeBuild): boolean {
  return table.tuples.some((t) => t.node === runtime.node && t.platform === runtime.platform);
}

/** The `active` tuple of `point` on this runtime build, when the table has one. */
export function activeTuple(
  table: QualificationTable,
  point: string,
  runtime: RuntimeBuild,
): QualificationTuple | undefined {
  return table.tuples.find(
    (t) =>
      t.point === point &&
      t.claim === "active" &&
      typeof t.report_sha256 === "string" &&
      t.node === runtime.node &&
      t.platform === runtime.platform &&
      (point !== UNDICI_POINT || t.undici === runtime.undici),
  );
}

/**
 * A wire point's state at install, from the qualification table and the install status
 * (spec 055 §7.2), in this order:
 * 1. Node below 24: `unsupported(unsupported_version)`;
 * 2. no usable native module: `unsupported(unsupported_runtime)`;
 * 3. a Node patch and platform the table does not list at all: `unsupported(unsupported_version)`;
 * 4. switched off: `disabled(hook_disabled)`;
 * 5. no `active` tuple with a report for this point and build: `unsupported(unsupported_version)`;
 * 6. the runtime failed: `failed(internal_error)`;
 * 7. the hook is not subscribed: `failed(internal_error)`;
 * 8. no endpoint to match: `installed_inactive(not_configured)`;
 * 9. otherwise `active`: qualified and observing (content may still be withheld).
 * A missing body channel never becomes active because metadata events exist.
 */
export function wirePointState(point: string, inputs: PointStatusInputs): StateEntry {
  const { runtime, table } = inputs;
  if (nodeMajor(runtime.node) < 24) return ["unsupported", "unsupported_version"];
  if (!inputs.nativeOk || runtime.platform === null) return ["unsupported", "unsupported_runtime"];
  if (!runtimeListed(table, runtime)) return ["unsupported", "unsupported_version"];
  if (inputs.enabled[point] !== true) return ["disabled", "hook_disabled"];
  if (activeTuple(table, point, runtime) === undefined) {
    return ["unsupported", "unsupported_version"];
  }
  if (inputs.failed === true || inputs.installed[point] !== true) {
    return ["failed", "internal_error"];
  }
  if (inputs.endpoints === 0) return ["installed_inactive", "not_configured"];
  return ["active", undefined];
}

/** The initial state of every runtime point. */
export function initialStates(
  inputs: PointStatusInputs,
  facts: BuildFacts = buildFacts(),
  overrides: Readonly<Record<string, StateEntry>> = {},
): Record<string, StateEntry> {
  const states: Record<string, StateEntry> = {};
  for (const point of facts.points) {
    states[point] = WIRE_POINTS.includes(point)
      ? wirePointState(point, inputs)
      : (DEFAULT_STATES[point] ?? UNKNOWN_STATE);
  }
  return { ...states, ...overrides };
}

/** Inserts `cls` into `classes` at its {@link CLASS_ORDER} place (unchanged when present). */
export function withClass(classes: readonly string[], cls: string): string[] {
  if (classes.includes(cls)) return [...classes];
  const rank = CLASS_ORDER.indexOf(cls);
  const at = classes.findIndex((c) => {
    const other = CLASS_ORDER.indexOf(c);
    return rank >= 0 && other > rank;
  });
  const out = [...classes];
  out.splice(at < 0 ? out.length : at, 0, cls);
  return out;
}

/**
 * The model traffic this process will not tee, from the points' states (spec 055 §7.2):
 * `node_http` unless core HTTP is active; `custom_fetch` when fetch capture is switched
 * off on a runtime that could record it; `node_below_24` on Node 22; and
 * `node_worker_unattached` when a worker isolate did not attach (§4.5).
 */
export function uncapturedClasses(
  states: Readonly<Record<string, StateEntry>>,
  runtime: RuntimeBuild,
  unattachedWorkers = false,
): string[] {
  const out: string[] = [];
  if (states[NODE_HTTP_POINT]?.[0] !== "active") out.push("node_http");
  if (states[UNDICI_POINT]?.[0] === "disabled") out.push("custom_fetch");
  if (nodeMajor(runtime.node) < 24) out.push("node_below_24");
  if (unattachedWorkers) out.push("node_worker_unattached");
  return [...out, ...ALWAYS_UNCAPTURED];
}

// ----------------------------------------------------------------------- the template

/** One `capture_points[]` row's fixed columns. */
export interface PointRow {
  readonly id: string;
  readonly version: string;
  readonly kind: string;
  readonly process_global: boolean;
  readonly opt_in: boolean;
  readonly fields: readonly string[];
}

/**
 * Everything fixed for every epoch of one install, read once at install (Python
 * `_Template`). Plain data: it crosses to the Fabric worker in `workerData`.
 */
export interface ManifestTemplate {
  readonly sourceId: string;
  /** The epoch-fixed document properties (no ids, epoch, time, chain or points). */
  readonly fixed: Readonly<Record<string, JsonValue>>;
  readonly points: readonly PointRow[];
  readonly initial: Readonly<Record<string, StateEntry>>;
  readonly uncaptured: readonly string[];
}

/** The install facts a template reads besides the settings. */
export interface TemplateInputs {
  /** The emitted (pseudonymous) source id. */
  readonly sourceId: string;
  readonly gate: ContentGate;
  /** The spool key's id (`kid-` + 8 hex), when the spool is sealed. */
  readonly spoolKeyId?: string | undefined;
  readonly states: Readonly<Record<string, StateEntry>>;
  readonly runtime: RuntimeBuild;
  /** An application worker isolate is already known not to have attached. */
  readonly unattachedWorkers?: boolean;
  readonly facts?: BuildFacts;
}

function checkState(point: string, entry: StateEntry, known: Iterable<string>): void {
  const [state, reason] = entry;
  if (![...known].includes(point)) throw new ManifestError("unknown capture point");
  if (!POINT_STATES.has(state))
    throw new ManifestError("capture point state outside the vocabulary");
  if (reason !== undefined && !POINT_REASONS.has(reason)) {
    throw new ManifestError("capture point reason outside the vocabulary");
  }
}

/** A safe integer as a number, a larger one as a bigint (exact in the canonical JSON). */
function exact(value: number | bigint): number | bigint {
  const big = BigInt(value);
  return big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big;
}

/**
 * The template of an install (Python `_build_template`): the gate (profile, content
 * capture and its reason, capture policy), identity mode, pseudonym mode and key id,
 * limits, spool encryption and key id, clock, endpoint-set digest, D2, inputs and the
 * point inventory with the fields this build supplies. Reads no file and no environment.
 */
export function manifestTemplate(settings: WireSettings, inputs: TemplateInputs): ManifestTemplate {
  const facts = inputs.facts ?? buildFacts();
  const gate = inputs.gate;
  const initial: Record<string, StateEntry> = {};
  for (const point of facts.points) {
    const entry = inputs.states[point] ?? DEFAULT_STATES[point] ?? UNKNOWN_STATE;
    checkState(point, entry, Object.keys(MANIFEST_POINTS));
    initial[point] = entry;
  }
  const wire = WIRE_POINTS.some((p) => initial[p] !== undefined && initial[p][0] !== "unsupported");
  const clock: Record<string, JsonValue> = {
    domain: CLOCK_DOMAIN,
    uncertainty_ns: exact(settings.clockUncertaintyNs) as JsonValue,
  };
  if (facts.clockMaxUncertaintyNs !== undefined) {
    clock.max_uncertainty_ns = exact(facts.clockMaxUncertaintyNs) as JsonValue;
  }
  const fixed: Record<string, JsonValue> = {
    schema_version: SCHEMA_VERSION,
    source_id: inputs.sourceId,
    sdk: { language: facts.sdkLanguage, version: facts.sdkVersion },
    runtime: { name: facts.runtimeName, version: facts.runtimeVersion },
    profile: gate.profile,
    coverage_profile: COVERAGE_PROFILE,
    identity_mode: settings.identityMode,
    pseudonym_mode: gate.keyed ? "keyed" : "unkeyed",
    content_capture: gate.contentCapture,
    role_table_version: ROLE_TABLE_VERSION,
    limits: {
      max_body_bytes: settings.maxBodyBytes,
      max_retain_bytes: settings.maxRetainBytes,
      max_inflight_bytes: exact(settings.maxInflightBytes) as JsonValue,
      queue_max_items: settings.queueMaxItems,
      part_min_bytes: settings.partMinBytes,
      records_max_object_bytes: settings.recordsMaxObjectBytes,
      open_run_deadline_s: settings.openDeadlineS,
    },
    sequence_unit: SEQUENCE_UNIT,
    clock,
    endpoint_set_sha256: endpointSetDigest([...settings.endpoints, ...settings.extraEndpoints]),
    // D2: the explicit owner wins over the wire tee (spec 055 §4.6, built in 055-t8).
    explicit_wins: true,
    inputs: wire ? ["wire", "records"] : ["records"],
    chunk_boundaries_retained: false,
    spool_encrypted: gate.spoolEncrypted,
    source_auth: settings.contentEndpoint !== undefined ? "bound" : "unbound",
  };
  const idKey = settings.secrets.idKey;
  if (gate.keyed && idKey !== undefined) fixed.key_id = keyId(idKey);
  if (gate.policy !== undefined) {
    fixed.capture_policy = {
      policy_id: gate.policy.policyId,
      policy_version: gate.policy.policyVersion,
      policy_digest: gate.policy.policyDigest,
      encrypted_store_required: gate.policy.encryptedStoreRequired,
    };
  }
  const reason = gate.reason === undefined ? undefined : CAPTURE_REASON[gate.reason];
  if (reason !== undefined) fixed.content_capture_reason = reason;
  if (gate.spoolEncrypted && inputs.spoolKeyId !== undefined) {
    fixed.spool_key_id = inputs.spoolKeyId;
  }
  const points = facts.points.map((id) => {
    const spec = MANIFEST_POINTS[id]!;
    return {
      id,
      version: pointVersion(id, facts),
      kind: spec.kind,
      process_global: spec.process_global,
      opt_in: spec.opt_in,
      fields: [...(facts.fields[id] ?? [])],
    };
  });
  return {
    sourceId: inputs.sourceId,
    fixed,
    points,
    initial,
    uncaptured: uncapturedClasses(initial, inputs.runtime, inputs.unattachedWorkers === true),
  };
}

// ------------------------------------------------------------------ assembling documents

/** Python `_emitted_at`: RFC 3339 UTC with microseconds. */
export function emittedAt(ns: bigint): string {
  const ms = ns / 1_000_000n;
  const stamp = new Date(Number(ms)).toISOString().slice(0, 19);
  const micros = (ns % 1_000_000_000n) / 1000n;
  return `${stamp}.${micros.toString().padStart(6, "0")}Z`;
}

const wallNs = (): bigint => BigInt(Date.now()) * 1_000_000n;

/** The variable part of one manifest. */
export interface ManifestPosition {
  readonly epoch: bigint;
  readonly seq: number;
  readonly after: bigint;
  readonly previous: string | undefined;
  readonly states: Readonly<Record<string, StateEntry>>;
  readonly uncaptured: readonly string[];
  readonly unsealed: readonly bigint[];
  readonly unsealedCount: number;
  readonly manifestId: string;
  readonly eventId: string;
  readonly emittedAt: string;
}

/** A deep copy of plain JSON data (bigints and all), so no document shares the template's. */
function copyJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(copyJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, copyJson(v)]));
  }
  return value;
}

/** One document, keys in contract order (Python `_assemble`). Pure: no I/O, no state. */
export function assemble(
  template: ManifestTemplate,
  at: ManifestPosition,
): Record<string, JsonValue> {
  if (at.epoch < 0n || at.epoch > INT64_MAX)
    throw new ManifestError("source_epoch is a non-negative int64");
  if (at.seq < 0 || at.after < -1n) {
    throw new ManifestError("manifest_seq >= 0 and after_source_sequence >= -1");
  }
  if ((at.seq === 0) !== (at.previous === undefined) || (at.seq === 0 && at.after !== -1n)) {
    throw new ManifestError("manifest 0 precedes every sequence; later manifests chain");
  }
  const rows = template.points.map((p) => {
    const [state, reason] = at.states[p.id] ?? template.initial[p.id] ?? UNKNOWN_STATE;
    const row: Record<string, JsonValue> = {
      id: p.id,
      version: p.version,
      kind: p.kind,
      state,
      process_global: p.process_global,
      opt_in: p.opt_in,
      fields: [...p.fields],
    };
    if (reason !== undefined) row.reason = reason;
    return row;
  });
  const variable: Record<string, JsonValue> = {
    manifest_id: at.manifestId,
    event_id: at.eventId,
    source_epoch: exact(at.epoch) as JsonValue,
    emitted_at: at.emittedAt,
    capture_points: rows,
    uncaptured_classes: [...at.uncaptured],
    manifest_seq: at.seq,
    after_source_sequence: exact(at.after) as JsonValue,
    unsealed_prior_epochs: at.unsealed.slice(0, MAX_LISTED_UNSEALED).map(exact) as JsonValue,
    unsealed_prior_epoch_count: at.unsealedCount,
  };
  if (at.previous !== undefined) variable.previous_manifest_sha256 = at.previous;
  const fixed = copyJson(template.fixed) as Record<string, JsonValue>;
  const out: Record<string, JsonValue> = {};
  for (const key of ORDER) {
    if (Object.hasOwn(variable, key)) out[key] = variable[key]!;
    else if (Object.hasOwn(fixed, key)) out[key] = fixed[key]!;
  }
  return out;
}

/**
 * The declared unsealed prior epochs: sorted, unique, without `current`, at most 64
 * listed; the count is exact (`count` may exceed what was listed by the scan).
 */
export function unsealedPrior(
  epochs: readonly bigint[],
  count: number,
  current?: bigint,
): { readonly epochs: bigint[]; readonly count: number } {
  const unique = [...new Set(epochs.filter((e) => e > 0n && e <= INT64_MAX && e !== current))];
  unique.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const dropped = epochs.length - unique.length;
  return {
    epochs: unique.slice(0, MAX_LISTED_UNSEALED),
    count: Math.max(unique.length, count - dropped),
  };
}

// --------------------------------------------------------------------------- markers

/** A spool entry (`Spool.writeBatch`): the header fields and no body. */
export interface MarkerEntry {
  readonly doc: Record<string, unknown>;
  readonly bodies: readonly Uint8Array[];
}

/** The manifest in force (Python `ManifestRef`): what markers, tokens and seals read. */
export interface ManifestRef {
  readonly sourceId: string;
  readonly epoch: bigint;
  readonly manifestSeq: number;
  readonly after: bigint;
  readonly manifestId: string;
  readonly digest: string;
}

function entry(sourceId: string, epoch: bigint, marker: Record<string, unknown>): MarkerEntry {
  return {
    doc: {
      record_kind: "marker",
      source: { source_id: sourceId, source_epoch: exact(epoch) },
      marker,
    },
    bodies: [],
  };
}

/**
 * The `manifest` marker of a document (capture/v1 1.3.0, Python `manifest_marker`):
 * `last_sequence` is its `after_source_sequence`, `event_id` its own, and the manifest
 * travels as its manifest-span-v1 attributes.
 */
export function manifestMarker(document: Readonly<Record<string, JsonValue>>): MarkerEntry {
  return entry(document.source_id as string, BigInt(document.source_epoch as number | bigint), {
    kind: "manifest",
    last_sequence: document.after_source_sequence,
    manifest: manifestToSpan(document),
    event_id: document.event_id,
  });
}

/** A heartbeat (`periodic` or `final`) as its spool `marker` object carries it. */
export interface Heartbeat {
  readonly kind: "periodic" | "final";
  readonly sourceId: string;
  readonly epoch: bigint;
  readonly lastSequence: bigint;
  readonly manifestSeq: number | undefined;
  /** uuid4, minted once when the heartbeat was built and kept until it is delivered. */
  readonly eventId: string;
}

/** The `marker` object of a heartbeat (Python `marker_fields`; keys sorted as there). */
export function heartbeatFields(beat: Heartbeat): Record<string, unknown> {
  const fields: Record<string, unknown> = {
    kind: beat.kind,
    last_sequence: exact(beat.lastSequence),
  };
  if (beat.manifestSeq !== undefined) fields.manifest_seq = beat.manifestSeq;
  fields.event_id = beat.eventId;
  return fields;
}

/** The spool entry of a `final` heartbeat. */
export function finalMarker(beat: Heartbeat): MarkerEntry {
  if (beat.kind !== "final") throw new ManifestError("only a final heartbeat is spooled");
  return entry(beat.sourceId, beat.epoch, heartbeatFields(beat));
}

/**
 * `(span name, attributes)` of a marker from its spool form (Python `marker_span`): the
 * `fabric.capture_manifest` span of a manifest, or a `fabric.capture_heartbeat` with the
 * run-marker-v1 keys placed by kind (heartbeats, run markers, `segment_seal`;
 * `loss.ts`'s {@link heartbeatSpan}). `fabric.event_id` is the persisted one.
 */
export function markerSpan(
  sourceId: string,
  epoch: bigint,
  fields: Readonly<Record<string, unknown>>,
): [string, Record<string, unknown>] {
  const kind = fields.kind;
  if (kind === "manifest") {
    const attrs: Record<string, unknown> = { ...(fields.manifest as Record<string, unknown>) };
    if (fields.event_id !== undefined) attrs["fabric.event_id"] ??= fields.event_id;
    attrs["fabric.source_id"] ??= sourceId;
    attrs["fabric.source.epoch"] ??= exact(epoch);
    return [SPAN_MANIFEST, attrs];
  }
  try {
    return heartbeatSpan(sourceId, epoch, fields);
  } catch {
    throw new ManifestError("markerSpan reads marker objects of a known kind");
  }
}

// ------------------------------------------------------------------------- the chain

export interface ChainOptions {
  /** The `emitted_at` text of the next manifest (default: now, {@link emittedAt}). */
  readonly stamp?: () => string;
  /** A fresh uuid4 (tests pin it). */
  readonly newId?: () => string;
}

/**
 * One install's manifests (Python `_Chain`): the template, current point states and
 * uncaptured classes, and the manifest in force. Lives in the Fabric worker, which
 * spools what it returns. Every method returns the marker to spool, or `undefined` when
 * nothing changed, and never throws (a failure is counted in {@link internalErrors}).
 */
export class ManifestChain {
  readonly template: ManifestTemplate;
  states: Record<string, StateEntry>;
  uncaptured: string[];
  ref: ManifestRef | undefined;
  document: Record<string, JsonValue> | undefined;
  internalErrors = 0;
  readonly #stamp: () => string;
  readonly #newId: () => string;

  constructor(template: ManifestTemplate, options: ChainOptions = {}) {
    this.template = template;
    this.states = { ...template.initial };
    this.uncaptured = [...template.uncaptured];
    this.#stamp = options.stamp ?? (() => emittedAt(wallNs()));
    this.#newId = options.newId ?? randomUUID;
  }

  /** `manifest_seq` of the manifest in force for `epoch` (heartbeats carry it). */
  latestSeq(epoch: bigint): number | undefined {
    const ref = this.ref;
    return ref !== undefined && ref.epoch === epoch ? ref.manifestSeq : undefined;
  }

  #issue(
    at: Omit<ManifestPosition, "states" | "uncaptured" | "manifestId" | "eventId" | "emittedAt">,
  ): MarkerEntry {
    const document = assemble(this.template, {
      ...at,
      states: this.states,
      uncaptured: this.uncaptured,
      manifestId: this.#newId(),
      eventId: this.#newId(),
      emittedAt: this.#stamp(),
    });
    this.ref = {
      sourceId: this.template.sourceId,
      epoch: at.epoch,
      manifestSeq: at.seq,
      after: at.after,
      manifestId: document.manifest_id as string,
      digest: manifestDigest(document),
    };
    this.document = document;
    return manifestMarker(document);
  }

  /**
   * Manifest 0 of `epoch` (install, and the first allocation of a post-final epoch):
   * `after_source_sequence = -1`, before any position. `unsealed` is the registration
   * scan's declaration (manifest 0 of a registered epoch only). `undefined` when this
   * epoch already has one.
   */
  initial(
    epoch: bigint,
    unsealed: { readonly epochs: readonly bigint[]; readonly count: number } = {
      epochs: [],
      count: 0,
    },
  ): MarkerEntry | undefined {
    try {
      if (this.ref !== undefined && this.ref.epoch === epoch) return undefined;
      const prior = unsealedPrior(unsealed.epochs, unsealed.count, epoch);
      return this.#issue({
        epoch,
        seq: 0,
        after: -1n,
        previous: undefined,
        unsealed: prior.epochs,
        unsealedCount: prior.count,
      });
    } catch {
      this.internalErrors++;
      return undefined;
    }
  }

  #next(epoch: bigint, cut: bigint): MarkerEntry | undefined {
    const current = this.ref;
    if (current === undefined || current.epoch !== epoch) {
      // The epoch moved on before its manifest 0: that manifest 0 carries the change.
      return this.#issue({
        epoch,
        seq: 0,
        after: -1n,
        previous: undefined,
        unsealed: [],
        unsealedCount: 0,
      });
    }
    return this.#issue({
      epoch,
      seq: current.manifestSeq + 1,
      after: cut > current.after ? cut : current.after,
      previous: current.digest,
      unsealed: [],
      unsealedCount: 0,
    });
  }

  /**
   * A capture point changed state within the epoch (050 §3.8 "State change"): the next
   * chained manifest, effective after `cut`, the last position allocated when the change
   * took effect (`WireRuntime.cut`). No change, no manifest.
   */
  pointChanged(
    epoch: bigint,
    point: string,
    state: PointState,
    reason: string | undefined,
    cut: bigint,
  ): MarkerEntry | undefined {
    try {
      checkState(
        point,
        [state, reason],
        this.template.points.map((p) => p.id),
      );
      const before = this.states[point];
      if (
        before !== undefined &&
        before[0] === state &&
        before[1] === reason &&
        this.ref?.epoch === epoch
      ) {
        return undefined;
      }
      const previous = this.states;
      this.states = { ...previous, [point]: [state, reason] };
      try {
        return this.#next(epoch, cut);
      } catch (error) {
        // No manifest states the change: a later one must not carry it from a later cut.
        this.states = previous;
        throw error;
      }
    } catch {
      this.internalErrors++;
      return undefined;
    }
  }

  /**
   * A model-traffic class became uncaptured within the epoch: `node_worker_unattached`
   * when an application worker isolate did not attach (spec 055 §4.5, §7.2). The next
   * chained manifest declares it from `cut` on. Already declared: nothing.
   */
  classUncaptured(epoch: bigint, cls: string, cut: bigint): MarkerEntry | undefined {
    try {
      if (!CLASS_ORDER.includes(cls))
        throw new ManifestError("uncaptured class outside the vocabulary");
      if (this.uncaptured.includes(cls) && this.ref?.epoch === epoch) return undefined;
      const previous = this.uncaptured;
      this.uncaptured = withClass(previous, cls);
      try {
        return this.#next(epoch, cut);
      } catch (error) {
        this.uncaptured = previous; // as pointChanged
        throw error;
      }
    } catch {
      this.internalErrors++;
      return undefined;
    }
  }
}

// ---------------------------------------------------------------------- heartbeats

/**
 * Heartbeats (Python `LossEmitter.heartbeat`/`final`/`take`). A `periodic` heartbeat is
 * due every {@link HEARTBEAT_INTERVAL_MS} for a source that allocated since the last one;
 * it waits in {@link pending} for the sender's export path, keeping its event id until
 * {@link delivered} removes it (at most {@link MAX_PENDING_BEATS}; the oldest is dropped
 * and counted). A `final` heartbeat is built once, after orderly settled capture, and
 * spooled with its event id. Both carry the latest `manifest_seq`.
 */
export class Heartbeats {
  readonly #chain: ManifestChain;
  readonly #intervalMs: number;
  readonly #newId: () => string;
  readonly #nowMs: () => number;
  #lastPeriodicMs: number;
  #active = false;
  /** The `(epoch, last)` the previous tick saw: a later position means the source allocated. */
  #seenEpoch: bigint | undefined;
  #seenLast: bigint | undefined;
  #finals = new Set<bigint>();
  readonly pending: Heartbeat[] = [];
  dropped = 0;

  constructor(
    chain: ManifestChain,
    options: { intervalMs?: number; newId?: () => string; nowMs?: () => number } = {},
  ) {
    this.#chain = chain;
    this.#intervalMs = options.intervalMs ?? HEARTBEAT_INTERVAL_MS;
    this.#newId = options.newId ?? randomUUID;
    this.#nowMs = options.nowMs ?? (() => performance.now());
    this.#lastPeriodicMs = this.#nowMs();
  }

  /** The source allocated: it is eligible for the next periodic heartbeat. */
  noteActivity(): void {
    this.#active = true;
  }

  #beat(kind: Heartbeat["kind"], epoch: bigint, last: bigint): Heartbeat {
    return {
      kind,
      sourceId: this.#chain.template.sourceId,
      epoch,
      lastSequence: last,
      manifestSeq: this.#chain.latestSeq(epoch),
      eventId: this.#newId(),
    };
  }

  /**
   * The periodic tick (the Fabric worker's loop): when the interval passed and the
   * source allocated since the last heartbeat (or `every` is set: a flush), queue one at
   * `last`, the last allocated position. Returns it, or `undefined`.
   *
   * Eligibility follows allocation, as Python's `note_activity` (called at allocation)
   * does: a position allocated since the previous tick makes the source eligible even
   * when its exchange was lost and never spooled, so its gap is still bounded by a beat.
   */
  tick(epoch: bigint, last: bigint, every = false): Heartbeat | undefined {
    if (this.#seenEpoch !== epoch || (this.#seenLast !== undefined && last > this.#seenLast)) {
      if (this.#seenEpoch === epoch || last >= 0n) this.#active = true;
    }
    this.#seenEpoch = epoch;
    this.#seenLast = last;
    const now = this.#nowMs();
    if (!every && now - this.#lastPeriodicMs < this.#intervalMs) return undefined;
    this.#lastPeriodicMs = now;
    if (!every && !this.#active) return undefined;
    this.#active = false;
    const beat = this.#beat("periodic", epoch, last);
    this.pending.push(beat);
    while (this.pending.length > MAX_PENDING_BEATS) {
      this.pending.shift();
      this.dropped++;
    }
    return beat;
  }

  /** The sender exported the first `count` pending heartbeats. */
  delivered(count: number): void {
    this.pending.splice(0, Math.max(0, Math.min(count, this.pending.length)));
  }

  /**
   * The `final` heartbeat of `epoch` at `last` (orderly close, after every position is
   * settled), as a spool entry; `undefined` when this epoch already has one. Not a
   * substitute for segment seals.
   */
  final(epoch: bigint, last: bigint): MarkerEntry | undefined {
    if (this.#finals.has(epoch)) return undefined;
    this.#finals.add(epoch);
    return finalMarker(this.#beat("final", epoch, last));
  }
}

// ------------------------------------------------------------------- spooling markers

/** A marker's charge against {@link MAX_HELD_MARKER_BYTES} (Python `marker_bytes`). */
function markerBytes(marker: MarkerEntry): number {
  const fields = (marker.doc.marker ?? {}) as Record<string, unknown>;
  const manifest = fields.manifest as Record<string, unknown> | undefined;
  return 768 + 128 * (manifest === undefined ? 0 : Object.keys(manifest).length);
}

/**
 * Markers waiting for the spool (Python `Sender._held` + `_write_docs`): written in
 * order, up to 64 to a batch file (`spool.ts` `writePrefix`), into the spool's reserve.
 * What is spooled is always a prefix: after a refused or failed record nothing later is
 * written in this pump, so a `final` never overtakes an earlier manifest. Bounded; a
 * marker past the bound is dropped and counted (its epoch is then unverified).
 */
export class MarkerQueue {
  readonly held: MarkerEntry[] = [];
  #bytes = 0;
  dropped = 0;
  spooled = 0;

  queue(marker: MarkerEntry | undefined): boolean {
    if (marker === undefined) return false;
    const size = markerBytes(marker);
    if (this.held.length >= MAX_HELD_MARKERS || this.#bytes + size > MAX_HELD_MARKER_BYTES) {
      this.dropped++;
      return false;
    }
    this.held.push(marker);
    this.#bytes += size;
    return true;
  }

  /**
   * Writes the held markers in order; returns how many were spooled now. With `until`,
   * stops before the first held marker it accepts (that marker and the rest stay held).
   */
  pump(spool: Pick<Spool, "writeBatch">, until?: (marker: MarkerEntry) => boolean): number {
    let take = 0;
    while (take < this.held.length && until?.(this.held[take]!) !== true) take++;
    let written: number;
    try {
      written = writePrefix(spool, this.held.slice(0, take));
    } catch {
      written = 0;
    }
    for (const marker of this.held.splice(0, written)) this.#bytes -= markerBytes(marker);
    this.spooled += written;
    return written;
  }
}
