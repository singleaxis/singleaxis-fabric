// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Spec 050's P1 contract rules as pure functions (spec 055 §4.3, unit 055-t2): the record
 * and seal digests (050 §3.7), the manifest digest and span form (049 §2.4, §2.8), the
 * span category (rule N), the registry key checks and the records projection (rule A),
 * the `fr3/`/`fr2/` resume-token grammar and run identity rules 1-5 (050 §3.6).
 *
 * Each function is a port of `scripts/contracts/p1_reference.py` (and the coverage
 * validator's `check_value`, `manifest_to_span`), and passes every case of the shared
 * vectors in `contracts/coverage/v1/fixtures/vectors/` byte for byte. No I/O, no state;
 * the seal accumulator, the run table and the records input of later units call these.
 */

import { createHash, createHmac } from "node:crypto";

import {
  INT64_MAX,
  INT64_MIN,
  PyFloat,
  canonicalBytes,
  encodeJson,
  sha256Prefixed,
} from "./codec.js";
import { utf8SurrogatePass } from "../identity.js";
import {
  BRANCH_ID_RE,
  MINTED_RUN_ID_RE,
  OPAQUE_ID_RE,
  RECEIVER_OWNED_KEYS,
  type IdBasis,
} from "./p1-types.js";
import { CAPTURE_POINT_KINDS, TELEMETRY_KEYS } from "./telemetry-keys.generated.js";
import type { KeyCheck, KeyCheckCommon, TelemetryKeyRow } from "./types.js";

/** A record attribute value: a string, bool, integer, float or a list of them. */
export type AttributeValue = unknown;

// ----------------------------------------------------------------- record and seal digests

/** One content descriptor's fields the digest reads. */
export interface DigestDescriptor {
  readonly object_id?: string;
  readonly role?: string;
  readonly links?: unknown;
  readonly stored_sha256?: string;
}

/**
 * The `content` of a record digest (050 §3.7). `exchange`: the stored digests of the
 * request and response primaries (no `part_of`/`derived_from` link), in that order, when
 * present. `record`: the `stored_sha256` of each object of `fabric.content.object_ids`, in
 * list order, `null` for a descriptor-only object.
 */
export function recordContent(
  kind: "exchange" | "record",
  descriptors: readonly DigestDescriptor[],
  objectIds: readonly string[] = [],
): (string | null)[] {
  if (kind === "exchange") {
    const out: (string | null)[] = [];
    for (const role of ["model.exchange.request", "model.exchange.response"]) {
      for (const d of descriptors) {
        const links = d.links;
        const linked =
          links !== null && typeof links === "object"
            ? Object.keys(links).length > 0
            : Boolean(links);
        if (d.role === role && !linked && d.stored_sha256 !== undefined) {
          out.push(d.stored_sha256);
        }
      }
    }
    return out;
  }
  const byId = new Map(descriptors.map((d) => [d.object_id, d]));
  return objectIds.map((id) => {
    const found = byId.get(id);
    if (found === undefined) {
      throw new Error("a record's object id has no descriptor");
    }
    return found.stored_sha256 ?? null;
  });
}

function isFloat(value: unknown): boolean {
  return value instanceof PyFloat || (typeof value === "number" && !Number.isInteger(value));
}

function plainNumber(value: unknown): number {
  return value instanceof PyFloat ? value.value : (value as number);
}

function plain(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(plain);
  }
  if (isFloat(value)) {
    const number = value instanceof PyFloat ? value.value : (value as number);
    if (!Number.isFinite(number)) {
      throw new Error("a record attribute is never a non-finite float");
    }
    return { f64: encodeJson(new PyFloat(number)) };
  }
  if (value !== null && typeof value === "object") {
    throw new Error("a record attribute is never a map");
  }
  return value;
}

/** The parts of one record's span a digest covers. */
export interface DigestSpan {
  readonly name: string;
  readonly start_ns: number | bigint;
  readonly end_ns: number | bigint;
  readonly status: string;
  readonly attributes: Readonly<Record<string, AttributeValue>>;
}

/** The document a record digest hashes (receiver-owned keys excluded). */
export function recordDigestDocument(
  span: DigestSpan,
  content: readonly (string | null)[],
): Record<string, unknown> {
  if (!["unset", "ok", "error"].includes(span.status)) {
    throw new Error("status is unset, ok or error, never a description");
  }
  const attributes: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(span.attributes)) {
    if (!RECEIVER_OWNED_KEYS.has(key)) {
      attributes[key] = plain(value);
    }
  }
  return {
    name: span.name,
    start_ns: span.start_ns,
    end_ns: span.end_ns,
    status: span.status,
    attributes,
    content: [...content],
  };
}

/** `sha256:` of the canonical JSON of `{name, start_ns, end_ns, status, attributes, content}`. */
export function recordDigest(span: DigestSpan, content: readonly (string | null)[]): string {
  return sha256Prefixed(canonicalBytes(recordDigestDocument(span, content)));
}

/** One segment-attributed loss range. */
export interface LossRange {
  readonly reason: string;
  readonly count: number | bigint;
  readonly first_sequence: number | bigint;
  readonly last_sequence: number | bigint;
  readonly segment_id?: string;
}

/** `[p, "loss:<reason>"]` for every position of an exact (segment-attributed) range. */
export function lossEntries(loss: LossRange): [bigint, string][] {
  const first = BigInt(loss.first_sequence);
  const last = BigInt(loss.last_sequence);
  if (BigInt(loss.count) !== last - first + 1n) {
    throw new Error("a segment-attributed loss range is exact");
  }
  const out: [bigint, string][] = [];
  for (let p = first; p <= last; p += 1n) {
    out.push([p, `loss:${loss.reason}`]);
  }
  return out;
}

/** One segment's seal members: its records and the positions of losses naming it. */
export function sealEntries(
  records: Iterable<readonly [number | bigint, string]>,
  losses: Iterable<LossRange>,
  segmentId: string,
): [bigint, string][] {
  const entries: [bigint, string][] = [];
  for (const [sequence, digest] of records) {
    entries.push([BigInt(sequence), digest]);
  }
  for (const loss of losses) {
    if (loss.segment_id === segmentId) {
      entries.push(...lossEntries(loss));
    }
  }
  return entries;
}

/** `sha256:` over the canonical JSON of `[sequence, entry]` pairs sorted by sequence. */
export function sealDigest(entries: Iterable<readonly [number | bigint, string]>): string {
  const pairs = [...entries].map(([seq, entry]) => [BigInt(seq), entry] as [bigint, string]);
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  for (let i = 1; i < pairs.length; i++) {
    if (pairs[i]![0] === pairs[i - 1]![0]) {
      throw new Error("one entry per sequence");
    }
  }
  return sha256Prefixed(canonicalBytes(pairs));
}

/** The canonical digest of a capture manifest (049 §2.4: `previous_manifest_sha256`). */
export function manifestDigest(manifest: unknown): string {
  return sha256Prefixed(encodeJson(manifest));
}

// ----------------------------------------------------------------- span category (rule N)

const TOOL_KEYS = ["fabric.tool.name", "gen_ai.tool.name", "fabric.tool.result_hash"];
const MODEL_KEYS = ["fabric.llm.system", "gen_ai.request.model", "fabric.wire.exchange_id"];
const ORDERED: readonly (readonly [string, string])[] = [
  ["fabric.retrieval.source", "fabric.retrieval"],
  ["fabric.memory.kind", "fabric.memory"],
  ["fabric.side_effect.type", "fabric.side_effect"],
  ["fabric.interaction.kind", "fabric.interaction"],
  ["fabric.file.operation", "fabric.file_access"],
  ["fabric.delegation.protocol", "fabric.delegation"],
  ["fabric.checkpoint.checkpoint_id", "fabric.checkpoint"],
  ["fabric.replay.execution_id", "fabric.replay"],
  ["fabric.mcp.server", "fabric.mcp.inventory"],
  ["fabric.skill.name", "fabric.skill"],
  ["fabric.hook.phase", "fabric.hook"],
  ["fabric.coverage.kind", "fabric.coverage"],
  ["fabric.execution.status", "fabric.execution"],
  ["fabric.execution_id", "fabric.execution"],
  ["fabric.decision_id", "fabric.decision"],
];
const KNOWN_NAMES: ReadonlySet<string> = new Set([
  "fabric.execution",
  "fabric.decision",
  "fabric.llm_call",
  "fabric.model_call",
  "fabric.tool_call",
  "fabric.retrieval",
  "fabric.memory",
  "fabric.side_effect",
  "fabric.interaction",
  "fabric.file_access",
  "fabric.delegation",
  "fabric.error",
  "fabric.retry",
  "fabric.cancellation",
  "fabric.deployment_change",
  "fabric.human_action",
  "fabric.checkpoint",
  "fabric.replay",
  "fabric.mcp.inventory",
  "fabric.skill",
  "fabric.hook",
  "fabric.coverage",
  "fabric.capture_loss",
  "fabric.capture_heartbeat",
  "fabric.capture_manifest",
]);

/** fabricguard's `activityCategory`: a record's span name, by attribute keys first. */
export function spanCategory(nameHint: string, attributeKeys: Iterable<string>): string {
  const keys = new Set(attributeKeys);
  if (keys.has("fabric.heartbeat.last_sequence")) return "fabric.capture_heartbeat";
  if (keys.has("fabric.loss.reason")) return "fabric.capture_loss";
  if (keys.has("fabric.sensor.event_class")) return "fabric.sensor_event";
  if (TOOL_KEYS.some((k) => keys.has(k))) return "fabric.tool_call";
  if (MODEL_KEYS.some((k) => keys.has(k))) return "fabric.model_call";
  for (const [key, category] of ORDERED) {
    if (keys.has(key)) return category;
  }
  return KNOWN_NAMES.has(nameHint) ? nameHint : "fabric.activity";
}

// ----------------------------------------------------------------- key checks

const PATTERNS = new Map<string, RegExp>();

function compiled(pattern: string): RegExp {
  let re = PATTERNS.get(pattern);
  if (re === undefined) {
    // Python's `re.fullmatch`, by code point (`u`). Every pattern comes from the generated
    // telemetry-key registry, never from captured input.
    // nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
    re = new RegExp(`^(?:${pattern})$`, "u");
    PATTERNS.set(pattern, re);
  }
  return re;
}

function fullmatch(pattern: string, value: string): RegExpExecArray | null {
  return compiled(pattern).exec(value);
}

/** An exact integer: a `bigint`, or a `number` that is a safe integer (never a rounded one). */
function isIntValue(value: unknown): value is number | bigint {
  return typeof value === "bigint" || (typeof value === "number" && Number.isSafeInteger(value));
}

const RFC3339 =
  /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]{1,9})?(Z|[+-]([0-9]{2}):([0-9]{2}))$/;

/** The coverage validator's `_rfc3339`: the pattern, and a real date and time. */
export function isRfc3339(value: string): boolean {
  const m = RFC3339.exec(value);
  if (m === null) return false;
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number) as number[];
  const leap = year! % 4 === 0 && (year! % 100 !== 0 || year! % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month! - 1];
  const zone = m[8] === "Z" || (Number(m[9]) <= 23 && Number(m[10]) <= 59);
  return (
    year! >= 1 &&
    days !== undefined &&
    day! >= 1 &&
    day! <= days &&
    hour! <= 23 &&
    minute! <= 59 &&
    second! <= 59 &&
    zone
  );
}

export interface CheckModes {
  /** The Node's `capture_labels`. */
  readonly labels?: "pseudonymous" | "clear";
  /** The Node's `identity_mode`. */
  readonly identity?: "pseudonymous" | "clear";
}

/** Whether a telemetry value passes a registry check (fabricguard's admission). */
export function checkValue(
  check: KeyCheck & KeyCheckCommon,
  value: unknown,
  modes: CheckModes = {},
): boolean {
  const labels = modes.labels ?? "clear";
  const identity = modes.identity ?? "pseudonymous";
  if (identity === "clear" && check.identity_mode?.clear === "existing") {
    return typeof value === "string";
  }
  switch (check.type) {
    case "never":
      return false;
    case "enum":
      return typeof value === "string" && check.values.includes(value);
    case "const": {
      const want = check.value;
      if (typeof want === "number" && Number.isInteger(want)) {
        return isIntValue(value) && BigInt(value) === BigInt(want);
      }
      if (typeof want === "number") return isFloat(value) && Number(plainNumber(value)) === want;
      return typeof value === typeof want && value === want;
    }
    case "bool":
      return typeof value === "boolean";
    case "int": {
      if (!isIntValue(value)) return false;
      const v = BigInt(value);
      const max = check.max === undefined ? INT64_MAX : BigInt(check.max);
      return v >= INT64_MIN && v <= INT64_MAX && v >= BigInt(check.min) && v <= max;
    }
    case "number": {
      let v: number;
      if (value instanceof PyFloat) v = value.value;
      else if (typeof value === "number") v = value;
      else if (typeof value === "bigint") v = Number(value);
      else return false;
      return Number.isFinite(v) && v >= check.min && v <= (check.max ?? Infinity);
    }
    case "datetime":
      return typeof value === "string" && isRfc3339(value);
    case "string": {
      if (typeof value !== "string") return false;
      const match = fullmatch(check.pattern, value);
      if (match === null) return false;
      for (const group of check.int64_groups ?? []) {
        const text = match.groups?.[group];
        if (text !== undefined && BigInt(text) > INT64_MAX) return false;
      }
      const rule = check.capture_labels;
      if (rule !== undefined && labels === "pseudonymous") {
        const subject = rule.group !== undefined ? match.groups?.[rule.group] : value;
        if (subject !== undefined) {
          return fullmatch(rule.pseudonymous_pattern, subject) !== null;
        }
      }
      return true;
    }
    case "array": {
      if (!Array.isArray(value)) return false;
      if (value.length < (check.min_items ?? 0) || value.length > check.max_items) return false;
      if (check.unique === true) {
        const seen = new Set(value.map((item) => encodeJson(item, { asciiOnly: true })));
        if (seen.size !== value.length) return false;
      }
      return value.every((item) => checkValue(check.items, item, { labels }));
    }
    default:
      return false;
  }
}

/** The records class (rule A): every key placed on `record`, with its admission check. */
export function recordChecks(
  rows: Readonly<Record<string, TelemetryKeyRow>> = TELEMETRY_KEYS,
): Map<string, KeyCheck & KeyCheckCommon> {
  const out = new Map<string, KeyCheck & KeyCheckCommon>();
  for (const key of Object.keys(rows).sort()) {
    const row = rows[key]!;
    const check = row.capture_check ?? row.check;
    if (row.placement?.includes("record") === true && check !== undefined) {
      out.set(key, check);
    }
  }
  return out;
}

/** Conditional records placements (050 §3.4 rule A, F1). */
export function recordConditions(
  rows: Readonly<Record<string, TelemetryKeyRow>> = TELEMETRY_KEYS,
): Map<string, { capture_points?: readonly string[]; capture_point_kinds?: readonly string[] }> {
  const out = new Map<
    string,
    { capture_points?: readonly string[]; capture_point_kinds?: readonly string[] }
  >();
  for (const key of Object.keys(rows).sort()) {
    const row = rows[key]!;
    if (row.placement?.includes("record") !== true) continue;
    const cond: { capture_points?: readonly string[]; capture_point_kinds?: readonly string[] } =
      {};
    if (row.capture_points !== undefined) cond.capture_points = row.capture_points;
    if (row.capture_point_kinds !== undefined) cond.capture_point_kinds = row.capture_point_kinds;
    if (Object.keys(cond).length > 0) out.set(key, cond);
  }
  return out;
}

function conditionHolds(
  condition:
    { capture_points?: readonly string[]; capture_point_kinds?: readonly string[] } | undefined,
  capturePoint: string | undefined,
  pointKinds: Readonly<Record<string, readonly string[]>>,
): boolean {
  if (condition === undefined) return true;
  const point = (capturePoint ?? "").split("@", 1)[0] ?? "";
  const kinds = new Set(pointKinds[point] ?? []);
  if (condition.capture_points !== undefined && !condition.capture_points.includes(point)) {
    return false;
  }
  return (
    condition.capture_point_kinds === undefined ||
    condition.capture_point_kinds.some((kind) => kinds.has(kind))
  );
}

function structured(value: unknown): boolean {
  return (
    isFloat(value) ||
    value instanceof Uint8Array ||
    (value !== null && typeof value === "object" && !Array.isArray(value))
  );
}

/**
 * Rule A (050 §3.4): keep exactly the records-class keys whose value passes the key's
 * check; drop everything else (unknown keys, failing values, floats, maps, bytes). A value
 * is never hashed or truncated. Returns `[kept, dropped keys sorted]`.
 */
export function projectRecordAttributes(
  attributes: Readonly<Record<string, unknown>>,
  modes: CheckModes = {},
  rows: Readonly<Record<string, TelemetryKeyRow>> = TELEMETRY_KEYS,
  pointKinds: Readonly<Record<string, readonly string[]>> = CAPTURE_POINT_KINDS,
): [Record<string, unknown>, string[]] {
  const table = recordChecks(rows);
  const conditions = recordConditions(rows);
  const kept: Record<string, unknown> = {};
  const dropped: string[] = [];
  const point = attributes["fabric.capture.point"];
  for (const [key, value] of Object.entries(attributes)) {
    const check = table.get(key);
    const ok =
      check !== undefined &&
      conditionHolds(
        conditions.get(key),
        typeof point === "string" ? point : undefined,
        pointKinds,
      ) &&
      !structured(value) &&
      !(Array.isArray(value) && value.some((v) => structured(v) || Array.isArray(v))) &&
      checkValue(check, value, {
        labels: modes.labels ?? "pseudonymous",
        identity: modes.identity ?? "pseudonymous",
      });
    if (ok) kept[key] = value;
    else dropped.push(key);
  }
  return [kept, dropped.sort()];
}

// ----------------------------------------------------------------- manifest span form

function manifestKeyRows(rows: Readonly<Record<string, TelemetryKeyRow>>): [string, string][] {
  const out: [string, string][] = [];
  for (const [key, row] of Object.entries(rows)) {
    if (row.manifest_property !== undefined) out.push([row.manifest_property, key]);
  }
  return out;
}

function getPath(document: unknown, path: string): unknown {
  let node: unknown = document;
  for (const part of path.split("/")) {
    if (
      node === null ||
      typeof node !== "object" ||
      Array.isArray(node) ||
      !Object.hasOwn(node, part)
    ) {
      return undefined;
    }
    // Read-only walk over own properties; `path` is a registry manifest property.
    // nosemgrep: javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop
    node = (node as Record<string, unknown>)[part];
  }
  return node;
}

interface ManifestPoint {
  readonly id: string;
  readonly version: string;
  readonly kind: string;
  readonly state: string;
  readonly process_global: boolean;
  readonly opt_in: boolean;
  readonly reason?: string;
  readonly fields: readonly string[];
}

/** The closed attributes of the `fabric.capture_manifest` span (049 §2.8). */
export function manifestToSpan(
  manifest: Readonly<Record<string, unknown>>,
  rows: Readonly<Record<string, TelemetryKeyRow>> = TELEMETRY_KEYS,
): Record<string, unknown> {
  const points = (manifest["capture_points"] ?? []) as readonly ManifestPoint[];
  const attributes: Record<string, unknown> = {};
  for (const [prop, key] of manifestKeyRows(rows)) {
    if (prop === "capture_points") {
      attributes[key] = points.map(
        (p) =>
          `${p.id}@${p.version}:${p.kind}:${p.state}:${Number(p.process_global)}` +
          `:${Number(p.opt_in)}:${p.reason ?? "-"}`,
      );
    } else if (prop === "capture_points/fields") {
      attributes[key] = points.map((p) => `${p.id}=${p.fields.join(",")}`);
    } else if (prop === "unsealed_prior_epochs") {
      attributes[key] = ((manifest[prop] ?? []) as readonly (number | bigint)[]).map(String);
    } else {
      const value = getPath(manifest, prop);
      if (value !== undefined && value !== null) attributes[key] = value;
    }
  }
  return attributes;
}

/** Inverse of {@link manifestToSpan}: the manifest a reader rebuilds. */
export function spanToManifest(
  attributes: Readonly<Record<string, unknown>>,
  rows: Readonly<Record<string, TelemetryKeyRow>> = TELEMETRY_KEYS,
): Record<string, unknown> {
  const keyRows = manifestKeyRows(rows);
  const keyOf = new Map(keyRows);
  const manifest: Record<string, unknown> = {};
  for (const [prop, key] of keyRows) {
    if (!(key in attributes) || prop === "capture_points" || prop === "capture_points/fields") {
      continue;
    }
    let value = attributes[key];
    if (prop === "unsealed_prior_epochs") {
      value = (value as readonly string[]).map((epoch) => BigInt(epoch));
    }
    const parts = prop.split("/");
    let node = manifest;
    for (const part of parts.slice(0, -1)) {
      // `parts` is a registry manifest property, never a span attribute name, so no
      // prototype key can reach this walk.
      node[part] ??= {};
      // nosemgrep: javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop
      node = node[part] as Record<string, unknown>;
    }
    node[parts[parts.length - 1]!] = value;
  }
  const fields = new Map<string, string>();
  for (const item of (attributes[keyOf.get("capture_points/fields")!] ?? []) as readonly string[]) {
    const at = item.indexOf("=");
    fields.set(item.slice(0, at), item.slice(at + 1));
  }
  const points: Record<string, unknown>[] = [];
  for (const item of (attributes[keyOf.get("capture_points")!] ?? []) as readonly string[]) {
    const parts = item.split(":");
    const [kind, state, processGlobal, optIn, reason] = parts.slice(-5);
    const head = parts.slice(0, -5).join(":");
    const at = head.indexOf("@");
    const id = head.slice(0, at);
    const point: Record<string, unknown> = {
      id,
      version: head.slice(at + 1),
      kind,
      state,
      process_global: processGlobal === "1",
      opt_in: optIn === "1",
      fields: (fields.get(id) ?? "").split(",").filter((f) => f !== ""),
    };
    if (reason !== "-") point.reason = reason;
    points.push(point);
  }
  manifest.capture_points = points;
  return manifest;
}

// ----------------------------------------------------------------- resume tokens

export const TOKEN_PREFIX = "fr3/";
export const LEGACY_TOKEN_PREFIX = "fr2/";

const ENTRY_RE =
  /^(seg-[0-9a-f]{32})\/([A-Za-z0-9][A-Za-z0-9._:-]{0,127})\/([1-9][0-9]{0,18})\/(-1|0|[1-9][0-9]{0,18})\/(sha256:[0-9a-f]{64})$/;

/** A parsed predecessor entry (049 X41). */
export interface PredecessorEntry {
  readonly segment_id: string;
  readonly source_id: string;
  readonly epoch: bigint;
  readonly last_sequence: bigint;
  readonly manifest_digest: string;
}

/** A parsed resume token: `fr3/` (with the run correlation id) or legacy `fr2/`. */
export interface ResumeToken extends PredecessorEntry {
  readonly version: 2 | 3;
  readonly correlation_id: string | null;
  readonly branch_id: string | null;
}

/** `<segment_id>/<source_id>/<epoch>/<last_sequence>/sha256:<hex>`, or `undefined`. */
export function parsePredecessor(entry: string): PredecessorEntry | undefined {
  const m = ENTRY_RE.exec(entry);
  if (m === null) return undefined;
  const epoch = BigInt(m[3]!);
  const last = BigInt(m[4]!);
  if (epoch > INT64_MAX || last > INT64_MAX) return undefined;
  return {
    segment_id: m[1]!,
    source_id: m[2]!,
    epoch,
    last_sequence: last,
    manifest_digest: m[5]!,
  };
}

function entryAndBranch(
  body: string,
): (PredecessorEntry & { branch_id: string | null }) | undefined {
  let branch: string | null = null;
  const at = body.lastIndexOf("/");
  const tail = body.slice(at + 1);
  if (BRANCH_ID_RE.test(tail)) {
    branch = tail;
    body = at < 0 ? "" : body.slice(0, at);
  }
  const parsed = parsePredecessor(body);
  return parsed === undefined ? undefined : { ...parsed, branch_id: branch };
}

/** `fr3/<correlation id>/<entry>[/br-<32 hex>]` or legacy `fr2/<entry>[/br-...]`; else undefined. */
export function parseToken(token: unknown): ResumeToken | undefined {
  if (typeof token !== "string") return undefined;
  if (token.startsWith(TOKEN_PREFIX)) {
    const rest = token.slice(TOKEN_PREFIX.length);
    const at = rest.indexOf("/");
    if (at < 0) return undefined;
    const correlation = rest.slice(0, at);
    if (!OPAQUE_ID_RE.test(correlation)) return undefined;
    const parsed = entryAndBranch(rest.slice(at + 1));
    return parsed === undefined
      ? undefined
      : { version: 3, correlation_id: correlation, ...parsed };
  }
  if (token.startsWith(LEGACY_TOKEN_PREFIX)) {
    const parsed = entryAndBranch(token.slice(LEGACY_TOKEN_PREFIX.length));
    return parsed === undefined ? undefined : { version: 2, correlation_id: null, ...parsed };
  }
  return undefined;
}

/** `<segment_id>/<source_id>/<epoch>/<last_sequence>/<manifest digest>` (049 X41). */
export function formatEntry(
  segmentId: string,
  sourceId: string,
  epoch: number | bigint,
  lastSequence: number | bigint,
  manifestDigest: string,
): string {
  return `${segmentId}/${sourceId}/${BigInt(epoch)}/${BigInt(lastSequence)}/${manifestDigest}`;
}

/**
 * An `fr3/` token; `undefined` when it cannot be issued (a correlation id outside the
 * opaque-id pattern: `api_misuse`; a malformed entry or branch id).
 */
export function formatToken(
  correlationId: string,
  entry: string,
  branchId?: string | null,
): string | undefined {
  if (!OPAQUE_ID_RE.test(correlationId) || parsePredecessor(entry) === undefined) return undefined;
  if (branchId !== undefined && branchId !== null && !BRANCH_ID_RE.test(branchId)) return undefined;
  return `${TOKEN_PREFIX}${correlationId}/${entry}` + (branchId ? `/${branchId}` : "");
}

/**
 * A carrier value's tokens as the reference splits them: comma-separated; a W3C
 * `baggage` value is percent-decoded first (undefined when that decoding fails).
 */
export function splitCarrier(value: string, carrier: "env" | "baggage"): string[] | undefined {
  if (carrier === "baggage") {
    const decoded = percentDecode(value);
    if (decoded === undefined) return undefined;
    value = decoded;
  }
  return value.split(",");
}

const UTF8_STRICT = new TextDecoder("utf-8", { fatal: true });

/**
 * Python's `urllib.parse.unquote(value, errors="strict")`: each `%XX` (two hex digits) is
 * a byte, runs of bytes decode as strict UTF-8 (undefined when they do not), and any other
 * `%` stays as it is (unlike `decodeURIComponent`, which throws).
 */
export function percentDecode(value: string): string | undefined {
  if (!value.includes("%")) return value;
  let out = "";
  let bytes: number[] = [];
  const flush = (): boolean => {
    if (bytes.length === 0) return true;
    try {
      out += UTF8_STRICT.decode(Uint8Array.from(bytes));
    } catch {
      return false;
    }
    bytes = [];
    return true;
  };
  for (let i = 0; i < value.length; i++) {
    if (value[i] === "%" && /^[0-9A-Fa-f]{2}$/.test(value.slice(i + 1, i + 3))) {
      bytes.push(parseInt(value.slice(i + 1, i + 3), 16));
      i += 2;
      continue;
    }
    if (!flush()) return undefined;
    out += value[i];
  }
  return flush() ? out : undefined;
}

/** The runtime's split: {@link splitCarrier}, items trimmed, empty items skipped. */
export function splitTokens(value: string, carrier: "env" | "baggage" = "env"): string[] {
  return (splitCarrier(value, carrier) ?? []).map((t) => t.trim()).filter((t) => t !== "");
}

// ----------------------------------------------------------------- run identity

/** A clear id as emitted: unchanged when opaque, else `h-` + 40 hex of its SHA-256. */
export function encodeOpaqueId(value: string): string {
  if (OPAQUE_ID_RE.test(value)) return value;
  return "h-" + createHash("sha256").update(utf8SurrogatePass(value)).digest("hex").slice(0, 40);
}

/** `r-` + 32 hex of HMAC-SHA256(key, value), or SHA-256 without a key (v1). */
export function runPseudonym(value: string, key: string | Uint8Array | undefined | null): string {
  const data = utf8SurrogatePass(value);
  const keyBytes = typeof key === "string" ? Buffer.from(key, "utf8") : key;
  const hex =
    keyBytes !== undefined && keyBytes !== null && keyBytes.length > 0
      ? createHmac("sha256", keyBytes).update(data).digest("hex")
      : createHash("sha256").update(data).digest("hex");
  return "r-" + hex.slice(0, 32);
}

export interface IdentityOptions {
  readonly identityMode?: "pseudonymous" | "clear";
  readonly key?: string | Uint8Array | null;
  /** The run id is an `EmittedId` of this process (passes through). */
  readonly runIdEmitted?: boolean;
}

/** The identity rule (R8) for a caller run id. */
export function mapRunId(value: string, options: IdentityOptions = {}): string {
  if (options.runIdEmitted === true) return value;
  if (options.identityMode === "clear") return encodeOpaqueId(value);
  return runPseudonym(value, options.key);
}

/** What rules 1-5 decide at segment open. */
export interface RunIdentity {
  readonly run_id: string;
  readonly id_basis: IdBasis;
  readonly predecessors: readonly string[];
  readonly branch_ids: readonly string[];
  readonly tokens_rejected: number;
}

function byUtf8(a: string, b: string): number {
  return Buffer.compare(utf8SurrogatePass(a), utf8SurrogatePass(b));
}

/**
 * Run identity at segment open (050 §3.6), the first rule that applies: (1) valid `fr3/`
 * tokens of one correlation id `c` → `c` (`token`); (2) differing ids and a run id → the
 * mapped run id (`caller_join`); (3) differing ids, no run id → the lowest by byte order
 * (`token_conflict`); (4) no valid `fr3/` token, a run id → the mapped run id (`caller`);
 * (5) neither → `minted`. Rules 4 and 5 report `legacy` when only `fr2/` tokens are valid.
 */
export function runIdentity(
  tokens: readonly string[],
  runId: string | null | undefined,
  minted: string,
  options: IdentityOptions = {},
): RunIdentity {
  if (!MINTED_RUN_ID_RE.test(minted)) {
    throw new Error("a minted correlation id is r- + 32 hex");
  }
  const parsed = tokens.map(parseToken).filter((p): p is ResumeToken => p !== undefined);
  const correlations = [
    ...new Set(parsed.filter((p) => p.version === 3).map((p) => p.correlation_id!)),
  ].sort(byUtf8);
  const hasRun = runId !== undefined && runId !== null;
  let runIdOut: string;
  let basis: IdBasis;
  if (correlations.length === 1) {
    [runIdOut, basis] = [correlations[0]!, "token"];
  } else if (correlations.length > 0 && hasRun) {
    [runIdOut, basis] = [mapRunId(runId, options), "caller_join"];
  } else if (correlations.length > 0) {
    [runIdOut, basis] = [correlations[0]!, "token_conflict"];
  } else if (hasRun) {
    [runIdOut, basis] = [mapRunId(runId, options), parsed.length > 0 ? "legacy" : "caller"];
  } else {
    [runIdOut, basis] = [minted, parsed.length > 0 ? "legacy" : "minted"];
  }
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
    run_id: runIdOut,
    id_basis: basis,
    predecessors: predecessors.length > 0 ? predecessors : ["none"],
    branch_ids: branches,
    tokens_rejected: tokens.length - parsed.length,
  };
}

/** `endRun`'s identity (050 §3.6): refused without a valid token or on a conflict. */
export function endRunIdentity(
  tokens: readonly string[],
  runId: string | null | undefined,
  minted: string,
  options: IdentityOptions = {},
):
  | ({ status: "ended" } & RunIdentity)
  | { status: "refused_no_token" | "refused_conflicting_tokens" } {
  const parsed = tokens.map(parseToken).filter((p): p is ResumeToken => p !== undefined);
  if (parsed.length === 0) return { status: "refused_no_token" };
  const correlations = new Set(parsed.filter((p) => p.version === 3).map((p) => p.correlation_id));
  if ((runId === undefined || runId === null) && correlations.size > 1) {
    return { status: "refused_conflicting_tokens" };
  }
  return {
    status: "ended",
    ...runIdentity(tokens, runId, minted, { ...options, runIdEmitted: false }),
  };
}
