// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The bytes of the wire spool (spec 055 §6.2), identical to Python's
 * `fabric/wire/_spool.py`, so a Python drainer reads a TypeScript spool and the reverse.
 *
 * ```text
 * record: FWSPOOL1 | u32be(header length) | canonical UTF-8 header | body blob
 *         | SHA256(all preceding bytes)
 * batch:  FWSPOOLB | u32be(count) | repeated(u64be(frame length) | frame)
 *         | SHA256(all preceding bytes)
 * sealed: FWSPENC1 | 12 ASCII bytes key_id | 12 random nonce bytes
 *         | AES-256-GCM(inner record or batch, aad), ciphertext then 16-byte tag
 * aad:    FWSPENC1 | key_id | UTF-8 original record basename
 * key_id: kid- + first 8 hex of HMAC-SHA256(key, "fabric-spool/v1/kid")
 * ```
 *
 * The header is `json.dumps(doc, sort_keys=True, separators=(",", ":"),
 * ensure_ascii=False)` ({@link encodeJsonBytes}); it never holds content. The reader's
 * structural check ({@link validHeader}) is a port of Python's `valid_header`, so the
 * two readers quarantine the same records. Nothing here performs I/O, logs, or puts a
 * value into an error message.
 */
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from "node:crypto";

import { type JsonValue, PyFloat, encodeJsonBytes, parseJson } from "./codec.js";
import {
  BRANCH_ID_RE,
  ID_BASES,
  MAX_BRANCHES,
  MAX_EXCHANGE_BODIES,
  MAX_RECORD_BODIES,
  MAX_RUN_LINKS,
  OPAQUE_ID_RE,
  RUN_OUTCOMES,
  SCOPE_STATUSES,
  SEGMENT_ID_RE,
  STOP_REASONS,
  UUID4_RE,
} from "./p1-types.js";

export const MAGIC = Buffer.from("FWSPOOL1", "latin1");
export const SCHEMA = "fabric.wire-spool-record/v1";
export const BATCH_MAGIC = Buffer.from("FWSPOOLB", "latin1");
/** The most records one batch file holds. */
export const MAX_BATCH = 4096;
export const ENVELOPE_MAGIC = Buffer.from("FWSPENC1", "latin1");
export const KID_LEN = 12;
export const NONCE_LEN = 12;
export const TAG_LEN = 16;
/** The spool key: exactly 32 bytes (AES-256-GCM). */
export const SPOOL_KEY_BYTES = 32;
const DIGEST_LEN = 32;

// ----------------------------------------------------------------------------- errors

/**
 * A record file that is not a valid record: bad magic, digest, header or body ranges,
 * or an envelope that does not authenticate (tampered, truncated or renamed). The
 * drainer quarantines it and counts a loss. `doc` is the header when it parsed; `docs`
 * every header that parsed (a batch file's), whose sequences are explained losses.
 */
export class CorruptRecordError extends Error {
  readonly doc: Record<string, JsonValue> | undefined;
  readonly docs: readonly Record<string, JsonValue>[];
  constructor(doc?: Record<string, JsonValue>, docs: readonly Record<string, JsonValue>[] = []) {
    super("corrupt spool record");
    this.name = "CorruptRecordError";
    this.doc = doc;
    this.docs = docs.length > 0 ? [...docs] : doc === undefined ? [] : [doc];
  }
}

/**
 * A record without the envelope, read by a spool that has a key (049 §7.8): never
 * delivered (it would be a downgrade to an unauthenticated frame); quarantined as corrupt.
 */
export class PlaintextRecordError extends CorruptRecordError {
  constructor(doc?: Record<string, JsonValue>) {
    super(doc);
    this.name = "PlaintextRecordError";
  }
}

/**
 * A record sealed under another key (or read with no key configured): never delivered or
 * quarantined by this process; it stays pending and charged for a drainer holding that key.
 */
export class UndecryptableRecordError extends Error {
  constructor() {
    super("spool record sealed under another key");
    this.name = "UndecryptableRecordError";
  }
}

/**
 * A record the writer refuses before writing (050 R6): an exchange with more than 260
 * bodies or a record with more than 8. Its position becomes an `internal_error` loss.
 */
export class OverBoundError extends Error {
  constructor() {
    super("spool record over its body bound");
    this.name = "OverBoundError";
  }
}

// ----------------------------------------------------------------------------- frames

/** A record header as decoded (exact integers; floats as {@link PyFloat}). */
export type SpoolDoc = Record<string, JsonValue>;

function sha256(pieces: readonly Uint8Array[]): Buffer {
  const hash = createHash("sha256");
  for (const piece of pieces) hash.update(piece);
  return hash.digest();
}

/**
 * The record's bytes as pieces (bodies are not copied); the last piece is the digest.
 * Python `frame(doc, bodies)`.
 */
export function frame(doc: unknown, bodies: readonly Uint8Array[] = []): Buffer[] {
  const header = encodeJsonBytes(doc);
  const head = Buffer.alloc(12);
  MAGIC.copy(head, 0);
  head.writeUInt32BE(header.length, 8);
  const pieces: Buffer[] = [head, header];
  for (const body of bodies) {
    pieces.push(
      Buffer.isBuffer(body) ? body : Buffer.from(body.buffer, body.byteOffset, body.byteLength),
    );
  }
  pieces.push(sha256(pieces));
  return pieces;
}

const UTF8 = new TextDecoder("utf-8", { fatal: true });

function isObject(value: unknown): value is Record<string, JsonValue> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !(value instanceof PyFloat)
  );
}

/** `{doc, blob}` of one `FWSPOOL1` frame, else {@link CorruptRecordError}. */
export function unframe(data: Uint8Array): { doc: SpoolDoc; blob: Buffer } {
  const bytes = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  if (bytes.length < 44 || !bytes.subarray(0, 8).equals(MAGIC)) throw new CorruptRecordError();
  const size = bytes.readUInt32BE(8);
  const end = bytes.length - DIGEST_LEN;
  let doc: unknown;
  if (12 + size <= end) {
    try {
      doc = parseJson(UTF8.decode(bytes.subarray(12, 12 + size)));
    } catch {
      doc = undefined;
    }
  }
  if (!isObject(doc)) throw new CorruptRecordError();
  const digest = sha256([bytes.subarray(0, end)]);
  if (!digest.equals(bytes.subarray(end)) || !validHeader(doc, end - 12 - size)) {
    throw new CorruptRecordError(doc);
  }
  return { doc, blob: bytes.subarray(12 + size, end) };
}

/** Several records' frames ({@link frame}) as one batch file's pieces. */
export function batchFrame(frames: readonly (readonly Buffer[])[]): Buffer[] {
  const head = Buffer.alloc(12);
  BATCH_MAGIC.copy(head, 0);
  head.writeUInt32BE(frames.length, 8);
  const pieces: Buffer[] = [head];
  for (const piecesOf of frames) {
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(piecesOf.reduce((sum, piece) => sum + piece.length, 0)));
    pieces.push(length, ...piecesOf);
  }
  pieces.push(sha256(pieces));
  return pieces;
}

/**
 * Every record of a record file (one frame, or a batch file), else
 * {@link CorruptRecordError} carrying the headers that did parse. Python `unframe_all`.
 */
export function unframeAll(data: Uint8Array): { doc: SpoolDoc; blob: Buffer }[] {
  const bytes = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  if (!bytes.subarray(0, 8).equals(BATCH_MAGIC) || bytes.length < 8) return [unframe(bytes)];
  const records: { doc: SpoolDoc; blob: Buffer }[] = [];
  const docs: SpoolDoc[] = [];
  const end = bytes.length - DIGEST_LEN;
  let count: number;
  let offset = 12;
  let intact: boolean;
  try {
    if (bytes.length < 12) throw new RangeError("short batch");
    count = bytes.readUInt32BE(8);
    while (offset < end && records.length < Math.min(count, MAX_BATCH)) {
      if (offset + 8 > bytes.length) throw new RangeError("short length");
      const size = bytes.readBigUInt64BE(offset);
      if (BigInt(offset) + 8n + size > BigInt(end)) break;
      const record = unframe(bytes.subarray(offset + 8, offset + 8 + Number(size)));
      records.push(record);
      docs.push(record.doc);
      offset += 8 + Number(size);
    }
    intact = end >= 0 && sha256([bytes.subarray(0, end)]).equals(bytes.subarray(end));
  } catch (error) {
    if (error instanceof CorruptRecordError && error.doc !== undefined) docs.push(error.doc);
    throw new CorruptRecordError(docs[0], docs);
  }
  if (!intact || offset !== end || records.length !== count || count < 1 || count > MAX_BATCH) {
    throw new CorruptRecordError(docs[0], docs);
  }
  return records;
}

// ---------------------------------------------------------------------------- envelope

/** `kid-` + the first 8 hex of HMAC-SHA256(key, "fabric-spool/v1/kid"); never the key. */
export function spoolKeyId(key: Uint8Array): string {
  return "kid-" + createHmac("sha256", key).update("fabric-spool/v1/kid").digest("hex").slice(0, 8);
}

function aad(keyId: string, name: string): Buffer {
  return Buffer.concat([ENVELOPE_MAGIC, Buffer.from(keyId, "ascii"), Buffer.from(name, "utf8")]);
}

/**
 * The envelope of record file `name` around its framed `pieces`:
 * `[FWSPENC1, key id, nonce, ciphertext | tag]`. The nonce is random per write; a fixed
 * one is for test vectors only.
 */
export function seal(
  name: string,
  pieces: readonly Uint8Array[],
  key: Uint8Array,
  keyId: string,
  nonce: Uint8Array = randomBytes(NONCE_LEN),
): Buffer[] {
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_LEN });
  cipher.setAAD(aad(keyId, name));
  const out: Buffer[] = [];
  for (const piece of pieces) out.push(cipher.update(piece));
  out.push(cipher.final(), cipher.getAuthTag());
  return [
    Buffer.from(ENVELOPE_MAGIC),
    Buffer.from(keyId, "ascii"),
    Buffer.from(nonce),
    Buffer.concat(out),
  ];
}

/**
 * The framed bytes of record file `name`, opened from its envelope with `key` (named
 * `keyId`); as is only when no key is configured. With a key, a record without the
 * envelope is {@link PlaintextRecordError}; an envelope that does not authenticate is
 * {@link CorruptRecordError}; one sealed under another key (or with no key configured)
 * is {@link UndecryptableRecordError}. Python `unseal`.
 */
export function unseal(
  data: Uint8Array,
  name: string,
  key: Uint8Array | undefined,
  keyId: string | undefined,
): Buffer {
  const bytes = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  const head = ENVELOPE_MAGIC.length;
  if (!(bytes.length >= head && bytes.subarray(0, head).equals(ENVELOPE_MAGIC))) {
    if (key === undefined) return bytes;
    let doc: SpoolDoc | undefined;
    try {
      doc = unframeAll(bytes)[0]?.doc;
    } catch {
      doc = undefined;
    }
    throw new PlaintextRecordError(doc);
  }
  const kid = bytes.subarray(head, head + KID_LEN);
  if (key === undefined || keyId === undefined || !kid.equals(Buffer.from(keyId, "ascii"))) {
    throw new UndecryptableRecordError();
  }
  if (bytes.length < head + KID_LEN + NONCE_LEN + TAG_LEN) throw new CorruptRecordError();
  const nonce = bytes.subarray(head + KID_LEN, head + KID_LEN + NONCE_LEN);
  const body = bytes.subarray(head + KID_LEN + NONCE_LEN);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_LEN });
    decipher.setAAD(aad(keyId, name));
    decipher.setAuthTag(body.subarray(body.length - TAG_LEN));
    return Buffer.concat([
      decipher.update(body.subarray(0, body.length - TAG_LEN)),
      decipher.final(),
    ]);
  } catch {
    throw new CorruptRecordError(); // tampered, truncated or renamed
  }
}

// ---------------------------------------------------------------------- record names

/** `<source_epoch:020d>-<pid:010d>-<order:012d>.rec`: name order is drain order. */
export function recordName(epoch: bigint | number, pid: number, order: number): string {
  return `${String(epoch).padStart(20, "0")}-${String(pid).padStart(10, "0")}-${String(order).padStart(12, "0")}.rec`;
}

// ------------------------------------------------------------------- header validation

/** Loss reasons a spool `loss` entry may carry. */
export const LOSS_REASONS: ReadonlySet<string> = new Set([
  "queue_full",
  "internal_error",
  "shutdown",
  "span_dropped",
  "uninstrumented_client",
  "disk_full",
]);
const LOSS_KEYS = new Set(["reason", "count", "first_sequence", "last_sequence", "segment_id"]);
const KEYS: Readonly<Record<string, readonly string[]>> = {
  exchange: ["service_name", "span", "bodies"],
  record: ["span"],
  loss: ["loss"],
  marker: ["marker"],
};
const OPTIONAL: Readonly<Record<string, readonly string[]>> = {
  record: ["service_name", "bodies"],
};
const COMMON = ["schema_version", "record_kind", "source", "order", "written_at_unix_nano"];
const DESCRIPTOR_ONLY = new Set(["not_captured", "unsupported"]);
const SPAN_KINDS = new Set(["internal", "client", "server", "producer", "consumer"]);
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const HEX16 = /^(?!0{16}$)[0-9a-f]{16}$/;
const HEX32 = /^(?!0{32}$)[0-9a-f]{32}$/;
const PREDECESSOR_RE =
  /^(none|seg-[0-9a-f]{32}\/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\/[1-9][0-9]{0,18}\/(-1|0|[1-9][0-9]{0,18})\/sha256:[0-9a-f]{64})$/;
const ROOT_ONLY = new Set(["session_id", "user_id", "parent_run_id", "resumed_from", "links"]);
const IDENTITY = new Set(["agent_id", "system_id", "deployment_id", "release_id", "environment"]);
const IDENTITY_VALUE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const ALL_FIELDS = [
  "run_id",
  "scope_id",
  "segment_id",
  "predecessors",
  "resumable",
  "open_deadline_s",
  "declared_branches",
  "branch_ids",
  "terminal",
  "seal",
  "manifest_id",
  "manifest_digest",
  "manifest_seq",
  "scope_status",
  "manifest",
  "event_id",
  "id_basis",
  ...ROOT_ONLY,
  "outcome",
  "stop_reason",
  "identity",
];
const without = (drop: readonly string[]): Set<string> =>
  new Set(ALL_FIELDS.filter((name) => !drop.includes(name)));
/** The marker fields each kind may carry (Python `_loss.MARKER_FIELDS`, `periodic` aside). */
const MARKER_FIELDS: Readonly<Record<string, ReadonlySet<string>>> = {
  run_start: without(["terminal", "seal", "scope_status", "manifest", "outcome", "stop_reason"]),
  run_end: without([
    "predecessors",
    "resumable",
    "open_deadline_s",
    "declared_branches",
    "branch_ids",
    "terminal",
    "seal",
    "manifest",
    "id_basis",
    ...ROOT_ONLY,
    "identity",
  ]),
  segment_seal: new Set([
    "run_id",
    "scope_id",
    "segment_id",
    "resumable",
    "terminal",
    "seal",
    "manifest_seq",
    "event_id",
  ]),
  final: new Set(["manifest_seq", "event_id"]),
  manifest: new Set(["manifest", "event_id"]),
};
const REQUIRED_MARKER: Readonly<Record<string, readonly string[]>> = {
  run_start: ["run_id", "scope_id"],
  run_end: ["run_id", "scope_id"],
  segment_seal: ["run_id", "segment_id", "terminal", "seal"],
  final: [],
  manifest: ["manifest"],
};

const own = (object: object, key: string): boolean =>
  Object.prototype.hasOwnProperty.call(object, key);

/** Python `type(value) is int and low <= value (<= high)`: never a bool or a float. */
function isInt(value: unknown, low: bigint = 0n, high?: bigint): boolean {
  let exact: bigint;
  if (typeof value === "bigint") exact = value;
  else if (typeof value === "number" && Number.isInteger(value)) exact = BigInt(value);
  else return false;
  return exact >= low && (high === undefined || exact <= high);
}

function exactInt(value: unknown): bigint {
  return typeof value === "bigint" ? value : BigInt(value as number);
}

/** A number as Python compares it (`True == 1`, `1.0 == 1`), else `undefined`. */
function numeric(value: unknown): number | bigint | undefined {
  if (typeof value === "boolean") return value ? 1n : 0n;
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return Number.isInteger(value) ? BigInt(value) : value;
  if (value instanceof PyFloat)
    return Number.isInteger(value.value) ? BigInt(value.value) : value.value;
  return undefined;
}

/** Python `==` over JSON values. */
function pyEquals(a: unknown, b: unknown): boolean {
  const x = numeric(a);
  const y = numeric(b);
  if (x !== undefined || y !== undefined) return x !== undefined && y !== undefined && x === y;
  if (Array.isArray(a) || Array.isArray(b)) {
    return (
      Array.isArray(a) &&
      Array.isArray(b) &&
      a.length === b.length &&
      a.every((item, index) => pyEquals(item, b[index]))
    );
  }
  if (isObject(a) && isObject(b)) {
    const keys = Object.keys(a);
    return (
      keys.length === Object.keys(b).length &&
      keys.every((key) => own(b, key) && pyEquals(a[key], b[key]))
    );
  }
  return a === b;
}

/** Python `len(str)`: code points. */
function codePoints(value: string): number {
  return Array.from(value).length;
}

function ids(value: unknown, pattern: RegExp, low: number, high: number): boolean {
  return (
    Array.isArray(value) &&
    value.length >= low &&
    value.length <= high &&
    value.every((item) => typeof item === "string" && pattern.test(item))
  );
}

const text = (value: unknown): boolean =>
  typeof value === "string" && codePoints(value) >= 1 && codePoints(value) <= 256;
const matches = (pattern: RegExp) => (value: unknown) =>
  typeof value === "string" && pattern.test(value);
const member = (set: ReadonlySet<string>) => (value: unknown) =>
  typeof value === "string" && set.has(value);
const isBool = (value: unknown): boolean => typeof value === "boolean";

const MARKER_CHECKS: Readonly<Record<string, (value: unknown) => boolean>> = {
  run_id: matches(OPAQUE_ID_RE),
  scope_id: (v) => typeof v === "string" && v.length > 0,
  segment_id: matches(SEGMENT_ID_RE),
  predecessors: (v) => ids(v, PREDECESSOR_RE, 1, MAX_BRANCHES),
  resumable: isBool,
  open_deadline_s: (v) => isInt(v, 60n, 31536000n),
  declared_branches: (v) => ids(v, SEGMENT_ID_RE, 0, MAX_BRANCHES),
  branch_ids: (v) => ids(v, BRANCH_ID_RE, 0, MAX_BRANCHES),
  terminal: isBool,
  manifest_id: matches(UUID4_RE),
  manifest_digest: matches(SHA256_RE),
  manifest_seq: (v) => isInt(v),
  scope_status: member(SCOPE_STATUSES),
  manifest: isObject,
  event_id: matches(UUID4_RE),
  id_basis: member(ID_BASES),
  session_id: text,
  user_id: text,
  parent_run_id: matches(OPAQUE_ID_RE),
  resumed_from: matches(OPAQUE_ID_RE),
  links: (v) => ids(v, OPAQUE_ID_RE, 0, MAX_RUN_LINKS),
  outcome: member(RUN_OUTCOMES),
  stop_reason: member(STOP_REASONS),
  identity: (v) =>
    isObject(v) &&
    Object.keys(v).length > 0 &&
    Object.keys(v).every((key) => IDENTITY.has(key)) &&
    Object.values(v).every((item) => typeof item === "string" && IDENTITY_VALUE.test(item)),
  seal: (v) => {
    if (!isObject(v) || !own(v, "last_sequence") || !own(v, "seal_digest")) return false;
    const allowed = new Set(["last_sequence", "manifest_digest", "seal_digest", "branch_ids"]);
    return (
      Object.keys(v).every((key) => allowed.has(key)) &&
      isInt(v.last_sequence, -1n) &&
      matches(SHA256_RE)(v.seal_digest) &&
      (!own(v, "manifest_digest") || matches(SHA256_RE)(v.manifest_digest)) &&
      (!own(v, "branch_ids") || ids(v.branch_ids, BRANCH_ID_RE, 0, MAX_BRANCHES))
    );
  },
};

function markerOk(marker: Record<string, JsonValue>): boolean {
  if (!own(marker, "kind") || !own(marker, "last_sequence")) return false;
  const kind = marker.kind;
  if (typeof kind !== "string" || !own(MARKER_FIELDS, kind)) return false;
  const allowed = MARKER_FIELDS[kind]!;
  if (!isInt(marker.last_sequence, -1n)) return false;
  const fields = Object.keys(marker).filter((key) => key !== "kind" && key !== "last_sequence");
  const root =
    !fields.some((name) => ROOT_ONLY.has(name)) || pyEquals(marker.predecessors, ["none"]);
  const ok =
    fields.every((name) => allowed.has(name)) &&
    root &&
    REQUIRED_MARKER[kind]!.every((name) => own(marker, name)) &&
    fields.every((name) => MARKER_CHECKS[name]!(marker[name]));
  return ok && (kind !== "manifest" || manifestOk(marker));
}

/** A manifest marker's `event_id` and position are its manifest's (spec 049 §2.8). */
function manifestOk(marker: Record<string, JsonValue>): boolean {
  const manifest = marker.manifest as Record<string, JsonValue>;
  const ownId = manifest["fabric.event_id"];
  if (
    own(marker, "event_id") &&
    ownId !== undefined &&
    ownId !== null &&
    !pyEquals(ownId, marker.event_id)
  ) {
    return false;
  }
  const after = manifest["fabric.manifest.after_source_sequence"];
  return after === undefined || after === null || pyEquals(after, marker.last_sequence);
}

/** Python `isinstance(value, (str, int))` or a finite float (a bool is an int). */
function scalar(value: unknown): boolean {
  if (typeof value === "string" || typeof value === "boolean" || typeof value === "bigint") {
    return true;
  }
  if (typeof value === "number") return Number.isFinite(value);
  return value instanceof PyFloat && Number.isFinite(value.value);
}

function attributeValue(value: unknown): boolean {
  return scalar(value) || (Array.isArray(value) && value.length <= 64 && value.every(scalar));
}

/** Python `list(value)` of an attribute value: a string's code points, else the list. */
function pyList(value: unknown): unknown[] | undefined {
  if (Array.isArray(value)) return value;
  if (typeof value === "string") return Array.from(value);
  return undefined;
}

function spanOk(doc: Record<string, JsonValue>, blobLength: number, kind: string): boolean {
  const span = doc.span;
  const source = doc.source as Record<string, JsonValue>;
  if (!isObject(span) || !own(span, "attributes") || !isObject(span.attributes)) return false;
  const attrs = span.attributes;
  const bodies = own(doc, "bodies") ? doc.bodies : [];
  const record = kind === "record";
  if (own(doc, "service_name") && typeof doc.service_name !== "string") return false;
  if (!Array.isArray(bodies)) return false;
  if (bodies.length > (record ? MAX_RECORD_BODIES : MAX_EXCHANGE_BODIES)) return false;
  let offset = 0n;
  for (const body of bodies) {
    if (
      !isObject(body) ||
      !own(body, "descriptor") ||
      !own(body, "offset") ||
      !own(body, "length")
    ) {
      return false;
    }
    const descriptor = body.descriptor;
    if (!isObject(descriptor)) return false;
    if (!pyEquals(body.offset, offset) || !isInt(body.length)) return false;
    const stored = own(descriptor, "stored_byte_length") ? descriptor.stored_byte_length : 0;
    if (!pyEquals(stored, body.length)) return false;
    const status = descriptor.status;
    // Python's `status in {...}` raises (False) for an unhashable list or object.
    if (status !== null && typeof status === "object" && !(status instanceof PyFloat)) {
      return false;
    }
    if (typeof status === "string" && DESCRIPTOR_ONLY.has(status)) {
      if (own(descriptor, "stored_byte_length") || own(descriptor, "stored_sha256")) return false;
    }
    offset += exactInt(body.length);
  }
  const parent = own(span, "parent_span_id") ? span.parent_span_id : "1".repeat(16);
  const ok =
    offset === BigInt(blobLength) &&
    matches(HEX32)(span.trace_id) &&
    matches(HEX16)(span.span_id) &&
    matches(HEX16)(parent) &&
    isInt(span.start_time_unix_nano) &&
    isInt(span.end_time_unix_nano) &&
    isInt(span.trace_flags) &&
    own(attrs, "fabric.source_id") &&
    pyEquals(attrs["fabric.source_id"], source.source_id) &&
    isInt(attrs["fabric.source.sequence"]);
  if (!ok || !own(span, "status")) return false;
  const input = own(attrs, "fabric.capture.input") ? attrs["fabric.capture.input"] : undefined;
  if (!record) {
    return (
      (span.status === "unset" || span.status === "error") &&
      (input === undefined ? true : pyEquals(input, "wire"))
    );
  }
  if (!own(span, "name")) return false;
  const objectIds = bodies.map((body) => {
    const descriptor = (body as Record<string, JsonValue>).descriptor as Record<string, JsonValue>;
    return own(descriptor, "object_id") ? descriptor.object_id : null;
  });
  const spanKind = own(span, "kind") ? span.kind : "internal";
  const listed = own(attrs, "fabric.content.object_ids") ? attrs["fabric.content.object_ids"] : [];
  const values = Object.values(attrs);
  if (!(
    (span.status === "unset" || span.status === "ok" || span.status === "error") &&
    typeof span.name === "string" &&
    typeof spanKind === "string" &&
    SPAN_KINDS.has(spanKind) &&
    pyEquals(input, "records") &&
    pyEquals(
      own(attrs, "fabric.source.epoch") ? attrs["fabric.source.epoch"] : null,
      source.source_epoch,
    ) &&
    matches(UUID4_RE)(attrs["fabric.event_id"]) &&
    matches(UUID4_RE)(attrs["fabric.attempt.uid"]) &&
    !own(attrs, "fabric.wire.exchange_id") &&
    !own(attrs, "fabric.source.authenticated") &&
    values.every(attributeValue)
  )) {
    return false;
  }
  if (objectIds.length === 0) return true;
  const list = pyList(listed);
  return list !== undefined && pyEquals(objectIds, list);
}

/**
 * Structural check of a decoded header (the reader's guard; the schema is normative).
 * Python `valid_header(doc, blob_length)`: the same documents pass and fail.
 */
export function validHeader(doc: unknown, blobLength: number): boolean {
  try {
    if (!isObject(doc) || !COMMON.every((key) => own(doc, key))) return false;
    const kind = doc.record_kind;
    const source = doc.source;
    if (typeof kind !== "string" || !own(KEYS, kind) || !isObject(source)) return false;
    const keys = Object.keys(doc).filter((key) => !COMMON.includes(key));
    const required = KEYS[kind]!;
    const optional = OPTIONAL[kind] ?? [];
    const ok =
      doc.schema_version === SCHEMA &&
      required.every((key) => keys.includes(key)) &&
      keys.every((key) => required.includes(key) || optional.includes(key)) &&
      own(source, "source_id") &&
      typeof source.source_id === "string" &&
      isInt(source.source_epoch) &&
      isInt(doc.order) &&
      isInt(doc.written_at_unix_nano);
    if (!ok) return false;
    if (kind === "loss") {
      const loss = doc.loss;
      if (!isObject(loss) || !Object.keys(loss).every((key) => LOSS_KEYS.has(key))) return false;
      const first = loss.first_sequence;
      return (
        typeof loss.reason === "string" &&
        LOSS_REASONS.has(loss.reason) &&
        isInt(loss.count, 1n) &&
        isInt(first) &&
        isInt(loss.last_sequence, exactInt(first)) &&
        (!own(loss, "segment_id") || matches(SEGMENT_ID_RE)(loss.segment_id))
      );
    }
    if (kind === "marker") return isObject(doc.marker) && markerOk(doc.marker);
    return spanOk(doc, blobLength, kind);
  } catch {
    return false;
  }
}

/** Whether `doc` has more bodies than its kind allows (260 exchange, 8 record). */
export function overBound(doc: unknown): boolean {
  if (!isObject(doc)) return false;
  const limit =
    doc.record_kind === "exchange"
      ? MAX_EXCHANGE_BODIES
      : doc.record_kind === "record"
        ? MAX_RECORD_BODIES
        : undefined;
  const bodies = doc.bodies;
  return limit !== undefined && Array.isArray(bodies) && bodies.length > limit;
}
