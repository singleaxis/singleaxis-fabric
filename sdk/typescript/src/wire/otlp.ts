// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * A pinned, dependency-free OTLP/HTTP protobuf encoder for Fabric's own delivery (spec
 * 055 §7.1): the `ExportTraceServiceRequest` of the spool's spans and the
 * `ExportLogsServiceRequest` of its content records, byte-equal to what the Python
 * sender sends for the same records (`opentelemetry-exporter-otlp-proto-common` 1.45's
 * `encode_spans`, and `wire/_content.py`'s `encode_content_records`).
 *
 * Pinned definitions: `opentelemetry-proto` v1 (`collector/trace/v1`, `collector/logs/v1`,
 * `trace/v1`, `logs/v1`, `common/v1`, `resource/v1`); the field numbers below are theirs.
 * Fields are written in field-number order and proto3 defaults are omitted, except inside
 * `AnyValue`'s `oneof` (always present) and a sub-message that was set (an empty status
 * or resource is still written), as Python's protobuf runtime does.
 *
 * Integers are exact: an int64 attribute is a `bigint` or a safe-integer `number`,
 * nanosecond times are `bigint`, and none is ever converted through a float. No global
 * OpenTelemetry provider is read, installed or replaced; nothing here does I/O.
 */
import { createHash } from "node:crypto";

import { INT64_MAX, INT64_MIN, PyFloat, pyFloatRepr } from "./codec.js";
import { lossAttributes, lossFromDoc, SPAN_LOSS } from "./loss.js";
import { markerSpan } from "./manifest.js";

/** The instrumentation scope name of Fabric's own loss, heartbeat and manifest spans. */
export const FABRIC_SDK_NAME_NODE = "singleaxis-fabric-node";
/** The scope of exchange spans (Python `InstrumentationScope("fabric.wire", ...)`). */
export const SCOPE_WIRE = "fabric.wire";
/** The scope of records-input spans. */
export const SCOPE_RECORDS = "fabric.records";
/** The media type of every Fabric OTLP request (Python's content client and exporter). */
export const OTLP_PROTOBUF = "application/x-protobuf";

const UINT64_MAX = (1n << 64n) - 1n;

/** A fixed-text encoding error; never carries the value. */
export class OtlpEncodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OtlpEncodeError";
  }
}

// ----------------------------------------------------------------- protobuf writer

const WIRE_VARINT = 0;
const WIRE_I64 = 1;
const WIRE_LEN = 2;
const WIRE_I32 = 5;

/** Appends protobuf fields to a list of buffers (no copy of a large `bytes` field). */
class Writer {
  readonly parts: Buffer[] = [];
  length = 0;

  #push(part: Buffer): void {
    this.parts.push(part);
    this.length += part.length;
  }

  #varint(value: bigint): void {
    const out: number[] = [];
    let rest = value;
    while (rest > 0x7fn) {
      out.push(Number(rest & 0x7fn) | 0x80);
      rest >>= 7n;
    }
    out.push(Number(rest));
    this.#push(Buffer.from(out));
  }

  #tag(field: number, wire: number): void {
    this.#varint(BigInt((field << 3) | wire));
  }

  /** An `int64`/`uint32`/enum varint; a negative int64 as its 64-bit two's complement. */
  varint(field: number, value: bigint, always = false): void {
    if (value === 0n && !always) return;
    this.#tag(field, WIRE_VARINT);
    this.#varint(BigInt.asUintN(64, value));
  }

  bool(field: number, value: boolean): void {
    this.#tag(field, WIRE_VARINT);
    this.#push(Buffer.from([value ? 1 : 0]));
  }

  fixed64(field: number, value: bigint): void {
    if (value === 0n) return;
    if (value < 0n || value > UINT64_MAX) throw new OtlpEncodeError("a fixed64 is out of range");
    const out = Buffer.alloc(8);
    out.writeBigUInt64LE(value);
    this.#tag(field, WIRE_I64);
    this.#push(out);
  }

  fixed32(field: number, value: number): void {
    if (value === 0) return;
    const out = Buffer.alloc(4);
    out.writeUInt32LE(value >>> 0);
    this.#tag(field, WIRE_I32);
    this.#push(out);
  }

  double(field: number, value: number): void {
    const out = Buffer.alloc(8);
    out.writeDoubleLE(value);
    this.#tag(field, WIRE_I64);
    this.#push(out);
  }

  bytes(field: number, value: Uint8Array, always = false): void {
    if (value.length === 0 && !always) return;
    this.#tag(field, WIRE_LEN);
    this.#varint(BigInt(value.length));
    if (value.length > 0) this.#push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
  }

  string(field: number, value: string, always = false): void {
    this.bytes(field, Buffer.from(value, "utf8"), always);
  }

  /** A set sub-message: written even when it is empty. */
  message(field: number, child: Writer): void {
    this.#tag(field, WIRE_LEN);
    this.#varint(BigInt(child.length));
    for (const part of child.parts) this.#push(part);
  }

  finish(): Buffer {
    return Buffer.concat(this.parts, this.length);
  }
}

// ----------------------------------------------------------------- AnyValue

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  !(value instanceof Uint8Array) &&
  !(value instanceof PyFloat);

function int64Of(value: unknown): bigint | undefined {
  if (typeof value === "bigint") {
    if (value < INT64_MIN || value > INT64_MAX)
      throw new OtlpEncodeError("an int64 is out of range");
    return value;
  }
  if (typeof value === "number" && Number.isInteger(value)) {
    if (!Number.isSafeInteger(value)) throw new OtlpEncodeError("an integer is not exact");
    return BigInt(value);
  }
  return undefined;
}

/**
 * An attribute's `AnyValue`, as OpenTelemetry Python's `_encode_value`: `null` is an
 * empty value, then bool, string, integer (`int_value`), float (`double_value`: a
 * {@link PyFloat} or a non-integral number), bytes, array, map. Throws for anything else.
 */
function attributeValue(value: unknown): Writer {
  const w = new Writer();
  if (value === null || value === undefined) return w;
  if (typeof value === "boolean") w.bool(2, value);
  else if (typeof value === "string") w.string(1, value, true);
  else if (value instanceof PyFloat) w.double(4, value.value);
  else if (typeof value === "number" && !Number.isInteger(value)) w.double(4, value);
  else if (int64Of(value) !== undefined) w.varint(3, int64Of(value)!, true);
  else if (value instanceof Uint8Array) w.bytes(7, value, true);
  else if (Array.isArray(value)) {
    const array = new Writer();
    for (const item of value) array.message(1, attributeValue(item));
    w.message(5, array);
  } else if (isRecord(value)) {
    const list = new Writer();
    for (const [key, item] of Object.entries(value))
      list.message(1, keyValue(key, attributeValue(item)));
    w.message(6, list);
  } else throw new OtlpEncodeError("an attribute value has an unsupported type");
  return w;
}

function keyValue(key: string, value: Writer): Writer {
  const kv = new Writer();
  kv.string(1, key);
  kv.message(2, value);
  return kv;
}

/**
 * The `KeyValue`s of `attributes` in insertion order; a key whose value cannot be
 * encoded is left out, as OpenTelemetry Python's `_encode_attributes` does.
 */
function attributeList(
  out: Writer,
  field: number,
  attributes: Readonly<Record<string, unknown>>,
): void {
  for (const [key, value] of Object.entries(attributes)) {
    let encoded: Writer;
    try {
      encoded = attributeValue(value);
    } catch {
      continue;
    }
    out.message(field, keyValue(key, encoded));
  }
}

// ----------------------------------------------------------------- traces

/** OTLP span kinds (`Span.SpanKind`). */
const SPAN_KINDS = { internal: 1n, server: 2n, client: 3n, producer: 4n, consumer: 5n } as const;
export type SpanKindName = keyof typeof SPAN_KINDS;
const STATUS_CODES = { unset: 0n, ok: 1n, error: 2n } as const;
export type SpanStatusName = keyof typeof STATUS_CODES;

/** `SPAN_FLAGS_CONTEXT_HAS_IS_REMOTE_MASK` and `SPAN_FLAGS_CONTEXT_IS_REMOTE_MASK`. */
const HAS_IS_REMOTE = 0x100;
const IS_REMOTE = 0x200;

/** One span to export: what the Python sender builds as a `ReadableSpan`. */
export interface OtlpSpan {
  readonly name: string;
  /** 32 lowercase hex digits. */
  readonly traceId: string;
  /** 16 lowercase hex digits. */
  readonly spanId: string;
  readonly parentSpanId?: string;
  readonly parentIsRemote?: boolean;
  readonly kind: SpanKindName;
  readonly startNs: bigint;
  readonly endNs: bigint;
  readonly attributes: Readonly<Record<string, unknown>>;
  readonly status: SpanStatusName;
  /** The resource's only attribute, `service.name`. */
  readonly serviceName: string;
  readonly scope: { readonly name: string; readonly version: string };
}

const HEX_ID: Readonly<Record<8 | 16, RegExp>> = { 8: /^[0-9a-f]{16}$/, 16: /^[0-9a-f]{32}$/ };

function hexId(value: string, bytes: 8 | 16): Buffer {
  if (!HEX_ID[bytes].test(value))
    throw new OtlpEncodeError("a trace or span id is not lowercase hex of the right length");
  return Buffer.from(value, "hex");
}

function spanMessage(span: OtlpSpan): Writer {
  const kind = SPAN_KINDS[span.kind];
  const status = STATUS_CODES[span.status];
  if (kind === undefined || status === undefined)
    throw new OtlpEncodeError("a span kind or status is outside the vocabulary");
  const w = new Writer();
  w.bytes(1, hexId(span.traceId, 16));
  w.bytes(2, hexId(span.spanId, 8));
  if (span.parentSpanId !== undefined) w.bytes(4, hexId(span.parentSpanId, 8));
  w.string(5, span.name);
  w.varint(6, kind);
  w.fixed64(7, span.startNs);
  w.fixed64(8, span.endNs);
  attributeList(w, 9, span.attributes);
  const statusMessage = new Writer();
  statusMessage.varint(3, status);
  w.message(15, statusMessage);
  const remote = span.parentSpanId !== undefined && span.parentIsRemote === true;
  w.fixed32(16, HAS_IS_REMOTE | (remote ? IS_REMOTE : 0));
  return w;
}

function resourceMessage(serviceName: string): Writer {
  const resource = new Writer();
  attributeList(resource, 1, { "service.name": serviceName });
  return resource;
}

/**
 * One `ExportTraceServiceRequest`: spans grouped by resource (`service.name`), then by
 * instrumentation scope, each group in first-seen order, spans in input order (Python
 * `encode_spans`). Throws {@link OtlpEncodeError} for a malformed id, kind or time.
 */
export function encodeTraceRequest(spans: readonly OtlpSpan[]): Buffer {
  const resources = new Map<string, Map<string, { scope: OtlpSpan["scope"]; spans: Writer[] }>>();
  for (const span of spans) {
    const encoded = spanMessage(span);
    let scopes = resources.get(span.serviceName);
    if (scopes === undefined) resources.set(span.serviceName, (scopes = new Map()));
    const key = `${span.scope.name}\u0000${span.scope.version}`;
    let group = scopes.get(key);
    if (group === undefined) scopes.set(key, (group = { scope: span.scope, spans: [] }));
    group.spans.push(encoded);
  }
  const request = new Writer();
  for (const [serviceName, scopes] of resources) {
    const resourceSpans = new Writer();
    resourceSpans.message(1, resourceMessage(serviceName));
    for (const { scope, spans: encoded } of scopes.values()) {
      const scopeSpans = new Writer();
      const scopeMessage = new Writer();
      scopeMessage.string(1, scope.name);
      scopeMessage.string(2, scope.version);
      scopeSpans.message(1, scopeMessage);
      for (const span of encoded) scopeSpans.message(2, span);
      resourceSpans.message(2, scopeSpans);
    }
    request.message(1, resourceSpans);
  }
  return request.finish();
}

// ----------------------------------------------------------------- spool record -> span

/** What the sender supplies beside a record (Python `Sender`'s service name and version). */
export interface SpanContextOptions {
  /** The capture `service.name` (loss, marker and a record without its own). */
  readonly serviceName: string;
  /** The capture point version (the SDK version). */
  readonly version: string;
  /** Scope name of loss/heartbeat/manifest spans (default {@link FABRIC_SDK_NAME_NODE}). */
  readonly sdkName?: string;
}

const PY_UNPRINTABLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]/u;

/** Python's `repr(str)`. */
function pyStrRepr(value: string): string {
  const quote = value.includes("'") && !value.includes('"') ? '"' : "'";
  let out = quote;
  for (const char of value) {
    const cp = char.codePointAt(0)!;
    if (char === quote || char === "\\") out += `\\${char}`;
    else if (char === "\t") out += "\\t";
    else if (char === "\n") out += "\\n";
    else if (char === "\r") out += "\\r";
    else if (cp < 0x20 || cp === 0x7f) out += `\\x${cp.toString(16).padStart(2, "0")}`;
    else if (cp < 0x7f || (char !== " " && !PY_UNPRINTABLE.test(char))) out += char;
    else if (cp <= 0xff) out += `\\x${cp.toString(16).padStart(2, "0")}`;
    else if (cp <= 0xffff) out += `\\u${cp.toString(16).padStart(4, "0")}`;
    else out += `\\U${cp.toString(16).padStart(8, "0")}`;
  }
  return out + quote;
}

/** Python's `repr` of a parsed JSON value (the root span seed formats the record's source). */
export function pyRepr(value: unknown): string {
  if (value === null || value === undefined) return "None";
  if (value === true) return "True";
  if (value === false) return "False";
  if (typeof value === "string") return pyStrRepr(value);
  if (typeof value === "bigint") return value.toString();
  if (value instanceof PyFloat) return pyFloatRepr(value.value);
  if (typeof value === "number")
    return Number.isInteger(value) ? String(value) : pyFloatRepr(value);
  if (Array.isArray(value)) return `[${value.map(pyRepr).join(", ")}]`;
  if (isRecord(value))
    return `{${Object.entries(value)
      .map(([k, v]) => `${pyStrRepr(k)}: ${pyRepr(v)}`)
      .join(", ")}}`;
  throw new OtlpEncodeError("a value has no Python representation");
}

const nanos = (value: unknown): bigint => {
  const exact = int64Of(value);
  if (exact === undefined) throw new OtlpEncodeError("a time is not an exact integer");
  return exact;
};

const listsToArrays = (attrs: Readonly<Record<string, unknown>>): Record<string, unknown> =>
  Object.fromEntries(Object.entries(attrs).map(([k, v]) => [k, Array.isArray(v) ? [...v] : v]));

/**
 * The span a spool record stands for, identical on every replay (Python
 * `Sender._span`): an `exchange` as its `fabric.model_call` client span, a `record` as
 * its own span, a `loss` as `fabric.capture_loss` and a `marker` as its heartbeat or
 * manifest span, whose ids derive from the record's source, order and write time.
 */
export function spanOfRecord(
  doc: Readonly<Record<string, unknown>>,
  options: SpanContextOptions,
): OtlpSpan {
  const source = doc.source as Readonly<Record<string, unknown>>;
  const at = nanos(doc.written_at_unix_nano);
  const kind = doc.record_kind;
  if (kind === "loss" || kind === "marker") {
    const seed = `${pyRepr(source)}:${pyRepr(doc.order)}:${at}`;
    const [name, attributes] =
      kind === "loss"
        ? [SPAN_LOSS, lossAttributes(lossFromDoc(doc))]
        : markerSpan(
            source.source_id as string,
            BigInt(source.source_epoch as number | bigint),
            doc.marker as Readonly<Record<string, unknown>>,
          );
    const digest = createHash("sha256").update(seed, "utf8").digest();
    const id = (bytes: Buffer): string =>
      bytes.every((b) => b === 0) ? `${"0".repeat(bytes.length * 2 - 1)}1` : bytes.toString("hex");
    return {
      name,
      traceId: id(digest.subarray(0, 16)),
      spanId: id(digest.subarray(16, 24)),
      kind: "internal",
      startNs: at,
      endNs: at,
      attributes: listsToArrays(attributes),
      status: "unset",
      serviceName: options.serviceName,
      scope: { name: options.sdkName ?? FABRIC_SDK_NAME_NODE, version: options.version },
    };
  }
  if (kind !== "exchange" && kind !== "record")
    throw new OtlpEncodeError("a spool record kind has no span");
  const span = doc.span as Readonly<Record<string, unknown>>;
  const exchange = kind === "exchange";
  const spanKind = exchange ? "client" : ((span.kind as string | undefined) ?? "internal");
  const status =
    span.status === "error" ? "error" : span.status === "ok" && !exchange ? "ok" : "unset";
  return {
    name: exchange ? "fabric.model_call" : (span.name as string),
    traceId: span.trace_id as string,
    spanId: span.span_id as string,
    ...("parent_span_id" in span
      ? {
          parentSpanId: span.parent_span_id as string,
          parentIsRemote: span.parent_is_remote === true,
        }
      : {}),
    kind: spanKind in SPAN_KINDS ? (spanKind as SpanKindName) : "internal",
    startNs: nanos(span.start_time_unix_nano),
    endNs: nanos(span.end_time_unix_nano),
    attributes: listsToArrays(span.attributes as Readonly<Record<string, unknown>>),
    status,
    serviceName:
      exchange || typeof doc.service_name === "string"
        ? (doc.service_name as string)
        : options.serviceName,
    scope: { name: exchange ? SCOPE_WIRE : SCOPE_RECORDS, version: options.version },
  };
}

// ----------------------------------------------------------------- content logs

const ISO_RE =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2})(?::(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?(?:(Z)|([+-])(\d{2}):?(\d{2})(?::?(\d{2})(?:\.(\d{1,6}))?)?)$/;
const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/**
 * `captured_at` as Unix nanoseconds at microsecond precision (Python's
 * `datetime.fromisoformat(captured_at) - epoch`, floored to microseconds, times 1000).
 * Throws for a time without a zone offset (Python cannot subtract a naive time) and for
 * any form Fabric's writers never produce.
 */
export function capturedAtNs(text: unknown): bigint {
  const match = typeof text === "string" ? ISO_RE.exec(text) : null;
  if (match === null) throw new OtlpEncodeError("captured_at is not an ISO 8601 time with a zone");
  const [, y, mo, d, h, mi = "0", s = "0", frac = "", z, sign, oh, om, os = "0", ofrac = ""] =
    match;
  const [year, month, day, hour, minute, second] = [y, mo, d, h, mi, s].map(Number) as [
    number, number, number, number, number, number,
  ]; // prettier-ignore
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const monthDays = (DAYS_IN_MONTH[month - 1] ?? 0) + (month === 2 && leap ? 1 : 0);
  if (year < 1 || day < 1 || day > monthDays || hour > 23 || minute > 59 || second > 59)
    throw new OtlpEncodeError("captured_at is not a valid time");
  const micros = BigInt((frac + "000000").slice(0, 6));
  let offset = 0n;
  if (z === undefined) {
    const offsetMicros =
      (BigInt(oh!) * 3600n + BigInt(om!) * 60n + BigInt(os)) * 1_000_000n +
      BigInt((ofrac + "000000").slice(0, 6));
    if (offsetMicros >= 86_400_000_000n)
      throw new OtlpEncodeError("captured_at has an invalid offset");
    offset = sign === "-" ? -offsetMicros : offsetMicros;
  }
  const local =
    ((daysFromCivil(year, month, day) * 24n + BigInt(hour)) * 60n + BigInt(minute)) * 60n +
    BigInt(second);
  return (local * 1_000_000n + micros - offset) * 1000n;
}

/** Days since 1970-01-01 of a proleptic Gregorian date (years below 100 included). */
function daysFromCivil(year: number, month: number, day: number): bigint {
  const y = BigInt(month <= 2 ? year - 1 : year);
  const era = (y >= 0n ? y : y - 399n) / 400n;
  const yoe = y - era * 400n;
  const m = BigInt(month);
  const doy = (153n * (m > 2n ? m - 3n : m + 9n) + 2n) / 5n + BigInt(day) - 1n;
  const doe = yoe * 365n + yoe / 4n - yoe / 100n + doy;
  return era * 146097n + doe - 719468n;
}

/**
 * A descriptor value as Python's `_content._value`: a map is a `kvlist_value`, an
 * integer an `int_value`, a string a `string_value`, a list an `array_value` whose maps
 * and integers keep their type and whose other members become strings. A boolean or a
 * float is refused (the closed descriptor schema has none).
 */
function descriptorValue(value: unknown): Writer {
  const w = new Writer();
  if (isRecord(value)) {
    const list = new Writer();
    for (const [key, item] of Object.entries(value))
      list.message(1, keyValue(key, descriptorValue(item)));
    w.message(6, list);
    return w;
  }
  if (typeof value === "boolean")
    throw new OtlpEncodeError("descriptor values are strings, integers, lists or maps");
  if (Array.isArray(value)) {
    const array = new Writer();
    for (const item of value) {
      if (isRecord(item) || typeof item === "boolean" || int64Of(item) !== undefined) {
        array.message(1, descriptorValue(item));
      } else {
        const text = new Writer();
        text.string(1, typeof item === "string" ? item : pyRepr(item), true);
        array.message(1, text);
      }
    }
    w.message(5, array);
    return w;
  }
  const integer = int64Of(value);
  if (integer !== undefined) w.varint(3, integer, true);
  else if (typeof value === "string") w.string(1, value, true);
  else throw new OtlpEncodeError("descriptor values are strings, integers, lists or maps");
  return w;
}

/** One content item: a body's descriptor (the closed attribute set) and its exact bytes. */
export interface ContentItem {
  readonly descriptor: Readonly<Record<string, unknown>>;
  readonly body: Uint8Array;
}

/**
 * One encoded content `LogRecord` (Python `_log_record`): `captured_at` as its time, the
 * exact bytes as `bytes_value`, `event_class=content` then the descriptor's attributes.
 * Throws {@link OtlpEncodeError} for a descriptor that cannot be encoded.
 */
export function encodeLogRecord(item: ContentItem): Buffer {
  const time = capturedAtNs(item.descriptor.captured_at);
  if (time < 0n || time > UINT64_MAX) throw new OtlpEncodeError("captured_at is out of range");
  const w = new Writer();
  w.fixed64(1, time);
  const body = new Writer();
  body.bytes(7, item.body, true);
  w.message(5, body);
  for (const [key, value] of Object.entries({ event_class: "content", ...item.descriptor }))
    w.message(6, keyValue(key, descriptorValue(value)));
  return w.finish();
}

/**
 * One `ExportLogsServiceRequest` (Python `encode_content_records`): resource
 * `service.name`, scope `fabric.wire`, the already-encoded records in order.
 */
export function encodeLogsRequest(records: readonly Uint8Array[], serviceName: string): Buffer {
  const resource = new Writer();
  const name = new Writer();
  name.string(1, serviceName, true);
  resource.message(1, keyValue("service.name", name));
  const scope = new Writer();
  scope.string(1, SCOPE_WIRE);
  const scopeLogs = new Writer();
  scopeLogs.message(1, scope);
  for (const record of records) scopeLogs.bytes(2, record, true);
  const resourceLogs = new Writer();
  resourceLogs.message(1, resource);
  resourceLogs.message(2, scopeLogs);
  const request = new Writer();
  request.message(1, resourceLogs);
  return request.finish();
}

// ----------------------------------------------------------------- responses

/** Reads one varint at `at`; `undefined` past the end or beyond 10 bytes. */
function readVarint(buf: Uint8Array, at: number): [bigint, number] | undefined {
  let value = 0n;
  for (let i = 0; i < 10; i++) {
    if (at + i >= buf.length) return undefined;
    const byte = buf[at + i]!;
    value |= BigInt(byte & 0x7f) << BigInt(7 * i);
    if ((byte & 0x80) === 0) return [value, at + i + 1];
  }
  return undefined;
}

const WIRE_START_GROUP = 3;
const WIRE_END_GROUP = 4;
/** Python's protobuf runtime refuses groups nested deeper than its recursion limit. */
const MAX_GROUP_DEPTH = 100;

/**
 * The fields of one message, as Python's protobuf runtime parses it; `undefined` when
 * malformed. A group (wire types 3/4, never used by OTLP) is skipped as an unknown field,
 * as Python skips it.
 */
function readFields(buf: Uint8Array): Map<number, (bigint | Uint8Array)[]> | undefined {
  const fields = new Map<number, (bigint | Uint8Array)[]>();
  const groups: number[] = [];
  let at = 0;
  while (at < buf.length) {
    const tag = readVarint(buf, at);
    if (tag === undefined) return undefined;
    at = tag[1];
    const field = Number(tag[0] >> 3n);
    const wire = Number(tag[0] & 7n);
    if (field === 0) return undefined;
    if (wire === WIRE_START_GROUP) {
      if (groups.length >= MAX_GROUP_DEPTH) return undefined;
      groups.push(field);
      continue;
    }
    if (wire === WIRE_END_GROUP) {
      if (groups.pop() !== field) return undefined;
      continue;
    }
    let value: bigint | Uint8Array;
    if (wire === WIRE_VARINT) {
      const v = readVarint(buf, at);
      if (v === undefined) return undefined;
      [value, at] = v;
    } else if (wire === WIRE_LEN) {
      const len = readVarint(buf, at);
      if (len === undefined || len[1] + Number(len[0]) > buf.length) return undefined;
      value = buf.subarray(len[1], len[1] + Number(len[0]));
      at = len[1] + Number(len[0]);
    } else if (wire === WIRE_I64 || wire === WIRE_I32) {
      const size = wire === WIRE_I64 ? 8 : 4;
      if (at + size > buf.length) return undefined;
      value = buf.subarray(at, at + size);
      at += size;
    } else return undefined;
    if (groups.length > 0) continue; // a field inside a skipped group
    fields.set(field, [...(fields.get(field) ?? []), value]);
  }
  return groups.length === 0 ? fields : undefined;
}

/**
 * The `rejected_log_records` (or `rejected_spans`) count of an OTLP export response's
 * `partial_success`, as Python's protobuf runtime reads it: repeated occurrences of the
 * sub-message merge (the last count written wins), and the count is any int64, so a
 * negative one is still non-zero (Python's `if reply.partial_success.rejected_log_records`
 * takes it as a rejection). 0 for an empty or unparsable body (Python suppresses the
 * parse error and takes the request as accepted).
 */
export function partialSuccessRejected(body: Uint8Array): bigint {
  const top = readFields(body);
  if (top === undefined) return 0n;
  let rejected = 0n;
  for (const partial of top.get(1) ?? []) {
    if (!(partial instanceof Uint8Array)) return 0n; // wrong wire type: a parse error
    const inner = readFields(partial);
    if (inner === undefined) return 0n;
    for (const count of inner.get(1) ?? []) {
      if (typeof count !== "bigint") return 0n;
      rejected = BigInt.asIntN(64, count);
    }
  }
  return rejected;
}
