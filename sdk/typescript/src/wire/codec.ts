// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Exact int64 and Python-identical JSON for the wire core (spec 055 §6.1, §6.2).
 *
 * Every digest, token, spool header and ledger slot TypeScript writes must be byte for
 * byte what the Python writer writes for the same value, so this module reproduces
 * Python's `json.dumps(value, sort_keys=True, separators=(",", ":"))` exactly:
 *
 * - integers are exact through 2^63-1 (`bigint`, or a safe-integer `number`); a value a
 *   float64 rounded is never written as an integer;
 * - a float is a {@link PyFloat} (or a non-integral `number`) and prints as Python's
 *   `repr(float)` (`1.0`, `1e+16`, `1.5e-07`); `NaN` and the infinities are refused;
 * - keys sort by Unicode code point (Python `str` order), not by UTF-16 unit;
 * - `asciiOnly` is Python's default `ensure_ascii=True` (the ledger); without it the text
 *   is literal UTF-8 (`ensure_ascii=False`, canonical JSON and spool headers), where a
 *   lone surrogate is refused as Python's strict `.encode()` refuses it.
 *
 * `JSON.stringify(bigint)` throws and `JSON.parse` rounds integers above 2^53, so neither
 * is the implementation: {@link parseJson} reads every integer from its source text.
 * Nothing here logs, and no error message carries a value.
 */

import { createHash } from "node:crypto";

/** 2^63 - 1, the largest epoch, sequence and nanosecond time. */
export const INT64_MAX = (1n << 63n) - 1n;
/** -2^63. */
export const INT64_MIN = -(1n << 63n);

/** A JSON float that must print as Python's `repr(float)`, integral or not (`2.0`). */
export class PyFloat {
  readonly value: number;
  constructor(value: number) {
    this.value = value;
    Object.freeze(this);
  }
}

/** A JSON value with exact integers. */
export type JsonValue =
  | null
  | boolean
  | string
  | number
  | bigint
  | PyFloat
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

/** A fixed-text encoding error; never carries the value. */
export class CodecError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CodecError";
  }
}

export interface EncodeOptions {
  /** Python's `ensure_ascii=True`: escape every character outside `' '..'~'`. */
  readonly asciiOnly?: boolean;
  /** Refuse every float (spec 029 canonical JSON carries none). */
  readonly noFloats?: boolean;
}

// ----------------------------------------------------------------- integers

/** Whether `value` is an exact integer in [-2^63, 2^63-1]. */
export function isInt64(value: unknown): value is number | bigint {
  if (typeof value === "bigint") {
    return value >= INT64_MIN && value <= INT64_MAX;
  }
  return typeof value === "number" && Number.isSafeInteger(value);
}

/** `value` as a `bigint`, or `undefined` when it is not an exact int64. */
export function toInt64(value: unknown): bigint | undefined {
  return isInt64(value) ? BigInt(value) : undefined;
}

/** A `bigint` as a safe-integer `number` when it fits, else unchanged. */
export function compactInt(value: bigint): number | bigint {
  return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)
    ? Number(value)
    : value;
}

/** Strict decimal int64 text (`0`, `-1`, `9223372036854775807`); no sign `+`, no spaces. */
export function parseInt64(text: string): bigint | undefined {
  if (!/^-?(0|[1-9][0-9]{0,18})$/.test(text)) {
    return undefined;
  }
  const value = BigInt(text);
  return value >= INT64_MIN && value <= INT64_MAX ? value : undefined;
}

// ----------------------------------------------------------------- floats

/** Python's `repr(float)` of a finite number: shortest round-trip digits, Python layout. */
export function pyFloatRepr(value: number): string {
  if (!Number.isFinite(value)) {
    throw new CodecError("canonical JSON carries no NaN or infinity");
  }
  const sign = value < 0 || Object.is(value, -0) ? "-" : "";
  const [mantissa = "0", exp = "0"] = Math.abs(value).toExponential().split("e");
  const digits = mantissa.replace(".", "");
  const e = Number(exp);
  if (e < -4 || e >= 16) {
    const frac = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    const magnitude = String(Math.abs(e)).padStart(2, "0");
    return `${sign}${frac}e${e < 0 ? "-" : "+"}${magnitude}`;
  }
  if (e < 0) {
    return `${sign}0.${"0".repeat(-e - 1)}${digits}`;
  }
  const whole = digits.length > e + 1 ? digits.slice(0, e + 1) : digits.padEnd(e + 1, "0");
  const frac = digits.length > e + 1 ? digits.slice(e + 1) : "0";
  return `${sign}${whole}.${frac}`;
}

// ----------------------------------------------------------------- strings

const SHORT_ESCAPES: Readonly<Record<number, string>> = {
  0x22: '\\"',
  0x5c: "\\\\",
  0x08: "\\b",
  0x0c: "\\f",
  0x0a: "\\n",
  0x0d: "\\r",
  0x09: "\\t",
};

function hex4(code: number): string {
  return "\\u" + code.toString(16).padStart(4, "0");
}

/** Whether `value` holds an unpaired UTF-16 surrogate. */
export function hasLoneSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return true;
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function encodeString(value: string, asciiOnly: boolean): string {
  if (!asciiOnly && hasLoneSurrogate(value)) {
    throw new CodecError("a lone surrogate has no UTF-8 encoding");
  }
  let out = '"';
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    const short = SHORT_ESCAPES[code];
    if (short !== undefined) {
      out += short;
    } else if (code < 0x20 || (asciiOnly && code > 0x7e)) {
      out += hex4(code);
    } else {
      out += value[i];
    }
  }
  return out + '"';
}

/** Python `str` order: by code point (a lone surrogate is its own code point). */
export function compareCodePoints(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const ca = ia.next();
    const cb = ib.next();
    if (ca.done === true || cb.done === true) {
      return ca.done === true ? (cb.done === true ? 0 : -1) : 1;
    }
    const d = (ca.value.codePointAt(0) ?? 0) - (cb.value.codePointAt(0) ?? 0);
    if (d !== 0) {
      return d;
    }
  }
}

// ----------------------------------------------------------------- encoding

function encodeValue(value: unknown, options: EncodeOptions, depth: number): string {
  if (depth > 256) {
    throw new CodecError("JSON value nests too deeply");
  }
  if (value === null) {
    return "null";
  }
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return encodeString(value, options.asciiOnly === true);
    case "bigint":
      if (value < INT64_MIN || value > INT64_MAX) {
        throw new CodecError("an integer is outside int64");
      }
      return value.toString();
    case "number":
      if (Number.isInteger(value)) {
        if (!Number.isSafeInteger(value)) {
          throw new CodecError("an integer above 2^53 must be a bigint");
        }
        return String(value);
      }
      if (options.noFloats === true) {
        throw new CodecError("canonical JSON carries no floats");
      }
      return pyFloatRepr(value);
    case "object":
      break;
    default:
      throw new CodecError(
        "a JSON value is null, boolean, string, integer, float, array or object",
      );
  }
  if (value instanceof PyFloat) {
    if (options.noFloats === true) {
      throw new CodecError("canonical JSON carries no floats");
    }
    return pyFloatRepr(value.value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((item) => encodeValue(item, options, depth + 1)).join(",") + "]";
  }
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new CodecError("a JSON object is a plain object");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort(compareCodePoints);
  const parts: string[] = [];
  for (const key of keys) {
    const item = record[key];
    if (item === undefined) {
      throw new CodecError("a JSON object value is never undefined");
    }
    parts.push(
      encodeString(key, options.asciiOnly === true) + ":" + encodeValue(item, options, depth + 1),
    );
  }
  return "{" + parts.join(",") + "}";
}

/** Python `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=...)`. */
export function encodeJson(value: unknown, options: EncodeOptions = {}): string {
  return encodeValue(value, options, 0);
}

/** UTF-8 bytes of {@link encodeJson} (literal UTF-8 unless `asciiOnly`). */
export function encodeJsonBytes(value: unknown, options: EncodeOptions = {}): Buffer {
  return Buffer.from(encodeJson(value, options), "utf8");
}

/** Spec-029 canonical JSON: sorted keys, `(",", ":")`, literal UTF-8, no floats. */
export function canonicalJson(value: unknown): string {
  return encodeJson(value, { noFloats: true });
}

/** UTF-8 bytes of {@link canonicalJson}. */
export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

/** `sha256:` + 64 lowercase hex of `data`. */
export function sha256Prefixed(data: Uint8Array | string): string {
  return "sha256:" + createHash("sha256").update(data).digest("hex");
}

// ----------------------------------------------------------------- parsing

export interface ParseOptions {
  /**
   * `auto` (default): an integer is a `number` when it is a safe integer, else a
   * `bigint`; `bigint`: every integer is a `bigint`.
   */
  readonly ints?: "auto" | "bigint";
}

type Reviver = (
  this: unknown,
  key: string,
  value: unknown,
  context?: { source?: string },
) => unknown;

/**
 * JSON text to a value with exact integers: an integer lexeme becomes a `bigint` (or a
 * safe `number`), never a rounded float; a number written with a fraction or an exponent
 * is a {@link PyFloat}, so it prints back as Python prints it. Duplicate keys keep the
 * last value, as Python's `json.loads` does. Throws {@link CodecError} (fixed text).
 */
export function parseJson(text: string, options: ParseOptions = {}): JsonValue {
  const allBigint = options.ints === "bigint";
  const reviver: Reviver = (_key, value, context) => {
    if (typeof value !== "number") {
      return value;
    }
    const source = context?.source;
    if (source === undefined) {
      throw new CodecError("this Node.js build cannot parse exact integers");
    }
    if (/[.eE]/.test(source)) {
      if (!Number.isFinite(value)) {
        throw new CodecError("a JSON float is out of range");
      }
      return new PyFloat(value);
    }
    const exact = BigInt(source);
    return allBigint ? exact : compactInt(exact);
  };
  try {
    return JSON.parse(text, reviver as (key: string, value: unknown) => unknown) as JsonValue;
  } catch (error) {
    if (error instanceof CodecError) {
      throw error;
    }
    throw new CodecError("text is not valid JSON");
  }
}

// ----------------------------------------------------------------- fixed-width integers

/** Big-endian u32. */
export function u32be(value: number): Buffer {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
}

/** Big-endian u64. */
export function u64be(value: bigint): Buffer {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(value);
  return out;
}
