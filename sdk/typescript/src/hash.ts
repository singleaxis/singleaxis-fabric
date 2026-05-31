// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
import { createHash, randomUUID as nodeRandomUUID } from "node:crypto";

/**
 * SHA-256 of a UTF-8 string, hex-encoded.
 *
 * MUST be byte-identical to the Python SDK's
 * `hashlib.sha256(x.encode("utf-8")).hexdigest()` so the
 * `fabric.tool.arguments_hash` / `fabric.tool.result_hash` attributes
 * match the shared conformance goldens.
 */
export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf-8").digest("hex");
}

/** A random UUID v4 string. Used for SDK-minted event ids. */
export function randomUuid(): string {
  return nodeRandomUUID();
}

/**
 * Serialize a string exactly as Python's `json.dumps` does with its default
 * `ensure_ascii=True`: JSON-escape the control chars / quote / backslash, and
 * escape every code point above 0x7E as `\uXXXX`. JS strings are already
 * UTF-16, so astral chars are already surrogate pairs — escaping each unit
 * above 0x7E reproduces Python's surrogate-pair output (e.g. `🚀` -> two
 * `\uXXXX` escapes).
 */
function pythonJsonString(value: string): string {
  let out = '"';
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    switch (code) {
      case 0x22:
        out += '\\"';
        break;
      case 0x5c:
        out += "\\\\";
        break;
      case 0x08:
        out += "\\b";
        break;
      case 0x09:
        out += "\\t";
        break;
      case 0x0a:
        out += "\\n";
        break;
      case 0x0c:
        out += "\\f";
        break;
      case 0x0d:
        out += "\\r";
        break;
      default:
        if (code < 0x20 || code > 0x7e) {
          // Control char or any non-ASCII unit -> \uXXXX (Python escapes both;
          // surrogate halves of astral chars are emitted as-is, matching Python).
          out += "\\u" + code.toString(16).padStart(4, "0");
        } else {
          out += value[i];
        }
    }
  }
  return out + '"';
}

/**
 * Render a finite number to match Python's `repr` (which `json.dumps` uses):
 * integers as bare digits and floats via `float.__repr__` (shortest
 * round-trip, with scientific notation when the decimal exponent is `< -4` or
 * `>= 16`, using a signed, ≥2-digit exponent).
 *
 * Throws on non-finite values: Python's `json.dumps` would emit invalid
 * `NaN`/`Infinity` tokens, so we fail loud instead of producing a hash that
 * cannot round-trip through a real JSON parser.
 */
function pythonJsonNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new Error(`pythonJsonStringify: non-finite number is out of contract: ${n}`);
  }
  // Python distinguishes -0.0 (float) from 0 (int); emit the float form.
  if (Object.is(n, -0)) {
    return "-0.0";
  }
  // A JS integer that fits the safe range maps to a Python int -> bare digits.
  if (Number.isInteger(n) && Number.isSafeInteger(n)) {
    return String(n);
  }
  // Everything else (fractional, or magnitude beyond the safe-integer range,
  // which Python would carry as a float) -> Python float repr.
  return pythonFloatRepr(n);
}

/**
 * Format a finite, non-zero-or-fractional/large number to match Python's
 * `float.__repr__`. Uses `toExponential()` (no precision arg) to obtain the
 * shortest round-trip significant digits, then lays them out per Python's
 * fixed-vs-scientific rule (scientific iff decimal exponent `< -4` or `>= 16`).
 */
function pythonFloatRepr(n: number): string {
  if (n === 0) {
    // Reached only for +0 that arrived via the large/float path; Python: "0.0".
    return "0.0";
  }
  const neg = n < 0;
  const abs = Math.abs(n);
  const expStr = abs.toExponential(); // shortest round-trip, e.g. "1.5e+300"
  const m = /^(\d)(?:\.(\d+))?e([+-]\d+)$/.exec(expStr);
  if (m === null || m[1] === undefined || m[3] === undefined) {
    // Should be unreachable for finite numbers; fall back defensively.
    return String(n);
  }
  const digits = m[1] + (m[2] ?? "");
  const exp = parseInt(m[3], 10);
  const ndigits = digits.length;

  let out: string;
  if (exp < -4 || exp >= 16) {
    let mantissa = digits.slice(0, 1);
    if (digits.length > 1) {
      mantissa += "." + digits.slice(1);
    }
    const esign = exp < 0 ? "-" : "+";
    const eabs = Math.abs(exp).toString().padStart(2, "0");
    out = `${mantissa}e${esign}${eabs}`;
  } else if (exp >= 0) {
    const intLen = exp + 1;
    out =
      ndigits <= intLen
        ? digits + "0".repeat(intLen - ndigits) + ".0"
        : digits.slice(0, intLen) + "." + digits.slice(intLen);
  } else {
    out = "0." + "0".repeat(-exp - 1) + digits;
  }
  return neg ? "-" + out : out;
}

/**
 * Serialize a JSON-able value to match Python's
 * `json.dumps(value, sort_keys=True, default=str)` byte-for-byte, so a
 * SHA-256 over the result equals the Python SDK's policy `input_hash`.
 *
 * Reproduces Python's defaults that naive `JSON.stringify` diverges from:
 * - object keys are sorted recursively; separators are `", "` between items
 *   and `": "` between key and value (Python defaults);
 * - strings use `ensure_ascii=True`: every code point above 0x7E is escaped as
 *   `\uXXXX` (astral chars as surrogate pairs), e.g. `"café"` -> `café`,
 *   `"🚀"` -> `🚀`;
 * - numbers follow Python's `repr`: `-0.0` keeps its sign and the `.0`,
 *   large/fractional floats use shortest-round-trip scientific notation with a
 *   signed ≥2-digit exponent (`1e16` -> `1e+16`, `1e-5` -> `1e-05`).
 * - non-finite numbers (`NaN`/`Infinity`) throw, rather than emitting the
 *   invalid tokens Python's `json.dumps` would.
 *
 * Residual unrepresentable case: JS has a single `number` type, so a Python
 * `float` with a whole value (`50.0`, which Python renders as `"50.0"`) is
 * indistinguishable from a Python `int` (`50` -> `"50"`); both serialize here
 * as `"50"`. Policy inputs that carry whole-valued floats are therefore out of
 * the byte-exact contract — for such payloads the host should pre-compute and
 * supply `inputHash` directly rather than relying on this serializer. The four
 * acceptance cases (non-ASCII Unicode, exponent notation, large floats, and
 * negative zero) ARE handled.
 */
export function pythonJsonStringify(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    return pythonJsonNumber(value);
  }
  if (typeof value === "string") {
    return pythonJsonString(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => pythonJsonStringify(v)).join(", ")}]`;
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts = keys.map((k) => `${pythonJsonString(k)}: ${pythonJsonStringify(obj[k])}`);
    return `{${parts.join(", ")}}`;
  }
  // default=str fallback (Python stringifies anything else).
  return pythonJsonString(String(value));
}

/**
 * SHA-256 of a policy input object, hashed exactly as the Python SDK does
 * (`sha256(json.dumps(input, sort_keys=True, default=str))`).
 */
export function policyInputHash(input: unknown): string {
  return sha256Hex(pythonJsonStringify(input));
}
