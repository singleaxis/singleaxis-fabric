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
 * Serialize a JSON-able value to match Python's
 * `json.dumps(value, sort_keys=True, default=str)` byte-for-byte, so a
 * SHA-256 over the result equals the Python SDK's policy `input_hash`.
 *
 * Key points where naive `JSON.stringify` differs and this matters:
 * - object keys are sorted (recursively);
 * - separators are `", "` between items and `": "` between key and value
 *   (Python's defaults), NOT JS's separator-free form;
 * - strings use JSON escaping (same as JS for the ASCII inputs the policy
 *   path carries).
 *
 * Targets JSON-safe inputs (objects, arrays, strings, finite numbers,
 * booleans, null) — the shape a policy `input` payload takes. Non-finite
 * numbers and other exotic values are out of contract.
 */
export function pythonJsonStringify(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    // Integers and standard floats render identically to Python's repr for
    // the values a policy input carries; JSON.stringify of a finite number
    // matches (e.g. 50 -> "50", 0.5 -> "0.5").
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => pythonJsonStringify(v)).join(", ")}]`;
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts = keys.map((k) => `${JSON.stringify(k)}: ${pythonJsonStringify(obj[k])}`);
    return `{${parts.join(", ")}}`;
  }
  // default=str fallback (Python stringifies anything else).
  return JSON.stringify(String(value));
}

/**
 * SHA-256 of a policy input object, hashed exactly as the Python SDK does
 * (`sha256(json.dumps(input, sort_keys=True, default=str))`).
 */
export function policyInputHash(input: unknown): string {
  return sha256Hex(pythonJsonStringify(input));
}
