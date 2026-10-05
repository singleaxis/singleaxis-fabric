// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Runtime telemetry guards shared by `decision.ts` and `calls.ts`.
 *
 * TS types protect compile-time callers, but plain-JS callers can pass
 * anything; these helpers fail loud (throw a specific Error) rather than
 * letting an out-of-contract span be emitted, matching the Python SDK's
 * posture. They never run for valid inputs, so the emitted shape — and
 * the conformance goldens — stay byte-identical.
 *
 * This is a leaf module: it imports nothing from the rest of the SDK.
 */

/** Throw unless `value` is a JSON scalar (string | number | boolean). */
export function assertScalarAttribute(key: string, value: unknown): void {
  const t = typeof value;
  if (t === "string" || t === "boolean") {
    return;
  }
  if (t === "number") {
    assertFiniteNumber(key, value as number);
    return;
  }
  throw new Error(
    `setAttribute: value for "${key}" must be a string, number, or boolean; got ${describe(value)}`,
  );
}

/** Throw if `value` is a non-finite number (NaN / Infinity / -Infinity). */
export function assertFiniteNumber(field: string, value: number): void {
  if (!Number.isFinite(value)) {
    throw new Error(`${field} must be a finite number; got ${String(value)}`);
  }
}

/** Throw unless `value` is an integer >= 0. */
export function assertNonNegativeInt(field: string, value: number): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${field} must be a non-negative integer; got ${String(value)}`);
  }
}

/** Throw unless `value` is an integer >= `min` (one-based counters use 1). */
export function assertIntAtLeast(field: string, value: number, min: number): void {
  if (!Number.isInteger(value) || value < min) {
    throw new Error(`${field} must be an integer >= ${min}; got ${String(value)}`);
  }
}

/** Throw when `value` is empty or whitespace-only. */
export function assertNonEmpty(field: string, value: string): void {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${field} must be non-empty`);
  }
}

/**
 * Throw unless `value` is a string whose length is within `[min, max]`.
 * Mirrors pydantic `Field(min_length=..., max_length=...)` on the Python
 * record models (a whitespace-only value still counts toward length).
 */
export function assertLength(field: string, value: string, min: number, max: number): void {
  if (typeof value !== "string" || value.length < min || value.length > max) {
    throw new Error(
      `${field} must be a string with length between ${min} and ${max}; got ${describe(value)}`,
    );
  }
}

/** Throw unless `value` is one of `allowed`. */
export function assertOneOf<T extends string>(
  field: string,
  value: unknown,
  allowed: readonly T[],
): void {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new Error(`${field} must be one of {${allowed.join(", ")}}; got ${describe(value)}`);
  }
}

/** Render an offending value for an error message. */
export function describe(value: unknown): string {
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (value === null) {
    return "null";
  }
  if (typeof value === "object" || typeof value === "function") {
    return typeof value;
  }
  return String(value);
}
