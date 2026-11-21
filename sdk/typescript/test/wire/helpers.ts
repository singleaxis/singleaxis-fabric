// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { PyFloat, compactInt, parseJson, type JsonValue } from "../../src/wire/codec.js";

/** The repository root (tests read the shared contracts in place). */
export const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

/** A contract file parsed with exact integers. */
export function contract(path: string): any {
  return parseJson(readFileSync(join(REPO, path), "utf8"));
}

/** A shared coverage vector (`contracts/coverage/v1/fixtures/vectors/<name>.json`). */
export function vector(name: string): any {
  return contract(`contracts/coverage/v1/fixtures/vectors/${name}.json`);
}

/** Every safe-range bigint as a number, recursively, so two exact parses compare equal. */
export function norm(value: unknown): unknown {
  if (typeof value === "bigint") return compactInt(value);
  if (Array.isArray(value)) return value.map(norm);
  if (value instanceof PyFloat || value === null || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, norm(v)]));
}

/** `[label, case]` rows for `it.each`, labelled by `field` (default `name`). */
export function cases(list: readonly any[], field = "name"): [string, any][] {
  return list.map((c) => [String(c[field]), c]);
}

export type { JsonValue };
