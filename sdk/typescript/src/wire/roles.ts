// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The content role table (spec 049 §4.3; Python `_roles.py`), generated from the
 * registry as `roles.generated.ts`, and the Node's admission rules over it (rules 1-4).
 * Shared by PROTECT (`protect.ts`) and typed extraction (`parts.ts`).
 */
import { ROLE_ROWS } from "./roles.generated.js";
import type { RoleRow } from "./types.js";

const CAPS: Readonly<Record<string, number>> = {
  "64 KiB": 64 << 10,
  "256 KiB": 256 << 10,
  "1 MiB": 1 << 20,
  "4 MiB": 4 << 20,
};
const MEDIA_RE = /^(?=.{3,128}$)[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;

/** The content role table (spec 049 §4.3), generated from the registry. */
export const ROLES: ReadonlyMap<string, RoleRow> = new Map(ROLE_ROWS.map((row) => [row.role, row]));

/** A role's object cap for a deployment whose `max_body_bytes` is `maxBodyBytes`. */
export function capBytes(row: RoleRow, maxBodyBytes: number): number {
  return row.cap === "max_body_bytes" ? maxBodyBytes : CAPS[row.cap]!;
}

/** Exact `type/subtype`, `type/*` or `*`, for a value passing the 047 §7 media rule. */
export function admitsMedia(row: RoleRow, mediaType: string): boolean {
  if (!MEDIA_RE.test(mediaType)) return false;
  const major = mediaType.split("/", 1)[0] + "/*";
  return row.media_types.some((m) => m === "*" || m === mediaType || m === major);
}

/** Whether the Node's role rules (049 §4.3 rules 1-4) admit an object with these values. */
export function admits(
  role: string,
  fields: {
    boundary: string;
    provenance: string;
    mediaType: string;
    storedByteLength: number;
    maxBodyBytes: number;
  },
): boolean {
  const row = ROLES.get(role);
  return (
    row !== undefined &&
    row.boundary.includes(fields.boundary) &&
    row.provenance.includes(fields.provenance) &&
    admitsMedia(row, fields.mediaType) &&
    fields.storedByteLength <= capBytes(row, fields.maxBodyBytes)
  );
}
