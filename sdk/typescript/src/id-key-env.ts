// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * The id key from the environment, as the Python SDK reads it (spec 058 §7):
 * by value in `FABRIC_WIRE_ID_KEY`, or in the file `FABRIC_WIRE_ID_KEY_FILE`
 * names (`fabric run` passes keys by file, never by value; one trailing
 * newline is ignored). A secret: never logged; errors are fixed text.
 */

import { readFileSync } from "node:fs";

export const ID_KEY_VAR = "FABRIC_WIRE_ID_KEY";
export const ID_KEY_FILE_VAR = "FABRIC_WIRE_ID_KEY_FILE";
const MAX_ID_KEY_FILE_BYTES = 4096;

/** The raw key bytes (unset or empty: `undefined`); length is checked by the caller. */
export function idKeyBytesFromEnv(env: Record<string, string | undefined>): Uint8Array | undefined {
  const value = env[ID_KEY_VAR] ?? "";
  const path = env[ID_KEY_FILE_VAR] ?? "";
  if (value !== "" && path !== "") {
    throw new Error(`set ${ID_KEY_VAR} or ${ID_KEY_FILE_VAR}, not both`);
  }
  if (value !== "") return Buffer.from(value, "utf8");
  if (path === "") return undefined;
  let raw: Buffer;
  try {
    raw = readFileSync(path);
  } catch {
    throw new Error(`${ID_KEY_FILE_VAR} is not readable`);
  }
  if (raw.length > MAX_ID_KEY_FILE_BYTES) {
    throw new Error(`${ID_KEY_FILE_VAR} must hold a key of at most ${MAX_ID_KEY_FILE_BYTES} bytes`);
  }
  const end = raw.subarray(-2).toString("latin1");
  const cut = end === "\r\n" ? 2 : end.endsWith("\n") ? 1 : 0;
  return new Uint8Array(raw.subarray(0, raw.length - cut));
}
