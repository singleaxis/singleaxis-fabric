// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";

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
