// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
import type { QualificationTable } from "../../../src/wire/manifest.js";

/**
 * A qualification table whose only tuple makes `wire.ts.undici` active on this machine's
 * Node patch, bundled undici and `target` (spec 055 §9.5: tests activate capture through a
 * table; the shipped one lists only the builds whose passivity reports passed).
 */
export function activeHere(target: string): QualificationTable {
  return {
    tuples: [
      {
        point: "wire.ts.undici",
        node: process.versions.node,
        undici: (process.versions as Record<string, string | undefined>).undici,
        platform: target,
        claim: "active",
        report_sha256: "sha256:" + "0".repeat(64),
      },
    ],
  };
}
