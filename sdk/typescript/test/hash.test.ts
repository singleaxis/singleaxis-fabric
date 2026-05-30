// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Locks the sha256 hex parity with Python's
 * `hashlib.sha256(x.encode()).hexdigest()`. The expected values were
 * computed with CPython and must never drift.
 */

import { describe, expect, it } from "vitest";

import { sha256Hex } from "../src/index.js";

describe("sha256Hex matches Python hashlib", () => {
  it("hashes alice@example.com identically to Python", () => {
    expect(sha256Hex("alice@example.com")).toBe(
      "ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976",
    );
  });

  it("matches the tool_call golden argument/result hashes", () => {
    expect(sha256Hex('{"query":"refunds"}')).toBe(
      "4f18a4cd0475a4be6c3c41e5954b1b4dfd730788198402bd10bb352ebff5d0a1",
    );
    expect(sha256Hex('{"hits":3}')).toBe(
      "5429ed31f7eec9dbc86e358b3bacc5eb07eba26715ab1e05c802841f2d3fbd57",
    );
  });
});
