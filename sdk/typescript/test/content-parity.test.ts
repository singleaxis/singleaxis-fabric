// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Cross-language byte/hash conformance (spec 029 §2, release gate 4):
 * every fixture under `contracts/content/v1/fixtures/bytes/` must
 * canonicalize to the pinned bytes and SHA-256 through the TypeScript
 * pipeline exactly as it does through Python's `canonical_bytes`.
 */

import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { canonicalBytes } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, "../../../contracts/content/v1/fixtures/bytes");

interface ByteFixture {
  name: string;
  kind: "text" | "json";
  value: string;
  byte_length: number;
  sha256: string;
  input?: unknown;
}

function loadFixtures(): ByteFixture[] {
  return fs
    .readdirSync(fixturesDir)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => JSON.parse(fs.readFileSync(path.join(fixturesDir, f), "utf-8")) as ByteFixture);
}

describe("shared content byte/hash fixtures", () => {
  const fixtures = loadFixtures();
  it("retains the complete committed byte-fixture inventory", () => {
    expect(
      fs
        .readdirSync(fixturesDir)
        .filter((name) => name.endsWith(".json"))
        .sort(),
    ).toEqual([
      "ascii.json",
      "empty-array.json",
      "empty-object.json",
      "empty-string.json",
      "multiline.json",
      "nested-json.json",
      "unicode.json",
    ]);
    expect(fixtures).toHaveLength(7);
  });
  for (const fixture of fixtures) {
    it(`${fixture.name} canonicalizes to the pinned bytes + digest`, () => {
      const content = fixture.kind === "json" ? fixture.input : fixture.value;
      const mediaType = fixture.kind === "json" ? "application/json" : "text/plain";
      const { data } = canonicalBytes(content, mediaType);
      const text = new TextDecoder("utf-8", { fatal: true }).decode(data);
      expect(text).toBe(fixture.value);
      expect(data.length).toBe(fixture.byte_length);
      const digest = "sha256:" + createHash("sha256").update(data).digest("hex");
      expect(digest).toBe(fixture.sha256);
    });
  }
});
