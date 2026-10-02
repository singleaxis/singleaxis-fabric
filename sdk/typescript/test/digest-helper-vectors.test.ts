// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
import { expect, it } from "vitest";
import { sha256BytesHex, sha256BytesPrefixed, sha256Hex } from "../src/hash.js";
import { contentHashBytes } from "../src/content-store.js";
import { sha256Prefixed } from "../src/content.js";

// Fixed external SHA-256 vectors; no implementation-derived expected digests.
it.each([
  [new Uint8Array(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
  [
    new TextEncoder().encode("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  ],
  [Uint8Array.of(0), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"],
] as const)("keeps exact byte digests and public aliases for %s", (bytes, expected) => {
  expect(sha256BytesHex(bytes)).toBe(expected);
  expect(contentHashBytes(bytes)).toBe(expected);
  expect(sha256BytesPrefixed(bytes)).toBe(`sha256:${expected}`);
  expect(sha256Prefixed(bytes)).toBe(`sha256:${expected}`);
});
it("preserves UTF-8 text encoding and byte-view offsets without decoding binary", () => {
  const text = "π🚀\u0000";
  expect(sha256Hex(text)).toBe("0c4e75fab12ce58b7167ac0cc86110e9af01db4d0c88c045dd8b85efd29c7c04");
  expect(sha256Hex(text)).toBe(sha256BytesHex(new TextEncoder().encode(text)));
  const backing = Uint8Array.of(255, 97, 98, 99, 254);
  expect(sha256BytesHex(backing.subarray(1, 4))).toBe(
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
  const invalidUtf8 = Uint8Array.of(255);
  expect(sha256BytesHex(invalidUtf8)).not.toBe(sha256Hex(new TextDecoder().decode(invalidUtf8)));
});
