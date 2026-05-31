// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Locks `pythonJsonStringify` byte-for-byte against CPython's
 * `json.dumps(value, sort_keys=True, default=str)`, so a SHA-256 over the
 * result equals the Python SDK's policy `input_hash`.
 *
 * Every `expected` string below was produced by running the corresponding
 * value through CPython:
 *
 *   python3 -c 'import json; print(json.dumps(v, sort_keys=True, default=str))'
 *
 * and must never drift. Covers the four acceptance divergences vs naive
 * `JSON.stringify`: non-ASCII Unicode (ensure_ascii), negative zero, exponent
 * notation, and large floats — plus integers, escaping, sorting, and nesting.
 */

import { describe, expect, it } from "vitest";

import { policyInputHash, pythonJsonStringify } from "../src/hash.js";

describe("pythonJsonStringify reproduces CPython json.dumps", () => {
  // [value, exact string CPython emitted]
  const vectors: ReadonlyArray<readonly [unknown, string]> = [
    // integers
    [0, "0"],
    [50, "50"],
    [5000, "5000"],
    [-7, "-7"],
    [9007199254740991, "9007199254740991"], // Number.MAX_SAFE_INTEGER
    // floats
    [0.1, "0.1"],
    [-0.0, "-0.0"],
    [1e16, "1e+16"],
    [1e20, "1e+20"],
    [1e21, "1e+21"],
    [1e-5, "1e-05"],
    [1e-7, "1e-07"],
    [1.5e300, "1.5e+300"],
    [2.5, "2.5"],
    [-3.75, "-3.75"],
    [9999999999999998.0, "9999999999999998.0"], // 16-digit float stays decimal
    [9007199254740992.0, "9007199254740992.0"], // 2^53 as float, decimal form
    [0.0001, "0.0001"],
    [123456789012345.6, "123456789012345.6"],
    // strings — ensure_ascii=True
    ["café", '"caf\\u00e9"'],
    ["naïve", '"na\\u00efve"'],
    ["🚀", '"\\ud83d\\ude80"'], // astral -> surrogate pair
    ["tab\tnewline\n", '"tab\\tnewline\\n"'],
    ['quote"backslash\\', '"quote\\"backslash\\\\"'],
    ["plain ascii", '"plain ascii"'],
    // booleans / null
    [true, "true"],
    [false, "false"],
    [null, "null"],
    // structure
    [{ b: 1, a: 2, c: { z: 9, y: 8 } }, '{"a": 2, "b": 1, "c": {"y": 8, "z": 9}}'],
    [[1, 2, 3, "x"], '[1, 2, 3, "x"]'],
    [{ b: 1, a: "café", z: [1, -0.0, "x"] }, '{"a": "caf\\u00e9", "b": 1, "z": [1, -0.0, "x"]}'],
  ];

  for (const [value, expected] of vectors) {
    it(`serializes ${JSON.stringify(value)} -> ${expected}`, () => {
      expect(pythonJsonStringify(value)).toBe(expected);
    });
  }

  it("throws on non-finite numbers (Python would emit invalid tokens)", () => {
    expect(() => pythonJsonStringify(NaN)).toThrow();
    expect(() => pythonJsonStringify(Infinity)).toThrow();
    expect(() => pythonJsonStringify(-Infinity)).toThrow();
  });
});

describe("policyInputHash matches the committed Python goldens", () => {
  it("hashes {amount:50} to the committed value (no regression)", () => {
    expect(policyInputHash({ amount: 50 })).toBe(
      "76486eecb93e90859a9039a37489b959954ee722a13497353787f5d7f50309d6",
    );
  });

  it("hashes {amount:5000} to the committed value (no regression)", () => {
    expect(policyInputHash({ amount: 5000 })).toBe(
      "40d73b5da3b2c0c2a3a53117df9ce7a4dc137bffcceeb71afc7d23acf9307914",
    );
  });
});
