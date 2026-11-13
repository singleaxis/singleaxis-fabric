// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §6.1 (unit 055-t2): exact int64 and Python-identical JSON. The expected bytes
// are what Python's json.dumps and the Python spool writer produced
// (contracts/capture/v1/fixtures/vectors/spool-bytes-v1.json, regenerated with no diff by
// scripts/tests/test_capture_contracts.py).
import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { pseudonymV2 } from "../../../src/identity.js";
import {
  CodecError,
  INT64_MAX,
  INT64_MIN,
  PyFloat,
  canonicalJson,
  compareCodePoints,
  encodeJson,
  encodeJsonBytes,
  isInt64,
  parseInt64,
  parseJson,
  pyFloatRepr,
  u32be,
  u64be,
} from "../../../src/wire/codec.js";
import { encodeOpaqueId, runPseudonym } from "../../../src/wire/p1.js";
import { cases, contract } from "../helpers.js";

const doc = contract("contracts/capture/v1/fixtures/vectors/spool-bytes-v1.json");

describe("spool-bytes-v1 json: Python json.dumps byte for byte", () => {
  it.each(
    cases(
      doc.json.map((c: any) => ({ ...c, label: `${c.name} (ensure_ascii=${c.ensure_ascii})` })),
      "label",
    ),
  )("%s", (_label, c: any) => {
    const value = parseJson(c.input);
    if (c.refused === true) {
      expect(() => encodeJsonBytes(value, { asciiOnly: c.ensure_ascii })).toThrow(CodecError);
      return;
    }
    expect(encodeJsonBytes(value, { asciiOnly: c.ensure_ascii }).toString("hex")).toBe(
      c.output_hex,
    );
  });

  it("covers escaping, surrogates, integral floats, int64 and ordering", () => {
    const names = new Set(doc.json.map((c: any) => c.name));
    for (const topic of ["escaping", "surrogate", "floats", "int64", "ordering"]) {
      expect(
        [...names].some((n) => String(n).includes(topic)),
        topic,
      ).toBe(true);
    }
  });
});

describe("spool-bytes-v1 ids: Python's ids of surrogatepass values", () => {
  it.each(cases(doc.ids, "function"))("%s", (_fn, c: any) => {
    const value = JSON.parse(c.value) as string; // ASCII-escaped: a lone surrogate survives
    const got =
      c.function === "encode_opaque_id"
        ? encodeOpaqueId(value)
        : c.function === "run_pseudonym"
          ? runPseudonym(value, c.key)
          : pseudonymV2(c.prefix, value, c.key);
    expect(got).toBe(c.expected);
  });
});

describe("spool headers and ledger payloads are this encoder's bytes", () => {
  it.each(cases(doc.records))("record header: %s", (_name, c: any) => {
    const frame = Buffer.from(c.frame_hex, "hex");
    const size = frame.readUInt32BE(8);
    expect(encodeJsonBytes(c.header).equals(frame.subarray(12, 12 + size))).toBe(true);
    expect(frame.subarray(0, 8).toString("latin1")).toBe("FWSPOOL1");
    expect(u32be(size).equals(frame.subarray(8, 12))).toBe(true);
    const digest = createHash("sha256").update(frame.subarray(0, -32)).digest();
    expect(digest.equals(frame.subarray(-32))).toBe(true);
  });

  it("ledger slot payload (Python's default ensure_ascii=True)", () => {
    const slot = Buffer.from(doc.ledger.slot.slot_hex, "hex");
    const size = slot.readUInt32BE(8);
    const names = new Map(doc.records.map((r: any) => [r.name, r.header]));
    const payload = {
      owner: doc.ledger.slot.owner,
      records: doc.ledger.slot.records.map((n: string) => names.get(n)),
    };
    expect(encodeJsonBytes(payload, { asciiOnly: true }).equals(slot.subarray(12, 12 + size))).toBe(
      true,
    );
  });

  it("registration epochs are exact u64 values through 2^63-1", () => {
    for (const r of doc.registrations) {
      const file = Buffer.from(r.file_hex, "hex");
      expect(file.readBigUInt64LE(12)).toBe(BigInt(r.epoch));
    }
    expect(doc.registrations.map((r: any) => BigInt(r.epoch))).toContain(INT64_MAX);
  });
});

describe("int64", () => {
  it("parses every integer lexeme exactly, never as a rounded float", () => {
    const text = "[9007199254740993,9223372036854775807,-9223372036854775808,1,-0]";
    const value = parseJson(text) as unknown[];
    expect(value).toEqual([9007199254740993n, INT64_MAX, INT64_MIN, 1, 0]); // "-0" is the int 0
    expect(encodeJson(value)).toBe(
      "[9007199254740993,9223372036854775807,-9223372036854775808,1,0]",
    );
    expect(parseJson("[1,2]", { ints: "bigint" })).toEqual([1n, 2n]);
  });

  it("refuses an integer outside int64, an unsafe number and JSON.stringify's shortcuts", () => {
    expect(() => encodeJson(INT64_MAX + 1n)).toThrow(CodecError);
    expect(() => encodeJson(INT64_MIN - 1n)).toThrow(CodecError);
    expect(() => encodeJson(2 ** 53 + 2)).toThrow(CodecError);
    expect(() => encodeJson(Number.NaN)).toThrow(CodecError);
    expect(() => encodeJson(Number.POSITIVE_INFINITY)).toThrow(CodecError);
    expect(() => encodeJson({ a: undefined })).toThrow(CodecError);
    expect(() => encodeJson(new Date(0))).toThrow(CodecError);
    expect(() => canonicalJson([1.5])).toThrow(CodecError);
  });

  it("checks int64 text strictly", () => {
    expect(parseInt64("9223372036854775807")).toBe(INT64_MAX);
    expect(parseInt64("-9223372036854775808")).toBe(INT64_MIN);
    for (const bad of ["9223372036854775808", "+1", "01", " 1", "1.0", "1e3", ""]) {
      expect(parseInt64(bad), bad).toBeUndefined();
    }
    expect(isInt64(INT64_MAX)).toBe(true);
    expect(isInt64(INT64_MAX + 1n)).toBe(false);
    expect(isInt64(2 ** 53)).toBe(false);
    expect(u64be(INT64_MAX).toString("hex")).toBe("7fffffffffffffff");
  });
});

describe("floats and ordering", () => {
  it("prints Python's repr(float)", () => {
    const pairs: [number, string][] = [
      [1, "1.0"],
      [-0, "-0.0"],
      [100, "100.0"],
      [1e16, "1e+16"],
      [1e15, "1000000000000000.0"],
      [1.5e-7, "1.5e-07"],
      [0.0001, "0.0001"],
      [1e-5, "1e-05"],
      [123456789.125, "123456789.125"],
      [0.1 + 0.2, "0.30000000000000004"],
    ];
    for (const [value, repr] of pairs) expect(pyFloatRepr(value)).toBe(repr);
    expect(encodeJson([new PyFloat(2), 2])).toBe("[2.0,2]");
    expect(encodeJson(parseJson("[2.0,2]"))).toBe("[2.0,2]");
  });

  it("orders keys by code point, not by UTF-16 unit", () => {
    expect(compareCodePoints("\u{1F600}", "￿")).toBeGreaterThan(0);
    expect("\u{1F600}" < "￿").toBe(true); // what a UTF-16 sort would do
    expect(encodeJson({ "￿": 1, "\u{1F600}": 2 })).toBe('{"￿":1,"\u{1F600}":2}');
  });
});
