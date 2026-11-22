// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 unit 055-t7 (§9.5): every `spool-record-*.json` fixture round-trips through
// the TypeScript frame and equals Python's frame byte for byte; the `spool-bytes-v1.json`
// vectors (record, batch, sealed, wrong basename, unknown key id) are reproduced byte for
// byte; the reader's structural check accepts and refuses what Python's does.
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { parseJson } from "../../../src/wire/codec.js";
import {
  BATCH_MAGIC,
  CorruptRecordError,
  PlaintextRecordError,
  UndecryptableRecordError,
  batchFrame,
  frame,
  overBound,
  recordName,
  seal,
  spoolKeyId,
  unframe,
  unframeAll,
  unseal,
  validHeader,
} from "../../../src/wire/spool-codec.js";
import { cases, norm } from "../helpers.js";
import { KEY, OTHER_KEY, VECTORS, fixtures, runPython, vectorRecord } from "./helpers.js";

const hex = (pieces: readonly Uint8Array[]): string => Buffer.concat(pieces).toString("hex");
const blobLength = (doc: any): number =>
  ((doc.bodies ?? []) as any[]).reduce((sum, body) => sum + Number(body.length), 0);
const zeroBodies = (doc: any): Buffer[] =>
  ((doc.bodies ?? []) as any[]).map((body) => Buffer.alloc(Number(body.length)));
const load = (path: string): any => parseJson(readFileSync(path, "utf8"));

/** Python: per fixture path, the frame of the fixture with zero bodies and valid_header. */
const PY_FRAMES = `
import json, sys
from fabric.wire._spool import frame, valid_header
out = []
for path in sys.argv[1:]:
    doc = json.load(open(path, encoding="utf-8"))
    try:
        blob = sum(body["length"] for body in doc.get("bodies", []))
        bodies = [bytes(body["length"]) for body in doc.get("bodies", [])]
    except Exception:
        blob, bodies = 0, []
    try:
        framed = b"".join(frame(doc, bodies)).hex()
    except Exception:
        framed = None
    out.append({"frame": framed, "valid": bool(valid_header(doc, blob))})
print(json.dumps(out))
`;

describe("spool-record fixtures (contracts/capture/v1/fixtures/valid)", () => {
  const valid = fixtures("valid");
  const python = runPython(
    PY_FRAMES,
    valid.map(([, path]) => path),
  ) as any[];

  it("covers every fixture the spec names", () => {
    const names = valid.map(([name]) => name);
    for (const name of [
      "spool-record-exchange",
      "spool-record-exchange-260",
      "spool-record-record",
      "spool-record-loss-segment",
      "spool-record-marker",
      "spool-record-manifest",
      "spool-record-segment-seal-terminal",
    ]) {
      expect(names).toContain(name);
    }
  });

  it.each(valid.map(([name, path], index) => [name, path, index] as const))(
    "%s round-trips and equals Python's frame byte for byte",
    (_name, path, index) => {
      const doc = load(path);
      expect(validHeader(doc, blobLength(doc))).toBe(true);
      const framed = frame(doc, zeroBodies(doc));
      expect(hex(framed)).toBe(python[index].frame);
      const { doc: back, blob } = unframe(Buffer.concat(framed));
      expect(norm(back)).toEqual(norm(doc));
      expect(blob.length).toBe(blobLength(doc));
      expect(unframeAll(Buffer.concat(framed))).toHaveLength(1);
    },
  );
});

describe("invalid spool-record fixtures", () => {
  const invalid = fixtures("invalid");
  const python = runPython(
    PY_FRAMES,
    invalid.map(([, path]) => path),
  ) as any[];

  it.each(invalid.map(([name, path], index) => [name, path, index] as const))(
    "%s: the TypeScript reader decides as Python's valid_header does",
    (_name, path, index) => {
      const doc = load(path);
      expect(validHeader(doc, blobLength(doc))).toBe(python[index].valid);
    },
  );

  it("refuses the body-bound fixtures before writing (R6)", () => {
    const over = invalid.filter(([name]) => name === "spool-record-exchange-261");
    expect(over).toHaveLength(1);
    expect(overBound(load(over[0]![1]))).toBe(true);
    expect(
      overBound(load(fixtures("valid").find(([n]) => n === "spool-record-exchange-260")![1])),
    ).toBe(false);
  });
});

describe("spool-bytes-v1 vectors", () => {
  it.each(cases(VECTORS.records))("record %s: frame bytes equal Python's", (_name, vector) => {
    const bodies = (vector.bodies_hex as string[]).map((h) => Buffer.from(h, "hex"));
    expect(hex(frame(vector.header, bodies))).toBe(vector.frame_hex);
    const { doc, blob } = unframe(Buffer.from(vector.frame_hex, "hex"));
    expect(norm(doc)).toEqual(norm(vector.header));
    expect(blob.toString("hex")).toBe(bodies.map((b) => b.toString("hex")).join(""));
  });

  it.each(cases(VECTORS.batches))("batch %s: FWSPOOLB bytes equal Python's", (_name, vector) => {
    const records = (vector.records as string[]).map(vectorRecord);
    const pieces = batchFrame(records.map(({ doc, bodies }) => frame(doc, bodies)));
    expect(hex(pieces)).toBe(vector.batch_hex);
    expect(pieces[0]!.subarray(0, 8).equals(BATCH_MAGIC)).toBe(true);
    const read = unframeAll(Buffer.from(vector.batch_hex, "hex"));
    expect(read.map(({ doc }) => norm(doc))).toEqual(records.map(({ doc }) => norm(doc)));
  });

  it.each(cases(VECTORS.sealed))("sealed %s: FWSPENC1 bytes equal Python's", (_name, vector) => {
    expect(spoolKeyId(KEY)).toBe(vector.key_id);
    const plain = Buffer.from(vector.plain_hex, "hex");
    const nonce = Buffer.from(vector.nonce_hex, "hex");
    const sealed = seal(vector.basename, [plain], KEY, vector.key_id, nonce);
    expect(hex(sealed)).toBe(vector.sealed_hex);
    const opened = unseal(
      Buffer.from(vector.sealed_hex, "hex"),
      vector.basename,
      KEY,
      vector.key_id,
    );
    expect(opened.toString("hex")).toBe(vector.plain_hex);
    // The sealed plaintext is itself a valid record or batch file.
    expect(unframeAll(opened).length).toBeGreaterThan(0);
  });

  it("seals in pieces exactly as in one buffer", () => {
    const vector = VECTORS.sealed[0];
    const plain = Buffer.from(vector.plain_hex, "hex");
    const nonce = Buffer.from(vector.nonce_hex, "hex");
    const split = [plain.subarray(0, 7), plain.subarray(7, 100), plain.subarray(100)];
    expect(hex(seal(vector.basename, split, KEY, vector.key_id, nonce))).toBe(vector.sealed_hex);
  });

  it.each(cases(VECTORS.refused))("refused %s", (_name, vector) => {
    const sealed = VECTORS.sealed.find((s: any) => s.name === vector.sealed);
    const data = Buffer.from(sealed.sealed_hex, "hex");
    if (vector.error === "corrupt") {
      expect(() => unseal(data, vector.opened_as, KEY, sealed.key_id)).toThrow(CorruptRecordError);
    } else {
      expect(vector.error).toBe("undecryptable");
      const key = Buffer.from(vector.key_hex, "hex");
      expect(spoolKeyId(key)).toBe(vector.key_id);
      expect(() => unseal(data, sealed.basename, key, vector.key_id)).toThrow(
        UndecryptableRecordError,
      );
      expect(() => unseal(data, sealed.basename, undefined, undefined)).toThrow(
        UndecryptableRecordError,
      );
    }
  });
});

describe("frame and envelope edge cases", () => {
  const { doc, bodies } = vectorRecord("exchange");
  const good = Buffer.concat(frame(doc, bodies));

  it("a flipped byte anywhere in a frame is corrupt", () => {
    for (const at of [0, 9, 20, good.length - 40, good.length - 1]) {
      const bad = Buffer.from(good);
      bad[at]! ^= 1;
      expect(() => unframe(bad)).toThrow(CorruptRecordError);
    }
  });

  it("a truncated frame is corrupt; a bad digest keeps the parsed header", () => {
    for (const length of [0, 8, 43, 44, good.length - 1]) {
      expect(() => unframe(good.subarray(0, length))).toThrow(CorruptRecordError);
    }
    const bad = Buffer.from(good);
    bad[bad.length - 1]! ^= 1;
    try {
      unframe(bad);
      expect.unreachable();
    } catch (error) {
      expect(norm((error as CorruptRecordError).doc)).toEqual(norm(doc));
    }
  });

  it("body ranges that do not cover the blob exactly are corrupt", () => {
    expect(() => unframe(Buffer.concat(frame(doc, [...bodies, Buffer.from("x")])))).toThrow(
      CorruptRecordError,
    );
    expect(() => unframe(Buffer.concat(frame(doc, [bodies[0]!])))).toThrow(CorruptRecordError);
  });

  it("a batch with a bad count, a corrupt member or a bad digest carries the parsed headers", () => {
    const record = vectorRecord("record");
    const pieces = batchFrame([frame(doc, bodies), frame(record.doc, record.bodies)]);
    const batch = Buffer.concat(pieces);
    const wrongCount = Buffer.from(batch);
    wrongCount.writeUInt32BE(3, 8);
    expect(() => unframeAll(wrongCount)).toThrow(CorruptRecordError);
    const badDigest = Buffer.from(batch);
    badDigest[badDigest.length - 1]! ^= 1;
    try {
      unframeAll(badDigest);
      expect.unreachable();
    } catch (error) {
      expect((error as CorruptRecordError).docs).toHaveLength(2);
    }
    expect(() => unframeAll(Buffer.concat(batchFrame([])))).toThrow(CorruptRecordError);
  });

  it("with a key, a plaintext record is a downgrade: PlaintextRecordError with its header", () => {
    try {
      unseal(good, "x.rec", KEY, spoolKeyId(KEY));
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(PlaintextRecordError);
      expect(norm((error as PlaintextRecordError).doc)).toEqual(norm(doc));
    }
    expect(unseal(good, "x.rec", undefined, undefined).equals(good)).toBe(true);
  });

  it("an envelope too short for nonce and tag is corrupt; a tampered one is corrupt", () => {
    const kid = spoolKeyId(KEY);
    const sealed = Buffer.concat(seal("a.rec", [good], KEY, kid));
    expect(() => unseal(sealed.subarray(0, 8 + 12 + 12 + 15), "a.rec", KEY, kid)).toThrow(
      CorruptRecordError,
    );
    const tampered = Buffer.from(sealed);
    tampered[40]! ^= 1;
    expect(() => unseal(tampered, "a.rec", KEY, kid)).toThrow(CorruptRecordError);
    expect(unseal(sealed, "a.rec", KEY, kid).equals(good)).toBe(true);
    expect(spoolKeyId(OTHER_KEY)).not.toBe(kid);
  });

  it("a fresh nonce per seal", () => {
    const kid = spoolKeyId(KEY);
    const a = seal("a.rec", [good], KEY, kid);
    const b = seal("a.rec", [good], KEY, kid);
    expect(a[2]!.equals(b[2]!)).toBe(false);
  });

  it("record names sort in drain order", () => {
    expect(recordName(1791331200000000000n, 4242, 7)).toBe(
      "01791331200000000000-0000004242-000000000007.rec",
    );
    expect(recordName(7, 1, 0) < recordName(7, 1, 10)).toBe(true);
    expect(recordName(7, 9, 0) < recordName(8, 1, 0)).toBe(true);
  });
});
