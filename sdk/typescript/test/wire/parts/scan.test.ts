// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Split parity (spec 055 §5, unit 055-t15): the byte-offset scan equals Python's
 * `find_parts` on the shared split fixtures (`test/wire/fixtures/split-parts.json`,
 * generated from `wire/_protect.py` by `scripts/contracts/generate_ts_wire_vectors.py`)
 * and reproduces the content-v2 split-reassembly contract vector.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  MAX_PARTS_PER_SIDE,
  findParts,
  partObjectId,
  skeletonOf,
  sniffMediaType,
} from "../../../src/wire/parts.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "../../../../..");
const FIXTURE = JSON.parse(readFileSync(join(HERE, "../fixtures/split-parts.json"), "utf8")) as {
  max_parts_per_side: number;
  cases: {
    name: string;
    body_base64: string;
    part_min_bytes: number;
    parts: [number, number, string][] | null;
    skeleton_sha256?: string;
    skeleton_byte_length?: number;
  }[];
  sniff: { base64: string; declared: string | null; media_type: string }[];
  part_object_ids: { skeleton_id: string; index: number; object_id: string }[];
};
const sha = (data: Uint8Array): string =>
  "sha256:" + createHash("sha256").update(data).digest("hex");

describe("the byte-offset scan equals Python's find_parts", () => {
  it("covers the shared fixture's edge cases and seeded random bodies", () => {
    expect(FIXTURE.cases.length).toBeGreaterThanOrEqual(80);
    expect(MAX_PARTS_PER_SIDE).toBe(FIXTURE.max_parts_per_side);
  });

  for (const c of FIXTURE.cases) {
    it(c.name, () => {
      const body = Buffer.from(c.body_base64, "base64");
      const found = findParts(body, c.part_min_bytes);
      expect(found?.map((p) => [p.start, p.end, p.mediaType]) ?? null).toEqual(c.parts);
      if (found !== null) {
        const skeleton = skeletonOf(body, found);
        expect(sha(skeleton)).toBe(c.skeleton_sha256);
        expect(skeleton.byteLength).toBe(c.skeleton_byte_length);
      }
    });
  }

  it("scans a plain Uint8Array (not a Buffer) and an offset view the same way", () => {
    const c = FIXTURE.cases.find((x) => x.name === "image and audio")!;
    const body = Buffer.from(c.body_base64, "base64");
    const copy = new Uint8Array(body);
    const framed = new Uint8Array(body.byteLength + 7);
    framed.set(body, 7);
    for (const view of [copy, framed.subarray(7)]) {
      expect(findParts(view, c.part_min_bytes)?.map((p) => [p.start, p.end, p.mediaType])).toEqual(
        c.parts,
      );
    }
  });

  it("sniffs media types as Python does (magic numbers, declared types, padding errors)", () => {
    for (const s of FIXTURE.sniff) {
      expect(
        sniffMediaType(Buffer.from(s.base64, "latin1"), s.declared ?? undefined),
        s.base64,
      ).toBe(s.media_type);
    }
  });

  it("derives part object ids as Python's part_object_id", () => {
    for (const p of FIXTURE.part_object_ids) {
      expect(partObjectId(p.skeleton_id, p.index)).toBe(p.object_id);
    }
  });
});

describe("the content-v2 split-reassembly contract vector", () => {
  it("the scan finds the vector's ranges and its skeleton", () => {
    const vector = JSON.parse(
      readFileSync(
        join(REPO, "contracts/content/v2/valid/split-reassembly-retain-original.json"),
        "utf8",
      ),
    ) as {
      original: { byte_length: number; sha256: string };
      objects: { descriptor: Record<string, any>; base64: string }[];
    };
    const [skeletonObject, ...partObjects] = vector.objects;
    const skeleton = Buffer.from(skeletonObject!.base64, "base64");
    const parts = partObjects
      .map((o) => ({
        range: o.descriptor.links[0].byte_range as [number, number],
        data: Buffer.from(o.base64, "base64"),
        media: String(o.descriptor.media_type),
      }))
      .sort((a, b) => a.range[0] - b.range[0]);
    // Reassemble the original from the vector, as a reader does.
    const pieces: Buffer[] = [];
    let pos = 0;
    let consumed = 0;
    for (const part of parts) {
      const take = part.range[0] - consumed;
      pieces.push(skeleton.subarray(pos, pos + take), part.data);
      pos += take;
      consumed = part.range[1];
    }
    pieces.push(skeleton.subarray(pos));
    const original = Buffer.concat(pieces);
    expect(original.byteLength).toBe(vector.original.byte_length);
    expect(sha(original)).toBe(vector.original.sha256);

    const found = findParts(original, 50)!;
    expect(found.map((p) => [p.start, p.end, p.mediaType])).toEqual(
      parts.map((p) => [p.range[0], p.range[1], p.media]),
    );
    expect(skeletonOf(original, found)).toEqual(skeleton);
  });
});
