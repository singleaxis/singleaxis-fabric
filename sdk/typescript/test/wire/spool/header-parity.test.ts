// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 unit 055-t7 (§6.2): "Python reads TS frames and TS reads Python frames" needs
// both readers to accept and quarantine the same records. The fixtures pin a few dozen
// headers; this differential test mutates every valid fixture and vector header at
// random paths (removed keys, extra keys, values of every JSON type, bools as ints,
// integral floats, int64 limits, near-miss ids) and checks that TypeScript's
// `validHeader` and Python's `valid_header` give the same verdict for each one.
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { PyFloat, encodeJson, parseJson } from "../../../src/wire/codec.js";
import { validHeader } from "../../../src/wire/spool-codec.js";
import { VECTORS, fixtures, runPython } from "./helpers.js";

/** A small deterministic PRNG (mulberry32). */
function prng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const PY_VERDICTS = `
import json, sys
from fabric.wire._spool import valid_header
cases = json.load(sys.stdin)
print(json.dumps([bool(valid_header(c["doc"], c["blob"])) for c in cases]))
`;

const VALUES = (): unknown[] => [
  true,
  false,
  null,
  0,
  1,
  -1,
  new PyFloat(1),
  new PyFloat(0.5),
  "",
  "x",
  "wire",
  "records",
  "unset",
  "ok",
  "error",
  [],
  {},
  ["none"],
  2n ** 63n - 1n,
  -(2n ** 63n),
  "1".repeat(16),
  "0".repeat(16),
  "a".repeat(32),
  `sha256:${"0".repeat(64)}`,
  "00000000-0000-4000-8000-000000000000",
  `seg-${"a".repeat(32)}`,
  "é",
  [1, 2],
  [true],
  ["x"],
  { a: 1 },
];

type Path = (string | number)[];

function paths(value: unknown, prefix: Path = []): Path[] {
  const out: Path[] = [prefix];
  if (Array.isArray(value)) value.forEach((item, i) => out.push(...paths(item, [...prefix, i])));
  else if (value !== null && typeof value === "object" && !(value instanceof PyFloat)) {
    for (const [key, item] of Object.entries(value)) out.push(...paths(item, [...prefix, key]));
  }
  return out;
}

function blobOf(doc: any): number {
  try {
    const total = ((doc.bodies ?? []) as any[]).reduce((sum, body) => sum + Number(body.length), 0);
    return Number.isSafeInteger(total) && total >= 0 ? total : 0;
  } catch {
    return 0;
  }
}

function mutated(seed: number, count: number): { doc: unknown; blob: number }[] {
  const random = prng(seed);
  const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)]!;
  const bases = [
    ...fixtures("valid").map(([, path]) => parseJson(readFileSync(path, "utf8"))),
    ...(VECTORS.records as any[]).map((record) => record.header),
  ];
  const cases: { doc: unknown; blob: number }[] = [];
  for (let n = 0; n < count; n += 1) {
    const doc = parseJson(encodeJson(pick(bases))) as any;
    for (let m = 1 + Math.floor(random() * 2); m > 0; m -= 1) {
      const path = pick(paths(doc).filter((p) => p.length > 0));
      let parent = doc;
      for (const key of path.slice(0, -1)) parent = parent[key];
      const last = path[path.length - 1]!;
      const roll = random();
      if (roll < 0.25 && !Array.isArray(parent)) delete parent[last];
      else if (roll < 0.35 && !Array.isArray(parent)) parent.zz_extra = pick(VALUES());
      else parent[last] = pick(VALUES());
    }
    const blob = blobOf(doc) + (random() < 0.1 ? 1 : 0);
    // Both readers see the header as decoded from the same JSON text.
    cases.push({ doc: parseJson(encodeJson(doc)), blob });
  }
  return cases;
}

describe("validHeader equals Python's valid_header on mutated headers", () => {
  for (const seed of [7, 11, 13]) {
    it(`seed ${seed}: 2,000 headers, the same verdict for each`, () => {
      const cases = mutated(seed, 2000);
      const python = runPython(PY_VERDICTS, [], encodeJson(cases)) as boolean[];
      expect(python).toHaveLength(cases.length);
      const accepted = python.filter(Boolean).length;
      // Both outcomes are well represented, so the comparison is not one-sided.
      expect(accepted).toBeGreaterThan(cases.length / 10);
      expect(accepted).toBeLessThan(cases.length * 0.9);
      const differ = cases.flatMap((entry, index) =>
        validHeader(entry.doc, entry.blob) === python[index]
          ? []
          : [`python=${python[index]} ${encodeJson(entry.doc)} blob=${entry.blob}`],
      );
      expect(differ).toEqual([]);
    }, 120_000);
  }
});
