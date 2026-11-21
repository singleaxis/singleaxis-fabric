// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 unit 055-t7 (§6.3, §9.5 "the no-I/O-in-hook trip-wire still passes"): every
// spool call does synchronous file I/O, so no module an application isolate loads for
// its transport hook may reach the spool. The passivity job's forbidden-work step
// (qualification/node-wire/passivity) arms trip-wires on sync fs, crypto and the rest
// while each hook runs; this test pins the import graph that keeps it green, and checks
// the spool modules themselves never run a hook-side path.
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { buildSync } from "esbuild";
import { describe, expect, it } from "vitest";

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "src", "wire");

/** The source files a bundle of `entry` reaches. */
function reached(entry: string): string[] {
  const result = buildSync({
    entryPoints: [join(SRC, entry)],
    bundle: true,
    write: false,
    metafile: true,
    platform: "node",
    format: "esm",
    logLevel: "silent",
  });
  return Object.keys(result.metafile.inputs).map((input) => relative(SRC, input));
}

describe("the spool stays off the hook path", () => {
  // The modules an application isolate loads to capture (055-t4, 055-t6).
  for (const entry of ["undici.ts", "exchange.ts", "runtime.ts", "arena.ts", "queue.ts"]) {
    it(`${entry} never imports the spool`, () => {
      const inputs = reached(entry);
      expect(inputs).toContain(entry);
      expect(inputs.filter((input) => /spool/.test(input))).toEqual([]);
    });
  }

  it("the spool modules import no transport hook or application-isolate runtime", () => {
    for (const entry of ["spool.ts", "spool-codec.ts"]) {
      const inputs = reached(entry);
      expect(
        inputs.filter((input) => /^(undici|exchange|runtime|arena|queue)\.ts$/.test(input)),
      ).toEqual([]);
    }
  });
});
