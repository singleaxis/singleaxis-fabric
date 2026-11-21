// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 unit 055-t5 (§9.5): a Python process reads a live TypeScript registration as
// live and a killed one as an orphan, and the reverse; the mirror holds the next
// sequence after SIGKILL, including positions allocated by attached worker isolates; a
// forced epoch collision across the two languages redraws. Every process here is real
// and every kill is SIGKILL, so nothing depends on cleanup running.
import { createHash } from "node:crypto";
import { readFileSync, rmSync } from "node:fs";
import { join } from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import type { NativeAddon } from "../../../src/wire/native.js";
import {
  EPOCHS_DIR,
  ORPHAN_SUFFIX,
  decode,
  encode,
  epochName,
  orphanBeat,
  register,
  scanOrphans,
} from "../../../src/wire/registration.js";
import { WireRuntime, createRuntimeShared } from "../../../src/wire/runtime.js";
import {
  type Native,
  PY_HOLD,
  PY_SCAN,
  type Running,
  bundleHolder,
  native,
  pythonWithFabric,
  runPython,
  sourceId,
  spoolDir,
  start,
} from "./helpers.js";

let lib: Native;
let addon: NativeAddon;
let holder: { file: string; cleanup(): void };
const dirs: string[] = [];
const running: Running[] = [];

beforeAll(() => {
  pythonWithFabric(); // fails here, with the fix, when no Python can import fabric
  lib = native();
  addon = lib.addon;
  holder = bundleHolder();
}, 120_000);
afterAll(() => {
  holder?.cleanup();
  lib?.build.cleanup();
});
afterEach(async () => {
  for (const child of running.splice(0)) await child.kill();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function spool(): string {
  const dir = spoolDir();
  dirs.push(dir);
  return dir;
}

/** A Node process registered on `dir` that allocated `count` (+ workers × perWorker). */
async function tsHolder(
  dir: string,
  source: string,
  count: number,
  workers = 0,
  perWorker = 0,
  epoch?: bigint,
): Promise<Running> {
  const args = [
    holder.file,
    lib.build.dir,
    lib.digest,
    dir,
    source,
    String(count),
    String(workers),
    String(perWorker),
    ...(epoch === undefined ? [] : [String(epoch)]),
  ];
  const child = await start(process.execPath, args);
  running.push(child);
  return child;
}

async function pyHolder(dir: string, source: string, count: number, epoch?: bigint) {
  const args = ["-c", PY_HOLD, dir, source, String(count)];
  if (epoch !== undefined) args.push(String(epoch));
  const child = await start(pythonWithFabric(), args, true);
  running.push(child);
  return child;
}

function readReg(dir: string, epoch: bigint, suffix = ".reg") {
  return decode(readFileSync(join(dir, EPOCHS_DIR, epochName(epoch, suffix))));
}

/** Python's `encode` and `decode` over the cases on stdin (exact integers as strings). */
const PY_CODEC = `
import json, sys
from fabric.wire import _registration as reg
cases = json.loads(sys.stdin.read())
encoded = []
for c in cases["encode"]:
    try:
        data = reg.encode(int(c["epoch"]), c["source"], pid=c["pid"],
                          registered_at_unix_nano=int(c["at"]))
        encoded.append(data.hex())
    except ValueError:
        encoded.append(None)
decoded = []
for blob in cases["decode"]:
    f = reg.decode(bytes.fromhex(blob))
    decoded.append(None if f is None else [str(f["epoch"]), f["pid"],
                   str(f["registered_at_unix_nano"]), f["source_id"],
                   str(f["next_sequence"]), f["final"]])
print(json.dumps({"encoded": encoded, "decoded": decoded}))
`;

function seeded(seed: bigint): (limit: bigint) => bigint {
  let state = seed;
  return (limit) => {
    state = (state * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
    return (state >> 1n) % limit;
  };
}

describe("the file, Python against TypeScript", () => {
  it("encodes and decodes byte-identically beyond the ASCII vectors", () => {
    const random = seeded(0x055_75n);
    // ASCII, 2-, 3- and 4-byte characters, a byte-order mark, lone surrogates
    // (surrogatepass on the way in) and a noncharacter.
    const pieces = ["s", "-", "a", "7", "é", "中", "😀", "﻿", "\ud800", "\udfff", "￾"];
    const encodeCases: { epoch: string; source: string; pid: number; at: string }[] = [];
    for (let n = 0; n < 400; n++) {
      let source = "";
      const length = Number(random(70n));
      for (let i = 0; i < length; i++) source += pieces[Number(random(BigInt(pieces.length)))];
      const edge = [1n, (1n << 63n) - 1n, 0n, 1n << 63n][n % 16];
      encodeCases.push({
        epoch: String(edge ?? 1n + random((1n << 63n) - 1n)),
        source,
        pid: Number(random(1n << 32n)),
        at: String(random(1n << 64n)),
      });
    }
    const valid: Buffer[] = [];
    const tsEncoded = encodeCases.map((c) => {
      try {
        const data = encode(BigInt(c.epoch), c.source, c.pid, BigInt(c.at));
        valid.push(data);
        return data.toString("hex");
      } catch (error) {
        expect(error).toBeInstanceOf(RangeError);
        return null;
      }
    });
    expect(valid.length).toBeGreaterThan(200);
    expect(tsEncoded.filter((h) => h === null).length).toBeGreaterThan(20);

    // Decode: valid files, then files whose header is re-digested after a change, so the
    // UTF-8, length and version checks are what decides.
    const reseal = (data: Buffer): Buffer => {
      createHash("sha256").update(data.subarray(0, 256)).digest().copy(data, 4064);
      return data;
    };
    const utf8 = [
      [0xff],
      [0x80],
      [0xc0, 0x80],
      [0xc2],
      [0xe2, 0x82],
      [0xed, 0xa0, 0x80],
      [0xed, 0xbf, 0xbf],
      [0xf4, 0x90, 0x80, 0x80],
      [0xf8, 0x88, 0x80, 0x80, 0x80],
      [0xef, 0xbb, 0xbf],
      [0xef, 0xbf, 0xbe],
      [0xf0, 0x9f, 0x98, 0x80],
      [0x00],
    ];
    const blobs: Buffer[] = [];
    valid.slice(0, 60).forEach((base, n) => {
      blobs.push(base);
      const tail = Buffer.from(base);
      tail.writeBigUInt64LE(random(1n << 63n), 256);
      tail[264] = Number(random(256n));
      blobs.push(tail);
      // Odd cases put the bytes first: a leading byte-order mark must survive decoding.
      const raw = utf8[n % utf8.length]!;
      const bytes = n % 2 === 1 ? [...raw, 0x73, 0x2d] : [0x73, 0x2d, ...raw];
      const text = Buffer.from(base);
      text.fill(0, 32, 256);
      text.writeUInt16LE(bytes.length, 32);
      Buffer.from(bytes).copy(text, 34);
      blobs.push(reseal(text));
      const long = Buffer.from(base);
      long.writeUInt16LE(160 + (n % 2), 32);
      blobs.push(reseal(long));
      const version = Buffer.from(base);
      version.writeUInt32LE(n % 3, 8);
      blobs.push(reseal(version));
      const flipped = Buffer.from(base);
      flipped[Number(random(256n))]! ^= 1;
      blobs.push(flipped);
      blobs.push(base.subarray(0, Number(random(4096n))));
    });

    const python = runPython(
      PY_CODEC,
      [],
      JSON.stringify({ encode: encodeCases, decode: blobs.map((b) => b.toString("hex")) }),
    );
    expect(python.encoded).toEqual(tsEncoded);
    const tsDecoded = blobs.map((blob) => {
      const f = decode(blob);
      return f === null
        ? null
        : [
            String(f.epoch),
            f.pid,
            String(f.registeredAtUnixNano),
            f.sourceId,
            String(f.nextSequence),
            f.final,
          ];
    });
    expect(python.decoded).toEqual(tsDecoded);
    // Both outcomes occur, so the comparison is not trivially all-null or all-valid.
    expect(tsDecoded.filter((d) => d === null).length).toBeGreaterThan(200);
    expect(tsDecoded.filter((d) => d !== null).length).toBeGreaterThan(20);
  }, 60_000);
});

describe("a Python drainer and a TypeScript writer", () => {
  it("reads a live TypeScript registration as live, and a killed one as an orphan", async () => {
    const dir = spool();
    const source = sourceId("1");
    const node = await tsHolder(dir, source, 5);
    expect(node.first.status).toBe("registered");
    const epoch = BigInt(node.first.epoch);
    const live = runPython(PY_SCAN, [dir]);
    expect(live.orphans).toEqual([]); // the writer holds its flock: alive
    const name = epochName(epoch);
    expect(Object.keys(live.files)).toEqual([name]);
    expect(BigInt(live.files[name].epoch)).toBe(epoch);
    expect(live.files[name].source_id).toBe(source);
    expect(BigInt(live.files[name].next_sequence)).toBe(5n);
    expect(Number(live.files[name].pid)).toBe(node.first.pid);
    expect(live.files[name].final).toBe(false);
    await node.kill();
    const dead = runPython(PY_SCAN, [dir]);
    expect(dead.orphans.map((o: unknown[]) => o.map(String))).toEqual([
      [source, String(epoch), "5"],
    ]);
    expect(Object.keys(dead.files)).toEqual([epochName(epoch, ORPHAN_SUFFIX)]);
    // Declared once: the next Python scan finds nothing new.
    expect(runPython(PY_SCAN, [dir]).orphans).toEqual([]);
  }, 60_000);

  it("keeps the next sequence in the mirror after SIGKILL, across attached isolates", async () => {
    const dir = spool();
    const source = sourceId("2");
    // 3 positions from the installing thread, then 8 isolates × 2,000 concurrently.
    const node = await tsHolder(dir, source, 3, 8, 2000);
    expect(node.first.status).toBe("registered");
    expect(node.first.next).toBe(String(3 + 8 * 2000));
    const epoch = BigInt(node.first.epoch);
    await node.kill();
    expect(readReg(dir, epoch)?.nextSequence).toBe(BigInt(3 + 8 * 2000));
    const orphans = scanOrphans({ addon, spoolDir: dir });
    expect(orphans).toEqual([{ sourceId: source, epoch, nextSequence: 16003n }]);
    expect(orphanBeat(orphans[0]!)?.sequence).toBe(16002n); // the last allocated position
    expect(runPython(PY_SCAN, [dir]).files[epochName(epoch, ORPHAN_SUFFIX)].next_sequence).toBe(
      16003,
    );
  }, 60_000);
});

describe("a TypeScript drainer and a Python writer", () => {
  it("reads a live Python registration as live, and a killed one as an orphan", async () => {
    const dir = spool();
    const source = sourceId("3");
    const py = await pyHolder(dir, source, 4);
    expect(py.first.status).toBe("registered");
    const epoch = BigInt(py.first.epoch);
    expect(scanOrphans({ addon, spoolDir: dir })).toEqual([]); // alive
    expect(readReg(dir, epoch)).toMatchObject({ epoch, sourceId: source, nextSequence: 4n });
    await py.kill();
    expect(scanOrphans({ addon, spoolDir: dir })).toEqual([
      { sourceId: source, epoch, nextSequence: 4n },
    ]);
    expect(readReg(dir, epoch, ORPHAN_SUFFIX)?.final).toBe(false);
    expect(scanOrphans({ addon, spoolDir: dir })).toEqual([]); // declared once
  }, 60_000);
});

describe("a forced epoch collision across the two languages", () => {
  it("redraws a TypeScript epoch that a live Python writer holds", async () => {
    const dir = spool();
    const py = await pyHolder(dir, sourceId("4"), 1);
    const taken = BigInt(py.first.epoch);
    const node = await tsHolder(dir, sourceId("5"), 2, 0, 0, taken);
    expect(node.first.status).toBe("registered");
    expect(BigInt(node.first.drawn)).toBe(taken);
    expect(BigInt(node.first.epoch)).not.toBe(taken);
    expect(node.first.runtimeEpoch).toBe(node.first.epoch); // the runtime adopted it
    expect(readReg(dir, BigInt(node.first.epoch))?.nextSequence).toBe(2n);
    expect(readReg(dir, taken)?.sourceId).toBe(sourceId("4"));
  }, 60_000);

  it("makes a Python writer redraw an epoch a live TypeScript writer holds", async () => {
    const dir = spool();
    const runtime = new WireRuntime(
      createRuntimeShared({ maxInflightBytes: 4 * 1024 * 1024, queueMaxItems: 4, maxExchanges: 4 }),
      "installer",
    );
    const mine = register({ addon, spoolDir: dir, sourceId: sourceId("6"), runtime });
    expect(mine.status).toBe("registered");
    const py = await pyHolder(dir, sourceId("7"), 1, mine.epoch);
    expect(py.first.status).toBe("registered");
    expect(BigInt(py.first.drawn)).toBe(mine.epoch);
    expect(BigInt(py.first.epoch)).not.toBe(mine.epoch);
    // The Python scan never takes the live TypeScript epoch for an orphan.
    expect(runPython(PY_SCAN, [dir]).orphans).toEqual([]);
    mine.final();
    mine.close();
  }, 60_000);
});
