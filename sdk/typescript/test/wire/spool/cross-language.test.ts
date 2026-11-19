// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 unit 055-t7 (§9.5): Python reads the frames a TypeScript process wrote and
// TypeScript reads Python's (single records and a batch file, plaintext and sealed); the
// records survive SIGKILL of their writer; two real processes (Node and Node, Node and
// Python) share one bound. Every process here is real; nothing is mocked.
import { readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { encodeJson } from "../../../src/wire/codec.js";
import type { NativeAddon } from "../../../src/wire/native.js";
import { ENVELOPE_MAGIC } from "../../../src/wire/spool-codec.js";
import { Spool, accounted } from "../../../src/wire/spool.js";
import { norm } from "../helpers.js";
import {
  KEY,
  type Lines,
  type Native,
  bundleFixture,
  cleanupDirs,
  entryOf,
  native,
  pythonEnv,
  pythonWithSpoolKey,
  read,
  runPython,
  sized,
  spawnLines,
  spoolDir,
} from "./helpers.js";

let lib: Native;
let addon: NativeAddon;
let writer: { file: string; cleanup(): void };
const running: Lines[] = [];
const spools: Spool[] = [];
const scratch: string[] = [];

beforeAll(() => {
  pythonWithSpoolKey(); // fails here, with the fix, when Python cannot seal records
  lib = native();
  addon = lib.addon;
  writer = bundleFixture("writer");
}, 120_000);
afterAll(() => {
  writer?.cleanup();
  lib?.build.cleanup();
});
afterEach(async () => {
  for (const child of running.splice(0)) await child.kill();
  for (const spool of spools.splice(0)) spool.close();
  for (const file of scratch.splice(0)) rmSync(file, { force: true });
  cleanupDirs();
});

function scratchFile(name: string, content: string): string {
  const file = join(tmpdir(), `f055-t7-${process.pid}-${Date.now()}-${name}`);
  writeFileSync(file, content, { mode: 0o600 });
  scratch.push(file);
  return file;
}

function open(dir: string, maxBytes: number, key?: Buffer): Spool {
  const spool = new Spool(dir, { maxBytes, addon, ...(key === undefined ? {} : { key }) });
  spools.push(spool);
  return spool;
}

const hexKey = (key?: Buffer): string => (key === undefined ? "-" : key.toString("hex"));

/** Python: every pending file of the spool read by Python's drainer, and its ledger total. */
const PY_READ = `
import json, sys
from fabric.wire._spool import CorruptRecordError, Spool, UndecryptableRecordError, unframe_all
key = None if sys.argv[3] == "-" else bytes.fromhex(sys.argv[3])
spool = Spool(sys.argv[1], int(sys.argv[2]), key=key)
try:
    files = []
    for name in spool.names():
        try:
            records = unframe_all(spool.read(name))
            files.append({"name": name, "records": [
                {"doc": doc, "blob": bytes(blob).hex()} for doc, blob in records]})
        except UndecryptableRecordError:
            files.append({"name": name, "error": "undecryptable"})
        except CorruptRecordError:
            files.append({"name": name, "error": "corrupt"})
    print(json.dumps({"files": files, "bytes": spool.bytes}))
finally:
    spool.release()
`;

/** Python: write each entry as its own record, then the last two as one batch file. */
const PY_WRITE = `
import json, sys
from fabric.wire._spool import Spool
key = None if sys.argv[3] == "-" else bytes.fromhex(sys.argv[3])
spool = Spool(sys.argv[1], int(sys.argv[2]), key=key)
entries = json.load(open(sys.argv[4], encoding="utf-8"))
pairs = [(e["doc"], [bytes.fromhex(h) for h in e["bodies_hex"]], e.get("reserve", False))
         for e in entries]
names = [spool.write(doc, bodies, reserve=reserve) for doc, bodies, reserve in pairs]
group = spool.write_group([(doc, bodies) for doc, bodies, _ in pairs[:2]])
spool.release()
print(json.dumps({"names": names, "group": group}))
`;

/** Python: wait for the go file, then write 1 KiB records until 50 in a row are refused. */
const PY_FILL = `
import json, os, sys, time
from fabric.wire._spool import Spool
key = None if sys.argv[3] == "-" else bytes.fromhex(sys.argv[3])
spool = Spool(sys.argv[1], int(sys.argv[2]), key=key)
template = json.load(open(sys.argv[4], encoding="utf-8"))
print(json.dumps({"ready": True}), flush=True)
while not os.path.exists(sys.argv[5]):
    time.sleep(0.001)
written = refused = errors = streak = max_shared = 0
while streak < 50:
    try:
        name = spool.write(template["doc"], [b"b" * 1024])
    except OSError:
        errors += 1
        streak += 1
        continue
    if name is None:
        refused += 1
        streak += 1
        time.sleep(0.001)
    else:
        written += 1
        streak = 0
        time.sleep(0.0005)  # paced, as a model-calling agent is: the lock is not fair
    max_shared = max(max_shared, spool.shared_bytes)
spool.release()
print(json.dumps({"written": written, "refused": refused, "errors": errors,
                  "maxShared": max_shared}), flush=True)
`;

const ENTRIES = [
  { ...entryOf("exchange"), reserve: false },
  { ...entryOf("record"), reserve: false },
  { ...entryOf("loss"), reserve: true },
  { ...entryOf("segment_seal"), reserve: true },
];

function entriesFile(): string {
  return scratchFile(
    "entries.json",
    encodeJson(
      ENTRIES.map(({ doc, bodies, reserve }) => ({
        doc,
        bodies_hex: bodies.map((body) => body.toString("hex")),
        reserve,
      })),
    ),
  );
}

/** The fields a writer supplied (the spool adds schema, order and time). */
function written(doc: any): unknown {
  const rest = { ...doc };
  for (const key of ["schema_version", "order", "written_at_unix_nano"]) delete rest[key];
  return norm(rest);
}

function tsWriter(
  dir: string,
  maxBytes: number,
  key: Buffer | undefined,
  mode: string,
  arg: string,
): Lines {
  const child = spawnLines(
    process.execPath,
    [writer.file, lib.build.dir, lib.digest, dir, String(maxBytes), hexKey(key), mode, arg],
    process.env,
  );
  running.push(child);
  return child;
}

describe("Python reads TypeScript frames", () => {
  for (const key of [undefined, KEY]) {
    it(`${key === undefined ? "plaintext" : "sealed"}: every record, header and body, after SIGKILL of the writer`, async () => {
      const dir = spoolDir();
      const child = tsWriter(dir, 1 << 20, key, "hold", entriesFile());
      const { names } = await child.next();
      expect(names).toHaveLength(ENTRIES.length);
      await child.kill(); // SIGKILL: the records are on disk already
      for (const name of names) {
        expect(read(join(dir, name)).subarray(0, 8).equals(ENVELOPE_MAGIC)).toBe(key !== undefined);
      }
      const python = runPython(PY_READ, [dir, String(1 << 20), hexKey(key)]);
      expect(python.files.map((file: any) => file.name)).toEqual(names);
      python.files.forEach((file: any, index: number) => {
        expect(file.error).toBeUndefined();
        expect(file.records).toHaveLength(1);
        expect(written(file.records[0].doc)).toEqual(norm(ENTRIES[index]!.doc));
        expect(file.records[0].blob).toBe(Buffer.concat(ENTRIES[index]!.bodies).toString("hex"));
      });
      // Both languages charge the directory the same bytes.
      const drainer = open(dir, 1 << 20, key);
      expect(python.bytes).toBe(drainer.bytes);
      expect(drainer.tryLock()).toBe(true);
      const scan = drainer.recover();
      expect(scan.files.map((file) => norm(file.records[0]!.doc))).toEqual(
        python.files.map((file: any) => norm(file.records[0].doc)),
      );
    }, 60_000);
  }

  it("Python keeps a record sealed under another key pending, as TypeScript does", async () => {
    const dir = spoolDir();
    const child = tsWriter(dir, 1 << 20, Buffer.alloc(32, 7), "hold", entriesFile());
    const { names } = await child.next();
    await child.kill();
    const python = runPython(PY_READ, [dir, String(1 << 20), hexKey(KEY)]);
    expect(python.files.map((file: any) => file.error)).toEqual(names.map(() => "undecryptable"));
    const drainer = open(dir, 1 << 20, KEY);
    drainer.tryLock();
    expect(drainer.recover().undecryptable).toEqual(names);
  }, 60_000);
});

describe("TypeScript reads Python frames", () => {
  for (const key of [undefined, KEY]) {
    it(`${key === undefined ? "plaintext" : "sealed"}: single records and a batch file`, () => {
      const dir = spoolDir();
      const out = runPython(PY_WRITE, [dir, String(1 << 20), hexKey(key), entriesFile()]);
      expect(out.names).toHaveLength(ENTRIES.length);
      expect(typeof out.group[0]).toBe("string");
      expect(out.group[0]).toBe(out.group[1]); // one batch file holds both
      const spool = open(dir, 1 << 20, key);
      expect(spool.tryLock()).toBe(true);
      const scan = spool.recover();
      expect(scan.quarantined).toEqual([]);
      expect(scan.undecryptable).toEqual([]);
      const byName = new Map(scan.files.map((file) => [file.name, file.records]));
      out.names.forEach((name: string, index: number) => {
        const records = byName.get(name)!;
        expect(records).toHaveLength(1);
        expect(written(records[0]!.doc)).toEqual(norm(ENTRIES[index]!.doc));
        expect(records[0]!.blob.equals(Buffer.concat(ENTRIES[index]!.bodies))).toBe(true);
      });
      const batch = byName.get(out.group[0])!;
      expect(batch.map((record) => written(record.doc))).toEqual([
        norm(ENTRIES[0]!.doc),
        norm(ENTRIES[1]!.doc),
      ]);
      expect(batch[1]!.blob.equals(Buffer.concat(ENTRIES[1]!.bodies))).toBe(true);
      // The same bytes on disk as Python counts them, and the order Python drains.
      const python = runPython(PY_READ, [dir, String(1 << 20), hexKey(key)]);
      expect(scan.files.map((file) => file.name)).toEqual(
        python.files.map((file: any) => file.name),
      );
      spool.rescan();
      expect(spool.bytes).toBe(python.bytes);
    }, 60_000);
  }
});

describe("two real processes share one bound", () => {
  const BOUND = 512 * 1024;

  async function race(start: () => Lines[], dir: string): Promise<any[]> {
    const go = join(dir, "..", "go");
    const children = start();
    for (const child of children) expect(await child.next()).toEqual({ ready: true });
    writeFileSync(go, "");
    const results = [];
    for (const child of children) results.push(await child.next());
    return results;
  }

  function onDisk(dir: string): { total: number; records: number } {
    let total = 0;
    let records = 0;
    for (const name of readdirSync(dir)) {
      const size = accounted(name, read(join(dir, name)).length);
      if (size !== undefined) total += size;
      if (name.endsWith(".rec") && !name.startsWith(".")) records += 1;
    }
    return { total, records };
  }

  it("Node and Node: never more than the one bound on disk", async () => {
    const dir = spoolDir();
    open(dir, BOUND).close(); // create the directory
    const template = scratchFile("template.json", encodeJson({ doc: sized(1024).doc }));
    process.env.FABRIC_SPOOL_ENTRY = template;
    const results = await race(
      () => [0, 1].map(() => tsWriter(dir, BOUND, undefined, "fill", join(dir, "..", "go"))),
      dir,
    );
    const { total, records } = onDisk(dir);
    expect(records).toBe(results.reduce((sum, r) => sum + r.written, 0));
    expect(total).toBeLessThanOrEqual(BOUND);
    expect(records).toBeGreaterThan(0);
    const size = total / records;
    expect(BOUND - total).toBeLessThan(size); // full: the bound, not one budget per writer
    for (const r of results) {
      expect(r.errors).toBe(0);
      expect(r.maxShared).toBeLessThanOrEqual(BOUND);
      expect(r.written).toBeGreaterThan(0); // both writers took part
    }
  }, 60_000);

  it("Node and Python: never more than the one bound on disk", async () => {
    const dir = spoolDir();
    open(dir, BOUND, KEY).close();
    const template = scratchFile("template.json", encodeJson({ doc: sized(1024).doc }));
    process.env.FABRIC_SPOOL_ENTRY = template;
    const go = join(dir, "..", "go");
    const results = await race(() => {
      const python = spawnLines(
        pythonWithSpoolKey(),
        ["-c", PY_FILL, dir, String(BOUND), hexKey(KEY), template, go],
        pythonEnv(),
      );
      running.push(python);
      return [tsWriter(dir, BOUND, KEY, "fill", go), python];
    }, dir);
    const { total, records } = onDisk(dir);
    expect(records).toBe(results.reduce((sum, r) => sum + r.written, 0));
    expect(total).toBeLessThanOrEqual(BOUND);
    expect(BOUND - total).toBeLessThan(total / records);
    for (const r of results) {
      expect(r.errors).toBe(0);
      expect(r.written).toBeGreaterThan(0); // both writers took part
    }
    // And every record either language wrote is readable by the other.
    const python = runPython(PY_READ, [dir, String(BOUND), hexKey(KEY)]);
    expect(python.files.every((file: any) => file.error === undefined)).toBe(true);
    const drainer = open(dir, BOUND, KEY);
    drainer.tryLock();
    const scan = drainer.recover();
    expect(scan.files).toHaveLength(records);
    expect(scan.quarantined).toEqual([]);
  }, 60_000);
});
