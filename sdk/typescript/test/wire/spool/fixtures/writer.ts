// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * A Node process that writes the wire spool as the Fabric worker would.
 *
 *   node writer.cjs <prebuilds> <sha256> <spool> <max-bytes> <key-hex|-> <mode> <arg>
 *
 * Modes:
 * - `hold <records-json-file>`: writes each `{doc, bodies_hex, reserve}` entry, prints
 *   `{"names": [...]}` and stays alive until it is killed (records survive SIGKILL);
 * - `fill <go-file>`: prints `{"ready": true}`, waits until `<go-file>` exists, then writes
 *   1 KiB exchange records until 50 writes in a row are refused, and prints
 *   `{"written": n, "refused": n, "errors": n, "maxShared": n}` and exits.
 */
import { existsSync, readFileSync } from "node:fs";
import { setInterval } from "node:timers";

import { parseJson } from "../../../../src/wire/codec.js";
import { loadNative, nativeTarget } from "../../../../src/wire/native.js";
import { Spool } from "../../../../src/wire/spool.js";

const [prebuilds, digest, dir, maxBytes, keyHex, mode, arg] = process.argv.slice(2) as string[];
const target = nativeTarget();
if (target === null) throw new Error("no native target for this platform");
const loaded = loadNative({ prebuildsDir: prebuilds, digests: { [target]: digest! } });
if (!loaded.ok) throw new Error(`${loaded.reason}: ${loaded.message}`);
const spool = new Spool(dir!, {
  maxBytes: Number(maxBytes),
  addon: loaded.addon,
  ...(keyHex === "-" ? {} : { key: Buffer.from(keyHex!, "hex") }),
});
const sleeper = new Int32Array(new SharedArrayBuffer(4));
const sleep = (ms: number): void => {
  Atomics.wait(sleeper, 0, 0, ms);
};

if (mode === "hold") {
  const entries = parseJson(readFileSync(arg!, "utf8")) as any[];
  const names = entries.map((entry) =>
    spool.write(
      entry.doc,
      (entry.bodies_hex as string[]).map((hex) => Buffer.from(hex, "hex")),
      entry.reserve === true,
    ),
  );
  process.stdout.write(JSON.stringify({ names }) + "\n");
  setInterval(() => undefined, 60_000);
} else if (mode === "fill") {
  const template = parseJson(readFileSync(process.env.FABRIC_SPOOL_ENTRY!, "utf8")) as any;
  process.stdout.write(JSON.stringify({ ready: true }) + "\n");
  while (!existsSync(arg!)) sleep(1);
  let written = 0;
  let refused = 0;
  let errors = 0;
  let maxShared = 0;
  let streak = 0;
  while (streak < 50) {
    try {
      const name = spool.write(template.doc, [Buffer.alloc(1024, 0x62)]);
      if (name === null) {
        refused += 1;
        streak += 1;
        sleep(1);
      } else {
        written += 1;
        streak = 0;
      }
    } catch {
      errors += 1;
      streak += 1;
    }
    maxShared = Math.max(maxShared, spool.sharedBytes);
  }
  process.stdout.write(JSON.stringify({ written, refused, errors, maxShared }) + "\n");
  spool.close();
} else {
  throw new Error(`unknown mode ${mode}`);
}
