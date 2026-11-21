// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * A Node process that uses the spool's loss ledger as the Fabric worker does (spec 055
 * §6.3, unit 055-t16), then stays alive until it is killed (its record locks die with it).
 *
 *   node ledger-writer.cjs <prebuilds> <sha256> <spool> <mode> <json-file>
 *
 * Modes:
 * - `store`: the file is a list of ledger records; stores them in this process's slots
 *   and prints `{"stored": bool, "used": n}`;
 * - `disk-full`: the file is `{"losses": [...], "markers": [...]}`. Opens the spool on a
 *   volume where every record write fails with `ENOSPC`, records the losses (`LossTable`)
 *   and queues the markers (`MarkerQueue`), pumps them as the capture pipeline does
 *   (markers, then losses, then markers; what is left is mirrored to the ledger) and
 *   prints `{"spooled": n, "pending": [...], "mirrored": bool, "used": n}`.
 */
import { readFileSync } from "node:fs";
import { setInterval } from "node:timers";

import { encodeJson, parseJson } from "../../../../src/wire/codec.js";
import { LossLedger } from "../../../../src/wire/ledger.js";
import { LossTable } from "../../../../src/wire/loss.js";
import { MarkerQueue } from "../../../../src/wire/manifest.js";
import { loadNative, nativeTarget } from "../../../../src/wire/native.js";
import { Spool, type SpoolIo, nodeSpoolIo } from "../../../../src/wire/spool.js";
import { LedgerMirror } from "../../../../src/wire/worker.js";

const [prebuilds, digest, dir, mode, file] = process.argv.slice(2) as string[];
const target = nativeTarget();
if (target === null) throw new Error("no native target for this platform");
const loaded = loadNative({ prebuildsDir: prebuilds, digests: { [target]: digest! } });
if (!loaded.ok) throw new Error(`${loaded.reason}: ${loaded.message}`);
const input = parseJson(readFileSync(file!, "utf8")) as any;
const keep = (): void => {
  setInterval(() => undefined, 60_000);
};
const out = (value: unknown): void => {
  process.stdout.write(encodeJson(value) + "\n");
};

if (mode === "store") {
  const ledger = new LossLedger(dir!, loaded.addon);
  const stored = ledger.store(input);
  out({ stored, used: ledger.used() });
  keep();
} else if (mode === "disk-full") {
  const base = nodeSpoolIo(loaded.addon);
  const full = (): never => {
    throw Object.assign(new Error("no space left on device"), { code: "ENOSPC" });
  };
  // A full volume: every record byte fails; the ledger, preallocated, needs no new block.
  const io: SpoolIo = { ...base, write: full, writev: full };
  const spool = new Spool(dir!, { maxBytes: 1 << 20, addon: loaded.addon, io });
  const losses = new LossTable();
  for (const loss of input.losses) {
    losses.record(
      loss.sourceId,
      BigInt(loss.epoch),
      loss.reason,
      BigInt(loss.sequence),
      loss.segmentId,
    );
  }
  const markers = new MarkerQueue();
  for (const doc of input.markers) markers.queue({ doc, bodies: [] });
  let spooled = markers.pump(spool);
  if (losses.pump(spool)) spooled += markers.pump(spool);
  const mirrored = new LedgerMirror().mirror(spool.ledger, losses.peek(), markers.held);
  out({
    spooled,
    pending: losses.peek().map((range) => ({
      reason: range.reason,
      first: range.first,
      last: range.last,
      count: range.count,
      segment: range.segmentId ?? null,
    })),
    markers: markers.held.length,
    mirrored,
    used: spool.ledger?.used() ?? 0,
  });
  keep();
} else {
  throw new Error(`unknown mode ${mode}`);
}
