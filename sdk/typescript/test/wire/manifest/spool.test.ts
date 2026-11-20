// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Manifests and the final heartbeat as `marker` spool records (spec 055 §7.2, §6.2;
 * 055-t9): a real, sealed spool written by TypeScript is read by Python's drainer, which
 * accepts every header, rebuilds each manifest with its digest and keeps every persisted
 * uuid4 event id on replay. Manifest 0 declares the prior unsealed epochs that the
 * registration scan finds (bounded list, exact count).
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { Heartbeats, ManifestChain, MarkerQueue } from "../../../src/wire/manifest.js";
import type { NativeAddon } from "../../../src/wire/native.js";
import { manifestDigest, spanToManifest } from "../../../src/wire/p1.js";
import { epochName, ORPHAN_SUFFIX, unsealedPriorEpochs } from "../../../src/wire/registration.js";
import { Spool } from "../../../src/wire/spool.js";

import { norm, vector } from "../helpers.js";
import {
  KEY,
  type Native,
  cleanupDirs,
  native,
  pythonWithSpoolKey,
  runPython,
  spoolDir,
} from "../spool/helpers.js";
import { templateOf } from "./helpers.js";

const M0 = vector("manifest-chain-v1").manifests[0];
let lib: Native;
let addon: NativeAddon;
const spools: Spool[] = [];

beforeAll(() => {
  pythonWithSpoolKey();
  lib = native();
  addon = lib.addon;
}, 120_000);
afterAll(() => lib?.build.cleanup());
afterEach(() => {
  for (const spool of spools.splice(0)) spool.close();
  cleanupDirs();
});

/** Python's drainer: each pending record, its header check, the marker's span and manifest. */
const PY_READ = `
import json, sys
from fabric.wire._spool import Spool, unframe_all, valid_header
from fabric._loss import marker_from_fields, marker_fields, marker_span
from fabric._manifest import manifest_digest, manifest_from_attributes
spool = Spool(sys.argv[1], int(sys.argv[2]), key=bytes.fromhex(sys.argv[3]))
out = []
try:
    for name in spool.names():
        for doc, blob in unframe_all(spool.read(name)):
            fields = doc["marker"]
            src = doc["source"]
            replayed = marker_fields(marker_from_fields(src["source_id"], src["source_epoch"], fields))
            span = marker_span(src["source_id"], src["source_epoch"], fields)
            row = {"valid": valid_header(doc, len(blob)), "kind": fields["kind"],
                   "event_id": fields.get("event_id"), "replayed_event_id": replayed["event_id"],
                   "span": span[0], "attributes": span[1]}
            if fields["kind"] == "manifest":
                row["digest"] = manifest_digest(manifest_from_attributes(fields["manifest"]))
            out.append(row)
finally:
    spool.release()
print(json.dumps(out))
`;

describe("manifest and final markers in a sealed spool", () => {
  it("are read, digested and replayed by Python unchanged", () => {
    const dir = spoolDir();
    const spool = new Spool(dir, { maxBytes: 1 << 20, addon, key: KEY });
    spools.push(spool);
    const epoch = BigInt(M0.source_epoch);
    const chain = new ManifestChain(templateOf(M0));
    const beats = new Heartbeats(chain);
    const queue = new MarkerQueue();
    const digests: string[] = [];
    queue.queue(chain.initial(epoch));
    digests.push(chain.ref!.digest);
    const zero = chain.document!;
    queue.queue(chain.pointChanged(epoch, "mcp.client", "active", undefined, 41n));
    digests.push(chain.ref!.digest);
    queue.queue(beats.final(epoch, 57n));
    expect(queue.pump(spool)).toBe(3);
    expect(spool.mine.size).toBe(3);

    const python = runPython(PY_READ, [dir, String(1 << 20), KEY.toString("hex")]);
    expect(python.map((r: any) => [r.valid, r.kind, r.span])).toEqual([
      [true, "manifest", "fabric.capture_manifest"],
      [true, "manifest", "fabric.capture_manifest"],
      [true, "final", "fabric.capture_heartbeat"],
    ]);
    expect(python.slice(0, 2).map((r: any) => r.digest)).toEqual(digests);
    for (const row of python) {
      expect(row.event_id).toMatch(/^[0-9a-f-]{36}$/);
      expect(row.replayed_event_id).toBe(row.event_id); // persisted, never re-minted
      expect(row.attributes["fabric.event_id"]).toBe(row.event_id);
    }
    expect(python[2].attributes["fabric.heartbeat.last_sequence"]).toBe(57);
    expect(python[2].attributes["fabric.capture.manifest_seq"]).toBe(1);

    // TypeScript's own drainer reads the same records back.
    expect(spool.tryLock()).toBe(true);
    const scan = spool.recover();
    expect(scan.quarantined).toEqual([]);
    const docs = scan.files.flatMap((f) => f.records.map((r) => r.doc));
    expect(docs.map((d: any) => d.marker.kind)).toEqual(["manifest", "manifest", "final"]);
    expect(manifestDigest(spanToManifest((docs[1] as any).marker.manifest))).toBe(digests[1]);
    expect(norm(spanToManifest((docs[0] as any).marker.manifest))).toEqual(norm(zero));
  });
});

describe("prior unsealed epochs from the registration scan", () => {
  it("declares at most 64 in manifest 0, with the exact count", () => {
    const dir = spoolDir();
    mkdirSync(dir, { mode: 0o700 });
    mkdirSync(join(dir, ".epochs"), { mode: 0o700 });
    const epochs = Array.from({ length: 70 }, (_, i) => BigInt(5000 + i));
    for (const epoch of epochs) {
      writeFileSync(join(dir, ".epochs", epochName(epoch, ORPHAN_SUFFIX)), Buffer.alloc(4096), {
        mode: 0o600,
      });
    }
    const declared = unsealedPriorEpochs(addon, dir);
    expect(declared.count).toBe(70);
    const chain = new ManifestChain(templateOf(M0));
    chain.initial(9999n, declared);
    const doc = chain.document!;
    expect(doc.unsealed_prior_epochs).toEqual(epochs.slice(0, 64).map(Number));
    expect(doc.unsealed_prior_epoch_count).toBe(70);
  });
});
