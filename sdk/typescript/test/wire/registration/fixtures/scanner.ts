// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * A drainer scan from an isolate other than the one that registered, as the Fabric
 * worker runs it: this isolate's own list of held registrations is empty, so only the
 * runtime's control block (the published mirror handle) says which epoch this process
 * holds. The module's flock is replaced by one that always succeeds, as on a
 * filesystem that does not enforce locks. Posts `{ withRuntime, withoutRuntime }`,
 * each a list of `[sourceId, epoch]`.
 */
import { parentPort, workerData } from "node:worker_threads";

import { NativeCode, loadNative, nativeTarget } from "../../../../src/wire/native.js";
import { scanOrphans } from "../../../../src/wire/registration.js";
import { type RuntimeShared, WireRuntime } from "../../../../src/wire/runtime.js";

interface ScannerData {
  readonly shared: RuntimeShared;
  readonly prebuilds: string;
  readonly digest: string;
  readonly spool: string;
}

const data = workerData as ScannerData;
const target = nativeTarget();
if (target === null) throw new Error("no native target for this platform");
const loaded = loadNative({ prebuildsDir: data.prebuilds, digests: { [target]: data.digest } });
if (!loaded.ok) throw new Error(`${loaded.reason}: ${loaded.message}`);
const addon = { ...loaded.addon, flock: () => NativeCode.OK };
const runtime = new WireRuntime(data.shared, "worker");
const pairs = (found: ReturnType<typeof scanOrphans>) =>
  found.map((orphan) => [orphan.sourceId, String(orphan.epoch)]);
const withRuntime = pairs(scanOrphans({ addon, spoolDir: data.spool, runtime }));
const withoutRuntime = pairs(scanOrphans({ addon, spoolDir: data.spool }));
parentPort?.postMessage({ withRuntime, withoutRuntime });
