// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The whole recorder the passivity harness measures from unit 055-t13 on (spec 055 §9.2
 * "event loop" sustained case and "stalled recorder"): explicit `install()` of the wire
 * core with the capture pipeline and the sender, built from the SDK source by
 * `build.mjs`. The Fabric worker runs `recorder-worker.ts`, which applies the arm's
 * test-only faults (never in the SDK) and then the SDK's own worker. `holdAdmission`
 * takes the spool's shared admission lock from this thread, as another writer would.
 */
import { install, type InstallOptions, type WireHandle } from "../../../../sdk/typescript/src/wire/install.js";
import { endRun, resumeToken, run } from "../../../../sdk/typescript/src/wire/run-api.js";
import { FLOCK_EXCLUSIVE, loadNative, nativeTarget } from "../../../../sdk/typescript/src/wire/native.js";

export { endRun, resumeToken, run };

export function startRecorder(options: InstallOptions): WireHandle {
  return install({ drainOnExit: false, ...options });
}

/** Holds `flock(.admit)` of `spoolDir` until the returned function is called. */
export function holdAdmission(spoolDir: string, prebuilds: string, digest: string): () => void {
  const target = nativeTarget();
  const loaded = loadNative({ prebuildsDir: prebuilds, digests: { [target!]: digest } });
  if (!loaded.ok) throw new Error(`native: ${loaded.reason}`);
  const addon = loaded.addon;
  const dir = addon.openDir(spoolDir);
  const handle = addon.openFile(dir, ".admit", true);
  addon.close(dir);
  if (handle < 0 || addon.flock(handle, FLOCK_EXCLUSIVE) !== 0) throw new Error("admission lock not taken");
  return () => addon.close(handle);
}
