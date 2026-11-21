// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §4.2 (R9), unit 055-t13: explicit `install()` throws only for malformed
 * configuration. A failure past configuration (here: the manifest template throws, after
 * the epoch was registered, on every Node version) undoes what was set up and returns a
 * handle that captures nothing and names the reason: no hook, no `beforeExit` listener, no
 * registration left behind.
 */
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

import { WireConfigError } from "../../../src/wire/config.js";
import { install, resetInstalledForTests } from "../../../src/wire/install.js";

import { cleanupDirs, native, spoolDir } from "../spool/helpers.js";
import { activeHere } from "../status/helpers.js";

const fault = vi.hoisted(() => ({ on: false }));

vi.mock("../../../src/wire/manifest.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../../src/wire/manifest.js")>();
  return {
    ...real,
    manifestTemplate: (...args: Parameters<typeof real.manifestTemplate>) => {
      if (fault.on) throw new TypeError("injected");
      return real.manifestTemplate(...args);
    },
  };
});

afterAll(() => cleanupDirs());
afterEach(() => {
  fault.on = false;
  resetInstalledForTests();
});

function env(dir: string): Record<string, string> {
  return {
    FABRIC_WIRE_SPOOL_DIR: dir,
    FABRIC_TENANT_ID: "tenant-install-test",
    FABRIC_OTLP_ENDPOINT: "http://127.0.0.1:9",
  };
}

// Spec 055 §9.4 (055-t14): below Node 24 no capture point can be active, so install()
// sets nothing up at all (no hook, worker or epoch) and the fault below is never reached.
const NODE_24 = Number(process.versions.node.split(".")[0]) >= 24;

describe("install()", { timeout: 60_000 }, () => {
  it.skipIf(NODE_24)("below Node 24 it sets nothing up and names the reason", async () => {
    const dir = spoolDir();
    const n = native();
    const listeners = process.listenerCount("beforeExit");
    const handle = install({
      env: env(dir),
      native: { prebuildsDir: n.build.dir, digests: { [n.build.target]: n.digest } },
      qualification: activeHere(n.build.target),
    });
    expect(handle.capturing).toBe(false);
    expect(handle.reason).toBe("unsupported_version");
    expect(handle.status().warning_ids).toContain("FW-026");
    expect(process.listenerCount("beforeExit")).toBe(listeners);
    const epochs = join(dir, ".epochs");
    expect(existsSync(epochs) ? readdirSync(epochs) : []).toEqual([]);
  });

  it.runIf(NODE_24)(
    "a failure that is not configuration returns an inert handle and undoes the setup",
    async () => {
      const dir = spoolDir();
      const n = native();
      const listeners = process.listenerCount("beforeExit");
      let handle: ReturnType<typeof install> | undefined;
      fault.on = true;
      expect(() => {
        handle = install({
          env: env(dir),
          native: { prebuildsDir: n.build.dir, digests: { [n.build.target]: n.digest } },
          qualification: activeHere(n.build.target),
        });
      }).not.toThrow();
      expect(handle!.capturing).toBe(false);
      expect(handle!.reason).toBe("internal_error");
      expect(await handle!.flush()).toBe(false);
      expect(await handle!.close()).toBe(false);
      expect(process.listenerCount("beforeExit")).toBe(listeners);
      // The epoch registered before the failure was finalized and removed.
      const epochs = join(dir, ".epochs");
      expect(existsSync(epochs) ? readdirSync(epochs) : []).toEqual([]);
    },
  );

  it("a first install that captures nothing is replaced by one with other settings", () => {
    const first = install({ env: { FABRIC_OTLP_ENDPOINT: "http://127.0.0.1:9" } });
    expect(first.reason).toBe("no_spool");
    // Same settings: the same handle.
    expect(install({ env: { FABRIC_OTLP_ENDPOINT: "http://127.0.0.1:9" } })).toBe(first);
    expect(install()).toBe(first);
    // Other settings: nothing was set up, so nothing is duplicated; no throw.
    const second = install({
      env: { FABRIC_OTLP_ENDPOINT: "http://127.0.0.1:9", FABRIC_WIRE_UNDICI: "0" },
    });
    expect(second).not.toBe(first);
    expect(install()).toBe(second);
  });

  it("after close() the next install() starts afresh, never the closed handle", async () => {
    const first = install({ env: { FABRIC_OTLP_ENDPOINT: "http://127.0.0.1:9" } });
    expect(install()).toBe(first);
    await first.close();
    const next = install({ env: { FABRIC_OTLP_ENDPOINT: "http://127.0.0.1:9" } });
    expect(next).not.toBe(first);
    expect(install()).toBe(next);
  });

  it("malformed configuration still throws its fixed text", () => {
    const dir = spoolDir();
    expect(() => install({ env: { ...env(dir), FABRIC_WIRE_SPOOL_MAX_BYTES: "lots" } })).toThrow(
      WireConfigError,
    );
    resetInstalledForTests();
  });
});
