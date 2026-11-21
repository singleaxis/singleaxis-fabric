// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §4.2 (R9), unit 055-t13: explicit `install()` throws only for malformed
 * configuration. A failure past configuration (here: a qualification table that is not
 * one) undoes what was set up and returns a handle that captures nothing and names the
 * reason: no hook, no `beforeExit` listener, no registration left behind.
 */
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { WireConfigError } from "../../../src/wire/config.js";
import { install, resetInstalledForTests } from "../../../src/wire/install.js";

import { cleanupDirs, native, spoolDir } from "../spool/helpers.js";

afterAll(() => cleanupDirs());

function env(dir: string): Record<string, string> {
  return {
    FABRIC_WIRE_SPOOL_DIR: dir,
    FABRIC_TENANT_ID: "tenant-install-test",
    FABRIC_OTLP_ENDPOINT: "http://127.0.0.1:9",
  };
}

describe("install()", { timeout: 60_000 }, () => {
  it("a failure that is not configuration returns an inert handle and undoes the setup", async () => {
    const dir = spoolDir();
    const n = native();
    const listeners = process.listenerCount("beforeExit");
    let handle: ReturnType<typeof install> | undefined;
    expect(() => {
      handle = install({
        env: env(dir),
        native: { prebuildsDir: n.build.dir, digests: { [n.build.target]: n.digest } },
        qualification: { tuples: 5 } as never,
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
    resetInstalledForTests();
  });

  it("malformed configuration still throws its fixed text", () => {
    const dir = spoolDir();
    expect(() => install({ env: { ...env(dir), FABRIC_WIRE_SPOOL_MAX_BYTES: "lots" } })).toThrow(
      WireConfigError,
    );
    resetInstalledForTests();
  });
});
