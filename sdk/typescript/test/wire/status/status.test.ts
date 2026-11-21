// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §4.7 (unit 055-t14): the status document. Every `typescript` catalogue entry is
 * emitted by some code path (the configuration's ids by `config.ts`, the rest by the
 * status module from real states), and every id TypeScript emits is catalogued; the file
 * is written atomically, mode 0600; `node -p` shows each id's text and fix, the JSON never.
 */
import { mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";

import { afterAll, describe, expect, it, vi } from "vitest";

import { CATALOGUE, TYPESCRIPT_IDS } from "../../../src/wire/catalogue.generated.js";
import { CONFIG_REASON_IDS } from "../../../src/wire/config.js";
import { install, resetInstalledForTests } from "../../../src/wire/install.js";
import { currentRuntime } from "../../../src/wire/manifest.js";
import {
  STATUS_SCHEMA,
  describe as describeStatus,
  envStatus,
  exitDocument,
  installDocument,
  notInstalledDocument,
  printable,
  statusMessages,
  writeStatusFile,
} from "../../../src/wire/status.js";

import { native } from "../spool/helpers.js";
import { activeHere } from "./helpers.js";

// This file runs as an application worker thread would: install() there records nothing
// and says so (FW-030). Nothing else here depends on the thread.
const thread = vi.hoisted(() => ({ main: true }));
vi.mock("node:worker_threads", async (importOriginal) => {
  const real = await importOriginal<typeof import("node:worker_threads")>();
  return {
    ...real,
    get isMainThread() {
      return thread.main;
    },
  };
});

function workerThreadIds(): string {
  thread.main = false;
  try {
    const handle = install();
    expect(handle.capturing).toBe(false);
    expect(handle.reason).toBe("worker_without_process_runtime");
    const doc = handle.status();
    return doc.warning_ids.includes("FW-030") ? "FW-030" : "none";
  } finally {
    thread.main = true;
    resetInstalledForTests();
  }
}

const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});
function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "f055-t14-status-"));
  dirs.push(dir);
  return dir;
}

const NODE_24 = Number(process.versions.node.split(".")[0]) >= 24;

function base(dir: string): Record<string, string> {
  return { FABRIC_WIRE_SPOOL_DIR: join(dir, "spool"), FABRIC_OTLP_ENDPOINT: "http://127.0.0.1:9" };
}

function policy(dir: string, mode: string, profile = "local"): string {
  const roles = ["model.exchange.request", "model.exchange.response", "model.exchange.part"];
  const path = join(dir, `policy-${mode}-${profile}.json`);
  writeFileSync(
    path,
    JSON.stringify({
      schema_version: "fabric.deployment-policy/v1",
      policy_id: "status-test",
      policy_version: 1,
      tenant_id: "t1",
      workload_id: "w",
      privacy: Object.fromEntries(roles.map((r) => [r, mode])),
      storage: { backend: "local", region: "local", key_id: "k" },
      retention: { days: 1 },
      required_integrations: [],
      deployment: {
        profile,
        image_digest: "sha256:" + "0".repeat(64),
        tls_required: true,
        encrypted_store_required: true,
      },
    }),
  );
  return path;
}

/** The ids of every document the scenarios below produce, by real code paths. */
function emittedByScenarios(): Set<string> {
  const ids = new Set<string>();
  const add = (doc: { warning_ids: readonly string[]; notice_ids: readonly string[] }) => {
    for (const id of [...doc.warning_ids, ...doc.notice_ids]) ids.add(id);
  };
  const dir = scratch();
  const n = native();
  const ok = { prebuildsDir: n.build.dir, digests: { [n.build.target]: n.digest } };
  const qualified = { qualification: activeHere(n.build.target), native: ok };
  add(envStatus({ FABRIC_WIRE_ENDPOINTS: "nope" })); // FW-025
  add(envStatus({ ...base(dir), OTEL_SDK_DISABLED: "true" })); // FW-007
  add(envStatus({})); // FW-034, FW-002
  add(envStatus(base(dir), { native: { prebuildsDir: join(dir, "none") } })); // FW-028
  add(envStatus(base(dir), { native: { platform: "aix" } as never })); // FW-027
  add(envStatus(base(dir), { qualification: { tuples: [] }, native: ok })); // FW-026
  add(envStatus({ ...base(dir), FABRIC_WIRE_NODE_HTTP: "0" }, qualified)); // FW-029, FW-031
  add(envStatus({ ...base(dir), FABRIC_WIRE_AUTOLOAD: "1" }, qualified)); // FW-005, FW-003
  add(envStatus({ ...base(dir), FABRIC_WIRE_STATUS_FILE: join(dir, "no", "s.json") })); // FW-023
  add(
    envStatus({
      ...base(dir),
      FABRIC_TENANT_ID: "t1",
      FABRIC_WIRE_CONTENT_ENDPOINT: "http://127.0.0.1:9/v1/logs",
    }),
  ); // FW-008 (production without a policy)
  add(
    envStatus({
      ...base(dir),
      FABRIC_TENANT_ID: "t1",
      FABRIC_WIRE_STORE: `file://${join(dir, "store")}`,
      FABRIC_CAPTURE_POLICY: policy(dir, "redact"),
    }),
  ); // FW-032
  add(
    envStatus({
      ...base(dir),
      FABRIC_TENANT_ID: "t1",
      FABRIC_WIRE_SPOOL_MIGRATE_PLAINTEXT: "1",
      FABRIC_CAPTURE_POLICY: policy(dir, "retain_original", "production"),
    }),
  ); // FW-022
  // A spool a process left records in, with its exit note (FW-033).
  const left = join(dir, "left");
  mkdirSync(left, { mode: 0o700 });
  writeFileSync(join(left, "00000000000000000001-1-1.rec"), "x");
  writeFileSync(join(left, ".exit-backlog"), "{}");
  add(envStatus({ ...base(dir), FABRIC_WIRE_SPOOL_DIR: left }));
  add(exitDocument({ warning_ids: [], notice_ids: [] }, false, { backlog: 3 })); // FW-033
  // The installing thread's counters: an unmatched model-shaped request (FW-006).
  const runtime = currentRuntime(n.build.target);
  add(
    installDocument({
      capture: "installed",
      runtime,
      listed: true,
      counters: { matched: 0, not_captured: 0, unmatched_model_shaped: 1 },
    }),
  );
  return ids;
}

describe("catalogue ids", () => {
  it.runIf(NODE_24)("every typescript catalogue entry is emitted by some code path", () => {
    const ids = emittedByScenarios();
    ids.add(workerThreadIds()); // FW-030
    for (const id of CONFIG_REASON_IDS) ids.add(id); // config.ts throws each (config tests)
    const missing = TYPESCRIPT_IDS.filter((id) => !ids.has(id));
    expect(missing).toEqual([]);
    // ... and every id emitted is a TypeScript catalogue entry.
    expect([...ids].filter((id) => !(TYPESCRIPT_IDS as readonly string[]).includes(id))).toEqual(
      [],
    );
  });

  it("documents name ids only, in catalogue order: warnings and notices by severity", () => {
    const { warning_ids, notice_ids } = describeStatus({
      capture: "disabled",
      reason: "autoload_off",
      runtime: currentRuntime(null),
      listed: false,
      states: { "wire.ts.undici": ["unsupported", "unsupported_version"] },
    });
    expect(warning_ids).toEqual(["FW-026"]);
    expect(notice_ids).toEqual(["FW-031"]);
    for (const id of [...warning_ids, ...notice_ids]) {
      const severity = CATALOGUE.find((e) => e.id === id)?.severity;
      expect(warning_ids.includes(id)).toBe(severity !== "info");
    }
  });
});

describe("documents", () => {
  it("a not_installed document carries the class, reason, id and fix, never a value", () => {
    const doc = notInstalledDocument({
      error: "WireConfigError",
      reason: "FABRIC_WIRE_ENDPOINTS is not valid JSON",
      reasonId: "FW-014",
      fix: "FABRIC_WIRE_ENDPOINTS is a JSON array",
    });
    expect(doc).toMatchObject({
      schema: STATUS_SCHEMA,
      phase: "install",
      sdk_language: "typescript",
      capture: "not_installed",
      error: "WireConfigError",
      reason_id: "FW-014",
      warning_ids: ["FW-025"],
      notice_ids: [],
    });
    expect(notInstalledDocument({ error: "a b", reason: "r", reasonId: "FW-025" }).error).toBe(
      "Error",
    );
  });

  it("an exit document keeps only content-free integer counters", () => {
    const doc = exitDocument({ warning_ids: ["FW-006"], notice_ids: ["FW-005"] }, true, {
      matched: 2,
      "lost.queue_full": 1,
      "Bad Name": 3,
      negative: -1,
      fraction: 0.5,
    });
    expect(doc.stats).toEqual({ matched: 2, "lost.queue_full": 1 });
    expect(doc.warning_ids).toEqual([]); // FW-006 only from the counters
    expect(doc.notice_ids).toEqual(["FW-005"]);
    expect(doc).toMatchObject({ phase: "exit", capture: "closed", delivered: true });
  });

  it("node -p shows each id's text and fix; JSON carries the document only", () => {
    const doc = printable(exitDocument({ warning_ids: [], notice_ids: [] }, false, { backlog: 1 }));
    const shown = inspect(doc);
    const entry = CATALOGUE.find((e) => e.id === "FW-033")!;
    expect(shown).toContain(entry.text);
    expect(shown).toContain("messages");
    expect(JSON.stringify(doc)).not.toContain("messages");
    expect(statusMessages(doc)).toEqual([
      { id: "FW-033", severity: entry.severity, text: entry.text, fix: entry.fix },
    ]);
  });
});

describe("the status file", () => {
  it("is written atomically, mode 0600, with sorted keys", () => {
    const dir = scratch();
    const path = join(dir, "status.json");
    const doc = notInstalledDocument({ error: "E", reason: "r", reasonId: "FW-025" });
    expect(writeStatusFile(path, doc)).toBe(true);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    const text = readFileSync(path, "utf8");
    expect(text.endsWith("\n")).toBe(true);
    const keys = Object.keys(JSON.parse(text));
    expect(keys).toEqual([...keys].sort());
    expect(readFileSync(path, "utf8")).not.toContain(".tmp");
  });

  it("an unwritable path is false and one FW-023 warning naming the fix, never a throw", () => {
    const dir = scratch();
    const warned: string[] = [];
    const doc = notInstalledDocument({ error: "E", reason: "r", reasonId: "FW-025" });
    expect(writeStatusFile(join(dir, "missing", "s.json"), doc, (t) => warned.push(t))).toBe(false);
    expect(writeStatusFile(join(dir, "missing", "s.json"), doc, (t) => warned.push(t))).toBe(false);
    expect(warned).toHaveLength(1);
    expect(warned[0]).toMatch(/\[FW-023\]$/);
    expect(warned[0]).not.toContain(dir);
  });
});
