// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Sol P0-A round 6 #1: emitted identity provenance never depends on a bounded cache.
 * An id a recorder emitted is an `EmittedId`, recognised by its type, so it never
 * changes for a live recorder however many other ids it sees; a plain string is always
 * caller input and always mapped.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ByteEvidenceRecorder, EmittedId, LocalFilesystemContentStore } from "../src/index.js";
import { labelPseudonym } from "../src/identity.js";

const KEY = Buffer.from("fabric-test-id-key-not-a-secret");
const roots: string[] = [];
afterEach(() => {
  vi.unstubAllEnvs();
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});
function recorder(idKey?: Buffer, identityMode?: "pseudonymous" | "clear") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "fabric-emitted-"));
  roots.push(root);
  return new ByteEvidenceRecorder({
    store: new LocalFilesystemContentStore(root, "tenant-a"),
    roles: new Set(["terminal.stdout"]),
    maxRecords: 8,
    ...(idKey !== undefined ? { idKey } : {}),
    ...(identityMode !== undefined ? { identityMode } : {}),
  });
}
const BASE = { role: "terminal.stdout", boundary: "terminal", sourceEpoch: 0 };

describe("EmittedId", () => {
  it("cannot be minted by callers and reads as its value", () => {
    expect(() => new EmittedId(Symbol("x"), "r-0", "kid-0")).toThrow("minted by Fabric");
    const id = recorder(KEY).emittedRunId("run-a");
    expect(`${id}`).toBe(id.value);
    expect(JSON.stringify({ id })).toBe(JSON.stringify({ id: id.value }));
  });

  it("identities never change for a live recorder after 131,073 other registrations", async () => {
    vi.stubEnv("FABRIC_IDENTITY_MODE", "");
    const target = recorder(KEY);
    const run = target.emittedRunId("run-a");
    const source = target.emittedSourceId("source-a");
    const capture = (sequence: number, extra: Record<string, unknown> = {}) =>
      target.capture(Buffer.from("x"), {
        ...BASE,
        sourceId: source,
        runId: run,
        sourceSequence: sequence,
        ...extra,
      });
    const before = capture(0);
    expect(before.run_id).toBe(labelPseudonym("r", "run-a", KEY));
    expect(before.source_id).toBe(labelPseudonym("s", "source-a", KEY));
    // Sol's scenario at the old capacity (2 x 65,536) plus one, through the same recorder.
    for (let i = 0; i < 131_073; i += 1) {
      target.emittedRunId(`other-run-${i}`);
      target.emittedSourceId(`other-source-${i}`);
    }
    for (let i = 0; i < 64; i += 1)
      target.capture(Buffer.from("x"), {
        ...BASE,
        sourceId: `other-source-${i}`,
        sourceSequence: 0,
        operationId: `other-op-${i}`,
      });
    const after = capture(1);
    expect(after.run_id).toBe(before.run_id);
    expect(after.source_id).toBe(before.source_id);
    // an operation id the recorder returned also passes through by type
    expect(String(target.emittedRunId(run))).toBe(before.run_id);
    await target.close();
  }, 60_000);

  it("maps every plain string, and an EmittedId issued under another key", async () => {
    const first = recorder(KEY);
    const other = recorder(Buffer.from("another-test-id-key-not-secret"));
    const run = first.emittedRunId("run-a");
    const hex = "0123456789abcdef0123456789abcdef";
    expect(String(first.emittedRunId("r-" + hex))).toBe(labelPseudonym("r", "r-" + hex, KEY));
    expect(String(first.emittedRunId(run.value))).toBe(labelPseudonym("r", run.value, KEY));
    expect(String(first.emittedRunId(run))).toBe(run.value);
    expect(String(other.emittedRunId(run))).not.toBe(run.value);
    // recorders sharing the key accept each other's ids (byte-identical output)
    const twin = recorder(KEY);
    expect(twin.emittedRunId(run)).toBe(run);
    for (const used of [first, other, twin]) await used.close();
  });

  it.each(["pseudonymous", "clear"] as const)(
    "a returned id round-trips in the %s identity mode",
    async (mode) => {
      const target = recorder(KEY, mode);
      const run = target.emittedRunId("run-a");
      const source = target.emittedSourceId("source-a");
      const descriptor = target.capture(Buffer.from("x"), {
        ...BASE,
        sourceId: source,
        runId: run,
        sourceSequence: 0,
      });
      expect(descriptor.run_id).toBe(
        mode === "clear" ? "run-a" : labelPseudonym("r", "run-a", KEY),
      );
      expect(descriptor.source_id).toBe(
        mode === "clear" ? "source-a" : labelPseudonym("s", "source-a", KEY),
      );
      expect(typeof descriptor.run_id).toBe("string");
      await target.close();
    },
  );
});
