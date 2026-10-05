// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { ByteEvidenceRecorder, LocalFilesystemContentStore } from "../src/index.js";

const roots: string[] = [];
function localStore(tenantId = "acme"): LocalFilesystemContentStore {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "fabric-byte-evidence-"));
  roots.push(root);
  return new LocalFilesystemContentStore(root, tenantId);
}
afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function options(sequence: number) {
  return {
    role: "terminal.stdout",
    boundary: "terminal",
    sourceId: "sdk-1",
    sourceEpoch: 0,
    sourceSequence: sequence,
    runId: "run-1",
    operationId: "op-1",
    streamId: "stdout-1",
    chunkIndex: sequence,
  };
}

describe("ByteEvidenceRecorder", () => {
  it("stores arbitrary non-UTF8 bytes exactly and never merges distinct observations", async () => {
    const store = localStore();
    const recorder = new ByteEvidenceRecorder({
      store,
      roles: new Set(["terminal.stdout"]),
      payloadMaxBytes: 100,
    });
    const bytes = Uint8Array.from([0, 255, 0xc3, 0x28, 10]);
    const first = recorder.capture(bytes, options(0));
    const second = recorder.capture(bytes, options(1));
    bytes[1] = 7; // the queued evidence is an immutable snapshot
    expect(first.status).toBe("pending");
    expect(first.provenance).toBe("caller_reported");
    expect(first.source_byte_length).toBe(5);
    expect(first.source_sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    const stats = await recorder.flush();
    expect(stats.stored).toBe(2);
    expect(first.status).toBe("stored");
    expect(first.stored_sha256).toBe(first.source_sha256);
    expect(first.stored_byte_length).toBe(first.source_byte_length);
    expect(first.object_id).not.toBe(second.object_id);
    expect(first.ref).not.toBe(second.ref);
    expect([...store.read(first.ref!)]).toEqual([0, 255, 0xc3, 0x28, 10]);
    expect([...store.read(second.ref!)]).toEqual([0, 255, 0xc3, 0x28, 10]);
    expect(store.readDescriptor(first.ref!)["source_sequence"]).toBe(0);
    expect(store.readDescriptor(second.ref!)["source_sequence"]).toBe(1);
    await recorder.close();
  });

  it("stores an empty byte stream with the exact empty SHA-256 and length zero", async () => {
    const store = localStore();
    const recorder = new ByteEvidenceRecorder({ store, roles: new Set(["terminal.stdout"]) });
    const item = recorder.capture(new Uint8Array(0), options(0));
    await recorder.flush();
    expect(item.status).toBe("stored");
    expect(item.source_byte_length).toBe(0);
    expect(item.stored_byte_length).toBe(0);
    expect(item.source_sha256).toBe(
      "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(store.read(item.ref!)).toHaveLength(0);
    await recorder.close();
  });

  it("returns pending before a slow store settles, without waiting on the monitored call", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "fabric-byte-slow-"));
    roots.push(root);
    const base = new LocalFilesystemContentStore(root, "acme");
    const slowStore = new Proxy(base, {
      get(target, key) {
        if (key === "putBytesObject") {
          return async (descriptor: Record<string, unknown>, data: Uint8Array) => {
            await new Promise((resolve) => setTimeout(resolve, 100));
            return target.putBytesObject(descriptor, data);
          };
        }
        const value = Reflect.get(target, key) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const recorder = new ByteEvidenceRecorder({
      store: slowStore,
      roles: new Set(["terminal.stdout"]),
    });
    const item = recorder.capture(Uint8Array.of(0, 255), options(0));
    expect(item.status).toBe("pending");
    await recorder.flush();
    expect(item.status).toBe("stored");
    await recorder.close();
  });

  it("makes policy exclusion, oversized inputs, and queue overflow explicit", async () => {
    const store = localStore();
    const recorder = new ByteEvidenceRecorder({
      store,
      roles: new Set(["terminal.stdout"]),
      payloadMaxBytes: 3,
      queueMaxItems: 1,
    });
    const excluded = recorder.capture(Uint8Array.of(1), {
      ...options(0),
      role: "terminal.stderr",
    });
    expect(excluded).toMatchObject({
      status: "not_captured",
      status_reason: "outside_capture_policy",
    });
    expect(excluded.ref).toBeUndefined();
    const oversized = recorder.capture(Uint8Array.of(1, 2, 3, 4), options(1));
    expect(oversized).toMatchObject({ status: "dropped", status_reason: "payload_too_large" });
    expect(oversized.ref).toBeUndefined();
    const accepted = recorder.capture(Uint8Array.of(1), options(2));
    const overflow = recorder.capture(Uint8Array.of(2), options(3));
    expect(overflow).toMatchObject({ status: "dropped", status_reason: "queue_full" });
    expect(overflow.ref).toBeUndefined();
    expect((await recorder.flush()).stored).toBe(1);
    expect(accepted.status).toBe("stored");
    await recorder.close();
  });

  it("accepts the full queue capacity before the scheduled drain starts", async () => {
    const recorder = new ByteEvidenceRecorder({
      store: localStore(),
      roles: new Set(["terminal.stdout"]),
      queueMaxItems: 2,
    });
    const first = recorder.capture(Uint8Array.of(1), options(0));
    const second = recorder.capture(Uint8Array.of(2), options(1));
    const overflow = recorder.capture(Uint8Array.of(3), options(2));
    expect(first.status).toBe("pending");
    expect(second.status).toBe("pending");
    expect(overflow).toMatchObject({ status: "dropped", status_reason: "queue_full" });
    expect((await recorder.close()).stored).toBe(2);
  });

  it("bounds the descriptor index and exposes settled outcomes for a manifest writer", async () => {
    const recorder = new ByteEvidenceRecorder({
      store: localStore(),
      roles: new Set(["terminal.stdout"]),
      maxRecords: 1,
    });
    const first = recorder.capture(Uint8Array.of(1), options(0));
    const second = recorder.capture(Uint8Array.of(2), options(1));
    expect(second).toMatchObject({ status: "dropped", status_reason: "record_index_full" });
    expect(recorder.stats().unretained_drops).toBe(1);
    expect(recorder.get(first.object_id)?.status).toBe("pending");
    await recorder.flush();
    expect(recorder.get(first.object_id)?.status).toBe("stored");
    expect(recorder.drainSettled().map((item) => item.object_id)).toEqual([first.object_id]);
    expect(recorder.get(first.object_id)).toBeUndefined();
    await recorder.close();
  });

  it("bounds source-epoch identity tracking without fabricating capture", async () => {
    const recorder = new ByteEvidenceRecorder({
      store: localStore(),
      roles: new Set(["terminal.stdout"]),
      maxSources: 1,
    });
    const first = recorder.capture(Uint8Array.of(1), options(0));
    const second = recorder.capture(Uint8Array.of(2), { ...options(1), sourceId: "sdk-2" });
    expect(second).toMatchObject({ status: "dropped", status_reason: "source_registry_full" });
    expect(recorder.stats().unretained_drops).toBe(1);
    await recorder.flush();
    expect(first.status).toBe("stored");
    await recorder.close();
  });

  it("does not fabricate stored status when the byte store rejects delivery", async () => {
    class FailingByteStore extends LocalFilesystemContentStore {
      override putBytesObject(): never {
        throw new Error("disk full");
      }
    }
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "fabric-byte-fail-"));
    roots.push(root);
    const recorder = new ByteEvidenceRecorder({
      store: new FailingByteStore(root, "acme"),
      roles: new Set(["terminal.stdout"]),
      retryMaxAttempts: 2,
    });
    const item = recorder.capture(Uint8Array.of(1, 2), options(0));
    const stats = await recorder.flush();
    expect(stats.failed).toBe(1);
    expect(item.status).toBe("failed");
    expect(item.ref).toBeUndefined();
    expect(item.stored_sha256).toBeUndefined();
    await recorder.close();
  });

  it("rejects invalid roles, identities, chunk lineage, and sequence reuse", async () => {
    const recorder = new ByteEvidenceRecorder({
      store: localStore(),
      roles: new Set(["terminal.stdout"]),
    });
    expect(() =>
      recorder.capture(Uint8Array.of(1), { ...options(0), sourceId: "../bad" }),
    ).toThrow();
    expect(() =>
      recorder.capture(Uint8Array.of(1), { ...options(0), streamId: undefined }),
    ).toThrow();
    expect(() => recorder.capture(Uint8Array.of(1), { ...options(0), role: "unknown" })).toThrow();
    recorder.capture(Uint8Array.of(1), options(0));
    expect(() => recorder.capture(Uint8Array.of(2), options(0))).toThrow(/increase/);
    await recorder.close();
  });

  it("keeps v1 and v2 namespaces separate and rejects mismatched tenant/digest", async () => {
    const store = localStore();
    const recorder = new ByteEvidenceRecorder({ store, roles: new Set(["artifact.after"]) });
    const item = recorder.capture(Uint8Array.of(0, 1, 255), {
      ...options(0),
      role: "artifact.after",
      boundary: "tool",
    });
    await recorder.flush();
    expect(item.ref).toContain("/acme/evidence/");
    expect(() =>
      store.putBytesObject(
        {
          ...store.readDescriptor(item.ref!),
          tenant_id: "other",
        },
        Uint8Array.of(0, 1, 255),
      ),
    ).toThrow(/invalid content-v2/);
    expect(() =>
      store.putBytesObject(
        {
          ...store.readDescriptor(item.ref!),
          stored_sha256: `sha256:${"0".repeat(64)}`,
        },
        Uint8Array.of(0, 1, 255),
      ),
    ).toThrow(/invalid content-v2/);
    expect(() =>
      store.putBytesObject(
        { ...store.readDescriptor(item.ref!), ref: "file:///other/evidence/unsafe" },
        Uint8Array.of(0, 1, 255),
      ),
    ).toThrow(/reference does not match/);
    await recorder.close();
  });
});
