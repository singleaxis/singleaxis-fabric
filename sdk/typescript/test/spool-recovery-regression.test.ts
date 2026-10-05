// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { LocalFilesystemContentStore } from "../src/content-store.js";
import { ContentWriter } from "../src/content-writer.js";
import { buildContentDescriptor, canonicalJson } from "../src/content.js";
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, writeSync: vi.fn(actual.writeSync) };
});
const original = await vi.importActual<typeof import("node:fs")>("node:fs");
let root: string;
beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "fabric-spool-regression-"));
});
afterEach(() => {
  vi.mocked(fs.writeSync).mockImplementation(original.writeSync);
  fs.rmSync(root, { recursive: true, force: true });
});
function fixture() {
  const content = "synthetic restart bytes: π";
  const { descriptor } = buildContentDescriptor({
    tenantId: "tenant",
    role: "tool_result",
    content,
    mediaType: "text/plain",
    source: "sdk",
    status: "pending",
    bindings: {},
    payloadMaxBytes: 1000,
  });
  const store = new LocalFilesystemContentStore(path.join(root, "store"), "tenant");
  const spoolDir = path.join(root, "spool");
  fs.mkdirSync(spoolDir);
  return { content, descriptor, store, spoolDir };
}
it("retains recovered bytes when reconciliation fails and recovers on restart", async () => {
  const { content, descriptor, store, spoolDir } = fixture();
  const record: Record<string, unknown> = {
    schema_version: "fabric.content-spool/v2",
    kind: "object",
    key: descriptor.object_id,
    tenant_id: "tenant",
    decision_id: "decision",
    attempts: 0,
    first_enqueued: Date.now() / 1000,
    manifest_id: "manifest",
    manifest_item_sequence: 0,
    descriptor,
    ref: store.refFor(descriptor.digest.slice(7)),
    content_b64: Buffer.from(content).toString("base64"),
  };
  record["checksum"] = createHash("sha256").update(canonicalJson(record)).digest("hex");
  const spoolFile = path.join(spoolDir, `${descriptor.object_id}.json`);
  fs.writeFileSync(spoolFile, JSON.stringify(record));
  const failed = Object.create(store) as LocalFilesystemContentStore;
  failed.putObject = () => {
    throw new Error("synthetic store unavailable");
  };
  failed.readManifest = () => {
    throw new Error("synthetic reconciliation unavailable");
  };
  const first = new ContentWriter({
    store: failed,
    roles: "all",
    durability: "spooled",
    spoolDir,
    retryMaxAttempts: 1,
  });
  expect((await first.close()).failed).toBe(1);
  expect(fs.existsSync(spoolFile)).toBe(true);
  const retained = JSON.parse(fs.readFileSync(spoolFile, "utf8")) as Record<string, string>;
  expect(Buffer.from(retained["content_b64"]!, "base64").toString()).toBe(content);
  store.writeManifest(
    {
      tenant_id: "tenant",
      items: [{ sequence: 0, role: descriptor.role, status: "pending", descriptor }],
    },
    "decision",
    "manifest",
  );
  const restarted = new ContentWriter({
    store,
    roles: "all",
    durability: "spooled",
    spoolDir,
    retryMaxAttempts: 1,
  });
  expect((await restarted.close()).stored).toBe(1);
  expect(fs.readFileSync(new URL(store.refFor(descriptor.digest.slice(7))), "utf8")).toBe(content);
  const manifest = JSON.parse(
    fs.readFileSync(new URL(store.manifestUriFor("manifest")), "utf8"),
  ) as { items: { status: string }[] };
  expect(manifest.items[0]?.status).toBe("stored");
  expect(fs.existsSync(spoolFile)).toBe(false);
});
it.each([false, true])("checks short writes and zero progress (stop=%s)", async (stop) => {
  const { content, descriptor, store, spoolDir } = fixture();
  const writer = new ContentWriter({ store, roles: "all", durability: "spooled", spoolDir });
  let calls = 0;
  vi.mocked(fs.writeSync).mockImplementation(((
    fd: number,
    data: Uint8Array,
    offset: number = 0,
    length: number = data.length - offset,
    position: number | null = null,
  ) => {
    if (stop && calls++ > 0) return 0;
    return original.writeSync(fd, data, offset, Math.min(length, 3), position);
  }) as typeof fs.writeSync);
  try {
    expect(writer.submit(descriptor, content)).toBe(stop ? "dropped" : "pending");
    const files = fs.readdirSync(spoolDir);
    expect(files.some((name) => name.endsWith(".tmp"))).toBe(false);
    if (stop) expect(files).toEqual([]);
    else {
      const record = JSON.parse(
        fs.readFileSync(path.join(spoolDir, `${descriptor.object_id}.json`), "utf8"),
      ) as Record<string, string>;
      expect(Buffer.from(record["content_b64"]!, "base64").toString()).toBe(content);
      const checksum = record["checksum"];
      delete record["checksum"];
      expect(createHash("sha256").update(canonicalJson(record)).digest("hex")).toBe(checksum);
    }
  } finally {
    vi.mocked(fs.writeSync).mockImplementation(original.writeSync);
    await writer.close();
  }
});
