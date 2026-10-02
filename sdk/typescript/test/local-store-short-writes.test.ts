// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { contentHashBytes, LocalFilesystemContentStore } from "../src/content-store.js";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, writeSync: vi.fn(actual.writeSync) };
});
const original = await vi.importActual<typeof import("node:fs")>("node:fs");
let root: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "fabric-short-write-"));
});
afterEach(() => {
  vi.mocked(fs.writeSync).mockImplementation(original.writeSync);
  fs.rmSync(root, { recursive: true, force: true });
});

function shortWrites(stopAfterFirst = false): void {
  let calls = 0;
  vi.mocked(fs.writeSync).mockImplementation(((
    fd: number,
    data: Uint8Array,
    offset: number = 0,
    length: number = data.length - offset,
    position: number | null = null,
  ) => {
    if (stopAfterFirst && calls++ > 0) return 0;
    return original.writeSync(fd, data, offset, Math.min(length, 3), position);
  }) as typeof fs.writeSync);
}

function files(): string[] {
  return fs.readdirSync(root, { recursive: true }).map(String).sort();
}

describe("local atomic writes", () => {
  it("writes complete content, descriptor, manifest and alias across short writes", () => {
    const store = new LocalFilesystemContentStore(root, "tenant");
    const content = "synthetic exact bytes: π";
    const descriptor = { digest: `sha256:${contentHashBytes(new TextEncoder().encode(content))}` };
    shortWrites();
    const ref = store.putObject(descriptor, content);
    expect(new TextDecoder().decode(store.read(ref.uri))).toBe(content);
    expect(store.readDescriptor(ref.uri)).toEqual(descriptor);
    const manifest = { items: ["synthetic-item"], status: "stored" };
    const uri = store.writeManifest(manifest, "decision", "manifest");
    expect(store.readManifest(uri)).toEqual(manifest);
    expect(store.readManifest(store.manifestUriForDecision("decision"))).toEqual({
      manifest_uri: uri,
    });
    expect(files().some((name) => name.endsWith(".tmp"))).toBe(false);
  });

  it("cleans a zero-progress new object write without publishing a partial object", () => {
    const store = new LocalFilesystemContentStore(root, "tenant");
    const content = "synthetic object";
    const digest = contentHashBytes(new TextEncoder().encode(content));
    shortWrites(true);
    expect(() => store.putObject({ digest: `sha256:${digest}` }, content)).toThrow();
    expect(store.exists(store.refFor(digest))).toBe(false);
    expect(files().some((name) => name.endsWith(".tmp"))).toBe(false);
  });

  it("preserves an existing manifest and alias when replacement makes no progress", () => {
    const store = new LocalFilesystemContentStore(root, "tenant");
    const manifest = { items: ["original"], status: "stored" };
    const uri = store.writeManifest(manifest, "decision", "manifest");
    const oldBytes = store.read(uri);
    const alias = store.read(store.manifestUriForDecision("decision"));
    shortWrites(true);
    expect(() => store.writeManifest({ items: ["replacement"] }, "decision", "manifest")).toThrow();
    expect(store.read(uri)).toEqual(oldBytes);
    expect(store.read(store.manifestUriForDecision("decision"))).toEqual(alias);
    expect(files().some((name) => name.endsWith(".tmp"))).toBe(false);
  });
});
