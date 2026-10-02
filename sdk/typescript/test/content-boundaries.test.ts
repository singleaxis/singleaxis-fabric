// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { LocalFilesystemContentStore, S3ContentStore } from "../src/index.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe("manifest namespace boundaries", () => {
  it.each(["../../outside", "../other-tenant/manifest", "a/b", "a\\b", "", ".", "..", "id\n"])(
    "rejects unsafe manifest IDs before any storage access: %j",
    async (manifestId) => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), "fabric-manifest-boundaries-"));
      roots.push(root);
      const local = new LocalFilesystemContentStore(root, "acme");
      const remote = new S3ContentStore("acme-evidence", "acme");
      expect(() => local.manifestUriFor(manifestId)).toThrow(/manifestId/);
      expect(() => local.writeManifest({}, "decision-1", manifestId)).toThrow(/manifestId/);
      expect(fs.readdirSync(root)).toEqual([]);
      expect(() => remote.manifestUriFor(manifestId)).toThrow(/manifestId/);
      // No AWS SDK or credentials are needed to reject an invalid path.
      await expect(remote.writeManifest({}, "decision-1", manifestId)).rejects.toThrow(
        /manifestId/,
      );
    },
  );
});

describe("local store symbolic-link boundaries", () => {
  function fixture() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "fabric-symlink-boundaries-"));
    roots.push(root);
    const base = path.join(root, "store");
    const outside = path.join(root, "outside");
    fs.mkdirSync(base);
    fs.mkdirSync(outside);
    return { base, outside };
  }

  it("resolves a trusted parent alias before creating missing root directories", () => {
    const { base, outside } = fixture();
    const alias = path.join(base, "trusted-parent");
    fs.symlinkSync(outside, alias, "dir");
    const store = new LocalFilesystemContentStore(path.join(alias, "missing", "store"), "acme");
    const uri = store.writeManifest({}, "decision", "manifest");
    expect(uri).toContain(`${outside}/missing/store/acme/`);
    expect(store.readManifest(uri)).toEqual({});
  });

  it.each(["root", "tenant"])("rejects an initial %s symlink", (component) => {
    const { base, outside } = fixture();
    const target = component === "root" ? base : path.join(base, "acme");
    fs.rmSync(target, { recursive: true, force: true });
    fs.symlinkSync(outside, target, "dir");
    expect(() => new LocalFilesystemContentStore(base, "acme")).toThrow(/symbolic links/);
    expect(fs.readdirSync(outside)).toEqual([]);
  });

  it.each(["root", "tenant", "manifests", "manifests/by-decision"])(
    "rejects post-construction %s replacement without writing outside",
    (component) => {
      const { base, outside } = fixture();
      const store = new LocalFilesystemContentStore(base, "acme");
      const target =
        component === "root"
          ? base
          : component === "tenant"
            ? path.join(base, "acme")
            : path.join(base, "acme", component);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.rmSync(target, { recursive: true, force: true });
      fs.symlinkSync(outside, target, "dir");
      expect(() => store.writeManifest({}, "decision", "manifest")).toThrow(/symbolic links/);
      expect(store.ownsUri(`file://${target}/object`)).toBe(false);
      expect(() => store.read(`file://${target}/object`)).toThrow(/symbolic links/);
      expect(fs.readdirSync(outside)).toEqual([]);
    },
  );

  it.each(["meta", "evidence", "evidence/meta"])(
    "rejects post-construction %s links on read and write",
    async (component) => {
      const { base, outside } = fixture();
      const store = new LocalFilesystemContentStore(base, "acme");
      const target = path.join(base, "acme", component);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.symlinkSync(outside, target, "dir");
      if (component === "meta") {
        const { contentHashBytes } = await import("../src/index.js");
        const content = "synthetic-only";
        const digest = contentHashBytes(new TextEncoder().encode(content));
        expect(() => store.putObject({ digest: `sha256:${digest}` }, content)).toThrow(
          /symbolic links/,
        );
        expect(() => store.readDescriptor(store.refFor(digest))).toThrow(/symbolic links/);
      } else {
        const { ByteEvidenceRecorder } = await import("../src/index.js");
        const recorder = new ByteEvidenceRecorder({
          store,
          roles: new Set(["terminal.stdout"]),
          retryMaxAttempts: 1,
        });
        const record = recorder.capture(new Uint8Array([0, 255]), {
          role: "terminal.stdout",
          boundary: "terminal",
          sourceId: "source-1",
          sourceEpoch: 0,
          sourceSequence: 0,
        });
        await recorder.close();
        expect(record.status).toBe("failed");
      }
      expect(() => store.read(`file://${target}/object`)).toThrow(/symbolic links/);
      expect(fs.readdirSync(outside)).toEqual([]);
    },
  );

  it("rejects final object, descriptor, and manifest symlinks", async () => {
    const { base, outside } = fixture();
    const store = new LocalFilesystemContentStore(base, "acme");
    const { contentHashBytes } = await import("../src/index.js");
    const content = "synthetic-only";
    const digest = contentHashBytes(new TextEncoder().encode(content));
    const outsideFile = path.join(outside, "private");
    fs.writeFileSync(outsideFile, content);
    const tenant = path.join(base, "acme");
    fs.mkdirSync(path.join(tenant, "meta"), { recursive: true });
    fs.mkdirSync(path.join(tenant, "manifests"));
    fs.symlinkSync(outsideFile, path.join(tenant, digest));
    fs.symlinkSync(outsideFile, path.join(tenant, "meta", `${digest}.json`));
    fs.symlinkSync(outsideFile, path.join(tenant, "manifests", "manifest.json"));
    expect(() => store.putObject({ digest: `sha256:${digest}` }, content)).toThrow(
      /symbolic links/,
    );
    expect(() => store.read(store.refFor(digest))).toThrow(/symbolic links/);
    fs.unlinkSync(path.join(tenant, digest));
    fs.writeFileSync(path.join(tenant, digest), content);
    expect(() => store.readDescriptor(store.refFor(digest))).toThrow(/symbolic links/);
    expect(() => store.putObject({ digest: `sha256:${digest}` }, content)).toThrow(
      /symbolic links/,
    );
    expect(() => store.readManifest(store.manifestUriFor("manifest"))).toThrow(/symbolic links/);
    expect(() => store.writeManifest({}, "decision", "manifest")).toThrow(/symbolic links/);
    expect(fs.readFileSync(outsideFile, "utf-8")).toBe(content);
  });
});
