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
