// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { LocalFilesystemContentStore } from "../src/content-store.js";
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, lstatSync: vi.fn(actual.lstatSync), openSync: vi.fn(actual.openSync) };
});
const original = await vi.importActual<typeof import("node:fs")>("node:fs");
let root: string;
beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "fabric-open-authority-"));
});
afterEach(() => {
  vi.mocked(fs.lstatSync).mockImplementation(original.lstatSync);
  vi.mocked(fs.openSync).mockImplementation(original.openSync);
  fs.rmSync(root, { recursive: true, force: true });
});
function fixture() {
  const store = new LocalFilesystemContentStore(root, "tenant");
  fs.mkdirSync(path.join(root, "tenant"));
  const target = path.join(root, "tenant", "object");
  fs.writeFileSync(target, "original");
  return { store, target, uri: `file://${target}` };
}
it("classifies the opened inode rather than stale pathname metadata", () => {
  const { store, target, uri } = fixture();
  // A former directory has already been replaced by a regular object at open.
  const stale = original.lstatSync(root);
  vi.mocked(fs.lstatSync).mockImplementation(((name: fs.PathLike, ...args: unknown[]) =>
    String(name) === target
      ? stale
      : Reflect.apply(original.lstatSync, fs, [name, ...args])) as typeof fs.lstatSync);
  expect(new TextDecoder().decode(store.read(uri))).toBe("original");
});
it.each(["regular", "symlink", "fifo"])(
  "handles a leaf replaced immediately before open: %s",
  (kind) => {
    if (process.platform === "win32" && kind !== "regular") return;
    const { store, target, uri } = fixture();
    const outside = path.join(root, "private");
    fs.writeFileSync(outside, "PRIVATE_CANARY");
    let swapped = false;
    vi.mocked(fs.openSync).mockImplementation(((
      name: fs.PathLike,
      flags: fs.OpenMode,
      mode?: fs.Mode,
    ) => {
      if (String(name) === target && !swapped) {
        swapped = true;
        fs.unlinkSync(target);
        if (kind === "regular") fs.writeFileSync(target, "replacement");
        else if (kind === "symlink") fs.symlinkSync(outside, target);
        else execFileSync("mkfifo", [target]);
      }
      return original.openSync(name, flags, mode);
    }) as typeof fs.openSync);
    if (kind === "regular") expect(new TextDecoder().decode(store.read(uri))).toBe("replacement");
    else expect(() => store.read(uri)).toThrow();
    expect(swapped).toBe(true);
  },
);
