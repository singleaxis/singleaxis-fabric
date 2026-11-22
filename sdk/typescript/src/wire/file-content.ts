// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The local profile's content path (spec 055 §7.1; Python `_pipeline._store_object`):
 * with `FABRIC_WIRE_STORE=file:///dir` and no Fabric Node, the sender writes each
 * protected body into that directory store itself, byte for byte as Python's
 * `LocalFilesystemContentStore.put_bytes_object` writes it and the reader reads it:
 * `<dir>/<tenant>/evidence/<object_id>` (the bytes) and
 * `<dir>/<tenant>/evidence/meta/<object_id>.json` (the descriptor with `encoding` and
 * `ref`, sorted keys, exact int64). A descriptor-only object (a withheld or
 * descriptor-only part) is written as its descriptor alone, as Python's
 * `put_descriptor_only` and the Node do, so the reader finds it `not_stored`.
 *
 * Runs on the Fabric worker only (synchronous file I/O, never on an application thread).
 * Create-only and idempotent: an object already stored with other bytes is `rejected`,
 * never overwritten; any other failure is `retry`, so the record stays in the spool.
 */
import { createHash, randomUUID } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

import type { ContentResult } from "./node-content.js";
import type { ContentItem } from "./otlp.js";
import type { ContentSender } from "./sender.js";

/** Python `check_safe_identifier`. */
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/;

/**
 * Python's `json.dumps(value, ensure_ascii=False, sort_keys=True)` for plain JSON values
 * and exact integers (`bigint`), as a descriptor holds them.
 */
export function pythonSortedJson(value: unknown): string {
  if (typeof value === "bigint") return value.toString();
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(pythonSortedJson).join(", ")}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}: ${pythonSortedJson(v)}`).join(", ")}}`;
}

class Conflict extends Error {}

/** The root with symbolic links resolved in its existing part (Python resolves it too). */
function canonicalRoot(root: string): string {
  let parent = path.resolve(root);
  const suffix: string[] = [];
  while (!fs.existsSync(parent) && path.dirname(parent) !== parent) {
    suffix.unshift(path.basename(parent));
    parent = path.dirname(parent);
  }
  return path.join(fs.realpathSync(parent), ...suffix);
}

/** The bytes of `target`, read through one descriptor that never follows a link. */
function readExisting(target: string): Buffer | undefined {
  let fd: number;
  try {
    fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  } catch (error) {
    const code = (error as { code?: unknown }).code;
    if (code === "ENOENT") return undefined;
    if (code === "ELOOP") throw new Conflict("a symbolic link where an object belongs");
    throw error;
  }
  try {
    if (!fs.fstatSync(fd).isFile()) throw new Conflict("not a regular file");
    return fs.readFileSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Removes the temp names this writer left for `name` (`.<name>.<uuid>.tmp`) that are
 * still hard links to the stored object: a process that died between `link` and
 * `unlink` leaves one, and Python's reader refuses an object file with more than one
 * link (`_read_at`: "unsafe local content file"), so the object would never be read.
 */
function dropStaleNames(directory: string, name: string, target: string): void {
  const stored = fs.lstatSync(target);
  if (stored.nlink <= 1) return;
  const prefix = `.${name}.`;
  for (const entry of fs.readdirSync(directory)) {
    if (!entry.startsWith(prefix) || !entry.endsWith(".tmp")) continue;
    const candidate = path.join(directory, entry);
    const info = fs.lstatSync(candidate, { throwIfNoEntry: false });
    if (info?.isFile() && info.ino === stored.ino && info.dev === stored.dev) {
      fs.unlinkSync(candidate);
    }
  }
  // Another name Fabric did not make: the object is unsafe to read, never ours to fix.
  if (fs.lstatSync(target).nlink !== 1) throw new Conflict("a stored object has other links");
}

/**
 * Writes `name` in `directory` once, create-only: the bytes go to a fresh temp file
 * (fsync'd), which is then hard-linked to the name, an operation that fails if the name
 * exists, so nothing is ever replaced and no check races the write. The same bytes
 * already there are fine; other bytes conflict. The temp name is removed before the
 * write counts as done (a failure to remove it is a retry, never `ok`), because the
 * reader refuses an object with a second link; a later attempt removes a temp name an
 * earlier, interrupted one left.
 */
function createOnce(directory: string, name: string, data: Uint8Array): void {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const target = path.join(directory, name);
  const temp = path.join(directory, `.${name}.${randomUUID()}.tmp`);
  const fd = fs.openSync(temp, "wx", 0o600);
  let linked = false;
  try {
    try {
      let offset = 0;
      while (offset < data.length) offset += fs.writeSync(fd, data, offset);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    try {
      fs.linkSync(temp, target);
      linked = true;
    } catch (error) {
      if ((error as { code?: unknown }).code !== "EEXIST") throw error;
    }
  } finally {
    try {
      fs.unlinkSync(temp);
    } catch (error) {
      // Unlinked, an unlinked temp is never read as an object. Still linked, the object
      // has two names and the reader refuses it: not done (`retry`).
      if (linked) throw error;
    }
  }
  if (!linked) {
    const existing = readExisting(target);
    if (existing === undefined || !existing.equals(data)) {
      throw new Conflict("a stored object differs");
    }
    dropStaleNames(directory, name, target);
    return;
  }
  const dir = fs.openSync(directory, "r");
  try {
    fs.fsyncSync(dir);
  } finally {
    fs.closeSync(dir);
  }
}

export class FileContentClient implements ContentSender {
  readonly #evidence: string;
  readonly #tenant: string;

  constructor(root: string, tenant: string) {
    if (!SAFE_ID.test(tenant)) throw new Error("FABRIC_TENANT_ID is not a safe identifier");
    this.#tenant = tenant;
    this.#evidence = path.join(canonicalRoot(root), tenant, "evidence");
  }

  /** Nothing to release (no connection); present so the worker closes every client alike. */
  close(): void {}

  send(item: ContentItem): Promise<ContentResult> {
    return Promise.resolve(this.#write(item));
  }

  #write(item: ContentItem): ContentResult {
    const descriptor = item.descriptor;
    const objectId = descriptor["object_id"];
    if (typeof objectId !== "string" || !SAFE_ID.test(objectId)) return "rejected";
    if (descriptor["schema_version"] !== "fabric.content-object/v2") return "rejected";
    if (descriptor["tenant_id"] !== this.#tenant) return "rejected";
    try {
      const meta = path.join(this.#evidence, "meta");
      if (typeof descriptor["stored_sha256"] !== "string") {
        // Python `check_descriptor_only`: no stored bytes and no reference.
        if (
          descriptor["status"] !== "not_captured" ||
          ["stored_byte_length", "encoding", "ref"].some((k) => Object.hasOwn(descriptor, k))
        ) {
          return "rejected";
        }
        const body = Buffer.from(pythonSortedJson(descriptor) + "\n", "utf8");
        createOnce(meta, `${objectId}.json`, body);
        return "ok";
      }
      const data = item.body;
      const digest = createHash("sha256").update(data).digest("hex");
      if (descriptor["stored_sha256"] !== `sha256:${digest}`) return "rejected";
      if (Number(descriptor["stored_byte_length"]) !== data.byteLength) return "rejected";
      const ref = `file://${path.join(this.#evidence, objectId)}`;
      const full = { ...descriptor, encoding: "binary", ref };
      createOnce(this.#evidence, objectId, data);
      createOnce(meta, `${objectId}.json`, Buffer.from(pythonSortedJson(full) + "\n", "utf8"));
      return "ok";
    } catch (error) {
      return error instanceof Conflict ? "rejected" : "retry";
    }
  }
}
