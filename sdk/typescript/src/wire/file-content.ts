// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The local profile's content path (spec 055 §7.1; Python `_pipeline._store_object`):
 * with `FABRIC_WIRE_STORE=file:///dir` and no Fabric Node, the sender writes each
 * protected body into that directory store itself, in the layout Python's
 * `LocalFilesystemContentStore` writes and the reader reads
 * (`<dir>/<tenant>/evidence/<object_id>` plus `evidence/meta/<object_id>.json`). A
 * descriptor-only object (a withheld or descriptor-only part) is written as its
 * descriptor alone, as Python's `put_descriptor_only` and the Node do, so the reader
 * finds it `not_stored` rather than missing.
 *
 * Runs on the Fabric worker only (synchronous file I/O, never on an application thread).
 * A body whose stored object already exists with other bytes is `rejected` (never
 * overwritten); any other failure is `retry`, so the record stays in the spool.
 */
import * as fs from "node:fs";
import * as path from "node:path";

import { CorruptedObjectError, LocalFilesystemContentStore } from "../content-store.js";
import type { ContentResult } from "./node-content.js";
import type { ContentItem } from "./otlp.js";
import type { ContentSender } from "./sender.js";

const OBJECT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

/** Python's `json.dumps(value, ensure_ascii=False, sort_keys=True)` for plain JSON values. */
export function pythonSortedJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(pythonSortedJson).join(", ")}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}: ${pythonSortedJson(v)}`).join(", ")}}`;
}

export class FileContentClient implements ContentSender {
  readonly #store: LocalFilesystemContentStore;
  readonly #root: string;
  readonly #tenant: string;

  constructor(root: string, tenant: string) {
    fs.mkdirSync(path.join(root, tenant), { recursive: true, mode: 0o700 });
    this.#store = new LocalFilesystemContentStore(root, tenant);
    this.#root = root;
    this.#tenant = tenant;
  }

  /** Nothing to release (no connection); present so the worker closes every client alike. */
  close(): void {}

  send(item: ContentItem): Promise<ContentResult> {
    return Promise.resolve(this.#write(item));
  }

  #write(item: ContentItem): ContentResult {
    const descriptor = item.descriptor;
    const objectId = descriptor["object_id"];
    if (typeof objectId !== "string" || !OBJECT_ID.test(objectId)) return "rejected";
    try {
      if (typeof descriptor["stored_sha256"] !== "string") {
        return this.#descriptorOnly(objectId, descriptor);
      }
      const ref = this.#store.evidenceRefFor(objectId);
      const stored = this.#store.putBytesObject(
        { ...descriptor, encoding: "binary", ref },
        item.body,
      );
      return stored.uri === ref && `sha256:${stored.contentHash}` === descriptor["stored_sha256"]
        ? "ok"
        : "rejected";
    } catch (error) {
      return error instanceof CorruptedObjectError ? "rejected" : "retry";
    }
  }

  /** Python `put_descriptor_only`: create-only and idempotent. */
  #descriptorOnly(objectId: string, descriptor: Readonly<Record<string, unknown>>): ContentResult {
    // Python `check_descriptor_only`: no stored bytes, no reference, this tenant.
    if (
      descriptor["tenant_id"] !== this.#tenant ||
      descriptor["status"] !== "not_captured" ||
      ["stored_byte_length", "encoding", "ref"].some((k) => Object.hasOwn(descriptor, k))
    ) {
      return "rejected";
    }
    const directory = path.join(this.#root, this.#tenant, "evidence", "meta");
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const target = path.join(directory, `${objectId}.json`);
    const body = Buffer.from(pythonSortedJson(descriptor) + "\n", "utf8");
    let existing: Buffer | undefined;
    try {
      existing = fs.readFileSync(target);
    } catch {
      existing = undefined;
    }
    if (existing !== undefined) return existing.equals(body) ? "ok" : "rejected";
    const temp = path.join(directory, `.${objectId}.${process.pid}.tmp`);
    const fd = fs.openSync(temp, "wx", 0o600);
    try {
      fs.writeSync(fd, body);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(temp, target);
    return "ok";
  }
}
