// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The local profile's content path (spec 055 §7.1, unit 055-t17): with
 * `FABRIC_WIRE_STORE=file:///dir` and no Fabric Node, the sender writes each protected
 * body into the directory store in Python's layout. Before this unit the sender had no
 * content path in this mode and counted every body `content_rejected`, so a local agent
 * kept no bytes (found by the client matrix's local profile).
 */
import { createHash, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { FileContentClient, pythonSortedJson } from "../../../src/wire/file-content.js";
import { runPython } from "../registration/helpers.js";

const TENANT = "tenant-local";

function descriptor(body: Uint8Array | undefined, extra: Record<string, unknown> = {}) {
  const base: Record<string, unknown> = {
    schema_version: "fabric.content-object/v2",
    tenant_id: TENANT,
    object_id: randomUUID(),
    role: "model.exchange.request",
    media_type: "application/json",
    content_encoding: "identity",
    status: body === undefined ? "not_captured" : "stored",
    ...(body === undefined ? {} : { representation: "exact" }),
    ...extra,
  };
  if (body !== undefined) {
    const digest = createHash("sha256").update(body).digest("hex");
    base.stored_sha256 = `sha256:${digest}`;
    base.source_sha256 = `sha256:${digest}`;
    base.stored_byte_length = body.byteLength;
    base.source_byte_length = body.byteLength;
  }
  return base;
}

describe("FileContentClient", () => {
  it("writes a body Python's LocalFilesystemContentStore reads back exactly", async () => {
    const root = mkdtempSync(join(tmpdir(), "f055-t17-store-"));
    const client = new FileContentClient(root, TENANT);
    const body = Buffer.from('{"model":"m","messages":[]}');
    const d = descriptor(body);
    expect(await client.send({ descriptor: d, body })).toBe("ok");
    // idempotent: the same object again is still ok
    expect(await client.send({ descriptor: d, body })).toBe("ok");
    const read = runPython(
      [
        "import json, sys",
        "from fabric.content_store import LocalFilesystemContentStore",
        "s = LocalFilesystemContentStore(root=sys.argv[1], tenant_id=sys.argv[2])",
        "ref = s.evidence_ref_for(sys.argv[3])",
        "print(json.dumps({'hex': s.read(ref).hex(), 'meta': s.read_descriptor(ref)}))",
      ].join("\n"),
      [root, TENANT, d.object_id as string],
    ) as { hex: string; meta: Record<string, unknown> };
    expect(Buffer.from(read.hex, "hex")).toEqual(body);
    expect(read.meta.stored_sha256).toBe(d.stored_sha256);
    expect(read.meta.encoding).toBe("binary");
  });

  it("writes a descriptor-only object as Python's put_descriptor_only does, byte for byte", async () => {
    const root = mkdtempSync(join(tmpdir(), "f055-t17-store-"));
    const client = new FileContentClient(root, TENANT);
    const d = descriptor(undefined, { note: "é", nested: { b: 1, a: [true, null] } });
    expect(await client.send({ descriptor: d, body: new Uint8Array() })).toBe("ok");
    const ours = readFileSync(
      join(root, TENANT, "evidence", "meta", `${d.object_id as string}.json`),
    );
    const pyRoot = mkdtempSync(join(tmpdir(), "f055-t17-store-py-"));
    const input = join(pyRoot, "d.json");
    writeFileSync(input, JSON.stringify(d));
    runPython(
      [
        "import json, sys",
        "from fabric.content_store import LocalFilesystemContentStore",
        "s = LocalFilesystemContentStore(root=sys.argv[1], tenant_id=sys.argv[2])",
        "s.put_descriptor_only(json.load(open(sys.argv[3])))",
        "print('{}')",
      ].join("\n"),
      [pyRoot, TENANT, input],
    );
    const theirs = readFileSync(
      join(pyRoot, TENANT, "evidence", "meta", `${d.object_id as string}.json`),
    );
    expect(ours.toString()).toBe(theirs.toString());
    expect(pythonSortedJson({ b: [1, "x"], a: null })).toBe('{"a": null, "b": [1, "x"]}');
  });

  it("never overwrites an object stored with other bytes; a foreign tenant is rejected", async () => {
    const root = mkdtempSync(join(tmpdir(), "f055-t17-store-"));
    const client = new FileContentClient(root, TENANT);
    const body = Buffer.from("one");
    const d = descriptor(body);
    expect(await client.send({ descriptor: d, body })).toBe("ok");
    const other = Buffer.from("two");
    const changed = { ...descriptor(other), object_id: d.object_id };
    expect(await client.send({ descriptor: changed, body: other })).toBe("rejected");
    const foreign = descriptor(undefined, { tenant_id: "someone-else" });
    expect(await client.send({ descriptor: foreign, body: new Uint8Array() })).toBe("rejected");
    expect(await client.send({ descriptor: { object_id: "../x" }, body })).toBe("rejected");
  });
});
