// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The shared manifest vectors through `wire/manifest.ts` (spec 055 §9.5, 055-t9): the
 * chain of `manifest-chain-v1` is rebuilt by a `ManifestChain` (manifest 0, then two state
 * changes at the vector's allocator cuts), byte for byte and digest for digest, and every
 * `manifest-span-v1` case is rebuilt by `assemble` and spooled as its marker.
 */
import { describe, expect, it } from "vitest";

import { canonicalJson } from "../../../src/wire/codec.js";
import { ManifestChain, assemble, manifestMarker, markerSpan } from "../../../src/wire/manifest.js";
import { checkValue, manifestDigest, spanToManifest } from "../../../src/wire/p1.js";
import { validHeader } from "../../../src/wire/spool-codec.js";
import { TELEMETRY_KEYS } from "../../../src/wire/telemetry-keys.generated.js";

import { cases, norm, vector } from "../helpers.js";
import { positionOf, templateOf } from "./helpers.js";

/** The spool header a writer would produce for a marker entry. */
const header = (doc: Record<string, unknown>) => ({
  schema_version: "fabric.wire-spool-record/v1",
  order: 0,
  written_at_unix_nano: 0,
  ...doc,
});

describe("manifest-chain-v1 through ManifestChain", () => {
  const doc = vector("manifest-chain-v1");
  const manifests: any[] = doc.manifests;

  it("rebuilds manifest 0 and both state changes byte for byte", () => {
    const ids = manifests.flatMap((m) => [m.manifest_id, m.event_id]);
    const stamps = manifests.map((m) => m.emitted_at as string);
    const chain = new ManifestChain(templateOf(manifests[0]), {
      newId: () => ids.shift()!,
      stamp: () => stamps.shift()!,
    });
    const epoch = BigInt(manifests[0].source_epoch);
    const zero = chain.initial(epoch);
    expect(zero).toBeDefined();
    expect(canonicalJson(chain.document)).toBe(canonicalJson(manifests[0]));
    // mcp.client: disabled(hook_disabled) -> active, effective after position 41.
    const one = chain.pointChanged(epoch, "mcp.client", "active", undefined, 41n);
    expect(canonicalJson(chain.document)).toBe(canonicalJson(manifests[1]));
    // wire.py.httpx fails at position 97.
    const two = chain.pointChanged(epoch, "wire.py.httpx", "failed", "internal_error", 97n);
    expect(canonicalJson(chain.document)).toBe(canonicalJson(manifests[2]));
    expect(chain.ref?.digest).toBe(doc.digests[2]);
    expect(chain.latestSeq(epoch)).toBe(2);

    // Each marker: last_sequence is the manifest's cut, event_id its own, and the
    // spool reader (both languages' rule) accepts the header.
    [zero, one, two].forEach((marker, index) => {
      const fields = marker!.doc.marker as Record<string, any>;
      expect(fields.kind).toBe("manifest");
      expect(BigInt(fields.last_sequence)).toBe(BigInt(manifests[index].after_source_sequence));
      expect(fields.event_id).toBe(manifests[index].event_id);
      expect(validHeader(header(marker!.doc), 0)).toBe(true);
      expect(norm(spanToManifest(fields.manifest))).toEqual(norm(manifests[index]));
      expect(manifestDigest(spanToManifest(fields.manifest))).toBe(doc.digests[index]);
    });
  });

  it("issues nothing for a change to the state already in force", () => {
    const chain = new ManifestChain(templateOf(manifests[0]));
    const epoch = BigInt(manifests[0].source_epoch);
    chain.initial(epoch);
    expect(chain.pointChanged(epoch, "mcp.client", "disabled", "hook_disabled", 5n)).toBe(
      undefined,
    );
    expect(chain.initial(epoch)).toBe(undefined);
    expect(chain.ref?.manifestSeq).toBe(0);
  });
});

describe("manifest-span-v1 through assemble and the manifest marker", () => {
  const spans = vector("manifest-span-v1");
  it.each(cases(spans.cases, "name"))("%s", (_name, c: any) => {
    const document = assemble(templateOf(c.manifest), positionOf(c.manifest));
    const expected = Object.fromEntries(Object.entries(c.manifest).filter(([, v]) => v !== null));
    expect(canonicalJson(document)).toBe(canonicalJson(expected));
    const marker = manifestMarker(document);
    const fields = marker.doc.marker as Record<string, any>;
    expect(norm(fields.manifest)).toEqual(norm(c.attributes));
    const [name, attributes] = markerSpan(
      c.manifest.source_id,
      BigInt(c.manifest.source_epoch),
      fields,
    );
    expect(name).toBe("fabric.capture_manifest");
    expect(norm(attributes)).toEqual(norm(c.attributes));
    for (const [key, value] of Object.entries(attributes)) {
      expect(TELEMETRY_KEYS[key], key).toBeDefined(); // a registry key, never a free one
      const check = TELEMETRY_KEYS[key]!.check;
      if (check !== undefined) expect(checkValue(check, value), key).toBe(true);
    }
    expect("fabric.capture.input" in attributes).toBe(false);
    expect(validHeader(header(marker.doc), 0)).toBe(true);
  });
});
