// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.5 (unit 055-t2): every case of the shared P1 vectors, byte for byte, through
// the TypeScript pure functions. The vectors are the ones scripts/contracts/p1_reference.py
// produces and the coverage validator re-checks; nothing here is TypeScript-specific.
import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { keyId, labelPseudonym, pseudonymV2 } from "../../../src/identity.js";
import { RECEIVER_OWNED_KEYS } from "../../../src/wire/p1-types.js";
import {
  checkValue,
  endRunIdentity,
  formatToken,
  lossEntries,
  manifestDigest,
  manifestToSpan,
  parsePredecessor,
  parseToken,
  projectRecordAttributes,
  recordChecks,
  recordConditions,
  recordContent,
  recordDigest,
  runIdentity,
  sealDigest,
  sealEntries,
  spanCategory,
  spanToManifest,
  splitCarrier,
} from "../../../src/wire/p1.js";
import {
  TELEMETRY_KEYS,
  TELEMETRY_KEY_REVISION,
} from "../../../src/wire/telemetry-keys.generated.js";
import { cases, contract, norm, vector } from "../helpers.js";

const nullable = (value: unknown): unknown => (value === undefined ? null : value);

describe("resume-token-v1 (fr2/ grammar, predecessors, carriers)", () => {
  const doc = vector("resume-token-v1");
  const v1 = (token: string): unknown => {
    const parsed = parseToken(token);
    if (parsed === undefined || parsed.version !== 2) return undefined;
    const rest: Record<string, unknown> = { ...parsed };
    delete rest.version;
    delete rest.correlation_id;
    return rest;
  };
  it.each(cases(doc.tokens, "name"))("token: %s", (_name, c: any) => {
    expect(norm(nullable(v1(c.token)))).toEqual(norm(c.parsed));
  });
  it.each(cases(doc.predecessors, "name"))("predecessor: %s", (_name, c: any) => {
    const parsed = c.entry === "none" ? undefined : parsePredecessor(c.entry);
    expect(c.entry === "none" || parsed !== undefined).toBe(c.valid);
    if (parsed !== undefined) expect(norm(parsed)).toEqual(norm(c.parsed));
  });
  it.each(cases(doc.carriers, "name"))("carrier: %s", (_name, c: any) => {
    const items = splitCarrier(c.value, c.carrier);
    const tokens = items?.map(v1);
    const got = tokens === undefined || tokens.includes(undefined) ? null : tokens;
    const want = c.tokens === null ? null : c.tokens.map(v1);
    expect(norm(got)).toEqual(norm(want));
  });
});

describe("resume-token-v2 (fr3/ grammar, issue, carriers, run identity, end_run)", () => {
  const doc = vector("resume-token-v2");
  it.each(cases(doc.tokens, "name"))("token: %s", (_name, c: any) => {
    expect(norm(nullable(parseToken(c.token)))).toEqual(norm(c.parsed));
  });
  it.each(cases(doc.issue, "name"))("issue: %s", (_name, c: any) => {
    const token = formatToken(c.correlation_id, c.entry, c.branch_id);
    expect(nullable(token)).toEqual(c.token);
    if (token !== undefined) expect(parseToken(token)).toBeDefined();
  });
  it.each(cases(doc.carriers, "name"))("carrier: %s", (_name, c: any) => {
    const tokens = splitCarrier(c.value, c.carrier);
    expect(tokens).toEqual(c.tokens);
    expect(tokens!.map((t) => parseToken(t) !== undefined)).toEqual(c.valid);
  });
  it.each(cases(doc.run_identity, "name"))("run identity: %s", (_name, c: any) => {
    const i = c.inputs;
    const got = runIdentity(i.tokens, i.run_id, i.minted, {
      identityMode: i.identity_mode,
      key: i.key,
      runIdEmitted: i.run_id_emitted,
    });
    expect(norm(got)).toEqual(norm(c.expected));
  });
  it("covers every rule 1-5", () => {
    expect(new Set(doc.run_identity.map((c: any) => Number(c.rule)))).toEqual(
      new Set([1, 2, 3, 4, 5]),
    );
  });
  it.each(cases(doc.end_run, "name"))("end_run: %s", (_name, c: any) => {
    const i = c.inputs;
    const got = endRunIdentity(i.tokens, i.run_id, i.minted, {
      identityMode: i.identity_mode,
      key: i.key,
    });
    expect(norm(got)).toEqual(norm(c.expected));
  });
});

describe("seal-digest-v1 (record digests and segment seals)", () => {
  const doc = vector("seal-digest-v1");
  const digests = new Map<string, string>();
  it.each(cases(doc.records, "name"))("record: %s", (_name, c: any) => {
    const content = recordContent(
      c.kind,
      c.descriptors,
      c.span.attributes["fabric.content.object_ids"] ?? [],
    );
    expect(content).toEqual(c.content);
    const digest = recordDigest(c.span, content);
    expect(digest).toBe(c.digest);
    if (c.same_digest_as !== undefined) expect(digests.get(c.same_digest_as)).toBe(digest);
    digests.set(c.name, digest);
  });
  it.each(cases(doc.segments, "name"))("segment: %s", (_name, c: any) => {
    const recordDigests = new Map<string, string>(
      doc.records.map((r: any) => [r.name, recordDigest(r.span, r.content)]),
    );
    const entries = sealEntries(
      c.records.map(([seq, name]: [bigint, string]) => [seq, recordDigests.get(name)!] as const),
      c.losses,
      c.segment_id,
    ).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    expect(norm(entries)).toEqual(norm(c.entries));
    expect(sealDigest(entries)).toBe(c.seal_digest);
  });
});

describe("seal-parity-v1 (Python-emitted spans pass the Node unchanged)", () => {
  const doc = vector("seal-parity-v1");
  const table = recordChecks();
  it.each(cases(doc.cases, "name"))("%s", (_name, c: any) => {
    const { emitted, expected_export: exported } = c;
    const kept = Object.fromEntries(
      Object.entries(exported.attributes).filter(([k]) => !RECEIVER_OWNED_KEYS.has(k)),
    );
    expect(kept).toEqual(emitted.attributes);
    expect(exported.name).toBe(emitted.name);
    expect(spanCategory(emitted.name, Object.keys(emitted.attributes))).toBe(emitted.name);
    for (const [key, value] of Object.entries(emitted.attributes)) {
      const row = TELEMETRY_KEYS[key];
      if (c.class === "record") {
        const check = table.get(key);
        expect(
          check !== undefined && checkValue(check, value, { labels: "pseudonymous" }),
          key,
        ).toBe(true);
      } else if (row?.placement !== undefined) {
        const check = row.capture_check ?? row.check;
        expect(row.placement.includes(c.class), key).toBe(true);
        if (check !== undefined)
          expect(checkValue(check, value, { labels: "pseudonymous" }), key).toBe(true);
      }
    }
    if (c.digest !== undefined) {
      expect(recordDigest(emitted, c.content)).toBe(c.digest);
      expect(recordDigest({ ...emitted, attributes: exported.attributes }, c.content)).toBe(
        c.digest,
      );
    }
    if (c.seal_entries !== undefined) {
      const a = emitted.attributes;
      const loss = {
        reason: a["fabric.loss.reason"],
        count: a["fabric.loss.count"],
        first_sequence: a["fabric.loss.first_sequence"],
        last_sequence: a["fabric.loss.last_sequence"],
      };
      expect(norm(lossEntries(loss))).toEqual(norm(c.seal_entries));
    }
  });
});

describe("manifest-chain-v1 and manifest-span-v1", () => {
  it("chains each manifest to the canonical digest of its predecessor", () => {
    const doc = vector("manifest-chain-v1");
    doc.manifests.forEach((m: any, index: number) => {
      expect(Number(m.manifest_seq)).toBe(index);
      if (index > 0)
        expect(m.previous_manifest_sha256).toBe(manifestDigest(doc.manifests[index - 1]));
    });
    expect(doc.manifests.map(manifestDigest)).toEqual(doc.digests);
  });
  const spans = vector("manifest-span-v1");
  it.each(cases(spans.cases, "name"))("span form: %s", (_name, c: any) => {
    expect(norm(manifestToSpan(c.manifest))).toEqual(norm(c.attributes));
    const expected = Object.fromEntries(Object.entries(c.manifest).filter(([, v]) => v !== null));
    expect(norm(spanToManifest(c.attributes))).toEqual(norm(expected));
    for (const [key, value] of Object.entries(c.attributes)) {
      const check = TELEMETRY_KEYS[key]?.check;
      if (check !== undefined) expect(checkValue(check, value), key).toBe(true);
    }
  });
});

describe("run-marker-v1 (marker attribute sets under the Node's checks)", () => {
  const doc = vector("run-marker-v1");
  it.each(cases(doc.admitted, "name"))("admitted: %s", (_name, c: any) => {
    for (const [key, value] of Object.entries(c.attributes)) {
      const check = TELEMETRY_KEYS[key]?.check;
      if (check !== undefined)
        expect(checkValue(check, value, { labels: c.capture_labels }), key).toBe(true);
    }
  });
  it.each(cases(doc.stripped, "name"))("stripped: %s", (_name, c: any) => {
    const check = TELEMETRY_KEYS[c.key]?.check;
    expect(check).toBeDefined();
    expect(checkValue(check!, c.value, { labels: c.capture_labels })).toBe(false);
  });
});

describe("records-span-v1 (rule A)", () => {
  const doc = vector("records-span-v1");
  it("is the generated records-class table", () => {
    expect(doc.keys).toEqual([...recordChecks().keys()]);
    expect(doc.conditions).toEqual(Object.fromEntries(recordConditions()));
    expect(Number(doc.table_revision)).toBe(TELEMETRY_KEY_REVISION);
  });
  it.each(cases(doc.cases, "name"))("%s", (_name, c: any) => {
    const [kept, dropped] = projectRecordAttributes(c.attributes, {
      labels: c.capture_labels,
      identity: c.identity_mode,
    });
    expect(kept).toEqual(c.admitted);
    expect(dropped).toEqual(c.dropped);
  });
  it.each(cases(doc.host_cases, "name"))("host: %s", (_name, c: any) => {
    const placement = new Set<string>(doc.host_placement);
    const [kept, dropped] = projectRecordAttributes(c.attributes);
    const allDropped = [...dropped, ...Object.keys(kept).filter((k) => !placement.has(k))].sort();
    const hostKept = Object.fromEntries(Object.entries(kept).filter(([k]) => placement.has(k)));
    expect(hostKept).toEqual(c.admitted);
    expect(allDropped).toEqual(c.dropped);
  });
});

describe("span-category-v1 (rule N)", () => {
  const doc = vector("span-category-v1");
  const all = [...doc.cases, ...doc.sensor_cases];
  it.each(cases(all))("%s", (_name, c: any) => {
    expect(spanCategory(c.name_hint, c.attribute_keys)).toBe(c.category);
  });
});

describe("pseudonym-v2 and run-id-pseudonym-v1", () => {
  const doc = vector("pseudonym-v2");
  it.each(cases(doc.cases, "name"))("%s", (_name, c: any) => {
    let got: string | undefined;
    if (c.function === "v2") {
      got = c.key ? pseudonymV2(c.prefix, c.value, c.key) : undefined;
    } else if (c.function === "legacy_provider") {
      got = "p-" + createHash("sha256").update(c.value, "utf8").digest("hex").slice(0, 16);
    } else {
      got = labelPseudonym(c.prefix, c.value, c.key ?? undefined);
    }
    expect(nullable(got)).toBe(c.pseudonym);
  });
  it.each(cases(doc.key_ids, "key_id"))("key id %s", (_id, c: any) => {
    expect(keyId(c.key)).toBe(c.key_id);
  });
  const v1 = contract("contracts/capture/v1/fixtures/run-ids/run-id-pseudonym-v1.json");
  it.each(cases(v1.cases, "name"))("v1 run id: %s", (_name, c: any) => {
    expect(labelPseudonym("r", c.run_id, c.key ?? undefined)).toBe(c.pseudonym);
  });
});
