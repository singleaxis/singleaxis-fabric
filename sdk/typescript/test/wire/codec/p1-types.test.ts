// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §4.3 (unit 055-t2): every P1 vocabulary and bound of wire/p1-types.ts equals
// Python's fabric/_capture_types.py, read from its source (no Python needed).
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { PRIVACY_MODES } from "../../../src/deployment-policy.js";
import * as P1 from "../../../src/wire/p1-types.js";
import { REPO } from "../helpers.js";

const source = readFileSync(
  join(REPO, "sdk", "python", "src", "fabric", "_capture_types.py"),
  "utf8",
);

/** `Name = Literal[...]` of the Python module, as string lists. */
function literals(): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const m of source.matchAll(/^(\w+) = Literal\[([^\]]*)\]/gms)) {
    out.set(
      m[1]!,
      [...m[2]!.matchAll(/"([^"]*)"/g)].map((v) => v[1]!),
    );
  }
  return out;
}

const PAIRS: [string, ReadonlySet<string>][] = [
  ["Phase", P1.PHASES],
  ["Lifecycle", P1.LIFECYCLES],
  ["ResultStatus", P1.RESULT_STATUSES],
  ["OtlpStatus", P1.OTLP_STATUSES],
  ["Provenance", P1.PROVENANCES],
  ["ContentProvenance", P1.CONTENT_PROVENANCES],
  ["PrivacyMode", PRIVACY_MODES],
  ["CaptureInput", P1.CAPTURE_INPUTS],
  ["StepKind", P1.STEP_KINDS],
  ["DescriptorStatus", P1.DESCRIPTOR_STATUSES],
  ["DescriptorReason", P1.DESCRIPTOR_REASONS],
  ["MarkerKind", P1.MARKER_KINDS],
  ["IdBasis", P1.ID_BASES],
  ["RunOutcome", P1.RUN_OUTCOMES],
  ["StopReason", P1.STOP_REASONS],
  ["ScopeStatus", P1.SCOPE_STATUSES],
  ["EndRunStatus", P1.END_RUN_STATUSES],
  ["RegistrationStatus", P1.REGISTRATION_STATUSES],
];

describe("P1 vocabularies equal Python's _capture_types.py", () => {
  const python = literals();
  it("every Python vocabulary is ported", () => {
    expect([...python.keys()].sort()).toEqual(PAIRS.map(([name]) => name).sort());
  });
  it.each(PAIRS)("%s", (name, set) => {
    expect([...set].sort()).toEqual([...python.get(name)!].sort());
  });

  it("bounds and identifiers", () => {
    const value = (name: string): string =>
      new RegExp(`^${name} = ([^#\\n]+)`, "m").exec(source)![1]!.trim();
    for (const name of [
      "MAX_RECORD_BODIES",
      "MAX_EVENT_IDS",
      "MAX_BRANCHES",
      "MAX_RUN_LINKS",
      "EVIDENCE_MAX_ITEMS",
    ]) {
      expect(String((P1 as Record<string, unknown>)[name]), name).toBe(value(name));
    }
    expect(P1.EVIDENCE_MAX_BYTES).toBe(1 << 20);
    for (const name of ["EVIDENCE_ROLE", "EVIDENCE_MEDIA_TYPE", "EVIDENCE_SCHEMA_VERSION"]) {
      expect(JSON.stringify((P1 as Record<string, unknown>)[name]), name).toBe(value(name));
    }
    for (const name of ["UUID4_RE", "SEGMENT_ID_RE", "BRANCH_ID_RE"]) {
      expect((P1 as Record<string, RegExp>)[name]!.source, name).toBe(
        /re\.compile\(r"(.*)"\)/.exec(value(name))![1],
      );
    }
  });

  it("the phase table keeps the three status inputs separate (R4)", () => {
    expect(P1.resolveStatusInputs("end")).toMatchObject({
      lifecycle: "completed",
      resultStatus: "unknown",
      otlpStatus: "unset",
    });
    expect(P1.resolveStatusInputs("update", "running")?.dropped).toEqual(["lifecycle"]);
    expect(P1.resolveStatusInputs("update", undefined, undefined, "error")?.dropped).toEqual([
      "otlp_status",
    ]);
    expect(P1.resolveStatusInputs("start", undefined, "ok")?.dropped).toEqual(["result_status"]);
    expect(P1.resolveStatusInputs("nope")).toBeUndefined();
  });
});
