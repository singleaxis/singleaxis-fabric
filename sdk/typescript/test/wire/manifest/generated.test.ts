// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * `wire/manifest-fields.generated.ts` equals the registries and Python's
 * `_manifest_fields_generated.py` and `_manifest.POINTS`; the manifest vocabularies equal
 * the capture-manifest schema; the endpoint-set digest equals Python's for the same
 * configuration (spec 055 §9.5, 055-t9).
 */
import { describe, expect, it } from "vitest";

import { resolveConfig } from "../../../src/wire/config.js";
import {
  CLASS_ORDER,
  FIELD_REGISTRY_REVISION,
  MANIFEST_FIELDS,
  MANIFEST_POINTS,
  NODE_HTTP_POINT,
  POINT_REASONS,
  POINT_STATES,
  RUNTIME_POINTS,
  UNDICI_POINT,
  endpointSetDigest,
} from "../../../src/wire/manifest.js";
import { UNDICI_POINT as HOOK_POINT } from "../../../src/wire/undici.js";

import { contract } from "../helpers.js";
import { runPython } from "./helpers.js";

const POINTS = contract("contracts/coverage/v1/registry/capture-points-v1.json");
const FIELDS = contract("contracts/coverage/v1/registry/field-registry-v1.json");
const SCHEMA = contract("contracts/coverage/v1/schema/capture-manifest-v1.schema.json");

describe("the generated per-build field table", () => {
  it("is the registry's supplies restricted to built fields", () => {
    const built = new Set(
      FIELDS.fields.filter((f: any) => f.phase.startsWith("built")).map((f: any) => f.id),
    );
    for (const point of POINTS.capture_points) {
      expect(MANIFEST_FIELDS[point.id], point.id).toEqual(
        point.supplies.filter((id: string) => built.has(id)),
      );
      expect(MANIFEST_POINTS[point.id]).toEqual({
        kind: point.kind,
        process_global: point.process_global.startsWith("yes"),
        opt_in: point.activation.includes("opt-in"),
      });
    }
    expect(Object.keys(MANIFEST_FIELDS).length).toBe(POINTS.capture_points.length);
    expect(FIELD_REGISTRY_REVISION).toBe(`fabric.field-registry/v1@${FIELDS.registry_revision}`);
  });

  it("equals Python's _manifest_fields_generated.py and _manifest.POINTS", () => {
    const python = runPython(
      [
        "import json",
        "from fabric._manifest_fields_generated import FIELD_REGISTRY_REVISION, MANIFEST_FIELDS",
        "from fabric._manifest import POINTS",
        "print(json.dumps({'revision': FIELD_REGISTRY_REVISION,",
        "  'fields': {k: list(v) for k, v in MANIFEST_FIELDS.items()},",
        "  'points': {k: {'kind': p.kind, 'process_global': p.process_global, 'opt_in': p.opt_in}",
        "             for k, p in POINTS.items()}}))",
      ].join("\n"),
      [],
    );
    expect(FIELD_REGISTRY_REVISION).toBe(python.revision);
    expect(MANIFEST_FIELDS).toEqual(python.fields);
    for (const [id, spec] of Object.entries(python.points)) {
      expect(MANIFEST_POINTS[id], id).toEqual(spec);
    }
  });

  it("covers every point this runtime reports", () => {
    for (const point of RUNTIME_POINTS) expect(MANIFEST_POINTS[point], point).toBeDefined();
    expect(UNDICI_POINT).toBe(HOOK_POINT);
    expect(RUNTIME_POINTS).toContain(NODE_HTTP_POINT);
  });
});

describe("the manifest vocabularies equal the schema", () => {
  const point = SCHEMA.properties.capture_points.items.properties;
  it("point states and reasons", () => {
    expect([...POINT_STATES].sort()).toEqual([...point.state.enum].sort());
    expect([...POINT_REASONS].sort()).toEqual([...point.reason.enum].sort());
  });
  it("uncaptured classes", () => {
    const allowed = new Set(SCHEMA.properties.uncaptured_classes.items.enum);
    for (const cls of CLASS_ORDER) expect(allowed.has(cls), cls).toBe(true);
  });
});

describe("the endpoint-set digest", () => {
  const ENDPOINTS = JSON.stringify([
    {
      endpoint_id: "gateway",
      dialect: "openai",
      hosts: ["llm.gateway.internal", "a.gateway.internal"],
      host_suffixes: [".models.internal"],
      path_prefix: "/v1",
    },
  ]);
  it.each([
    ["the built-in table", {}],
    ["the legacy rows", { FABRIC_WIRE_BUILTIN_ENDPOINTS: "legacy" }],
    ["built-ins and a configured gateway", { FABRIC_WIRE_ENDPOINTS: ENDPOINTS }],
  ])("equals Python's for %s", (_name, env: Record<string, string>) => {
    const settings = resolveConfig({}, env);
    const ours = endpointSetDigest([...settings.endpoints, ...settings.extraEndpoints]);
    const python = runPython(
      [
        "import json, sys",
        "from fabric.wire._config import config_from_env",
        "from fabric._manifest import endpoint_set_digest",
        "config, _ = config_from_env(json.loads(sys.argv[1]))",
        "print(json.dumps(endpoint_set_digest(config.all_endpoints)))",
      ].join("\n"),
      [JSON.stringify(env)],
    );
    expect(ours).toBe(python);
    expect(ours).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});
