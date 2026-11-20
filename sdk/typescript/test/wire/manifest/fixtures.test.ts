// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The TypeScript manifests of spec 055 §8 (`contracts/coverage/v1/valid/
 * manifest-typescript-*.json`) built by `wire/manifest.ts` from the scenario each one
 * names: point states from the qualification table and the install status, the gate, the
 * uncaptured classes and inputs. Each built manifest equals its fixture except for what
 * this build legitimately differs in (the per-build field table, and the fixture's
 * synthetic endpoint digest and production policy), and passes Python's contract
 * validator (schema, registry, exact integers, the qualification rule).
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { DeploymentPolicy } from "../../../src/deployment-policy.js";
import { canonicalJson } from "../../../src/wire/codec.js";
import {
  type BuildFacts,
  type ManifestTemplate,
  ManifestChain,
  NODE_HTTP_POINT,
  type PointStatusInputs,
  type QualificationTable,
  type RuntimeBuild,
  UNDICI_POINT,
  assemble,
  buildFacts,
  initialStates,
  manifestTemplate,
  wirePointState,
} from "../../../src/wire/manifest.js";
import { type ContentGate, decideGate } from "../../../src/wire/protect.js";

import { REPO, contract, norm } from "../helpers.js";
import { policyDoc } from "../protect/helpers.js";
import { KEY1, KEY2, positionOf, pythonValidate, runPython, settingsFor } from "./helpers.js";

const TABLE: QualificationTable = JSON.parse(
  readFileSync(join(REPO, "sdk", "typescript", "wire-qualification.json"), "utf8"),
);
/** The real table plus the core-HTTP tuple 055-t21 will add, for the node_http scenarios. */
const WITH_NODE_HTTP: QualificationTable = {
  tuples: [
    ...TABLE.tuples,
    {
      point: NODE_HTTP_POINT,
      node: "24.22.3",
      platform: "linux-x64-glibc",
      claim: "active",
      report_sha256: "sha256:" + "0".repeat(64),
    },
  ],
};
const LINUX = "linux-x64-glibc";
const MIN: RuntimeBuild = { node: "24.4.0", undici: "7.11.0", platform: LINUX };
const NEW: RuntimeBuild = { node: "24.22.3", undici: "7.30.2", platform: LINUX };
const OLD: RuntimeBuild = { node: "24.0.0", undici: "7.8.0", platform: LINUX };
const NODE22: RuntimeBuild = { node: "22.23.5", undici: "6.29.1", platform: LINUX };

const FACTS = (runtime: RuntimeBuild): BuildFacts =>
  buildFacts({
    sdkVersion: "0.13.0",
    runtimeVersion: runtime.node,
    pointVersions: Object.fromEntries(
      [
        "fabric.self",
        "install.config",
        UNDICI_POINT,
        NODE_HTTP_POINT,
        "sdk.records",
        "run.scope",
      ].map((p) => [p, "1.0.0"]),
    ),
    clockMaxUncertaintyNs: 300_000_000_000n,
  });

/** The fixture's own records and run points are `active` (a fully built Node SDK). */
const BUILT = { "sdk.records": ["active", undefined], "run.scope": ["active", undefined] } as const;

const LOCAL: ContentGate = decideGate({
  node: false,
  store: true,
  policy: undefined,
  idKey: true,
  spool: false,
  spoolKey: false,
});
const NO_STORE: ContentGate = decideGate({
  node: false,
  store: false,
  policy: undefined,
  idKey: true,
  spool: false,
  spoolKey: false,
});
const PRODUCTION: ContentGate = decideGate({
  node: true,
  store: false,
  policy: new DeploymentPolicy(
    policyDoc({ "model.exchange.request": "metadata_only" }, "production"),
  ),
  idKey: false,
  spool: true,
  spoolKey: true,
});

interface Scenario {
  readonly runtime: RuntimeBuild;
  readonly gate: ContentGate;
  readonly key: string | undefined;
  readonly enabled: Record<string, boolean>;
  readonly table?: QualificationTable;
  readonly nativeOk?: boolean;
  readonly unattached?: boolean;
  readonly node?: boolean;
  readonly spoolKeyId?: string;
}

const SCENARIOS: Record<string, Scenario> = {
  "active-undici": { runtime: MIN, gate: LOCAL, key: KEY1, enabled: { [UNDICI_POINT]: true } },
  "active-node-http": {
    runtime: NEW,
    gate: LOCAL,
    key: KEY1,
    enabled: { [NODE_HTTP_POINT]: true },
    table: WITH_NODE_HTTP,
  },
  "active-both": {
    runtime: NEW,
    gate: LOCAL,
    key: KEY1,
    enabled: { [UNDICI_POINT]: true, [NODE_HTTP_POINT]: true },
    table: WITH_NODE_HTTP,
  },
  "production-content-disabled": {
    runtime: NEW,
    gate: PRODUCTION,
    key: undefined,
    enabled: { [UNDICI_POINT]: true },
    node: true,
    spoolKeyId: "kid-5e6f7a8b",
  },
  "node-22": { runtime: NODE22, gate: NO_STORE, key: KEY1, enabled: { [UNDICI_POINT]: true } },
  "node-24-old-undici": {
    runtime: OLD,
    gate: NO_STORE,
    key: KEY1,
    enabled: { [UNDICI_POINT]: true },
  },
  "native-missing": {
    runtime: NEW,
    gate: NO_STORE,
    key: KEY1,
    enabled: { [UNDICI_POINT]: true },
    nativeOk: false,
  },
  "unattached-worker": {
    runtime: NEW,
    gate: LOCAL,
    key: KEY1,
    enabled: { [UNDICI_POINT]: true },
    unattached: true,
  },
  "key-rotation": { runtime: MIN, gate: LOCAL, key: KEY2, enabled: { [UNDICI_POINT]: true } },
};

function statusInputs(s: Scenario): PointStatusInputs {
  return {
    runtime: s.runtime,
    table: s.table ?? TABLE,
    nativeOk: s.nativeOk ?? true,
    enabled: s.enabled,
    installed: s.enabled,
    endpoints: 3,
  };
}

function templateFor(s: Scenario, fixtureSource: string): ManifestTemplate {
  const facts = FACTS(s.runtime);
  const states = initialStates(statusInputs(s), facts, BUILT as never);
  const settings = settingsFor(
    s.key,
    s.node === true ? { contentEndpoint: "https://fabric-node.internal:4318" } : {},
  );
  return manifestTemplate(settings, {
    sourceId: fixtureSource,
    gate: s.gate,
    spoolKeyId: s.spoolKeyId,
    states,
    runtime: s.runtime,
    unattachedWorkers: s.unattached === true,
    facts,
  });
}

/** The fixture with what this build differs in replaced by the built manifest's values. */
function comparable(fixture: any, built: any): any {
  const out = globalThis.structuredClone(fixture);
  out.endpoint_set_sha256 = built.endpoint_set_sha256; // the fixture's is synthetic
  out.capture_points.forEach((p: any, i: number) => (p.fields = built.capture_points[i].fields));
  // The fixtures' policy blocks are synthetic: production names an invented policy, and
  // the local default's digest predates the role table; ours equals Python's (below).
  if (out.capture_policy !== undefined) out.capture_policy = built.capture_policy;
  return out;
}

describe("the spec 055 §8 TypeScript manifests", () => {
  it.each(Object.keys(SCENARIOS))("%s", (name) => {
    const fixture = contract(`contracts/coverage/v1/valid/manifest-typescript-${name}.json`);
    const scenario = SCENARIOS[name]!;
    const document = assemble(templateFor(scenario, fixture.source_id), positionOf(fixture));
    expect(norm(document)).toEqual(norm(comparable(fixture, document)));
    expect(pythonValidate(document)).toBe(null);
  });

  it("names the local default policy by the digest Python computes", () => {
    const python = runPython(
      "import json\nfrom fabric.wire._policy import LOCAL_DEFAULT as p\n" +
        "print(json.dumps([p.policy_id, p.policy_version, p.policy_digest]))",
      [],
    );
    const fixture = contract("contracts/coverage/v1/valid/manifest-typescript-active-undici.json");
    const template = templateFor(SCENARIOS["active-undici"]!, fixture.source_id);
    const block = template.fixed.capture_policy as Record<string, unknown>;
    expect([block.policy_id, block.policy_version, block.policy_digest]).toEqual(python);
  });

  it("the fixtures themselves pass the same validator", () => {
    for (const name of Object.keys(SCENARIOS)) {
      const fixture = contract(`contracts/coverage/v1/valid/manifest-typescript-${name}.json`);
      expect(pythonValidate(fixture), name).toBe(null);
    }
  });

  it("an unattached worker after install is a chained manifest declaring the class", () => {
    const fixture = contract("contracts/coverage/v1/valid/manifest-typescript-active-undici.json");
    const scenario = SCENARIOS["active-undici"]!;
    const chain = new ManifestChain(templateFor(scenario, fixture.source_id));
    const epoch = BigInt(fixture.source_epoch);
    chain.initial(epoch);
    const zero = chain.document!;
    expect(zero.uncaptured_classes).not.toContain("node_worker_unattached");
    const marker = chain.classUncaptured(epoch, "node_worker_unattached", 12n);
    expect(marker).toBeDefined();
    const one = chain.document!;
    expect(one.manifest_seq).toBe(1);
    expect(one.after_source_sequence).toBe(12);
    expect(one.uncaptured_classes).toEqual([
      "node_http",
      "node_worker_unattached",
      "axios",
      "websocket",
      "non_post_endpoints",
      "unmatched_endpoints",
    ]);
    expect(pythonValidate(one)).toBe(null);
    expect(chain.classUncaptured(epoch, "node_worker_unattached", 20n)).toBe(undefined);
    expect(chain.classUncaptured(epoch, "made_up_class", 20n)).toBe(undefined);
    expect(chain.internalErrors).toBe(1);
  });

  it("a key rotation is a new epoch whose manifest 0 names the new key id", () => {
    const before = contract("contracts/coverage/v1/valid/manifest-typescript-active-undici.json");
    const after = contract("contracts/coverage/v1/valid/manifest-typescript-key-rotation.json");
    expect(BigInt(after.source_epoch)).toBe(BigInt(before.source_epoch) + 1n);
    const a = templateFor(SCENARIOS["active-undici"]!, before.source_id);
    const b = templateFor(SCENARIOS["key-rotation"]!, after.source_id);
    expect(a.fixed.key_id).toBe(before.key_id);
    expect(b.fixed.key_id).toBe(after.key_id);
    expect(canonicalJson({ ...a.fixed, key_id: null })).toBe(
      canonicalJson({ ...b.fixed, key_id: null }),
    );
  });
});

describe("point states from the qualification table and the install status", () => {
  const base = statusInputs(SCENARIOS["active-undici"]!);
  it.each([
    ["the audited minimum, undici on", base, ["active", undefined]],
    ["Node 22", { ...base, runtime: NODE22 }, ["unsupported", "unsupported_version"]],
    [
      "Node 24.0.0 (no body channels)",
      { ...base, runtime: OLD },
      ["unsupported", "unsupported_version"],
    ],
    ["no native module", { ...base, nativeOk: false }, ["unsupported", "unsupported_runtime"]],
    [
      "no prebuild for the platform",
      { ...base, runtime: { ...MIN, platform: null } },
      ["unsupported", "unsupported_runtime"],
    ],
    ["switched off", { ...base, enabled: {} }, ["disabled", "hook_disabled"]],
    [
      "an audited, not active, tuple (darwin)",
      { ...base, runtime: { ...MIN, platform: "darwin-arm64" } },
      ["unsupported", "unsupported_version"],
    ],
    [
      "an undici the table does not pair with this Node",
      { ...base, runtime: { ...MIN, undici: "7.12.0" } },
      ["unsupported", "unsupported_version"],
    ],
    ["the runtime failed", { ...base, failed: true }, ["failed", "internal_error"]],
    ["the hook did not subscribe", { ...base, installed: {} }, ["failed", "internal_error"]],
    ["no endpoint to match", { ...base, endpoints: 0 }, ["installed_inactive", "not_configured"]],
  ] as const)("%s", (_name, inputs, expected) => {
    expect(wirePointState(UNDICI_POINT, inputs as PointStatusInputs)).toEqual(expected);
  });

  it("never activates a point from a tuple without a report hash", () => {
    const table: QualificationTable = {
      tuples: TABLE.tuples.map((t) => ({ ...t, report_sha256: undefined })),
    };
    expect(wirePointState(UNDICI_POINT, { ...base, table })).toEqual([
      "unsupported",
      "unsupported_version",
    ]);
  });

  it("reports core HTTP unsupported until a tuple qualifies it", () => {
    expect(
      wirePointState(NODE_HTTP_POINT, { ...base, enabled: { [NODE_HTTP_POINT]: true } }),
    ).toEqual(["unsupported", "unsupported_version"]);
  });
});
