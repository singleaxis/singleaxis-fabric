// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Helpers of the manifest tests (spec 055 §9.5, unit 055-t9): templates rebuilt from the
 * shared vectors, settings for the §8 scenarios, and the Python contract validator.
 */
import { resolveConfig } from "../../../src/wire/config.js";
import { type JsonValue, encodeJson } from "../../../src/wire/codec.js";
import {
  type ManifestPosition,
  type ManifestTemplate,
  type PointRow,
  type StateEntry,
} from "../../../src/wire/manifest.js";
import type { WireSettings } from "../../../src/wire/types.js";

import { REPO } from "../helpers.js";
import { runPython } from "../registration/helpers.js";

export { runPython };

/** What a manifest document varies per manifest (everything else is the template). */
const VARIABLE = new Set([
  "manifest_id",
  "event_id",
  "source_epoch",
  "emitted_at",
  "capture_points",
  "uncaptured_classes",
  "manifest_seq",
  "after_source_sequence",
  "unsealed_prior_epochs",
  "unsealed_prior_epoch_count",
  "previous_manifest_sha256",
]);

/** The template a vector's manifest was built from (Python's `_Template`). */
export function templateOf(manifest: Record<string, any>): ManifestTemplate {
  const fixed: Record<string, JsonValue> = {};
  for (const [key, value] of Object.entries(manifest)) {
    if (!VARIABLE.has(key)) fixed[key] = value as JsonValue;
  }
  const points: PointRow[] = manifest.capture_points.map((p: any) => ({
    id: p.id,
    version: p.version,
    kind: p.kind,
    process_global: p.process_global,
    opt_in: p.opt_in,
    fields: p.fields,
  }));
  const initial: Record<string, StateEntry> = {};
  for (const p of manifest.capture_points) initial[p.id] = [p.state, p.reason];
  return {
    sourceId: manifest.source_id,
    fixed,
    points,
    initial,
    uncaptured: manifest.uncaptured_classes,
  };
}

/** The position of an existing manifest document, so `assemble` can rebuild it. */
export function positionOf(manifest: Record<string, any>): ManifestPosition {
  const states: Record<string, StateEntry> = {};
  for (const p of manifest.capture_points) states[p.id] = [p.state, p.reason];
  return {
    epoch: BigInt(manifest.source_epoch),
    seq: Number(manifest.manifest_seq),
    after: BigInt(manifest.after_source_sequence),
    previous: manifest.previous_manifest_sha256,
    states,
    uncaptured: manifest.uncaptured_classes,
    unsealed: manifest.unsealed_prior_epochs.map((e: number | bigint) => BigInt(e)),
    unsealedCount: Number(manifest.unsealed_prior_epoch_count),
    manifestId: manifest.manifest_id,
    eventId: manifest.event_id,
    emittedAt: manifest.emitted_at,
  };
}

/** The id key of the shared vectors (`generate_p0_contracts.py` `KEY1`, `KEY2`). */
export const KEY1 = "fabric-test-id-key-not-a-secret";
export const KEY2 = "another-test-key";

/**
 * Validated settings with the vectors' limits (`LIMITS`: queue 1,024) and a zero clock
 * uncertainty; `overrides` replace plain fields, the secrets stay the resolved ones.
 */
export function settingsFor(
  idKey: string | undefined,
  overrides: Partial<Record<keyof WireSettings, unknown>> = {},
  env: Record<string, string> = {},
): WireSettings {
  const resolved = resolveConfig(
    { queueMaxItems: 1024, ...(idKey === undefined ? {} : { idKey }) },
    { FABRIC_CLOCK_UNCERTAINTY_MS: "0", ...env },
  );
  const out = { ...resolved, ...overrides };
  Object.defineProperty(out, "secrets", { value: resolved.secrets, enumerable: false });
  return out as WireSettings;
}

/**
 * Python's semantic validation of a capture manifest (`validate_coverage_contracts.py`
 * `validate_manifest_document`: schema, registry points and fields, exact integers, the
 * TypeScript qualification rule). Returns `null` when valid, else the error text.
 */
export function pythonValidate(manifest: unknown): string | null {
  const script = `
import json, sys
from pathlib import Path
try:
    import jsonschema  # noqa: F401
except ImportError:
    sys.exit("the contract validator needs jsonschema: run 'uv sync --group dev' in "
             "sdk/python, or point FABRIC_TEST_PYTHON at an interpreter that has it")
sys.path.insert(0, str(Path(sys.argv[1]) / "scripts" / "contracts"))
import validate_coverage_contracts as v
root = Path(sys.argv[1])
reg = v.load_registries(root)
schema = json.loads((root / "contracts/coverage/v1/schema/capture-manifest-v1.schema.json").read_text())
doc = json.loads(sys.stdin.read())
try:
    v.validate_manifest_document(doc, reg, schema)
    print(json.dumps(None))
except Exception as exc:
    print(json.dumps(f"{type(exc).__name__}: {exc}"))
`;
  return runPython(script, [REPO], encodeJson(manifest)) as string | null;
}
