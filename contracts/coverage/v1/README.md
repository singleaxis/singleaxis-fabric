# Coverage contract v1 (draft)

Specified by [spec 049 revision 3](../../../specs/049-four-layer-capture-coverage.md)
(four-layer capture contract). **Draft, pending owner confirmation. No
runtime emits these documents yet**, and this family is not part of the
published contracts archive (`scripts/release/release-policy.json`
`public_families`).

The registries are the single source of truth for spec 049's field
inventory and tables. `python scripts/contracts/validate_coverage_contracts.py`
checks them against each other, against the two schemas and content-v2,
checks every pin in `manifest.json`, and fails if any generated block of the
spec differs from its rendering; `--write` regenerates the blocks.
`scripts/tests/test_coverage_contracts.py` runs it.

| File | Document |
|---|---|
| `registry/field-registry-v1.json` | `fabric.field-registry/v1` — every four-layer field (id, layer, type, capture-point ids that observe it, default policy, privacy class, required/optional, status when the capture point is absent, phase, where it lives, definition) and the coverage profiles |
| `registry/vocabularies-v1.json` | statuses, reasons, field classes, provenance, capture-point kinds, assertion origins, link types and states, inference methods, step kinds, actor types, lifecycle and result states, layer verdicts, privacy classes, capture policies, source paths, store reasons, commit bases |
| `registry/capture-points-v1.json` | `fabric.capture-point-registry/v1` — every capture point, what it can and cannot observe, activation, passivity gate and the fields it `supplies` |
| `registry/content-roles-v1.json` | `fabric.content-role-table/v1` — every content-v2 role (existing and new) with layer, boundaries, provenance, media types, default policy, cap and phase |
| `registry/telemetry-keys-v1.json` | `fabric.telemetry-key-registry/v1` — every new telemetry key and every changed validator of an existing key |
| `schema/step-projection-v1.schema.json` | `fabric.step-projection/v1` — per-step four-layer field wrappers and verdicts |
| `schema/capture-manifest-v1.schema.json` | `fabric.capture-manifest/v1` — JSON form of the per-source-epoch manifest record |

Every document is metadata only.
