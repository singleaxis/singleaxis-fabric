# Coverage contract v1 (draft)

Specified by [spec 049 revision 2](../../../specs/049-four-layer-capture-coverage.md)
(four-layer capture contract). **Draft, pending owner confirmation. No
runtime emits these documents yet**, and this family is not part of the
published contracts archive (`scripts/release/release-policy.json`
`public_families`).

| File | Document | Produced by (from its phase) |
|---|---|---|
| `registry/field-registry-v1.json` | `fabric.field-registry/v1` — every four-layer field: id, layer, type, capture point, default policy, privacy class, required/optional, status when the capture point is absent, phase, where it lives, definition; and the coverage profiles | maintained by hand; the spec 049 section 3 tables are generated from it and it wins on any disagreement |
| `registry/vocabularies-v1.json` | coverage statuses, reasons, provenance, capture-point kinds, assertion origins, link types and states, step kinds, actor types, lifecycle and result states, layer verdicts, privacy classes, capture policies | same |
| `registry/content-roles-v1.json` | `fabric.content-role-table/v1` — the content-v2 role widening: per role boundary, provenance, default policy, cap and phase | read by the SDKs and the `fabriccontent` exporter from P0-A |
| `registry/capture-points-v1.json` | `fabric.capture-point-registry/v1` — every capture point, what it can and cannot observe, activation and passivity gate | release coverage matrix |
| `schema/step-projection-v1.schema.json` | `fabric.step-projection/v1` — per-step four-layer field wrappers with coverage status, provenance and locators | `python -m fabric.reconstruct --projection` (P1) |
| `schema/capture-manifest-v1.schema.json` | `fabric.capture-manifest/v1` — JSON form of the per-source-epoch manifest record | every capture source (P1) |

Every document is metadata only. Customer content stays in content-v2
objects in customer-controlled storage; the projection references it by
locator unless it is generated with `--inline-content`.

A validator (`scripts/contracts/validate_coverage_contracts.py`), valid
and invalid fixtures and pinned vectors are P0 deliverables of spec 049.
