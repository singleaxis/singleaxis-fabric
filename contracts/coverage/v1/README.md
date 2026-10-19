# Coverage contract v1 (draft)

Specified by [spec 049 revision 6](../../../specs/049-four-layer-capture-coverage.md)
(four-layer capture contract). **Draft contract family; spec 049 rev 6.2 owner-approved 2026-10-18. No
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
| `registry/vocabularies-v1.json` | statuses, reasons, field classes, provenance, capture-point kinds, assertion origins, link types and states, inference methods, step kinds, actor types, lifecycle and result states, layer verdicts, privacy classes, capture policies, capture inputs, store reasons, commit bases |
| `registry/capture-points-v1.json` | `fabric.capture-point-registry/v1` — every capture point, what it can and cannot observe, activation, passivity gate and the fields it `supplies` |
| `registry/content-roles-v1.json` | `fabric.content-role-table/v1` — every content-v2 role (existing and new) with layer, boundaries, provenance, media types, default policy, cap and phase |
| `registry/telemetry-keys-v1.json` | `fabric.telemetry-key-registry/v1` — every new telemetry key and every changed validator of an existing key |
| `schema/step-projection-v1.schema.json` | `fabric.step-projection/v1` — per-step four-layer field wrappers and verdicts |
| `schema/capture-manifest-v1.schema.json` | `fabric.capture-manifest/v1` — JSON form of the per-source-epoch manifest record |

Fixtures and vectors (spec 049 P0, section 8.2; each pinned with its
expectation, and each invalid fixture with the error code it must raise):

| Path | Pins |
|---|---|
| `valid/projection-*.json`, `invalid/projection-*.json` | field wrappers: empty versus absent (an empty value is `captured`; `absent` carries no value and needs a parsed carrier), conflict (every assertion kept, none chosen), unsupported, unknown identity (`not_captured(missing_id_key)`, `unknown`, no clear id), extension step kinds and `x-` fields, tentative links and the fixed confidence of each inference method, `same_as` only by `trace_id_match` / `cross_run_previous_response`; run states `open`, `unterminated` and `conflicted` with `segment_missing`, `segment_conflict` (a replayed branch id) and `post_terminal_activity`; branch ids; predecessor entries |
| `valid/manifest-*.json`, `invalid/manifest-*.json` | manifest states: capture points `active`, `installed_inactive`, `disabled`, `unsupported` (TypeScript `wire.ts.undici`), `failed`; content capture enabled/disabled/metadata-only with its reason and policy; keyed/unkeyed with `key_id`; manifest 0 at position −1; unsealed prior epochs beyond the 64-entry list; capture points and fields agree with the registry |
| `fixtures/vectors/manifest-chain-v1.json` | `manifest_seq` chaining by canonical digest; only capture-point state changes within an epoch |
| `fixtures/vectors/manifest-span-v1.json` | the `fabric.capture_manifest` span form: every attribute passes its key check and `contracts/capture/v1/schema/capture-manifest-record-v1.schema.json` (generated from this family by `--write`), and rebuilds the manifest exactly |
| `fixtures/vectors/resume-token-v1.json` | `fr2/` resume tokens, branch tokens, predecessor entries, environment and percent-encoded `baggage` joins |
| `fixtures/vectors/run-marker-v1.json` | `run_start`, `segment_seal` and `run_end` attribute sets fabricguard admits intact, and values it strips |
| `fixtures/vectors/pseudonym-v2.json` | function v2 for provider ids, `kid-` key ids, domain separation from v1 and between keys, the legacy `p-` + 16 hex form; capture/v1's v1 vectors are re-verified unchanged |

Each telemetry-key row carries `check`, the machine-readable form of its
validator that fabricguard applies key by key (the Go test reads this file),
or `check_pending` naming why the key is not admitted yet. Keys with
`owner: receiver` are stripped from agent-supplied records.

Every document is metadata only.
