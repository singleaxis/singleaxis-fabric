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
| `schema/record-evidence-v1.schema.json` | `fabric.record-evidence/v1` — the structured-evidence carrier (spec 050 §3.4a) |

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
| `fixtures/vectors/pseudonym-v2.json` | function v2 for all 18 prefixes and their type strings (§2.9), `kid-` key ids, domain separation between types, from v1 and between keys, the legacy `p-` + 16 hex form; capture/v1's v1 vectors are re-verified unchanged |

Spec 050 (P1) adds, in version 1.1.0:

| Path | Pins |
|---|---|
| `schema/record-evidence-v1.schema.json`, `evidence/*.schema.json` | the structured-evidence carrier `fabric.record-evidence/v1` (one per records-input record, role `record.evidence`) and each registered evidence type's closed item schema (`field-registry-v1.json` `evidence_types`; P1 registers only `fabric.test.items/v1`) |
| `valid/evidence-*.json`, `invalid/evidence-*.json` | carrier documents: an unknown type, an extra key, free text over the bound, too deep, too many items, a CONTENT-class value; a clear-mode id valid only under a clear-mode manifest |
| `fixtures/vectors/seal-digest-v1.json` | record digests (exchange, record with bodies, descriptor-only body, evidence object, receiver-owned key exclusion, int64 typing) and segment seal digests with segment-attributed losses |
| `fixtures/vectors/span-category-v1.json` | every branch of fabricguard's span-name category, which a record's span name must equal |
| `fixtures/vectors/records-span-v1.json` | the records-class key table (registry `placement` and `capture_check`) and rule A: admitted and dropped attributes |
| `fixtures/vectors/seal-parity-v1.json` | spans as the emitter writes them, the Node export and the digest it must reproduce (T3) |
| `fixtures/vectors/resume-token-v2.json` | `fr3/` tokens with the run correlation id, the `fr2/` legacy parse, token issue, carriers, run-identity rules 1–5 and `end_run` |
| `fixtures/vectors/record-evidence-v1.json` | the Node envelope check, per-type item errors, projected fields, and a record's evidence object in its digest and seal |
| `fixtures/projection/*.json` | model-call field extraction per dialect (chat, responses, Anthropic messages, embeddings; document and stream) and the 40 MiB / 70 MiB size outcomes |
| `valid/projection-records-explicit-d2.json`, `valid/projection-many-records.json` | D2 `deferred_to_explicit` fields; an attempt with 300 records (64 `event_ids`, `collection: partial`) |

Spec 056 (agent action reconstruction, milestone M1) adds, in version 1.2.0:

| Path | Pins |
|---|---|
| `registry/vocabularies-v1.json` | inference methods `sequence_bracket` (tentative), `output_match` (certain), `process_anchor` and `process_lineage` (confidence `varies`: certain only with matching process start times); the action-chain, `effect_not_observed` and `remote_sandbox` reasons |
| `registry/telemetry-keys-v1.json` | `fabric.process.parent_pid` and `fabric.process.start_ns` (placement `record`, capture point `exec.subprocess` only: the first conditional rows); placement `record` for `fabric.process.pid`, `.exit_code`, `.signal` and the C41 execution keys |
| `registry/field-registry-v1.json`, `evidence/fabric.exec.observation-v1.schema.json` | the spec 053 §3.2 evidence type of `exec.subprocess` records |
| `valid/evidence-exec-*.json`, `invalid/evidence-exec-*.json` | one valid document per `api` value; an extra key, an unknown enum value, a string over its bound, a path in a LABEL and a capture point the type is not registered for |
| `fixtures/action-record/` | the shared interface goldens (an `exec.subprocess` attempt's records, today's local-profile host records, the spec 053 §6.2.3 host span) and the rule fixtures A0-A4, H1-H4, the §6.1 edge cases and AR-1; [its README](fixtures/action-record/README.md) documents every field |

Spec 056 milestone M2 (production profile, WP6-11) adds, in version 1.3.0:

| Path | Pins |
|---|---|
| `registry/telemetry-keys-v1.json` | the spec 053 §6.2.3 host-record keys (`fabric.sensor.*`, including `ns_pid`, `ns_ppid`, `pid_ns`, `scope`, `pod_id`, and `fabric.tenant_id`): placement `record`, `capture_point_kinds: ["S"]`; `fabric.sensor.upstream_lost` and `.upstream_loss_reason` (with `scope_late`) on `periodic` heartbeats; `fabric.process.pid_ns` and `fabric.sandbox.created_id` on `exec.subprocess` only; `http.request.method` and `.status_code` on `http.nonmodel` records; `fabric.network.host_id` on records |
| `registry/capture-points-v1.json` | the `remote.sandbox` point (kind H, E2B), `http.nonmodel` on the records input, the production host rows |
| `registry/field-registry-v1.json`, `evidence/fabric.{http,sandbox}.observation-v1.schema.json` | the evidence types `fabric.http.observation/v1` and `fabric.sandbox.observation/v1`, with one valid fixture per enum branch and five refusals each (`{valid,invalid}/evidence-{http,sandbox}-*.json`) |
| `registry/vocabularies-v1.json`, `schema/step-projection-v1.schema.json` | the inference method `sandbox_report` (rule H5, certain, provenance reported) |
| `schema/capture-manifest-v1.schema.json` | `sdk.language` `go` and the `sensor_*` uncaptured classes, for a host source's manifest |
| `fixtures/vectors/peer-address-v1.json`, `sandbox-id-v1.json` | the canonical peer text that `fabric.network.host_id` keys; container and pod ids from cgroup names and from container-runtime output |
| `fixtures/vectors/span-category-v1.json`, `records-span-v1.json` | the `fabric.sensor_event` branch (`sensor_cases`); the M2 records cases and the host-record cases with the host placement (`host_cases`, `host_placement`) |
| `fixtures/action-record/` | the §6.1 M2 rule fixtures, four refusals, the goldens' M2 sections and `remote-sandbox-records.json` ([its README](fixtures/action-record/README.md), section 9) |

The rules the fixtures pin are executable in
`scripts/contracts/action_reference.py`; `scripts/contracts/action_record.py`
and `action_record_m2.py` build the fixtures and check them, and
`scripts/contracts/host_records.py` builds and checks the host vectors.

The vectors are produced and re-checked by the reference implementations in
`scripts/contracts/p1_reference.py` and `scripts/contracts/model_fields_reference.py`.
Telemetry-key rows may carry `placement` (the capture record classes a key may
appear on: `exchange`, `record`, `loss`, a heartbeat kind or `manifest`) and,
for a reused key, `capture_check` (its closed check on those classes). The
records class admits exactly the keys placed on `record`; fabricguard's
`recordKeyValidators` and the SDK's `fabric/_records_keys_generated.py` are
generated from those rows.

Each telemetry-key row carries `check`, the machine-readable form of its
validator that fabricguard applies key by key (the Go test reads this file).
Every key is admitted in P0 (spec 049 rev 6.3 §4.2); `admission` names the
exceptions: `existing` (enforced by older fabricguard code), `never`, or
`P0-A` (a tightening validator that switches in its phase). Keys with
`owner: receiver` are stripped from agent-supplied records.

The checks, these fixtures and vectors, the family pins and fabricguard's
generated validator table are derived by
`scripts/contracts/generate_p0_contracts.py`; `--check` (and
`scripts/tests/test_contract_generators.py`) fails if regenerating would
change any of them.

Every document is metadata only.
