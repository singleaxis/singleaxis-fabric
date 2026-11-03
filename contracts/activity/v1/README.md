# Fabric activity contract v1

This directory is the public, implementation-neutral wire-contract fixture set for Fabric
activity telemetry. SDKs and downstream consumers use the same schema, scenario manifest,
and normalized golden payloads; no language SDK is the canonical contract by itself.

## Contents

- `manifest.json` identifies the contract and pins the schema and every scenario fixture by
  SHA-256 digest.
- `schema/fabric-decision-v1.schema.json` is the JSON Schema for decision spans and Fabric
  events.
- `goldens/*.json` are deterministic normalized traces produced by the named scenarios.

The `support` array on each scenario is an explicit compatibility declaration. An
implementation must execute exactly the scenarios that name it: neither missing declared
coverage nor undeclared extra coverage is accepted by the conformance suites. A scenario
without `typescript` support remains visible in this manifest so partial parity cannot be
misrepresented as full parity.

A `python-legacy` or `typescript-legacy` entry names the pre-recorder SDK line
only: the scenario exercises a removed control-surface primitive (the
guardrail content-reference stamp) that recorder-v1 SDKs deliberately do not
emit. Current Python and TypeScript SDKs support the scenarios naming
`python` or `typescript`; the legacy entry keeps the historical coverage
honest instead of claiming current conformance.

The legacy scenarios outside the OSS recorder scope (`policy_*`,
`guardrail_*`, `tool_authorization_*`, `escalation`, `eval_record` and
`queue_judge`) were retired to git history by spec 049 P0. Activity v1 is
not a published contract version (`scripts/release/release-policy.json`
publishes activity `v2` only).

Changing a fixture, schema, support declaration, or digest is a public contract change and
must be reviewed as such. Consumers must verify digests before trusting these artifacts.

## Deprecated in v0.9

The following schema elements are deprecated in v0.9 and will be removed in
contract v1.0. Fabric records activity and does not evaluate it. Each carries
JSON Schema `"deprecated": true` and a description; validation is unchanged,
so every document that is valid today stays valid until v1.0.

| Element | Kind |
| --- | --- |
| `fabric.guardrail` (with `fabric.guardrail.entities` PII labels) | span event |
| `fabric.eval` | span event |
| `fabric.judge.queued` | span event |
| `fabric.blocked`, `fabric.blocked.policies` | decision-span attributes |
| `fabric.eval_count`, `fabric.eval_rubrics` | decision-span attributes |
| `fabric.judge_queued_count`, `fabric.judge_rubrics` | decision-span attributes |
| `fabric.escalation.rubric_id`, `fabric.escalation.triggering_score` | decision span and `fabric.escalation` event |

There is no replacement inside Fabric: evaluation results belong to the system
that produces them. Neither current SDK emits these elements. The goldens use
neutral example values (`example:category`, `example:label`,
`stub-redactor:canary`, `example-redactor`) rather than attack-taxonomy tags or
PII-flavoured labels.

## Compatibility status

Version 1 remains pinned and unchanged for existing SDK conformance. New recorder data-plane
integrations should use activity v2; v2 is a separate contract and does not reinterpret v1
fixtures or make v1 payloads valid v2 envelopes.
