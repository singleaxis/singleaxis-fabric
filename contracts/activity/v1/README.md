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

The `support` array on each scenario records which SDK line produced the golden. It is a
historical declaration: the full SDK conformance suites that executed every declared
scenario were retired with the passive-capture release qualification (#161), and no
current suite runs the whole manifest. Today only the `hook` and `interaction_tagged`
goldens are reproduced, by `sdk/python/tests/test_activity_v1_goldens.py` and
`sdk/typescript/test/activity-v1-goldens.test.ts`; the other `python` / `typescript`
declarations are not re-verified against the current SDKs.

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

## Deprecated in Fabric v0.9

Activity v1 is an unpublished, pinned historical contract: the release policy ships
activity `v2` only, so this deprecation carries no published-compatibility promise. The
schema elements below are deprecated in Fabric v0.9 because Fabric records activity and
does not evaluate it. Each carries JSON Schema `"deprecated": true` and a description;
validation is unchanged, so every document that is valid today stays valid against v1.

Contract schemas are immutable (see [API stability](../../../docs/api-stability.md)), so
Fabric v1.0 does not edit v1 in place. It drops these elements by retiring activity v1,
which v2 already supersedes; v2 carries none of them.

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
that produces them. Neither current SDK emits these elements.

This deprecation covers the evaluation, judge and guardrail elements the v0.9 decision
named. The `fabric.policy.evaluation`, `fabric.tool.authorization` and `fabric.escalation`
events and their span attributes (`fabric.policy_evaluation_count`,
`fabric.policy_engines`, `fabric.tool_authorization_count`, `fabric.escalated`,
`fabric.escalation.reason`, `fabric.escalation.mode`) are not deprecated by it. Whether
they follow the same path is an open owner decision; until it is made they keep their
current status.

The goldens use neutral example values (`example:category`, `example:label`,
`stub-redactor:canary`, `example-redactor`) rather than attack-taxonomy tags or
PII-flavoured labels.

## Compatibility status

Version 1 remains pinned by digest as a historical contract. Its example values were
neutralized in Fabric v0.9 (the fixture digests were re-pinned) and only the goldens named
above are reproduced by current SDK tests. New recorder data-plane integrations should use
activity v2; v2 is a separate contract and does not reinterpret v1
fixtures or make v1 payloads valid v2 envelopes.
