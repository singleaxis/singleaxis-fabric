# Recorder v1 compatibility policy

> **Status:** describes the compatibility policy of the released v0.8.0
> artifacts. The artifact boundary it states is enforced by
> [`scripts/release/`](../scripts/release/) (`release-policy.json`) and
> [`scripts/tests/test_recorder_release_boundary.py`](../scripts/tests/test_recorder_release_boundary.py).

The supported public surface consists of released artifacts, not every source
file visible in the repository.

## Supported surfaces

- documented imports exported by the Python `fabric` package;
- documented exports from `@singleaxis/fabric`;
- recorder-only `fabricctl` commands and machine-readable output;
- Fabric Node Helm values accepted by the chart schema;
- the Fabric Node image entry point and documented OTLP receiver/export path;
- public versioned contracts packaged by the release policy; and
- released connector capability manifests.

Internal modules, tests, examples, historical components, superseded specs,
and source excluded from release artifacts are not compatibility commitments.

## Versioning

- Breaking changes to a stable SDK, CLI, or chart surface require a major
  version after 1.0, or a clearly documented release-candidate break before it.
- Additive optional fields and commands may ship in a minor version.
- Fixes that preserve documented behavior ship in a patch version.
- Versioned contract schemas are immutable. A breaking wire change receives a
  new contract version and migration guidance.

Deprecations must identify the replacement, begin warning before removal, and
remain documented for at least one minor release unless a security issue makes
that unsafe.

## Deprecated contract elements

Some contracts still describe evaluation, judge and guardrail-verdict elements
from before the recorder scope. Fabric records activity and does not evaluate
it, so these are deprecated in Fabric v0.9 and dropped at Fabric v1.0. Because
versioned contract schemas are immutable, the drop never edits a v1 schema in
place: the v1 schemas keep accepting these elements and mark each one with
JSON Schema `"deprecated": true`.

- `contracts/connect/v1` (published): the `guardrail_verdict` and `evaluation`
  semantic-surface enum values. Fabric v1.0 removes them in a new connect
  contract version (v2) with migration guidance.
- `contracts/activity/v1` (unpublished, pinned historical contract; the
  release policy ships activity v2 only): the `fabric.guardrail` event
  (including its `fabric.guardrail.entities` PII labels), the `fabric.eval`
  and `fabric.judge.queued` events, the decision-span attributes
  `fabric.blocked`, `fabric.blocked.policies`, `fabric.eval_count`,
  `fabric.eval_rubrics`, `fabric.judge_queued_count` and
  `fabric.judge_rubrics`, and `fabric.escalation.rubric_id` and
  `fabric.escalation.triggering_score`. These are not a published
  compatibility commitment; Fabric v1.0 drops them by retiring activity v1,
  which activity v2 already supersedes.

There is no replacement in Fabric; evaluation results belong to the system
that produces them. Neither SDK emits these elements and no shipped connector
manifest declares them, so there is no runtime warning to act on.

The policy, tool-authorization and escalation verdict elements follow the
same path (spec 057 owner decision OD-11, 2026-11-09):

- `contracts/connect/v1`: the `policy_verdict`, `authorization_verdict` and
  `escalation` semantic-surface enum values. Connect v2 (Fabric v1.0) replaces
  them with `control_decision`, `grant_snapshot` and `extension_inventory`.
- `contracts/activity/v1`: the `fabric.policy.evaluation`,
  `fabric.tool.authorization` and `fabric.escalation` events and their
  attributes.

Each is marked `"deprecated": true` in its v1 schema and stays accepted. The
replacement is one record-only shape with invariants: the control decision
record of spec 057 (`record_control`, `ControlObservation` v2,
`contracts/coverage/v1/schema/control-observation-v2.schema.json`, activity
2.1.0 `control.decision`). Every control decision carries
`enforced_by_fabric=false` and `authentication=unverified_caller_report`;
Fabric records a decision another system made and never makes, applies,
waits for or returns one. No SDK emits the deprecated elements and no
shipped connector manifest declares them.

## Artifact boundary

Release qualification uses explicit allowlists and rejects recorder packages
containing policy, guardrail, judge, red-team, assurance-tier, governance, or
management-plane implementations. The package contents and published digests,
not the source tree alone, define what recorder v1 supports.

## No hidden compatibility promise

Fabric preserves accepted trace/span identity for downstream deduplication, but
does not promise that arbitrary upstream telemetry is complete, correctly
ordered, or semantically equivalent across connectors. Each connector must
declare and test those capabilities.
