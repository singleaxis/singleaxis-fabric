# Assurance findings across the agent lifecycle

> **Platform design, not recorder v1.** Recorder release artifacts do not
> include the Assurance Finding contract, judge or red-team engines, campaign
> workers, or assurance management. This document is retained as downstream
> SingleAxis Platform design context and must not be used as an OSS runtime
> capability claim.

Fabric Assurance answers a specific question: **what did a defined test,
judge, red-team exercise, or human review conclude about an agent or one of its
recorded actions?** It does not replace runtime enforcement, telemetry
collection, incident management, or evidence retention.

The designed interoperability output is the digest-pinned
[`AssuranceFinding v1 contract`](../contracts/assurance/v1/README.md). The
contract is shared across assurance methods so clients do not need a different
result model for every judge or testing vendor.

## Where each responsibility belongs

| Plane | Responsibility | Does not claim |
| --- | --- | --- |
| Assurance | Execute deterministic tests, red teams, LLM judges, and human review; emit a versioned finding | Runtime telemetry delivery, immutable retention, or inline agent control |
| Observe | Carry the finding and its trace/decision correlation through the approved telemetry path | That the finding is correct or that an evaluation was executed |
| Governance | Retain finding revisions and referenced evidence; join them to the Decision Graph; manage appeal, supersession, incident, and approval history | That merely storing a finding certifies the agent |

Red teaming is therefore an **Assurance activity**, most commonly run before
deployment. A red-team result can be transported by Observe and later retained
by Governance without turning red-team execution into a telemetry feature.
Incident replay and explicitly approved continuous probes may also produce
red-team findings, but their execution policy and worker infrastructure are
outside the OSS contract.

## Lifecycle use

### Pre-deployment

Deterministic suites, simulations, and red teams evaluate an agent bundle,
test case, policy decision, or controlled trace projection. A deployment,
execution, decision, or trace may not exist yet, so those identifiers remain
explicitly `null`. Promotion gates should bind the finding's subject digest to
the exact agent artifact being approved.

### Runtime continuous assurance

Sampling or event-driven evaluation can score approved production activity.
The finding must name the deployment and at least one execution, decision, or
trace identifier. This allows the platform to join the conclusion to the
recorded action without pretending every evaluator receives every ID.

Continuous judges are asynchronous analysis, not an inline safety control. A
judge result arriving after a tool executed can trigger investigation or a
future policy change, but it cannot retroactively authorize or block that
action.

### Incident review

An incident finding requires deployment and incident identity plus causal
execution, decision, or trace correlation. Human reviewers reference protected
review records and policy versions; raw notes and customer content do not enter
the finding envelope. Governance retains the linked evidence and all appeal or
supersession history.

## One finding shape, source-specific provenance

- **Deterministic test:** suite version, deterministic evaluator artifact,
  exact outcome, and referenced test report.
- **LLM judge:** rubric version, evaluator version and digest, provider/model,
  model version when available, configuration digest, and optional confidence.
- **Red team:** suite version, harness provenance, model provenance when a model
  drives the exercise, and a protected transcript reference.
- **Human review:** policy version, reviewer principal reference, review record,
  and incident or decision correlation as applicable.

Confidence may be omitted. A numeric confidence must declare whether it is
calibrated or heuristic; a model's uncalibrated self-assessment must not be
presented as calibrated probability.

## Privacy and evidence handling

An `AssuranceFinding` contains only subject/evidence digests, controlled
references, stable reason codes, bounded scores, and provenance. It has no raw
prompt, completion, transcript, tool argument, tool result, or free-form review
field. Those materials belong in a separately authorized evidence store with
retention, residency, encryption, and access policy appropriate to the client.

An authorized downstream integration may transport the compact finding
alongside normal activity telemetry.
The referenced evidence does not need to leave the customer's boundary. A
SingleAxis Platform deployment can retain the finding and a resolvable customer
reference without receiving the referenced sensitive object.

## Status, appeal, and supersession

`finding_id` is stable; `record_version` makes status history appendable and
auditable. `status_changed_at` records when the represented state took effect,
separately from the original `finalized_at`:

- `final` is the active completed determination.
- `appealed` records an appeal filed after finalization without deleting the
  original version.
- `superseded` points to the replacement finding that should be used for the
  current conclusion.

A replacement finding receives its own `finding_id` and may identify the prior
finding in `supersedes_finding_id`. Findings cannot point to themselves or both
supersede and be superseded in the same record. Governance must retain all
versions and links; the latest status is a view, not an overwrite of evidence.

## Integration checklist

Before accepting a producer's findings:

1. validate the exact schema version and digest-pinned contract;
2. authenticate the producer independently of caller-supplied agent IDs;
3. verify evaluator, rubric, suite, and policy versions against the approved
   deployment profile;
4. confirm trace context and deployment identity came from trusted correlation
   sources;
5. reject inline raw content and resolve evidence references only through an
   authorized evidence service;
6. preserve finding ID, run ID, record version, timestamps, and evaluator
   provenance during transport; and
7. append status transitions and supersession links in Governance storage.

This OSS slice defines and validates the finding envelope. It deliberately does
not ship judge workers, red-team orchestration, model credentials, human review
queues, scheduling, or a Governance database.
