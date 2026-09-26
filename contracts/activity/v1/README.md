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
only: the scenario exercises removed control-surface primitives (policy
verdicts, guardrails, tool authorization, escalation, evaluation, queue
judging, and the guardrail content-reference stamp) that recorder-v1 SDKs
deliberately do not emit. Current Python and TypeScript SDKs support the
scenarios naming `python` or `typescript`; the legacy entries keep the
historical coverage honest instead of claiming current conformance.

Changing a fixture, schema, support declaration, or digest is a public contract change and
must be reviewed as such. Consumers must verify digests before trusting these artifacts.

## Compatibility status

Version 1 remains pinned and unchanged for existing SDK conformance. New recorder data-plane
integrations should use activity v2; v2 is a separate contract and does not reinterpret v1
fixtures or make v1 payloads valid v2 envelopes.
