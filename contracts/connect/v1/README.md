# Fabric Connect capability contract v1

This contract makes every integration state what it can **prove**, rather than
letting the words “connected” or “monitored” imply complete agent visibility.
It is the machine-readable boundary between an integration and the Fabric
activity contract.

## Contract contents

- [`manifest.json`](manifest.json) pins the schema, released capability
  manifests, and positive/negative fixtures by SHA-256.
- [`schema/connector-capability-v1.schema.json`](schema/connector-capability-v1.schema.json)
  defines the closed document shape.
- [`manifests/`](manifests/) describes the current Python SDK, TypeScript
  capture SDK, Collector OTLP and audit receivers, and the eBPF host emitter.
- [`fixtures/valid/`](fixtures/valid/) demonstrates the minimum honest shape
  for framework adapters, gateways, and existing vendor receivers.
- [`fixtures/invalid/`](fixtures/invalid/) locks rejection of common
  overclaims.

The contract separates:

1. semantic surfaces and how each surface is learned;
2. agent-path control from post-action telemetry processing;
3. raw-content capability from its default;
4. asserted identifiers from authenticated workload identity;
5. protocol propagation from actual correlation guarantees;
6. transport capability from durable evidence retention; and
7. shipped verification evidence from known blind spots.

An eBPF-assisted connector is deliberately constrained to process, network,
and file metadata. Kernel discovery can find a workload or an uninstrumented
dependency, but it cannot claim prompts, policy verdicts, tool meaning, or
agent decision semantics.

## `compatibility.activity_contract`

This field names the version of the **activity v1 wire contract**
(`contracts/activity/v1`, manifest version `1.0.0`) whose span and event
attributes the connector emits, or `null` when the connector does not
implement that wire contract. It is not an Activity Envelope v2 claim:
recorder v1 transports protected OTLP and does not materialize the v2 JSON
envelope on the wire, so every shipped manifest in `manifests/` sets
`activity_contract: null`. The illustrative `fixtures/valid/` documents show
`"1.0.0"` for connectors that emit the v1 attribute contract.

## Validate

From the repository root:

```bash
python scripts/contracts/validate_connector_contract.py
```

The validator checks JSON Schema, semantic consistency, pinned digests,
unique connector identities, negative-fixture error codes, and complete
coverage of every JSON artifact under this version. `manifest.json` pins the
schema and every JSON manifest and fixture by SHA-256; Markdown
documentation, including this README, is not a pinned artifact.

## Change control

Treat every manifest change as a public compatibility and assurance change.
A change is ready only when:

1. the implementation and version-specific tests support the claim;
2. evidence paths identify executable repository checks;
3. raw-content, identity, authentication, egress, and blind-spot declarations
   have been reviewed;
4. negative fixtures cover any new impossible combination; and
5. all changed digests are intentionally updated in `manifest.json`.

Do not copy these documents into SDKs. Consumers and CI must read this single,
versioned contract location.
