# Fabric activity contract v2

Activity v2 defines the recorder's implementation-neutral activity envelope. Each
event carries stable deployment identity, an authoritative source sequence,
explicit capture semantics, and typed causal references. Correlation identifiers
are optional and each present identifier declares whether it was observed,
reported, or inferred. Agentless integrations must omit identifiers they do not
know; they must never fabricate them as observed facts.
The root schema is a conformance sequence; its `activity-envelope-v2` anchor is the
schema for each event.

Recorder v1 transports protected OTLP. This contract is the public downstream
normalization and interchange target; publication of the schema does not claim
that Fabric Node materializes this JSON envelope in its OTLP pipeline.
[MAPPING.md](MAPPING.md) maps the admitted OTLP wire attributes to the
envelope paths they populate during normalization.

The contract intentionally records observable facts. `reported` and `inferred`
events must never be represented as directly `observed`.

`manifest.json` pins the schema and every valid and invalid fixture by SHA-256.
The validator adds sequence and graph invariants that JSON Schema cannot express:
event IDs are unique, source order is strictly increasing, internal references
resolve to earlier events, external references are explicitly typed, and the
causal graph is acyclic.

Digest scope in this release is **the exact bytes of the pinned UTF-8 JSON file**.
The contract does not claim RFC 8785 canonicalization; reserializing JSON changes
its digest even when the parsed value is equivalent. `manifest.json` pins the
schema and every JSON fixture; Markdown documentation, including this README
and MAPPING.md, is not a pinned artifact.
