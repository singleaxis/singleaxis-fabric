# API stability and compatibility

This document defines what SingleAxis Fabric considers a stable, supported
interface, and what may change without notice. It is the contract enterprise
adopters can build against.

Fabric follows [Semantic Versioning](https://semver.org/). The project is
pre-1.0; see [_Pre-1.0 expectations_](#pre-10-expectations) below.

## What is public

For the Python SDK (`singleaxis-fabric`), the **supported public surface** is:

- Every name exported from the top-level `fabric` package — i.e. the names in
  `fabric.__all__` (e.g. `Fabric`, `FabricConfig`, `Decision`, `LLMCall`,
  `ToolCall`, the protocol/value types, and the public exceptions).
- The documented method signatures on those types.
- The emitted **wire contract**: the `fabric.*` / `gen_ai.*` span and span-event
  attributes, governed by `fabric.schema_version` (see below).
- The guardrail-sidecar HTTP contracts and the umbrella Helm chart's documented
  values.

Anything else is **internal** and carries no compatibility guarantee:

- Modules and names prefixed with an underscore (`fabric._calls`,
  `fabric._chain`, `fabric._uds`, `fabric._id_validators`, `_util`, etc.).
- Test suites, the conformance harness, the benchmark and soak suites.
- Behaviour not described in the specs or docstrings.

Optional integrations (the `[langgraph]`, `[crewai]`, `[agent-framework]`,
`[opa]`, `[deepeval]`, `[ragas]`, `[nats]`, `[redis]`, `[aws]`, `[mcp]`,
`[otlp]`, `[model]` extras) are public but version-tracked against their
upstream libraries; their adapters may change to follow upstream API shifts
within a minor release.

## The schema-version contract

Every emitted decision span and span event carries
`fabric.schema_version` (currently `"1.0"`). This is the contract the
Telemetry Bridge, replay engine, audit exporters, and any non-Python SDK
consume.

- **Additive** changes (a new optional attribute or event, emitted only when a
  new feature is used) keep the same `schema_version`. Existing events stay
  byte-identical. These ship in a minor or patch release.
- **Breaking** changes to the wire shape (renaming/removing an attribute,
  changing a type, changing when an existing attribute is emitted) bump
  `schema_version` and are a major-version concern.

The schema is frozen as machine-readable **golden fixtures** under
`sdk/python/tests/conformance/`. Any change that alters an existing emitted
event fails the conformance suite, so wire-contract drift cannot land silently.
A reusable adapter-conformance kit (`tests/conformance/adapters/`) lets
third-party adapters prove protocol compliance.

## Deprecation policy

When a public API element is to be removed:

1. It is marked deprecated in its docstring and the
   [CHANGELOG](../CHANGELOG.md), with the replacement named.
2. It continues to work for at least one subsequent **minor** release
   (post-1.0), emitting a `DeprecationWarning` where practical.
3. It is removed no earlier than the next **major** release.

Breaking changes are flagged in commits with a `!` after the type and a
`BREAKING CHANGE:` footer (see [CONTRIBUTING](../CONTRIBUTING.md)), and called
out in the CHANGELOG.

## Pre-1.0 expectations

Until `1.0.0`:

- The capture **wire contract** (`schema_version`) is treated as stable and
  evolved additively — it is the part downstream systems depend on, and it is
  conformance-locked.
- The **Python API surface** may still see ergonomic adjustments between minor
  releases; such changes are documented in the CHANGELOG.
- Per the [security policy](../SECURITY.md), only the latest minor release
  receives fixes pre-1.0.

## Supported runtimes

- Python 3.11, 3.12, 3.13 (tested in CI on all three).
- The collector and sidecars ship as multi-arch (amd64/arm64), cosign-signed
  container images with SBOMs.
