# Recorder v1 compatibility policy

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
