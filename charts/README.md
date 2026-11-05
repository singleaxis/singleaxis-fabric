# charts/

Helm charts for deploying Fabric Node — the public, Apache-2.0 recorder
runtime (`CAPTURE -> PROTECT -> DELIVER`).

The umbrella chart is `fabric/`; it vendors exactly one subchart,
`fabric/charts/otel-collector/`, which runs the Fabric Node collector
distribution. **Only the `fabric/` umbrella chart is published** (as a
single OCI artifact) — the subchart is packaged inside it and is not
released or installed independently.

## Profiles

Three postures ship under `fabric/profiles/`:

- [`shadow-dev`](./fabric/profiles/shadow-dev.yaml) — plaintext, no auth,
  for a local trial on trusted clusters.
- [`shadow-production`](./fabric/profiles/shadow-production.yaml) —
  fail-closed: pinned image required, receiver TLS/mTLS enforced, strict
  NetworkPolicy peers, persistent fsync queue, unbounded retry.
- [`shadow-production-host-ingress`](./fabric/profiles/shadow-production-host-ingress.yaml)
  — layered on `shadow-production`: static dedicated ingress groups
  (`receiver.sourceBindings[]`), one agent group and one `host.ebpf` group
  per node, each with its own source, token and port.

See [`../docs/deployment.md`](../docs/deployment.md) for the install path
and [`../specs/027-recorder-v1.md`](../specs/027-recorder-v1.md) for the
release scope.

## Status

No customer production deployment has been qualified; see
[limitations](../docs/limitations-and-roadmap.md).

## Release signing

Published chart OCI artifacts are signed with keyless `cosign`; the current
workflow does not generate a Helm `.prov` file. See
[release verification](../docs/verify-release.md) for digest and signer checks.
