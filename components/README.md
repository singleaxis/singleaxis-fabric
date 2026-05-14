# Components

This directory holds the **Layer 1** (public, Apache-2.0) Fabric-authored
services that run inside the `fabric-system` namespace. Each subdirectory
is an independently buildable artifact (container image and, usually, a
Helm subchart).

Components follow the layout described in
[`../specs/002-architecture.md`](../specs/002-architecture.md).

Components not in this repository are maintained by SingleAxis
internally and are not part of this distribution.

## Status

All components are pre-alpha. Directories exist as placeholders with
pointers to the relevant specs. Code lands in Phase 1 onward (see
[`../specs/011-roadmap.md`](../specs/011-roadmap.md)).

## Layout (Layer 1)

| Directory | Role | Primary spec |
|-----------|------|--------------|
| [`nemo-sidecar/`](nemo-sidecar/) | NeMo Colang guardrails sidecar for the SDK | [005](../specs/005-guardrails-inline.md) |
| [`presidio-sidecar/`](presidio-sidecar/) | Presidio PII redaction sidecar | [005](../specs/005-guardrails-inline.md) |
| [`otel-collector-fabric/`](otel-collector-fabric/) | Fabric-standard OTel Collector distribution | [002](../specs/002-architecture.md) |
| [`redteam-runner/`](redteam-runner/) | Scheduled Garak / PyRIT jobs | [002](../specs/002-architecture.md) |
| [`update-agent/`](update-agent/) | GitOps pull of signed manifests | [008](../specs/008-deployment-model.md) |

Third-party subcharts (Postgres, Langfuse) are **not** in this
directory — they are referenced from `../charts/fabric/Chart.yaml` as
upstream dependencies.

## Not here (Layer 2 / Layer 3)

The following live in a separate SingleAxis-internal repo and are not
part of the public release:

- `telemetry-bridge/` — sanitized egress bridge + reference ingest
- `decision-graph/` — Graph Builder worker + read API
- `judge-workers/` — Judge runtime + routing + rubric execution
- `escalation-service/` — HITL review + signed verdict workflow
- `fabric-admin-ui/` — Operator and reviewer UI

The primary specs for these components remain in `../specs/` for
transparency about the design of record; implementation is internal
during Phase 1.

## Component layout convention

Each component follows the same structure:

```
components/<name>/
├── README.md
├── pyproject.toml           # or go.mod, package.json
├── src/                     # or cmd/ + internal/
├── tests/
│   ├── unit/
│   ├── property/            # if applicable
│   ├── integration/
│   └── fixtures/
├── schema/                  # if the component owns a schema
├── docs/                    # component-specific docs
├── Containerfile            # or Dockerfile
├── chart/                   # Helm subchart for this component
└── .component-meta.yaml     # component metadata: language, owner, spec
```

## Component metadata

`.component-meta.yaml` declares:

```yaml
name: <component-name>
language: python | go | typescript
owner: <maintainer-handle-or-team>
primary_spec: specs/NNN-name.md
depends_on:
  - nats
  - postgres
produces_events:
  - subject: fabric.guardrails.action
    schema_version: 1.0
consumes_events:
  - subject: fabric.decisions
    schema_version: 1.0
```

CI uses these metadata files for dependency graph analysis and
spec-to-code traceability.
