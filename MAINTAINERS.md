# Maintainers

This file lists current maintainers of SingleAxis Fabric, their areas of
responsibility, and contact information.

Maintainer roles are defined in [`GOVERNANCE.md`](GOVERNANCE.md).

## Project lead

SingleAxis Fabric is in **Phase 1a** (OSS pre-release). The project
currently has a **single maintainer**: the AI5 Labs founder/operator.
Per [`GOVERNANCE.md`](GOVERNANCE.md#technical-steering-committee-tsc),
once there are 5+ maintainers from 2+ organisations, the project will
transition to a Technical Steering Committee (TSC). Until then, the
project's technical direction is led by the AI5 Labs technical lead.

| Name  | GitHub     | Email                | Areas |
|-------|------------|----------------------|-------|
| Bryan | @jrcks67   | bryan@singleaxis.ai    | All   |

## Core maintainers

Phase 1a has a single maintainer across all components. As additional
maintainers are onboarded, this section will list them with their
primary component ownership.

| Name  | GitHub   | Component | Email             |
|-------|----------|-----------|-------------------|
| Bryan | @jrcks67 | All       | bryan@singleaxis.ai |

## Component maintainers

Until component-specific maintainers are onboarded, the project lead
owns all component areas. Listed here so CODEOWNERS routing stays
honest about who actually reviews.

| Component                           | Maintainers                           |
|-------------------------------------|---------------------------------------|
| `charts/fabric`                     | @jrcks67                              |
| `components/presidio-sidecar`       | @jrcks67                              |
| `components/nemo-sidecar`           | @jrcks67                              |
| `components/otel-collector-fabric`  | @jrcks67                              |
| `components/langfuse-bootstrap`     | @jrcks67                              |
| `components/redteam-runner`         | @jrcks67                              |
| `components/update-agent`           | @jrcks67                              |
| `sdk/python`                        | @jrcks67                              |
| `specs/`                            | Project lead + assigned spec authors  |

Layer 2 / Layer 3 components live in a separate SingleAxis-internal
repo and do not have external maintainer slots — see
[`specs/012-oss-commercialization-strategy.md`](specs/012-oss-commercialization-strategy.md).

## Emeritus

Maintainers who have stepped down or become inactive. We thank them for
their service.

_(none yet)_

## How to become a maintainer

See the "Roles" section of [`GOVERNANCE.md`](GOVERNANCE.md) and the
contributor ladder in [`CONTRIBUTING.md`](CONTRIBUTING.md). In short:

1. Contribute sustained, high-quality work to a component.
2. Be nominated (or self-nominate) after ~5 non-trivial PRs in that
   component.
3. Current maintainers decide by lazy consensus over 7 days.

Growing the maintainer bench is a Phase 1a priority — reach out via the
addresses below if you are interested.

## How to reach a maintainer privately

- Security: `security@singleaxis.ai` (see [`SECURITY.md`](SECURITY.md))
- Code of Conduct: `fabric-conduct@singleaxis.ai`
- General: `fabric-maintainers@singleaxis.ai`
