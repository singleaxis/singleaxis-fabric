# Changelog

All notable changes to SingleAxis Fabric will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0-rc.2] - 2026-04-23

Re-cut of `0.1.0-rc.1` to exercise the signing path end-to-end. No
functional changes to Fabric itself — same code, same charts, same
SDK — only a release-pipeline fix so chart signatures actually land.

### Fixed

- **`release.yml` / `publish-chart`**: cosign sign was hitting
  `GET /ghcr.io/token ... UNAUTHORIZED` on `rc.1`. `helm registry login`
  writes to `~/.config/helm/registry/config.json`; cosign reads
  `~/.docker/config.json`. Added a `docker/login-action` step before the
  sign step so cosign can pull the just-pushed manifest by digest.
  `publish-image` was already doing this — `publish-chart` just never
  was.

### Known issues

- Carried forward from `rc.1`: `OpenSSF Scorecard` currently fails on
  `main` because top-level `security-events: write` trips
  scorecard-action's workflow verification. Cosmetic, not
  release-blocking. Will be cleaned up before `0.1.0`.

## [0.1.0-rc.1] - 2026-04-20

First public pre-release of SingleAxis Fabric — the Layer-1 OSS substrate
for audit-ready AI agents. This release cut is a release candidate: the
code, charts, and SDK are frozen against this tag so operators can
install, inspect, and file issues, but the release pipeline itself
(cosign signing, SBOM attachment, GHCR image + chart push) has not yet
been exercised against a real tag. See Known issues below.

### Added

- **Umbrella Helm chart `charts/fabric`** with five optional Layer-1
  subcharts gated by `*.enabled` toggles so operators can start with
  just the collector and layer on guardrails/observability/red-team as
  the deployment matures
  ([008-deployment-model.md](specs/008-deployment-model.md),
  [012-oss-commercialization-strategy.md](specs/012-oss-commercialization-strategy.md)):
  - `otel-collector` — Fabric OTel Collector distribution with the
    `fabricguard`, `fabricpolicy`, `fabricsampler`, and `fabricredact`
    processors.
  - `nemo-sidecar` — NeMo Colang inline guardrails sidecar, Deployment
    form for dev; per-pod sidecar injection lands in Phase 2
    ([005-guardrails-inline.md](specs/005-guardrails-inline.md)).
  - `langfuse` — single-Deployment Langfuse v2 wrapper as the default
    observability sink; tenants at scale swap in the upstream chart.
  - `redteam-runner` — CronJob running Garak + PyRIT against the
    tenant's agent endpoint, emitting results as OTel spans. Opt-in
    (see Security below).
  - `update-agent` — ValidatingAdmissionWebhook over `fabric-system`
    that denies resources whose Fabric signature / version / schema
    annotations don't verify.
- **Two ship-ready regulatory profiles** (`charts/fabric/profiles/`):
  - `permissive-dev` — minimum-viable path for local clusters.
  - `eu-ai-act-high-risk` — fail-closed redact provider, signed updates,
    observability required
    ([009-compliance-mapping.md](specs/009-compliance-mapping.md)).
- **Python SDK `fabric-sdk`** (`sdk/python`) with inline guardrails,
  decision/escalation helpers, Presidio + NeMo clients over UDS,
  HMAC-signed sampler hints, retrieval/memory wrappers, OTel tracing,
  and orchestration adapters for LangGraph, Microsoft Agent Framework,
  and CrewAI as opt-in extras
  ([011-roadmap.md](specs/011-roadmap.md)).
- **Six Python components** with matching Docker/Helm surfaces:
  `presidio-sidecar`, `nemo-sidecar`, `langfuse-bootstrap`,
  `redteam-runner`, `update-agent`, plus the OTel collector
  distribution under `components/otel-collector-fabric`
  (Go / OCB-built).
- **Go Telemetry Bridge** scaffold under `_internal/` as the Layer-2
  ingest path ([004-telemetry-bridge.md](specs/004-telemetry-bridge.md));
  not shipped in the public OSS release.
- **Release pipeline** (`.github/workflows/release.yml`): CI-green gate
  on the tagged SHA, tag-must-be-on-main check, CHANGELOG extraction,
  SPDX + CycloneDX SBOMs, cosign-keyless-signed source archive, signed
  multi-arch collector image to GHCR, signed Helm chart push to GHCR
  OCI, SLSA build-provenance attestations, and a draft GitHub Release.
- **Design-of-record specs** (`specs/000-overview.md` through
  `specs/013-design-partner-model.md`) covering product vision,
  architecture, Context Graph, Telemetry Bridge, guardrails, judges,
  escalation, deployment, compliance mapping, development standards,
  roadmap, OSS commercialization strategy, and design-partner model.

### Changed

- CI scaffolding graduated to enforceable gates: lint + test + security
  scan + DCO, with the release workflow hard-requiring a successful
  `ci.yml` run on the tagged SHA before any artifact is built.

### Security

- **Ed25519 manifest verification** — `update-agent` refuses any
  resource whose Fabric signature does not verify against the
  installed trusted key; the default placeholder
  `REPLACE_AT_INSTALL_TIME` causes the webhook to fail closed until
  operators install a real key
  ([008-deployment-model.md](specs/008-deployment-model.md)).
- **Fabric-canonical JSON** for signable manifest bytes so verification
  is deterministic across producers.
- **HMAC-signed sampler hints** — SDK-emitted sampling hints carry an
  HMAC the `fabricsampler` processor validates before honouring, so
  downstream callers can't forge sampling decisions.
- **PII redaction via UDS** — `fabricredact` processor requires an
  `existingSocketProvider` pointing at a Presidio-compatible redaction
  socket and fails closed unless the operator explicitly sets
  `acceptMissingProvider=true` (dev-only escape hatch).
- **Admission webhook gates** — the `update-agent` webhook must admit a
  resource for it to apply in `fabric-system`; signature, version, and
  schema annotations are all required.
- **Supply chain** — release pipeline produces SPDX + CycloneDX SBOMs,
  keyless cosign signatures via Fulcio for the source archive / image /
  chart, and GitHub attestations for SLSA build provenance. Images are
  signed by immutable digest.
- **Red-team runner opt-in** — `redteamRunner.enabled` defaults to
  false because the CronJob launches live adversarial traffic against
  the tenant's own endpoint; operators must set the flag explicitly.
- **CHANGELOG-must-exist gate** — the release workflow's `changelog`
  job fails loudly if no `## [<version>]` section exists, refusing to
  publish a release with a placeholder body.

### Known issues

- **Single maintainer.** Bus factor of one. Issue triage and PR review
  SLOs are best-effort until a second maintainer is on-board
  ([MAINTAINERS.md](MAINTAINERS.md)).
- **GHCR images and charts do not yet exist.** The
  `ghcr.io/ai5labs/fabric-otelcol` image and the `charts/otel-collector`
  Helm OCI artifact are published by the release workflow; until this
  tag is cut and the workflow succeeds end-to-end, neither is
  resolvable. Installs that pull these refs will fail until first
  successful release.
- **Release pipeline is untested against a real tag.** `release.yml`
  has been linted and shape-reviewed but has never run against an
  actual `v*.*.*` tag. The first cut of `v0.1.0-rc.1` is also the
  first live exercise of cosign + SBOM + SLSA + OCI chart push; expect
  workflow-level fixes in subsequent rc's.
- **Saved views are render-only.** The umbrella chart lints and renders
  against both shipped profiles, but there is no in-cluster E2E test
  yet — no smoke test harness spins up the collector + sidecars + a
  reference agent and asserts end-to-end guardrail + telemetry flow.
  That lands before `v0.1.0` final.
- **Phase-1a scope.** Per
  [012-oss-commercialization-strategy.md](specs/012-oss-commercialization-strategy.md),
  judge-workers, escalation-service, context-graph, telemetry-bridge,
  and NATS broker are intentionally not part of the public chart
  (Layer 2 under `_internal/`); operators deploying the OSS umbrella
  get inline guardrails + collector + opt-in red-team, not the full
  async judge loop.

## [Unreleased]

### Added
_(nothing yet)_

### Changed
_(nothing yet)_

### Deprecated
_(nothing yet)_

### Removed
_(nothing yet)_

### Fixed
_(nothing yet)_

### Security
_(nothing yet)_

---

[Unreleased]: https://github.com/ai5labs/singleaxis-fabric/compare/v0.1.0-rc.1...HEAD
[0.1.0-rc.1]: https://github.com/ai5labs/singleaxis-fabric/releases/tag/v0.1.0-rc.1
