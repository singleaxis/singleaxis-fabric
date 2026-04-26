# Changelog

All notable changes to SingleAxis Fabric will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0-rc.5] - 2026-04-27

Hardening pass over the v0.1.0 release surface. Bundles the four PRs
landed since rc.4 (#20, #21, #22, #23). No functional SDK changes;
tenant-facing API stable.

### Changed

- **README rewritten** for customer clarity (#22). Adds badges, a
  "why Fabric" framing, concrete feature list with tech-stack
  links, copy-paste 60-second example, working Helm-from-source
  install, ASCII request-path diagram, and a documentation lookup
  table. Replaces the OSS-vs-services-first intro that buried the
  install path.
- **Apache copyright legal entity** corrected to *AI5Labs Research
  OPC Private Limited* and role emails switched to `singleaxis.ai`
  (#20).
- **GitHub Actions bumped to latest majors** (#23): `checkout` v4 →
  v6, `setup-python` v5 → v6, `setup-go` v5 → v6, `codeql-action` v3
  → v4, `action-gh-release` v2 → v3. All Node 20 → 24 runtime bumps
  with no flag-affecting API change.
- **`cryptography`** upper bound widened to `<47.0` for the
  update-agent (#23). Patches CVE-2026-39892, CVE-2026-34073,
  CVE-2026-26007.
- **OpenTelemetry floor** raised to `>=1.41` across `api`, `sdk`, and
  `otlp` exporter (#23). Previous floor of 1.27 was three years
  stale.
- **`langgraph`** and **`crewai`** upper bounds widened to `<2.0`
  (#23) so the optional adapter extras pick up langgraph 1.x and
  crewai 1.x without manual intervention.
- **`litellm`** force-pinned to `>=1.83.7` (#22) to fix
  GHSA-xqmj-j6mv-4862 (HIGH, RCE in LiteLLM Proxy `/prompts/test`).
  Transitive via `crewai`; core install unaffected.
- **`nemo-sidecar` Dockerfile** rewritten as multi-stage (#21) so
  the `annoy` C++ extension builds against `build-essential` in a
  builder stage and the runtime image stays slim.
- **`charts/fabric` defaults** flipped `nemoSidecar.enabled: false`
  (#21) so a stock install does not `ImagePullBackOff` against an
  image that does not yet publish.
- **Signing posture aligned** across `SECURITY.md`,
  `docs/deployment.md`, and `charts/fabric/README.md` (#21, #22).
  Documents now agree: cosign + SLSA + SBOM ship from `0.1.0`; Helm
  `.prov` provenance is a roadmap item.

### Added

- **Sidecar image build (PR smoke)** matrix CI job (#21) — builds
  all five sidecar Dockerfiles on every PR so a regression like the
  rc.4 nemo build break surfaces in review, not at release.

### Fixed

- **DCO check skips merge commits** (#22) via `git rev-list
  --no-merges`. The synthetic merge commit GitHub creates on
  "Update branch" has no DCO trailer and was failing the check
  even when every authored commit was signed off.
- **`commitlint` subject-case rule disabled** (#23). Was rejecting
  Dependabot's `Bump X from Y to Z` capitalization and silently
  blocking every dep update.
- **CodeQL Go autobuild Go version pin** corrected to 1.25 (#23).
  Latent issue exposed by `setup-go@v6` enforcing local toolchain;
  the otel-collector processors require Go 1.25 in their `go.mod`.
- **Lychee link-check excludes** for `slsa.dev` (#22) and
  `securityscorecards.dev` (#23). Both flake on connection-reset
  under CI crawl bursts.

### Operator action required

None for tenants upgrading from rc.4. Bumping `litellm` and OTel
floors is transparent at install; pinned environments continue to
resolve.

## [0.1.0-rc.4] - 2026-04-24

Re-cut of `0.1.0-rc.3` (yanked on PyPI) with the Python distribution
version now derived from the git tag at build time, plus the GitHub
org rebrand from `ai5labs` to `singleaxis`. No functional changes to
Fabric itself.

rc.3 was yanked because the SDK hardcoded `_version.py = "0.1.0"`
while the tag was `v0.1.0-rc.3`. PEP 440 would have normalized the
tag to `0.1.0rc3`, but the static version meant PyPI received the
pre-release artifact in the stable `0.1.0` slot — pre-release code
masquerading as GA. rc.4 moves the version source to the tag (via
hatch-vcs) so every build wears the version its tag commits to.

### Changed

- **Python version is now derived from the git tag** via `hatch-vcs`
  (`[tool.hatch.version] source = "vcs"`). The previous static
  `_version.py` is replaced by an `importlib.metadata` runtime
  lookup that reads whatever PyPI gave the installed distribution.
  Dev checkouts without a tag resolve to `0.0.0.dev0`.
- **GitHub org** `ai5labs/singleaxis-fabric` → `singleaxis/singleaxis-fabric`.
  GitHub creates redirects for old URLs, but hardcoded refs have been
  rewritten: 4 collector-processor `go.mod` declarations,
  `ocb-config.yaml` gomod + replace directives, `sdk/python/pyproject.toml`
  project URLs, quickstart clone URL, lychee URL exclusions,
  CHANGELOG link-refs, ISSUE_TEMPLATE contact links, CODEOWNERS
  comment.
- **Container image** published to `ghcr.io/singleaxis/fabric-otelcol`
  (was `ghcr.io/ai5labs/...`). Release workflow uses
  `${{ github.repository_owner }}` so this change is automatic.

### Fixed

- **OpenSSF Scorecard workflow permissions** — top-level
  `permissions: security-events: write` was rejecting Sigstore/Fulcio
  webapp publishing with HTTP 400. Scoped `security-events: write`
  per-job (`trivy-fs`, `semgrep`); Scorecard's job keeps its own
  block. Top-level stays read-only so Fulcio accepts the SARIF.

### Operator action required

- If you were tracking a PyPI pending-publisher on `ai5labs/singleaxis-fabric`,
  update the owner to `singleaxis`. Trusted publishing is bound to
  the full `owner/repo` path, so the old config stops matching after
  the transfer. Done before this tag was cut.

## [0.1.0-rc.3] - 2026-04-24

Re-cut of `0.1.0-rc.2` with the Python distribution renamed and an
actual PyPI publish step wired in. Up to rc.2 the quickstart told
prospects to `pip install fabric-sdk` — that name is squatted on
PyPI by an abandoned unrelated Hyperledger SDK, so anyone following
the quickstart got the wrong package. No functional changes to
Fabric itself.

### Changed

- **Python distribution renamed** `fabric-sdk` → `singleaxis-fabric`.
  Import path is unchanged: `from fabric import ...` still works
  (the module name stays `fabric`, only the PyPI distribution name
  changed). Mirrors the standard pattern where distribution name
  and module name differ (`opencv-python` / `cv2`, `PyYAML` / `yaml`).
- **OTel instrumentation scope** constant `FABRIC_SDK_NAME` now
  emits `singleaxis-fabric-python` instead of `fabric-sdk-python`,
  so dashboards keying off `telemetry.sdk.name` see the new name.

### Added

- **`release.yml` `publish-pypi` job** using PyPA trusted publishing
  (no PyPI API token needed — keyless OIDC exchange). Builds both
  sdist and wheel from `sdk/python/` and uploads on every `v*.*.*`
  tag. `skip-existing: true` so a re-run on the same version is a
  no-op rather than a hard failure.

### Operator action required

- Before tagging `v0.1.0-rc.3`, configure a **pending publisher**
  on [pypi.org](https://pypi.org/manage/account/publishing/):
  project = `singleaxis-fabric`, owner = `ai5labs`, repo =
  `singleaxis-fabric`, workflow = `release.yml`. Takes ~2 min and
  is only needed once; after the first successful publish PyPI
  promotes it to a regular trusted publisher automatically.

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
- **Python SDK `singleaxis-fabric`** (`sdk/python`) with inline guardrails,
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

[Unreleased]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.1.0-rc.4...HEAD
[0.1.0-rc.4]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.4
[0.1.0-rc.3]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.3
[0.1.0-rc.2]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.1
