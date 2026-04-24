---
title: Development, Testing & Release Standards
status: draft
revision: 1
last_updated: 2026-04-18
owner: project-lead
---

# 010 — Development Standards

## Summary

Fabric is intended to be open-sourced, audited by enterprise security
teams, and trusted by regulators. This spec fixes the engineering
standards — languages, tooling, testing coverage, CI gates, supply-
chain practices, release signing — that the project commits to
before the first public release.

Where we cut corners, we document it. Where we raise the bar beyond
typical OSS projects, we also document it — because regulatory
reviewers will ask.

## Goals

1. Define the language and tooling baseline.
2. Define the testing taxonomy and minimum coverage bars.
3. Define CI gates that every PR must pass.
4. Define release-engineering practices: signing, SBOM, provenance.
5. Define dependency governance and licence policy.
6. Make these standards **enforceable by automation**, not by
   reviewer vigilance.

## Non-goals

- Exhaustive style guide. Linters enforce style; this spec defines
  what linters run, not what they enforce.
- Component-specific standards. Individual components may add
  stricter requirements (noted in their own READMEs); they cannot
  relax project-wide standards.

## Languages and runtimes

| Language | Version | Use |
|----------|---------|-----|
| Python | 3.12+ | Judges, Graph Builder, SDK (primary), Bridge, Admin UI backend |
| Go | 1.22+ | Telemetry Bridge (high-throughput path), Update Agent helpers |
| TypeScript | 5.5+ | Admin UI frontend, future web artefacts |
| Rust | — | Not currently used; reserved for performance-critical paths if needed |

Rationale: Python is the agent ecosystem's lingua franca; Go is the
Kubernetes ecosystem's lingua franca and fits the Bridge's
throughput needs; TypeScript is the unavoidable UI choice.

## Tooling

### Python

- **Package manager:** `uv` for speed; `pip` remains supported for
  contributors who prefer it.
- **Formatter:** `ruff format` (on save, in CI).
- **Linter:** `ruff check` with the Fabric base config
  (`ruff.toml`).
- **Type checker:** `mypy --strict` on all new code. Existing code
  migrates to strict over time.
- **Test runner:** `pytest`.
- **Test coverage:** `pytest-cov` with `coverage.py`.
- **Dependency audit:** `pip-audit` in CI on every PR.

### Go

- **Formatter:** `gofmt` + `goimports`.
- **Linter:** `golangci-lint` with the Fabric config.
- **Tests:** standard library `testing`; `testify` for assertions
  when helpful.
- **Modules:** `go mod` with a tidy-on-save commit hook.

### TypeScript

- **Package manager:** `pnpm`.
- **Formatter:** `prettier`.
- **Linter:** `eslint` with the Fabric config.
- **Tests:** `vitest` for unit, `playwright` for browser.

### Helm / Kubernetes

- **Lint:** `helm lint` + `kubeconform`.
- **Schema:** every chart must ship a `values.schema.json`.
- **Security scan:** `checkov` + `kube-score` in CI.

### Markdown

- **Lint:** `markdownlint-cli` with the project config.
- **Link check:** `lychee` in CI, weekly cron.

## Testing taxonomy

Every component has four levels of test:

### Unit tests

Fast, isolated, deterministic. Test a single function or class. No
network, no file system beyond `tmp_path`, no real databases.

Minimum coverage bars on new code:

- **Line coverage:** 80%
- **Branch coverage:** 70%
- **Critical paths** (redaction, signing, rubric loading,
  escalation state machine): 95% line, 90% branch

PRs that drop overall coverage are flagged; drops must be
justified in the PR description and signed off by a maintainer.

### Property-based tests

Used for:

- Redaction pipelines (`hypothesis` for Python)
- Signature / cryptographic code
- Schema validators
- State machines (escalation, Update Agent)

Property tests verify invariants over random input rather than
specific cases. Required for any code that processes adversarial
or unbounded inputs.

### Integration tests

Components talk to real dependencies (real Postgres, real NATS).
Run in CI with ephemeral containers via `testcontainers` (Python)
or `dockertest` (Go).

Required for:

- Every cross-component interaction
- Every external API contract (to SingleAxis ingest, to LLM
  endpoints)
- Every database schema migration

### End-to-end tests

Full `fabric-system` stack stood up in a `kind` cluster in CI. A
synthetic agent exercises the complete decision flow: input,
guardrails, retrieval, judge, escalation, resume, bundle export.

Required for:

- Every release candidate
- PRs touching the chart, escalation workflow, or bridge

### Security tests

- **SAST:** `bandit` (Python), `gosec` (Go), `semgrep` across all.
- **Secrets scanning:** `gitleaks` in CI and pre-commit.
- **Container scanning:** `trivy` on every published image.
- **Adversarial prompt suite:** Fabric's own suite of injection and
  jailbreak attempts run against shipped judge prompts and
  guardrail rails. Regressions here are release-blocking.

## CI gates

Every pull request must pass, in order:

1. **DCO check** — every commit has `Signed-off-by:` trailer
2. **Commit lint** — conventional-commit format
3. **Pre-commit** — formatters, linters, whitespace, file-size
   limits, gitleaks
4. **Type check** — `mypy` (Python), `tsc --noEmit` (TS)
5. **Unit tests** — all components, parallelised
6. **Property tests** — for components that have them
7. **Integration tests** — with containerised dependencies
8. **SAST + secrets + container scans**
9. **Chart lint** — `helm lint` + `kubeconform` + `checkov`
10. **Coverage check** — no regression beyond threshold
11. **Docs build** — markdown lint + link check + spec schema
    validation
12. **License check** — SPDX headers present; dependency licences
    allowed

For PRs that modify the chart, escalation workflow, or bridge,
additional gate:

13. **End-to-end test** — full cluster smoke test

PRs remain red until all gates pass. Gate failures print
actionable remediation guidance.

## Release engineering

### Versioning

[Semantic Versioning](https://semver.org/). Before 1.0.0, minor
bumps may contain breaking changes (documented in the changelog);
after 1.0.0, standard SemVer applies.

Each release has a version line in the umbrella chart
(`Chart.yaml`), a tag in Git, and a GitHub Release.

### Release cadence

- Patch releases as needed for correctness or security
- Minor releases monthly (target)
- Major releases when breaking changes accumulate

Each release is preceded by a release candidate (`X.Y.Z-rc.N`)
published at least 7 days before promotion, unless it is a critical
security release.

### Signing

- **Container images** signed with `cosign` using a long-lived
  Fabric signing key, rotated annually. Key lineage documented in
  `SECURITY.md` and the release notes.
- **Helm charts** signed (`.prov` provenance file) and the chart
  `.tgz` signed with `cosign`.
- **Python / Go binaries** attached to GitHub Releases are signed.
- **Git tags** signed with a maintainer's OpenPGP key.

### Provenance (SLSA)

Target: SLSA level 3 for the release build by 0.3.0.

Until then:

- Builds run in a pinned, public GitHub Actions workflow with
  provenance attestations (`actions/attest-build-provenance`).
- Reproducible build scripts published so third parties can verify.

### SBOM

Each release ships:

- SPDX JSON SBOM per published image
- CycloneDX JSON SBOM per published image
- Umbrella SPDX SBOM for the chart

Generated with `syft`. Attached to the GitHub Release and pushed to
the container registry alongside the images.

### Vulnerability response

See `SECURITY.md`. Summary:

- Advisories published via GitHub Security Advisory
- CVEs requested for confirmed vulnerabilities
- Patch releases for supported versions
- Disclosure timeline: 90 days default, shorter for active exploits

## Dependency governance

### Adding a dependency

A new dependency requires:

1. A maintainer-approved PR with:
   - The dependency's name, version, SPDX licence
   - A rationale (why we can't reasonably write it ourselves or use
     an already-included alternative)
   - Its SBOM position (which subpackage includes it)
   - An initial `osv-scanner` report
2. The dependency must have an OSI-approved licence compatible
   with Apache-2.0 (we accept: Apache-2.0, MIT, BSD-2/3, MPL-2.0,
   ISC; we require review for: LGPL; we reject: GPL-3, AGPL-3,
   SSPL, Elastic).

### Pinning

- Python: `uv`'s `requirements.lock` committed.
- Go: `go.sum` committed.
- TypeScript: `pnpm-lock.yaml` committed.
- Helm: subchart versions pinned in `Chart.yaml`.

### Auto-update

Dependabot (or Renovate) opens PRs weekly. Each update PR runs the
full CI pipeline including adversarial test suite. Maintainers
review and merge.

### Supply-chain attacks

- Dependencies pinned to exact versions (no `~` or `^`).
- `npm`, `pip`, and `go` use verified checksums.
- Typosquatting / dependency-confusion protection via scoped /
  namespaced registries where applicable.

## SPDX headers

Every source file carries a SPDX header:

```
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 AI5Labs Research OPC Private Limited
```

Enforced by a pre-commit hook.

## Documentation standards

- Every component has a `README.md` (overview, dev setup, tests)
- Every public API has doc comments
- Every spec follows the structure in `specs/000-overview.md`
- User-facing docs (in `docs/`) are built from the specs and
  component READMEs; not separately maintained
- ADRs (Architecture Decision Records) live as specs, not a
  separate directory

## Code review

- Minimum one maintainer approval
- PR author does not merge their own PR
- PRs touching `SECURITY`-labelled code require a security
  maintainer approval (see `CONTRIBUTING.md`)
- Stale PRs (no activity 14 days) may be closed with a note

## Backward compatibility

Pre-1.0.0: best-effort, breaking changes documented in changelog.

Post-1.0.0:

- Public APIs (SDK, REST, GraphQL, chart values) are stable within
  a major version.
- Breaking changes require a major bump and a 6-month deprecation
  window for the old behaviour.
- Context Graph schema is versioned independently; within a major,
  readers tolerate a window of consumer-visible changes.

## Observability of Fabric itself

Every Fabric component emits:

- Prometheus metrics (`fabric_<component>_*`)
- OTel traces (tracing its own operations)
- Structured logs (JSON by default; `logfmt` available)

Metrics are documented in the component's README; a consolidated
Grafana dashboard ships in `charts/fabric/dashboards/`.

## Open questions

- **Q1.** Do we target SLSA level 3 from 0.1.0, accepting the build
  complexity, or start at level 2 and ramp? *Resolver: project
  lead + security maintainer. Deadline: before 0.1.0.*
- **Q2.** Should we adopt `pants` / `bazel` for the monorepo build
  as component count grows, or stay on per-component native
  tooling? *Resolver: platform maintainer. Deadline: review at
  0.3.0.*
- **Q3.** Minimum supported Kubernetes version — we currently say
  1.29; should we pin tighter (last two minor versions) or looser
  (everything with working NetworkPolicy)? *Resolver: platform
  maintainer. Deadline: before 0.1.0.*

## References

- [SLSA framework](https://slsa.dev/spec/v1.0/)
- [Sigstore](https://www.sigstore.dev/)
- [SPDX](https://spdx.dev/)
- [CycloneDX](https://cyclonedx.org/)
- [OSV](https://osv.dev/)
- [OpenSSF Scorecard](https://securityscorecards.dev/)
