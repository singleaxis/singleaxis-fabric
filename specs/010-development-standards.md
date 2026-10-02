---
title: Development, Testing & Release Standards
status: accepted
revision: 3
last_updated: 2026-09-15
owner: project-lead
---

# 010 — Development Standards

## Summary

Fabric is intended to be open-sourced, audited by enterprise security
teams, and deployed inside customer trust boundaries. This spec fixes
the engineering standards — languages, tooling, testing coverage, CI
gates, supply-chain practices, release signing — that the project
commits to for the recorder-v1 line.

Where we cut corners, we document it. Where we raise the bar beyond
typical OSS projects, we also document it — because security reviewers
will ask.

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
- Platform-side standards. Monitoring, evaluation, and governance of
  delivered records belong to SingleAxis Platform, outside this
  repository.

## Languages and runtimes

| Language | Version | Use |
|----------|---------|-----|
| Python | 3.11+ | `sdk/python`, `scripts/`, `examples/` |
| Go | 1.22+ | `tools/fabricctl`, `fabricguardprocessor`, `gate` |
| TypeScript | 5.5+ | `sdk/typescript` |
| Rust | — | Not used |

## Tooling

### Python

- **Package manager:** `uv` (`uv.lock` committed); `pip` remains
  supported for contributors.
- **Formatter:** `ruff format`.
- **Linter:** `ruff check` with the project config.
- **Type checker:** `mypy --strict` on `sdk/python/src`.
- **Test runner:** `pytest` with `pytest-cov`.
- **Dependency audit:** `pip-audit` / `osv-scanner` in CI.

### Go

- **Formatter:** `gofmt`.
- **Linter:** `go vet` (golangci-lint optional locally).
- **Tests:** standard library `testing`; `testify` where helpful.
- **Modules:** `go mod`, `go.sum` committed; use `go mod tidy -diff` for a non-mutating tidy check on the pinned toolchain.

### TypeScript

- **Package manager:** `npm` (`package-lock.json` committed).
- **Formatter:** `prettier`.
- **Linter:** `eslint`.
- **Tests:** `vitest`; package-artifact smoke tests run under Node.

### Helm / Kubernetes

- **Lint:** `helm lint` on the umbrella chart and the vendored
  `otel-collector` subchart.
- **Schema:** both charts ship `values.schema.json` with
  `additionalProperties: false`; `tests/test-values-schema.sh` proves
  schema rejection paths including the `invalid-values/` fixtures.
- **Boundary tests:** `tests/*.sh` render-time assertions that only
  recorder components can render and removed surfaces cannot.

### Markdown / docs

- **Lint:** `markdownlint-cli2` (`.markdownlint-cli2.jsonc`).
- **Truthfulness:** `scripts/tests/test_recorder_documentation_scope.py`
  scans maintained docs for stale capability claims.

## Testing taxonomy

### Unit tests

Fast, isolated, deterministic. No network, no file system beyond
`tmp_path`, no real services.

Minimum coverage bars on new code:

- **Line coverage:** 80%
- **Branch coverage:** 70%
- **Critical paths** (allowlist filtering, hashing, persistent queue
  recovery, ingress auth, identity propagation): 95% line, 90% branch

### Integration and end-to-end tests

- `deploy/compose/qualify.sh` — local evaluation stack testing protection,
  durable queue and controlled-sink delivery. This path is plaintext and
  unauthenticated; it does not qualify authenticated production ingress.
- `e2e.yml` kind job — Helm install on a real cluster, fsync sink,
  queue-survives-pod-restart proof.
- `examples/harness-smoke` — SDK-to-node trace smoke.
- `fabricctl` — init → validate → digest coverage in Go tests.

Required for every release candidate, and for PRs touching the chart,
the collector distribution, or the deploy overlay.

### Security tests

- **Secrets:** `gitleaks` (CI + pre-commit).
- **Vulnerabilities:** `trivy` fs + `osv-scanner --lockfile-only` over
  `sdk/python`, `sdk/typescript`, `tools/fabricctl`, and the processor
  module.
- **Boundary regression:** artifact-content tests that would fail if
  removed capabilities (guardrails, judges, red-team, policy,
  management, relay, sidecars) reappeared in any release surface.

## CI gates

Every pull request must pass:

1. **DCO check** — every commit has a `Signed-off-by:` trailer
2. **Commit lint** — conventional-commit format
3. **actionlint** — workflow syntax
4. **Type check** — `mypy` (Python), `tsc --noEmit` (TS), `go vet`
5. **Unit tests** — all components
6. **Repository tests** — `scripts/tests` (contracts, boundary,
   documentation scope, release identity)
7. **Helm** — lint, schema tests, boundary tests
8. **Security** — gitleaks, trivy, osv-scanner, codeql
9. **License** — `scripts/license_check.py` against
   `.github/license-allowlist.txt`
10. **Coverage check** — no regression beyond threshold

For PRs that modify the chart, collector, or deploy overlay:

11. **End-to-end** — kind cluster smoke (`e2e.yml`)

## Release engineering

### Versioning

[Semantic Versioning](https://semver.org/). Before 1.0.0, minor bumps
may contain breaking changes (documented in the changelog). Each release
candidate precedes promotion (`X.Y.Z-rc.N`).

### Signing

- **Container images** signed with `cosign` (keyless via Fulcio), at the
  pushed digest.
- **Helm chart OCI artifact** signed with `cosign` at
  `name:version@digest`.
- **SLSA build provenance** via `actions/attest-build-provenance` for
  images and release tarballs.
- No long-lived signing keys — keyless identity bound to the CI OIDC
  flow.

### SBOM

- Design target: SPDX and CycloneDX SBOMs per published image, generated
  with `syft` and attached to the release.
- Current implementation note (2026-10-02): the release workflow enables
  BuildKit SBOM/provenance attestations and keyless OCI signatures; it does
  not implement that dual-format `syft` attachment target. Publication also
  rebuilds images after CI rather than promoting the exact scanned image
  bytes. Do not claim the target or exact scanned-byte promotion as shipped.

### Contract packaging

`scripts/release/package_contracts.py` produces the contract archive
from `scripts/release/release-policy.json` (public families:
`activity/v2`, `connect/v1`, `delivery/v1`, `privacy/v1`,
`recorder/v1`) plus `SHA256SUMS.contracts`.

## Dependency governance

### Adding a dependency

A new dependency requires:

1. A maintainer-approved PR with the dependency's name, version, SPDX
   licence, rationale, and SBOM position.
2. A licence on `.github/license-allowlist.txt` — the gate is
   fail-closed (unlisted licences fail).
3. `osv-scanner` clean at the pinned version.
4. Prefer versions published at least 7 days ago; no floating ranges.

### Pinning

- Python: `uv.lock` committed.
- Go: `go.sum` committed.
- TypeScript: `package-lock.json` committed.
- Helm: subchart versions pinned via `Chart.lock`.
- GitHub Actions: pinned by full SHA.
- Container base images: digest-pinned.

### Auto-update

Dependabot opens weekly PRs per real manifest directory
(`tools/fabricctl`, the processor module, `sdk/typescript`,
`sdk/python`, docker, github-actions). Each update PR runs the full CI
pipeline.

## SPDX headers

Every source file carries:

```
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 AI5Labs Research OPC Private Limited
```

## Documentation standards

- Every component has a `README.md` (overview, dev setup, tests)
- Every public API has doc comments
- Every spec follows the structure in `specs/000-overview.md`
- Stale-spec convention: superseded specs carry a `superseded` status
  and a do-not-implement banner (see specs 001, 025)
- ADRs live as specs, not a separate directory
- Documentation truthfulness is tested: claims about shipped
  capabilities must match code (`test_recorder_documentation_scope.py`)

## Code review

- Minimum one maintainer approval
- PR author does not merge their own PR
- PRs touching the protection processor, auth wiring, or release
  packaging require a security maintainer approval (see CODEOWNERS)
- Stale PRs (no activity 14 days) may be closed with a note

## Backward compatibility

Pre-1.0.0: best-effort; breaking changes documented in the changelog.
The public contract families version independently (`v1`/`v2` dirs
under `contracts/`); wire compatibility between SDK releases is
preserved by the shared vocabulary tests in `contracts/activity`.

## Observability of Fabric itself

The Fabric Node exposes collector self-metrics (Prometheus reader,
`:8888` in the compose production overlay) covering exporter queue
depth, send failures, and processor counters — the operator-facing
reliability surface. Health is on `:13133`. No Grafana dashboards ship;
destination-side monitoring is the customer's backend.

## Open questions

- **Q1.** Byte-bounded persistent queues — `sizer: bytes` is not
  available at collector v0.150; revisit on the v0.16x train.
- **Q2.** gRPC ingress authentication is covered by the same
  `bearertokenauth` extension as HTTP but is not yet exercised live in
  the compose verify script beyond the grpcurl probe.

## References

- [SLSA framework](https://slsa.dev/spec/v1.0/)
- [Sigstore](https://www.sigstore.dev/)
- [SPDX](https://spdx.dev/)
- [CycloneDX](https://cyclonedx.org/)
- [OSV](https://osv.dev/)
