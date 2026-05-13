---
title: Publishing Pipeline & Integration CI
status: draft
revision: 1
last_updated: 2026-05-13
owner: project-lead
---

# 017 — Publishing Pipeline & Integration CI

## 1. Problem

Of the seven artifacts the OSS umbrella chart references, **only two
are actually published to GHCR** as of v0.2.0:

| Artifact | Published? |
|---|---|
| `fabric-otelcol` (collector image) | ✅ |
| `charts/otel-collector` (subchart) | ✅ |
| `fabric-presidio-sidecar` (image) | ❌ |
| `fabric-nemo-sidecar` (image) | ❌ |
| `fabric-redteam-runner` (image) | ❌ |
| `fabric-update-agent` (image) | ❌ |
| `fabric-langfuse-bootstrap` (image) | ❌ |
| `charts/fabric` (umbrella chart) | ❌ |
| `charts/presidio-sidecar` (subchart — doesn't exist) | n/a (see SPEC 012) |

So a customer who runs `helm install fabric oci://ghcr.io/singleaxis/charts/fabric`
gets `not found`. They can install only the `otel-collector` subchart in
isolation, which doesn't deliver any of Fabric's differentiating value.

Separately, the existing CI integration coverage is weak:

- The "kind cluster install + smoke" job in `.github/workflows/ci.yml`
  installs the chart and runs `helm test` against it. But `helm test`
  only checks the collector pod's `/healthz` endpoint. It does NOT:
  - Run a real agent
  - Exercise the SDK end-to-end
  - Verify that spans actually traverse the collector → backend pipeline
- The chart-rendering bug (SPEC 016 §4.1) and the silent
  PassthroughAnalyzer bug (SPEC 012 §1) BOTH slipped through CI because
  no test exercised the actual data path.

## 2. Goals

- On every tag push, the `release.yml` workflow publishes **all five
  missing images** and the **umbrella chart** to GHCR with cosign
  signatures + SBOMs + SLSA build provenance (same supply-chain rigor
  as the existing collector image).
- A new CI workflow `e2e.yml` runs on every PR and on every release tag:
  - Stands up a kind cluster
  - Installs the full umbrella chart with all sidecars
  - Runs a reference agent against a real (or stubbed) Anthropic
    endpoint
  - Asserts that spans appear in a real trace backend (Phoenix) with
    the expected attribution + content shape
  - Asserts that PII redaction visibly happens (input with email → span
    contains tag, not email)
  - Asserts that the trace pipeline accepts spans (no 404 on /v1/traces)
- Customers running v0.3.0 can deploy the full Fabric stack with one
  `helm install` command — no manual config patching like we did during
  the 2026-05-12 validation.

## 3. Non-goals

- We do not change the release-versioning scheme. Each tag still
  publishes everything at the same version. No independent component
  versioning.
- We do not build Windows / non-amd64-arm64 images. Multi-arch stays
  amd64 + arm64.
- We do not publish to PyPI Test or any pre-release index for the sidecar
  Python packages. Only the SDK goes to PyPI; sidecars are container-only.

## 4. Design

### 4.1 Extend `release.yml` to publish all images

Add a matrix job per sidecar image. Mirror the existing `publish-image`
job structure (multi-arch + cosign + SBOM + provenance).

```yaml
publish-sidecar-images:
  strategy:
    fail-fast: false
    matrix:
      include:
        - { component: presidio-sidecar, image_name: fabric-presidio-sidecar }
        - { component: nemo-sidecar,     image_name: fabric-nemo-sidecar }
        - { component: redteam-runner,   image_name: fabric-redteam-runner }
        - { component: update-agent,     image_name: fabric-update-agent }
        - { component: langfuse-bootstrap, image_name: fabric-langfuse-bootstrap }
  steps:
    - uses: actions/checkout@v6
    - uses: docker/setup-qemu-action@v3
    - uses: docker/setup-buildx-action@v3
    - name: Build and push (multi-arch)
      uses: docker/build-push-action@v6
      with:
        context: components/${{ matrix.component }}
        push: true
        platforms: linux/amd64,linux/arm64
        tags: ghcr.io/${{ github.repository_owner }}/${{ matrix.image_name }}:${{ steps.vars.outputs.version }}
        provenance: true
        sbom: true
    - name: Sign images (cosign keyless)
      ...
    - name: Attest provenance
      ...
```

`fail-fast: false` so if one component's build breaks, others still
publish — release engineering decision (better to publish 4 of 5 than
0 of 5).

### 4.2 Publish umbrella `charts/fabric`

A second `publish-chart` job alongside the existing subchart publish:

```yaml
publish-umbrella-chart:
  steps:
    - uses: actions/checkout@v6
    - uses: azure/setup-helm@v4
    - name: Update subchart dependencies
      run: helm dependency update charts/fabric
    - name: Package
      run: helm package charts/fabric --destination dist/
    - name: Push to GHCR OCI
      run: helm push dist/fabric-*.tgz oci://ghcr.io/${{ github.repository_owner }}/charts
    - name: Sign chart
      ...
```

The umbrella chart's `Chart.yaml` already lists subchart dependencies.
Verify each dependency points to a version that exists.

### 4.3 The integration CI workflow (`e2e.yml`)

A new workflow file. Triggered on `pull_request` and `push` to main, and
on tags.

```yaml
name: E2E
on:
  pull_request:
  push:
    branches: [main]
    tags: ['v*.*.*']

jobs:
  e2e-kind:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@v6
      - uses: helm/kind-action@v1
        with:
          cluster_name: fabric-e2e
          wait: 90s
      - name: Build all sidecar images locally
        run: ./scripts/e2e/build-images.sh
      - name: Load images into kind
        run: ./scripts/e2e/load-images.sh
      - name: Deploy Phoenix
        run: kubectl apply -f scripts/e2e/phoenix.yaml
      - name: Wait for Phoenix
        run: kubectl wait -n phoenix pod -l app=phoenix --for=condition=Ready --timeout=180s
      - name: Install Fabric umbrella chart
        run: |
          helm install fabric ./charts/fabric \
            -f scripts/e2e/values-e2e.yaml \
            --namespace fabric --create-namespace \
            --wait --timeout 5m
      - name: Run reference agent
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY_E2E }}
        run: python scripts/e2e/reference-agent.py
      - name: Assert traces in Phoenix
        run: python scripts/e2e/assert-spans.py
      - name: Assert PII redaction
        run: python scripts/e2e/assert-redaction.py
      - name: Dump diagnostic on failure
        if: failure()
        run: ./scripts/e2e/dump-state.sh
```

The `scripts/e2e/` directory ships:

- `build-images.sh` — `docker build` each component
- `load-images.sh` — `kind load docker-image` for each
- `phoenix.yaml` — Phoenix Deployment + Service
- `values-e2e.yaml` — fabric chart values that point at in-cluster Phoenix
- `reference-agent.py` — the test agent we built during the 2026-05-12
  validation, generalized; runs N turns with PII-laden prompts
- `assert-spans.py` — queries Phoenix's `/v1/projects/.../spans` API
  and asserts the expected span tree shape
- `assert-redaction.py` — asserts that span events have
  `fabric.guardrail.entities` populated and that the redacted text does
  NOT contain the original PII strings
- `dump-state.sh` — for debugging failures: collect pod logs, chart
  values, span dumps

A real Anthropic API key for the E2E job goes into a repo secret. Budget:
~$0.05 per CI run with claude-haiku at 5 turns.

### 4.4 Secrets management for the E2E API key

`ANTHROPIC_API_KEY_E2E` is a GitHub repo secret scoped to the
`e2e-kind` job. The job runs on a self-hosted or trusted runner — never
on a fork PR (use `pull_request_target` with explicit allowlist for
external contributors, or skip E2E on fork PRs and only run on push to
main).

### 4.5 Failure budget

The E2E job is not yet required for merge — for the first 2-3 weeks
after it lands, it's advisory. Once it's stable (no flakes in 50 runs),
add to required status checks in branch protection.

## 5. Work breakdown

| # | PR | Effort | Depends on |
|---|---|---|---|
| 1 | Extend `release.yml` to publish 5 sidecar images (matrix) | 2-3 days | SPEC 014 #1 (redteam Dockerfile fix), SPEC 012 #1 (Presidio analyzer wire) |
| 2 | Add umbrella chart publish step | 1 day | #1 |
| 3 | Author `scripts/e2e/` (build, load, deploy, assert, dump) | 3-5 days | none |
| 4 | New `.github/workflows/e2e.yml` | 1-2 days | #3 |
| 5 | Self-hosted runner or repo-secret config for `ANTHROPIC_API_KEY_E2E` | 1 day (mostly process) | #4 |
| 6 | Tag v0.3.0-rc.1 and verify all artifacts publish + e2e passes | 1-2 days | all |
| 7 | Tag v0.3.0 after rc burn-in | n/a |  |

**Total: ~2-3 weeks, parallelizable with SPEC 012 / 013 / 014 work.**

## 6. Acceptance criteria

- Tagging `v0.3.0` on main produces six new GHCR artifacts: five
  sidecar images + the umbrella chart. All cosign-signed, all have
  SBOMs + provenance.
- A reasonable user can do `helm install fabric oci://ghcr.io/singleaxis/charts/fabric --version 0.3.0`
  on a fresh cluster and get a working stack (collector + 5 sidecars,
  all pods running, all readiness probes green).
- `e2e.yml` runs in <20 minutes and passes on every commit to main.
- E2E job catches at least three regressions reproduced from the
  2026-05-12 findings (we can re-create the bugs deliberately on a
  test branch and verify the workflow catches each).
- A failure dump from the workflow is informative enough to triage
  within 15 minutes (pod logs, chart values, latest spans from Phoenix).

## 7. Open questions

1. **Self-hosted runner vs hosted runner with Anthropic key?** Hosted is
   simpler; self-hosted has stricter key scoping. I lean hosted for v0.3,
   self-hosted later if real ANR/security review demands it.
2. **Stub the LLM for E2E?** Faster, deterministic, but doesn't exercise
   the auto-instrumentation against a real provider. I lean real
   Anthropic with haiku in v0.3, add a `--stub` mode in v0.4 for forks.
3. **Should E2E run on every PR or only on main + release tags?**
   PR-on-every is the safer pattern. Cost: ~$0.05 per run × maybe 50
   runs/month = $2.50. Cheap. I lean PR-on-every.
4. **Pin the GHCR image tags pulled into kind** — should the integration
   test use the JUST-built local images (testing local code) or pull
   the published images (testing the release artifacts)? Different tests.
   v0.3 ships both as separate jobs: `e2e-local` and `e2e-published`.

## 8. Related work

- SPEC 012, 013, 014 — each defines an artifact that this spec publishes
- SPEC 016 — foundational fixes verified by this spec's E2E coverage
- SPEC 008 (deployment model) — chart conventions
- Existing `release.yml` — extended, not rewritten
