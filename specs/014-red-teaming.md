---
title: Red-Teaming — Completion Spec
status: draft
revision: 1
last_updated: 2026-05-13
owner: project-lead
---

# 014 — Red-Teaming Completion

## 1. Scope

v0.2.0 ships the red-team runner as source. v0.3 turns it into a fully
shippable component: working build, published image, deployable chart,
and integrated telemetry. Four areas:

1. **Build.** The current Dockerfile installs garak and pyrit into a
   single Python environment; both libraries pin different exact
   versions of `mistralai`, producing a resolver conflict. v0.3 fixes
   this by installing each tool in its own virtualenv inside the image.
2. **Publishing.** Image needs to land on GHCR alongside the other
   four sidecars — covered by SPEC 017's matrix publish.
3. **CI integration recipes.** The strategy calls for red-team to run
   as a pre-release CI gate and as a scheduled probe against staging.
   v0.3 ships reference GitHub Actions workflow templates customers
   can copy.
4. **Telemetry integration.** Red-team findings currently emit JSON
   only; v0.3 adds OTel span emission with `event_class=red_team_result`
   so findings flow through the existing fabricguard / fabricsampler /
   fabricpolicy processors and land in the customer's trace backend.

## 2. Goals

- `fabric-redteam-runner:0.3.0` builds in CI and publishes to GHCR.
- The runner image is `helm install`-able as a CronJob in any K8s
  cluster with the existing `charts/fabric/charts/redteam-runner/` chart.
- Red-team findings emit as OTel spans (one span per probe execution,
  events on the span per finding) so they flow through Fabric's
  processors and land in the customer's trace backend.
- A `.github/workflows/redteam.yml` reference workflow ships in the
  repo as the canonical "how to gate releases on red-team findings"
  recipe.
- Optional: a scheduled mode (cron) that runs the suite against a target
  endpoint and writes findings to a configured destination.

## 3. Non-goals

- We do not maintain a curated probe library that tracks the threat
  landscape (new jailbreaks weekly). That's Commercial L3.8 — we ship
  the starter set garak + pyrit provide, and let customers / L2
  Commercial add to it.
- We do not build a UI for finding triage. JSON output + standard
  ticketing-system integration (GitHub Issues via `gh`, Jira via REST)
  is enough for OSS. Triage UI is Commercial.
- We do not run the red-team as managed service ("red-team as a service"
  against staging continuously). That's a separate Commercial offering
  for later.

## 4. Design

### 4.1 Fix the Dockerfile

The garak/pyrit conflict is fundamental — both libraries pin different
`mistralai==1.5.2` exactly, transitively. Three options:

- **(a) Separate venvs in one image.** Build with two `venv` paths,
  install garak into one and pyrit into the other. The runner CLI
  invokes them as subprocess calls into the respective venv. Single
  image, no conflict.
- **(b) Two separate images.** `fabric-redteam-runner-garak` and
  `fabric-redteam-runner-pyrit`. Each builds cleanly with its own dep set.
  Customer chart deploys both as separate CronJobs.
- **(c) Patch the upstream pins.** Fork or PR garak/pyrit to relax the
  pin. Upstream-dependent, slow.

I lean (a). Single image is operationally simpler for customers.
Implementation:

```dockerfile
FROM python:3.12-slim AS base
# Common: install the runner orchestrator
RUN python -m venv /opt/venv-runner
RUN /opt/venv-runner/bin/pip install fabric-redteam-runner

# Garak in its own venv — pin a known-tested minor version
RUN python -m venv /opt/venv-garak
RUN /opt/venv-garak/bin/pip install 'garak==0.9.0.15.*'

# Pyrit in its own venv — pin a known-tested minor version
RUN python -m venv /opt/venv-pyrit
RUN /opt/venv-pyrit/bin/pip install 'pyrit==0.5.0.*'

ENTRYPOINT ["/opt/venv-runner/bin/fabric-redteam-runner"]
```

**Version pinning is load-bearing.** garak and pyrit have aggressive
upstream release cycles (~weekly), and CLI behavior has changed in
recent minor versions of both. Pinning a known-tested minor version
in the published image prevents customer surprise. The pin should be
bumped in a controlled way — bump-and-test as a separate PR per
upstream release, not via Dependabot auto-merge.

The runner's CLI gains `--garak-bin /opt/venv-garak/bin/garak` and
`--pyrit-bin /opt/venv-pyrit/bin/pyrit` flags, defaulted to those paths
in the published image.

### 4.2 Emit findings as OTel spans

The runner gets a new dependency on `opentelemetry-sdk` and emits spans
per probe execution:

```
fabric.red_team_run                (root span, event_class=red_team_result)
  attributes:
    fabric.red_team.suite = "garak"
    fabric.red_team.target = "<endpoint>"
    fabric.red_team.probes_total = 47
    fabric.red_team.findings_total = 3
    fabric.red_team.run_id = "..."
  events:
    fabric.red_team.finding (1 event per finding)
      attributes:
        finding.probe = "jailbreak.dan_v8"
        finding.severity = "high"
        finding.snippet_hash = "<sha256 of the failing prompt>"
        # NOT the raw prompt (PII concerns); customer can correlate
        # via hash if they retain raw probe logs separately
```

The runner writes both:
- Standard JSON output (current behavior, for compatibility with
  existing CI scripts)
- OTel spans via OTLP exporter (new — enabled by `--otlp-endpoint`)

When wired through Fabric's collector, `event_class=red_team_result`
ensures fabricsampler keeps 100% of these events (per existing
`fabricsamplerprocessor` rates config), and fabricpolicy can apply
per-tenant rules.

### 4.3 CronJob deployment

The existing chart needs:

- `schedule: "0 2 * * *"` defaulted to nightly 2am UTC
- `target.endpoint: ""` required value, fails to render if empty
  (chart-time validator pattern from spec 008)
- `target.auth: bearer | basic | none` for hitting an authenticated
  agent endpoint
- `suites: [garak, pyrit]` controls which engine(s) run
- `probeAllowlist: []` / `probeBlocklist: []` for narrowing scope
- `findings.sinkS3: s3://bucket/path/` optional, for JSON archival
- `otlp.endpoint: "fabric-otel-collector.fabric.svc.cluster.local:4318"`
  for span emission

### 4.4 Reference CI workflow

A new file: `.github/workflows/redteam.yml.example` (template; customers
copy into their repo). Two modes:

- **Pre-release gate** — runs the configured suite against a test agent,
  fails the build if `findings.severity=high` count exceeds the
  configured threshold
- **Nightly cron** — same suite, against staging, writes findings to a
  configured destination (S3 + OTLP), opens GitHub issues for new
  high-severity findings (deduplicated by `finding.probe`)

### 4.5 Integration with the L2 audit bundle (Commercial hook)

L1 OSS produces the OTel spans. L2 Commercial consumes them via the
collector and includes them in regulator-ready audit bundles (per
L3.8 — "Periodic adversarial-testing evidence"). The OSS need not know
about L2; the contract is the span format.

## 5. Work breakdown

| # | PR | Effort | Depends on |
|---|---|---|---|
| 1 | Fix Dockerfile — separate venvs for garak / pyrit | 1-2 days | none |
| 2 | OTel span emission from runner | 3-5 days | none |
| 3 | Chart updates (CronJob schedule, target validation, otlp config) | 2 days | #1 |
| 4 | Publish `fabric-redteam-runner` image via CI on tag | 1 day | SPEC 017 |
| 5 | Reference `.github/workflows/redteam.yml.example` workflow | 1-2 days | #2 |
| 6 | Reference agent / target — minimal endpoint for smoke-testing the runner in CI | 1 day | #2 |
| 7 | Documentation: how to gate releases, how to schedule nightly, how to integrate findings into issue tracking | 1-2 days | #1-#5 |
| 8 | Tests: dry-run mode, OTLP span emission verification, chart render | 2 days | #2 |

**Total: ~2-3 weeks.**

## 6. Acceptance criteria

- `docker build components/redteam-runner` succeeds in CI.
- `fabric-redteam-runner:0.3.0` published to GHCR.
- `helm install fabric/redteam-runner --set target.endpoint=https://my-agent.example.com`
  creates a CronJob that runs nightly.
- A manual `kubectl create job --from=cronjob/...` invocation
  successfully runs garak + pyrit suites against the target, emits
  JSON findings AND OTel spans.
- Spans appear in the customer's trace backend with `event_class=red_team_result`
  and survive fabricsampler/fabricguard/fabricpolicy.
- The reference workflow runs in this repo's own CI as a smoke test
  (red-team against a stub agent that intentionally fails one probe;
  workflow should fail).

## 7. Open questions

1. **Venv path vs separate image** — confirm (a) over (b). Reasons to
   reconsider (b): image-size optimization (each is smaller), security
   (one CVE in garak's deps doesn't affect pyrit). I still lean (a) but
   it's a small call.
2. **Default suite scope** — ship with all garak + all pyrit probes
   enabled by default? Most teams will narrow; the default should be
   "broad enough to be useful, narrow enough to finish in <30 min on a
   modest cluster." Need to benchmark.
3. **Findings sink** — JSON to file + OTLP spans, or also Slack /
   GitHub Issues integration? I lean ship the JSON+OTLP foundation;
   integrations are recipes customers wire themselves.
4. **Span content** — finding snippets in span attributes (potential
   for PII / harmful content leakage into the trace store) or only
   hashes? I lean hashes by default with an explicit `--capture-snippets`
   flag for dev/eval.

## 8. Related work

- SPEC 007 (escalation; red-team findings can fire escalations for
  high-severity blocked content)
- SPEC 008 (deployment model; chart conventions)
- SPEC 017 (publishing pipeline)
- The garak/pyrit upstream projects — track their pin behaviors so
  this spec doesn't drift
