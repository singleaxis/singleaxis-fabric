# Changelog

All notable changes to SingleAxis Fabric will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

*(nothing yet)*

## [0.2.0] - 2026-05-01

Fabric earns the "open-source observability + control plane for
AI agents" framing by capturing LLM operations natively. Three
substantive additions over the v0.1.x line: per-LLM-call child
spans with `gen_ai.*` semantic conventions, auto-instrument extras
for the popular LLM SDKs, and a trace pipeline on the OTel
collector's custom guard processor so the chart's privacy promise
actually applies to the SDK's spans (not just future L2 bridge
log records).

This release subsumes the **never-tagged 0.1.3 audit follow-up**
work (round-2 audit fixes across SDK, components, charts, docs,
and specs). 0.1.3 was prepped on the `chore/v0-1-3-audit-followup`
branch and merged to main, but the new public API additions in
that branch (`Decision.llm_call`, `Decision.tool_call`, the
`[openai]/[anthropic]/...` extras, `fabricguardprocessor` trace
processing) are semver-minor work, not patch — so we skip the
0.1.3 tag and ship everything as 0.2.0. The audit-follow-up
section below preserves the full per-component fix list.

### Added (SDK)

- `Decision.llm_call(system=..., model=...)` opens a `fabric.llm_call`
  child span (kind=CLIENT) under the active decision span. Writes
  the OpenTelemetry GenAI semantic conventions
  (`gen_ai.system`, `gen_ai.request.model`,
  `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`,
  `gen_ai.response.finish_reasons`) plus matching `fabric.llm.*`
  mirrors. The returned context manager exposes
  `.set_usage(input_tokens, output_tokens, finish_reason)`,
  `.set_response_model(model)`, and `.set_attribute(key, value)` for
  attaching response data on exit. Phoenix LLM views, Langfuse cost
  dashboards, and any backend keying off either namespace render
  Fabric traces natively from this release onward.
- `Decision.tool_call(name, call_id=None)` follows the same pattern
  for tool/function invocations. Writes `gen_ai.tool.name`,
  `gen_ai.tool.call.id`, plus `fabric.tool.*` mirrors. Setter
  `.set_result_count(count)` records how many results the tool
  returned.
- `LLMCall` and `ToolCall` exposed at the package level for callers
  building custom instrumentation patterns.
- Auto-instrumentation extras — one `pip install` covers governance
  and LLM-call observability for the popular SDK families:
  - `singleaxis-fabric[openai]` →
    `opentelemetry-instrumentation-openai-v2`
  - `singleaxis-fabric[anthropic]` →
    `opentelemetry-instrumentation-anthropic`
  - `singleaxis-fabric[bedrock]` →
    `opentelemetry-instrumentation-bedrock`
  - `singleaxis-fabric[otel-langchain]` →
    `opentelemetry-instrumentation-langchain`
  - `singleaxis-fabric[cohere]` →
    `opentelemetry-instrumentation-cohere`
- `Fabric.enable_auto_instrumentation(only=..., capture_content=...)`
  lazy-detects which extras are installed and invokes each
  Instrumentor's `.instrument()`. Content capture (raw prompts /
  completions on spans) is **off by default** per Fabric's
  compliance posture; override with `capture_content=True` or
  `FABRIC_CAPTURE_LLM_CONTENT=true` env. Silently skips uninstalled
  extras; warns and continues when an upstream Instrumentor raises
  rather than crashing agent startup.
- Reference agent (`examples/reference-agent/`) now wraps its
  simulated LLM call in `decision.llm_call` so users see the
  canonical pattern in the runnable example.

### Added (OTel collector)

- `fabricguardprocessor` registers a Traces pipeline variant
  alongside the existing Logs variant. Spans are filtered by an
  attribute-key namespace allowlist (default:
  `fabric.`, `gen_ai.`, `llm.`, `tool.`, `service.`, `telemetry.`,
  `otel.`, `http.`, `net.`, `rpc.`, `db.`). Anything outside these
  prefixes is stripped before egress; spans whose attributes become
  empty are dropped. Operators tighten / extend via
  `trace_attribute_prefixes`; trace processing is OFF by default
  (`trace_processing_enabled: false`) so existing operator config
  files work unchanged. Closes the gap where the chart's privacy/
  policy enforcement only applied to L2-bridge-shaped log records,
  while the SDK's spans bypassed the processor entirely.

### Changed (docs / scope)

- L1/L2 boundary now load-bearing across all narrative docs.
  README hero is "open-source observability and control plane for
  AI agents"; specs 003 (Context Graph), 004 (Telemetry Bridge),
  006 (LLM-as-Judge), 007 (Escalation Workflow) gain explicit "L2
  commercial control plane / not in this OSS distribution"
  disclaimers — the implementation lives in a separate private
  repository, the spec is retained for partner/auditor
  transparency.
- Spec 002 §L2 wording corrected from "OpenTelemetry +
  OpenLLMetry" to "OpenTelemetry + GenAI semantic conventions" —
  the conventions are joint OTel/Traceloop work; "OpenLLMetry" is
  a project name, not a spec name. Fabric does not depend on
  `traceloop-sdk`.
- Spec 011 (roadmap) recast as "L2 + L4 + L5 + L1 adapters" of
  the 8-layer agent stack: that's the OSS scope. v0.2.x = capture-
  everything SDK; v0.3.x+ = additional language SDKs + broader
  rails catalog + conformance test suite.
- Spec 009 (compliance mapping) rewritten to make explicit that
  per-regulation mappings ship with the L2 commercial control
  plane; the L1 OSS chart provides regulatory profiles as
  hardened presets only.
- New `docs/exporting-to-your-observability-backend.md` — concrete
  Helm wire-ups for Langfuse, Phoenix, Datadog, Honeycomb, Grafana
  Cloud, custom collectors. Replaces the implicit
  "fabric-ingest:8080" assumption.
- New `docs/how-fabric-fits-in-your-agent-stack.md` — 8-layer
  picture with where Fabric ships code (★) vs adapter/integration
  vs out-of-scope (◆), plus end-to-end ASCII diagram showing the
  L1 OSS / L2 commercial boundary.
- New `sdk/python/SCOPE.md` — what the SDK does and explicitly
  does NOT do.

### Fixed (CI)

- Pre-existing CI red on the audit-followup branch resolved
  (5 of 5 red checks): SDK ruff RUF100 unused `# noqa: SLF001`
  directives in `test_tracing.py`, SIM117 nested `with` in
  `test_retrieval.py`, three nemo-sidecar CLI tests
  (`test_cli_invokes_uvicorn_on_uds/tcp`,
  `test_cli_unlinks_stale_socket`) updated to pass
  `--allow-passthrough` after the round-1 security tightening
  made `--rails-config` mandatory by default.

### Audit follow-up (folded from never-tagged 0.1.3)

Round-2 audit fixes. 5 parallel deep-audit agents flagged ~80
issues across SDK code-correctness, components, charts, specs, and
production-readiness. The following per-component fix list was
prepped under the `chore/v0-1-3-audit-followup` branch and merged
to main as PR #44, but the surrounding work added new public API
(`Decision.llm_call`, `Decision.tool_call`, auto-instrument extras,
collector trace processing) so we skip the 0.1.3 tag and roll
everything into 0.2.0.

### Fixed (SDK)

- `FabricConfig` and `Fabric.from_env` now strip whitespace from
  `tenant_id`, `agent_id`, `profile` and reject empty-after-strip.
  Trailing newlines in `.env` files / Helm values no longer ship as
  span attributes.
- `Decision.__exit__` now records `blocked_and_escalated` status
  when both fire on the same Decision, instead of silently
  collapsing the escalation behind the block status.
- `Decision.record_block` and `Decision.request_escalation` are now
  first-wins; the second call raises `RuntimeError` rather than
  silently overwriting.
- `Decision.set_attribute` validates value type and raises
  `TypeError` on dict/list/None, matching OTel's actual contract
  rather than relying on OTel to silently drop unsupported values.
- `RetrievalRecord.from_query` now enforces 1:1 parity between
  `result_hashes` and `result_count` when supplied. Mismatched
  partial supply was silently corrupting downstream Context Graph
  projections. `source_document_ids` remains free-form (N chunks
  may share M < N source documents).
- `_chain.GuardrailChain` no longer pushes NeMo rail names into
  `entities_detected` (`EntitySummary` represents PII entity
  classes, not rail names). NeMo rails appear only in
  `policies_fired`.
- `install_default_provider` refuses to silently re-install when an
  existing real `TracerProvider` is configured. Returns the existing
  provider with a warning; OTel's own API documents that
  re-installation is not allowed.
- New: `fabric.tracing` emits a one-shot warning at first
  `get_tracer()` if the global TracerProvider is the OTel no-op
  default. Without this, hosts who skip `install_default_provider`
  ship instrumented agents that emit zero-trace_id spans silently.

### Fixed (components)

- NeMo sidecar refuses to start without `--rails-config` unless the
  operator explicitly passes `--allow-passthrough`. Previously a
  missing volumeMount silently produced an "allow-everything" engine
  that disabled jailbreak/policy defence with only a docstring
  warning.
- NeMo sidecar `FABRIC_LIMIT_CONCURRENCY` parsing emits a clear
  parser error on non-int input rather than crashing the whole
  process at uvicorn boot.
- Update-agent webhook refuses to fall back to plaintext on the
  admission path when only one of `--tls-cert` / `--tls-key` is
  present. Plaintext on a webhook causes either every-admission-
  failure (failurePolicy=Fail) or every-admission-bypass
  (failurePolicy=Ignore); both are customer outages. Fully-
  plaintext mode is opt-in via `FABRIC_UPDATE_AGENT_ALLOW_PLAINTEXT=1`
  for local smoke tests only.

### Fixed (charts)

- Umbrella chart now fail-renders on empty `tenant.id` for any
  profile other than `permissive-dev`. Empty tenant ID stamps every
  emitted span with no attribution and was the most common
  silent-misconfiguration footgun.
- Per-subchart `NetworkPolicy` allow templates now ship for
  `otel-collector`, `nemo-sidecar`, and `update-agent`. Each opens
  the minimum surface (collector OTLP receivers, sidecar service
  port, webhook ingress) plus DNS to `kube-system`. Default off so
  CNIs without enforcement aren't penalised; the
  `eu-ai-act-high-risk` profile re-enables `networkPolicy.denyDefault:
  true` paired with these allow rules.
- `PodDisruptionBudget` templates added to all three subcharts,
  honoured only when `replicaCount > 1`. `update-agent` is the
  load-bearing one — losing both webhook replicas during a node
  drain blocks ConfigMap/Secret CREATE/UPDATE cluster-wide.
- `otel-collector` and `nemo-sidecar` readiness probe initial
  delays bumped (from 5s/3s to 15s/20s) so rolling deploys on slow
  networks don't mark pods Unready repeatedly during cold-start.
- **`otel-collector.exporter.endpoint`** default flipped from the
  phantom `http://fabric-ingest:8080` (which resolved to a non-existent
  service in any L1-only deploy) to the empty string, paired with a
  render-time validator that fails the chart install if the field is
  unset. Previously: spans dropped silently because the configured
  exporter target had no service behind it. Now: operator must point
  at a real backend (bundled Langfuse, Datadog, Honeycomb, your own
  collector chain, or — for partner deployments — the SingleAxis
  commercial Telemetry Bridge). CI smoke renders set
  `otel-collector.exporter.acceptUnsetEndpoint=true` to bypass.
- `eu-ai-act-high-risk` profile now sets explicit `ingressFrom` /
  `egressTo` defaults on otel-collector and nemo-sidecar
  NetworkPolicies — ingress restricted to `fabric-system` namespace
  rather than the previous `namespaceSelector: {}` (which permitted
  any namespace under denyDefault). Operators bridging from agent
  pods in other namespaces extend `ingressFrom` to permit them.

### Fixed (docs)

- **Hero repositioning.** README + SDK pyproject description shifted
  from "audit-ready substrate" to "open-source observability and
  control plane for AI agents." The old framing implied this OSS
  distribution generated audit trails on its own; in fact the
  collection infrastructure ships here and evidence-bundle generation
  / signed audit trails ship with the SingleAxis commercial control
  plane. Engineer-vocabulary hero, honest L1/L2 boundary, no
  compliance-tool buyer mismatch.
- README NIST AI RMF / ISO/IEC 42001 / SR 11-7 / HIPAA profiles list
  now explicitly marked as roadmap (only `eu-ai-act-high-risk` and
  `permissive-dev` ship in `charts/fabric/profiles/`).
- README + docs/README no longer link to `docs/compliance/mappings/`
  as if it contained authoritative content; the only thing landing
  there is an in-progress stub. Pointer is now to spec 009.
- `docs/architecture.md` latency framing softened to "design budget"
  to match the README v0.1.2 wording. Numbers are unchanged but
  no longer claimed as measured P99s.
- `charts/fabric/README.md` no longer claims readiness probes
  enforce latency budgets (today's probes are simple HTTP
  `/healthz` checks; latency-aware readiness gate is roadmap).
- `Pre-alpha` → `Beta` framing reconciled across the README and the
  SDK README to match the `pyproject.toml` classifier
  (`Development Status :: 4 - Beta`) introduced in 0.1.2.

### Operator action required

If you run `helm install fabric` with a non-`permissive-dev` profile,
you must now pass `--set tenant.id=<uuid>` (previously this was
documented as required but only warned in NOTES.txt).

If you want fail-closed network posture, NetworkPolicy
`denyDefault: true` is no longer enabled by the EU profile — flip it
in your tenant values once you have allow-rules for your cluster.

If you used `--allow-passthrough` semantics by relying on a missing
`--rails-config` to NeMo sidecar (probably nobody — but flagging it
as a behaviour change), pass `--allow-passthrough` explicitly.

## [0.1.2] - 2026-04-27

Pre-launch hardening pass following an enterprise-grade audit.
Functionally identical SDK surface; this release fixes
documentation, packaging, and supply-chain hygiene that the audit
flagged.

### Fixed

- **README 60-second example** now compiles end-to-end. Pinned the
  `[otlp]` extra requirement, switched to explicit
  `Fabric(FabricConfig(...))` so it runs without environment setup,
  replaced placeholder names (`session.id`, `req.body`, `my_llm`)
  with literal strings.
- **`eu-ai-act-high-risk` Helm profile** now renders under
  `helm template` with the documented `--set` overrides
  (`update-agent.config.allowPlaceholderKey=true` and
  `otel-collector.fabric.redact.acceptMissingProvider=true`).
  Production install still fail-closes on the placeholder key —
  the override only affects dry-renders for compliance review.
  `docs/deployment.md` documents both paths.
- **OTel Collector binary version stamp** now matches the chart
  and image tag (was reporting `0.1.0` under the `0.1.1` tag).
- **Chart versions** bumped across the umbrella, all five
  subcharts, and the `ocb-config.yaml` to track the release tag.
- **mypy --strict** passes cleanly — removed an unused
  `# type: ignore[import-not-found]` in
  `sdk/python/src/fabric/adapters/langgraph.py`.
- **Quickstart step 2** no longer references an undefined `my_llm`
  symbol.
- **`docs/quickstart.md` and `examples/reference-agent`** now
  install a real `TracerProvider` so `trace_id` is a real 32-hex
  value rather than the all-zeros sentinel.
- **README compliance frameworks** list reconciled with
  `docs/compliance/mappings/README.md` (initial mappings target
  EU AI Act, NIST AI RMF, ISO/IEC 42001; SR 11-7, HIPAA, GDPR are
  roadmap).
- **LICENSE** trademark clause restored to verbatim Apache-2.0
  wording so license scanners do not flag the file as modified.

### Changed

- **`sdk/python/pyproject.toml`** classifier from
  `Development Status :: 2 - Pre-Alpha` to `4 - Beta` — matches
  the released GA posture.
- **`Decision` concurrency contract** documented in
  `sdk/python/src/fabric/decision.py`: one `Decision` per agent
  turn; do not share across coroutines or threads.
- **`release.yml`** workflow permissions narrowed — workflow-level
  default is `contents: read`; each job that needs writes
  escalates explicitly. Reduces the blast radius of any compromise
  to one step.
- **README latency claims** softened to "design budget" framing —
  the `<1ms` and `<100ms` P99 numbers are budgets enforced by
  readiness probes, not measured benchmarks (which land in a
  follow-up release).

### Operator action required

If you are upgrading from `0.1.1` and using `helm template` /
`helm lint` against the `eu-ai-act-high-risk` profile, add:
`--set update-agent.config.allowPlaceholderKey=true`
`--set otel-collector.fabric.redact.acceptMissingProvider=true`.
A real `helm install` is unaffected.

PyPI `0.1.1` will be yanked after `0.1.2` is verified live;
`pip install singleaxis-fabric` will resolve to `0.1.2`.

## [0.1.1] - 2026-04-27

**First publishable GA on PyPI.** Functionally identical to `0.1.0`;
cut as a fresh version because the PyPI `0.1.0` slot was occupied
by a yanked artifact and `skip-existing: true` on the publish
action prevented the GA build from overwriting it.

`pip install singleaxis-fabric` resolves to `0.1.1`. Container
image `ghcr.io/singleaxis/fabric-otelcol:0.1.0` and the OCI Helm
chart at `0.1.0` are unaffected and remain the canonical names
there.

See `[0.1.0]` below for the complete shipping surface.

## [0.1.0] - 2026-04-27

**Initial general-availability release** of SingleAxis Fabric — the
open-source substrate for audit-ready AI agents.

Functionally identical to `0.1.0-rc.6`; this tag stamps the
release-candidate verification as the canonical `0.1.0` artifact set.

### What ships in 0.1.0

**Fabric Python SDK** (`pip install singleaxis-fabric`)

- `Fabric` client and `Decision` context manager — one OpenTelemetry
  span per agent turn, tagged with tenant / agent / session /
  request / user
- Inline guardrail chain — Microsoft Presidio (PII redaction) and
  NVIDIA NeMo Guardrails (Colang policy rails) over Unix domain
  sockets, fail-loud by design (`GuardrailNotConfiguredError` if a
  rail is invoked but not wired)
- Retrieval recording (SHA-256 hashed locally; raw text never leaves
  the span) and memory-write recording mapping onto the provenance
  graph
- Escalation pause primitive returning a framework-agnostic payload
  for human-in-the-loop review
- First-class adapters for **LangGraph**, **Microsoft Agent
  Framework**, and **CrewAI**, each gated behind an install extra so
  the core install stays framework-neutral
- OTel helpers: `get_tracer`, `install_default_provider`
- Tested across Python 3.11, 3.12, 3.13

**Guardrail sidecars**

- Presidio sidecar — UDS PII redaction with default recognizers
- NeMo Guardrails sidecar — UDS Colang rails, multi-stage Dockerfile
  builds the `annoy` C++ extension cleanly

**OTel Collector distribution**

- Pre-configured Fabric processor chain: tail sampling, attribute
  allowlisting, tenant scoping
- Fans out to Langfuse, Tempo, Jaeger, Honeycomb, Datadog — anything
  that speaks OTLP
- Published to `ghcr.io/singleaxis/fabric-otelcol:0.1.0`, signed
  with cosign (keyless via Fulcio), multi-arch (amd64 + arm64)

**Helm chart**

- Umbrella chart at `charts/fabric/` with two regulatory profiles:
  `permissive-dev` for evaluation, `eu-ai-act-high-risk` for
  production under the EU AI Act
- Subcharts gated behind `*.enabled` toggles so operators can start
  small (just collector) and layer on guardrails / observability /
  red-team as needed
- `otel-collector` subchart published as an OCI artifact at
  `oci://ghcr.io/singleaxis/charts/otel-collector:0.1.0` (signed)

**Reference agent**

- End-to-end example exercising every SDK surface (decision span,
  retrieval, guardrails, memory, escalation) — runs offline against
  a simulated LLM and judge

**Supply-chain integrity**

- All artifacts (Python wheels, container images, OCI chart, source
  tarball, SBOMs) are signed with [Sigstore cosign](https://sigstore.dev)
  keyless via Fulcio
- SBOMs in CycloneDX and SPDX formats accompany every release
- SLSA build provenance attestations for images and tarballs

**Specs (design of record)**

- 14 specs covering overview, product vision, architecture,
  context graph, telemetry bridge, inline guardrails, LLM-as-judge,
  escalation workflow, deployment model, compliance mapping,
  development standards, and the phased roadmap

### Status

**Pre-alpha** (development status 2 in `pyproject.toml`). The SDK
public surface above is stable for the duration of `0.1.x`; the
Python distribution version is derived from the git tag at build
time so pinning works as expected. Anything labeled "Phase 2",
"roadmap", or "planned" in any document is exactly that — not
shipping in `0.1.x`.

### Known boundaries

- The agent request path **never** blocks on a Fabric HTTP call —
  SDK work is in-process (`<1ms` P99), guardrail sidecars run over
  UDS (`<100ms` P99), everything else (judges, escalation
  bookkeeping, provenance writes) is async off the OTel stream
- Raw agent traces, retrieved context, and user content **never**
  egress the tenant VPC by default — the Telemetry Bridge that
  egresses sanitized summaries is opt-in and not part of this
  release
- "Audit-ready" means Fabric produces the evidence trail an audit
  requires, not that Fabric issues certifications — certification
  remains the tenant's process

### Acknowledgements

Fabric stands on the shoulders of OpenTelemetry, Microsoft
Presidio, NVIDIA NeMo Guardrails, LangGraph, Microsoft Agent
Framework, CrewAI, Langfuse, and Sigstore. Thank you to those
project teams for the foundations.

### Operator action required

None for fresh installs. There is no prior stable release to
upgrade from.

## [0.1.0-rc.6] - 2026-04-27

Re-cut of `0.1.0-rc.5` to refresh release artifacts. No functional
or SDK changes; tenant-facing API stable. PyPI artifacts for rc.1
through rc.5 have been yanked.

Anyone with a prior clone or fork must re-clone or hard-reset.

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
  ([008-deployment-model.md](specs/008-deployment-model.md)):
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
  `specs/011-roadmap.md`) covering product vision, architecture,
  Context Graph, Telemetry Bridge, guardrails, judges, escalation,
  deployment, compliance mapping, development standards, and
  roadmap.

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
- **Phase-1a scope.** Judge-workers, escalation-service,
  context-graph, telemetry-bridge, and NATS broker are not part of
  this distribution; operators deploying the OSS umbrella get
  inline guardrails + collector + opt-in red-team, not the full
  async judge loop.


---

[Unreleased]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.2.0
[0.1.2]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.2
[0.1.1]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.1
[0.1.0]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0
[0.1.0-rc.6]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.6
[0.1.0-rc.5]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.5
[0.1.0-rc.4]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.4
[0.1.0-rc.3]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.3
[0.1.0-rc.2]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.1
