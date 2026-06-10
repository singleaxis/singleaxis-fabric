# Enterprise readiness

A single-page trust overview for security, risk, and procurement teams
evaluating SingleAxis Fabric. Every claim here is verifiable against this
repository — Fabric is Apache 2.0, so you can audit every line yourself.

> **Scope honesty.** This page covers the **OSS substrate**
> (`singleaxis-fabric`, the SDK + sidecars + collector + Helm chart),
> which is generally available (v0.6.x) and the layer you deploy. The
> **commercial control plane** (Decision Graph, Evidence Bundles, Judge
> Workers, Expert Review) is pre-GA and is **not** represented as
> production-ready here — engage SingleAxis for its current status.

---

## 1. Security model

| Property | How Fabric enforces it |
|---|---|
| **Raw content never on telemetry** | Span attributes carry **hashes only**; raw inputs/outputs go out-of-band to a tenant-controlled content store. A leak of your traces is not a leak of your data. |
| **Inline PII redaction** | Presidio sidecar over a Unix domain socket redacts EMAIL/PHONE/SSN/CREDIT_CARD + named entities (HMAC or tag mode) **before** content reaches the model or a span. |
| **Egress allowlist** | The `fabricguard` collector processor strips any attribute outside the configured namespace allowlist before traces leave the cluster. |
| **Fail-closed guardrails** | Guardrail/redaction failures **block** the turn (do not forward unverified content) — verified by an adversarial fault-injection test suite. |
| **Tool authorization** | A `ToolAuthorizer` hook re-checks authorization at every tool call (input/tool/output/egress enforcement points), defeating the confused-deputy pattern. |
| **No phone-home** | The OSS emits only to the OTLP endpoint you configure. No telemetry is sent to SingleAxis. |

## 2. Supply-chain integrity

| Control | Evidence |
|---|---|
| **Signed artifacts** | Multi-arch container images + Helm chart + source archive signed with **cosign** (keyless, Sigstore). |
| **SBOMs** | Both **SPDX** and **CycloneDX** SBOMs generated and signed per release. |
| **Provenance** | PyPI publish via **OIDC Trusted Publishing** (no long-lived tokens); build provenance attestations attached. |
| **Reproducible version** | Version is stamped from the signed git tag (`hatch-vcs`); no hand-edited version files. |
| **OpenSSF Scorecard** | Public scorecard badge tracked in the README. |
| **License hygiene** | Apache-2.0; all dependencies are Apache/MIT/BSD-class, enforced by a license-compatibility CI gate. |

## 3. Vulnerability management

Every pull request and release runs:

| Tool | Covers |
|---|---|
| **CodeQL** | Code scanning (Python + Go) |
| **Semgrep** | SAST (static analysis) |
| **Trivy** | Filesystem + dependency vulnerability scan |
| **OSV-Scanner** | Known-vulnerability scan against the dependency graph |
| **gitleaks** | Secret scanning |

Findings post to GitHub Code Scanning and **block merge** via required
status checks + `required_conversation_resolution`. Private vulnerability
disclosure process is in [`SECURITY.md`](../SECURITY.md), with a
documented supported-version matrix.

## 4. Quality & correctness gates (enforced in CI, block merge)

| Gate | Bar |
|---|---|
| Type safety | **`mypy --strict`** on `src` and `tests` |
| Lint / format | `ruff` check + format |
| Test suite | **653 tests**, 0 skipped |
| Coverage | **≥85% gate; actual ≈95%** |
| Wire contract | **31 byte-locked conformance goldens** — the emitted schema cannot drift silently (`fabric.schema_version = 1.0`) |
| Multi-version | Tested on Python 3.11 / 3.12 / 3.13 |
| API stability | Documented public-surface + deprecation policy ([`api-stability.md`](api-stability.md)) |

## 5. Reliability & operations

| Property | Status |
|---|---|
| **Pod security** | `runAsNonRoot`, `runAsUser` 1000/65532, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault` across the chart |
| **High availability** | Configurable replicas, **PodDisruptionBudgets**, `topologySpreadConstraints`, liveness/readiness probes, resource requests + limits |
| **Network policy** | Deny-default NetworkPolicy in the production profile; sidecars cannot egress to the public internet |
| **Performance overhead** | ~10–30 ms per decision (UDS-local sidecars, async span export, sub-ms regex pre-filter) — typically <5% of an LLM turn |
| **Resource safety** | Verified under a 20k+ decision soak: flat memory, no FD/socket leak, bounded backpressure |
| **Fail-loud config** | The production profile refuses to install without real signing keys, tenant keys, and an exporter endpoint |

## 6. Data handling & privacy

- **Data residency:** Fabric runs entirely in **your** cluster/region; you
  choose the OTLP backend. No data crosses to SingleAxis in OSS mode.
- **PII:** redacted at the per-pod boundary before model/telemetry exposure;
  raw content is hash-referenced and stored only where you configure.
- **Right to erasure:** content store + graph expose tenant-scoped content deletion primitives.
- **Multi-tenancy:** every record is tenant-scoped (`tenant_id` on all spans/nodes/edges).

## 7. Compliance posture

| Regime | How Fabric helps |
|---|---|
| **EU AI Act (high-risk)** | `eu-ai-act-high-risk` Helm profile; per-decision record-keeping (Art. 12); human-oversight escalation hooks (Art. 14) |
| **HIPAA** | §164.312(b) audit controls — PII never on spans; tenant-scoped audit trail |
| **SOC 2** | Audit-log substrate + supply-chain controls supporting CC-series criteria |
| **NIST AI RMF / ISO 42001** | MEASURE/MANAGE telemetry foundation; mappings in [`docs/compliance/`](compliance/) |

A full auditor question-by-question mapping is in
[`docs/auditor-checklist.md`](auditor-checklist.md).

## 8. Governance & support

- **Governance:** [`GOVERNANCE.md`](../GOVERNANCE.md) ·
  [`MAINTAINERS.md`](../MAINTAINERS.md) ·
  [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) ·
  [`CONTRIBUTING.md`](../CONTRIBUTING.md)
- **Versioning:** Semantic Versioning; schema version is independent and conformance-locked.
- **Support:** see [`SUPPORT.md`](../SUPPORT.md). Enterprise SLA + CVE-response + LTS available commercially.

---

## What we do not claim (known limitations)

Procurement teams should weigh these:

1. **Pre-1.0.** The SDK is v0.6.x; the public API may change before 1.0
   (policy in `SECURITY.md` / `api-stability.md`). The **wire contract** is
   conformance-locked and stable.
2. **No third-party SOC 2 / pen-test report yet.** The controls above are real
   and verifiable in-repo; an independent attestation is on the roadmap
   (available to design partners on request).
3. **TypeScript SDK** is not yet at full conformance parity with Python and is
   not published to npm.
4. **The commercial control plane is pre-GA.** Do not deploy Decision Graph /
   Evidence Bundles / Judge Workers / Expert Review as production-critical
   until SingleAxis confirms GA status for your use case.

We publish these gaps deliberately — a vendor that hides its gaps is the
real risk. Everything claimed above is auditable today; everything
deferred is named here.

---

**Questions / a security review call:** bryan@singleaxis.ai
