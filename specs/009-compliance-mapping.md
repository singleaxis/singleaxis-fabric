---
title: Regulation-to-Layer Mapping & Evidence Bundle
status: draft
revision: 1
last_updated: 2026-04-18
owner: compliance-lead
---

# 009 — Compliance Mapping

> **Scope note (2026-04-27).** Two distinct artifacts described here
> ship at different tiers:
>
> - **L1 OSS — Regulatory profiles.** The Helm chart's
>   `eu-ai-act-high-risk` profile (and any future `nist-ai-rmf`,
>   `iso-42001`, `sr-11-7`, `hipaa` profiles, all roadmap) lock the
>   subset of configuration that maps to the regulation's
>   technical-control surface. Today only `eu-ai-act-high-risk` and
>   `permissive-dev` ship in `charts/fabric/profiles/`.
>
> - **L2 commercial — Evidence Bundle export + per-regulation
>   mappings.** The signed Evidence Bundle, the `/evidence/bundle`
>   endpoint, the queryable Context Graph, the per-regulation control
>   mapping documents, and the retention enforcement all live in the
>   SingleAxis commercial control plane (separate private repo). They
>   are described in this spec for design-of-record transparency.
>   `docs/compliance/mappings/` ships empty in this OSS distribution
>   by design — concrete mapping files (`eu-ai-act.md` etc.) land
>   alongside the L2 control plane that actually produces the
>   evidence those mappings reference.

## Summary

This spec maps specific regulatory requirements — EU AI Act, NIST AI
RMF, ISO 42001, SR 11-7, HIPAA, GDPR — to the Fabric layers, events,
and artifacts that produce evidence for each control. It also
specifies the **Evidence Bundle** format — what Fabric exports when a
tenant needs to answer an auditor.

The mapping is the design contract Fabric's L1 collection
infrastructure targets so that the L2 commercial control plane can
materialize defensible evidence bundles. L1 alone produces the
collection substrate; producing audit-grade bundles requires the L2
pipeline.

## Goals

1. Provide a control-by-control mapping for each supported
   regulation, showing which Fabric component produces evidence
   and what form it takes.
2. Define the Evidence Bundle — a signed, schema-validated,
   point-in-time export of Fabric's state suitable for
   presentation to an auditor.
3. Define the lifecycle: when are bundles produced, how long are
   they retained, how are they requested.
4. Keep the mapping honest — state what Fabric covers and what it
   does NOT cover for each regulation.

## Non-goals

- Legal advice. This spec describes Fabric's technical mapping;
  regulatory conformance ultimately requires the tenant's own
  legal and compliance judgement.
- Certifying specific deployments. SASF attestation is separate
  from this spec and covers a narrow, defined scope; see spec 001
  and 006.
- Complete coverage of every possible regulation. Supported
  regulations are those with concrete Regulatory Profiles.

## The regulations we map

| Regulation | Jurisdiction | Fabric Profile |
|------------|--------------|----------------|
| EU AI Act (Reg. 2024/1689) | European Union | `eu-ai-act-high-risk`, `eu-ai-act-limited-risk` |
| NIST AI RMF 1.0 | United States (voluntary) | `nist-ai-rmf` |
| ISO/IEC 42001:2023 | International | `iso-42001` |
| SR 11-7 Model Risk | US banking | `sr-11-7` |
| HIPAA | US healthcare | `hipaa` |
| GDPR (right-to-erasure) | European Union | Layered over any profile |

Future profiles (UK AI Bill, Canadian AIDA, Brazilian AI framework)
will be added as regulations take effect.

## Mapping structure

For each regulation, the mapping enumerates controls. Each control
entry declares:

- **Fabric artifact(s)** that produce the evidence
- **Evidence form** — log, metric, signed attestation, etc.
- **How it is surfaced in the Evidence Bundle**
- **Gaps** — what Fabric does not cover, explicitly

The full mapping tables are long; below are exemplary excerpts. The
authoritative source will live in
[`docs/compliance/mappings/`](../docs/compliance/mappings/) — the
directory is scaffolded; per-regulation mapping files land as the
underlying evidence pipeline stabilizes.

### Excerpt — EU AI Act

| Article / §  | Requirement (summary) | Fabric artifact | Evidence form | Gaps |
|--------------|------------------------|------------------|---------------|------|
| Art. 9 — Risk management | Establish, document, maintain risk management system | Rubric library + red-team suite + profile | Red-team report + rubric manifest; profile declaration | Does not cover the tenant's organizational risk management process |
| Art. 10 — Data & data governance | Training/validation data quality controls | N/A directly (Fabric does not train) | Bridges to tenant's data lineage if configured | Fabric does not assess training data; tenant must |
| Art. 12 — Record-keeping | Automatic recording of events over lifecycle | Context Graph (Decision / Step / Retrieval / Guardrail / Judge / Review nodes) | Signed Context Graph export | Complete within Fabric's scope |
| Art. 13 — Transparency | Clear information about system operation | Context Graph decision-scoped read + profile documentation | GraphQL queries; human-readable summaries in Evidence Bundle | Does not generate user-facing documentation; tenant must |
| Art. 14 — Human oversight | Enable effective human oversight | Escalation workflow + SASF review + guardrails | Escalation / Review nodes; SASF attestations | Requires tenant to define which decisions require oversight (profile-configured but tenant-owned) |
| Art. 15 — Accuracy, robustness, cybersecurity | Appropriate level across the lifecycle | Judges + red-team + security controls | Judge scores over time; red-team reports; security posture declarations | Does not assess model robustness directly; provides the measurement substrate |
| Art. 17 — Quality management system | Written QMS | Spec library + release artifacts + signed manifests | Spec repository; release history | QMS process is organizational |
| Art. 61 — Post-market monitoring | Ongoing monitoring after placing on market | Continuous judge scores + SASF sampling | Rolling bundle updates | Tenant remains responsible for incident reporting |

### Excerpt — NIST AI RMF 1.0

| Function | Category / sub-cat | Requirement | Fabric artifact |
|----------|--------------------|--------------|------------------|
| GOVERN | 1.1 | Policies, processes are in place | Profile declarations + spec library |
| MAP | 1.1 | Context is established | Agent metadata + profile declaration |
| MEASURE | 2.1 | Appropriate methods used to evaluate system | Rubric library + red-team + SASF |
| MEASURE | 2.3 | AI system operates as expected (accuracy, reliability) | Judge scores (factuality, faithfulness) + red-team |
| MEASURE | 2.7 | AI risks from privacy are examined and documented | Presidio detections + profile PII policy |
| MEASURE | 2.8 | AI system's behaviour is monitored | Context Graph + Langfuse dashboards |
| MEASURE | 4.1 | Deployment decisions are informed by risks | Pre-deploy red-team + judge baseline + SASF gate |
| MANAGE | 1.3 | Responses to AI risks are documented | Escalation + Review nodes + incident bundle |
| MANAGE | 4.1 | Ongoing monitoring and re-evaluation | Continuous judges + rubric versioning |

### Excerpt — ISO/IEC 42001:2023

| Clause | Requirement (summary) | Fabric artifact |
|--------|------------------------|------------------|
| 6.1.2 | AI risk assessment | Profile + rubric library |
| 7.5.3 | Documented information: control | Spec repository with signed commits |
| 8.2 | AI system impact assessment | Red-team reports + judge baselines |
| 8.3 | AI system requirements and data quality | Guardrail policy + retrieval audit |
| 9.1 | Monitoring, measurement, analysis, evaluation | Context Graph + judges + Langfuse |
| 10.2 | Continual improvement | Rubric evolution + profile updates via signed manifests |

## The Evidence Bundle

An Evidence Bundle is a **signed, schema-validated archive** that a
tenant exports (or has exported on their behalf by SingleAxis) to
present to an auditor. It is Fabric's primary commercial output.

### Shape

```
evidence-bundle-<bundle_id>.tar.gz
├── manifest.json                    ← signed, describes contents
├── manifest.json.sig                ← Ed25519 signature
├── scope.json                       ← what this bundle covers
├── profile.yaml                     ← active profile at the time
├── fabric-version.json              ← Fabric + component versions, SBOM digest
├── decisions/                       ← Context Graph export
│   └── <decision_id>.json
├── rubrics/
│   └── <rubric_id>-<version>.yaml   ← signed rubrics in use
├── policies/
│   ├── guardrails/                  ← Presidio + NeMo in use
│   └── escalation/
├── redteam-reports/
│   └── <report_id>.json
├── sasf-attestations/
│   └── <attestation_id>.json        ← signed human reviews
├── escalation-log/
│   └── <escalation_id>.json
├── deletions-log/                   ← GDPR erasure events
│   └── <event_id>.json
├── access-log/                      ← SingleAxis content fetches
│   └── <event_id>.json
├── compliance-mapping/
│   └── <regulation>.json            ← control-by-control evidence pointers
└── README.md                        ← human-readable summary
```

### Manifest signing

The manifest is signed by the tenant's Fabric install key. If
SingleAxis-originated evidence (SASF attestations, rubrics) is
present, it carries its own signatures preserved within the bundle.
Verification is:

```bash
cosign verify-blob \
  --certificate fabric-install.pem \
  --signature manifest.json.sig \
  manifest.json
```

### Compliance-mapping pointers

Each `compliance-mapping/<regulation>.json` is a JSON document
keyed by control identifier. Each entry lists the bundle paths that
provide evidence for that control. Example:

```json
{
  "regulation": "eu_ai_act",
  "article_12": {
    "description": "Record-keeping",
    "evidence": [
      "decisions/*.json",
      "escalation-log/*.json",
      "deletions-log/*.json"
    ],
    "coverage": "complete"
  },
  "article_14": {
    "description": "Human oversight",
    "evidence": [
      "escalation-log/*.json",
      "sasf-attestations/*.json"
    ],
    "coverage": "complete"
  },
  "article_15": {
    "description": "Accuracy, robustness, cybersecurity",
    "evidence": [
      "redteam-reports/*.json",
      "decisions/*.json"
    ],
    "coverage": "measurement_layer_only",
    "gaps": [
      "Model robustness assessment not performed by Fabric; tenant or third-party responsibility."
    ]
  }
}
```

This is the document an auditor actually reads to find what they
are looking for. It is the bundle's index.

### Lifecycle

| When | What happens |
|------|--------------|
| On install | Baseline bundle produced with empty history, profile declaration, fabric-version record |
| Continuously | Context Graph, attestations, red-team reports, escalations accumulate |
| On request | `POST /evidence/bundle` with scope + time range → bundle produced |
| On schedule | Profiles may configure monthly / quarterly automatic bundles archived to tenant storage |
| On incident | A bundle for the incident's scope is produced with elevated retention |
| On tenant offboarding | A final bundle is produced; tenant retains ownership |

### Retention

Bundle retention is profile-defined and **tenant-controlled**:

- EU AI Act high-risk: minimum 10 years (Article 12 retention)
- ISO 42001: minimum 3 years
- SR 11-7: minimum 7 years
- Default (no profile): 1 year

Retention applies to bundles. The underlying Context Graph may be
shorter (e.g. 90 days) with bundles as the long-term record.

## Coverage claims — honest scope

Fabric covers the **technical evidence production** side of each
regulation. It does NOT cover:

- **Training data governance.** Fabric does not train models; tenants
  are responsible for training-data provenance.
- **Organizational policies.** Fabric produces evidence of system
  behaviour; tenants are responsible for having policies that
  behaviour conforms to.
- **Legal interpretation.** Which controls apply to a specific
  deployment is a legal determination.
- **Human decision-making.** Where regulation requires a human
  decision (sign-off, impact assessment), Fabric records the
  decision; tenants make it.
- **Third-party dependencies.** Bridges to Langfuse, Presidio, NeMo
  rely on those tools' own correctness; Fabric pins versions and
  tracks them, but does not independently certify them.

Each regulation's mapping document repeats this honest scope at
the top.

## Security considerations

- **Bundle tampering.** Manifest signature + per-file hashes in the
  manifest make tampering detectable.
- **Bundle leakage.** Bundles contain redacted content per profile
  but may still be sensitive (metadata, access patterns). Tenants
  are responsible for bundle storage access control; Fabric does
  not mandate it but recommends encrypted object storage with
  access logging.
- **Replay.** Bundles declare their `scope.time_range`; auditors
  consuming bundles should verify time ranges align with their
  inquiry.
- **Retroactive changes.** Context Graph content is append-only;
  edits produce new nodes, not modifications. Bundles produced at
  different times may differ; that is expected and preserved.

## Open questions

- **Q1.** CycloneDX vs SPDX for the SBOM inside the bundle —
  probably both, for broadest auditor tool compatibility. Confirm.
  *Resolver: compliance lead. Deadline: before 0.1.0.*
- **Q2.** Should bundles include source code references for shipped
  rubrics (so auditors can review what was being scored)? Increases
  bundle size meaningfully. *Resolver: compliance lead + SASF.
  Deadline: before 0.2.0.*
- **Q3.** Can SingleAxis co-sign a bundle (endorsing that Fabric
  version + profile was operationally correct at export time)?
  Attestation beyond just shipping. *Resolver: project lead.
  Deadline: before 0.2.0.*

## References

- Spec 001 — Product vision (commercial framing)
- Spec 003 — Context Graph (bundle contents)
- Spec 006 — LLM-as-Judge (rubric library)
- Spec 007 — Escalation (review attestations)
- [EU AI Act, full text](https://eur-lex.europa.eu/eli/reg/2024/1689/oj)
- [NIST AI RMF 1.0](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf)
- [ISO/IEC 42001:2023](https://www.iso.org/standard/42001)
- [SR 11-7](https://www.federalreserve.gov/supervisionreg/srletters/sr1107.htm)
