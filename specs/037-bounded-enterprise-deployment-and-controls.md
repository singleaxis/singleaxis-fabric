---
title: Bounded enterprise evidence deployment and control applicability
status: draft
revision: 1
last_updated: 2026-09-26
owner: product-architecture
depends_on: 027, 033, 035, 036
related: 038, 039
---

# 037 — Bounded enterprise evidence deployment and control applicability

## Decision and non-claim

This is a **qualification profile**, not a claim that the repository is
enterprise-ready or compliant today. The [AEEP plan](036-evidence-capture-implementation-plan.md)
is draft and its runtime is not implemented. Fabric OSS stays passive
`CAPTURE -> PROTECT -> DELIVER`; customer systems and independent assessors
own legal applicability, risk acceptance, evaluation, and governance. No
installation of Fabric alone satisfies a regulatory framework.

The profile defines a reference deployment that can be tested. Each customer
must replace its assumptions with a signed scope record before production
promotion. Unknown or disputed applicability is `undetermined`, never
`not_applicable`; an unresolved requirement blocks a compliance claim.

## 1. Reference boundary and topology

Reference profile `enterprise-k8s-agent-v1` assumes:

- one customer-controlled Kubernetes cluster on Linux, one named tenant,
  one namespace/workload/service account for a pinned agent build, and a
  named operator-owned Fabric Node deployment using the
  `shadow-production` posture;
- a version-pinned Python **or** TypeScript SDK and provider-bound model
  adapter, one pinned terminal/PTY adapter, and one pinned sandbox adapter;
- explicit allowlisted destinations for a model provider, HTTPS service,
  database, object store, and one instrumented SSH remote host **if any is
  reachable**; all reachable routes must appear in the scope record, not
  just routes used by test fixtures;
- a customer-controlled governed-content store and a separately selected
  OTLP destination, with authenticated identities and documented durable
  receipts; and
- customer-owned Kubernetes, remote-host, database, and destination audit
  feeds for independent reconciliation.

This is an example topology, not an assertion that the adapters or remote
instrumentation exist. A pilot may omit a service class only when network
and execution inventory prove it is unreachable and the customer signs
that exclusion. Fabric does not enforce the boundary; the customer's
sandbox, IAM, firewall, and cluster controls do. A newly installed tool,
child process, remote host, plugin, sidecar, or route changes the scope and
invalidates the prior qualification until inventoried and tested.

The signed scope record MUST contain:

| Field | Minimum content |
| --- | --- |
| Identity | customer, tenant, workload, namespace, service account, agent build digest, operator, approval date |
| Environment | cluster/runtime/kernel, namespace, sandbox image digests, mounts, remote hosts, DBs, provider/API endpoints, egress paths |
| Sources | connector ID/version/digest, placement, boundary and provenance, auth method, expected role families, bypasses, source truth feed |
| Data | data classes, jurisdiction/residency, purpose, content opt-ins, excluded roles, redaction, retention/deletion rules |
| Capacity | measured peak/burst rates, maximum outage, spool/queue sizes, replay window and recovery targets |
| Claims | exact operations and content roles required for reconstruction; excluded/unsupported classes; no hidden-provider or deterministic-replay claim |
| Approval | security, privacy, records, platform owner, AI-system owner, and independent assessor where required |

The scope is frozen before a qualification run. Revisions are numbered,
signed, and linked to the run manifest; a late revision cannot retroactively
turn missing evidence into complete evidence. Raw content is opt-in by role;
metadata-only remains the default. Dev/offline evaluation may use
harness-owned local transcripts without Fabric.

## 2. Applicability decision record

For every framework, a customer-owned record MUST state:
`applicable | conditionally_applicable | not_applicable | undetermined`,
the exact provision/version, why it applies, the data/system boundary,
control owner, required evidence, reviewer, and review date. Only the
customer's counsel/compliance owner may approve `not_applicable`; technical
tests do not make that legal determination. The control matrix below is a
**candidate crosswalk**, not a legal opinion or certification.

| Framework / trigger | Candidate requirements to assess | Fabric evidence contribution | Owner and gap |
| --- | --- | --- | --- |
| NIST SP 800-53 Rev. 5 audit baseline, if adopted by customer | AU-2 event selection; AU-3 record content; AU-4 capacity; AU-5 audit failure response; AU-6 review; AU-9 protection; AU-11 retention; AU-12 generation | Scoped observations, loss and receipt records, protected export | Customer selects control baseline/parameters, monitors and reviews logs, and qualifies storage; Fabric alone does not implement the control system |
| NIST AI RMF, if adopted | Govern/Map/Measure/Manage outcomes and documented risk boundaries | Traceable activity inputs and coverage gaps | AI owner and governance/evaluation systems decide risk, outcomes and actions; recorder has no judge |
| EU AI Act, if system/role/jurisdiction is in scope | Assess classification and provider/deployer role; for applicable high-risk systems assess Arts. 12, 13, 19 and 26 logging, instructions, retention and monitoring | Automatic logging and resolvable evidence only for qualified boundaries | EU counsel determines applicability, effective obligations and retention; customer/provider supplies wider system controls |
| GDPR or other privacy law, if personal data is processed | Assess lawful purpose, minimization, storage limitation, security, access, deletion and impact assessment as applicable | Metadata minimization and role-scoped governed-content controls | Controller/processor determines basis, notices, DPIA, rights handling and retention; recording all raw content may conflict with minimization |
| HIPAA Security Rule, if a regulated entity/business associate uses ePHI | Assess 45 CFR 164.312(b) audit controls and wider safeguards | Capture of approved, observable ePHI-system activity | Regulated entity owns risk analysis, BAA, access/security and examination of all relevant systems |
| PCI DSS, if a component is in the CDE or connected-to/security-impacting scope | Assess Req. 10 logging/monitoring plus applicable access, protection and testing controls | Evidence for only instrumented components | Customer/QSA determines CDE scope and compensating/other controls; uninstrumented DB/terminal access is not covered |
| SOC 2 / ISO/IEC 27001, if customer pursues attestation/certification | Map to customer control objectives and statement of applicability | Recorder test and operational evidence | Service organization/auditor owns criteria, operating effectiveness and certification; this repo is not an attestation |

Authoritative starting points, checked 2026-09-26:
[NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final),
[NIST AI RMF](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/),
[EU AI Act Art. 12](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-12),
[EU AI Act Art. 26](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-26),
[GDPR](https://eur-lex.europa.eu/eli/reg/2016/679),
[HHS HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html),
[PCI SSC scope guidance](https://www.pcisecuritystandards.org/faqs/do-all-pci-dss-requirements-apply-to-every-system-component/),
[AICPA SOC resources](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2),
and [ISO/IEC 27001](https://www.iso.org/standard/27001).
These sources are not interchangeable requirements; the customer must
verify current law, standards versions, contract terms and assessor scope.

## 3. Technical control matrix and evidence ownership

Each row becomes a machine-readable qualification entry with
`control_id, scope_revision, requirement_reference, applicability,
implementation_owner, evidence_uri, test_id, result, reviewer, exception_id`.
Evidence URIs must be customer-controlled and access checked. A passing
unit test is not operating-effectiveness evidence.

| ID | Required outcome for this profile | Technical proof | Owner |
| --- | --- | --- | --- |
| BD-01 | Every reachable execution/egress boundary and source is inventoried; bypasses are explicit | Signed scope, network policy/firewall/IAM export, runtime inventory, connector manifest and direct-call bypass tests | Customer platform + connector |
| ID-01 | Tenant/workload/source/remote identities are authenticated, not accepted from untrusted attributes | mTLS/workload-identity mapping, rotation/revocation test, rejected spoofing fixtures | Customer IAM + Fabric ingress |
| CA-01 | Inputs, outputs, tool context and effects required by scope are byte-exact or marked missing | Content-v2 digests, per-source sequences, attempt links, independent source comparison | Capture adapters |
| CA-02 | Sampling, overflow, kernel loss, source outage and unsupported actions cannot appear complete | Failure injection, gap markers, health/high-water and deterministic run verdict | Every source + reconciler |
| PR-01 | Content/metadata are minimized and protected before crossing customer boundary | Secret canaries, allowlist tests, role policy, approved data classification | Customer privacy + Fabric guard |
| ST-01 | Content, manifests, telemetry and receipts have authorized, encrypted, verifiable storage | IAM/KMS/config proof, cross-tenant denial, digest corruption test, immutable/versioned receipt | Customer storage + resolver |
| ST-02 | Retention, deletion, legal hold and restoration match the approved schedule | Bucket/PVC/backup policy export, time-travel/deletion tests, legal-hold exercise | Customer records + storage |
| DL-01 | Source, Node and destination acknowledgement stages are distinguished | Queue/spool fsync, retry/partial-success tests, destination durable receipt | Connector + Node + destination |
| OP-01 | Alerts, review, incident and change procedures work in the customer environment | On-call drill, evidence of log review, runbook execution, rollback and certificate-expiry drill | Customer operations |
| RL-01 | Exact release artifacts and configuration are pinned and independently tested | Tagged SHA, image/SDK/chart digests, SBOM, provenance/signatures, live E2E and scan reports | Release engineering |
| EV-01 | Authorized evaluators can resolve the approved transcript, but judgments stay outside OSS | Resolver export and external harness proof with incomplete-run handling | Customer evaluator/platform |

## 4. Promotion rule

`critical_enterprise_go` is true only if:

1. scope and all applicable/undetermined control entries are reviewed;
   no `undetermined` or unapproved `not_applicable` remains;
2. every mandatory technical row above has exact-artifact passing evidence
   from [spec 038](038-capture-boundary-and-loss-qualification.md) and
   [spec 039](039-storage-release-and-shadow-pilot.md);
3. the target customer environment passes the shadow-pilot reconciliation
   with no unexplained or silent loss in the declared scope; and
4. the customer risk owner and independent reviewer sign the exact
   scope revision, artifact digests, residual gaps and intended claims.

Any failed/expired proof, unknown source, untested branch, missing receipt,
or unresolved legal applicability yields `NO_GO`. A `NO_GO` cannot be
overridden by a successful schema/unit test. A narrower metadata-only
pilot may be approved separately, but it must never be described as
complete content capture or compliance-grade reconstruction.
