---
title: Protected evidence storage, exact-artifact release, and shadow-pilot qualification
status: draft
revision: 1
last_updated: 2026-09-26
owner: product-architecture
depends_on: 027, 032, 033, 035, 036, 037, 038
---

# 039 — Storage, release and shadow-pilot qualification

## Decision

Recorder release tests and a customer shadow pilot are **separate gates**.
Passing tests against fake stores, schema fixtures or source checkouts is
not evidence that a production store retains bytes, that a shipped image
behaves correctly, or that a customer deployment captures its intended
boundary. This spec defines the evidence needed for
`critical_enterprise_go` in [spec 037](037-bounded-enterprise-deployment-and-controls.md).
It does not authorize a production deployment or a compliance claim.

Fabric OSS remains a customer-controlled passive recorder. The destination,
KMS, IAM, retention, legal hold, backup, SIEM review, evaluation and final
acceptance remain customer responsibilities; no SingleAxis service is
mandatory.

## 1. Protected storage and retention profile

Qualify **three distinct stores/paths**: (A) source content spool,
(B) governed content objects/manifests, and (C) Node telemetry queue and
customer destination. They must not share a vague `durable` label. The
source spool's fsync acknowledgment, Node queue acceptance, OTLP
destination acceptance and destination durable-persistence receipt are
different stages with different issuers.

| Control | Required qualification evidence |
| --- | --- |
| Tenant and workload isolation | IAM/workload-identity policy export; two-tenant read/write/overwrite/side-channel denial; no tenant chosen solely by untrusted OTLP attribute |
| Encryption and keys | TLS/mTLS path test, customer KMS/encryption settings, key rotation/revocation and failure behavior; distinguish queue/spool/object encryption |
| Reference safety | Credential-free opaque refs; resolver allowlists store/namespace and rejects userinfo, signed URLs, traversal, symlinks and unapproved hosts; no SSRF from telemetry-supplied URI |
| Byte integrity | Store/retrieve exact binary/text bytes, size and SHA-256; corrupt existing object, descriptor and manifest tests; no claim that a matching digest proves capture completeness |
| Atomicity and revision | Atomic object write, immutable stored object identity, serialized monotonic manifest revisions, recovery after torn/crashed write; no cross-store atomicity claim |
| Spool security | Restricted owner/mode, encrypted disk if required, quotas, crash recovery, quarantine of corrupt entries, bounded cleanup and diagnostics without raw bytes |
| Retention and deletion | Signed per-class schedule for metadata/content/spools/backups; lifecycle/version/object-lock settings, deletion/tombstone behavior, legal-hold exception, restore and expiry tests |
| Availability and capacity | Measured peak/burst data volume, minimum capacity for maximum approved outage, replication/backup, restore RPO/RTO, disk-full and quota alarms |
| Access and review | Authorized resolver audit log, least-privilege roles, break-glass procedure, periodic access review, incident export and customer SIEM review |
| Residency and privacy | Region/replica/backup inventory, approved data classes and content roles, DPA/BAA and transfer mechanism where applicable; redaction and minimization tests |

No fixed retention duration is asserted by this spec: legal and contractual
requirements can conflict. The customer records the effective schedule and
its legal basis, tests expiry and hold behavior, and documents exceptions.
Metadata-only defaults minimize exposure; broad raw capture is not
automatically safer for audit. Production S3-compatible delivery requires
a live target-environment gate, not only a mocked adapter test. An
unavailable or expired object resolves `missing`/the appropriate
resolution status, never `available` or an empty value.

GDPR's [data minimization, storage limitation and security principles](https://eur-lex.europa.eu/eli/reg/2016/679)
and NIST's [audit storage/protection/retention control family](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
are candidate inputs to the customer schedule, not universal Fabric
retention defaults.

## 2. Exact-artifact release gate

Build once from a clean, reviewed, tagged commit. The gate records a
machine-verifiable bundle with commit SHA, tag, source tree state, SDK
wheel/sdist and npm tarball digests, Fabric Node and any host-emitter
image digests, chart package/digest, CLI digest, contract versions/pins,
SBOMs, provenance/signatures, vulnerability/license reports, workflow
run IDs, and rendered customer profile/config digest. A dirty worktree,
mutable image tag, missing required workflow, unsigned required artifact,
or mismatch between tested and installed digest is `NO_GO`.

Tests execute against **installed artifacts**, not imports from the source
tree or a locally rebuilt untagged image:

1. Verify package/image/chart contents contain recorder-only capture,
   protection and delivery; no judge, red-team, enforcement, management
   or private platform module is installed or advertised.
2. Run SDK/adapter/contract suites for the exact language/runtime and
   connector versions in the scope. Use real binary-content fixtures,
   partial streams, direct bypasses and loss faults from spec 038.
3. Deploy the exact pinned Node image and chart in a disposable
   Kubernetes environment with production-equivalent ingress identity,
   egress authorization, NetworkPolicy, encrypted persistent queue and
   customer-like destination. Test a forbidden canary through OTLP,
   queue and logs; it must not cross the protection boundary.
4. Interrupt destination, source, Node and content store in turn;
   prove recovery, stable dedupe IDs, source gap accounting and receipt
   stage separation. OTLP HTTP success alone cannot satisfy the durable
   receipt gate.
5. Exercise certificate expiry/rotation/revocation, invalid token,
   cross-tenant ref, storage corruption, disk full, queue overflow,
   rollback and restore against the shipped artifacts.
6. Have an independent reviewer reproduce the artifact identity and
   inspect failure logs, not just a CI green summary.

The local `shadow-production` chart validates some configuration
invariants today, but it does not establish target-cluster NetworkPolicy
enforcement, customer IAM/KMS, destination retention or source coverage.
The current AEEP schemas are draft and are intentionally **not shipped**
as an implemented recorder-v1 runtime capability. Full qualification
also requires the release workflow and live E2E jobs for the **same SHA**.

## 3. Customer shadow pilot

The pilot runs passive capture beside an existing bounded workload. Start
with synthetic/non-sensitive fixtures; customer security/privacy approval
is required before actual regulated data. The pilot must not change agent
responses, tool authorization, latency-critical path or side effects.
Customer controls define the environment boundary; Fabric records or
honestly reports gaps.

Before starting, freeze the spec-037 scope and a test plan that names:
run IDs, scenario seeds, expected operations and content roles, concurrency
and rate, injected faults, source truth systems, privacy canaries,
capacity/outage objectives, retention schedule, pass thresholds, and
reviewers. Use at least one model→tool→model flow, one direct terminal
and binary-artifact flow, and each reachable remote/DB/network/sandbox
route. Include both a successful run and runs with redacted, unsupported,
truncated, failed, and lost items.

Independent truth is collected **outside the same capture path**:

| Claimed surface | Independent comparison source |
| --- | --- |
| Provider-bound request/response | Controlled provider endpoint or provider-side request record with approved payload access |
| Tool/terminal/PTY | Fixture harness streams plus host process audit |
| Files and artifacts | Pre/post filesystem/object-store inventory and byte hashes |
| Sandbox/Kubernetes | Runtime process/network inventory and Kubernetes audit IDs |
| SSH/remote | Authenticated remote execution/audit record and remote artifact snapshot |
| Database | DB server audit/CDC, transaction outcome and final test-table state |
| HTTP/cloud/messaging | Fixture server/service audit and side-effect receipt |
| Delivery | Source spool and Node queue stats plus customer destination durable receipt |

Compare identities, **specific operation sets**, ordered per-source
sequences, attempt links, bytes/digests, statuses and side-effect receipts;
matching aggregate counts alone is insufficient. Reconcile every required
event against independent truth and every required content ref through an
authorized resolver. Document out-of-scope actions and unexpected routes.
For concurrent operations, compare the causal graph rather than
timestamp-sorting to manufacture an order.

The pilot MUST produce a reproducible discrepancy report:
`expected / captured / matched / missing / extra / duplicate / corrupted /
redacted / unsupported / unverified`, by connector, boundary, role and
run. Store source-truth exports, capture records, qualification config,
content digests, receipts, canary results and reviewer decisions in
customer-controlled evidence storage. Exports shared outside the customer
boundary remain metadata-only unless separately authorized.

## 4. Pilot acceptance and stop conditions

The pre-registered minimum for a **complete-for-declared-scope** pilot is:

- all required sources authenticated, healthy, sequenced and reconciled;
  every required role present, stored, byte-verified and durably receipted;
- zero unexplained mismatches, silent drops, cross-tenant accesses,
  forbidden-content leaks or untested bypasses in the declared scope;
- every injected known loss, unsupported role and unavailable source
  correctly lowers the run verdict rather than appearing complete;
- all target-environment storage, retention, backup/restore, key rotation,
  alerting and incident drills pass their pre-registered objectives; and
- the exact installed artifacts and signed scope/control matrix are
  reviewed by customer security, privacy, records, platform and AI owners.

Any missing independent feed, unresolved privacy issue, loss hidden by
the recorder, failed release gate, or material scope drift is immediate
`NO_GO` for critical-enterprise promotion. A partial or unverified run may
be retained as valuable evidence, but it is not a complete-run proof.
Published coverage claims must name the boundary, versions, sample size,
test duration, observed discrepancies and residual blind spots. Finite
pilot success does not prove universal capture or legal compliance.

## 5. Handoff artifacts and status

Deliver a signed scope/control matrix, connector coverage matrix, exact
release bundle, storage/retention qualification report, loss-test report,
shadow-pilot reconciliation dataset and reviewer go/no-go record. Archive
the evidence under customer retention policy. Repeat qualification after
scope, connector, model-provider, kernel, runtime, store, chart or
destination change that can affect observation or delivery.

As of this draft, these artifacts and a live customer pilot do not exist;
the repo's local tests and schema fixtures are insufficient for this gate.
