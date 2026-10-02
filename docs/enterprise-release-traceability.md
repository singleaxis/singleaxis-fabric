# Enterprise capture testing release: traceability

Base: `dd7e2683dd0db62aada5ff720ff53c7b272b66a6`. This source bundle includes the earlier review fixes and the optional enterprise capture testing slice. It is a local test release, not a published release, deployment, compliance certification, or proof of universal capture. No push, PR, merge, customer provisioning or paid model call is part of this delivery.

**Verdict:** scoped local fixtures can be READY. Production remains **NO_GO**. “Implemented” below refers to the stated local behavior, never all customer infrastructure. The Python/TypeScript capture path remains passive: evidence failures withhold evidence and preserve the monitored delegate's result/exception. Synchronous capture and redaction still consume time and must be bounded.

## 1. Versioned capture configuration and approval — implemented locally; external rollout

Strict `DeploymentPolicy` and `contracts/deployment-policy/v1` bind tenant/workload, revision, privacy roles, storage requirements, retention and required integrations. Unknown/invalid fields fail validation. `CapturePolicyRegistry` supplies authenticated dry-run/read/propose/approve/observe-applied, optimistic revisions, exact desired-digest approval, desired/applied drift and bounded local history. This is an optional local capture-configuration adapter, not action authorization or a fleet service. Applied capability readback is a caller report. SSO, service transport, portal UI and verified remote rollout remain external.

Evidence: `test_deployment_policy.py`, `test_deployment_state.py`, TypeScript `deployment-policy.test.ts`.

## 2. Per-content privacy before queue admission — implemented at explicit byte boundaries; partial ecosystem coverage

Python and TypeScript `ByteEvidenceRecorder` apply metadata-only, omit, customer-redact, scoped HMAC tokenization and retain-original policy before their byte queue. `PolicyCaptureSession` wires Python CallRecorder to protected stores and a source journal. Original and derivative planes stay separate; redaction failures never fall back to raw bytes. These are governed bytes supplied to Fabric, not automatic interception of every prompt, error, file, provider log or instrumentor. Redactor correctness and effective final-request adapters remain customer responsibilities. Whole-object irreversible HMAC is not a token vault.

Evidence: byte-evidence/content-boundary/deployment-policy tests, `test_enterprise_integration.py`.

## 3. Explicit missing, transformed, sampled and lost states — implemented locally; partial end-to-end accounting

Descriptors distinguish metadata-only, omitted, redacted, tokenized and original content. Byte failures/capacity and call gaps remain visible. Python/TS decision capture-health reports sampled/nonrecording spans, native dropped counters and unknown counters. The Go protection processor adds removed events/links to native counters with saturation. Unknown is never promoted to complete. Exporter/destination loss and unobserved routes need independent receipts and route closure.

Evidence: capture-health tests, call recorder and byte tests, Go `traces_test.go`.

## 4. Governed storage and isolation — implemented local AES-GCM/readback; external cloud qualification

`GovernedLocalContentStore` implements authenticated tenant/workload/policy/plane-bound operations, separate original/derivative namespaces, AES-256-GCM payload encryption, authenticated envelopes, exact readback and safe POSIX paths. Actual encryption status is distinguished from configured intent. Local OS/process owners and the local authority key are trusted. Region and KMS labels are not location or custody proof. Real cloud IAM, KMS, region, cross-host isolation and destination receipts remain external; ordinary S3 adapter availability does not qualify those gates.

Evidence: `test_governed_store.py`, governed local storage documentation and enterprise local runner.

## 5. Retention, deletion and legal holds — implemented current local objects; partial full lifecycle

Authorized holds prevent delete/expiry purge; explicit purge creates minimal signed tombstones and blocks object resurrection. Derivatives have their own plane and lifecycle permissions. This removes the adapter's current accessible payload, not disk remnants, in-flight application bytes, every queue/index/export, backup or snapshot. No automatic purge scheduler, coordinated all-copy erasure, key destruction or backup restore anti-rollback is supplied. Customers must design retention for audit/tombstones and qualify all copies.

Evidence: governed-store lifecycle/tamper/expiry tests and `docs/governed-local-storage.md`.

## 6. Identity, least privilege and support access — implemented local capabilities; external identity infrastructure

Short-lived signed grants bind tenant/workload/exact policy/subject/permission/expiry. Original and derivative write/read, lifecycle, audit and policy administration are distinct. Wrong tenant/workload/policy, expired grants and invalid signatures fail. Subject identity is a local administrator assertion; no IdP/workload attestation, emergency access workflow, revocation service, production support boundary or managed key rotation is implemented.

Evidence: capability and registry authorization tests.

## 7. Authenticated audit and artifact-bound reviews — implemented local capture audit; partial action evidence

Local reads and mutations record bounded signed hash-linked audit history, with fsynced intent/completion around mutation. Capture approval binds the exact desired policy digest. `ControlObservation` records separately labelled external policy/artifact/decision/issuer/proof-reference metadata; it is explicitly unverified and never authorizes actions. External review proof verification, customer key-management audit, comprehensive exports and rollback-resistant independent audit anchoring remain external.

Evidence: `test_control_evidence.py`, policy-registry and governed-store audit tests.

## 8. Secure deployment configuration — implemented validation; external runtime assurance

The Helm shadow-production profile requires full image digests, explicit workload/evidence binding, TLS/auth, encryption-attestation references and network boundaries. Compose is a technical overlay that still requires additional identity, immutable-image and storage qualification. These checks and chart renders do not establish live TLS rejection, image-signature verification, real secrets custody, encrypted volumes or successful delivery. Docker/kind/customer cluster tests, runtime signature verification and production credentials are not supplied by rendering.

Evidence: chart shell tests, `scripts/tests/test_enterprise_deployment.py`, documented production gates.

## 9. Coverage inventory and actual canaries — implemented bounded inventory/fixture; partial adapters

Required/missing/failed/unknown integration state and versions are inspectable. A real loopback HTTP fixture tests routed attempts and deliberate hidden retry/bypass mismatch. Installation alone is not active-hook proof. The preflight canary is separate from selected deployment privacy testing, as its report states. Each real provider/tool/runtime route and version still needs qualified adapters and independent witnesses. Internal model reasoning is outside scope.

Evidence: coverage-manifest/preflight tests and orchestration report.

## 10. Durability, restart, background work and outcomes — partial

Existing source journal seals/recovery, explicit gaps, bounded export batches and exact-set manifests are exercised. The sample joins background work, records explicit physical retries, compares fixture-side HTTP truth, checks file/SQLite/subprocess effects, and reopens journal history. Restart/recovered epochs and multiple sources remain unqualified for complete coverage. OTLP acceptance is not destination durability, local journal readback is not a remote receipt, and a tool return is not universal external transaction/CDC proof. Pre-fsync crashes, disk-full/power-loss, distributed closure and authenticated independent destination receipts remain external qualification.

Evidence: source-spool/qualified-run/call-batches tests, orchestration scenarios.

## 11. Failure behavior and action-control boundary — implemented passive behavior

Invalid setup is rejected before monitoring. Runtime evidence errors are bounded/visible and do not replace monitored results, exceptions or cancellations. Missing redactors/failed protection never admit raw fallback. Fabric does not implement a blocking action mode or convert capture-policy approval into tool permission. An independently authorized action-control runtime, if desired, is a separate system. Python local authenticated store operations themselves fail closed; that does not imply gating the observed application.

Evidence: byte/call recorder and enterprise integration failure tests.

## 12. Repeatable qualification and evidence pack — implemented local regression pack; external production campaign

The source, cumulative patch, quickstart and evidence logs make the local privacy, authorization, tenant, retry, stream, bypass, hold/delete, schema and package checks reproducible. The sample's planner is a deterministic HTTP fixture, with a provider-adapter extension point documented, not an implemented or qualified live provider connector; no credentials or paid calls were used. Local restart testing is not disaster recovery. Live cloud/SSO/KMS/TLS, native BPF, restore/rollback, disk exhaustion, prolonged outage, throughput/latency budgets and air-gap dependency supply remain explicit customer gates. No load or performance qualification is claimed.

## Architecture boundary and next deployment decision

This is CAPTURE → PROTECT → DELIVER. Optional local capture policy approval/configuration interfaces are isolated modules and are not installed as an enterprise fleet/approval service. No evaluator, judge, proprietary regulatory pack or action-enforcement engine is added. Start with one named Python dispatch boundary and the supplied fixture; then select actual runtime/provider versions, independent witnesses, stores and the customer's qualification owner before promoting any production readiness claim.
