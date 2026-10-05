# Capture configuration and future control compatibility

Fabric OSS remains **Capture → Protect → Deliver**. This build provides a
customer-controlled capture reference and vendor-neutral integration contracts.
It does not ship a portal, remote rollout service, action gate or enforcement
runtime. Installing or importing these modules never enables action control.

A future client SingleAxis portal can configure capture through an authenticated
service adapter. A separately deployed customer-side control runtime could use
the same stable activity identities at the final physical dispatch boundary.
Those two integrations have different authorities and failure semantics:

- Capture configuration determines what evidence may be retained and delivered.
- External action policy determines whether an application may dispatch an action.
- Capture-policy approval, a matching digest, an `allow` observation, and a delivery
  receipt are never interchangeable with an authenticated action authorization.

## Implemented configuration contracts

The Python imports are explicit optional submodules; none installs global hooks.

| Interface | Implemented behavior | Boundary |
| --- | --- | --- |
| `DeploymentPolicy`, `fabric.deployment-policy/v1` | Closed validation, immutable snapshot and canonical digest; privacy/storage/retention/integration requirements | Configuration cannot prove encryption, region, hook installation or production readiness |
| `validate_policy` | Pure dry-run validation and digest | No persistence, credential generation, rollout or dispatch |
| `CapturePolicyRegistry` | Local authenticated read/propose/approve/observe-applied; optimistic revisions; atomic durable state and bounded hash history | Single host; local administrators trusted; history is not independent signed audit anchoring |
| `IdentityBoundAuthority` / `PrincipalBinding` | Intersects a verified grant with an explicit issuer/subject/tenant/workload/role/permission binding | Customer supplies credential verification; this is not an SSO or workload-attestation service |
| `CaptureReadback` / registry `readback` | Authenticated report comparison, exact scope, digest, required capabilities and freshness | An authorized caller report, not proof of remote execution or loaded hooks |
| `sdk_capabilities` | Versioned Python/TypeScript source support declaration | Does not attest a running workload or qualification result |

### Authenticated operator and workload adapters

`PolicyAuthority.authorize` is the verification seam. An implementation must
validate credentials and authorization on every call, including issuer,
audience, expiry, revocation and exact tenant/workload/policy scope as applicable.
Never implement it by trusting telemetry attributes or an unsigned subject label.

The existing `LocalCapabilityAuthority` is a real HMAC bearer-grant verifier for
a trusted local administrator; it does not provide federated SSO, audience-bound
service tokens, hardware identity or cloud IAM. `IdentityBoundAuthority` can wrap
it or a customer-supplied verifying authority. Bindings are trusted local
configuration and cannot be supplied by the report being authorized. Unknown,
wrong-issuer, wrong-subject, cross-tenant, cross-workload or insufficient grants
fail before any configuration operation. Returned identity metadata is closed;
unknown claims and credential material are not forwarded.

This adapter implements the configuration `PolicyAuthority` interface.
`GovernedLocalContentStore` still uses its existing `LocalCapabilityAuthority`
interface for envelope signing and store operations; the configuration wrapper
is not a drop-in replacement for that store's authority object.

- Workloads may receive explicitly selected data read/write, `policy_read`, and
  `policy_observe` permissions. They cannot receive `policy_admin`, lifecycle or
  audit authority through this adapter.
- Operators can receive explicitly selected permissions, including `policy_admin`.
  Being an operator alone does not grant any operation.
- `policy_observe` reports configuration readback. It does not approve or apply
  policy. An observer must use a fresh grant bound to the current desired policy
  even when reporting that its loaded policy is old.
- Transport authentication, principal provisioning, key custody, revocation and
  support-access workflows remain the deployment owner's responsibilities.

### Desired, approved, applied and observed

`read` returns the versioned persisted state plus `configuration_lifecycle`:
`desired`, `approved`, or `applied_observed`. A proposal must increase the version
and preserve tenant/workload/policy identity. It clears approval and preserves the
older applied observation. Approval binds the exact desired digest.
`observe_applied` requires the approved desired digest and an operator grant; it
is explicitly an authorized caller report. It does not install configuration.
The existing `drift` field compares the stored desired/applied digests.

`readback(reader_capability, observation=CaptureReadback(...),
observer_capability=..., max_age_seconds=300)` is a separate read-only assessment:

- The reader requires `policy_read`; the reporter independently requires
  `policy_observe`. Both grants are checked against the same locked revision.
- Reported tenant/workload must match. `source_id` is correlation metadata, not
  independent source attestation. The returned reporter is the authenticated
  principal, separately from that source label.
- The report includes its loaded digest, capability inventory and epoch-seconds
  observation time. `None` means unobserved; an empty inventory means observed empty.
- Old/future readback or missing digest/inventory yields `status=unknown` and
  `drift=null`, never healthy. Fresh mismatches, missing required integrations or
  an unapproved desired policy yield `status=drifted`. A fresh approved match yields
  `status=matched`, while `runtime_attestation=unverified` remains explicit.
- Matching readback does not write state, advance revisions, approve policy or
  turn an absent applied observation into a rollout. Assessment results contain
  desired, approved, stored applied and freshly reported digests separately.

No JSON report constitutes proof that customer transforms, keys, storage,
network controls or hooks are effective. Validate those boundaries independently.

## Optional final-boundary exchange contract

`fabric.control_protocol` contains immutable metadata structures and the
`ExternalFinalBoundaryController` Python Protocol. It has **no implementation,
network client, callback installation, dispatch function or action gate**. No
recorder code calls the protocol. An external runtime must be explicitly selected,
installed, authorized and integrated by the customer before any action-control
semantics exist.

The v1 exchange reserves the following correlation:

1. `FinalBoundaryRequest` binds a unique request to tenant/workload, run, recorded
   decision, logical action, physical attempt, final boundary, expected controller,
   external policy identity/version/digest, reviewed artifact digest and expiry.
   Its canonical digest binds every field. IDs are bounded and opaque; the
   contract has no URL, credential, prompt or argument payload field.
2. `ExternalControlReply` binds the request ID and digest to the existing
   `ControlObservation`. The observation separately binds action, controller,
   policy and reviewed artifact. A proof reference remains an opaque lookup key.
3. `BoundaryOutcomeObservation` binds actual outcome to that same request digest.
   An observed success following a reported deny is preserved as evidence; the
   recorder cannot prevent or rewrite it.
4. `correlate_external_exchange` rejects mismatched metadata and reports expiry.
   Even a matched, unexpired `allow` sets `authorizes_execution=false`,
   `authentication=unverified_caller_report` and
   `enforcement_performed_by_fabric=false`.

A future external runtime must independently authenticate the controller and
policy, authorize the requested action, enforce expiry and single-use/replay
protection, reconcile reviewed versus actual dispatch bytes, and observe final
outcome. Every physical retry needs a new request/attempt identity. Hash matching
alone is not authentication, authorization or proof of non-bypass. A reviewed
redacted derivative must not be advertised as proof of identical original dispatch
bytes. Digests can themselves reveal equality; callers must apply their privacy
policy before emitting correlation metadata.

The controller's failure/timeout/approval semantics belong to that separate
runtime. Fabric's passive evidence failures must continue preserving application
results, exceptions and cancellation. There is deliberately no recorder setting
that silently changes passive capture into blocking execution.

## Verification and support

See [SDK support matrix](sdk-support-matrix.md) for the exact Python/TypeScript
boundary. The focused tests are `test_capture_identity.py`,
`test_capture_readback.py`, `test_capture_capabilities.py`,
`test_control_protocol.py`, `test_deployment_state.py` and
`test_control_evidence.py`. They exercise authenticated role separation,
cross-scope/revision denial, unknown/stale readback, all final-boundary bindings,
retry mismatch, deny-followed-by-success and the absence of execution permission.
They are local contract tests, not portal or production-control qualification.
