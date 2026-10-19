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
boundary. The focused tests are `test_deployment_policy.py`,
`test_control_protocol.py` and `test_control_evidence.py`. They exercise closed
policy validation, all final-boundary bindings, retry mismatch,
deny-followed-by-success and the absence of execution permission. They are
local contract tests, not portal or production-control qualification.
