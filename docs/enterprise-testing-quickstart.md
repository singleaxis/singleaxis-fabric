# Enterprise testing slice: start here

This local test release implements configurable **CAPTURE → PROTECT → DELIVER**
primitives. Fabric remains passive. It is not an action-policy engine, client
portal, production deployment, universal agent recorder or compliance certification.
The production verdict remains **NO_GO** until customer infrastructure is qualified.

For implementation conventions, see [agent developer best practices](agent-developer-best-practices.md).

## Choose the smallest useful integration

For an existing codebase, start with the context it already emits. If its
framework or application already produces useful OpenTelemetry traces, route
those supported spans to Fabric Node using the
[existing integration models](integration-models.md). The SDK is not the only
source of application meaning. Imported spans still need identity, privacy and
coverage checks; they are not independent proof that every action was observed.

If you need exact model/tool bytes and physical retry identity, add the shared
final-dispatch wrapper below. This is one startup change and one common dispatch
change, plus context at background handoff points. You do not need to rewrite the
framework or instrument every helper. Existing tracing and the wrapper can
coexist; avoid double-wrapping a single physical attempt.

Additional evidence is chosen for the claims you need, not three mandatory
application integrations:

- Application/framework spans or SDK boundaries describe model/tool semantics,
  causal links and permitted payloads at the boundaries they actually observe.
- Optional host sensors can be deployed centrally to observe process/network
  metadata and help discover bypasses. They do not automatically recover
  application meaning or plaintext behind TLS. This local build has not
  qualified a live host/BPF sensor; missing host evidence stays unknown.
- For an important committed effect, read back the affected database, file,
  service or selected destination using an independent authority. An SDK call
  returning, a host socket event or Node acceptance alone does not prove that
  effect committed. Target those checks at the effects/destinations that matter.

The larger `examples/enterprise-reference/run.py` campaign exercises stronger
local durability, receipt and closure claims. It is a reference qualification
exercise, not an extra integration requirement for every application. Neither
that campaign nor the small onboarding demo establishes universal coverage.

## 1. Install the local source

Python 3.11+ on a POSIX filesystem is required for the governed store/source
journal. Python 3.12 is used in the included results. From the source-bundle root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install './sdk/python[signing,otlp]'
python examples/enterprise-reference/integrate.py --output ./integration-demo
python -m fabric.enterprise_preflight \
  --policy examples/enterprise-reference/policy.integration.json \
  --scope ./integration-demo/scope.json \
  --snapshot ./integration-demo/snapshot.json \
  --run-canary --filesystem-root "$(pwd)/integration-demo" \
  --output ./integration-demo/preflight.json
python -c 'import json; p=json.load(open("integration-demo/preflight.json")); print(p["verdict"], p["production_verdict"])'
```

The first command runs two real loopback HTTP requests through one shared
model/tool dispatch wrapper and propagates a parent call into a background thread.
It checks encrypted byte delivery to a local governed store, metadata journaling,
independent receiver reconciliation and bounded shutdown. The printed integration
result should be `local_integration_passed: true`. The doctor/preflight should
report `LOCAL_READY NO_GO`: local checks passed, production remains unqualified.
Any exit code `2` means inspect the report's failed or unknown checks before
continuing. The demo does not configure a remote exporter or destination receipts.

Its explicitly named synthetic policy retains only the generated demo inputs.
Choose your application's privacy policy before passing real content. Demo keys
are ephemeral: the encrypted example output is **not restart-recoverable after
exit**. Production applications must provide stable managed keys, grant refresh,
retention and a destination. Existing encrypted data must not be reopened with
new random keys.

### Application changes: two touch points plus background context

Use the working `initialize_capture` and `AppCapture.dispatch` helpers in
[`integrate.py`](../examples/enterprise-reference/integrate.py) as the reference:

1. At application startup, call `initialize_capture` once with the validated
   policy, private storage path, customer-managed authority/storage/spool keys,
   run/source/agent IDs and the application's OTel tracer. It constructs
   `PolicyCaptureSession(durable_spool=...)`; no global hooks are installed.
2. At the existing shared model/tool dispatcher, replace the final
   `send(payload)` call with `capture.dispatch(payload, send, kind=...,
   operation_id=..., attempt_id=...)`. `payload` must be the actual serialized
   bytes and the delegate must return the exact response bytes to capture them.
   Other return objects are preserved but marked unsupported for byte evidence.
   Each physical retry must pass through that boundary with a new attempt ID;
   an SDK's hidden retry does not become visible just because its outer call is wrapped.
3. Before submitting background work, read
   `capture.session.calls.current_call_id` and pass it as `parent_call_id` to the
   child's wrapper. The runnable example does this across a thread and joins it.
   For a different process, carry run/source/parent context through your existing
   queue and initialize its own recorder. Context propagation alone is not
   authenticated source registration or distributed closure.
4. Stop accepting new work, join background work, and call `capture.close()` on
   shutdown. A false result is unresolved evidence, not successful delivery.
   The helper leaves the store open while its writer is unsettled.

For async/streaming dispatch use the existing public
`session.calls.acall`, `stream` or `astream` method at that same boundary; close
partially consumed streams explicitly. The small runnable helper deliberately
shows the synchronous bytes contract, rather than claiming an arbitrary provider
SDK or framework is hooked automatically. It rejects redact/tokenize policies
until you explicitly configure transforms and derivative storage.

`integration-report.json` records installed integration support, observed HTTP
coverage, byte and journal health, background correlation and shutdown. A static
installed integration row does not prove real traffic routing. The preflight
canary exercises its own synthetic route; neither check qualifies undeclared
routes or target production infrastructure.

Additional regression fixtures:

```sh
python scripts/qualification/run_enterprise_local.py --output ./enterprise-local-evidence
python examples/enterprise-orchestration/run.py --scenario clean --output ./orchestration-clean
python examples/enterprise-orchestration/run.py --scenario gaps --output ./orchestration-gaps
```

Dependency installation uses the package registry and requires network access;
this is not an offline dependency bundle. No Docker, provider key, SaaS account,
paid cloud resource, real personal data or external model call is needed for
these local examples. Choose a new output directory for every run.

The additional local runner checks actual AES-GCM content writes/readback, five privacy
modes, separate derivative storage, authenticated operations, legal hold/deletion,
approved capture configuration, stale revisions and sanitized batch projection.
The orchestration runner exercises real local HTTP, file,
SQLite and subprocess effects. Its deterministic planning endpoint is a fixture,
not an LLM. The clean scenario checks matched HTTP fixture routes and a completed
stream. The gaps scenario deliberately introduces a bypass and partial stream
and restarts the journal: those conditions must prevent a complete-coverage
verdict. Even a clean scenario is not complete source/destination qualification.

Fixture keys are generated only in memory and are not saved. Encrypted fixture
objects cannot be reopened after process exit. Reports/policy/audit metadata are
reviewable; synthetic application effects exist in the orchestration output.
Delete only those output directories when no longer needed. This does not claim
secure disk erasure or deletion of exported copies/backups.

## 2. Choose deployment capture policy

A strict versioned JSON schema lives at
`contracts/deployment-policy/v1/schema/deployment-policy-v1.schema.json`; start
with `examples/enterprise/policy.local.json`. It binds tenant, workload, revision,
per-role privacy, store/region/key references, retention, required integrations
and deployment declarations. Unknown fields and invalid production declarations
are rejected. Configured region/key/TLS requirements are intent, not evidence.

- `metadata_only`: no payload; bounded permitted metadata only
- `omit`: no payload, original length or original digest
- `redact`: explicit customer transform before queue admission; derivative only
- `tokenize`: scoped irreversible whole-object HMAC; no token-vault/reversal claim
- `retain_original`: exact caller-supplied bytes in a separately authorized store

The supplied `policy.local.json` retains no original content; the default
orchestration fixture deliberately uses mixed modes including original retention
to test the store. Choose retention and purposes for your deployment; sample
durations are not legal advice. The sample redactor only
replaces its synthetic canary. Production redactors require customer-specific
validation and are synchronous: keep them bounded and nonblocking. Privacy
errors withhold/fail evidence, never silently fall back to raw originals.

Use `--policy FILE.json` on the orchestration runner to try your policy. Omit
`storage.root` in that file; the sample binds an isolated directory under its
output. No policy grants permissions to perform tool actions.

## 3. Integrate an application

```python
from fabric.deployment_policy import DeploymentPolicy
from fabric.enterprise import PolicyCaptureSession

policy = DeploymentPolicy.from_dict(configuration)
session = PolicyCaptureSession(
    policy=policy,
    store=authenticated_original_store,
    derivative_store=authenticated_derivative_store,
    redactors=approved_role_redactors,
    tokenization_key=customer_managed_token_key,
    run_id="run-001", source_id="python-dispatch", agent_id="agent-001",
)
result = session.calls.call(final_request_bytes, actual_tool_dispatch,
                            operation_id="tool-001", attempt_id="attempt-001")
report = session.report()
session.close()
```

This is an integration pattern, not a runnable credential initializer. The
working examples show local fixtures. Call wrapping observes only explicitly
wrapped final boundaries. Instrument each physical retry. Async methods and
pull-through streams preserve results, exceptions and cancellation. Threads,
processes and remote workers need explicit propagation/qualified adapters.

`GovernedLocalContentStore` plugs into the existing byte store protocol. Each
operation verifies a short-lived tenant/workload/policy-bound capability.
Writer, reader, lifecycle and policy-admin permissions are separate. Local HMAC
authority is a real local authorization implementation, not production SSO/IAM;
process/host owners who possess its key remain trusted. Real AES-256-GCM encrypts
local payloads when supplied a customer key; metadata/journal are minimized but
not encrypted by this class. See `governed-local-storage.md` for exact limits.

Protection is wired into Python and TypeScript **ByteEvidenceRecorder** before
its queue. It does not intercept arbitrary ordinary OTel exporters, diagnostics,
application logs, provider instrumentors, or bytes never supplied to Fabric.
Those routes need Node protection and deployment/privacy canaries. Python's
CallRecorder, journal, governed backend and qualification session do not yet have
TypeScript feature parity; TS supports the shared policy/protection byte path.

## 4. Portal-ready configuration interfaces

`fabric.deployment_state.validate_policy` is a pure dry-run.
`CapturePolicyRegistry` provides authenticated local `read`, `propose`, `approve`
and `observe_applied` operations, exact optimistic revisions and an audit history.
Policy approval binds the exact desired digest; changes clear that approval.
Applied capability readback is explicitly an authorized caller report, not a
verified remote rollout. Drift compares desired/applied digests. It never
installs an agent or remotely changes a workload.

A future portal can call these versioned interfaces through its own authorized
service adapter. This release does not install a web server, SSO adapter, fleet
controller or frontend. Concurrent callers must refresh after
`RevisionConflictError`. Local policy history is bounded; archival is needed
before capacity is exhausted. Local filesystem administrators are trusted; the
registry does not claim rollback-resistant external audit anchoring.

`ControlObservation` separately represents externally reported action-policy
identity, decision, reviewed artifact digest and opaque proof reference. It is
always unverified until an external verifier authenticates the proof. Capture
policy approval and recorded action-control decisions are never interchangeable.

## 5. Run honest preflight

```sh
mkdir -p ./preflight-data
python -m fabric.enterprise_preflight --policy examples/enterprise/policy.local.json \
  --scope examples/enterprise/scope.local.json --run-canary \
  --filesystem-root "$(pwd)/preflight-data" --output ./preflight-report.json
```

This command can return fixture-scoped `LOCAL_READY`, while its production verdict
remains `NO_GO`. The supplied scope is a declaration for the local fixture, not an
authenticated inventory of your application. Omitting it reports unknown scope
and capacity and exits `2` (`NO_GO`). The filesystem root must already exist and
be absolute. See `enterprise-preflight.md` for scope and trace-health inputs. Missing required
integrations, unknown sampling/loss counters and absent closure evidence are
visible. Installation does not prove active hooks; an actual loopback canary
records physical attempts and deliberately detects hidden retry/bypass gaps.
A signed statement authenticates an issuer statement, not a live TLS/KMS/IAM/
region/destination proof. Production remains NO_GO in this build.

`project_call_snapshot_batches` validates all records before returning bounded
batches, rejects cross-batch identity/sequence duplicates and preserves exact
IDs. `call_batch_manifest` binds immutable payloads/IDs for caller-managed retry;
it is not a background sender, durable cursor or destination receipt. The older
single-batch projection and qualified single-source/epoch-zero verifier keep
their explicit 4,096-record bounds. Source restart evidence remains unqualified.

## 6. Customer infrastructure gates

Helm production validation requires pinned full image digest, TLS, explicit
workload/evidence binding, storage encryption-attestation reference and network
boundaries. Rendering is configuration validation, not live qualification.
Read `deployment.md` and chart documentation before provisioning anything.
Do not promote fixture keys, example values, unknown image digests or synthetic
receipts to production. Real customer IAM/KMS/SSO, secret provisioning, TLS
negative tests, actual cloud region/retention/readback, independent source/Node/
destination receipts, runtime overhead, crash/disk-full and air-gap installation
remain deployment-specific gates. No such resources are provisioned here.

The release traceability and test report enumerate implemented, partial and
external items. Re-execution is not deterministic reconstruction and may cause
new side effects; the examples only exercise their inert local fixture effects.

## Capture/control compatibility and SDK support

The [compatibility contracts](capture-control-compatibility.md) add explicit
workload/operator authority bindings, fresh authenticated configuration readback
and an inert final-boundary external-controller exchange. Readback does not
perform rollout or approve policy; matching external decisions never authorize
execution in Fabric. The [SDK support matrix](sdk-support-matrix.md) identifies
Python-only durable/call/configuration/reference capabilities and TypeScript's
supported privacy/byte subset.
