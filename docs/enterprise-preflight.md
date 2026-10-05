# Deployment preflight and bounded integration coverage

Fabric is a passive **Capture → Protect → Deliver** data plane. This optional
preflight checks configuration, reports unsupported scope, and runs a local
fixture when requested. It does not block monitored calls, install a control
runtime, or approve a production deployment.

## What the verdict means

- `LOCAL_READY`: the declared scope is within the current verifier's limits,
  required local capability is available, and the explicitly selected filesystem
  probe and routed fixture passed. This is fixture readiness only
- `NO_GO`: required evidence is missing, a required capability failed, declared
  scope is unsupported, known capture loss exists, or the profile is production
- `PASS`, `FAIL`, and `UNKNOWN` are separate per-check states. Absent evidence is
  never treated as a healthy zero or silently removed from the report

**Production is always `NO_GO` in this version.** Real deployment gates remain
`UNKNOWN`: actual image identity, TLS, encryption, region, retention, tenant IAM,
source identity, independently inventoried route closure, authoritative outcomes,
four-stage delivery, and qualified issuers. This tool has no live adapters to
establish those facts. A valid policy, a passing local fixture, or an authentic
signed statement cannot promote them to verified.

## Run the installed entrypoint

Use the installed wheel so the command tests the artifact you intend to use:

```sh
python -m fabric.enterprise_preflight \
  --policy policy.json \
  --scope scope.json \
  --filesystem-root /absolute/customer-selected-test-directory \
  --run-canary \
  --output preflight-report.json
```

The repository wrapper `scripts/qualification/enterprise_preflight.py` calls
this same installed entrypoint. It does not add the checkout to `sys.path`.
Exit codes are `0` for `LOCAL_READY`, `2` for `NO_GO`, and `1` for invalid or
unreadable inputs. Omitting `--output` prints the report. No credentials or
exception bodies are written to the report.

The filesystem directory must already exist. The probe creates a private
randomly named temporary directory, writes synthetic random bytes, fsyncs the
file and its directory, reads the bytes back, and removes its own temporary
files. This establishes only that those syscalls and readback succeeded there
at that instant. It does not establish power-loss behavior, cloud encryption,
KMS policy, or retention. The canary also uses a private temporary directory
under this root and an ephemeral loopback HTTP port. It makes no provider calls.

Example local policy, parsed by the shared strict `DeploymentPolicy` schema:

```json
{
  "schema_version": "fabric.deployment-policy/v1",
  "policy_id": "evaluation",
  "policy_version": 1,
  "tenant_id": "tenant",
  "workload_id": "local-evaluation",
  "privacy": {
    "tool.call.arguments": "omit",
    "tool.call.result": "omit"
  },
  "storage": {"backend": "local", "region": "local", "key_id": "local-key"},
  "retention": {"days": 1},
  "required_integrations": ["fabric.call_recorder"],
  "deployment": {
    "profile": "local",
    "image_digest": "local",
    "tls_required": false,
    "encrypted_store_required": false
  }
}
```

Production policy parsing requires a lowercase `sha256:` image digest and
both TLS/encrypted-store requirement flags set to `true`. Setting those flags
states requirements; it does not verify the requirements were realized. Unknown
fields, duplicate JSON keys at the CLI, wrong types, and unsupported values fail
closed. The policy digest binds normalized policy content and is included in
the report and external-attestation subject.

Example `scope.json`:

```json
{
  "source_ids": ["source-one"],
  "source_epochs": [0],
  "expected_max_records": 4096,
  "expected_max_object_bytes": 16777216
}
```

For a runnable repository fixture, use `examples/enterprise/policy.local.json`
with `examples/enterprise/scope.local.json`. Create the filesystem probe directory
first and pass its absolute path. Successful fixture checks with that declared
scope can return `LOCAL_READY`; unknown target snapshot/OTel loss inputs remain
visible and do not become evidence of target-run completeness. Without a scope
file, scope and capacity remain `UNKNOWN` and the verdict is `NO_GO`.

This is a declared scope, not an authenticated source inventory. The current
`QualifiedRun` path supports **one source and epoch zero**. Additional sources,
recovered epochs, and distributed/background source joins are unsupported.
This preflight's qualification capacity gate keeps the existing 4,096 total
start/content/outcome record limit and 16 MiB byte-object limit. An ordinary
input/output call consumes four projected records; streams consume additional
content records. Per-list recorder capacity must not be confused with this total.
The explicit `project_call_snapshot_batches` API can project larger live snapshots
in bounded batches and preserve exact identities; it does not expand
`QualifiedRun`'s accepted scope or establish durable delivery. Outage duration,
queue saturation, and storage sizing require separate measurements.

## Installed, active, and qualified are different

The original `enable_auto_instrumentation()` tuple-returning API is unchanged.
Use `enable_auto_instrumentation_with_manifest()` for inspectable registration:

```python
from fabric.auto_instrument import enable_auto_instrumentation_with_manifest

manifest = enable_auto_instrumentation_with_manifest(
    required=["openai"],
    only=["openai"],
    expected_versions={
        "openai": {
            "instrumentor_version": "OWNER_TESTED_EXACT_VERSION",
            "target_version": "OWNER_TESTED_EXACT_VERSION"
        }
    }
)
```

Registration is explicitly opt-in. `inspect_integrations(enable=False)` is the
default read-only inventory API; preflight never installs hooks. Every required
name appears in the manifest, even when it is unsupported or unavailable.
Each row separates distribution installation, exact instrumentor and target SDK
versions, registration outcome, upstream-reported activation, and qualification:

- `ACTIVE`: explicit boundary available or upstream activation reported
- `MISSING`: package unavailable or installed hook inactive
- `FAILED`: import/registration failure, explicit no-op, or version drift
- `UNKNOWN`: unsupported integration, missing distribution version, or no
  observable activation flag

An upstream `instrument()` returning successfully does not establish activation.
Even an upstream activation flag does not prove it captured an actual request.
Rows remain `UNVERIFIED` for qualification, and required upstream integrations
cannot satisfy the separate routed-canary qualification check in this version.
An active flag from a no-op instrumentor therefore cannot yield readiness.
Optional missing integrations remain visible but do not substitute for required
capabilities. Exact version pins are string equality, not a compatibility-range
claim. Enabling capture never changes whether a monitored call may execute.

## What the local routed canary actually tests

`run_fixture_canary()` runs `CallRecorder`, `ByteEvidenceRecorder`, the local
byte store, and `SyntheticSourceSpool` against a real loopback HTTP server:

1. A normal request/response traverses the explicit recorder boundary
2. A line-delimited stream preserves delivered chunks and order
3. A retryable HTTP failure and succeeding physical retry are separately wrapped
4. A deliberate unwrapped request reaches the server and is detected as missing
5. Two requests inside a hidden retry appear as one wrapper and are detected as
   unmatched physical attempts
6. Stored fixture byte objects are read back and compared; source metadata is
   sealed, freshly read from disk, and compared with projected record identities

The expected baseline is seven server-observed physical attempts, five recorded
wrapper attempts, three missing physical attempts (direct bypass and two hidden
retry attempts), one unmatched wrapper, and 21 projected source records.
`status=PASS` means the positive and **false-complete negative controls passed**.
It deliberately also reports `full_route_coverage_complete=false`.

The server is a same-process fixture witness, not an independent production
trust authority. No production receipts are issued. It does not test arbitrary
provider protocols, TLS, real cloud storage, provider-internal reasoning, or all
reachable routes. The canary uses synthetic original fixture bytes independently
of the supplied deployment privacy policy. Its
`deployment_privacy_policy_exercised=false` is intentional; use the separate
policy/session tests to test the selected privacy modes and governed store.

## Target loss and closure evidence

Optional `--snapshot snapshot.json` inspects a real `CallRecorder.snapshot()`
after `seal_source()`. Known gaps, drops, unsettled writers, unsupported content,
incomplete calls, missing source seals, multiple source identities, recovered
history, and a projection beyond current qualification bounds fail the local
recording check. No loss reported by the local snapshot still does not prove
independent source completeness or exact original reconstruction.

Optional `--trace-health health.json` accepts a list of `Decision.capture_health`
values. Non-recording/sampled spans or dropped events/attributes fail; unavailable
counters remain `UNKNOWN`. Zero local counters do not verify exporter queues,
network delivery, Node acceptance or destination durability. Missing snapshots
or span health are explicitly `UNKNOWN`, even when the unrelated local fixture
is ready. These unknowns always prevent a production claim.

## External attestation verification

The Python API accepts `PreflightAttestation(statement, evidence, issuer_id)` per
named live gate plus separately configured `EvidenceTrustKey` values. It reuses
`fabric.evidence_attestation`'s Ed25519 authentication, revocation, time interval,
tenant/run/scope/subject bindings, and duplicate-field rejection. The subject is
`preflight_subject_bytes(policy, gate, evidence)`; its digest binds the full policy
and the exact supplied evidence bytes. It uses statement type
`independent_witness`, subject kind `evidence_set`, subject ID `preflight.<gate>`,
and the policy workload ID as the run ID.

For the CLI, `--attestations` is an object keyed by live gate, each with
`statement` and `evidence` JSON objects. Evidence JSON is canonicalized with
sorted keys, compact separators, ASCII escaping, and no non-finite numbers.
`--trust` is a separate owner-controlled file with `keys` and `gate_issuers`:

```json
{
  "keys": {
    "owner-key-id": {
      "issuer_id": "owner-qualified-issuer",
      "tenant_id": "tenant",
      "public_key": "BASE64_32_BYTE_ED25519_PUBLIC_KEY",
      "statement_types": ["independent_witness"],
      "valid_from": 0,
      "valid_until": 2000000000,
      "revoked": false
    }
  },
  "gate_issuers": {"encrypted_store": "owner-qualified-issuer"}
}
```

Never take trust keys or issuer expectations from the supplied evidence itself.
The public key is not a secret; no private signing key is generated or loaded by
preflight. Missing statements are `UNKNOWN`; a wrong key, issuer, policy, evidence
digest, signature or validity interval is `FAIL`. A valid statement yields only
`authentic_statement_only=true` and `actual_environment_verified=false`.
Fixture signers and assertions of encryption must never be promoted into live
verification. Qualifying issuers and supplying actual authoritative live gate
adapters remains a separate, deployment-specific requirement.
