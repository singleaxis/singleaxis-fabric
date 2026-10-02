# Historical secret-scan triage for recorder qualification

Status: **historical matches classified; production NO-GO**. Source review
identifies eight fixture matches across the two scans. On 2026-09-30 the requesting user answered
the specific provenance question about the old Basic-auth example with
“never used.” That statement closes its reported live-credential ambiguity for
this technical triage; it is not a general production security sign-off.
Do not copy the candidate values into release evidence.

On 2026-09-30, the eight entries in the locally redacted Gitleaks 8.30.1
report were checked against their exact public Git commits and source-line
context. The redacted report's SHA-256 is
`5d38580e6f94ec7ffb7e7a746e6d24f9ea8b8d6f96517c73cb3b1694b8e07556`.
No credential was sent to a provider or service. Findings below use Gitleaks'
exact fingerprint; no candidate value is reproduced.

| Fingerprint | Local source evidence | Triage |
| --- | --- | --- |
| `6e2d51504293d3643f0bee79584026d382a05695:tools/fabricctl/internal/initializer/initializer_test.go:github-pat:325` | Commit `6e2d51504293d3643f0bee79584026d382a05695`, `tools/fabricctl/internal/initializer/initializer_test.go:325`, rule `github-pat`. The match is a trivially numbered token-shaped string in the test's `rejected` input table; the same table includes other known example credential shapes. | **Source-proven test fixture.** Security owner still confirms it was never issued or reused. |
| `b52a3b1fdb51dd5172a8de92111580f5213be19f:charts/fabric/tests/fixtures/v0.6-supported-values.yaml:generic-api-key:30` | Commit `b52a3b1fdb51dd5172a8de92111580f5213be19f`, `charts/fabric/tests/fixtures/v0.6-supported-values.yaml:30`, rule `generic-api-key`. The `hmacKey` value is a 64-character hex string consisting of the same 32-character pattern twice. It is byte-identical to the five HMAC findings below. | **Predictable shared fixture**, pending owner confirmation that it was never used as a live key. |
| `250b40f60a90ccbebf57b4c3dfd3b7f4484d1e07:charts/fabric/charts/otel-collector/tests/test-traces-pipeline.sh:generic-api-key:23` | Commit `250b40f60a90ccbebf57b4c3dfd3b7f4484d1e07`, `charts/fabric/charts/otel-collector/tests/test-traces-pipeline.sh:23`, rule `generic-api-key`. Test command supplies the shared predictable HMAC fixture. | **Predictable shared fixture;** live reuse unverified. |
| `7e0806c0c62be25064721c2aa616be88ae6d9f7a:.github/workflows/ci.yml:generic-api-key:308` | Commit `7e0806c0c62be25064721c2aa616be88ae6d9f7a`, `.github/workflows/ci.yml:308`, rule `generic-api-key`. Helm lint command supplies the shared predictable HMAC fixture. | **Predictable shared fixture;** live reuse unverified. |
| `7e0806c0c62be25064721c2aa616be88ae6d9f7a:.github/workflows/ci.yml:generic-api-key:321` | Commit `7e0806c0c62be25064721c2aa616be88ae6d9f7a`, `.github/workflows/ci.yml:321`, rule `generic-api-key`. Helm template command supplies the shared predictable HMAC fixture. | **Predictable shared fixture;** live reuse unverified. |
| `519d518d280a12067ee0bea645e44ce5ec5a7a9e:.github/workflows/e2e.yml:generic-api-key:109` | Commit `519d518d280a12067ee0bea645e44ce5ec5a7a9e`, `.github/workflows/e2e.yml:109`, rule `generic-api-key`. Test deployment command supplies the shared predictable HMAC fixture. | **Predictable shared fixture;** live reuse unverified. |
| `0f4f02f82e49f88d0fc165953dff692a99090e14:components/otel-collector-fabric/processor/fabricsamplerprocessor/processor_test.go:generic-api-key:20` | Commit `0f4f02f82e49f88d0fc165953dff692a99090e14`, `components/otel-collector-fabric/processor/fabricsamplerprocessor/processor_test.go:20`, rule `generic-api-key`. Go `testKeyHex` constant is the same predictable HMAC fixture. | **Predictable shared fixture;** live reuse unverified. |
| `0f4f02f82e49f88d0fc165953dff692a99090e14:deploy/compose/.env.example:generic-api-key:12` | Commit `0f4f02f82e49f88d0fc165953dff692a99090e14`, `deploy/compose/.env.example:12`, rule `generic-api-key`. It is a commented `LANGFUSE_BASIC_AUTH` example. Source alone was ambiguous; the requesting user confirmed on 2026-09-30 that it was never used. | **Never-used example, user confirmed; not signed security acceptance.** |
| `4bf4df9665aaa107ff9c0fd0ac2ebadbf9acac5a:components/otel-collector-fabric/gate/evidence_binding_test.go:generic-api-key:12` | PR #164 CI run `36625823192` found a 48-character test-only static token in the dedicated-ingress gate test. The commit created the file; all references in it create a temporary test token file or compare an error against that fixture, not an external service or deployment credential. The source literal was replaced with a predictable runtime-generated fixture after the finding. | **Source-proven new unit-test fixture;** exact committed fingerprint only is baselined. Security-owner confirmation and sign-off remain pending. |

The six HMAC entries are one repeated value, not six independent key values.
That observation does not make a predictable key safe for production. The
repository alone cannot prove that no customer copied it into a deployment.
The Basic-auth classification relies on the user confirmation recorded above;
no separately signed security-owner acceptance was provided.

`.gitleaksignore` baselines only the nine exact historical fingerprints after
this review. It does not ignore a path, regex, credential value, rule or future
commit. Default detection and complete history scanning remain enabled. A
separate synthetic new-commit probe must still fail, proving these historical
exceptions do not permit a new credential-shaped value. No Git history was
rewritten and no provider alert was dismissed. These source/user classifications
do not clear target-storage, source-identity, receipt, independent-pilot or
production-owner acceptance gates.

## Capture publication findings (2026-10-02)

PR #165's full-history scan at commit
`18ec69a4ddd6e5fdab7a097b30b34571096e708f` identified seven additional
source-proven synthetic or non-value matches. The exact fingerprints are
recorded in `.gitleaksignore`; they apply only to that commit, path, rule
and line. Default detection, full-history scanning and security-owner
acceptance remain in force. No provider credential or live access was tested.

| Path / rule / line | Source evidence and classification |
| --- | --- |
| `.github/workflows/e2e-production-profile.yml` / `curl-auth-header` / 279 | Explicit deliberately wrong token in a negative authentication test that must return HTTP 401. It grants no access. |
| `examples/enterprise-reference/run.py` / `generic-api-key` / 79 | Function signature contains an `Ed25519PrivateKey` parameter type, not a serialized private-key value. The service receives an ephemeral process-local key at execution. |
| `benchmarks/fabric-comparison/run.py` / `generic-api-key` / 20 | Public synthetic privacy canary used only by loopback benchmark requests and disclosure assertions. |
| `docs/protected-byte-spool.md` / `generic-api-key` / 19 | Documentation passes the variable `customer_spool_key`; no literal credential is present. |
| `sdk/python/tests/test_deployment_policy.py` / `generic-api-key` / 22 | Deterministic public tokenization golden output for synthetic input; this is content-protection output, not an authentication bearer token. |
| `sdk/python/tests/test_span_protection.py` / `generic-api-key` / 24 | Same public synthetic privacy canary used by metadata-disclosure regression tests. |
| `sdk/typescript/test/deployment-policy.test.ts` / `generic-api-key` / 20 | Cross-language deterministic tokenization golden output matching the Python fixture; no service credential. |

This classification does not provide production security acceptance. A fresh
commit containing the same synthetic canary must still fail detection, proving
that these exact historical fingerprints do not exempt future matches.
