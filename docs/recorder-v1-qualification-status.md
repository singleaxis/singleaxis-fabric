# Recorder v1 qualification status

This document distinguishes implemented runtime behavior from public contracts
and from checks that require the release CI environment. It is a development
status record, not a certification or legal compliance statement.

## Qualified offline evidence batch — 2026-10-01 — deployment NO-GO

### HTTP transport correction — latest frozen local artifacts

The findings follow-up head `3911f82` cleared GitHub's separate CodeQL check.
Its updated security scan identified urllib3 2.7.0 in the HTTP OTLP dependency
chain: CVE-2026-97687 and CVE-2026-97689, fixed in 2.8.0. Spec 046 documented
the correction before code changes; the OTLP extra and development dependency
now require urllib3 >=2.8.0, with a narrow lock update and source/lock/installed
requirement regression tests. The maintainer's
[release notes](https://github.com/urllib3/urllib3/releases/tag/2.8.0) describe
the proxy TLS and unbounded chunk-size parsing fixes. No scan was suppressed.

Latest local results: **1,075 SDK tests passed**, **87.13% branch-inclusive
coverage**, Ruff and strict mypy over 93 files passed; **204 focused tests**
passed against the newly installed wheel. The new installed-wheel pilot again
reconciled 4 calls, 15 required byte objects and 23 metadata records, with zero
unexplained fixture discrepancies, all 24 negative cases preventing complete,
and metadata canaries absent. Wheel/sdist release-content qualification passed.

Latest wheel SHA-256:
`3233f673de8722361c6528df6932d870ea16380a808cf71257c0f17c00366a77`;
sdist SHA-256:
`e4c48076d4906cfcedee59c30e29cb26e35acc43d79ecb27b7305a95e8aeb1d9`.
Evidence is in the private `transport-dist/`, `transport-pilot/` and
`transport-artifact-qualification.json` under
`/private/tmp/fabric-qualified-run-release.8ELf6P/`; coverage is
`/private/tmp/fabric-qualified-run-coverage-20261001-transport.xml`.
The final Linux/security rerun is pending. All previous package digests below
are historical: they do not qualify this dependency-metadata change.

### Final Linux evidence and findings-check follow-up

Head `11b2e42` passed all six workflow runs, including exact-artifact kind
production-profile qualification (`36767899335`). Its installed wheel digest
matches the final local wheel below; the chart digest is
`3a0c0bbca2f502d095bceeaeab0f506aa5d357404db8c65b038cbb32f8aac469`.
The Linux pilot independently reports 4 operations, 15 byte objects, 23
metadata records, all 24 negative tests, zero unexplained discrepancies and
passed metadata canaries, under explicitly fixture-only receipt authority.

Workflow success is not the same as findings-check success: GitHub's separate
CodeQL findings check failed with one high test-only permission finding and
three assertion-side-effect errors. Before code changes, spec 046 recorded the
correction. The permission test now injects an unsafe stat observation rather
than creating a world-readable seal, while retaining fail-closed rejection;
append calls no longer execute inside the three flagged assertions. Eighty
focused spool/readback/witness tests passed. Descriptor-close warnings were
reviewed: each opened descriptor is immediately registered with ExitStack's
`os.close` callback, including exception paths. They are not suppressed.
The findings-check rerun for this follow-up is pending; deployment remains NO-GO.

[Spec 046](../specs/046-qualified-call-run-verification.md) preceded its code.
The optional combined verifier is now implemented: it rechecks raw signed
independent feeds, compares every required original byte and physical attempt,
checks the call graph against fresh sealed source records, authenticates source
binding and route closure, and verifies four separately issued exact receipt
sets. Original witness bytes are read once and reused internally to prevent
second-read substitution. Reports contain fixed reasons and metadata only.
The original local reconciler remains conservative; no trust flag upgrades it.

Fresh source readback uses directory file descriptors and no-follow traversal,
rejects hardlinks/FIFOs, nonprivate permissions, corrupt/noncanonical records
and deleted tails, and never substitutes a cached seal. The separate local
witness resolver has equivalent bounded tenant/issuer namespace checks. These
are local integrity/permission checks, not target IAM or encryption proof.

Executed final local checks: **1,074 SDK tests passed**, **87.13% branch-inclusive
coverage**, full strict mypy (93 files) and Ruff passed. The final frozen installed
wheel passed **203 focused tests** for combined proofs, receipts, source
readback, witness storage, independent feeds, signatures, MCP and security
dependency floors. The real loopback-provider ->
no-shell subprocess -> binary artifact -> provider pilot reconciled **4 calls,
15 required original objects and 23 projected metadata records**, with zero
unexplained fixture discrepancies. All **24 injected omissions/substitutions**
prevented completeness, including source seal/record loss, original/witness
corruption, missing feeds/stage receipts, invalid signatures and partial
acceptance. Canaries stayed out of projection, journals, receipts and reports.

Repository tests: **215 passed, 9 skipped**. The three Docker-backed tests in
`test_governed_node_e2e.py` were not rerun locally because the previously
established Docker ENOSPC condition remains; no pre-existing images/volumes
were removed. Seven skips require a live approved S3 endpoint; the other two
are filesystem-case behavior and a missing source-venv gRPC extra (installed
artifact checks have gRPC available). Recorder wheel/sdist content and release
identity qualification passed. New exact-artifact Linux CI is pending; prior
head `9bcc439` CI is historical evidence only for its artifacts.

Final frozen wheel SHA-256:
`dbca2af95d631437533cbefca9a1630156837203560dfaa2ea3a68b460220a35`;
sdist SHA-256:
`d8d1fe4eb97a4d486616e6ed628076522b053882c6f89810ec41956034c419e3`.
Owned private local evidence:
`/private/tmp/fabric-qualified-run-release.8ELf6P/`; coverage:
`/private/tmp/fabric-qualified-run-coverage-20261001-final.xml`.
Reproduction commands are in [qualified testing](qualified-call-run-testing.md).
The Linux workflow now tests the same built wheel with the combined verifier
and pilot and publishes only a non-secret summary.

### Exact remaining live gates, owner and next action

| Missing gate | Environment / owner | Next action |
| --- | --- | --- |
| Qualified native provider/tool/filesystem feed and terminal checkpoints | Declared real custom agent; application and independent service owners | Connect separately authorized native witness producers; reconcile every operation/byte, including direct bypass and pre-fsync loss |
| Actual signed stage issuance and durable readback | Selected Fabric Node, metadata destination and separate original store; recorder/destination/storage owners | Implement/qualify issuer integration at each actual stage; copying source sets or an OTLP 200 is insufficient |
| Route closure and capacity/passivity qualification | Isolated declared customer/laptop target; platform/application owners | Close excluded routes outside Fabric, inject bypasses, and measure behavior/rates/outage bounds against the unrecorded baseline |
| IAM/KMS/encryption, retention, restore and rotation | Actual protected stores and spools; storage/security/privacy owners | Run the configured target-store failure/control suite and provide authorized readback evidence; local filesystem mocks cannot substitute |
| Witnessed pilot and deployment decision | Frozen release on the signed target; independent reviewer and risk owner | Reconcile the live proof package and sign the bounded deployment decision after all gates pass |

The new offline API supports one tenant/run/source at epoch zero, not a
multi-source or recovered-history completeness claim. Pilot stage signers
are explicitly **fixture-only**. Its positive
`verified_complete_for_declared_scope` verifies that submitted synthetic
package under fixture authority; it does not qualify real issuers, Node
receipt production, storage controls, provider independence or customer
deployment. Engineering for those live integrations is not claimed finished.
Deployment status remains **NO-GO**.

### First Linux run and dependency correction

Commit `93f226f` passed the new exact-installed-wheel Kubernetes
production-profile pilot (`36765324739`), CodeQL and license checks. Recorder
CI failed only the new commit's missing DCO trailer; the commit was amended
with the repository-required sign-off. The security scanner found the SDK's
optional MCP dependency lock still selecting PyJWT 2.13.0: one critical and
five high findings, with a patched version available. This is a real release
dependency issue, not a reason to disable the scan.

Before changing dependencies, spec 046 recorded the correction: require
PyJWT >=2.15.0 in the MCP extra and regenerate its lock (resolved 2.15.1), and
require cryptography >=49 in signing/dev so existing vulnerable versions do
not satisfy an installation. Add source/lock/installed-metadata regression
tests and repeat exact artifact/signature/MCP/security qualification. The
maintainers' [PyJWT release](https://github.com/jpadilla/pyjwt/releases/tag/2.15.0)
and [cryptography advisory](https://github.com/pyca/cryptography/security/advisories/GHSA-jwv3-5hgf-82ww)
support the minimums. A new final wheel and Linux rerun are required; the
original `dist/` artifact digests do not cover this dependency-metadata change.
The final `final-dist/` wheel and `final-pilot/` evidence above passed the
rerun locally. Linux release/security checks for that correction are pending.

## Current closure work — 2026-09-30 — NO-GO

### Finite engineering completion batch — spec 046

[Spec 046](../specs/046-qualified-call-run-verification.md) was written before
the implementation. Remaining code in this batch: fresh sealed journal
readback; exact-set, stage-specific receipt verification; authenticated
independent-feed-to-capture reconciliation; source-binding and route-closure
proof verification; an owner-authorized local witness resolver; and an
installed-wheel model/tool/artifact/model qualification command with omissions
and substitution tests. This pre-implementation entry is superseded by the
dated October 1 evidence above. No production approval is credited.

The prior feed-only checker and conservative reconciler remain valid as
separate interfaces. This new optional offline path may verify a bounded
submitted evidence package under out-of-band issuer authority. Fixture
signatures do not qualify real provider independence, real Node/destination
receipt issuance, target storage controls or customer route closure. Those
live deployment gates remain NO_GO and must not be hidden by a positive
synthetic offline verification result.

This section supersedes older pending-security descriptions below, which are
retained as dated test history. [Spec 044](../specs/044-production-evidence-closure.md)
was written before this implementation. Work is on PR #164, not the user's
separate dirty checkout. The exact tested artifacts below have bounded test
evidence; none is approved for a critical production deployment.

### Deployment documentation cleanup scope

Before editing, the cleanup inventory identified two obsolete task/design
documents for removal: `docs/run-variant-artifact-outcome-change-list.md`
(superseded, includes removed judge/bridge scope) and
`docs/governed-content-implementation-brief.md` (old agent task prompt,
replaced by specs 028, 029 and 032–034). Preserve their history in Git; remove
live references and retain the dated gap assessment as explicitly historical
evidence. Keep numbered superseded specifications per spec-index policy,
active qualification evidence, public contracts and all user-uncommitted work.

Correct customer-facing claims in the root/example/deployment documentation:
scripted demonstrations are not complete-agent or production proofs. Make
the orchestration demo allocate its own output directory and container,
preserve prior output and refuse broad host-audit changes. The demo now uses a
unique run directory and owned container ID, read-only audit mount and
explicit isolated-synthetic acknowledgement. Its helper no longer changes
host audit rules. Five script-safety tests pass, including preserving previous
output, refusal without acknowledgement, and no auditctl invocation. This is
not a live Docker run of the changed example; that remains blocked locally by
Docker disk capacity. Do not remove an unfinished gate merely to present a
cleaner release story.

### Independent-feed checker — local artifact qualification

[Spec 045](../specs/045-independent-evidence-feeds.md) preceded the optional
offline `fabric.independent_feed` implementation. It checks separately pinned
native cursor bounds, exact operations/attempts/outcomes and required ordered
byte roles; verifies an approved issuer's signature before object reads; then
checks every resolved object's byte length and SHA-256. No raw evidence or
private callback error text enters its result. Wrong tenant/issuer, tampering,
missing/extra records, reordering and unreadable objects cannot verify.

This is a feed checker, **not** the completed independent-witness integration
or a production GO. It does not supply qualified service-side producers,
tenant IAM, route closure, complete delivery receipts or an authenticated
comparison with Fabric's record. The reconciler still cannot promote a run
to `verified_complete_for_declared_scope`.

Local source verification: **976 tests passed**, **86.79% coverage**, Ruff and
strict mypy passed. The new feed suites contain **41 tests**. A fresh isolated
wheel installation passed **102 tests** covering feeds, signatures and source
binding readback; the custom-agent smoke matched five calls and twelve byte
objects, with zero discrepancies before/after journal recovery. Injected
bypass, corruption and privacy loss stayed `partial`; the clean run stayed
`unverified`. Wheel/sdist recorder-content qualification passed.

Frozen local wheel SHA-256:
`0375740539d13c4c68f61c539302507662d27621949db96bc2cd7d74d279acb3`;
sdist SHA-256:
`a797260f6248fedc5569571ddcac115bf3098578b66e2c7a6d53db3587de58cf`.
Local evidence: `/private/tmp/fabric-independent-feed-release.C2wjA5/` and
`/private/tmp/fabric-independent-feed-coverage-20260930.xml`. The Linux workflow
now checks that the feed module comes from its installed wheel and runs both
feed suites against that artifact. Its new run is pending, not covered by the
earlier C2 CI results below.

The first new Recorder CI run (`36704858256`, commit `d144bd9`) found a
test-fixture typing error: unpacking a heterogeneous dictionary into the typed
feed expectation. Replace it with independently specified, explicitly typed
expected fields; no runtime/package code changed. The corrected full
`mypy src tests` check covers 84 files and passes, as do all 41 feed tests.
Retest the corrected commit; do not treat the failed quality gate as a pass.

Repository checks excluding the container-dependent module passed **212 tests**
with **9 explicit skips**: seven live S3 tests have no approved endpoint, one
case-collision test is unavailable on this filesystem, and one probe module
requires the isolated grpcio extra (covered by the installed-wheel run).
The attempted local Compose run hit Docker **no space left on device**, so
its three live tests did not run successfully. No existing Docker resources
were pruned; repeat those gates on the isolated Linux runner. A documentation
test briefly encountered a file being removed during parallel cleanup; its
post-cleanup-reference rerun passed. These are not production-storage proofs.

```sh
cd sdk/python
.venv/bin/python -m pytest
.venv/bin/ruff check src tests
.venv/bin/mypy src/fabric
cd ../..
/private/tmp/fabric-independent-feed-release.C2wjA5/venv/bin/python -m pytest -q -o addopts= sdk/python/tests/test_independent_feed.py sdk/python/tests/test_independent_feed_adversarial.py sdk/python/tests/test_evidence_attestation.py scripts/tests/test_source_binding_readback.py
/private/tmp/fabric-independent-feed-release.C2wjA5/venv/bin/python scripts/qualification/run_custom_agent_smoke.py --evidence-dir /private/tmp/fabric-independent-feed-release.C2wjA5/reproduction-smoke
```

### Source metadata finalization qualification

C2 adds an explicit offline `CallRecorder.seal_source()` and a persisted
epoch seal. It checks assigned sequence bounds and admission-time record
digests against secure disk readback. Recovery rejects missing tails,
additional events and self-consistently rehashed substitutions, and exposes
unsealed prior epochs even when no record survived. A persisted intent marks
interrupted finalization; detected loss during finalization restores that
marker. The agent still executes when recording is closed or fails.

Independent code review found a call-completion race: the call became `ok`
before its outcome was journaled. Completion now follows outcome admission,
and a barrier test proves that finalization refuses while the outcome is in
flight. This is a recorder correctness fix, not an agent-action lock.

Local verification on Python 3.12.13: **935 tests passed**, **86.74% coverage**;
Ruff, strict mypy and changed-file pre-commit hooks passed. The freshly built
wheel `f3721a5d8d87c796107a9a1502045b66696cb7d0e743057ad509ead8a634a6fa`
and sdist `05d27791f50db4389cc44c10111442a6aa5d7c7abbf49ddf5a2218fde01f894d`
passed package-content qualification. An isolated installation of that wheel
passed **124 focused tests** and the extended custom-agent smoke: five calls,
twelve byte objects, zero discrepancies before and after restart, and rejected
deleted-tail recovery. All expected faults remain `partial`; clean and
recovered runs remain `unverified`. Local artifact evidence is under
`/private/tmp/fabric-c2-final.4W8Osf/`; full coverage is in
`/private/tmp/fabric-source-seal-coverage-final-20260930.xml`.
The frozen commit `f70fa8b51a57fa3147294e178ff35c6f2d6e8bae` also passed
[Recorder CI](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36700082237),
CodeQL, security, basic kind and
[full production-profile qualification](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36700082241).
The downloaded artifact `synthetic-production-profile-36700082241-1` confirms
the **same wheel digest** as the local test above, zero restart discrepancies
and rejected deleted-tail recovery through both normal and dedicated-source
installed-wheel runs. The tested chart SHA-256 is
`d7e673b110b7777c8983c6d0b25d34f5dee900a65d8b2c92032cb72cdef47136`;
the Node image ID remains
`sha256:636fed937fd6b9c3c55515e2125446d54ffeb28a7ff361a7a355cee413576669`.
This is not a new completeness verdict. Reports are locally available under
`/private/tmp/fabric-ci-f70fa8b-36700082241/`.

Residual limits: a seal covers a terminal metadata prefix, not all physical
agent actions. Its cached copy is not fresh disk readback. It does not
authenticate an issuer, persist queued raw content, or prove the absence of
later work. Single directory-fsync faults and process exit during sealing are
tested; actual power loss and simultaneous failure of both final fsync and
the recovery-marker restoration remain unqualified. No completeness verdict
or customer storage proof is inferred from these tests.

```sh
cd sdk/python
.venv/bin/python -m pytest
.venv/bin/ruff check src tests
.venv/bin/mypy src/fabric
cd ../..
/private/tmp/fabric-c2-final.4W8Osf/venv/bin/python -m pytest -q -o addopts= sdk/python/tests/test_source_spool.py sdk/python/tests/test_call_source_spool.py sdk/python/tests/test_call_reconcile.py sdk/python/tests/test_call_otlp.py
/private/tmp/fabric-c2-final.4W8Osf/venv/bin/python scripts/qualification/run_custom_agent_smoke.py --evidence-dir /private/tmp/fabric-c2-final.4W8Osf/reproduction-smoke
```

### Dedicated ingress Linux qualification

The corrected commit `fcb618dacebe2994983c0a3a8295a3119f357da1` passed
[Recorder CI](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36698218653),
[security](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36698218605),
[CodeQL](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36698218577),
[basic kind smoke](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36698218679)
and [production-profile qualification](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36698218602).
This supersedes the pending CI corrections below. The published non-secret
artifact `synthetic-production-profile-36698218602-1` records:

- Sixteen HTTP/gRPC negative identity/authentication cases, with HTTP 400 and
  gRPC `INVALID_ARGUMENT` for identity rejection; zero rejected records found
  in destination readback. Live credential rotation passed both protocols.
- The source-bound custom-agent slice matched five calls and twelve byte
  objects with zero fixture discrepancies; all 22 metadata records plus four
  privacy-failure records were checked against destination readback. The
  clean verdict remains `unverified`; bypass, corruption and privacy faults
  remain `partial`.
- The controlled model/terminal/artifact fixture matched 25 required byte
  objects, ten outcomes and 39 destination metadata records, with zero clean
  discrepancies. Missing-object and bypass tests remained `partial`.
- TLS failure checks and scans for private canaries in destination data,
  Collector logs and persistent telemetry queue passed. This is disposable
  CI storage, not target-environment encryption, retention or restore proof.

Exact tested artifacts: wheel SHA-256
`8082f93661ef9417d1f331113ebaa9e8d015265ca92d2b4b758b5c671ac091f0`;
chart SHA-256 `9b95b62745c40071c000c8571b2bd2c244858330d314565cd39794eab1b963d7`;
Node Docker image ID
`sha256:636fed937fd6b9c3c55515e2125446d54ffeb28a7ff361a7a355cee413576669`.
Both installed deployments reported the same container-runtime image digest
`sha256:7f34be2b7548e541d423d64977aa5d7f46b489507488c8072a75f18aa16a026a`;
the image ID and imported runtime digest are different identifiers, not
interchangeable hashes. Downloaded reports are also available locally under
`/private/tmp/fabric-ci-fcb618d-36698218602/`.

The C2 source-seal work described in spec 044 is a subsequent code change;
none of the `fcb618d` results qualifies that newer SDK. Full authenticated
complete-run reconciliation, qualified receipt producers, independent feed
completeness, route closure and target-storage controls remain open.

The frozen commit `4bf4df9665aaa107ff9c0fd0ac2ebadbf9acac5a` passed
[CodeQL](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36625823263),
[basic kind smoke](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36625823164)
and license checks. The
[fuller production-profile test](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36625823349)
failed when the dedicated receiver returned HTTP 500 for a forged tenant.
The guard rejected the batch, but the response incorrectly invited retries.
The correction preserves a permanent gRPC `InvalidArgument` status through
the receiver, yielding HTTP 400. Unit/race tests pass; the live probe still
requires exactly HTTP 400 or gRPC `INVALID_ARGUMENT`, not a relaxed assertion.
Live rotation, final readback and privacy gates after that failure are not
credited until a fresh run completes.

The recorder CI chart test also failed because Helm versions phrase schema
errors differently. Its assertion now checks the rejected setting without
requiring one diagnostic wording; local Helm tests pass. The image job
stopped during a `proxy.golang.org` HTTP/2 download error before image
construction or vulnerability scanning, so neither image result is credited.
The history scanner identified one new static test token in this commit.
Its source-proven fixture classification is recorded in
[security triage](security-history-triage.md), with only its exact historical
fingerprint added to the baseline (nine total). The fixture is now generated
at test runtime. Full-history scanning and the independent new-credential
rejection probe pass locally. A fresh committed CI run is required for all
corrections. These results do not change the overall **NO-GO** decision.

| Gate | Implemented / locally tested | Still required |
| --- | --- | --- |
| Historical secrets | Nine exact historical fingerprints classified; eight source fixtures and one Basic-auth example confirmed **never used** by the requesting user. History scan and new-commit rejection probe passed locally and on `fcb618d` CI. | Named security-owner acceptance of the release, not just fixture classification. |
| Security findings | Python import cycle removed with typed protocols; resolver descriptor cleanup uses independent cleanup callbacks; host-spool close/unlock errors preserved. Regression, race, CodeQL and release image scans passed on `fcb618d`. | Repeat applicable gates for subsequent code changes; target deployment review. |
| Independent statement verification | Optional offline Ed25519 verifier pins issuer, tenant, run, scope, subject digest, stage, key validity and revocation. It rejects substituted issuers and expired-key backdating; 54 tests passed. | Qualified independent issuers and actual source/Node/destination receipt producers. A signature alone never promotes a run to complete. |
| Credential-bound ingress | Dedicated one-tenant/one-source guard, strict startup validation, chart opt-in and HTTPS-only file-based bearer export implemented. Go race/vet/chart tests and `fcb618d` installed-artifact HTTP/gRPC rejection, rotation and readback tests passed. | Exclusive credential ownership and approved deployment identity mapping remain deployment controls. |
| Python regression | Full suite: **895 passed**, **86.58%** coverage on Python 3.12.13; Ruff and mypy passed using SDK configuration. Installed-wheel evidence below. | Fresh Linux CI qualification. |

Installed-package evidence: the freshly built wheel
`8082f93661ef9417d1f331113ebaa9e8d015265ca92d2b4b758b5c671ac091f0`
and sdist `f1d2a7da9e590ebfecbe973ec7483f1f88b374f1149acaea53ddb98c0d8fcdf9`
passed the package-content qualifier. The isolated wheel installation passed
77 attestation/export tests and the custom-agent smoke: five calls, twelve
byte objects, zero fixture discrepancies; clean remains `unverified`, and
bypass, corruption and privacy failures remain `partial`. These are SDK
artifact checks, not a complete release or approved deployment.

Repository tests: 207 passed, eight skipped and three real-Node setup errors.
Seven skips were the live S3 tests (approved endpoint/bucket/credentials not
configured); the eighth requires a case-sensitive filesystem. A rerun excluding
only the diagnosed Docker module reproduced 207 passed and the same eight
explicit skips. No live S3 or target-storage control is credited.
The errors were reproduced in a fresh, uniquely named Compose project:
Collector startup failed with `no space left on device` opening its queue.
Only those newly created test resources were cleaned up; no pre-existing
workload or volume was removed. Local Docker evidence is **not passed**.
The isolated Linux CI environment must run these exact-artifact tests.
Local reproducible outputs are under
`/private/tmp/fabric-security-release-20260930/` (package manifest, installed
environment and smoke reports); source coverage is
`/private/tmp/fabric-security-coverage-20260930.xml`.

```sh
cd sdk/python
.venv/bin/python -m pytest
.venv/bin/ruff check src tests
.venv/bin/mypy src/fabric
cd ../..
python3 scripts/qualification/check_secret_scan_baseline.py
gitleaks detect --source . --redact --exit-code 1
uv build --out-dir /private/tmp/fabric-security-release-20260930/dist sdk/python
python3 scripts/release/qualify_release.py --policy scripts/release/release-policy.json --tag v0.8.0-rc.1 --chart-dir charts/fabric --dist-dir /private/tmp/fabric-security-release-20260930/dist --output /private/tmp/fabric-security-release-20260930/package-manifest.json
/private/tmp/fabric-security-release-20260930/venv/bin/python -m pytest -q -o addopts= sdk/python/tests/test_evidence_attestation.py sdk/python/tests/test_call_otlp.py
/private/tmp/fabric-security-release-20260930/venv/bin/python scripts/qualification/run_custom_agent_smoke.py --evidence-dir /private/tmp/fabric-security-release-20260930/new-smoke
```

The venv above was created with `uv venv --python 3.12` and installed only
the exact wheel with `[otlp,signing]` plus pytest, not the source checkout.
Adding the isolated probe's `grpcio==1.76.0` test dependency then passed seven
readback-validator tests: exact match, missing record, duplicate, forged tenant,
unexpected content, unaccounted operation and rejected record at destination.
The Linux workflow installs that dependency and explicitly runs this test file;
general repository environments without it report a skip.

Review found an upstream bearer-token reload race: a malformed rotated file
could admit an empty token before the gate's periodic check. The release build
now applies the pinned v0.150.0 receiver patch and tests it before rebuilding
the final binary; Go build metadata must identify the patched replacement.
Dedicated-source configuration requires `require_single_token: true` inside
the receiver, not merely a polling supervisor. Invalid, multiple, empty or
unreadable token files clear accepted credentials on reload. Kubernetes
projected-Secret symlink updates are observed, with a one-second strict-mode
reread fallback for missed filesystem events. This is eventual rotation after
projection/reload, not instantaneous revocation at Secret update time.

The full patched upstream module passed `go test -race -count=1 ./...`, including
real filesystem watcher valid→valid→malformed symlink swaps. Chart render and
lint passed. The isolated Linux workflow now uses the same built image and
packaged chart for a second dedicated-source deployment, tests both protocols,
performs live Secret rotation, compares every expected SDK metadata record
with durable fixture readback, and scans sink/log/queue bytes for credentials
and content canaries. Those live tests passed on `fcb618d` as recorded above.
The separate local Docker setup failure is not waived.

The complete-run decision remains unavailable: pre-fsync source loss and raw
queued-content crash safety are not closed; the trusted four-stage receipt
chain and independent complete operation sets are not implemented end to end.
The customer deployment still needs a signed route/capacity/privacy scope,
actual storage encryption/isolation/retention/restore/rotation tests, and
platform, security, records and independent-reviewer acceptance. Passing
synthetic CI does not substitute for these controls.

## First synthetic evidence slice — NO-GO

### Existing-agent integration test-start (spec 042)

An opt-in Python byte-call adapter now wraps an existing synchronous model or
tool delegate, observes caller-supplied exact request/context/response bytes,
records a separate outcome, and returns the delegate result or exception
unchanged. It does not auto-discover an agent, capture streaming/async calls,
prove that lower client layers leave the bytes unchanged, or see unwrapped
routes. The source remains unauthenticated and the full receipt chain is
missing; this is a test-start integration, **not** production-qualified
capture. Client-specific capability manifests, route inventories and bypass
tests are still required before a completeness claim.

Local evidence on 2026-09-28: 24 focused byte-boundary/synthetic tests and
the full Python SDK suite (700/700 without coverage; the preceding 699-test
run met the 85% coverage gate at 85.28%) passed. Ruff passed for the changed
Python files; mypy passed with a writable temporary cache.
A newly built wheel (SHA-256
`3a7dac5d868c36cf1d8927611d29c49e0ecab0e6e7770aa3d17e640019b6ae24`)
was installed into a disposable Python 3.11 environment and ran the new
client adapter smoke: five protected byte objects and two outcomes matched
independent in-process truth; five metadata
records contained no secret canary; a direct bypass caused two missing-object
discrepancies and `partial`. The clean run remained `unverified`. The exact
wheel passed the package-content qualifier. The same wheel digest appeared
in [Linux kind run 36422550081](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36422550081)
on commit `6fb5ba6`: the new installed-wheel client smoke passed, and the
existing production-profile fixture reconciled 25 byte objects, 10 outcomes
and 39 sink metadata records with zero clean-run discrepancies. Bypass and
missing-object cases remained `partial`; the clean case remained `unverified`.
The run's non-secret `synthetic-production-profile-36422550081-1` artifact
contains the exact reports and digests. This is an isolated CI test, not a
customer environment or complete-run proof. Source hygiene on `6fb5ba6`
failed only because the connector-contract test needed formatting; the
formatting fix is pending a new CI run. The history-wide secret scan also
remains red pending security-owner classification.

[Spec 040](../specs/040-synthetic-agent-evidence-slice.md) records the phase-1
gap ledger, provisional scope and control/coverage matrix, and documents
phases 2–8 before code changes. The declared test workflow is a non-sensitive
Python 3.11 model → no-shell terminal/tool → file artifact → model flow using
a controlled endpoint and independent fixture/filesystem truth. The scope is
not a signed customer deployment approval. Draft contracts and caller-supplied
byte storage are locally tested. Opt-in loopback HTTP, no-shell terminal and
allowlisted-file adapters now have **source-checkout local** binary-byte
tests. An offline resolver checks tenant-scoped refs and source/stored SHA-256
and length, and a conservative reconciler reports known missing/corrupt
bytes as `partial`. Matching fixture bytes remain `unverified`, never
complete. An optional metadata-only source journal now persists an epoch,
events and outcomes off the action path, with restart recovery and explicit
overflow/corruption tests. Its bounded handoff still has an unverified
pre-fsync crash window. An offline, post-run, loopback-only AEEP metadata
projection now reaches the real Fabric Node. Its closed evidence guard
preserves fixed names and strips bodies/unknown fields; OTLP partial success
is counted without blind retry. This is Node acceptance only: source IDs
remain unauthenticated, with no continuous AEEP publication or durable
destination receipt,
and reachable direct bypasses. The optional host emitter now quarantines
partly accepted OTLP batches without replay, retaining the rejected count
across restart; it remains corroborative and excluded from the complete
source set.
The terminal proxy and synchronous artifact observer are test-harness
adapters, **not** proven non-interfering passive production capture; their
timing/backpressure remains a release gate.

Phase evidence as of 2026-09-27: `sdk/python/.venv/bin/pytest -q -o
addopts= tests/test_synthetic_otlp.py tests/test_synthetic_evidence.py
tests/test_source_spool.py` passed 25/25 locally with an
ephemeral loopback endpoint (the default sandbox denied the bind; the bounded
test was rerun with network permission). Targeted Python Ruff and mypy
passed; `GOCACHE=/private/tmp/fabric-go-cache go test -race ./...` passed
for `components/host-emitter`; the Node guard race suite also passed. The full
Python SDK suite passed 690/690 (85.10% coverage); package-boundary tests passed 21 with one skip because
case-colliding files are unavailable on this filesystem. The
source-checkout synthetic pilot compared twelve byte objects and five outcomes
with independent fixture/endpoint/filesystem values and found zero local
discrepancies; its verdict is still `unverified`. See the
[local discrepancy report](../qualification/synthetic-slice/local-pilot-report.md).
The follow-up fixture projects all twelve reconciled byte events to offline
AEEP metadata and verifies their IDs, roles, statuses and digests; the
focused synthetic suite passed 25/25. This does not constitute live delivery.
With elevated Docker socket permission, uniquely tagged local Node and host
images were built; a disposable Python wheel and chart were packaged. The
latest installed local wheel passed 24/24 focused tests. A pre-resource-hardening
Node image passed 3/3 real-Node governed-content, AEEP privacy/export,
and controlled-sink outage/restart tests in an isolated random Compose
project. A later guard fix clears evidence resource/scope attributes and
passed `go test -race`; its rebuilt image **could not start the persistent
queue** in the shared Docker daemon (`no space left on device`), so its
live privacy probe remains unverified. Exact local digests and commands
are in the [artifact ledger](../qualification/synthetic-slice/local-artifact-ledger.md).
No privileged BPF run or customer deployment was performed. The dirty
worktree has no clean tagged artifact identity, and these tests are not
target-Linux BPF, target-storage or live-customer-destination proofs.
A complete-run or critical-enterprise claim remains **NO-GO**.

Isolated Linux qualification has now started in draft PR
[#164](https://github.com/singleaxis/singleaxis-fabric/pull/164). The first
Ubuntu/kind smoke run on commit `75afeb1` passed Collector install, the
controlled fsync sink, protection/delivery, destination outage and restart
recovery. It did **not** run the synthetic model/terminal/artifact byte
reconciliation, scoped BPF, or target storage/retention tests. The same
commit's security and recorder CI runs failed: dependency scans found
`google.golang.org/grpc` 1.82.1 and AnyIO 4.13.0; the history-wide secret
scan reported seven findings in older commits; clean Python installation
exposed an S3 fake-client test failure; CI typing and repository-test setup
were incomplete. Dependency and test-environment fixes are being qualified
on the PR branch, not yet accepted as a passing release gate. The seven
history findings need security-owner classification before any suppression
or release decision.

The second PR run on commit `334c5b8` passed all released lockfile/dependency
scans, Python SDK tests on 3.11/3.12/3.13, repository contract tests, Node
image scan, and source hygiene. Its recorder CI still failed on one Python
test typing assertion, fixed locally for the next run. The history-wide
secret scan still failed on the same older findings; a separate scan of the
two PR commits (`gitleaks git --log-opts=main..HEAD`) found no new leaks.
Neither result classifies the historical matches or authorizes release.
The next run on commit `3073142` passed Recorder CI, CodeQL, license
compliance, and the Linux/kind smoke, including queue outage/restart recovery.
Recorder security remained red **only** on the same history-wide secret scan;
all current released-dependency scans passed. These CI results establish a
bounded Node smoke on that commit, not a synthetic exact-byte pilot, target
storage qualification, or enterprise GO.

The later PR head `c5ca90f` also passed Recorder CI, Linux/kind smoke,
CodeQL and license checks. Recorder security still fails solely on seven
history-wide secret-scan findings in old commits; the current tree and PR
range scans found no new leaks. The smoke still did not run the synthetic
agent. The [installed-artifact pilot plan](../qualification/synthetic-slice/end-to-end-agent-pilot-plan.md)
now defines that missing CI step. A newly built local wheel installed in a
disposable Python 3.11 environment ran a deterministic three-model/two-tool
agent fixture: 25 required byte objects and 10 outcomes reconciled with
fsynced endpoint/tool journals and artifact inventory, with zero discrepancies
in the clean case. A direct provider bypass produced four discrepancies and
a deleted required object produced one; both were `partial`. The clean case
remained `unverified`. The new workflow step will test that same installed
wheel against the isolated Linux/kind Node and controlled sink; its live result
is pending. This fixture is not a customer shadow pilot or passive
non-interference proof.

The local wheel SHA-256 was
`d3ca361f5acb008daf8bb96b392033514393851b5b7f66ce4e127d2797d15561`.
The executable check was
`/private/tmp/fabric-agent-pilot-venv/bin/python scripts/qualification/run_synthetic_agent_pilot.py --report-path /private/tmp/fabric-agent-pilot-report.json`
from the PR worktree, after installing that wheel into the disposable venv.
This local digest is not a clean tagged release identity.

On signed PR commit `038b75c`, [Linux/kind run
36298189775](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36298189775)
passed the installed-wheel fixture against the live Node and controlled fsync
sink. The wheel SHA-256 was the same `d3ca361f…d15561` as the local build.
The clean case reconciled 25 required byte objects and 10 outcomes with zero
discrepancies; 39 metadata record IDs and their digests appeared in sink
storage, and the canary was absent. The bypass and deleted-object faults
produced four and one discrepancies respectively and `partial` verdicts.
The exact CI report is the run's `synthetic-agent-pilot-36298189775-1`
artifact. This run checked record/digest *presence*, not parsed per-record
association. Parsed OTLP sink readback and Collector-log canary checks have
since been added and await a new run. Recorder CI's Source hygiene job on
`038b75c` failed due Ruff formatting of the new fixture; the next revision
formats those files. CodeQL and license checks passed; the security workflow
still fails only on the seven historical secret-scan matches.

The stronger [Linux/kind run
36298890912](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36298890912)
on commit `5c2ab7f` passed. It installed the packaged chart and Python wheel,
ran the three-model/two-tool fixture, reconciled 25 required byte objects and
10 outcomes with zero clean-run discrepancies, and read back all 39 evidence
records from the controlled sink's fsynced OTLP files. Each parsed record ID
was unique and matched its expected event name, role, status,
source/operation/attempt identity and content digest. The canary was absent
from sink bytes and current Collector logs. The bypass run had four expected
discrepancies and the missing-content run one; both were `partial`. The clean
run remains `unverified`, not complete. The exact CI evidence artifact is
`synthetic-agent-pilot-36298890912-1`. Artifact identities from that run:

| Artifact | Exact tested identity |
| --- | --- |
| Python wheel | SHA-256 `d3ca361f5acb008daf8bb96b392033514393851b5b7f66ce4e127d2797d15561` |
| Packaged chart | SHA-256 `8d4175030d8246862bc0df2604c838fb27faf286077cd42e9c7bd5c62fde41e1` |
| Local Node image | image ID `sha256:fd527bb998c1a59e6163a832de18a9be6e43edf29c70d0495219de70eb1c468d` |

Recorder CI, CodeQL and license compliance passed on the same commit.
Recorder security still fails solely on the seven older whole-history secret
scan matches; all released dependency and source scans passed. The run did
not pin a clean release tag or qualify the host-emitter image, source
authentication, destination receipt, target storage/retention,
non-interference, scoped BPF, or a customer shadow pilot. It is a bounded
exact-artifact CI pilot, not a critical-enterprise GO.

The subsequent [Linux/kind run
36299296091](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36299296091)
passed the same installed-wheel pilot and parsed fsynced sink readback on
commit `827fffc`, with 25/25 required byte objects, 10/10 outcomes and 39/39
metadata records reconciled. Its exact chart SHA-256 was
`325a635a5d7e9091744f9121aeca3921526bed1d5801f70e2ca007213ac45e6c`
and local Node image ID was
`sha256:8de47ac7f40db683d4f81a3d771b8c7c961926eaacf4838a07609949b5a05476`;
the wheel SHA-256 remained `d3ca361f…d15561`. The difference in chart and
image IDs between these runs means cross-run reproducibility is **not**
established. Each run did test its own built artifacts. This was still the
development chart profile; it did not qualify production-profile TLS.

The [production-profile kind plan](../qualification/synthetic-slice/production-profile-kind-plan.md)
now has a separate CI implementation that installs the packaged
`shadow-production` profile with an ephemeral client CA, mTLS ingress,
authenticated HTTPS export and the same installed-wheel byte/record pilot.
Local chart rendering, Python TLS bridge unit tests, Ruff and workflow lint
passed. The first [Linux run
36324254204](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36324254204)
verified mTLS rejection of missing/untrusted client certificates and sink
rejection of missing export authentication, but its exact-byte delivery gate
failed: the CI-generated Authorization Secret had a trailing newline, which
made the Go exporter reject its own header before contacting the sink. All 78
required sink ID/digest checks failed, correctly preserving NO-GO. The test
Secret writer was corrected. [Run
36324523853](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36324523853)
then passed the `shadow-production` kind job: missing and untrusted client
certificates failed, unauthenticated sink writes returned 401, and the
installed-wheel pilot reconciled 25 required byte objects, 10 operations and
39 parsed sink records with zero clean discrepancies. The bypass and
missing-object cases had four and one discrepancies and stayed `partial`;
the clean case stayed `unverified`. The canary was absent from the sink files
and Collector logs. The exact run artifact is
`synthetic-production-profile-36324523853-1`: wheel SHA-256
`cb057a898646ae9c9f9c487360cb062faf64a61eaa7ab91237ce664972b00d50`,
chart SHA-256
`dcbb93d7091ad580c59fb34811b7d0f16b3175ef07f40132b0b8cf511406a672`,
Node image ID
`sha256:fd527bb998c1a59e6163a832de18a9be6e43edf29c70d0495219de70eb1c468d`.
This commit's Recorder CI Source hygiene failed because the test sink YAML
had multiple documents; it was split into single-document manifests. The
same-code [run
36324824792](https://github.com/singleaxis/singleaxis-fabric/actions/runs/36324824792)
on signed commit `da379ec` then passed the production-profile kind gate and
parsed sink readback again. Its exact artifact is
`synthetic-production-profile-36324824792-1`: wheel SHA-256
`cb057a898646ae9c9f9c487360cb062faf64a61eaa7ab91237ce664972b00d50`,
chart SHA-256
`6d4bb954f1d199832fcd51f451931089c4665b60eca74b9f5b8319b783cc309b`,
and Node image ID
`sha256:fd527bb998c1a59e6163a832de18a9be6e43edf29c70d0495219de70eb1c468d`.
Recorder CI, the development-profile kind smoke, CodeQL, license and all
released dependency/SAST jobs passed on `da379ec`; the whole-history secret
scan remained red on the same seven
older findings. A healthy Collector Pod alone did not prove delivery. This
remains a synthetic transport/protection test, not a customer
storage, identity-binding, retention, NetworkPolicy-enforcement or production
GO proof.

The next hardening revision adds a Fabric Node startup check for outbound
Secret-backed HTTP header bytes. It refuses empty, whitespace-surrounded,
control-byte or non-ASCII header values before reporting healthy, without
printing credentials. This directly addresses the failed `36324254204`
test's newline-bearing Authorization Secret. A new exact-image negative CI
step tests the refusal, and the release policy now requires the
production-profile workflow on the exact release SHA. A bounded failure
injection test confirms that a content-recorder write error does not change
the synthetic provider response or terminal result; it does **not** prove
timing non-interference. Local gate `go test -race`, 692 Python SDK tests,
and 197 repository tests passed (12 repository tests skipped for their
documented environment prerequisites). The new image/CI result is pending
at this documentation revision. The [GO decision packet](../qualification/production-go/decision-packet.md)
lists the exact target evidence and owner approvals still required; neither
the packet nor a passing CI job grants production approval.

The first new PR-head production-profile job passed on Linux, including the
exact-image malformed-header refusal. Its separate CodeQL alert check still
failed: the audit receiver converted a uint64 serial to int64 without an
upper-bound check; the controlled sink allowed legacy TLS versions by
default; and a permission-rejection test deliberately sets mode 0777.
The first two are engineering fixes in the next PR revision. Security must
classify the intentional test alert; no passing analysis job overrides an
unresolved alert check.

The [local GO simulation](../qualification/local-go-simulation/README.md)
now has a reproducible laptop-kind runner and a fail-closed, unsigned
decision summary. Its first live local attempt exposed a missing sink
ingress allowance: the Node accepted/queued the synthetic record, but the
sink had zero files and the exact-record check failed. A narrow policy for
Node → sink port 8443 restored queued delivery without restarting the Pod;
the script now pre-registers a deny-then-allow probe. A full fresh pilot is
pending at this documentation revision. Even a passing rehearsal remains
`NO_GO` for production because local-path storage, target CNI/identity,
source continuity and real owner approvals remain unqualified.

The fresh local rehearsal on clean commit `b91a9de` subsequently passed:
the clean fixture reconciled 10 operations, 25 required byte objects and
39 parsed fsynced sink records without discrepancy; source high-water was
provider 15, terminal 25 and artifact 6. Direct provider bypass produced
four discrepancies and `partial`; deletion of one required content object
produced `partial`. The local deny-then-allow policy probe recovered queued
delivery after the sink allowance. Its [observed-run report](../qualification/local-go-simulation/observed-run-20260928.md)
retains exact artifact IDs and limitations. This is an unsigned simulation
with `unverified` clean verdict and production `NO_GO`, not a customer pilot.
The local simulation unit tests and broader installed-wheel repository suite
passed (3/3 and 204 passed/8 skipped respectively); environment-only
missing-dependency failures from earlier invocations were corrected and
recorded in the observed-run report.

The subsequent PR-head audit shows the two real CodeQL defects (audit serial
overflow and legacy sink TLS) fixed and tested. The remaining high-severity
CodeQL annotation was the spool negative-test fixture that deliberately set
a test directory to mode 0777. The test now exercises the same 0700 rejection
with mode 0770, and the focused spool and host-manifest suites passed 14/14
locally. The new CodeQL run still flags group-writable mode, so the negative
fixture now uses owner-only mode 0500 and restores 0700 on exit;
the focused spool suite passes 7/7 with that change. CodeQL must still
be rerun on the new PR head. The history-wide secret scan
still reports seven findings in older
commits. A clean PR-range scan does not classify those historical values or
clear the release gate; the security owner must review and, if any are live,
rotate/revoke them. This phase remains **NO-GO**.

A read-only Dependabot audit on 2026-09-28 found that default-branch alerts
include packages outside the recorder release, plus Python SDK lockfile
`idna` 3.13 and `pydantic-settings` 2.14.0 and TypeScript SDK development
`vitest`/`@vitest/mocker` 3.2.4. The PR already had the advisory's fixed
`anyio` 4.14.2; that default-branch alert is stale for this branch. The SDK
lockfiles now select `idna` 3.20, `pydantic-settings` 2.15.0, `vitest` 4.1.11
and `esbuild` 0.28.1. The last package is pinned by an npm override because
the first resolution of Vitest 4 still selected a vulnerable development
server build. On this branch, locked Python tests passed 692/692; TypeScript
tests passed 315/315, with typecheck, build, package-content tests (5/5),
lint and format passing. `npm audit --audit-level=low` reported zero
vulnerabilities in the resulting graph. The new PR-head Linux/security gates
and owner classification remain pending; passing tests do not certify a
customer deployment.

The next Linux Python 3.12 CI run exposed a real asynchronous completion
race in `ContentWriter`: destination write incremented `stored` and removed
pending bookkeeping before the durable spool file was unlinked/fsynced, so
`flush()` could report a drained writer while cleanup was still in flight.
The restart test also left the original worker alive, so it did not faithfully
model process death. The implementation acceptance rule is now: successful
spooled settlement occurs only after the durable spool cleanup; failed
cleanup retains a pending gap, and a deterministic test pauses cleanup to
prove `flush()` cannot report completion early. This is an engineering fix,
not a destination-durable receipt or a passive-capture qualification. The
implementation and restart-test correction passed the governed-content suite
(91/91) and full Python SDK suite (694/694) locally. Linux CI on the new
commit is still required.

### Decision rule for the first bounded GO

`GO` applies only to the signed synthetic model → terminal → artifact → model
scope, not to every AI tool or compliance regime. All gates below must pass
on the **same clean, tagged, digest-pinned artifact set**; a unit test, OTLP
200, or self-reported manifest cannot substitute for a missing gate.

| Gate | Required evidence | Current blocker |
| --- | --- | --- |
| Approved boundary | Signed route/version/source/role/privacy/capacity record and proof excluded routes are unreachable or explicitly outside the claim | Scope unsigned; direct HTTP/subprocess bypasses are reachable |
| Capture and loss | Exact bytes, outcomes, order, causal IDs and source high-water for every required operation; crash/overflow/partial-success injection always lowers verdict without altering the action | Wrappers not passive-qualified; source pre-fsync blind window and missing authenticated gap chain |
| Identity and receipts | Authenticated tenant/source binding; independently checked source-spooled, Node, destination-accepted and destination-durable stages | IDs caller-supplied; no complete trusted receipt chain |
| Protection and retention | Final image canary-free outbound telemetry/logs/queue/errors/receipts; tenant isolation, encryption, retention, restore and key rotation proved on target stores | CI sink/log canary passed; queue/error/receipt paths and target storage controls remain unverified |
| Exact release | Installed SDKs, chart, Node and any shipped host image by digest; security/package/race/E2E gates on isolated target Linux/Kubernetes; scoped BPF if a host route is included, only with approval | CI wheel/chart/Node digests tested; clean release tag, host image, target environment and authorized BPF absent; historical secret scan red |
| Independent shadow pilot | Every expected operation and required byte object reconciles against separately authenticated endpoint, terminal and filesystem records; zero unexplained discrepancies; reviewer reproduces verdict | Isolated synthetic CI fixture passed; feeds not authenticated, no customer pilot or independent sign-off |

Engineering can close code and fixture gaps in this repository. Customer
platform, security, privacy, records and release owners must supply the
bounded target environment, signed scope and trust roots, storage policies,
destination readback and independent review. No recorder code can honestly
manufacture those proofs. When any gate is unavailable, status remains
`NO-GO` or `unverified`; it is never inferred from a passing schema test.

| Phase | State | Exact missing gate / environment / owner / next action |
| --- | --- | --- |
| 1–2 scope and contract | Documented, provisional | Customer platform/security must sign route, identity, privacy and target limits in an isolated deployment record. |
| 3 boundary adapters | Partly locally tested | Recorder engineering: process crash, partial-stream, backpressure/non-interference and direct-bypass closure in disposable Python 3.11 fixture; replace any intrusive observation before promotion. |
| 4 loss and receipts | Local source journal, host partial success and offline AEEP Node acceptance tested; slice unverified | Crash-before-fsync test proves a blind window; recorder engineering must reconcile it against authenticated independent truth, publish gaps and qualify distinct source/Node/destination/durable receipts. Audit receiver remains excluded. |
| 5 resolver/reconciliation | Synthetic Linux/kind byte and parsed-sink reconciliation passed; verdict still unverified | Customer verifier: authenticate independent feeds and durable receipt proof before enabling `verified_complete_for_declared_scope`. |
| 6 privacy/storage | CI final Node sink/log canary and local source-spool canary passed; target storage unverified | Customer privacy/storage: canary across queue/errors/receipts and live encryption, retention, backup/restore, key rotation and disk-full tests for each store. |
| 7 exact artifacts | Linux/kind installed-wheel, packaged-chart and built-Node-image pilot passed on `5c2ab7f`; host image, clean tag and target environment unverified | Release engineering: pin a release tag/digest set, qualify any shipped host image and target Linux/Kubernetes; scoped BPF requires explicit approval. |
| 8 shadow pilot | Isolated synthetic CI fixture passed with parsed sink readback; customer pilot not run | Customer pilot owner: pre-register authenticated endpoint/terminal/filesystem records, run exact artifacts in target environment, reconcile every operation/object and obtain independent review. |

## Implemented in release artifacts

| Area | Implemented behavior |
|---|---|
| Capture | Python and TypeScript SDK surfaces; OTLP trace and log ingestion through Fabric Node |
| Protect | Non-disableable exact metadata allowlist; raw bodies and unapproved native OTLP strings removed before export; named production profile rejects custom allowlist extensions |
| Deliver | OTLP/HTTP export, persistent file queue, no production pre-queue batch window, blocking overflow, restart recovery, and unbounded retry |
| Deployment | Collector-only Helm chart with `shadow-dev` and fail-closed `shadow-production` profiles |
| Setup | Recorder-only `fabricctl` init, validate, digest, help, and version commands |
| Packaging | Explicit release allowlists for SDKs, chart, image, CLI, and public contract families |

Governed content capture (specs 028–034, **draft**) is present in the SDK
source and packages but is **not yet a qualified release capability** — see
its dedicated section below. The recorder claims above are about the
metadata-only pipeline.

The released recorder artifacts do not contain or install judges, red-team
runners, prompt-time PII controls, guardrail engines, policy/tool authorization,
assurance tiers, governance workflows, or management-plane services.

## Public contracts, not automatic runtime evidence yet

Activity Envelope v2, privacy assertions, and delivery batches/receipts define
interoperability shapes and validation rules. Recorder v1 does not yet claim
that Fabric Node materializes Activity Envelope v2 on its OTLP wire path,
automatically emits a signed privacy assertion for every batch, or obtains
durable-persistence proof from arbitrary destinations.

The AEEP profile (specs 035–036) now has **draft, pinned contract fixtures**
for `agent.evidence.*` event projections, source capabilities, a bounded
run manifest, and binary content-object v2. The validator and tests check
schema closure, exact-byte digests, tenant/ref safety, source lifecycle,
loss/sampling, independent-feed and durable-receipt structure, and false
completeness verdicts. The Python and TypeScript SDKs now locally test an
explicit opt-in content-v2 **byte** recorder: it persists caller-supplied
bytes per observation in a tenant-bound local or S3-compatible store. Its
bounded queue is process-memory only; it does not automatically intercept
model/tool/terminal calls, produce run manifests or obtain durable
destination receipts. A separate offline synthetic adapter projects settled
metadata to AEEP OTLP logs for a controlled loopback Node; it is not an
automatic production publisher. The schemas are not an implemented
complete-evidence runtime and are not qualified as a production capture
surface. Proof fields in fixtures are structural, not authenticated proof.
Draft specs [037](../specs/037-bounded-enterprise-deployment-and-controls.md),
[038](../specs/038-capture-boundary-and-loss-qualification.md), and
[039](../specs/039-storage-release-and-shadow-pilot.md) define the
customer-specific control matrix, capture/loss qualification,
protected-storage proof, exact-artifact tests, and shadow-pilot
reconciliation required for a critical-enterprise go decision. No such
go decision or pilot evidence is present in this repository today.

### Governed content (specs 028–034, draft)

Status vocabulary used here: **implemented** (code exists and passes unit
tests), **locally tested** (suite-level evidence in this repository),
**environment-dependent** (requires a live endpoint/cluster), **deferred**
(designed, not built), **unsupported** (explicitly out of scope for v1).

Locally tested in the SDKs today:

- versioned `fabric.content-object/v1` descriptors and
  `fabric.transcript-manifest/v1` / `fabric.transcript-export/v1`
  contracts, with shared byte/hash fixtures passing in both languages;
- local filesystem and S3-compatible governed stores behind a shared
  safe-identifier tenant rule (tenant namespacing, content-addressed
  objects, descriptor sidecars, by-decision manifest aliases);
- bounded writer with `process`/`spooled` durability plus dev-only
  `inline`, `fabric.content-spool/v2` durable records, full recovery
  drain with post-restart manifest-item reconciliation, revision-safe
  manifest rewrites, quarantine, and exact stored/pending/dropped/failed
  accounting — a nonblocking enqueue is never reported as durable;
- passive delivery end to end: refs and `manifest_ref` are deterministic
  and stamped before spans end; objects and manifests travel the bounded
  writer — the monitored path performs no object-store I/O in
  `process`/`spooled`;
- governed capture across `llm_call` (request, output, partial output),
  `tool_call` (arguments, result), retrieval, memory, side-effect,
  context, and interaction surfaces in both SDKs;
- authorized resolution confined to configured stores and tenant
  namespaces; `available` is returned only after descriptor, byte-length,
  and SHA-256 verification, with explicit
  available/pending/missing/denied/corrupted/unverified results.

Environment-dependent, not yet qualified:

- production S3 delivery against a live endpoint (adapter is
  contract-tested with fakes; a skippable live gate exists and must pass
  before S3 is claimed production-ready);
- promotion evidence for governed-content flow through the tagged real
  Fabric Node build. The local Docker E2E gate proves refs cross and raw
  content stays out of exported OTLP, collector logs, and queue files;
  release CI must repeat that proof for the exact promoted commit.

Deferred:

- adapter/framework auto-capture of governed content (manual `llm_call`
  surfaces only — auto-instrumentation content is not wired).

Unsupported in v1:

- binary or multimodal content (mark it `unsupported`; v1 is text/JSON);
- immutable-evidence/retention claims (WORM, object lock, and lifecycle
  are customer bucket/filesystem policies the SDK does not provide);
- hidden provider context or reasoning (Fabric records the observable
  boundary only).

An unsigned privacy assertion records what a processor claims it applied. It is
not independent proof and is not a legal de-identification determination.

### Host-source hardening (not a complete-host claim)

The optional host emitter now has a bounded disk spool with fsync, restart
replay, stable source record IDs, and explicit ring/rate loss summaries. It
defaults to no intentional rate limiting or deduplication. Raw argv and paths
are not spooled or exported; truncated argv/path fields are marked incomplete
rather than mislabeled as full hashes. The guard has exact keys and closed
values for host status metadata and strips raw path keys. The audit receiver
now has an explicit persistent logfile mode: private checkpoint/replay state,
accepted cursor, stable record IDs, bounded source/rotation handling and
fault/restart tests. Logfile configuration requires a dedicated persistent
`state_directory`; see its migration guidance. Netlink remains bounded
in-memory and non-replayable. Neither host path has passed a target-Linux
BPF/kernel loss test or independent host-truth reconciliation here.

The host-emitter DaemonSet is a fail-closed qualification template. A static
preflight checks pinned image identity, scoped cgroup, TLS credentials and
persistent spool mounts. It cannot verify encrypted disk, valid credentials,
real cgroup coverage, or lossless live operation.

## Locally qualified

The repository qualification suite covers:

- contract schema, digest, ordering, causality, and receipt invariants;
- guard processor unit, race, and static checks;
- chart schema, package boundary, production ingress/egress, and durable queue
  configuration checks;
- recorder-only CLI build and dependency graph;
- SDK unit, typing, lint, build, and exact package-surface checks;
- installed-artifact runtime smoke for both SDK packages, including local
  governed capture, manifest export, and integrity verification;
- release identity, release policy, workflow syntax, and artifact boundaries.

Exact test counts can change as coverage grows. The release's immutable CI run
is the authority for published counts.

## Required before an enterprise test release is promoted

The tagged commit must pass the required GitHub workflows, including the live
`recorder-ci.yml`, `recorder-license.yml`, `recorder-security.yml`,
`codeql.yml`, and `e2e.yml` runs for that exact commit. The live kind job builds the real Fabric
Node image and proves:

1. accepted telemetry reaches the controlled destination;
2. a forbidden content marker cannot leave Fabric Node;
3. telemetry queued during a destination outage survives a Node restart; and
4. delivery resumes when the destination returns.

Each customer must also qualify its own connectors, certificates, identity
mapping, storage class, egress path, destination acknowledgements, retention,
deduplication, alerting, and operational recovery.

## Known boundaries

- Passive shadow capture can record only activity exposed by SDKs, adapters,
  gateways, vendor APIs, or existing telemetry. Fabric must not infer invisible
  internal reasoning as fact.
- At-least-once delivery can duplicate events; destinations must deduplicate
  using preserved trace/span identity or identities added by an adapter.
- OTLP acceptance is not evidence of durable retention.
- Metadata-only protection reduces export exposure but does not establish legal
  de-identification or prevent PII from reaching the monitored model.
- Historical and experimental source can remain visible in the public Git
  repository during migration; release tests must prove it is absent from the
  recorder binaries, chart, SDK packages, and installer surface.

## Custom-agent call recorder build — NO-GO (2026-09-29)

The second local build phase (spec 043 F–I) is implemented and locally tested:
metadata-only custom-call Node publication, asynchronous source-journal
linkage, authorized masked-review resolution and exact-package/sink tests.
The artifacts are uncommitted worktree builds, not a signed release candidate.

[Spec 043](../specs/043-custom-agent-call-recording.md) was written before
implementation. The following evidence was obtained locally on 2026-09-30,
in the PR worktree based on `efcf36c` with the uncommitted spec-043 changes.
These are locally tested SDK additions, not a clean tagged release or a
customer-production approval.

| Area | Implemented and locally tested | Still unverified |
| --- | --- | --- |
| Custom call recording | `CallRecorder` joins safe tracing, operation/attempt/agent parents, exact byte content, sync/async calls and streams; 12 focused tests | Final provider-bound placement, deployment route closure, production overhead |
| Privacy and identity | Per-role original/omit/masked-only/original-plus-masked policies; background customer transform; separate review namespace; no raw fallback; attempt-ID fixes; governed legacy/raw-span conflict checks | Customer PII detector accuracy, actual IAM/KMS isolation, other independently installed instrumentors, hung callback recovery |
| Offline comparison | Exact bytes, outcomes, sequence/lifecycle links, stream closure, bypass, corruption, SQLite state readback, and separate masked-review resolution | Authenticated independent feeds, target IAM/KMS proof and stage-specific trusted receipts |
| Source journal | Call events and outcomes use the asynchronous local journal; recovery, overflow, corrupt records and recording-failure behavior are unit tested | Crash gap before fsync, trusted source credentials, durable original-content queue |
| Metadata delivery | Call records project through the strict Node allowlist; installed-wheel Docker pilot read back all 52 expected records by ID and safe fields from a controlled fsyncing sink after sink outage and Node restart, with no private canary in OTLP, queue or logs | Authenticated target ingress, customer destination durability and four-stage receipts |
| Installed package | Final wheel smoke: 5 calls, 12 exact objects, zero fixture discrepancies; clean `unverified`, direct DB bypass/corruption/privacy failure `partial`; wheel and sdist package-content checks passed | Exact-image Linux kind/BPF and customer shadow pilot, signed release/customer control review |

Reproduction from repository root (Python environment includes project dev
dependencies):

```sh
cd sdk/python
COVERAGE_FILE=/private/tmp/fabric-custom-agent-branch-coverage .venv/bin/python -m pytest -q -o cache_dir=/private/tmp/fabric-custom-agent-pytest
cd ../..
sdk/python/.venv/bin/python scripts/contracts/validate_evidence_contracts.py
sdk/python/.venv/bin/python -m pytest -q --no-cov scripts/tests/test_release_qualification.py
uv build --out-dir /path/to/evidence/dist sdk/python
# Install that exact wheel in a new virtual environment, then:
/path/to/evidence/venv/bin/python scripts/qualification/run_custom_agent_smoke.py
```

Results: **767 SDK tests passed**, package-configured branch coverage **86.30%**;
21 release-qualifier tests passed; 17 pinned evidence/content-v2 artifacts
validated; Ruff and changed-module strict type checks passed. Four existing
HTTP tests first failed because sandbox loopback binding was forbidden; the
full suite passed after approved loopback access. No target test is credited
from that permission-only retry.

The final locally tested wheel SHA-256 is
`370de83edb6597ab1274ae7f0adf5860c547a031918247763b88be4c41070774`;
sdist SHA-256 is
`737330d53e1b20a3c2d8f547a9de74fc2299e0f9f4721b35b1abf6e4cdc729b3`.
Package-content/version qualification passed for these artifacts. The Node
image ID was
`sha256:c3c140948b672670016fe826243117d0b79adfbbca5b8c6dfbfa085376507d35`.
The production-profile CI definition now runs the custom smoke against its
built wheel; that new workflow has **not** been run remotely for these changes.

Second-phase local evidence (macOS host, disposable Linux Docker containers,
synthetic-only data): **827 SDK tests passed**, package-configured branch
coverage **86.38%**; 118 focused recorder/pilot tests passed; 21 release
qualification tests passed; 17 contract artifacts validated; changed-module
strict mypy, Ruff and guard Go race tests passed. A fresh venv installed the
final wheel with the `otlp` extra. The installed-file check matched the wheel.
The final pilot report at
`/private/tmp/fabric-custom-agent-phase2.wtiRUH/final-pilot/node-pilot-report.json`
reports 52/52 exact metadata records, controlled-sink fsync readback,
outage/restart and privacy canary checks passed, and `NO_GO`.

Reproduce the exact local pilot from repository root, using a new empty
evidence directory and an image built from the same source:

```sh
uv build --out-dir /private/tmp/fabric-custom-agent-phase2.wtiRUH/final-dist sdk/python
uv venv /private/tmp/fabric-custom-agent-phase2.wtiRUH/final-venv --python 3.12
uv pip install --python /private/tmp/fabric-custom-agent-phase2.wtiRUH/final-venv/bin/python '/private/tmp/fabric-custom-agent-phase2.wtiRUH/final-dist/singleaxis_fabric-0.8.0rc1-py3-none-any.whl[otlp]'
/private/tmp/fabric-custom-agent-phase2.wtiRUH/final-venv/bin/python scripts/qualification/run_custom_agent_node_pilot.py \
  --node-image local/fabric-custom-agent:qualification-1790707930609 \
  --installed-python /private/tmp/fabric-custom-agent-phase2.wtiRUH/final-venv/bin/python \
  --wheel /private/tmp/fabric-custom-agent-phase2.wtiRUH/final-dist/singleaxis_fabric-0.8.0rc1-py3-none-any.whl \
  --evidence-dir /private/tmp/fabric-custom-agent-phase2.wtiRUH/new-pilot
```

The exact local image tag is not an immutable distribution reference; the
pilot resolves and checks its image ID. The controlled sink is a fixture, not
the customer's OTLP destination or protected content store. No Linux host
BPF, target Kubernetes network policy, customer encryption/tenant isolation,
disk-full/retention/restore/key rotation, authenticated provider/DB feed or
independently witnessed customer run was exercised in this phase.

The smoke's provider is an in-process fixture. SQLite readback demonstrates
committed state, not a trusted DB audit trail. Source identity is
caller-reported; the asynchronous metadata journal does not close the
pre-fsync window, and raw queued content is not crash safe. All four trusted
receipt stages remain unavailable. The local Node/sink test is not the
exact-artifact target Kubernetes/BPF, storage-control or customer shadow
pilot under specs 037–039. Release/platform/storage/customer owners must
supply those proofs. Critical-enterprise status remains **NO-GO**.

PR #164 Linux CI on head `efffd30` additionally passed the installed-wheel
custom-agent smoke (5 calls, 12 byte objects, zero fixture discrepancies),
the isolated kind production-profile job (22 custom-call and 4 privacy-fault
metadata records read back exactly from its controlled sink), the Fabric Node
processor/image jobs, and the broader kind smoke. That is a synthetic CI
environment, not the customer's signed target. The head had Python mypy and
source-format failures in new tests/scripts; the following commit fixes those
and requires a fresh run before those gates can be credited. The history-wide
gitleaks job still reports eight matches in older commits, none introduced by
this change according to local redacted scan; security must classify them.
CodeQL reports two module-import-cycle errors on `TYPE_CHECKING`-guarded
imports and a warning about the new resolver's file-descriptor cleanup; the
security owner must review those findings rather than treating the check as
passed. No owner sign-off or production GO is inferred from CI.

## GPT-6 Sol subscription-backed laptop stage — NO-GO

The [bounded synthetic Sol stage](../qualification/sol-local-stage/README.md)
ran a real `gpt-6-sol` Codex CLI agent through a synthetic policy →
calculation → local telemetry/DB → Git/file artifact → ticket workflow on the
laptop. The [observed results](../qualification/sol-local-stage/local-results.md)
give exact source/artifact hashes, private evidence locations and commands.
The completed live run reconciled three independently fsynced service
operations and the two output artifacts with zero local discrepancies; its
verdict remained `unverified`. An unwrapped direct request and a corrupted
byte object lower the reconciler verdict to `partial` in targeted tests.

Using the installed local wheel, an offline Fabric projection stored and
resolved 38/38 observed byte objects and emitted 50 explicit unsupported
provider-bound/terminal-stream events. The protected metadata traversed
the disposable kind Node's mTLS ingress, and all 88 projected records were
parsed from fsynced controlled-sink files with exact ID/name/attribute
matching. No content canary appeared in OTLP, copied sink bytes or recent
Node logs. This qualifies **only** local post-run byte storage and synthetic
metadata delivery. It does not turn Codex JSONL into the final provider
request/response or raw ordered terminal streams, establish a passive
source-authenticated adapter, or qualify customer storage and reachable
routes. The full-workflow and production decision remain **NO-GO**.
