# Cloud evidence qualification — 2026-10-02

The composed local Collector functional gate now executes successfully. This
is a draft qualification of the standalone CAPTURE → PROTECT → DELIVER product,
not customer production approval. No merge, deployment, security-alert dismissal
or security-gate reduction is part of this work.

## Source and restoration boundary

The configured checkout is `singleaxis/singleaxis-fabric`. Work begins at
published PR #165 revision `acf7fbf8d2950331559aadc67c4576375dc0ca57`, preserving
its PR #164 base. No other repository was changed. Contributions retain
`Signed-off-by: Bryan <bryan@singleaxis.ai>`.

Both supplied Library handoffs failed to download in this consumer executor,
including the one supported retry with an explicit local destination. Therefore
checkpoint `1f119c91c9462a7aef9f2dd0d8d633b0f3604c7f`, its four desktop cleanup
commits and its review ledger were **not restored or adopted**. This cloud work
is independently implemented on the published parent. Reconcile those commits
after a verified transfer; do not assume they are present here.

The current Library materialization flow and bundled transfer helper were used,
including one retry targeting `/workspace/fabric-handoffs/retry`. Both inputs
returned `library file transfer failed: download failed`; no readable archive
arrived. The tools did not report an explicit permission denial. The underlying
download failure is unresolved; no alternate private URL or denied route was
used. Neither supplied archive SHA-256 can be verified without its bytes.

| Desktop logical change, as described in the handoff | Independent cloud status |
|---|---|
| Consolidate SDK hashing | Independently consolidated equivalent Python text and TypeScript byte/text helpers; encoding and outputs regression-tested |
| Remove proven unused Go internals | Independent dependency review found both current private packages required by the released CLI; retained |
| Move the legacy tailer into tests | Independently moved with identical bytes and attribution; durable production tailer retained |
| Repair license gate wiring and related docs | Independently repaired and expanded; desktop patch equivalence unverified |

These are logical groupings from the handoff description; the four desktop
commit boundaries could not be inspected. The cloud parent chain is
`dd7e2683 → 18ec69a4 → acf7fbf8 → 24e50931 → 060dd983 → 059d5474 → 0c057678 → ee2b3dd0 → 2757a117 → 0ad942bf`.
The first cloud checkpoint comprises `24e50931`, `060dd983` and `059d5474`, each
with the approved DCO. Later cloud commits and the current PR follow-ups are
descendants of that chain, not of the unavailable desktop checkpoint.

The subsequent [Go and license reconciliation](../qualification/cloud-audit-go-license-reconciliation.json)
records reference and build-graph proof for retained packages, the byte-identical
test-only move, and existing reconstruction-path and synthetic-provenance checks.
No cleanup was inferred merely from an unused-looking filename. The license
follow-up fixes permissive substring matching, expression grouping, conflicting
declarations and empty inventories; the unchanged policy now also receives
isolated optional-install inventories and the actual patched Collector graph.

The [Python](../qualification/cloud-audit-python-codeql-followup.json) and
[TypeScript](../qualification/cloud-audit-typescript-security-followup.json)
reviews reconcile duplicate hashing while preserving encoding behavior and
public interfaces. Python private registry aliases retain initial identity;
rebinding private module constants across modules is not a supported interface.

## Security follow-up and application-network evidence

The exact `0ad942bf` checkpoint passed five workflows and all Recorder CI jobs;
source SAST still failed with five Semgrep findings, and the separate CodeQL
result check failed with 71 findings (three high, nine warnings, 59 notes).
The full generated CodeQL scan contains 88 locations, which is a different
scope. The read-only annotation diagnostic added afterward checks exact head,
PR, app, terminal status and annotation counts; it fails when that membership
cannot be verified. It does not accept or dismiss any finding.

[Permission and TLS follow-up](../qualification/cloud-audit-security-followup.json)
adds effective-directory-mode verification and explicit TLS floors. Its exact
upstream rule review demonstrates why the five Semgrep audit matches persist:
the numeric permission rule flags owner-only `0700`, and the HTTPS rule matches
every direct `HTTPSConnection` call. No API was renamed or replaced to evade a
query. The local rule reproduction is diagnostic evidence, not a substitute for
the hosted source gate. The benchmark canary remains byte-identical. The
TypeScript adapter still requires a customer-controlled ancestor namespace;
native directory-relative operations are outside its current portable API.

The [C8 matrix](../qualification/c8-network-capture-matrix.json) now records three
executed application-network scenarios. Four physical HTTP requests cover a
503/200 retry, a 400 response, and a lost response after an independent SQLite
commit. Seven prequeue-redacted content observations can be reopened by a fresh
authorized consumer. The lost-response caller remains uncertain until separate
service readback; evidence recovery does not repeat the effect. Loopback peer
metadata is distinct from HTTP semantics. This fixture does not establish host
packet capture, TLS plaintext interception, uninstrumented application contents,
remote authorization or production destination durability.

Final local checks, source hashes and rebuilt package identities for this
follow-up are in [security follow-up checks](../qualification/cloud-2026-10-02/security-followup-checks.json).
The final published head and terminal hosted results are recorded on draft PR165.

The published reconstruction defect was independently reproduced: two stored
descriptors and two journal object IDs, but four exported records with zero
content joins and two historical pending statuses.

## Composed functional evidence

The [runnable journey](../scripts/qualification/run_composed_collector_journey.py)
uses owner-only stable key files, the existing governed encrypted store, the
source journal and sender, the built Fabric Collector, a fsynced loopback
destination and a separate authorized consumer process. The independent SQLite
fixture records one business effect. Recovery never invokes that effect again.

The [capture matrix](../qualification/composed-collector-capture-matrix.json)
records eight received metadata records, four unique identities and two
verified content objects. The first destination ACK is lost; the Collector is
killed while delivery remains outstanding, then reopens its durable queue.
The consumer deduplicates, orders and reads the content from durable state.
Tenant, policy, key, missing-object, corrupt-ciphertext and truncated-envelope
faults refuse content availability. This qualifies a local fixture: production
TLS/authentication, customer IAM/KMS, remote durability and pre-fsync loss remain
separate obligations.

Pending metadata is an immutable admission observation. Current verified
content availability is a separate result. Neither result proves complete
capture or producer closure. A root return explicitly leaves producer closure
unknown; inherited background work can continue.

The separate qualified-run verifier still uses a legacy original-byte resolver
and settled-snapshot receipt identities. Its `verified_complete` result is not
qualified for the new governed journal journey. Pre-change journals without
policy/privacy bindings remain unverified by strict governed reconstruction.

See the [onboarding and readback guide](standalone-evidence-guide.md) for
integration, storage ownership and demonstration commands, and the
[qualification map](evidence-qualification-map.md) for C0–C10 boundaries.

## Executed cloud checks

The [check record and captured logs](../qualification/cloud-2026-10-02/checks.json)
record 1,711 Python tests with 88.65% coverage, CI-pinned Ruff 0.13.0 and mypy,
380 TypeScript tests and six package tests. The final Python runtime, tests and artifact qualifier remained unchanged
during this full run. An earlier 1,689-test run and its focused annotation
recheck are also retained for provenance.
Python wheel/sdist and TypeScript ESM/CommonJS/type artifacts were built and
checked. Artifact topology checks do not prove runtime coverage by themselves.

The [follow-up check record](../qualification/cloud-2026-10-02/followup-checks.json)
adds 1,721 passing Python tests with unchanged source hashes during the run,
433 TypeScript tests, six package tests and a composed journey from a freshly
installed Python wheel. The fresh consumer imported that installed package;
its Python file hashes match the reviewed checkout. The same wrong-binding and
corruption faults refused content, and the independent business-effect count
remained one. This installed-artifact run supersedes the earlier source-only
journey limitation; customer authentication and production qualification remain
outside its scope.

The [final local check record](../qualification/cloud-2026-10-02/final-checks.json)
supersedes those earlier test totals: 1,754 Python tests with 88.79% coverage,
453 TypeScript tests, six package tests and 457 repository tests passed.
CI-version mypy passed 138 files. The final wheel and sdist passed both artifact
inspectors; the installed wheel repeated the real Collector journey with the
fresh consumer and fault refusals. File snapshots stayed unchanged during the
full SDK runs. The record binds these tested working bytes by hash; its checkout
head alone is not a claim that uncommitted changes were absent.

The repository run skipped 43 unavailable Helm checks and seven unconfigured
live-S3 checks, and excluded the three separately attempted Docker tests.
Follow-up CI installs the TypeScript driver so emitted-manifest schema tests
execute there as well. All 15 local pre-commit hooks and the pinned Markdown
linter passed; Markdown used the registry package because npm blocked the hook's
Git installation. No npm security setting was changed.

CI at `2757a117` exposed four test/setup issues: Node 20 lazy-stack fixture
construction, incomplete synthetic certificate extensions rejected by Python
3.13 strict verification, Helm ignore rules excluding the health-test hook,
and the queue privacy probe's mismatched filesystem identity. The
[CI portability follow-up](../qualification/cloud-2026-10-02/ci-followup-checks.json)
records their fixes and local checks: 453 tests on Node 20, 16 strict TLS cases,
mypy across 138 files and 477 repository tests. Runtime SDK bytes and the
installed-wheel journey remain unchanged; live Helm/Docker checks require CI.

The selected C0–C7, C9 and C10 fixture checks passed; C8 application-network
semantics remains `NOT_IMPLEMENTED`. Each level retains explicit unimplemented
scenarios. These fixture passes do not close all producers or qualify every
requested real-world boundary. Native Go checks and the actual Collector
journey add separate evidence; live BPF and the Docker tests remain bounded as
described below.

At that checkpoint, repository checks passed 303 tests and skipped 51:
43 Helm render checks because Helm is absent, seven live-S3 checks because
no endpoint, bucket or credentials are configured, and one source-binding test
because its isolated gRPC extra was absent. That extra was installed for the
follow-up and its regressions now execute. An attempt to install the
CI-pinned Helm 3.15.0 binary from the official download endpoint received
HTTP 403, so no alternate route was used. Three Docker Compose tests had been
attempted separately and could not start because Docker Hub returned HTTP 429.

The follow-up protects TypeScript decision/execution callback diagnostics,
including LLM/tool wrappers, using a closed error classification and static
message. Direct host-exporter canary regressions pass. This is not a general
sanitizer for externally supplied spans and does not establish Python's managed
export or durable governed journal/reconstruction parity. Its local store
rejects symlink redirection and nonregular objects, but Node's path APIs do not
close a concurrent ancestor-replacement race.

## Audit and remaining qualification

The [published-path inventory](../qualification/cloud-audit-inventory.json)
accounts for all 1,035 original paths. The
[audit index](../qualification/cloud-audit-index.json) links every original
path to at least one declared review method. The adjacent cloud audit ledgers state
per-file hashes, review methods, findings and limitations. Inventory, syntax
checks, test execution and targeted semantic review are distinct. The missing
desktop ledger prevents verification of its claimed 560 reviewed paths or
reconciliation of the 475 deeper reviews. Follow-up ledgers now provide manual
semantic review for those 48 Python test paths, the remaining runtime modules,
documentation, scripts, charts and Compose files. Contract fixtures and frozen
benchmark evidence use their declared structural, oracle and provenance checks.
The index distinguishes current byte-matched reviews from historical entries.
All 1,035 original paths now have a review reference matching their current
bytes; the later TypeScript ledgers include all runtime files and test/config
paths. All 326 benchmark paths remain unchanged, including the indexed evidence.
Role-appropriate coverage of every original path does not mean exhaustive
line-by-line security review of every file or of dependency implementations;
targeted-review limits and open findings remain explicit.

All 324 indexed benchmark artifacts retain their SHA-256 values; no benchmark
measurements were rerun or attributed to this new runtime. The generated
`vmlinux.h` bytes also remain unchanged. Its original BTF input provenance is
unknown and is recorded as such.

The independently read CodeQL result gate for checkpoint `059d5474` failed with
62 findings: two high, six warnings and 54 notes
([check](https://github.com/singleaxis/singleaxis-fabric/runs/111017078281)).
Its language-analysis workflow succeeded; that does not clear the result gate.
The earlier 58 findings belong to `acf7fbf8`, not this checkpoint. Exact current
annotation/alert endpoints are unavailable through the connector; finding
identities must not be inferred from the old triage.

The strengthened Semgrep source gate also failed with five findings. Its
separate SARIF check reports four new warnings; these are different counts.
An independent local rerun could not obtain the rules: the proxy returned
HTTP 403 for `semgrep.dev`. No alternate route, finding suppression or gate
reduction was used.

The diagnostic checkpoint `ee2b3dd0` subsequently passed five workflows,
including Recorder CI, license compliance and both integration workflows.
Recorder security still failed with five Semgrep findings, and its separate
CodeQL result gate reported 67 findings: two high, seven warnings and 58 notes.
The [diagnostic record](../qualification/cloud-2026-10-02/diagnostic-checkpoint.json)
distinguishes those PR findings from the 87 whole-scan CodeQL locations.
The workflows now print rule IDs and locations from their own generated SARIF,
without source snippets or messages; no remote alert API route is bypassed.
Current findings can therefore be inspected despite the connector limitation.
No findings are suppressed or accepted by this change. The final follow-up
head must be scanned and assessed separately.

Native auditreceiver unit/race checks and cross-compilation do not qualify live
kernel capture. The checkpoint CI generated BPF bindings and passed its host
build and image checks, which remain distinct from a live kernel experiment.
It also passed Helm and Docker-backed contract tests. Locally, Helm downloads
were blocked and Docker Hub rate limits prevented the Compose image setup;
the composed journey builds the pinned Collector and runs that real binary.
Changed chart and Compose regressions require the follow-up head's CI results.
