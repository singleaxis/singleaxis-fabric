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

The selected C0–C7, C9 and C10 fixture checks passed; C8 application-network
semantics remains `NOT_IMPLEMENTED`. Each level retains explicit unimplemented
scenarios. These fixture passes do not close all producers or qualify every
requested real-world boundary. Native Go checks and the actual Collector
journey add separate evidence; live BPF and the Docker tests remain bounded as
described below.

TypeScript still exports raw exception messages/stacks through an externally
owned span provider in some APIs. It does not have Python's managed metadata
export protection or durable governed journal/reconstruction parity. Its local
store now rejects symlink redirection and nonregular objects, but Node's path
APIs do not close a concurrent ancestor-replacement race. Deployments must not
claim uniform pre-persistence protection from the TypeScript subset.

## Audit and remaining qualification

The [published-path inventory](../qualification/cloud-audit-inventory.json)
accounts for all 1,035 original paths. The
[audit index](../qualification/cloud-audit-index.json) links every original
path to at least one declared review method. The adjacent cloud audit ledgers state
per-file hashes, review methods, findings and limitations. Inventory, syntax
checks, test execution and targeted semantic review are distinct. The missing
desktop ledger prevents verification of its claimed 560 reviewed paths or
reconciliation of the 475 deeper reviews. **An every-file deep audit is not
complete:** 48 paths in the remaining Python ledger still have structural-only
review, and other ledgers retain explicit targeted-review limits.

All 324 indexed benchmark artifacts retain their SHA-256 values; no benchmark
measurements were rerun or attributed to this new runtime. The generated
`vmlinux.h` bytes also remain unchanged. Its original BTF input provenance is
unknown and is recorded as such.

The published CodeQL result gate remains a security review blocker: the handoff
and PR report 58 findings, including the synthetic raw benchmark canary. This
executor could not retrieve the current annotation set through its available
GitHub read endpoint. No finding was suppressed or dismissed. New-head CI must
be evaluated separately from the earlier six successful workflow runs.

Native auditreceiver unit/race checks and cross-compilation do not qualify live
kernel capture. The full host emitter still needs generated BPF bindings and
its compiler/toolchain. Docker is available, but Docker Hub rate limits blocked
the existing Compose image-backed test setup; the composed journey instead
builds the pinned Collector source and runs that real binary locally.
