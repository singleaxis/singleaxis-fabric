# Enterprise capture reference validation

This build implements and qualifies the finite Python local reference path.
It does **not** qualify a customer production deployment or claim unconditional
loss-free capture. The application remains passive; admission before durable
fsync is unknown unless separately witnessed.

## Implemented and exercised

- Protected-byte AES-256-GCM spool, fsynced admission, stable IDs, replay,
  crash-consistent settlement/cleanup, retry/retention/capacity and sticky loss
  accounting. Existing governed encrypted storage/privacy paths are reused.
- Journal-backed metadata outbox, immutable bounded batches, durable ACK ledger
  and cursor, transient retries and permanent/partial rejection accounting.
  HTTP Node acceptance remains distinct from destination durability.
- Separate OS-process reference ingress and destination, authenticated
  tenant/run/scope, independent persisted inventories, exact-set signatures and
  fresh object readback. The reference ingress is not the production OTel Node.
- Explicit HTTP/1.1 final-body adapter, independent receiver truth, physical
  retry/bypass/partial-stream/terminal accounting and passive-failure tests.
- Signed source/child registration, authenticated propagated context, expected
  child joins, multi-source/recovered-epoch closure and a precommitted separate
  local coordinator witness. Automatic distributed hook installation is not
  claimed.
- Versioned configuration lifecycle, verified workload/operator adapters,
  least-privilege readback and drift, explicit SDK capabilities, and inert
  future external-control contracts. No portal UI or enforcement engine.

## Executable campaign

```sh
python examples/enterprise-reference/run.py --output /tmp/fabric-reference-UNIQUE --iterations 20
```

The campaign runs actual instrumented HTTP calls and uninstrumented baselines,
retains encrypted protected objects during destination outage, SIGKILLs the
separate ingress and destination processes, reopens source journal/byte
spool/sender, and independently enumerates and rereads destination contents.
Expected identities are frozen **before** restart and cross-checked with source
object references. Recovered inventory cannot redefine what was expected.
Loss/unknown counters and missing/failed closure prevent a local PASS.

An independent adversarial review found and fixed four concrete problems:
empty-ingress rows bypassing payload-only capacity; recovery inventory shrink
being used to redefine sample expectations; and persisted loss counters being
downgraded after reopening; and aggregate success ignoring failed/missing
distributed closure. New negative regressions reproduce all four.
The final review reran these reproductions and confirmed their rejection.

The report exposes actual overhead, CPU, peak process RSS, backlog occupancy,
outage and recovery time. These measurements have an explicit local workload
and no invented universal production budget. The source/process/key custody
trust boundaries are reported separately from test success.

## Test commands

```sh
(cd sdk/python && python -m pytest tests -q)
(cd sdk/python && python -m mypy src/fabric)
(cd sdk/python && python -m ruff check src tests)
(cd sdk/python && python -m ruff format --check src tests)
python -m pytest scripts/tests -q -rs
(cd sdk/typescript && npm run typecheck && npm test && npm run build)
(cd sdk/typescript && npm run lint && npm run format && npm run test:package)
```

For Go, run `go test ./...` in the gate, guard processor, audit receiver and
fabricctl modules. The host-emitter's portable logic can be tested with its
explicit non-Linux stub source list; that is not a native sensor build/test.

## Audit logfile durability

The logfile receiver now requires an absolute, private persistent
`state_directory` and atomically persists a scrubbed replay batch together with
its accepted cursor. It advances only after downstream acceptance and fsynced
checkpoint replacement. Duplicate replay retains stable record IDs; rotating,
truncated, missing, malformed or oversized source evidence cannot silently
become a complete-host claim. Numeric retained rotations are supported within
a bounded inventory. Netlink remains explicitly non-replayable.

The implementation and independent review exercised actual abrupt child-process
termination, multiple retained rotations, accepted-but-uncheckpointed replay,
permanent rejection, cursor/source mutation, bounded discard/argv handling,
FIFO rejection and guard preservation of typed loss/identity fields. See the
[audit receiver migration contract](../components/otel-collector-fabric/receiver/auditreceiver/README.md).

## Not qualified here

- Actual production OTel Node restart/TLS/auth deployment (Docker unavailable).
- Live S3/cloud IAM/KMS/legal hold/residency (target and credentials unavailable).
- Native auditd/netlink/eBPF privileges, generated BPF object and target kernel.
- TypeScript durable spool/call/journal/closure parity; its supported subset is
  documented in the [SDK matrix](sdk-support-matrix.md).
- Arbitrary provider/framework routes, automatic completeness, production
  workload/throughput/outage budgets, fleet rollout or action enforcement.

A skip means untested, never passed. The [build specification](specs/enterprise-capture-build.md)
and [easy integration guide](enterprise-testing-quickstart.md) distinguish implementation,
reference verification and customer target qualification.

## Recorded local regression result (2026-10-02)

- Python configured full suite: **1,569 passed**, **88.40%** branch-aware coverage;
  required coverage gate is 85%. Strict mypy: 65 source files clean. Ruff and
  formatting checks passed.
- Repository suite: **337 passed, 10 skipped**. The skips are three Docker Node
  integration cases and seven unconfigured live S3 cases.
- TypeScript: **369 tests plus 5 package-contract tests passed**; typecheck,
  build, lint and formatting passed. Exact npm tarball allowlist/integrity
  qualification passed.
- Fresh Python wheel and source distribution passed the recorder artifact
  allowlist checks. The extracted wheel ran the separate-process reference
  campaign, including destination recovery and required distributed closure.
- Audit logfile receiver: **56 test cases/subcases passed** under the race
  detector; receiver vet passed. Guard processor: **61 test cases/subcases
  passed** under the race detector. Independent review and additional repeated
  restart/unaligned-boundary tests passed. Updated audit connector artifact
  digests and persistent-volume migration/config checks passed.
- Gate and fabricctl Go module tests passed. Portable host
  emitter metadata/spool tests passed with the explicitly supplied non-Linux
  stub; the native Linux build remains blocked by unavailable generated BPF
  bindings/toolchain and is not reported as passed.

The core reference workload reconciles 80 metadata records and 40 protected
objects for 20 actual final HTTP calls. These are finite local results, not a
comparative market benchmark or customer throughput guarantee.

## Publication follow-up validation

The publishing Mac exposed concurrent lock creation failures in the governed
store: a minimal eight-thread probe produced ENOENT with combined O_CREAT
opens, while exclusive creation followed by existing-file opens completed
20 trials without errors. The store now uses that atomic creation boundary
with the same O_NOFOLLOW, private-file validation and flock enforcement.
This qualifies that observed race fix, not every Mac/filesystem deployment.

The frozen matched benchmark remains tied to initial PR commit
`18ec69a4ddd6e5fdab7a097b30b34571096e708f`. Publication follow-ups correct
CI tests/hygiene and close-error handling; they are not a rerun of the
matched campaign. The current benchmark artifact index scopes itself to
324 supplied files; 63 omitted stderr diagnostics are disclosed separately.
