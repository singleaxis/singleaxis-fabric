# Recorder cleanup audit

Status: maintainer working document. Not a product claim and not a spec.
Baseline: branch `chore/recorder-cleanup` at `c3f1e51` (PR #185 head, the wire
capture line stacked on `origin/main` `4a5c945`).
Scope boundary: `AGENTS.md` (CAPTURE -> PROTECT -> DELIVER, passive).
Target: the shared target architecture used by the spec 049 rev 4 track:

1. two inputs: **wire** (`fabric.wire` httpx/httpx2 tee) and **records**
   (Decision `record_*`, `tool_call()`, `llm_call()`, with `CallRecorder`
   folded in as a records producer);
2. one durable agent spool (the wire spool is the base);
3. one sequencer per `(source, epoch)`, one loss/heartbeat/manifest model;
4. one content writer path: agent -> `otlp/content` -> Node `fabriccontent`
   -> file or S3-compatible store;
5. one offline verifier: `fabric.reconstruct`;
6. no framework adapters;
7. everything else is merged into that path or deleted (history stays in git).

Where main's explicit evidence line (specs 035–046) holds a guarantee the
target needs, the guarantee is kept and moved, not dropped. Deleting a
merged-on-main evidence module needs owner sign-off.

## How to read this document

**Classes.**

- **KEEP**: on the target path; stays as it is (it may still be edited).
- **MERGE→X**: holds a guarantee the target needs; the guarantee moves to X
  and the module is then removed. Used for code that is *not* part of the
  035–046 evidence line.
- **DELETE**: dead, out of scope per AGENTS.md, superseded, or a framework
  adapter. "Blocked" means a KEEP or MERGE module still depends on it, so it
  cannot be removed without a code change.
- **OWNER**: first merged on main in #164 (`804f40b`) or #165 (`4a5c945`) as
  part of the 035–046 explicit evidence line (CallRecorder line, byte path,
  governed storage, offline verification, enterprise/deployment helpers and
  their qualification apparatus). Merging or deleting it needs owner
  sign-off. Each OWNER row carries a recommendation (`rec:`).

#164 and #165 were large squashes. They also carried code for older specs
(022–034: records surface, governed content). That code is classified on its
merits, not as OWNER.

**Evidence of use.** "Users" lists were produced by an AST import graph over
every `.py` file in the repository (relative and absolute imports, plus
string module names such as `importlib.import_module("fabric.x")`), a
symbol grep for names re-exported from `fabric/__init__.py`, and plain grep
for non-Python surfaces (workflows, charts, compose, contracts, docs).
"tests" means `sdk/python/tests` unless prefixed `scripts/tests`. The
introducing commit was taken from `git log --diff-filter=A`.

**Line counts and `file:line` references** are at `c3f1e51` unless a
row says otherwise.

## 1. Headline findings

1. **Duplicate durable spools: five, not three.**
   - `wire/_spool.py` (735): the target base. fsync'd, flock-admitted,
     fork-safe, shared bound across processes.
   - `byte_spool.py` (672): encrypted (AES-256-GCM) protected-byte spool.
   - `source_spool.py` (915): metadata journal with epoch seal.
   - `_content_writer.py` "spooled" mode (830, Python): records content.
   - `sdk/typescript/src/content-writer.ts` `fabric.content-spool/v2` (871).
   - Outside the agent: `components/host-emitter` has its own spool. That
     one is a separate binary and is in scope only as a host sensor.
2. **Four agent-side content writers, plus one on the Node.**
   - Python: `_content_writer.py`/`_content_sink.py` (records content,
     writes the store directly from the agent), `byte_evidence.py` (bounded
     handoff to a store), `governed_store.py` (encrypting local store),
     `content_store/` (store protocol and local/S3 writers).
   - TypeScript: `content-writer.ts` and `byte-evidence.ts`.
   - `independent_store.py` is a read-only witness store, not a writer.
   - Only `wire/_sender.py` -> Node `fabriccontentexporter` follows the
     target path.
3. **Six offline readers/verifiers besides `fabric.reconstruct`.**
   - `resolver.py` (ContentResolver plus `python -m fabric.resolver`),
     `byte_resolver.py`, `governed_reconstruction.py`,
     `synthetic_reconcile.py`, `call_reconcile.py`, `qualified_run.py`.
   - Also `distributed_closure.py`, `independent_feed.py`,
     `receipt_sets.py`, the TypeScript `resolver.ts`, and
     `examples/agent-orchestration/reconstruct.py`.
4. **Three OTLP projectors for the explicit line.** `synthetic_otlp.py`,
   `call_otlp.py` and `metadata_delivery.py` all ship evidence-class
   metadata to the Node. The wire line ships through `wire/_sender.py`.
5. **Two loss models.** The wire `_loss.py` (coalesced ranges plus
   heartbeats) and the explicit line's per-recorder counters
   (`_capture_health.py`, byte-evidence status counts, source-spool
   sequence gaps). The TypeScript SDK has a third, `FlushResult` counters.
6. **One framework adapter left: CrewAI.** It was pre-approved for deletion
   and is removed in this change (section 9). No framework adapter remains
   in either SDK or in `components/`.
7. **Release-surface items that are dead or stale but on the evidence line:**
   - `benchmarks/fabric-comparison` (45,189 lines, mostly frozen evidence).
     Nothing runs it; 32 of its 66 pinned SDK file hashes already drift.
   - Most of `qualification/` (98,075 lines). Only
     `synthetic-slice/kind-production-*.yaml` is read by CI.
   - Sol/Codex and "local GO" rehearsal scripts that nothing invokes.
   - These are OWNER items. None is deleted here.
8. **Spec drift found while auditing.** Spec 049 P4 says the auditd
   receiver's netlink path "currently splits raw frames". It does not:
   `receiver/auditreceiver/netlink_linux.go:317-347` (`decodeAuditNetlink`)
   parses `nlmsghdr` lengths and types, handles alignment and rejects
   `NLMSG_ERROR`/`OVERRUN`, with tests at `netlink_linux_test.go:82,94`
   (from #165). The spec item looks stale.

## 2. Guarantees TARGET.md does not cover (for the spec rev 4 agent)

Each row is a guarantee held by a MERGE or OWNER module that has no stated
home in the target. The spec should either place it or drop it explicitly.

| # | Guarantee | Held by today | Gap in the target |
|---|---|---|---|
| G1 | **Encryption at rest of protected bytes on the agent**, with a customer-supplied key (AES-256-GCM, no-follow private files). | `byte_spool.py`, `governed_store.py` | `wire/_spool.py` writes exact bodies in plaintext. The Node writes S3 with mandatory SSE (`fabriccontentexporter/config.go:58`), but the agent spool and the Node directory backend are plaintext. Target item 2 ("one spool, wire spool is the base") silently drops encryption at rest. |
| G2 | **Protect before persistence.** Privacy modes (`omit`, `redact`, `tokenize` with a scoped HMAC, masked-only, original plus a separately referenced masked review copy). A transform failure withholds content with a fixed reason and never falls back to raw. `protection_status` is recorded. | `deployment_policy.py`, `byte_evidence.py`, `governed_store.py`; TS `deployment-policy.ts`, `byte-evidence.ts` | The target writer path (item 4) has no PROTECT stage. Wire stores raw exact bytes. Spec 049 F-A says `fabriccontent` is closed to the content-v2 privacy fields until a spec 050. AGENTS.md makes "protect the record before it crosses the customer boundary" part of the promise. **Highest-risk gap.** |
| G3 | **Source-end seal.** An explicit post-run seal: exact per-source high-water map plus SHA-256 over the ordered canonical record set, mode 0600, file and directory fsync, atomic replace. It fails closed on tail deletion, an extra record or a self-consistently rehashed substitution. Every prior epoch without a seal (even an empty one) is reported. | `source_spool.py` (`seal_epoch`), `call_recorder.py` (`seal_source`) | The wire allocator's `final` heartbeat (`_loss.py:209`) carries `last_sequence` only. Deleting that marker with the tail, or rehashing one record, is not detectable from a digest. Target item 3 ("one manifest model") must state whether the seal moves to the wire sequencer. |
| G4 | **Receipt and attestation contract.** Four separate stages (source-spooled, Node-accepted, destination-accepted, destination-durable), exact receipt sets, and Ed25519 statements against an owner-supplied trusted key registry. | `evidence_attestation.py`, `receipt_sets.py`, `qualified_run.py`, `reference_receipts.py`; contracts/evidence | `fabric.reconstruct` (target item 5) takes no receipts, attestations or witness feeds. AGENTS.md lists public delivery and integrity receipt contracts as in scope. Spec 049 already says no 049 phase emits `verified_complete_for_declared_scope`. Rev 4 should say whether that verdict lives in reconstruct or is retired. |
| G5 | **Authenticated source binding at the Node.** A dedicated bearer ingress bound to one tenant/source, a per-record identity check, and a non-retryable `INVALID_ARGUMENT` on a forged identity. | fabricguard `EvidenceSourceBinding`, gate dedicated-ingress checks, the bearer `require_single_token` patch, chart `evidenceSourceBinding` | With binding enabled, the guard accepts only evidence logs and rejects every trace batch (`fabricguardprocessor/processor.go:472-473`), so wire spans and content cannot use the bound ingress. Wire's `fabric.source.*` identity is unauthenticated. The target is silent on source authentication. |
| G6 | **Independent witness comparison.** Provider, filesystem and DB witnesses, route declarations, and known-bypass detection, giving a conservative `partial`/`unverified` verdict. | `call_reconcile.py`, `independent_feed.py`, `independent_store.py`, `synthetic_reconcile.py` | Reconstruct has no witness input. Spec 049 "Verification" still cites `call_reconcile` verdicts. |
| G7 | **Exact-byte capture at non-model boundaries**: the final HTTP body for any host, a no-shell subprocess (argv, stdin, stdout, stderr, exit), and file before/after bytes. | `http_dispatch.py` (FinalHTTPAdapter), `adapters/synthetic_evidence.py`, `adapters/byte_boundary.py` | The target names only `CallRecorder` as the explicit producer. Spec 049 P4 builds on these three. Rev 4 must say they fold into the records producer, or keep them. |
| G8 | **Per-decision transcript manifest** (content v1), with goldens in `contracts/content/v1` and Python/TS parity tests. | `_content.py`, `_content_sink.py`; TS `content.ts`, `content-sink.ts` | The target's "one manifest model" does not say whether content v1 manifests survive or are replaced by stitched wire runs. Retiring them changes a public contract family listed in `release-policy.json`. |
| G9 | **Tenant-scoped, authorized reads.** No telemetry-chosen path or URI, no symlink following, and a per-tenant store root. Masked review bytes can never satisfy an original requirement. | `byte_resolver.py`, `governed_reconstruction.py`, `resolver.py`, `governed_store.py` (HMAC capability grants) | `reconstruct/_objects.py` is tenant-scoped (`:197-202`). Capability grants and the review-versus-original distinction have no home. |
| G10 | **Host-sensor inputs.** auditd receiver and eBPF host emitter, kept by spec 049 as `corroborated_by` links, each with its own cursor or spool. | `components/otel-collector-fabric/receiver/auditreceiver`, `components/host-emitter`, `deploy/auditd`, `deploy/kubernetes` | "Two inputs only" leaves host sensors unstated. They are released artifacts (`release-policy.json` image `fabric-host-emitter`). Rev 4 should list them as corroboration-only inputs or move them out. |

## 3. Python SDK — `sdk/python/src/fabric` (34,452 lines incl. 2 taxonomy JSON files)

### 3.1 Wire line (specs 047/048; branch-only, not on main) — all KEEP

| Path | Lines | What it does | Users (verified) | Class | Risk if removed / co-changes |
|---|---|---|---|---|---|
| `wire/__init__.py` | 383 | `install()`/`install_from_env()`, public wire API. | `_autoload/sitecustomize`; 30+ `test_wire_*`; `scripts/tests/_wire_capture_agent.py`; `examples/wire-capture`; wheel qualifier (`CAPTURE_MEMBER_PREFIXES`) | KEEP | Target input 1. |
| `wire/__main__.py` | 27 | `python -m fabric.wire --print-autoload-path`. | `test_wire_install`, `test_wire_spool_replay`, `test_wire_spool_window`; `scripts/tests/_wire_capture_common.py` | KEEP | — |
| `wire/_config.py` | 231 | Env/config parsing, direct vs node mode, local store root. | wire `__init__`, `_sender`, `_transport`; 8 tests | KEEP | — |
| `wire/_content.py` | 148 | OTLP content client to the Node (`event_class=content`). | wire `__init__`, `_sender`; 3 tests | KEEP | Target writer path. |
| `wire/_match.py` | 61 | Provider endpoint matching. | `_pipeline`, `_transport` | KEEP | — |
| `wire/_model.py` | 94 | Exchange data model. | 7 wire modules; 6 tests | KEEP | — |
| `wire/_pipeline.py` | 426 | Exchange assembly, digests, span emission. | `_stream`, `_transport`; 2 tests | KEEP | — |
| `wire/_sender.py` | 410 | Spool drainer, delivery receipts (`.ack`). | wire `__init__`, `_pipeline`, `_transport`; 7 tests | KEEP | Target sender; MERGE destination for `metadata_delivery`, `call_otlp`. |
| `wire/_spool.py` | 735 | The agent durable spool. | `_sender`; 11 tests incl. `test_wire_spool_shared_bound` | KEEP | Target spool; MERGE destination for `byte_spool`, `source_spool`, `_content_writer` spooled mode. |
| `wire/_stream.py` | 592 | Non-blocking stream tee. | `_transport`; 6 tests | KEEP | — |
| `wire/_transport.py` | 446 | httpx/httpx2 transport wrapper. | wire `__init__`, `_stream`; 9 tests | KEEP | — |
| `_autoload/__init__.py` | 4 | Inert package marker. | wheel qualifier `AUTOLOAD_MEMBER` | KEEP | — |
| `_autoload/sitecustomize.py` | 69 | Env-gated `PYTHONPATH` bootstrap. | `test_wire_credential_logging`, `test_recorder_wheel_qualifier` | KEEP | — |
| `_loss.py` | 384 | Coalesced loss ranges and heartbeats (`final` seals an allocator). | 5 wire modules; 23 tests | KEEP | Target loss model; MERGE destination for `_capture_health`. |
| `_sequence.py` | 233 | One sequence per `(source_id, epoch)`, run scopes, pseudonyms. | `_loss`, `tracing`, `reconstruct/_ids`, 5 wire modules; 24 tests | KEEP | Target sequencer. |
| `_model_names.py` | 128 | Model-name exposure rule shared with reconstruct. | wire `_config`, `_pipeline`; reconstruct `__main__`, `_inputs`, `_verify`; 7 tests | KEEP | — |
| `_capture_scope.py` | 116 | "Explicit wins" scope (spec 049 D2). | `__init__`, `adapters/byte_boundary`, `call_recorder`, wire `_stream`, `_transport`; `test_wire_explicit_coexistence` | KEEP | Becomes internal to the records producer. |
| `_export_diagnostics.py` | 71 | Sanitized exporter diagnostics. | `tracing`, `_span_protection`, wire `_content` | KEEP | — |

### 3.2 Offline verifier — `reconstruct/` (branch-only) — all KEEP

| Path | Lines | What it does | Users | Class |
|---|---|---|---|---|
| `reconstruct/__init__.py` | 30 | Public verifier API. | `test_reconstruct_*`, `test_capture_*`, `scripts/tests/test_wire_capture_*` (via `-m`) | KEEP |
| `reconstruct/__main__.py` | 350 | `python -m fabric.reconstruct` CLI (local or S3 reader). | 6 tests; `examples/wire-capture`; `docs/wire-capture-deployment.md` | KEEP |
| `reconstruct/_ids.py` | 66 | Id helpers. | 4 reconstruct modules; 3 tests | KEEP |
| `reconstruct/_inputs.py` | 647 | Span/record input parsing. | 5 reconstruct modules; 6 tests | KEEP |
| `reconstruct/_objects.py` | 325 | Tenant-scoped, read-only object view. | `_verify`; `test_reconstruct_s3_options` | KEEP (MERGE destination for the readers in 3.4/3.5) |
| `reconstruct/_report.py` | 137 | Verdict report. | 4 reconstruct modules | KEEP |
| `reconstruct/_stitch.py` | 999 | Run stitching and history-rewrite detection. | `_verify`; `test_reconstruct_stitch` | KEEP |
| `reconstruct/_stitch_check.py` | 174 | Stitch consistency checks. | `_verify` | KEEP |
| `reconstruct/_verify.py` | 1,043 | Integrity verdicts. | `__init__`, `__main__` | KEEP |

### 3.3 Records input (Decision surface; on main: the initial release and specs 020–023, 027) — KEEP unless noted

| Path | Lines | What it does | Users | Introduced | Class | Notes |
|---|---|---|---|---|---|---|
| `__init__.py` | 146 | Public root API. | everything | 0f4f02f | KEEP | Re-exports explicit-line and governed-content symbols (`ByteEvidenceRecorder`, `DurableByteSpool`, `GovernedStore`, `JournalMetadataSender`, `ContentResolver`, …); each MERGE/OWNER removal edits this file and `test_recorder_package_surface.py`. |
| `_attributes.py` | 212 | Shared span-attribute keys. | `_calls`, `_crosscut`, `client`, `decision`, `execution`, `integrations/mcp` | 198699d | KEEP | — |
| `_calls.py` | 1,255 | `llm_call()`/`tool_call()` child spans. | `__init__`, `decision`, `integrations/mcp`; `test_calls`, `test_async`, `test_call_privacy`, … | d211ecc | KEEP | Records input. |
| `_crosscut.py` | 116 | tags/baseline/signature kwargs. | `decision`, `integrations/mcp` | 6d6a245 | KEEP | — |
| `_hashes.py` | 42 | SHA-256 hex validation. | 8 modules; `test_hash_compatibility` | 5584954 | KEEP | — |
| `_id_validators.py` | 374 | PII-shaped and placeholder id guards. | `client`, `decision`; 2 tests | 8fb020f | KEEP | — |
| `_version.py` | 5 | Version mirror. | 9 modules; `scripts/verify_release_identity.py` | 0f4f02f | KEEP | — |
| `baseline.py` | 111 | Caller-supplied baseline hash comparison (spec 023). | `__init__`, `_crosscut`, `decision`, `integrations/mcp` | 6d6a245 | KEEP | Recorded metadata, not evaluation. |
| `checkpoint.py` | 53 | Checkpoint event schema. | `__init__`, `decision`; `test_checkpoint` | fcdfffd | KEEP | Docstring still says "the replay engine (commercial)"; reword when touched. |
| `client.py` | 485 | `Fabric` client and config. | `__init__`; most tests; examples | 0f4f02f | KEEP | Imports `auto_instrument` (blocks its removal). |
| `decision.py` | 2,412 | Decision context and every `record_*`. | `__init__`, `client`, `integrations/mcp`; ~20 tests | 0f4f02f | KEEP | Target records input. About 130 lines of governed-content glue (`_governed_sink`, `content_manifest`) move with `_content_writer`. |
| `execution.py` | 413 | Optional `fabric.execution` correlation span. | `__init__`, `client`, `decision`; `test_execution` | 198699d | KEEP | — |
| `memory.py` | 162 | Memory write records. | `__init__`, `decision`; `test_memory` | 0f4f02f | KEEP | Docstring mentions the Telemetry Bridge and Decision Graph (private systems); reword when touched. |
| `propagation.py` | 397 | W3C `tracestate` identity propagation. | `__init__`, `client`, `decision`; `test_propagation` | a46cfa8 | KEEP | — |
| `retrieval.py` | 109 | Retrieval records. | `__init__`, `decision`; `test_retrieval` | 0f4f02f | KEEP | Same docstring note as `memory.py`. |
| `side_effect.py` | 143 | Side-effect records. | `__init__`, `decision`; `test_side_effect` | b81736c | KEEP | — |
| `signing.py` | 180 | Local signature verification over caller hashes. | `__init__`, `_crosscut`, `decision`, `integrations/mcp`; `test_generic_interaction` | 6d6a245 | KEEP | — |
| `taxonomy.py` + `taxonomies/*.json` | 194 + 64 | Tag validation against bundled MITRE ATLAS and OWASP LLM lists. | `__init__` only; `test_generic_interaction` | 6d6a245 | KEEP | Owner may drop the bundled risk taxonomies (red-team vocabulary). Tags work without them. Public API, so not dead. |
| `tracing.py` | 749 | Tracer/meter plumbing, `install_default_provider`. | `__init__`, `_loss`, `call_recorder`, `client`, `coverage_manifest`, 4 wire modules; 12 tests; `benchmarks/` | 0f4f02f | KEEP | — |
| `_span_protection.py` | 480 | Fail-closed metadata projection for Fabric-installed exporters (spec 049 D3); Python mirror of the fabricguard allowlist. | `tracing`; `test_span_protection`, `test_wire_line_separation` | 4a5c945 | KEEP | Edit in step with any fabricguard allowlist change. |
| `integrations/__init__.py` | 29 | Package docstring/re-export. | `__init__` | b45c002 | KEEP | — |
| `integrations/mcp.py` | 406 | MCP `call_tool` wrapper emitting `tool_call` spans. | `__init__`; `test_mcp_integration`, `test_generic_interaction`, `test_surface_logging` | b45c002 | KEEP | A protocol wrapper the caller invokes (provenance `reported`). It is not a framework adapter, but rev 4 should state whether wrappers like this remain. |
| `_capture_health.py` | 77 | Local decision-span dropped-event counters. | `decision`; `test_capture_health` | 4a5c945 | MERGE→`_loss.py` | Guarantee: per-decision loss is visible locally. It belongs in the one loss model (P0). |
| `auto_instrument.py` | 196 | Enables upstream `opentelemetry-instrumentation-*` (openai, anthropic, bedrock, langchain, cohere). | `client.py` (`Fabric.enable_auto_instrumentation`); `test_auto_instrument`, `test_coverage_manifest`; `benchmarks/` | d211ecc | DELETE (blocked) | Superseded by wire capture, and it hooks a framework (langchain). Blocked: `client.py` imports it. Removal also drops 5 extras in `pyproject.toml`, `_instrumentation_registry`, `coverage_manifest`, docs `python-auto-capture-privacy.md`, `governed-content-gap-assessment.md`. Needs a public API removal decision. |

### 3.4 Governed content, records side (specs 028–034; on main via #164) — classified on merits

| Path | Lines | What it does | Users | Class | Guarantee and destination / co-changes |
|---|---|---|---|---|---|
| `_content.py` | 328 | Content roles, canonical bytes, descriptors, `TranscriptManifest` (content v1). | `__init__`, `_content_sink`, `_content_writer`, `client`, `decision`, `resolver`; `test_content_boundaries`, `test_governed_content`; `scripts/tests/test_s3_live.py` | MERGE→ one content contract shared with `wire/_content.py` | Guarantee: canonical bytes and closed role set match `contracts/content/v1` goldens (Python/TS parity). See G8. |
| `_content_sink.py` | 354 | Per-decision bridge: serialize, enqueue, manifest item, deterministic ref. | `decision`; `test_empty_content_manifest`, `test_governed_content` | MERGE→ records producer enqueue into `wire/_spool.py` | Guarantee: the ref is deterministic and stamped on the span with no store I/O on the agent path. |
| `_content_writer.py` | 830 | Inline/process/spooled writer straight from the agent to a store. | `__init__`, `_content_sink`, `client`, `decision`; `test_governed_content`; `examples/governed-content`, `offline-transcript`, `agent-orchestration`; `scripts/tests/_governed_flow_driver.py` | MERGE→ `wire/_spool.py` + `wire/_sender.py` | Guarantees: bounded queue; loss visible via `FlushResult`; nothing raises into the agent; spooled mode fsyncs each entry on enqueue. Removing it drops `ContentCaptureConfig(durability=…)`, a public API. Co-change: `scripts/tests/test_governed_node_e2e.py`, `test_governed_queue_probe.py`, `docs/governed-content.md`. |
| `resolver.py` | 422 | `ContentResolver` and `python -m fabric.resolver` (spec 033). | `__init__`; `test_governed_content`, `test_empty_content_manifest`; `scripts/tests/test_s3_live.py`; `examples/offline-transcript`; TS smoke tests mirror it | MERGE→ `reconstruct/_objects.py` | Guarantees: reads only configured stores; length+SHA-256 verified; namespace-scoped (G9). A second CLI to retire. |
| `content_store/__init__.py` | 28 | Store exports. | `__init__`, `client`, `decision`, `resolver`; ~18 tests | KEEP | — |
| `content_store/base.py` | 166 | `ContentStore`/`ByteEvidenceStore` protocols, `ContentRef`. | 15 modules incl. wire `_config`, `_pipeline` | KEEP | — |
| `content_store/local.py` | 330 | Local store: atomic writes, no-follow. | wire `_config` (direct/local profile), reconstruct `__main__`, `byte_resolver`, `_content_writer`, `_coverage_canary`, `synthetic_reconcile`; 10 tests | KEEP | Local profile writer and reconstruct reader. |
| `content_store/s3.py` | 341 | S3 store (boto3 lazy). | wire `_config` (rejects it for agents), reconstruct `__main__`; 2 tests; `scripts/tests/test_s3_live.py` | KEEP | Reader side only in the target (the Node writes S3). |

### 3.5 Explicit evidence line (specs 035–046; on main via #164/#165)

| Path | Lines | What it does | Users | Class | Recommendation; guarantee; co-changes |
|---|---|---|---|---|---|
| `call_recorder.py` | 801 | `CallRecorder`: explicit call timelines with exact bytes, streams, retries, `seal_source()`. | `__init__`, `enterprise`, `http_dispatch`, `_coverage_canary`, `coverage_manifest`; 8 tests; `examples/enterprise-*`; 3 qualification scripts; `benchmarks/` | OWNER | rec: MERGE→ records producer writing into `wire/_spool.py` (target item 1). Keep the identity model (`call_id`, `parent_call_id`, `attempt_id`, kinds, `result_status`) that 049 P0 reuses, and the explicit-wins scope. G3 (`seal_source`). |
| `adapters/__init__.py` | 7 | Package marker. | — | KEEP | Docstring updated in this change. |
| `adapters/byte_boundary.py` | 171 | `ByteBoundaryAdapter`: explicit final byte boundary. | `test_byte_boundary_adapter`, `test_wire_explicit_coexistence`; `scripts/qualification/run_client_byte_adapter_smoke.py`; `contracts/connect/v1/manifests/python-byte-boundary.json`; wheel qualifier and `release-policy.json` required paths | OWNER | rec: MERGE→ records producer (same scope object as CallRecorder). Co-change: connector manifest + digest, `release-policy.json`, `qualify_recorder_wheel.py:299`, `test_recorder_wheel_qualifier.py:35,121`, `test_recorder_wheel_both_lines.py:31`. G7. |
| `adapters/synthetic_evidence.py` | 835 | Spec 040 slice: loopback model, no-shell subprocess, artifact before/after. | `adapters/byte_boundary`; 3 tests; `run_synthetic_agent_pilot.py` (e2e.yml, e2e-production-profile.yml), `run_client_byte_adapter_smoke.py`, `project_sol_stage_to_fabric.py` | OWNER | rec: MERGE the terminal/artifact capture into 049 P4 records producers; delete the synthetic projections. It drives the only kind e2e gate today. G7. |
| `byte_evidence.py` | 715 | `ByteEvidenceRecorder`: content v2 descriptors, privacy policy, bounded handoff. | `__init__`, `_coverage_canary`, `adapters/synthetic_evidence`, `byte_resolver`, `call_recorder`, `enterprise`, `governed_reconstruction`, `source_spool`; 8 tests; `benchmarks/`; `examples/enterprise-reference` | OWNER | rec: MERGE→ records producer; deliver through the spool. G2. |
| `byte_spool.py` | 672 | `DurableByteSpool`: AES-256-GCM encrypted restartable spool. | `__init__`, `byte_evidence`, `enterprise`; `test_byte_spool`, `test_enterprise_reference`; `examples/enterprise-reference` | OWNER | rec: MERGE→ `wire/_spool.py`. Guarantees: encryption at rest (G1); permanent vs transient delivery errors; immutable descriptor replay. |
| `source_spool.py` | 915 | `SyntheticSourceSpool`: metadata journal, epochs, gap detection, `seal_epoch`. | 7 modules; 10 tests; 10 examples/scripts | OWNER | rec: MERGE→ `wire/_spool.py` + `_sequence.py`. Guarantees: G3 seal; prior-unsealed-epoch reporting; recovered sequence gaps. |
| `metadata_delivery.py` | 748 | `JournalMetadataSender`: at-least-once journal batches to the Node. | `__init__`, `reference_receipts`; 4 tests; `examples/enterprise-reference`, `run_composed_collector_journey.py` | OWNER | rec: MERGE→ `wire/_sender.py` (already at-least-once with `.ack` receipts), then delete. Guarantee: immutable batch identity across replay. |
| `call_otlp.py` | 299 | Metadata-only OTLP projection of call snapshots (`agent.evidence.call`). | `_coverage_canary`, `enterprise`, `enterprise_preflight`, `metadata_delivery`, `qualified_run`; 4 tests; 3 qualification scripts | OWNER | rec: MERGE→ `wire/_sender.py` projection. Guarantee: no path, ref, byte or exception text ever projected. |
| `synthetic_otlp.py` | 306 | Spec 040 AEEP projection. | `call_otlp`, `receipt_sets`; 6 tests; 3 qualification scripts; `scripts/tests/test_governed_node_e2e.py` | OWNER | rec: DELETE after `call_otlp` is merged (shared helpers move with it). |
| `content_join.py` | 82 | Closed binding fields for content lookup. | `call_otlp`, `call_recorder`, `governed_reconstruction`, `receipt_sets`, `source_spool`; `test_governed_reconstruction` | OWNER | rec: MERGE→ the shared content contract (3.4 `_content.py`). |
| `deployment_policy.py` | 333 | Versioned privacy configuration and pre-persistence protection. | `byte_evidence`, `capture_identity`, `deployment_state`, `enterprise`, `enterprise_preflight`, `governed_store`; 9 tests; `examples/enterprise/*.json`; `scripts/tests/test_evidence_contracts.py` | OWNER | rec: KEEP as the PROTECT configuration; apply it at spool admission (G2). Spec 049 P2 reuses `contracts/deployment-policy/v1`. |
| `governed_store.py` | 1,017 | Encrypting, capability-authenticated local store. | `byte_spool`, `governed_reconstruction`; 8 tests; examples; 4 scripts | OWNER | rec: MERGE encryption and grants into the Node writer (spec 050), then delete the SDK copy. G1, G9. |
| `governed_reconstruction.py` | 144 | Fresh authorized readback from journal plus store. | `test_governed_reconstruction`; `run_c8_network_journey.py`, `run_composed_collector_journey.py` | OWNER | rec: MERGE→ `fabric.reconstruct`. |
| `byte_resolver.py` | 293 | Tenant/view-scoped byte reads, no symlinks. | `__init__`, `call_reconcile`, `call_recorder`, `governed_reconstruction`, `qualified_run`; 3 tests; 2 scripts | OWNER | rec: MERGE→ `reconstruct/_objects.py`. G9 (review vs original). |
| `call_reconcile.py` | 537 | Conservative witness comparison (`partial`/`unverified`). | `qualified_run`; 3 tests; 2 scripts; spec 049 Verification | OWNER | rec: MERGE→ `fabric.reconstruct` as an optional witness input. G6. |
| `synthetic_reconcile.py` | 332 | Spec 040 reconciler. | `call_reconcile`; 3 tests; 4 scripts | OWNER | rec: fold into `call_reconcile`'s merge, then delete. |
| `http_dispatch.py` | 381 | `FinalHTTPAdapter`: stdlib final HTTP body adapter plus local receiver truth. | `test_http_dispatch`, `test_semgrep_security_boundaries`; `examples/enterprise-reference`; `run_c8_network_journey.py` | OWNER | rec: keep until 049 P4 generalizes wire to non-model hosts, then MERGE→ wire or records producer. G7. |
| `evidence_attestation.py` | 278 | Ed25519 statement verifier against an owner key registry. | 6 modules; 9 tests; examples; `run_qualified_call_pilot.py` | OWNER | rec: KEEP as an optional reconstruct input (G4). |
| `receipt_sets.py` | 341 | Exact four-stage receipt sets. | `qualified_run`, `reference_receipts`; 3 tests; examples; scripts | OWNER | rec: MERGE→ reconstruct as an optional input (G4). |
| `reference_receipts.py` | 748 | HTTP + SQLite receipt **service** that ships in the SDK wheel. | `test_reference_receipts`; `examples/enterprise-reference` | OWNER | rec: DELETE from the wheel; move to test apparatus. A server in the recorder package is outside the product promise. |
| `qualified_run.py` | 662 | Spec 046 qualified verdict. | `test_qualified_run`; `run_qualified_call_pilot.py` (e2e-production-profile.yml) | OWNER | rec: MERGE→ reconstruct if rev 4 keeps `verified_complete_for_declared_scope`, else DELETE with 045/046. |
| `independent_feed.py` | 456 | Spec 045 feed verifier. | `qualified_run`; 3 tests; `run_qualified_call_pilot.py` | OWNER | rec: same decision as `qualified_run`. G6. |
| `independent_store.py` | 120 | Read-only native-witness objects. | `test_fd_ownership`, `test_independent_store`; `run_qualified_call_pilot.py` | OWNER | rec: goes with `independent_feed`. |
| `distributed_closure.py` | 855 | Multi-source signed closure. | `test_distributed_closure`; `examples/enterprise-reference/closure_campaign.py`; `docs/enterprise-distributed-closure.md` | OWNER | rec: DELETE. No 035–046 spec section names it; only the enterprise reference uses it. |
| `enterprise.py` | 154 | `PolicyCaptureSession` around CallRecorder. | `test_enterprise_integration`, `test_governed_store`; `examples/enterprise-*`; `run_enterprise_local.py` | OWNER | rec: DELETE; configuration moves to the records producer. |
| `enterprise_preflight.py` | 542 | Offline deployment checks plus a local canary, with a CLI. | `test_enterprise_preflight`; `scripts/qualification/enterprise_preflight.py`; `scripts/tests/test_enterprise_integration_example.py` | OWNER | rec: DELETE; move any config check to `fabricctl recorder validate` or a wire check. |
| `deployment_state.py` | 416 | Policy registry with optimistic revisions for "portal adapters". | `capture_identity`; 2 tests; `examples/enterprise-orchestration`; `run_enterprise_local.py` | OWNER | rec: DELETE. Policy rollout and registry is out of scope per AGENTS.md. |
| `capture_identity.py` | 123 | Principal binding around a customer authority. | 2 tests only | OWNER | rec: DELETE with `deployment_state`. |
| `capture_readback.py` | 141 | Caller-reported readback assessment. | `deployment_state`; `test_capture_readback` | OWNER | rec: DELETE with `deployment_state`. |
| `capture_capabilities.py` | 57 | Static SDK capability matrix. | `test_capture_capabilities`; `docs/sdk-support-matrix.md` | OWNER | rec: DELETE; it duplicates `contracts/connect/v1/manifests`. |
| `coverage_manifest.py` | 263 | Instrumentor registration registry. | `auto_instrument`, `enterprise_preflight`; 4 tests; `examples/enterprise-reference` | OWNER | rec: DELETE with `auto_instrument`. |
| `_coverage_canary.py` | 273 | Fixture HTTP canary inside the package. | `coverage_manifest` | OWNER | rec: DELETE; move to tests. |
| `_instrumentation_registry.py` | 76 | Lazy instrumentor registry. | `auto_instrument`, `coverage_manifest` | OWNER | rec: DELETE with `auto_instrument`. |
| `control_evidence.py` | 78 | Closed evidence about an external control decision. | `control_protocol`, `enterprise`; 2 tests; `run_enterprise_local.py` | KEEP | 049 P3 builds `record_control` on it. |
| `control_protocol.py` | 206 | Data contract for a future external controller; never invoked. | `test_control_protocol` only | OWNER | rec: DELETE from the recorder package. AGENTS.md puts any Control Runtime outside the default recorder. |

### 3.6 Removed in this change

| Path | Lines | Class |
|---|---|---|
| `adapters/crewai.py` | 137 | DELETE (pre-approved; framework adapter). Users were only `test_adapters_crewai.py` and `test_hash_compatibility.py`. See section 9. |

## 4. TypeScript SDK — `sdk/typescript` (src 9,130; test 5,745)

`@singleaxis/fabric` 0.8.0-rc.1, single entry `src/index.ts` (ESM and CJS).
Every file is identical to `origin/main` (`git diff origin/main...HEAD --
sdk/typescript` is empty). No framework adapter, wire tee, spool or sender
exists yet (spec 049 F-C). Release pins:

- `scripts/package-qualified.mjs` `EXPECTED_PACKAGE_FILES` and its ESM/CJS
  smoke imports;
- `release.yml` qualify and publish-npm jobs (pinned by
  `scripts/tests/test_npm_release_workflow.py`);
- `contracts/connect/v1/manifests/typescript-capture-sdk.json`;
- `scripts/tests/test_typescript_content_contract.py`, and
  `test_evidence_contracts.py:331`, which imports from `dist`.

| Path | Lines | What it does | Users | Introduced | Class | Notes |
|---|---|---|---|---|---|---|
| `src/index.ts` | 160 | Package entrypoint. | tsup; 16 tests; smoke | ab49fcc | KEEP | — |
| `src/client.ts` | 265 | `Fabric` client, env config, content-capture wiring. | index; most tests; smoke; 2 scripts tests | ab49fcc | KEEP | Rewire `contentCapture` when the writer moves. |
| `src/decision.ts` | 2,109 | Decision and all record APIs. | client, testing, index; nearly every test | ab49fcc | KEEP | Records input. Lines 757–839 are governed-content glue that moves. |
| `src/calls.ts` | 754 | `llmCall`/`toolCall` spans. | decision, index | ab49fcc | KEEP | `captureContent` writes raw gen_ai messages onto span attributes (`:296-306, 463, 679-685`). That is a third content path; the owner should confirm it stays (connector manifest says `configurable_raw`). |
| `src/execution.ts` | 316 | Execution correlation span. | client, decision, index | 198699d | KEEP | — |
| `src/crosscut.ts` | 157 | tags/baseline/signature. | decision, calls, index | 804f40b | KEEP | — |
| `src/propagation.ts` | 413 | W3C tracestate propagation. | decision, index; 3 tests | 804f40b | KEEP | — |
| `src/attributes.ts` | 336 | Attribute constants. | 8 modules; `verify_release_identity.py` reads `SCHEMA_VERSION` here | ab49fcc | KEEP | Must stay at this path. |
| `src/recorder-attributes.ts` | 216 | Public `attributes` namespace. | index; surface test; smoke | 5584954 | KEEP | — |
| `src/tracing.ts` | 129 | Tracer helpers. | client, index | 804f40b | KEEP | — |
| `src/version.ts` | 19 | `SDK_VERSION`. | tracing, content-sink, index | 804f40b | KEEP | Not checked against `package.json` by `verify_release_identity.py`; can drift. |
| `src/hash.ts` | 211 | Hash/canonical JSON helpers (Python parity). | almost every module; 3 tests; smoke | ab49fcc | KEEP | — |
| `src/validators.ts` | 95 | Telemetry guards. | decision, calls, crosscut | 804f40b | KEEP | — |
| `src/id-validators.ts` | 322 | PII-shape and placeholder ids. | client, decision; 2 tests | 804f40b | KEEP | — |
| `src/testing.ts` | 12 | Test reset helpers. | index; 2 tests | 804f40b | KEEP | — |
| `src/content.ts` | 332 | Content v1 primitives and `TranscriptManifest`. | 6 modules; 5 tests; contract tests | 804f40b | MERGE→ shared content contract | Keep canonical bytes/descriptor; the manifest goes to the one manifest model (G8). |
| `src/content-sink.ts` | 326 | Per-decision serialize, enqueue, ref. | decision; index export (no external consumer) | 804f40b | MERGE→ records producer / spool enqueue | Guarantee: deterministic ref with no store I/O. |
| `src/content-writer.ts` | 871 | In-agent writer with its own `fabric.content-spool/v2`. | client, decision, content-sink, index; 2 tests; smoke | 804f40b | MERGE→ spec 048 TS spool and sender | Guarantees: checksum quarantine, crash recovery, loss counters, never throws. |
| `src/content-store.ts` | 837 | GovernedStore, local and S3 stores. | 5 modules; 10 tests; smoke; Node `backend_file.go` layout comment | 804f40b | KEEP | 049 F-C reuses it. |
| `src/deployment-policy.ts` | 361 | Policy and `ContentProtector` (omit/redact/tokenize/retain). | byte-evidence, index; `deployment-policy.test.ts`; `test_evidence_contracts.py`; `capture_capabilities.py` | 4a5c945 | OWNER | rec: KEEP as the PROTECT stage (G2). |
| `src/byte-evidence.ts` | 520 | Explicit exact-byte recorder (content v2). | index; 3 tests; `test_evidence_contracts.py` | 804f40b | OWNER | rec: MERGE→ TS records producer; replace the direct store write with the spool. |
| `src/resolver.ts` | 369 | `ContentResolver` and transcript export (specs 033/034). | index; 2 tests; ESM/CJS smoke | 804f40b | DELETE (blocked) | A second verifier. Blocked: exported from `index.ts` and required by `package-qualified.mjs` smoke. Removal is a public API change. |
| `scripts/package-qualified.mjs` | 432 | Tarball qualification and smoke. | release.yml, recorder-ci.yml | b52a3b1 | KEEP | Update smoke imports as exports change. |
| config files (`package.json` 89, `tsconfig.json` 21, `tsup.config.ts` 17, `eslint.config.js` 48, README 288, LICENSE 15) | — | Build and docs. | — | ab49fcc | KEEP | — |

Tests (23 files, 5,745 lines) track the modules above. `governed-content.test.ts`
(1,298), `spool-recovery-regression.test.ts` (133) and
`content-manifest-contract.test.ts` (156) move with the content-writer MERGE.
`byte-evidence.test.ts` (260) and `deployment-policy.test.ts` (422) are OWNER.
Possible CI gap: `recorder-ci.yml` contracts job runs `npm ci` but not
`npm run build`, so the Node leg of `test_evidence_contracts.py` may skip in
clean CI.

## 5. Components (Go)

All four collector components are in `ocb-config.yaml` and the Dockerfile, and
used by shipped configs. No component is dead or duplicated; none implements
evaluation, red-team, policy enforcement or fleet management. There are no
framework keys left after this change.

| Path | Non-test / test lines | What it does | Users | Introduced | Class | Notes |
|---|---|---|---|---|---|---|
| `otel-collector-fabric/processor/fabricguardprocessor` | 1,923 / 3,275 | Exact-key metadata allowlist guard (PROTECT on the telemetry path). | ocb manifest, Dockerfile, chart and every compose config; gate refuses pipelines without it; scripts/tests and chart tests | 0f4f02f | KEEP | Sub-items below. |
| ↳ `fabric.crewai.*` keys | 8 keys + 3 vocabulary entries | CrewAI adapter attributes and event names. | only the removed adapter | — | DELETE (done) | Section 9. |
| ↳ evidence class and `EvidenceSourceBinding` | allowlist.go:155-167; processor.go evidence branches; config.go; `call_evidence_test.go`, `source_binding_test.go` | AEEP evidence validation and identity binding. | evidence-line SDK projections; chart `evidenceSourceBinding` | 804f40b/4a5c945 | OWNER | rec: decide together with the gate's dedicated ingress (G5). `agent.evidence.loss/coverage/receipt` branches have no SDK emitter. |
| ↳ log classes `decision_summary`, `cost_usage_aggregate`, `activity` | allowlist.go:177-183 | Log classes with no emitter in this repository. | `processor_test.go` only | 0f4f02f | OWNER | rec: check the private telemetry bridge (moved to the internal repo) before removal. It may still send `decision_summary`. |
| ↳ keys `fabric.cost_usd`, `fabric.latency_ms`, `fabric.input_length`, `fabric.output_length` | allowlist.go:117-118 | No emitter in either SDK; emitted by removed pre-0.8 features. | `_span_protection.py` mirror; one Go test | 0f4f02f | DELETE (blocked) | Inside KEEP code; released pre-0.8 SDKs may still send them. Remove with the activity v1 alias set. |
| ↳ activity v1 aliases (`event_id`, `fabric.event_type`, …, about 30 keys) | allowlist.go | "Safe v1 aliases still emitted by released SDKs". | contracts/activity/v2 `MAPPING.md` | 0f4f02f | KEEP | Released-SDK compatibility. |
| `otel-collector-fabric/exporter/fabriccontentexporter` | 1,683 / 2,547 | Spec 048 content writer: directory or S3 (SSE required), never overwrites. | manifest, Dockerfile, chart, compose content configs; gate keeps it in `logs/content*` | 6010735 (branch) | KEEP | Target writer. |
| `otel-collector-fabric/extension/noredirectextension` | 111 / 264 | Turns any 3xx into a retryable error. | gate `checkRedirectMiddleware`; every OTLP/HTTP exporter | 6010735 (branch) | KEEP | — |
| `otel-collector-fabric/gate` | 1,498 / 1,871 | `fabric-gate` entrypoint: refuses weakened configs, supervises token files. | Dockerfile ENTRYPOINT, chart, compose, many scripts tests | 804f40b | KEEP | The dedicated evidence ingress (`gate.go:76-289`, `evidence_binding_test.go`) is OWNER, decided with G5. |
| `otel-collector-fabric/receiver/auditreceiver` | 2,511 / 1,578 | auditd netlink/logfile receiver (spec 030). | manifest, Dockerfile, `collector-host-monitor.yaml`, `deploy/auditd`, `collector.demo.yaml` | 804f40b | KEEP | Host sensor kept by 049 as `corroborated_by` (G10). Spec 049's netlink item is stale (section 1). |
| `host-emitter` | 1,313 / 572 (+ BPF C) | eBPF exec/connect/openat emitter with its own spool (spec 031). | `release-policy.json` image, release.yml, recorder-ci host-emitter job, `deploy/kubernetes`, 7 scripts tests | 804f40b | KEEP | Released image; G10. `dedupe.go` is near-identical to auditreceiver's (separate modules; not worth merging). |
| `otel-collector-fabric/upstream` | 183 test + patch 164 | Patched bearertokenauth (drop empty tokens; `require_single_token`). | Makefile, Dockerfile, 2 scripts tests | 804f40b | KEEP | `require_single_token` exists only for the dedicated evidence ingress: OWNER with G5. |
| `otel-collector-fabric/tests`, `examples/config.yaml` | shell tests; 1 config | Manifest and distribution checks; minimal reference config. | Makefile, recorder-ci.yml | b52a3b1/0f4f02f | KEEP | — |

Test commands: `go test ./...` in each of `processor/fabricguardprocessor`,
`exporter/fabriccontentexporter`, `extension/noredirectextension`, `gate`,
`receiver/auditreceiver` (macOS runs a subset; netlink and durable-logfile
tests are linux-only) and `components/host-emitter` (macOS builds stubs; Linux
needs `go generate` first).

## 6. Charts, deploy, examples, benchmarks, qualification, tools

### 6.1 charts/ (38 files, 4,924 lines)

| Path | Lines | What it does | Users | Class | Notes |
|---|---|---|---|---|---|
| `charts/README.md`, `charts/fabric/{Chart.yaml,Chart.lock,values.yaml,values.schema.json,README.md,.helmignore}` | ~440 | Umbrella Fabric Node chart. | release.yml, e2e.yml, e2e-production-profile.yml, recorder-ci.yml; `verify_release_identity.py`; `release-policy.json`; 4 scripts tests; kind-quickstart | KEEP | Node install path. |
| `charts/fabric/templates/` | 235 | Helpers, namespace, network policy. | chart | KEEP | — |
| `charts/fabric/profiles/shadow-dev.yaml`, `shadow-production.yaml` | 35, 115 | Deployment profiles. | e2e.yml, e2e-production-profile.yml, kind-quickstart | KEEP | — |
| `charts/fabric/tests/` | 290 | Schema and package-boundary tests. | recorder-ci.yml | KEEP | — |
| `charts/fabric/charts/otel-collector/` | ~3,800 | Collector subchart (templates, values, 6 test scripts). | recorder-ci.yml and all of the above | KEEP | — |
| ↳ `receiver.evidenceSourceBinding` (values, configmap, helpers, deployment, schema, README, `test-evidence-source-binding.sh`) | ~120 | Spec 044 bound ingress. | `test_enterprise_deployment.py:116` | OWNER | rec: decide with G5. Small issue: the comment at `values.yaml:73-76` describes it but sits above `workloadAuthentication`. |

### 6.2 deploy/ (3,584 lines)

| Path | Lines | What it does | Users | Class | Notes |
|---|---|---|---|---|---|
| `deploy/README.md` | 39 | Overview. | — | KEEP | Stale: does not mention `auditd/`, `kubernetes/` or the content overlays. |
| `deploy/compose/` (33 files) | ~3,100 | Compose harness, production overlay, spec 048 content and S3 overlays, sink. | e2e workflows; 8 scripts tests; `gate_test.go` `TestShippedConfigsPass` | KEEP | Target writer path. `collector-config/collector-host-monitor.yaml` (50) is the host input (G10). |
| `deploy/auditd/` | 328 | auditd rules and e2e harness. | nothing in CI; specs 030/049 | KEEP | G10. Manual only. |
| `deploy/kubernetes/host-emitter-daemonset.yaml` | 114 | eBPF DaemonSet. | `scripts/tests/test_host_emitter_manifest.py` | KEEP | G10. |

### 6.3 examples/ (6,406 lines)

| Path | Lines | What it does | Users | Introduced | Class | Notes |
|---|---|---|---|---|---|---|
| `examples/README.md` | 37 | Index. | `test_recorder_documentation_scope.py` | 200b0f4 | KEEP | e2e-smoke row removed in this change. |
| `reference-agent/` | 669 + uv.lock 338 | Minimal records-API agent. | dependabot; its own tests (not in CI) | 0f4f02f | KEEP | `uv.lock:274-308` still records removed extras (crewai, langgraph, cedar, …). Run `uv lock` there. |
| `kind-quickstart/` | 289 | kind + chart + instrumented agent. | none in CI | 6d6a245 | KEEP | — |
| `harness-smoke/` | 201 | Compose smoke: one decision lands in the sink. | dependabot; specs/010 | 0f4f02f | KEEP | — |
| `e2e-smoke/` | 131 | Manual SDK -> OTLP -> collector landing check. | only `examples/README.md` (whose claim that e2e.yml pairs with it is false; its own docstring says e2e.yml does not use it) | da9752b (#118) | DELETE (done) | Superseded by `harness-smoke` and the e2e.yml fixture path. Section 9. |
| `wire-capture/` | 445 | httpx ReAct loop -> wire -> reconstruct. | examples/README | 6010735 (branch) | KEEP | Promote as the primary example. |
| `governed-content/` | 353 | Records content via inline `ContentWriter`. | docs, specs/034 | 804f40b | MERGE→ `wire-capture` | Goes with `_content_writer.py`. |
| `offline-transcript/` | 175 | Inline writer plus `ContentResolver`. | docs, specs/034 | 804f40b | MERGE→ `wire-capture` | Same. |
| `agent-orchestration/` | 1,569 | Scripted demo with spooled ContentWriter, audit shim, own `reconstruct.py` and viewer. | `scripts/tests/test_orchestration_demo_safety.py` (CI); `components/.../gate/gate_test.go:208-209` reads `collector.demo.yaml` | 804f40b | DELETE (blocked) | It breaks the target three ways (second spool, second verifier, audit input). Blocked: KEEP gate tests read its config. It is also under active development on `feat/governed-content` (`df63011`, `47dc48e`, `392aab6`), so deleting it here would conflict. |
| `enterprise/` | 36 | Policy and scope fixtures. | Python and TS SDK tests; 2 scripts tests; docs | 4a5c945 | OWNER | rec: lives or dies with `deployment_policy`/`enterprise_preflight`. |
| `enterprise-orchestration/` | 738 | Enterprise demo on the evidence line. | `test_enterprise_examples.py`, `test_enterprise_integration.py` | 4a5c945 | OWNER | rec: DELETE with the enterprise modules. |
| `enterprise-reference/` | 1,425 | Flagship evidence-line reference (closure campaign, receipts). | 2 SDK tests, 1 scripts test; README.md:47; docs/quickstart.md:15; 6+ docs | 4a5c945 | OWNER | rec: DELETE once the evidence modules are merged; replace the README link with `wire-capture`. |

### 6.4 benchmarks/ (45,189 lines)

| Path | Lines | What it does | Users | Introduced | Class | Notes |
|---|---|---|---|---|---|---|
| `benchmarks/fabric-comparison/` code | 1,355 + 108 JSON | SDK instrumentation comparison (none, otel, fabric-explicit, fabric-auto, openinference). | Nothing runs it: no workflow, test or Makefile. References: `.pre-commit-config.yaml:34`, `.gitleaksignore`, 3 docs | 4a5c945 | OWNER | rec: DELETE. Imports `auto_instrument`, `ByteEvidence*`, `CallRecorder`. |
| `benchmarks/fabric-comparison/evidence/` | ~43,700 (317 files incl. 126 `.bin`) | Frozen results pinned to commit `18ec69a`. | none | 4a5c945 | OWNER | rec: DELETE. 32 of 66 pinned SDK hashes already drift and 30 current files are unpinned. Its `PUBLICATION.md` already scopes it to `18ec69a`. |

### 6.5 qualification/ (158 files, 98,075 lines; all from #164/#165)

| Path | What it is | Read by | Class | Notes |
|---|---|---|---|---|
| `synthetic-slice/kind-production-values.yaml`, `kind-production-sink-*.yaml` | Helm values and sink for the production-profile kind e2e. | `e2e-production-profile.yml:67-68,139,150,365` | OWNER | rec: KEEP while that workflow runs the evidence pilots; move under `deploy/` or `scripts/` later. |
| `synthetic-slice/end-to-end-agent-pilot-plan.md` | Plan doc. | `e2e.yml:50` paths filter only | OWNER | rec: DELETE with the slice. |
| `capture-level-matrix.json`, `local-go-simulation/*`, `synthetic-slice/scope.v1.json` | Inputs for scripts nothing invokes. | `run_capture_acceptance.py` `main()`, `run_local_go_simulation.sh` | OWNER | rec: DELETE with those scripts. |
| `cloud-audit-*.json` (37 files), `cloud-2026-10-02/` (~100 files), `python-test-contracts/` (3 files, 680 KB), `c8-network-capture-matrix.json`, `composed-collector-capture-matrix.json`, `production-go/`, `sol-local-stage/`, remaining `synthetic-slice/*` | Historical audit and qualification records. | Docs only (`recorder-v1-qualification-status.md`, `cloud-qualification-2026-10-02.md`, `evidence-qualification-map.md`, `standalone-evidence-guide.md`) or nothing | OWNER | rec: DELETE from the tree (history stays in git) and replace doc links with a commit reference. No test verifies the source-hash pins in them (12 of 70 c8 pins already drift), so they break nothing. Release writes `qualification/{npm,contracts,chart}` at release time with `mkdir`; that does not depend on the committed directory. |

### 6.6 tools/

| Path | Lines | What it does | Users | Class | Notes |
|---|---|---|---|---|---|
| `tools/fabricctl` (Go) | 1,638 | Offline `init`, `recorder validate`, `recorder digest`, `version`. | recorder-ci, recorder-security, recorder-license, release (archives, SHA256SUMS); `verify_release_identity.py`; docs | KEEP | No runtime consumes the `FabricRecorder` file it writes. `spec.input.method` still accepts `adapter` (`internal/recorder/recorder.go:110`); drop it in rev 4 if adapters are gone. |

## 7. scripts/ (26,132 lines) and sdk/python/scripts/

CI reaches these through `recorder-ci.yml:83` (`pytest scripts/tests`), the
contract validators (`:85-91`), `qualify_recorder_wheel.py` (`:118`), and the
release, codeql, security, license and e2e workflows.

| Path | Lines | Purpose | Invoked by | Class | Notes |
|---|---|---|---|---|---|
| `check_changelog_keep_alive.py` | 55 | Unreleased keep-alive. | release.yml:200; test | KEEP | — |
| `license_check.py`, `license_scan.sh` | 720, 129 | License gate. | recorder-license.yml; 3 tests | KEEP | — |
| `verify_release_identity.py` | 600 | Version identity across artifacts. | recorder-ci.yml:91, release.yml:63; test | KEEP | — |
| `contracts/validate_capture_contracts.py` | 917 | contracts/capture/v1 (047/048). | recorder-ci.yml:89; tests | KEEP | Branch-only. |
| `contracts/validate_connector_contract.py` | 423 | contracts/connect/v1 and digest index. | `test_connector_contract.py` | KEEP | Check-only; there is no re-pin tool. |
| `contracts/validate_content_contracts.py`, `validate_data_plane_contracts.py`, `validate_recorder_contract.py`, `__init__.py` | 441, 628, 387, 3 | Contract validators. | recorder-ci.yml; tests | KEEP | — |
| `contracts/validate_evidence_contracts.py` | 974 | AEEP evidence/v1 and content/v2. | recorder-ci.yml:87; 2 tests | OWNER | rec: KEEP while contracts/evidence ships; decide with G4. |
| `release/*` (`package_contracts.py` 501, `qualify_release.py` 618, `release-policy.json` 208, `verify_workflow_runs.py` 157, `__init__.py` 3) | 1,487 | Release qualification. | release.yml; 5 tests | KEEP | `release-policy.json` edited in this change. |
| `qualification/check_host_emitter_manifest.py`, `check_secret_scan_baseline.py`, `pin_kind_node_image.sh`, `report_codeql_pr_annotations.py`, `summarize_sarif.py` | 183, 89, 36, 256, 73 | CI helpers. | workflows; tests | KEEP | — |
| `qualification/run_synthetic_agent_pilot.py`, `synthetic_agent_tool.py`, `verify_synthetic_sink_readback.py` | 649, 66, 125 | Spec 040 pilot (the only kind e2e gate in e2e.yml). | e2e.yml:320,335; e2e-production-profile.yml | OWNER | rec: replace with a wire-capture kind e2e before deleting. |
| `qualification/run_qualified_call_pilot.py`, `run_custom_agent_smoke.py`, `run_custom_agent_node_pilot.py`, `run_client_byte_adapter_smoke.py`, `check_source_binding.py`, `otlp_readback_validation.py` | 875, 539, 283, 183, 449, 53 | Evidence-line pilots. | e2e-production-profile.yml; tests | OWNER | rec: retire with the modules they exercise. `run_client_byte_adapter_smoke.py` is cited as evidence by `python-byte-boundary.json`. |
| `qualification/run_c8_network_journey.py`, `run_capture_acceptance.py`, `capture_measurements.py`, `enterprise_preflight.py`, `run_enterprise_local.py` | 524, 150, 89, 9, 258 | Evidence-line journeys and enterprise exercises. | tests only | OWNER | rec: DELETE with the enterprise modules. |
| `qualification/run_composed_collector_journey.py` | 602 | Governed bytes through a real Collector. | docs only | OWNER | rec: DELETE. |
| `qualification/project_sol_stage_to_fabric.py`, `run_sol_local_stage.py`, `verify_sol_sink_readback.py` | 278, 546, 118 | Codex/Sol rehearsal (`run_sol_local_stage.py` calls itself "not an OSS recorder adapter"). | nothing invokes the projector; `test_sol_local_stage.py`, `test_readback_privacy.py` (mocked) | OWNER | rec: DELETE (edit `test_readback_privacy.py` with it). |
| `qualification/run_local_go_simulation.sh`, `summarize_local_go_simulation.py` | 164, 138 | Laptop "GO rehearsal". | nothing invokes the script; `test_local_go_simulation.py` | OWNER | rec: DELETE. |
| `tests/` wire, compose, release, contract, license, infra tests (about 30 files) | — | — | recorder-ci.yml:83 | KEEP | `test_final_audit_regressions.py` lists evidence modules in `CURRENT_MODULES` and must change with them. |
| `tests/` evidence-line tests (about 14 files) and governed-content tests (`test_governed_node_e2e.py`, `_governed_flow_driver.py`, `test_governed_queue_probe.py`, `test_s3_live.py`, `test_s3_live_harness.py`) | — | — | recorder-ci.yml:83 | OWNER / MERGE | Go with the modules they cover. |
| `sdk/python/scripts/qualify_recorder_wheel.py` | 413 | Structural wheel/sdist qualifier. | recorder-ci.yml:118; 2 SDK tests | KEEP | Edited in this change (forbids `fabric/adapters/crewai.py`). |

## 8. Summary

### 8.1 Counts per class

Rows counted as listed in sections 3–7. Sub-rows (↳) count as items.
"done" items are counted under DELETE.

| Area | KEEP | MERGE | DELETE | OWNER |
|---|---|---|---|---|
| Python SDK (3.1–3.6) | 55 | 5 | 2 (1 done, 1 blocked) | 34 |
| TypeScript SDK (4) | 18 | 3 | 1 (blocked) | 2 |
| Components (5) | 9 | 0 | 2 (1 done, 1 blocked) | 2 |
| charts/ (6.1) | 5 | 0 | 0 | 1 |
| deploy/ (6.2) | 4 | 0 | 0 | 0 |
| examples/ (6.3) | 5 | 2 | 2 (1 done, 1 blocked) | 3 |
| benchmarks/ (6.4) | 0 | 0 | 0 | 2 |
| qualification/ (6.5) | 0 | 0 | 0 | 4 |
| tools/ (6.6) | 1 | 0 | 0 | 0 |
| scripts/ (7) | 10 | 0 | 0 | 8 |
| **Total** | **107** | **10** | **7** | **56** |

Counts are table rows; a row can group several files (for example the
`cloud-audit-*.json` pile is one row). Of the 7 DELETE rows, 2 were removed
in this change and 5 are blocked by a KEEP dependent or need a compatibility
decision (section 9). OWNER rows split by recommendation: 24 delete, 20
merge, and 12 keep-as-is or "decide with G4/G5".

### 8.2 Line counts before and after this change

`wc -l` over tracked files. "Before" is `c3f1e51`; "after" is this branch
without this document.

| Area | Before | After | Change |
|---|---|---|---|
| `sdk/python/src` | 34,452 | 34,317 | −135 |
| `sdk/python/tests` | 41,647 | 41,368 | −279 |
| `sdk/python/scripts` + `pyproject.toml` | — | — | +3 |
| `sdk/typescript` (src + test) | 14,875 | 14,875 | 0 |
| `components/` (all files) | 175,017 | 175,032 | +15 (−7 allowlist/processor, +22 new fail-closed test) |
| `contracts/` | — | — | 0 (+3/−3: wording and digest) |
| `charts/`, `deploy/`, `tools/` | 10,146 | 10,146 | 0 |
| `examples/` | 6,406 | 6,274 | −132 |
| `benchmarks/` | 45,189 | 45,189 | 0 |
| `qualification/` | 98,075 | 98,075 | 0 |
| `scripts/` | 26,132 | 26,135 | +3 |
| `CHANGELOG.md` | — | — | +18 |
| **Repository (tracked)** | **496,726** | **496,219** | **−507 (+55/−562)** |


### 8.3 What the full plan would remove

If every OWNER `rec: DELETE` and every MERGE completes, the following leave the
tree (approximate, at `c3f1e51`):

- Python SDK: 15,888 source lines across 38 modules (every MERGE and OWNER
  module except `deployment_policy`, `evidence_attestation`,
  `control_evidence`, plus `auto_instrument`), and about 13,900 test lines.
  MERGE modules are partly rewritten into their destination, so the net
  reduction is smaller.
- TypeScript SDK: 2,086 source lines (`content-writer`, `content-sink`,
  `resolver`, `byte-evidence`).
- `benchmarks/`: 45,189 lines. `qualification/`: about 97,900 lines (all but
  the kind production YAML).
- Examples: 4,294 lines (enterprise ×3, governed-content, offline-transcript,
  agent-orchestration).
- Scripts: about 6,100 lines of `scripts/qualification` plus their
  `scripts/tests`.

## 9. Phase B — what this change removed

Only items classified DELETE that (1) no KEEP or MERGE code depends on and
(2) are not part of main's 035–046 evidence line.

| Group | Removed | Also changed |
|---|---|---|
| CrewAI adapter (pre-approved) | `sdk/python/src/fabric/adapters/crewai.py` (137), `sdk/python/tests/test_adapters_crewai.py` (278) | `test_hash_compatibility.py` (dropped the CrewAI hasher); fabricguard `allowlist.go` (8 keys), `processor.go` (`fabric.crewai` category and the `fabric.crewai.step`/`.task` vocabulary), `traces_test.go` (vocabulary list, plus a new fail-closed test `TestRemovedCrewAIVocabularyFailsClosed`); `contracts/connect/v1/manifests/python-sdk.json` (`coverage_basis` wording; `framework_lifecycle` is now `caller_reported` via `record_hook`) re-pinned in `contracts/connect/v1/manifest.json`; `fabric/adapters/crewai.py` added to the forbidden/excluded lists in `pyproject.toml` (wheel and sdist), `test_recorder_package_surface.py`, `qualify_recorder_wheel.py` and `release-policy.json` (wheel and sdist), asserted in `test_recorder_release_boundary.py`; `adapters/__init__.py` docstring; CHANGELOG `Unreleased > Removed`. |
| Superseded example | `examples/e2e-smoke/flow.py` (131) | `examples/README.md` row. The historical CHANGELOG line is left as written. |

The `"crewai"` entries in the forbidden-extras sets
(`test_recorder_package_surface.py:51`, `qualify_recorder_wheel.py:51`) stay:
they still block a crewai extra from returning.

Not removed, although classified DELETE: `auto_instrument.py` (imported by
`client.py`), TS `resolver.ts` (root export and release smoke),
`examples/agent-orchestration` (read by `gate_test.go`; active branch), and
the four unemitted fabricguard keys (KEEP module; released-SDK compatibility).

Re-pin procedure used (there is no re-pin tool): edit the manifest, compute
`shasum -a 256 contracts/connect/v1/manifests/python-sdk.json`, paste it into
`contracts/connect/v1/manifest.json`, then run
`python scripts/contracts/validate_connector_contract.py` and
`pytest scripts/tests/test_connector_contract.py scripts/tests/test_package_contracts.py`.

Left stale on purpose (historical records, nothing validates them):
`qualification/*` and `benchmarks/fabric-comparison/evidence/*` entries that
name `adapters/crewai.py`, and `examples/reference-agent/uv.lock` (see 6.3).

### 9.1 Test results

Environment: macOS (darwin arm64), Go 1.26.2, Docker Desktop daemon running.
Python 3.12.13 in a scratch virtualenv with the CI dependency set from
`recorder-ci.yml:109` (`-e sdk/python pytest pytest-cov jsonschema PyYAML
httpx openai anthropic cryptography opentelemetry-exporter-otlp-proto-http
build boto3`). `~/fabric-test` was not used: it has no pytest or dev
dependencies, and its editable install points at another worktree, so
re-pointing it would have changed someone else's environment. The system
Python 3.10 was not used for any test.

"Before" is a clean tree at `c3f1e51`. "After" is `e2eeebc` (both removal
commits).

| Suite | Command | Before | After |
|---|---|---|---|
| Python SDK | `cd sdk/python && pytest -q` (with `--cov-fail-under=85`) | 3154 passed, 5 warnings; coverage 90% | 3136 passed, 5 warnings; coverage 90% |
| scripts/tests | `pytest scripts/tests -q -rfEs` | 776 passed, 15 skipped | 776 passed, 15 skipped |
| fabricguard (only Go module touched) | `cd components/otel-collector-fabric/processor/fabricguardprocessor && go test ./...` | ok | ok (plus `TestRemovedCrewAIVocabularyFailsClosed`) |
| Connector contract | `python scripts/contracts/validate_connector_contract.py` | valid: 13 pinned artifacts | valid: 13 pinned artifacts |

The Python SDK delta is exactly the removed tests: 12 in
`test_adapters_crewai.py` and 6 parametrized cases of
`test_existing_text_hash_interfaces_preserve_exact_utf8_surrogatepass` (the
CrewAI hasher × 6 values). No test failed before or after.

The 15 scripts/tests skips are identical before and after, and all are
environmental:

- `test_source_binding_http.py`, `test_source_binding_readback.py`: need the
  isolated grpcio extra;
- `test_evidence_contracts.py:335` and 4 in
  `test_typescript_content_contract.py`: need `npm ci` and a built
  `sdk/typescript/dist`;
- `test_package_contracts.py:271`: case-insensitive filesystem (macOS);
- 7 in `test_s3_live.py`: no live S3 credentials.

Docker was available, so the Docker-backed node e2e tests ran and passed in
both runs. There were no machine-specific failures to compare.


## 10. Recommended order of work

1. **Land this change** (CrewAI and e2e-smoke). No owner decision needed.
2. **Spec rev 4 decides G1–G10** (section 2), especially G2 (PROTECT stage on
   the single writer path) and G3 (seal). Nothing below should start before
   those decisions, because the merges move these guarantees.
3. **Owner sign-off on the out-of-scope set** (no guarantee moves; pure
   deletion): `deployment_state`, `capture_identity`, `capture_readback`,
   `control_protocol`, `reference_receipts` (out of the wheel),
   `distributed_closure`, `enterprise`, `enterprise_preflight`,
   `capture_capabilities`, `coverage_manifest`, `_coverage_canary`,
   `_instrumentation_registry`, plus their tests, `examples/enterprise-*`,
   the enterprise scripts, `benchmarks/`, and the dead qualification
   rehearsals (sol, local-go). Then decide `auto_instrument` (public API
   plus 5 extras).
4. **Spool and sequencer convergence** (build work after rev 4): fold
   `source_spool` (seal, epochs) and `byte_spool` (encryption, error classes)
   into `wire/_spool.py` and `_sequence.py`; move `_capture_health` into
   `_loss`.
5. **Single sender and writer**: `CallRecorder`, `byte_evidence`,
   `byte_boundary` and the records content path (`_content_writer`,
   `_content_sink`) become records producers enqueuing into the wire spool;
   retire `metadata_delivery`, `call_otlp`, `synthetic_otlp`. Do the same in
   TypeScript with the spec 048 spool (F-C). Replace the spec 040 kind e2e
   gate with a wire/records kind e2e before deleting `synthetic_evidence`.
6. **Single verifier**: fold `resolver`, `byte_resolver`,
   `governed_reconstruction`, `call_reconcile`, `synthetic_reconcile` (and,
   if kept, `receipt_sets`, `evidence_attestation`, `independent_feed`,
   `qualified_run`) into `fabric.reconstruct`. Retire `python -m
   fabric.resolver` and TS `resolver.ts`.
7. **Node side**: decide G5 (fabricguard `EvidenceSourceBinding`, gate
   dedicated ingress, bearer `require_single_token`, chart
   `evidenceSourceBinding`) as one unit; move governed-store encryption and
   privacy fields into `fabriccontent` (spec 050).
8. **Housekeeping**: delete the historical `qualification/` pile and the
   benchmark evidence (link a commit instead); regenerate
   `examples/reference-agent/uv.lock`; update `deploy/README.md`; fix the
   stale spec 049 auditd-netlink item; drop `adapter` from fabricctl's
   input methods.

## 11. OWNER list with recommendations

Every OWNER row needs sign-off before it is merged or deleted. Grouped by
recommendation; the per-row reasoning is in sections 3–7.

**Delete (out of scope or dead; no guarantee moves)**

- `deployment_state.py`, `capture_identity.py`, `capture_readback.py`:
  policy registry and principal binding are management/rollout scope.
- `control_protocol.py`: an external-controller contract belongs with a
  future Control Runtime, not the recorder.
- `reference_receipts.py`: an HTTP + SQLite receipt service inside the SDK
  wheel; move it to test apparatus.
- `distributed_closure.py`: used only by the enterprise reference.
- `enterprise.py`, `enterprise_preflight.py`: thin wrappers; move any config
  check to `fabricctl recorder validate`.
- `capture_capabilities.py`: duplicates the connector manifests.
- `coverage_manifest.py`, `_coverage_canary.py`,
  `_instrumentation_registry.py`: go with `auto_instrument`.
- `synthetic_otlp.py`: after `call_otlp` is merged.
- `examples/enterprise-orchestration`, `examples/enterprise-reference`
  (replace the README and quickstart links with `wire-capture`),
  `examples/enterprise` (with `deployment_policy` fixtures moved to tests).
- `benchmarks/fabric-comparison` and its evidence: stale, run by nothing.
- `qualification/` historical pile, sol and local-go rehearsals and their
  scripts/tests; `run_composed_collector_journey.py`; the enterprise
  journeys (`run_c8_network_journey.py`, `run_capture_acceptance.py`,
  `capture_measurements.py`, `run_enterprise_local.py`,
  `scripts/qualification/enterprise_preflight.py`).
- fabricguard log classes `decision_summary`/`cost_usage_aggregate`:
  only after checking the private telemetry bridge.

**Merge (a guarantee moves first)**

- Into `wire/_spool.py` / `_sequence.py`: `byte_spool.py` (G1, error
  classes), `source_spool.py` (G3).
- Into `wire/_sender.py`: `metadata_delivery.py`, `call_otlp.py`.
- Into the records producer: `call_recorder.py`, `byte_evidence.py`,
  `adapters/byte_boundary.py`, `adapters/synthetic_evidence.py`
  (G7; replace its kind e2e gate first), `http_dispatch.py` (after 049 P4),
  TS `byte-evidence.ts`.
- Into `fabric.reconstruct`: `byte_resolver.py`, `governed_reconstruction.py`,
  `call_reconcile.py`, `synthetic_reconcile.py` (G6, G9), and, if rev 4 keeps
  the qualified verdict, `receipt_sets.py`, `qualified_run.py`,
  `independent_feed.py`, `independent_store.py` (G4).
- Into the Node writer (spec 050): `governed_store.py` (G1, G9).
- Into the shared content contract: `content_join.py`.

**Keep as is, pending a rev 4 decision**

- `deployment_policy.py` and TS `deployment-policy.ts`: the PROTECT
  configuration (G2).
- `evidence_attestation.py`, `contracts/validate_evidence_contracts.py`:
  the receipt/attestation contract (G4).
- fabricguard evidence class and `EvidenceSourceBinding`, the gate's dedicated
  ingress, bearer `require_single_token`, chart `evidenceSourceBinding`: one
  unit (G5).
- `qualification/synthetic-slice/kind-production-*.yaml` and the spec 040
  pilot scripts: keep until a wire/records kind e2e replaces them.

