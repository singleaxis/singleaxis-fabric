---
title: TypeScript model-call wire capture for Node.js agents
status: draft
revision: 3.2
last_updated: 2026-11-13
owner: recorder-engineering
depends_on: 047, 048, 049, 050
related: 027, 029, 032, 035, 043, 045, 046, 051, 052, 057, 058
qualification: NO_COVERAGE_CLAIM
---

# 055 — TypeScript wire capture

**Status: draft; not built; prepared for build.** TypeScript has no wire
capture, released or unreleased, so nothing can verify or replay what a
Node.js agent's model decided. Codes in parentheses such as (R8) or (R12)
name the cross-spec revision decisions that a rule applies, and
"decision n" means row n of 049 §9; the [glossary](../docs/glossary.md)
lists both.

## Revision log

| Rev | Date | Change |
|---|---|---|
| 3.3 | 2026-11-15 | Unit `055-t3` (build notes, no scope change). §4.4: the maintainers' `binding.gyp` lives in `sdk/typescript/native/`, not at the package root, because npm runs `node-gyp rebuild` on install for any package with a root `binding.gyp` and no install script. The shipped prebuilds are compiled by `scripts/typescript/prebuild/compile.sh` (not node-gyp) against the pinned `node-api-headers` dev dependency, with relative paths, no debug info, build id or compiler ident, inside per-platform build images pinned by digest (gcc on Debian 10 for glibc 2.28, gcc on Alpine for musl) and one pinned Xcode for macOS, so the digest table reproduces. §9.2 `typescript-native`: the arm64 Linux targets build and test on native `ubuntu-24.04-arm` runners instead of QEMU (same bytes, no emulation). The codes that need a failing kernel call (`PERMISSION`, `EXISTS`, `NO_SPACE`, `QUOTA`, `IO`, `UNSUPPORTED`, `OVERFLOW`, `FORKED`, `OTHER`) are reached through a test-only fault-injection build of the same sources (`FABRIC_WIRE_FAULTS`, read from `FABRIC_WIRE_TEST_FAULT`), which is never shipped and never digested. The install self-test also reserves the probe page with `allocate` and reads the mapped word back with `pread`. A disabled loader reports `FW-027` for `platform_unsupported` and `FW-028` for the other five reasons. |
| 3.2 | 2026-11-13 | Unit `055-t2` (build notes, no scope change). TypeScript reports `FW-025` wherever Python's `wire/_diagnose.py` reports its generic `FW-001` (§4.7: `FW-001`'s fix names a Python command); every other configuration id is Python's, checked against `python -m fabric.wire status` for each case of `test/wire/fixtures/config-env.json`. Configuration errors are typed by catalogue id at the throw site (the generated `TypeScriptCatalogueId`), not found by message substring; a message names the variable and the rule, never the value (Python's `invalid endpoint matcher` message quotes the endpoint id; TypeScript's does not). An OTLP route whose protocol is `grpc` is a configuration error in TypeScript (`FW-024`, fix: `FABRIC_OTLP_ENDPOINT`), where Python accepts it: the Node sender speaks only OTLP/HTTP (§7.1). `FABRIC_WIRE_BUILTIN_ENDPOINTS=legacy` selects the table's `legacy_endpoint_ids` rows (§3.4); a test keeps them equal to Python's hard-coded `LEGACY_ENDPOINTS`. `FABRIC_IDENTITY_MODE`, `FABRIC_WIRE_UNDICI` and `FABRIC_WIRE_NODE_HTTP` are validated by the configuration (`FW-025`); `FABRIC_RUN_OPEN_DEADLINE_S`, `FABRIC_CLOCK_UNCERTAINTY_MS` and `FABRIC_RECORDS_MAX_OBJECT_BYTES` fall back to their defaults with a note, as Python's `_manifest.py` does. As Python's `RedactionService` does, the configuration reads `FABRIC_REDACTION_TOKEN_FILE` once (missing: `FW-019`; not owner-only: generic; not one token: `FW-019`). Keys, that token and OTLP header values are non-enumerable properties of the settings, so printing them never shows a secret (Python: `repr=False`). The TS-0 inventory (R9) is built in this unit, not deferred: `test/wire/ts0/stringify-inventory.json` lists each automatic stringification in `decision.ts`, `calls.ts` and `byte-evidence.ts` with a verdict; two are `follow_up` items for `055-t20` (the unbounded `JSON.stringify` of opt-in GenAI content in `calls.ts`, and `fabric.tool.error_category` emitted without its registry check). `spool-bytes-v1.json` is re-read by `scripts/contracts/spool_bytes.py` (no `fabric` import); capture contract 1.11.0. |
| 3.1 | 2026-11-13 | Unit `055-t1` (build notes, no scope change). Audit result (§3.1, §10.3): Node 22.23.5, 24.0.0 and 24.3.0 (bundled undici 6.29.1, 7.8.0, 7.10.0) publish neither body-chunk channel; 24.4.0 (undici 7.11.0) and 24.22.3 (7.30.2) publish both, on linux x64/arm64 glibc and musl and macOS arm64, so the candidate minimum is **24.4.0**, not 24.13.1 (OQ-2's example). Every audited build publishes the response chunk **before** decompression (`boundary: pre_decompression`; §9.4's example shows the other value). §9.4's table gains `audit_script`, `audits` (one row per exact build, re-checked in CI on exact pins 22.23.5, 24.0.0, 24.4.0, 24.22.3) and a tuple `claim` (`audited`: publications observed, written by `055-t1`; `active`: requires `report_sha256`, from `055-t6`), which reconciles §9.5's "audited candidate tuples" with §9.4's "a tuple enters the table in the unit that proves its body publications". §4.4's codes take the values −1 to −16 in the listed order. §4.7: FW-011 (OTLP exporter package) has no TypeScript counterpart, since the TS sender has its own encoder and nothing to install; the status schema adds the optional `sdk_language` and, in `status`, `capture_point_reasons`, `runtime_qualification` and `spool_backlog`. §8: the `fix` text is in each row's `activation` (058's `integration-rows-v1.json` is not on main); a rounded int64 is refused by its lexical form (a fraction or exponent), since an integer a float64 rounded and printed without one is indistinguishable from a real value. |
| 3 | 2026-11-10 | Prepared for build against main `be39aca6`. §2 refreshed with current `file:line` anchors (TypeScript SDK after #256 and #286, the Python P1 runtime, spec 057 P0 records, the delivery fix #289, and spec 058 E1a #291: diagnostics catalogue, endpoint table, status file, `FABRIC_OTLP_*`). §3.4 and §4.7 bind TypeScript to the shared endpoint table and diagnostics catalogue of #291. §10 settles R1–R16: confirmed where Python has built them as written; only open items remain in §14. §9.5 replaces the parallel waves with 22 build units, one PR each, stacked, ordered so a Node agent using global `fetch` or the official `openai` / `@anthropic-ai/sdk` clients gets a verified, replayable record first (TS-1U + TS-1D), then core HTTP (TS-1H). §9.2 names the CI jobs that measure the passivity and privacy gates. §7.1 follows #289 (several content records per request, with a one-per-request fallback). §9.3 drops matrix rows named after agent frameworks. §13 aligns with spec 058 (preload name, `fabric run`, injector, npm launcher, G2) and names the interface spec 057 WP7-16 uses. |
| 2 | 2026-10-22 | Applied the cross-spec revision decisions R1–R16 (defined in the introduction of [050](050-run-structure-and-records-p1.md)); bound TypeScript to 050's P1 run, records, seal and delivery contract; froze the native addon ABI; moved every Python edit to its Python owner; split the oversized runtime work package. §12 maps every review finding to its resolution. |

## 1. Scope and release gates

Implement spec 049 §8.2 TS-0 and TS-1, decision 9, as a parallel track.
TS-2 (new P2/P3 reporting APIs) is outside this build. Python phase exits
never depend on this track or on any work package in it. Shared
P0/P0-A/P1 contracts are dependencies; the TS track does not wait for the
Python implementation to finish, but it binds to 050's frozen interfaces
(§4.3) rather than defining its own run, token, seal or records semantics.

The product remains **CAPTURE -> PROTECT -> DELIVER**: an opt-in, passive
Node.js recorder of matched model HTTP exchanges, with protected content,
durable delivery and field-level coverage. Zero-code means a deployment
preload and configuration, with no changes to agent or provider calls.
Installing the npm package alone installs no hooks. No framework adapters,
evaluation, control execution or required SingleAxis connection ships.

Copy of the authoritative TS gates (049 rev 6.8, lines 3542–3551):

> - TS-0: `decision.ts` parity for P0-A identity rules and new keys.
> - TS-1: `wire.ts.undici` on Node.js 24+, for qualified undici versions
>   only; subscribers bounded, exception-contained, never throwing, retaining
>   immutable data, with a queue bound and a latency gate (undici documents
>   its diagnostics channel as synchronous and experimental); spool and
>   sender per 048. Gate: capture goldens byte-identical with Python; the
>   same exchanges reconstruct identically.
> - TS-2: P2/P3 reporting APIs.
> - Until each gate passes, the TypeScript manifest reports those capture
>   points `unsupported`.

Tighten TS-1 into three independently reported qualification gates:

| Gate | Capture point / deliverable | Additional exit condition |
|---|---|---|
| TS-1U | `wire.ts.undici`; global fetch and qualified external undici, including the official `openai` and `@anthropic-ai/sdk` clients using them | Request and response chunk publication proven for the exact runtime/transport build; JSON, SSE, compression and early termination byte fixtures; passivity and privacy gates below |
| TS-1H | New `wire.ts.node_http`; `node:http` and `node:https` HTTP/1.x | Separate hook qualification; request write/end and response push identity, backpressure, exceptions and cancellation unchanged |
| TS-1D | Both points' common protection, spool, sender, lifecycle and readback | Python-format frames/envelopes, shared source sequencing, 050 loss/manifest/seal/token vectors, restart/chaos and bound-source Node e2e pass |

TS-1U + TS-1D permit an undici-only claim; TS-1H is independently gated.
An unqualified point cannot become active because another point passed.
The full scope of this build exits when all three pass. These additions do
not move TS-2 into TS-1 or expand the model-calls coverage profile.

**Build order (§9.5).** TS-1U and TS-1D are built first, because global
`fetch` and the official `openai` and `@anthropic-ai/sdk` clients all send
through undici: units `055-t1`–`055-t17` end with the undici-only claim.
`055-t18` switches spec 058's zero-code path to Node. `055-t19`–`055-t20`
add application worker threads and the records bridge that spec 057
WP7-16 builds on. TS-1H (`055-t21`–`055-t22`) comes last. §9.5 says what
each unit makes newly visible.

### 1.1 Fields and boundaries

Both wire points supply this exact proposed registry set, matching the
Python wire rows:

```text
X08 X22 X24 X40
C34 C35 C37 C40
S07 S08 S09 S10 S11 S29 S30 S32
N01 N02 N07 D31
```

`C35` is the persisted matched-endpoint id `fabric.wire.endpoint_id`
(R15; 050 §3.9, WP-00 contract, WP-14 Python emitter): `<provider>.default`
for a built-in endpoint, else `lbl-` + keyed v1 label of the configured
name (clear name only under `FABRIC_WIRE_LABELS=clear`), never a host or
path. `C40` remains explicitly off unless enabled; 050 WP-14 builds the
Python opt-in (050 OD-13), and TS implements the same opt-in. `S32` supplies
only an observed cancellation state, never an invented requester. `N02`
applies only to split bodies. Supplied fields still carry absence,
withholding, truncation or unsupported reasons; the set is not a claim
that every exchange contains every value.

Supporting points retain their registered ownership: `fabric.self`
supplies identity, event/attempt ids, trace position, clocks, provenance,
privacy, manifest, loss and seal fields (`X01–X03`, `X06–X07`, `X17–X20`,
`X23`, `X25–X27`, `X29`, `X32–X36`, `X38–X39`, `X44–X45`, `X47`, `C16`,
`S01`, `S03`, `S31`, `D11`, `D24`, `D34`); `install.config` supplies
`X04–X05`, `X31`, `C12`, `C15`; `run.scope` owns the existing run and
segment field rows, including `X41–X43`, `X46`. Do not assign these fields
to a transport just to enlarge its coverage list.

The existing offline parser supplies `C19–C23`, `C36–C39`,
`N03–N16`, `N18–N21`, `N53`, `N55`, `N60`, `D17`, `D32–D34` where
supported by stored evidence and registered parsing/inference methods.
Keep provider assertions, literal observations and inferred links distinct.
Automatic wire capture does not observe local tool execution, framework
nodes, memory, retrieval, side effects or task success. `D30` comes only
from `endRun` in TS-1 (§4.3). `D35` cost remains downstream; `X37`
delivery receipts remain a contract, not automatic proof.

## 2. Current state at main `be39aca6`

Paths and line numbers were read from main at `be39aca6` (2026-11-10,
after #291).
TypeScript paths are relative to `sdk/typescript/`; Python paths are
relative to `sdk/python/src/fabric/`. No TypeScript wire directory,
preload, native addon or Node sender exists: `sdk/typescript/src/` has no
`wire/` folder and no file imports `diagnostics_channel` or `undici`.

### 2.1 TypeScript SDK (what exists and what 055 reuses)

| Area | Existing code | Reuse / missing work |
|---|---|---|
| Package | `package.json:3` version 0.12.1; `:16–27` one root export (ESM `dist/index.js`, CJS `dist/index.cjs`); `:33` `sideEffects: false`; `:51–53` `engines.node >=22.18.0` (#256); `:64–67` peers `@opentelemetry/api >=1.9.0 <1.11.0` and optional `@aws-sdk/client-s3` (#286); `tsup.config.ts:5–17` builds ESM and CJS from `src/index.ts` only | Unit `055-t14` adds the `./wire` and `./register` exports, the one-file CJS wire core and the prebuilds. The package engine range stays `>=22.18.0`; wire capture needs a qualified Node 24 build and reports `unsupported` elsewhere (§3.1). tsup builds separate ESM and CJS bundles, so `identity.ts`'s `MINT`/`ISSUERS` (`identity.ts:321–322`) exist once per bundle; the wire core therefore ships as one module instance (§4.1) |
| CI | `.github/workflows/recorder-ci.yml:159–196` job `typescript-sdk`, Node 22 and 24: `npm ci`, lint, typecheck, build, `vitest`, then `npm run test:fresh-install` (`scripts/fresh-install.mjs`, #286) | The wire tests join this job; the passivity, privacy and native jobs of §9.2 are added by units `055-t3`, `055-t6`, `055-t8` and `055-t13` |
| Identity | `src/identity.ts:32` v2 type table; `:72` surrogatepass encoding; `:118` v1 labels; `:146` v2 HMAC; `:161` identity key id; `:209` `IdentityPolicy` (`clear` returns the value as given, `:253–257`); `:321–366` issuer-checked `EmittedId` | Reuse unchanged; 055 makes no edits to this file (§9.1). Never recognize emitted provenance by string shape |
| Decision identity | `src/decision.ts:633`, `:701–713` and `:805` map session, agent and user ids through `IdentityPolicy`; `:528` `FABRIC_RECORDS_STRICT` | TS-0 is an audit and regression gate (`055-t2`). Sequencing and wire/explicit scope ownership are still missing. `decision.ts` has no `recordControl`, `recordGrant` or `recordExtension`; spec 057 WP7-16 adds them after this lane (§13.2) |
| Explicit records | `src/decision.ts:1300–2031` (`recordRetrieval` … `recordInteraction`), `src/calls.ts:237` `LlmCall`, `:452` `ToolCall`, `src/byte-evidence.ts:327` | Emitted as host OpenTelemetry spans only: unsequenced, no spool, no seal. The Python reader shows them as *reported* (058 §13.3). Unit `055-t20` routes them through the records input |
| OTLP transport (#286) | `src/otlp-transport.ts:90` `otlpTraceTransport` (plaintext only to loopback, Python rule parity), `:127` `captureStatus`, `:146` `reportCaptureStatus`; `src/tracing.ts:105` `installDefaultProvider`; `src/client.ts:124` `Fabric` | The wire sender uses its own private clients (§7.1) and reuses only the endpoint rule of `otlp-transport.ts:90`. Wire status reasons extend `captureStatus`'s vocabulary (§4.7) |
| Redaction service | `src/redaction.ts:89` endpoint check; `:127` no-follow token file; `:166` bounded client; `:223` in-flight bound | Reuse this client in Fabric's worker. Unix socket or numeric loopback HTTP only; no customer process/thread/plugin execution |
| Protection | `src/deployment-policy.ts:107` `DeploymentPolicy`; `:293` `ContentProtector`; `:308` 1 MiB default payload cap; `:336` tokenization key check; `:371` `protectAsync` | Reuse; explicitly set the wire payload cap. Add wire split/review orchestration; `original_plus_masked` is not implemented by this single-object protector (`:40`). The loader does not accept the `security_context` policy section that spec 057 P0 added to Python (`deployment_policy.py:120`); WP7-16 owns that |
| Byte evidence | `src/byte-evidence.ts:282` config, `:327` recorder, `:377` 1 MiB default | Existing explicit bounded process-memory queue. It has no source spool or durable receipt. Reuse rules, not this queue as a wire durability claim |
| Content writer | `src/content-writer.ts:33` `fabric.content-spool/v2`; `:176` `ContentWriter`; `:512`, `:520`, `:708` synchronous fsync | Not the 048 wire frame, encrypted spool, shared admission or loss ledger; must not run from a wire hook |
| Governed content | `src/content-sink.ts:31`; `content-store.ts`; `content.ts` | Reuse governed storage/descriptor primitives behind the common writer. A transcript manifest is not a capture capability manifest |

### 2.2 Python reference (built; what TypeScript ports)

Spec 050 waves 0–2 are released (v0.10.0); [the P1 run
record](../docs/run-record.md) lists the modules. TypeScript ports the
code below, not the historical 047/048 limits.

| Area | Reference on main | TypeScript port |
|---|---|---|
| Matching | `wire/_match.py:31` `EndpointIndex`, `:42` `match`; `wire/_routes.py` route table (`internal`, `owned`, `model`, `nonmodel`, `none`) | `wire/match.ts` ports `EndpointIndex` and the `internal`, `owned` and `model` routes. No non-model route in this build |
| Capture | `wire/_stream.py:191` `Exchange`, `:394` finish-once, `:98` `adopt`; `wire/_transport.py:117` `WireTee`; `_capture_scope.py:45` `ExplicitScope` | Bounded retention, finish-once, provisional explicit ownership. Sticky withholding (050 WP-40) is not built in Python either; TypeScript implements 049's rule directly (§4.6) |
| Limits | `wire/_config.py:41–48` (64 MiB side cap, 63 MiB Node object cap, 1 MiB reserve, 16,384 queue entries, batch 256 / concurrency 16 maxima), `:147–176` `WireConfig` (32 MiB object, retained bytes, 256 MiB in flight, queue, `drain_on_exit_s`, content batch 32 / concurrency 4) | Same defaults and maxima (§4.2) |
| Protection | `wire/_protect.py:129` `find_parts`, `:179` `skeleton_of`, `:200` `Protector`; `wire/_pipeline.py:141` `Budget`, `:242` `CapturePipeline`, `:394` `submit` | `wire/protect.ts`, `parts.ts`, `worker.ts` |
| Spool | `wire/_spool.py:61–66` magics (`FWSPOOL1`, `FWSPOOLB`, `FWSPENC1`), `:67–75` reserve, lock names, 5 s admission deadline, `:118` `MAX_BODIES = 260`, `:181` `frame`, `:247` `unseal`; `wire/_keys.py:65` spool key id; `wire/_ledger.py:50–58`, `:96` `LossLedger` | `wire/spool-codec.ts`, `spool.ts`, `ledger.ts`; byte-identical frames (§6.2) |
| Epochs | `wire/_registration.py:61–72` (`FWEPOCH1`, 4,096-byte file, offsets, 8 redraws), `:84` `Registration`; `_sequence.py` allocator and pseudonyms | `wire/registration.ts`, allocator in `runtime.ts` (§4.5, §6.1) |
| Records input | `_records.py:479–497` `Attempt.emit` (three status inputs), `:548` `RecordsInput`, `:610` `begin`; `_capture_types.py:43–123` vocabularies and bounds | `wire/p1-types.ts`, `wire/records-input.ts` |
| Runs | `_segments.py:96` token prefixes, `:158–183` token grammar, `:210–241` identity rules; `_seal.py:157` `record_digest`, `:175` `seal_digest`, `:229` `SegmentSeals`; `_loss.py:69` segment-keyed losses, `:349` aggregation; `_manifest.py:753` `build_manifest`, `:789` `emit_initial`; `wire/__init__.py:960` `run`, `:1061` `resume_token`, `:1070` `resume_tokens`, `:1078` `end_run` | `wire/scope.ts`, `segments.ts`, `seal.ts`, `loss.ts`, `manifest.ts`, `run-api.ts` |
| Exchange span | `wire/_attrs.py:45–81` (C40 opt-in `FABRIC_WIRE_PROVIDER_REQUEST_ID`, `fabric.capture.point`, `fabric.capture.source`, `fabric.wire.endpoint_id`) | `wire/worker.ts` span build (§7.1) |
| Delivery (#289) | `wire/_content.py:21` result classes, `:83` `NodeContentClient`, `:127` `send`, `:140` `send_many` (several bodies per request, one-per-request fallback); `wire/_sender.py:102` `Sender`, `:613–656` progress and `content_rejected`; `tracing.py:557` `delivery_proxy_from_env`, `:578` `pin_delivery_proxies` | `wire/node-content.ts`, `sender.ts`, `delivery.ts` (§7.1) |
| Status and diagnostics (#287, #291) | `wire/_status.py:174` `env_status` (`python -m fabric.wire status`); `wire/__init__.py:917` `status()`; `wire/_diagnose.py:122–143` (reason, catalogue id and fix per configuration error); `wire/_statusfile.py:34–35` (`FABRIC_WIRE_STATUS_FILE`, schema `fabric.wire-status/v1`), `:116–145` install, failure and exit documents with `warning_ids` / `notice_ids`; `wire/__init__.py:134` exit-backlog note | Same status document, ids and reasons (§4.7) |
| Diagnostics catalogue (058 §13.1, #291) | `contracts/diagnostics/v1/messages-v1.json`: `FW-001`–`FW-024` (SDK) and `FC-001`–`FC-010` (CLI), each a stable id, fixed text and fix with no interpolated value; packaged in Python as the generated `_catalogue_data.py`; `sdk/python/tests/test_diagnostics_catalogue.py` requires every catalogued id to be emitted by Python code; docs page `docs/diagnostics.md` is generated from it | TypeScript emits catalogue ids, never its own message table (§4.7). `055-t2` adds the TypeScript-only entries |
| Built-in endpoint table (058 §8.1, #291) | `contracts/providers/v1/builtin-endpoints.json` (table version 1: `openai`, `anthropic`, `azure-openai`; other providers are `candidates`, not shipped); generated `wire/_endpoint_table.py`; `wire/_config.py:52` `LEGACY_ENDPOINTS`, `:106` `builtin_endpoints_from_env` (`FABRIC_WIRE_BUILTIN_ENDPOINTS=table\|legacy`) | TypeScript's defaults are generated from the same table (§3.4) |
| `FABRIC_OTLP_*` route (058 WP8-6, #291) | `tracing.py:379` `fabric_otlp_selected`, `:416` `_fabric_signal_settings`, `:465` `otlp_signal_settings` (Fabric's own variables win over `OTEL_EXPORTER_OTLP_*`; http/protobuf) | `wire/config.ts` and `delivery.ts` apply the same precedence |
| Operator CLI (058 E1a, #291) | `cli/__init__.py:37–38` command table; only `version` and `help` are built, the rest report `FC-010`; `cli/_config.py` (`fabric.yaml`), `cli/_providers.py` | `055-t18` adds the Node branch to `run` when 058 WP8-4 is in its base (§13.1) |
| Security context (057 P0, #277–#280) | `_rec_grant.py:829` `record_grant`, `_rec_controls.py:271` `record_control`, `_rec_extension.py:187` `record_extension`, `_rec_check.py` (`control_check`), reader `reconstruct/_security.py`, `_controls.py` | Not in 055. WP7-16 adds the TypeScript APIs on the seam of §13.2 |

### 2.3 Contracts and vectors

| Artifact | State on main | Work |
|---|---|---|
| `contracts/coverage/v1/registry/capture-points-v1.json:139` row `wire.ts.undici` | Runtime `Node.js 24+, qualified undici versions only`, state `TS track; manifest reports unsupported until built`, supplies `N01` only | `055-t1` applies §8 |
| Same registry, `wire.ts.node_http` | Absent. `node_http` is an `uncaptured_classes` member (`coverage/v1/schema/capture-manifest-v1.schema.json:402`, `capture/v1/schema/capture-manifest-record-v1.schema.json:279`) | `055-t1` adds the row |
| `contracts/coverage/v1/valid/manifest-typescript-unsupported.json`; `telemetry-keys-v1.json:1119` example `wire.ts.undici@0.0.0:W:unsupported:1:1:unsupported_runtime` | Present | Kept; `055-t1` adds the fixtures of §8 |
| Shared vectors `contracts/coverage/v1/fixtures/vectors/`: `resume-token-v1.json`, `resume-token-v2.json`, `seal-digest-v1.json`, `seal-parity-v1.json`, `manifest-chain-v1.json`, `manifest-span-v1.json`, `run-marker-v1.json`, `records-span-v1.json`, `span-category-v1.json`, `pseudonym-v2.json`, `record-evidence-v1.json` | Built by 050 WP-00; reference code `scripts/contracts/p1_reference.py` | Mandatory TypeScript tests (`055-t2`, `055-t9`–`055-t11`) |
| Spool fixtures `contracts/capture/v1/fixtures/valid/spool-record-*.json` (exchange, 260-object exchange, record, loss with segment, markers, manifest, terminal seal) | Built | TypeScript round-trips each one (`055-t7`) |
| Encrypted spool, ledger and registration byte vectors | Absent | `055-t2` adds `contracts/capture/v1/fixtures/vectors/spool-bytes-v1.json`, produced by a new generator script from the Python writer and re-checked by the capture validator (§8) |
| Contract versions | coverage 1.4.0, capture 1.9.0 (`manifest.json:3` of each) | Minor bumps in `055-t1` and `055-t2` |

### 2.4 Harnesses

`qualification/` on main holds `action-record/` and `remote-sandbox/`
only. The agent-matrix and chaos harnesses are still on the branches
`origin/test/agent-matrix` and `origin/test/chaos`; R16 (merge them to
main) has not happened and no unit in the program does it. TypeScript
qualification therefore does not wait for them: it lives in its own
tree, `qualification/node-wire/` (§9.3, §14 OQ-7). Existing Node e2e
patterns are in `scripts/tests/test_wire_capture_node_e2e.py` and its
`_wire_capture_*` helpers (sink, agent, common); throughput tooling is
`scripts/qualification/bench_wire_capture_throughput.py`; the Python
passivity gate is `sdk/python/tests/test_wire_passivity.py`. The field
harness (`fabric-field-harness`, outside this repository) has no Node
agent shape; its delivery finding F1 was fixed by #289 and the
TypeScript sender starts from the fixed design.

## 3. Runtime qualification and capture points

### 3.1 Node 24 floor; Node 22 negative coverage

The owner-approved major-version floor is **Node 24**. Do not broaden it
to 22 because `diagnostics_channel` exists there. Run Node 22 compatibility
tests to prove fail-open preload and an unsupported manifest; existing
non-wire SDK APIs keep their present engine range (`>=22.18.0`), so
`npm i @singleaxis/fabric` keeps working on Node 22 and the preload there
is a no-op with status `unsupported(unsupported_version)`.

Node major alone is insufficient. Node 24.0.0's vendored undici lacks both
body-chunk publications; Node 22.0.0 does too. Compare the pinned
[Node 24.0.0 channels](https://raw.githubusercontent.com/nodejs/node/v24.0.0/deps/undici/src/lib/core/diagnostics.js)
and [Node 22.0.0 channels](https://raw.githubusercontent.com/nodejs/node/v22.0.0/deps/undici/src/lib/core/diagnostics.js).
Undici's [diagnostics API](https://undici.nodejs.org/api/DiagnosticsChannel)
documents chunk events and synchronous subscribers, but this is not proof
for every bundled release. Version 7.19.2's
[pinned diagnostics documentation](https://raw.githubusercontent.com/nodejs/undici/v7.19.2/docs/docs/api/DiagnosticsChannel.md)
is a qualification candidate, not a claimed passing build.

Observation while revising this spec (a candidate, not a qualification):
a local `fetch` POST on Node 24.13.1 (bundled undici 7.18.2, macOS arm64)
published `create`, `bodyChunkSent`, `bodySent`, `headers`,
`bodyChunkReceived` and `trailers`; Node 22.23.3 (undici 6.28.1)
published neither chunk channel.

Unit `055-t1` must produce a checked-in compatibility table
(`sdk/typescript/wire-qualification.json`, §9.4) with exact Node patch,
`process.versions.undici`, external undici package/version where applicable,
OS/architecture, source publication sites, boundary and passing report hash.
Pick the lowest passing Node 24 patch as the supported minimum; keep
24.0.0 explicitly unsupported if its producer lacks events. Creating a
channel or observing `hasSubscribers` never proves a producer publishes it.
Do not replace global fetch, install a dispatcher, upgrade the application's
undici or send a probe to a provider to make qualification pass.

An external undici used on Node 24 requires its own qualification. Multiple
copies share channel names without a publisher-version field. The manifest
cannot claim complete capture for a mixture containing an unqualified
publisher. Pin an approved dependency inventory in the deployment; unknown
publisher compatibility is unsupported, never inferred from channel shape
alone. This is a coverage boundary, not a security attestation.

### 3.2 Undici/global fetch

New `wire/undici.ts` subscribes only to these request channels:

| Channel | Action |
|---|---|
| `undici:request:create` | Match method/origin/path; capture clean parent context and run scope; create request-identity entry; allocate unless provisional |
| `undici:request:bodyChunkSent` | Snapshot the published request body chunk; preserve callback ordering |
| `undici:request:bodySent` | Mark request side transport-complete, including zero-byte bodies |
| `undici:request:headers` | Accept final status and permitted media/encoding metadata; informational responses do not finish an exchange |
| `undici:request:bodyChunkReceived` | Snapshot response body chunk and first-chunk monotonic offset |
| `undici:request:trailers` | Finish response once; do not read trailer values |
| `undici:request:error` | Finish once with a validated class/code category; never read message/stack/cause |

Correlate by request object identity in an isolate-local `WeakMap`, plus a
bounded active index for shutdown. Never retain the diagnostic message,
socket, headers object or entire request after extracting allowed values.
All subscribers catch their own failures internally. A rejected promise or
an exception escaping a subscriber is a qualification failure.

The capture boundary is the qualified undici body's publication site:
HTTP payload after transfer framing removal, before SDK JSON/SSE parsing;
compression state is established from that version's source and fixtures.
For a pre-decompression publication retain compressed bytes with their
actual `content_encoding`; for a post-decompression publication use
`identity`. No fabricated compressed-body digest. Unsupported HTTP/2
dispatchers do not inherit HTTP/1 qualification. No TLS/socket interception.

Do not call `Response.clone()`, `tee()`, `arrayBuffer()`, `text()`, a reader
or an iterator for Fabric. Reading ahead would change backpressure and
memory. Transport publications can include bytes undici already received
before application consumption; receipt does not establish consumption.

The official OpenAI and Anthropic JS clients are matrix entries using
this same point, without SDK monkey-patches. Custom `fetch` is covered only
when it demonstrably delegates to a qualified point. A provider SDK retry
is another physical exchange with another attempt id; Fabric never retries
the monitored model call.

### 3.3 node:http and node:https

New `wire/node-http.ts`, a separate process-global opt-in, covers matched
HTTP/1.x model requests. Core HTTP diagnostics lifecycle events alone do
not supply body bytes; do not advertise diagnostics-only body capture.
Use request-creation diagnostics where qualified and thin request/get
export wrappers where needed for that Node patch. Install before application
module evaluation and refresh builtin ESM exports with
`syncBuiltinESMExports()` when export wrappers are installed. Already cached
function references and alternate implementations remain a stated limit.

For each matched `ClientRequest`, wrap the qualified `write` and `end`
paths and the associated `IncomingMessage.push` boundary. Prefer
instance-scoped wrappers to changing every stream prototype. Preserve
receiver, overloads, argument identity, encoding, callbacks, return values
and `write(false)` backpressure. Snapshot a candidate request chunk before
calling the original; commit it only when the original accepts the write
(a false return still means accepted). If it throws, propagate that exact
exception object and discard the candidate. A request-local delegation
flag prevents `end(data)` or `_writev` from counting the same accepted
payload twice. Cork/uncork never causes a forced flush.

Observe the response's parser-fed push path, not a `data` listener: adding
a reader would make a paused stream flow. Forward the same chunk object
and preserve the original push return value. String encodings and
`setEncoding()` must leave caller decoding unchanged; observe raw bytes
before that decoding. Unsupported subclass/overridden paths pass through
with a capture failure, not a reconstructed JSON approximation.

Lifecycle wrappers may observe `emit`/destroy/EOF, but must delegate exactly
once with the same arguments and result. Catch only Fabric bookkeeping;
never swallow an exception from the original. Do not add an `error`
listener that consumes an otherwise unhandled error. Aborted, timeout and
close races use the same finish-once state machine as undici. No socket
reads, global `net`/TLS patches, extra listeners that change stream flow,
or assumption that an HTTP 200 means the body completed.

Axios is not a new capture point or a promised framework integration. A
pinned Axios HTTP/1 adapter can qualify through this point; other adapters
remain uncaptured. Generic non-model HTTP stays outside this build.

### 3.4 Matching, redirects and proxies

Port `EndpointIndex` semantics from `wire/_match.py:31–61` and 047 §2 exactly:
POST only; allowed scheme; lowercase exact host or configured suffix;
optional port; configured path prefix and one of `/chat/completions`,
`/responses`, `/completions`, `/embeddings`, `/messages` for its dialect.
The built-in matchers come from the shared endpoint table
`contracts/providers/v1/builtin-endpoints.json` (058 §8.1): `055-t2`
generates `src/wire/endpoint-table.generated.ts` from it, with a test
that keeps it equal, as Python's `wire/_endpoint_table.py` is. Only rows
with `default: true` are on; `FABRIC_WIRE_BUILTIN_ENDPOINTS=legacy` pins
`legacy_endpoint_ids`. Table version 1 holds `api.openai.com`,
`api.anthropic.com` and `.openai.azure.com`; a row added to the table
later reaches both languages by regeneration, with no 055 change. The
status document reports the table version.
Only explicitly configured matchers allow HTTP. Preserve Azure/custom
base-path behavior. Queries are ignored for matching and never retained.
Endpoint hosts, paths and proxy URLs never appear in manifests: only the
endpoint-set canonical digest, `fabric.wire.endpoint_id` (C35) and safe
configured labels are exported.

No new redirects: Fabric's sender/redaction traffic never follows any
3xx, including 307/308. The monitored fetch retains its own redirect policy;
Fabric must not set `redirect:error` or otherwise change it. Each actual
hop is matched separately, and an unmatched redirect target is not
captured. This distinction is required for passivity.

Preserve the application's proxy/dispatcher/agent choices. Fabric delivery
ignores `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, system proxy
discovery and Node's environment-proxy defaults. Use explicit private
agents with ambient proxy discovery disabled. Literal loopback delivery is
always direct, even with `FABRIC_WIRE_PROXY`. Remote delivery requires
HTTPS; only `FABRIC_WIRE_PROXY` may select an HTTP(S) CONNECT proxy, with
end-to-end Node certificate verification. Ingress authorization stays
inside the TLS tunnel; proxy credentials go only to the proxy. Never
mutate `process.env`, global agents or application trust settings. This
ports Python `tracing.py:557–606` (`delivery_proxy_from_env`,
`pin_delivery_proxies`) and 047/048 redirect hardening.

## 4. Modules, APIs and the passive handoff

### 4.1 Owned modules

| New area | Responsibility |
|---|---|
| `src/wire/config.ts`, `types.ts`, `p1-types.ts`, `match.ts`, `codec.ts`; generated `endpoint-table.generated.ts`, `catalogue.generated.ts` | Validated wire configuration, immutable internal DTOs, TS port of 050's P1 interface types, matching, exact int64/canonical JSON/OTLP encoding; the built-in endpoint table (§3.4) and the diagnostics catalogue (§4.7), generated from their contracts |
| `src/wire/native.ts`; `native/fabric_wire.c`, `native/fabric_wire_abi.h`, `binding.gyp` | Loader and the Node-API addon of §4.4: kernel lock, fd and mmap primitives plus isolate-teardown notification; nothing else |
| `src/wire/runtime.ts`, `arena.ts`, `queue.ts`, `isolate.ts`, `exchange.ts`, `registration.ts` | JavaScript shared runtime of §4.5: SharedArrayBuffer control block, allocator, byte arenas, completed-job ring, isolate attach, exchange slots and finish-once state; epoch registration files (050 §3.2) |
| `src/wire/scope.ts`, `segments.ts`, `seal.ts`, `manifest.ts`, `loss.ts`, `run-api.ts` | ALS scopes and D2 ownership; 050 run table, segments, tokens, `endRun`; seal accumulator; manifests; segment-attributed losses |
| `src/wire/undici.ts`, `node-http.ts` | Transport hooks only; no protection, hashing, disk, network, logger or span construction |
| `src/wire/worker.ts`, `protect.ts`, `parts.ts`, `writer.ts` | Fabric-owned worker; extraction, existing protector/redaction client, descriptor construction, unified content writer |
| `src/wire/spool.ts`, `ledger.ts`, `spool-codec.ts` | 048 durable spool, accounting, encrypted frames, recovery and metadata-only emergency ledger (locks through §4.4 only) |
| `src/wire/sender.ts`, `node-content.ts`, `delivery.ts`, `otlp.ts` | Private bound-source OTLP delivery, retry, permanent rejection and retirement; the pinned OTLP protobuf encoder |
| `src/wire/status.ts` | Content-free status snapshot, catalogue ids with fixes and the status file (§4.7) |
| `src/wire/records-input.ts` | TS port of 050's records input (`RecordsInput`, `Attempt`, `RecordBody`); the seam existing explicit producers call (§6.1) |
| `src/wire/index.ts`, `src/register.ts` | Explicit API (`@singleaxis/fabric/wire`) and the synchronous ESM/CJS preload (`@singleaxis/fabric/register`, the name spec 058 §5.5 uses) |

The wire core is built once, as CommonJS, and both the ESM and CJS wire
entry points (`@singleaxis/fabric/wire`, `@singleaxis/fabric/register`) load that one
file, so each isolate has exactly one wire module instance regardless of
module format. The root package does not import the wire core; the
records bridge finds an installed runtime through a per-isolate
`globalThis[Symbol.for("fabric.wire.runtime/1")]` slot and is inert
without it. Values crossing that bridge are already-emitted attribute
values and are not mapped again; an `EmittedId` from another module copy
or isolate is caller input and is mapped (the safe direction).

### 4.2 Public API and configuration

Proposed exports (camelCase TS facade over unchanged wire/contract names):

```ts
import { install, run, resumeToken, resumeTokens, endRun } from '@singleaxis/fabric/wire';

const capture = install({ nodeHttp: true }); // optional explicit alternative to preload

// Process A: a root run with a clear caller id (mapped unless identity_mode=clear).
const token = await run({ runId: 'clear-order-id', sessionId: 'clear-session-id' }, async () => {
  await existingAgent();
  return resumeToken(); // string | undefined; requests the seal, does not wait for it
});

// Service B (another host): only the token crossed, as the `fabric.resume` baggage entry.
await run({ resume: [token] }, () => continueAgent()); // run id = the token's correlation id

const status = endRun({ outcome: 'completed', stopReason: 'goal_reached', resume: [lastToken] });
const ok: boolean = await capture.flush({ timeoutMs: 2000 });
await capture.close({ timeoutMs: 2000 });
```

`install(options?: WireConfig): WireHandle` installs synchronously;
installation may validate/read config, keys and token files, load the
native addon, register the epoch and initialize disk durability. It never
sends a provider probe and never throws because of capture (R9). As in
050 §3.4, malformed *configuration* is not a recorder call: explicit
`install()` throws fixed text for it, and the preload catches that and
reports a disabled recorder without failing the agent. A missing
prerequisite (key, policy, native addon) is a disabled state with a
reason, never a throw. The handle exposes a content-free status
snapshot, stats, and bounded async `flush`/`close`. Startup recovery,
parsing, crypto and networking run in the Fabric worker, not as deferred
work on the application's event loop. No guarantee that an ordinary
Promise or `setImmediate` isolates CPU work.

The run API is specified in §4.3. Reuse Python environment names and units:
`FABRIC_WIRE_AUTOLOAD`, `FABRIC_WIRE_ENDPOINTS`, `FABRIC_CAPTURE_POLICY`,
`FABRIC_WIRE_ID_KEY`, `FABRIC_IDENTITY_MODE`, `FABRIC_WIRE_LABELS`,
`FABRIC_WIRE_SPOOL_DIR`, `FABRIC_WIRE_SPOOL_MAX_BYTES`,
`FABRIC_WIRE_SPOOL_KEY[_FILE]`, `FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY`,
`FABRIC_TOKENIZATION_KEY[_FILE]`, `FABRIC_REDACTION_ENDPOINT`,
`FABRIC_REDACTION_TOKEN_FILE`, `FABRIC_RUN_ID`, `FABRIC_RUN_RESUME_TOKEN`,
`FABRIC_WIRE_PROXY`, `FABRIC_SOURCE_ID`, `FABRIC_TENANT_ID`,
`FABRIC_WIRE_STORE`, `FABRIC_WIRE_CONTENT_ENDPOINT`,
`FABRIC_WIRE_MODEL_ALLOWLIST`, `FABRIC_CLOCK_UNCERTAINTY_MS`,
`FABRIC_RECORDS_STRICT`, `FABRIC_RUN_OPEN_DEADLINE_S`,
`FABRIC_RECORDS_MAX_OBJECT_BYTES`, `FABRIC_WIRE_PROVIDER_REQUEST_ID` (C40),
`FABRIC_WIRE_CONTENT_BATCH_BODIES`, `FABRIC_WIRE_CONTENT_CONCURRENCY`,
`FABRIC_WIRE_DRAIN_ON_EXIT_S` (#289), `FABRIC_WIRE_DIAGNOSTICS`, and the
existing OTLP endpoint/auth settings in 048. The variables spec 058 WP8-6
and WP8-7 added to Python in #291 (`FABRIC_OTLP_*`, `FABRIC_WIRE_ID_KEY_FILE`,
`FABRIC_WIRE_STATUS_FILE`, `FABRIC_WIRE_BUILTIN_ENDPOINTS`) are read by
TypeScript under the same names and rules from `055-t2` on, so the
compiled environment file `fabric init` writes (058 §6.5) configures a
Node agent unchanged. New separate switches are `FABRIC_WIRE_UNDICI=0|1` and
`FABRIC_WIRE_NODE_HTTP=0|1`. Config precedence: explicit options,
environment, pinned defaults. Snapshot config per epoch; never
enumerate/dump the environment. Unit `055-t2` freezes a Python-to-TS
option/environment mapping with validation fixtures, including unset
versus empty values and endpoint suffix construction.

Defaults: 32 MiB object, 64 MiB retained per side, 256 MiB global retained
bytes, 16,384 queue entries (cap 65,536), 64 KiB part minimum, 16 MiB
records-producer object cap, 1 GiB spool plus 1 MiB emergency reserve,
4,096 receipts and 2 s explicit shutdown timeout. Preserve the Node's
64 MiB request ceiling: a single object is capped at 63 MiB. Content goes
up to 32 records and about 4 MiB per request, 4 requests in flight, with
a one-record-per-request resend when the Node refuses a request (§7.1);
trace batches split by actual encoded
length, never by splitting body evidence. The entry cap and retained-byte
cap are independent, both enforced.

### 4.3 Binding to the P1 contract (050)

TypeScript ports 050 §3.3–§3.7, §3.4a and §3.14 (revision 2, R1–R9).
Names below are 050's; where 050 WP-01 freezes a different name, WP-01 of
this spec follows it without a semantic change. Shared vectors (tokens,
run identity, seals, markers, records spans, span categories, manifests)
are the acceptance test: TS passes 050's vectors byte for byte or the
difference is a defect, not a language choice.

| P1 item (050) | TypeScript binding |
|---|---|
| `run(run_id: str \| None = None, *, session_id, user_id, parent_run_id, resumed_from, links, resume, resumable, final, open_deadline_s)` | `run<T>(options: RunOptions, fn: () => T): T`. Every option is optional, including `runId` (R1). `runId` absent takes `FABRIC_RUN_ID` (same host, read once at install); `resume` absent takes `FABRIC_RUN_RESUME_TOKEN` for the first root entry only. A non-string `runId` runs `fn` uncaptured (R9) |
| Run identity (R1; 050 §3.6 rule table) | Decided once at segment open by 050's five rules and emitted as `fabric.run.id_basis` (X49) on every `run_start`: (1) valid tokens sharing correlation id `c` → `c` verbatim, a clear `runId` ignored (`token`); (2) differing correlation ids plus a clear `runId` → the mapped clear id (`caller_join`); (3) differing correlation ids, no `runId` → the lowest correlation id, reported by the verifier as `segment_conflict` (`token_conflict`); (4) no valid token, clear `runId` → the mapped clear id (`caller`); (5) neither → a minted `r-` + 32 hex from `crypto.randomBytes(16)`, an `EmittedId` (`minted`). The run's correlation id is its root segment's run id and is copied into every token, so A → B → C keeps one run id even when B is lost entirely, and key rotation does not change it. In clear mode rules 2 and 4 emit the clear id as given, so a caller-rooted run's tokens carry the clear id in `baggage` (clear mode is an explicit opt-in); rule 5 still mints. TS-OD-8: 050's rule is adopted |
| Run id propagation (R1; 050 OD-7) | Clear run ids travel only in process and through same-host `FABRIC_RUN_ID`. Only tokens cross service or host boundaries (`fabric.resume` baggage entry, percent-encoded, or message attribute), and the application carries them; Fabric never injects baggage or changes child argv/env |
| Tokens | 050's `fr3/<correlation id>/<seg>/<source_id>/<epoch>/<last_seq>/sha256:<manifest digest>[/br-<32 hex>]` grammar, resume-token-v2 vectors and strict reference-parser port. `fr2/` tokens from older Python producers parse for one release (`id_basis: legacy`). A malformed token is dropped and counted; if none remains, rule 4 or 5 applies. In clear mode a correlation id outside 050's opaque pattern means no token is issued (`api_misuse`) |
| `resume_token()` / `resume_tokens(n)` | `resumeToken(): string \| undefined` and `resumeTokens(n: number): readonly string[]` (1 ≤ n ≤ 64; `[]` when not capturing). Synchronous: each requests the segment seal and returns the token at once, as 050 does. A token never waits for the `segment_seal` to become durable; `flush()` is the durability call. A seal that is never written leaves the predecessor unsealed, which the verifier reports, never as complete |
| `end_run(run_id: str \| None, outcome, *, resume, stop_reason=None) -> EndRunStatus` | `endRun({runId?, outcome, resume, stopReason?}): EndRunStatus`, synchronous, with 050's literal strings (`ended`, `refused_no_token`, `refused_bad_token`, `refused_conflicting_tokens`, `not_capturing`, `failed`). It queues the zero-width segment: `run_start` (predecessors = tokens, `id_basis`), `run_end` with `fabric.run.outcome`/`fabric.run.stop_reason`, terminal `segment_seal`. Without a valid token it emits nothing and returns `refused_no_token`; with no `runId` and disagreeing correlation ids it returns `refused_conflicting_tokens`. `ended` means queued, not durable |
| D30 run outcome (R4) | Only `endRun` and 050's run-level hook set it; the outermost `run_end` of the run in this process carries it, inner `run_end` markers carry neither key. TS-1 ports the hook as internal `setRunOutcome`, unexported until TS-2 |
| Segments and seal triggers (050 §3.6) | The five triggers, one open segment per run per process, continuation `run_start`, immutable after sealing. Promise fan-out inside an open block shares its segment |
| Seal (050 §3.7) | Canonical record digest over `{name, start_ns, end_ns, status, attributes, content}` minus receiver-owned keys; seal digest over `[sequence, entry]` sorted by sequence, entry = record digest or `loss:<reason>`; settle after the record is spooled; forced non-terminal seal at 1,000,000 positions; at `close()` outstanding positions become `shutdown` losses before `final` |
| Marker event ids (R2; 050 OD-8) | uuid4 minted once and persisted in the marker's spool and ledger record; replay reads it back. Never uuid5. TS-1 emits no inferred steps |
| Losses (R3) | Every loss carries `segment_id` through aggregation, the ledger slot, the spool, the `fabric.capture_loss` span (`fabric.run.segment_id`) and Go admission. Ranges never coalesce across segments, reasons, sources, epochs or runs. A loss outside any run has no `segment_id` |
| `RecordsInput.begin(kind, point, *, provenance, ...)`, `mode_of`, `v2` | `begin(kind, point, {provenance, stepId, parentAttempt, aliases})`, `modeOf(role)`, `v2(prefix, value)`; same fail-open returns (`undefined`/`false`) and `api_misuse`/`internal_errors` counters. Existing producers use `provenance: "reported"` |
| `Attempt.emit` (R4) | `emit(phase, {nameHint, attributes, startNs, endNs, lifecycle, resultStatus, otlpStatus, bodies, evidence, eventId, spanIds})`: lifecycle, result status and OTLP status are three separate inputs with 050's vocabularies (`Lifecycle` includes `deferred`; `ResultStatus` includes `timeout`, `unknown`; `OtlpStatus` defaults to `unset`) |
| `RecordBody`, `DescriptorOnlyBody` (R5) | A TS union of `RecordBody` (bytes or string, `content_provenance`) and `DescriptorOnlyBody` (status `not_captured`/`unsupported`, reason `payload_too_large`, `parse_failed`, `not_exact_bytes` or `encoding_failed`, no bytes). Never empty captured content standing in for a failure. `MAX_RECORD_BODIES = 8` counts both kinds and the evidence object |
| Shared bodies bound (R6; 050 OD-12) | 260 objects per exchange and 8 per record; 050 WP-00 owns the schema and 050 WP-11b the Python writer check. The TS writer checks the same bounds before admission (§5) |
| Structured evidence (R7; 050 §3.4a) | One evidence object per record. Not produced by TS-1; future TS P4/P5 producers use it on the records input with `begin(..., {provenance: "observed"})` |
| Content validation before acknowledgement (R10; 050 OD-1, §3.14) | The TS sender inherits 050 WP-21's semantics and the permanent-rejection retirement of §7.1 |

**Intentional language differences** (shape only; the contract is the same):

| Python (050) | TypeScript | Reason |
|---|---|---|
| `with run(...):` context manager | `run(options, fn)` callback; returns `fn`'s value, including a Promise, with thrown/rejected object identity preserved | No `with` in JS; ALS scopes follow the callback's async continuation |
| Keyword arguments, snake_case | One options object, camelCase | JS idiom |
| `None`, tuples | `undefined`, `readonly string[]` | JS idiom |
| `contextvars` (thread pools without a copied context run outside the run, 050 §3.6) | ALS: promises, timers and `queueMicrotask` keep the run; callbacks queued by code that captured another context, and work posted to `worker_threads`, run outside it unless the application passes a token or the clear id | Runtime semantics |
| Argument misuse fails open; `FABRIC_RECORDS_STRICT=1` raises `ValueError` (050 §3.4, OD-11) | Same rule; strict mode throws a fixed-text `Error` | No `ValueError` in JS |
| `flush()`/`close()` return `bool` | `Promise<boolean>` with a required deadline | Async I/O on the Fabric worker |

**Identity (R8, one rule across 050–055; 050 OD-10).**
`FABRIC_IDENTITY_MODE=pseudonymous` (default) maps every caller id through
the keyed v2 function whatever its shape (`r-`, `s-`, `sess-`, uuid or
anything else). Only issuer-validated, process-minted `EmittedId`
instances pass through, and serialization or worker cloning removes that
type. `identity_mode=clear` / `FABRIC_IDENTITY_MODE=clear` is an explicit,
manifest-recorded opt-in (owner decision 7) in which caller ids are
emitted as given, exactly as `identity.ts:253–257` and 050's `v2()` do; a
clear run id outside the opaque-id pattern is emitted in its `h-` encoded
form, as 050 §3.6 specifies. Minted ids (correlation, segment, scope,
event, attempt) are never caller ids in either mode. TS qualifies
pseudonymous mode first; clear mode is its own matrix case. Clear
operator-label exposure (`FABRIC_WIRE_LABELS=clear`) is separate from
caller-id provenance; a resume token carries the emitted source id, which
under clear labels is a clear label crossing the boundary (050 K7), and
the TS documentation states this.

**Fail open (R9).** Every exported wire function catches all Fabric
failures. No automatic `String(err)`, `err.message`, `err.stack`, `cause`
or `util.inspect` of application objects; error capture is a validated
class/code and bounded Fabric-computed metadata. Any encoder the records
bridge adds checks size, depth and item limits before serializing.

### 4.4 Native addon ABI (frozen, R12)

**Scope.** The addon exists because Node has no `flock`, `fcntl` record
lock or `mmap` API, and PID/mtime lockfiles are not kernel-released. It
provides kernel lock, fd and mmap primitives and one isolate-teardown
notification; nothing else. No allocator, queue, byte arena, threads,
async work, thread-safe functions, callbacks into JS, retained JS
references (`napi_ref`), finalizers on JS objects, network, crypto,
logging or customer code. The allocator, queue and every other runtime
structure are JavaScript (§4.5).

**Build and packaging.** C against Node-API version 8 (Node 24 provides
10), no `node-addon-api`. One prebuild per platform covers every Node 24
patch because Node-API is ABI-stable: `linux-x64-glibc`,
`linux-arm64-glibc` (glibc ≥ 2.28), `linux-x64-musl`, `linux-arm64-musl`,
`darwin-x64`, `darwin-arm64` (macOS 13+). Prebuilds ship inside the npm
tarball under `prebuilds/<platform>-<arch>[-<libc>]/fabric_wire.node`,
built reproducibly in CI with npm provenance. No `install`/`postinstall`
script, no node-gyp, compiler or download at install or startup;
`binding.gyp` is for maintainers. The loader checks the file's SHA-256
against a table embedded in the JS before `process.dlopen`.

**Loading.** `wire/native.ts` loads the addon during install in the
installing thread, in the Fabric worker and in each attaching application
isolate (§4.5); never in a hook. The shared object is opened once per
process; Node-API module initialization runs once per environment
(main thread and each Worker). Process-global C state (handle tables,
detached-environment ring, fork handler) is initialized once with
`pthread_once`.

**Handles and ownership.**
- Every descriptor and mapping is owned by the process, in a fixed
  process-global table (64 fd handles, 8 map handles), never by an
  isolate. A handle is a 32-bit value: slot index plus generation, so a
  stale handle returns `BAD_HANDLE` and never reaches a reused slot.
- The table mutex is held only to claim or release a slot, never across
  `open`, `close` or I/O.
- Fd handles are used only by the Fabric worker thread. The runtime never
  publishes them to application isolates. Only the registration-mirror
  map handle is published, for `store64` on the allocation path.
- The `.lock`, `.admit`, registration and ledger files are opened only
  through the addon. JavaScript directory scans `lstat`/`readdir` those
  names and never `open` them, because closing any descriptor of a file
  releases every POSIX record lock the process holds on it.
- An isolate's teardown (normal exit, `worker.terminate()`, uncaught
  exception) closes nothing and unmaps nothing. If the Fabric worker
  dies, its replacement adopts the same handles from the runtime's
  control block; locks and the source counter are unaffected.
- Maps are never unmapped while the process runs. `retire` turns later
  stores into no-ops; the kernel releases the mapping at exit. This
  avoids a store racing an unmap from another isolate.

**Functions.** All are synchronous and return in bounded time. Fd
operations run only on the Fabric worker thread, where blocking disk I/O
is acceptable; `store64` and `envAttach` are the only calls an
application isolate makes. No function throws: a wrong argument type
returns `BAD_ARGUMENT`.

| Function (JS view) | Semantics |
|---|---|
| `abiVersion(): number` | Returns `1`. The loader refuses any other value |
| `openDir(path: string): number` | `open(O_RDONLY\|O_DIRECTORY\|O_NOFOLLOW\|O_CLOEXEC)`; `fstat` must show a directory owned by the effective uid with no group/other bits. Returns a handle or a code |
| `openFile(dir: number, name: string, create: boolean): number` | `name` is one safe component (no `/`, not `.`/`..`, ≤ 255 bytes). `openat(O_RDWR\|O_NOFOLLOW\|O_CLOEXEC[\|O_CREAT], 0600)`; `fstat` must show a regular file, same owner, `nlink == 1`. Returns a handle or a code |
| `flock(h: number, op: 0 \| 1 \| 2): number` | Shared, exclusive or unlock, always `LOCK_NB`. `0`, `WOULD_BLOCK` or a code. Never blocks |
| `recordLock(h: number, offset: bigint, length: bigint, op: 0 \| 1 \| 2): number` | Read, write or unlock with `fcntl(F_SETLK)`, never `F_SETLKW`. Process-associated POSIX locks, as Python `fcntl.lockf`, so TS and Python drainers exclude each other; open-file-description locks are not used |
| `pread(h: number, dst: Uint8Array, offset: bigint): number` | Bytes read or a code; `dst` ≤ 1 MiB |
| `pwrite(h: number, src: Uint8Array, offset: bigint): number` | Bytes written (a short write is returned, the JS loops) or a code; `src` ≤ 1 MiB |
| `fsync(h: number): number` | `fsync`; `0` or a code (`IO` on failure, which never proves durability) |
| `allocate(h: number, length: bigint): number` | Reserves real blocks: `posix_fallocate` on Linux, `F_PREALLOCATE` then `ftruncate` on macOS. For the emergency reserve and ledger |
| `mapShared(h: number, length: number): number` | `mmap(MAP_SHARED, PROT_READ\|PROT_WRITE)` at offset 0, length ≤ 64 KiB. Returns a map handle or a code |
| `store64(m: number, offset: number, value: bigint): number` | Atomic release store of 8 aligned bytes; no system call, no lock. `RETIRED` after `retire`, `FORKED` in a forked child |
| `load64(m: number, offset: number): bigint` | Atomic acquire load; a negative value is a code (stored values are ≥ 0) |
| `retire(m: number): number` | Later stores become no-ops; the mapping stays until exit |
| `close(h: number): number` | Closes an fd handle; idempotent (`BAD_HANDLE` when stale). Called only by orderly `close`, after the final seal and heartbeat are written |
| `envAttach(): number` | Registers `napi_add_env_cleanup_hook` for the calling environment and returns its environment id (at most 1,024 live) |
| `takeDetachedEnvs(dst: Uint32Array): number` | Moves up to `dst.length` ids of torn-down environments from the 1,024-entry ring into `dst`; returns the count, or `OVERFLOW` once if ids were dropped |

Codes are fixed negative integers: `WOULD_BLOCK`, `NOT_FOUND`, `EXISTS`,
`PERMISSION`, `NO_SPACE` (ENOSPC), `QUOTA` (EDQUOT), `IO`, `UNSAFE_PATH`
(symlink, wrong type/owner/mode/link count), `BAD_HANDLE`,
`BAD_ARGUMENT`, `LIMIT`, `FORKED`, `RETIRED`, `OVERFLOW`, `UNSUPPORTED`,
`OTHER`. No message strings, paths or errno text cross the ABI. Unit `055-t1`
commits `native/fabric_wire_abi.h` with these exact names and values.

**Lifecycle across execution modes.**
- *Application `worker_threads`.* The environment cleanup hook only
  appends the environment id to the detached ring; it touches no JS and
  no descriptor. The Fabric worker polls `takeDetachedEnvs` at least every
  100 ms and settles the dead isolate's outstanding positions as
  `shutdown` losses in their own segments (R3). On `OVERFLOW` those
  positions settle as `shutdown` at `close()` instead, and the affected
  seals wait until then.
- *`child_process.fork`, `spawn`, `exec` and `cluster.fork`.* libuv
  starts a new process image (fork then exec, or `posix_spawn`): mappings
  are dropped at exec and every addon descriptor is `O_CLOEXEC`, so no
  child inherits the `.lock`, `.admit` or registration `flock`. A `flock`
  belongs to the open file description, so an inherited descriptor would
  keep a dead parent's registration locked and hide it from orphan
  detection, as the spec review found for 050 §3.2. POSIX record locks are never
  inherited. The child loads the addon afresh and registers its own epoch.
- *Raw `fork()` without exec* by third-party native code: a
  `pthread_atfork` child handler sets `FORKED` and closes every table
  descriptor (async-signal-safe `close`, which releases nothing the
  parent holds). Every later call returns `FORKED`. Unsupported; the child
  captures nothing.
- *Process exit by any path* (`process.exit`, uncaught exception,
  SIGKILL): the kernel releases locks and mappings. Correctness never
  depends on cleanup hooks running at process exit; a registration left
  behind is found by another drainer's orphan scan (050 §3.2).

**Unsupported fallback (R12).** Unsupported platform, missing prebuild,
digest mismatch, `dlopen` failure, ABI mismatch, or failure of the
install self-test (two handles on one test file: an exclusive `flock` on
the first must make the second `WOULD_BLOCK`; a `recordLock` and a
`mapShared` round trip must succeed) disables capture with a reason:
`platform_unsupported`, `native_missing`, `native_digest_mismatch`,
`native_load_failed`, `native_abi_mismatch` or `native_selftest_failed`.
No transport hook is installed, so there are never hooks without locks,
and there is no JavaScript lockfile fallback. The handle and status name
the reason; the points report `unsupported(unsupported_runtime)`. A
best-effort unsupported manifest may be sent from a Fabric worker with
generated safe identity; it does not imply durable sequencing or a
complete run, and an undelivered manifest is never reported as recorded.
Ordinary SDK use loads without the addon. First production qualification
is local POSIX filesystems on Linux and macOS, arm64/x64; Windows,
network filesystems, Bun, Deno and browser/edge runtimes are unsupported
until separately qualified.

### 4.5 JavaScript shared runtime and byte ownership

**Shared memory.** The installing thread creates, before application
code runs:
- a fixed control block (`SharedArrayBuffer`, ≤ 64 KiB): epoch, next
  sequence, reservation counters, state word, run table, isolate table
  (1,024 entries), the mirror map handle and the instance nonce;
- a payload arena: one growable `SharedArrayBuffer` whose
  `maxByteLength` is the global retained budget, cut into 64 KiB slabs;
- metadata arenas: growable `SharedArrayBuffer`s for exchange slots,
  chunk-vector slots and the completed-job ring.

It publishes them with `worker_threads.setEnvironmentData(
"fabric.wire.runtime/1", ...)`. Every Worker created afterwards, nested
ones included, receives that data at construction, and the
`SharedArrayBuffer`s are shared, not copied (checked on Node 24.13.1 while
revising this spec; WP-02b qualifies it on the minimum patch). Only the
Fabric worker grows arenas, ahead of a low-water mark; hooks never grow
or allocate arenas.

**Allocation.** A position is `Atomics.add` on the control block's
`BigInt64Array` sequence word, followed by `store64` of the next sequence
into the registration mirror (050 §3.2: a memory store, no system call).
Segment membership is decided with allocation under one control-block
try-lock word taken with `Atomics.compareExchange`. Application isolates
never call `Atomics.wait`; they spin at most 20 µs, counted in the hook
budget. On timeout the position is still allocated and becomes an
`internal_error` loss attributed to the run's last-read segment; a
resulting seal mismatch makes the run partial, never complete. The Fabric
worker waits with `Atomics.waitAsync`.

**Isolate attach.** An application isolate attaches when the wire
preload or `install()` runs in it and finds the environment data: it loads
the addon, calls `envAttach`, records itself in the isolate table and
installs its own hook subscriptions. `install()` in such an isolate
attaches; it never creates a second allocator or epoch. A Worker created
before installation, a Worker without the preload, or a Worker whose
runtime data is missing is unattached: no hooks, counted in status, and
declared in the manifest as uncaptured class `node_worker_unattached`
(§8). Preload reach is runtime behavior to qualify, not assume: on Node
24.13.1 `--import` preloads did not run in `eval: true` Workers, CLI
preloads did not run in Workers created with `execArgv: []`, and
`NODE_OPTIONS` preloads did. `install()` in a Worker with no inherited
runtime is disabled with reason `worker_without_process_runtime`.

**Fabric worker.** One internal Worker, started by the installing thread
with `execArgv: []`, `env: {}` (the configuration snapshot travels in
`workerData`) and an internal `workerData` marker, then `unref()`'d. An
empty `env` is required: on Node 24.13.1 a `NODE_OPTIONS --require`
preload still ran in a Worker created with `execArgv: []` unless the
Worker's `env` omitted `NODE_OPTIONS`. `register.ts` also stays inert when
it sees the marker, which is readable during preload. The worker never
autoloads capture, loads customer modules or starts processes or threads
for customer code.

**Job handoff.** Completed jobs go through a multi-producer,
single-consumer ring of fixed 2 KiB records in shared memory; producers
`Atomics.notify` without waiting. No `MessagePort` carries job data, so
there is no hidden unbounded queue and no structured clone of bodies.

**Byte ownership.** JavaScript `Buffer`/`Uint8Array` is mutable. Keeping a
view, freezing its wrapper, or passing it to `postMessage` later does not
provide Python's immutable-bytes guarantee. Transferring a caller's
backing store would detach it and violate passivity. Therefore:

1. Admit a whole chunk only if side, process byte and metadata/entry bounds
   permit it. Retention stops at the first rejected chunk; forward all
   later data unchanged. Reasons are `body_cap` or `inflight_budget`.
2. Copy each admitted chunk once, before the observation callback returns,
   into payload-arena slabs. A string chunk is encoded into the slab with
   the same Node encoder and encoding as the original write. Never read
   the caller's view later to reconstruct the snapshot.
3. The Fabric worker reads the slabs in place; bodies are not cloned again
   before PROTECT. Charge full slab capacity, not a subarray's visible
   length.
4. Keep reservations charged through queueing, transformation and
   admission. Account scratch and output buffers; bound worker scratch to
   two `max_retain_bytes` sides plus two `max_body_bytes` outputs. At most
   65,536 live chunk-vector slots process-wide (64 bytes each reserved),
   65,536 active exchange slots (2 KiB each) and the configured queue
   entry count of completed jobs (2 KiB each). Slot exhaustion loses an
   exchange as `queue_full`; no partially missing body may be labeled
   exact. Metadata arenas stay within 260 MiB at maximum configured counts
   (unrelated to 050's 260-object bound), separate from the 256 MiB
   payload budget. Include real JS wrapper/map overhead in measurement.
   Coalescing never changes caller chunks.
5. Hook work is match, reserve, snapshot, clean-context/time capture and
   enqueue/finish. No hashing, JSON/SSE parse, customer transform, fsync,
   network, log or blocking wait. A full completed-job ring loses the
   allocated position with `queue_full`.

Snapshot copy cost is real, especially for a single 40 MiB request. It must
be measured, not described as zero-copy. The 049 retention limits cannot
be silently replaced by a small per-hook copy cap to pass benchmarks.
If byte ownership and §9.2 budgets cannot both be qualified, the affected
transport/body case remains unsupported and the full parity gate stays
closed pending an explicit contract change. No raw mutable reference is
an acceptable optimization. `SharedArrayBuffer`-backed bodies concurrently
mutated by another application thread have no atomic snapshot guarantee;
reject that capture as `transport_incomplete`, preserving the monitored
send.

### 4.6 Exchange state and mixed capture

Each invocation gets a new exchange uuid4/attempt, event uuid4, trace span
id and source position; stable once allocated, reused across delivery.
Clean parent context contains only trace id, span id, flags and remoteness;
never baggage, tracestate, ambient attributes or arbitrary ALS values.
No parent is invented when the host has none. Capture remains useful with
no host OTel provider or a sampling-out host provider.

Finish exactly once on EOF, early close/abort, transport failure or recorder
shutdown. Response states use the existing enum: `complete`, `closed_early`,
`error`, `abandoned`. A missing response is not a zero-byte complete body;
an incomplete request is `truncated(transport_incomplete)`. GC finalization
can enqueue a notice but is never a durability mechanism or a forced read.
An unresolved exchange at shutdown is a `shutdown` loss; no synthetic
successful response or final seal covers unsettled positions.

Use ALS for the explicit-model ownership scope, holding mutable
`ended`/`withheld` flags referenced by provisional exchanges. While an
explicit scope is live, tee provisionally without allocating a sequence.
At response finish: if explicit ownership is still live, release bytes,
allocate nothing and project `deferred_to_explicit`; if it has ended,
adopt and allocate then. If it withheld, adopted capture stores no bytes,
no original digest, and emits `store_status=disabled`,
`store_reason=explicit_withheld`. The flag survives scope exit and an
explicit recorder failure. Add this bridge to model `llm_call`/byte-evidence
records only where the explicit producer actually owns that model exchange;
an unrelated decision scope must not suppress capture.

Suppression for Fabric's own requests uses a private context/token and
unmatched delivery endpoints. Suppression for delegation between qualified
transport hooks uses a request-local ownership token, never blanket ALS
suppression of nested calls: a nested independent send is a new exchange.

### 4.7 Status, reasons and messages

Ease of integration is a release requirement: a Node agent that records
nothing must be able to say why in one command, without reading this
spec. TypeScript uses the diagnostics catalogue and the status file that
spec 058 E1a built for Python (#291, §2.2); it defines no message table
of its own.

**Status document.** `capture.status()`, `envStatus()` and the status
file (`FABRIC_WIRE_STATUS_FILE`, written by the Fabric worker at install
and at exit, never by a hook; atomic rename, mode 0600) carry the
document Python writes (`wire/_statusfile.py`): `schema`
(`fabric.wire-status/v1`), `phase`, `written_at`, `pid`, `sdk_version`,
`capture` (`installed`, `disabled`, `not_installed` or `closed`),
`warning_ids` and `notice_ids` (catalogue ids), and a content-free
`status` object. TypeScript's `status` object adds, per capture point,
its state and reason, the qualification tuple (Node patch, undici
version, platform) and the endpoint table version, next to the counters
Python reports (matched, captured, lost by reason, unmatched
model-shaped requests, spooled, delivered, `content_rejected`), the
spool backlog and the exit-backlog note of #289. The document has no
schema file on main; `055-t1` adds
`contracts/diagnostics/v1/schema/wire-status-v1.schema.json` with
fixtures, and a test under `scripts/tests/` validates documents produced
by Python and (from `055-t14`) by TypeScript against it.

**The one command.** With the agent's environment:

```sh
node -p "require('@singleaxis/fabric/wire').envStatus()"
```

`envStatus()` is the TypeScript form of Python's `env_status`
(`python -m fabric.wire status`): it reads the configuration, installs
no hook, sends nothing and returns the status document with every
warning's text and fix. `fabric doctor` (058) reads the status file and
needs no Node-specific code.

**Catalogue ids.** Every disabled or degraded state maps to one entry
of `contracts/diagnostics/v1/messages-v1.json`: a stable `FW-` id, a
fixed text and a fix. Texts and fixes carry no interpolated value (the
catalogue's rule); the variable, capture point or reason code a message
is about appears beside it in local output only (the status document
and stderr), never on telemetry.

- TypeScript reuses an existing entry when its text and fix are true for
  a Node agent as written: `FW-002` (no destination), `FW-003` (no
  store), `FW-005` (endpoint set), `FW-006` (unmatched model host),
  `FW-007` (`OTEL_SDK_DISABLED`), `FW-008` (content capture disabled:
  `missing_capture_policy`, `missing_id_key`, `missing_spool_key`),
  `FW-010`, `FW-012`–`FW-020`, `FW-022`–`FW-024` (endpoint, key, file
  and setting errors).
- Entries whose fix names a Python command or package (`FW-001`,
  `FW-004`, `FW-009`, `FW-011`) get a TypeScript counterpart, and the
  Node-only states get new entries. `055-t1` adds the rows below with
  the next free `FW-` ids at the time it lands; ids are never reused.
- Each entry gains an optional `sdk` list (`python`, `typescript`;
  absent means `python`, today's meaning). Python's catalogue test
  keeps its rule for entries that include `python`; a TypeScript test
  (`055-t2` for configuration reasons, completed in `055-t14`) requires
  every `typescript` entry to be emitted by TypeScript code and every
  id TypeScript emits to be catalogued. `docs/diagnostics.md` is
  regenerated (§14 OQ-10).

| New entry (`name`) | Reason codes it covers | Text | Fix |
|---|---|---|---|
| `node_capture_not_installed` | `config_invalid` | "wire capture is not installed in this Node.js process: the configuration is invalid" | "run the status command (node -p with require('@singleaxis/fabric/wire').envStatus()) with the agent's environment; it names the setting and the fix" |
| `node_runtime_unqualified` | `unsupported_version` | "model-call capture is off: this Node.js or undici build is not in the Fabric compatibility table" | "run the agent on a Node.js 24 build listed in the compatibility table of the release notes, then start it again" |
| `node_platform_unsupported` | `platform_unsupported` | "model-call capture is off: Fabric has no native lock module for this operating system or CPU" | "run the agent on Linux or macOS, x64 or arm64" |
| `node_native_unusable` | `native_missing`, `native_digest_mismatch`, `native_load_failed`, `native_abi_mismatch`, `native_selftest_failed` | "model-call capture is off: Fabric's native lock module could not be used" | "reinstall @singleaxis/fabric so its prebuilds directory is complete, and keep the spool directory on a local disk; the status names the reason" |
| `node_hook_disabled` (info) | `hook_disabled` | "a capture point is switched off by its FABRIC_WIRE_UNDICI or FABRIC_WIRE_NODE_HTTP setting" | "set the variable to 1 to record through that capture point" |
| `node_worker_unattached` | `worker_without_process_runtime`; uncaptured class `node_worker_unattached` | "a worker thread records nothing: Fabric was not loaded in the main thread before the worker started, or the worker did not inherit the preload" | "load Fabric with NODE_OPTIONS=--import=@singleaxis/fabric/register so every thread inherits it" |
| `node_autoload_off` (info) | `autoload_off` | "@singleaxis/fabric/register was loaded but did nothing: FABRIC_WIRE_AUTOLOAD is not 1" | "set FABRIC_WIRE_AUTOLOAD=1, or start the agent with `fabric run`" |
| `node_redacted_roles` | `protection_failed` for a role with no redaction service | "the capture policy masks some content roles and no redaction service is configured: their content is withheld" | "set FABRIC_REDACTION_ENDPOINT, or give those roles retain_original or metadata_only in the capture policy" |
| `node_spool_backlog` | exit backlog | "records wait in the spool and no process is draining it" | "start the agent again, or set FABRIC_WIRE_DRAIN_ON_EXIT_S for batch or serverless workers; `python -m fabric.wire drain --until-empty` also drains a Node.js spool" |

**Where messages go.** Diagnostics go to Fabric's own channel as in
Python: silent on the agent's stdout and stderr by default, printed once
per epoch to stderr only with `FABRIC_WIRE_DIAGNOSTICS=stderr`, and
always available in the status document. The first unmatched
model-shaped request (a POST whose path ends in one of §3.4's suffixes
on a host no matcher covers) is counted and reported as `FW-006`; the
host appears only in the local status document, as in Python.

## 5. PROTECT before persistence

Pipeline, executed by Fabric code in the capture worker:

```text
captured owned bytes
  -> typed extraction (when applicable)
  -> role policy + customer redaction service / tokenization
  -> allowed digests + protected descriptors + safe telemetry
  -> encrypted spool admission
  -> one content writer + Node sender
```

Reuse `ContentProtector`/`RedactionClient`; add orchestration rather than a
second redaction protocol. The worker may execute Fabric code; it never
loads customer modules or starts processes/threads to run customer code.
The configured service has hard timeout, output and in-flight bounds;
timeout, redirect, non-200, connection error, oversized response, malformed
output or saturation withholds. Build new clients inside the worker, not
by serializing an object containing secrets/private sockets across isolates.
An absent transformation/service for a required masking role produces
`protection_failed` for that role without admitting raw content. Adapt the
wire orchestration around the current strict protector constructor to
represent this withheld state. Malformed configured endpoints, callbacks
or transformation identities remain fixed-text install errors (§4.2); do
not convert a valid missing-prerequisite disabled state into an autoload
crash.

| Mode | Persisted evidence and failure behavior |
|---|---|
| `omit` | Nothing; do not extract or hash the body |
| `metadata_only` | Descriptor only, permitted byte counts; no bytes, original digest, range or ref |
| `retain_original` | Exact bytes with source/stored digests; protected means policy-authorized retention, not an assertion that content lacks secrets |
| `redact`, `masked_only` | Service-produced bytes only; stored digest only, no original digest/range. Failure yields withheld descriptor `protection_failed` |
| `tokenize` | Existing tenant/workload/role/policy-scoped whole-object HMAC output, distinct tokenization key; no original digest or range |
| `original_plus_masked` | Original plus separate masked review object linked by `derived_from`; stage both before admission. A failed review withholds both, including original digest/range, matching Python `wire/_protect.py:200` `Protector` |

Spool neither originals awaiting masking nor arbitrary exception/debug
data. Clear identifiers may occur only inside policy-authorized content.
Headers, URLs, queries, credentials, original provider ids and content
digests forbidden by a mode must not enter telemetry/ledger/manifests/logs.
Read only the permitted protocol metadata (status, normalized media type
and encoding); no header block capture. Opt-in `C40` reads just the
configured provider request-id value and maps it with v2 `p-`; otherwise
never inspect it. Validate error class/code against bounded vocabularies;
arbitrary `Error.name` is content, not automatically a safe class name.

Split parity is mandatory: worker scans original JSON byte offsets, not a
parse/reserialize approximation. At most the existing 64 candidate parts
per side; source ranges are half-open byte offsets. A 40 MiB request with
one inline image retains text via skeleton plus `model.exchange.part`;
reassemble and check original source digest only under retaining modes.
A part beyond object cap is descriptor-only `part_cap`; a side beyond
64 MiB is whole-chunk `body_cap`. Transformed objects have no original
source digest or byte ranges and make no reassembly claim. Parts inherit
their own role policy (missing configured part role means omit).
Review copies are never substitutes for required original evidence.

The shared exchange bound is 050's (R6): 260 objects, enough for two
sides of a primary, 64 parts, 64 part review copies and a side review.
The schema and the Python writer-side check are built
(`spool-record-v1.schema.json:437`, `wire/_spool.py:118`). The TS writer
counts actual admitted objects and checks the same bound before
admission; an exchange above it is an accounted `internal_error` loss,
never a silently shortened object list.

Production gate reuses 049 §7.3/§7.8: policy, id key and spool key required
for content; missing prerequisites disable content while safe metadata
continues. Report `missing_capture_policy`, `missing_id_key` or
`missing_spool_key` with the same precedence as the shared Python gate.
No-key production ids use generated fallbacks, not unkeyed caller hashes.
Local mode uses `fabric.local-default` and remains explicitly local.
Malformed configuration throws fixed text at explicit install; preload
catches and reports the disabled/failed recorder without failing the agent.
Log missing-protection class-only status
at every install and first matched exchange of each epoch.

Identity follows §4.3's R8 rule: `identity.ts` unchanged for v1 labels,
v2 domains and `IdentityPolicy`; pseudonymous mode maps every caller id;
clear mode is an explicit opt-in; only issuer-validated `EmittedId`
instances pass through in pseudonymous mode.

## 6. Shared source, spool and process semantics

### 6.1 Sequencing and int64

One process runtime owns one allocator, one logical source binding and
one spool for wire and records. Every ordinary exchange or records-input
record consumes one position. Losses, manifests, heartbeats, run markers
and segment seals consume none. Never reallocate at export time.

Use BigInt for nonzero CSPRNG 63-bit epochs, sequence/order numbers and
nanosecond times end-to-end. Register `(source_id, epoch)` at install under
admission lock, keep its registration `flock` until orderly shutdown and
redraw collisions (050 §3.2). JSON files contain exact integer tokens, not
quoted epochs or rounded Numbers. OTLP JSON `intValue`/timestamps use
decimal strings as OTLP requires. Canonical JSON, parser and schema
validation must handle values through 2^63−1; `JSON.stringify(BigInt)` and
ordinary `JSON.parse` cannot be the implementation. Pin Python
canonicalization vectors including escaping, surrogatepass ids, integral
floats and ordering.

Wire and existing explicit producers share this allocator and content
writer when the wire runtime is installed. `decision.ts`, `calls.ts` and
`byte-evidence.ts` supply records through `wire/records-input.ts`, the TS
port of 050's records input (rule A projection from the generated key
table, rule N names, the four phases, `modeOf` before serializing, typed
bodies). Host-provider copies are best-effort duplicates with the same
event id. They never create another authoritative journal or hide a
missing spool record. New TS-2 API families are not necessary to prove
interleaving of today's decision and byte producers. Without wire
installation, preserve current explicit API behavior and document its
existing delivery limits.

### 6.2 Frame and encryption format

Use `fabric.wire-spool-record/v1` from `contracts/capture/v1`, not
`fabric.content-spool/v2`. Inner record kinds: `exchange`, `record`,
`loss`, `marker`; marker kinds include `manifest`, `run_start`, `run_end`,
`segment_seal`, `final` according to the schemas as 050 WP-00 extends
them (persisted marker `event_id`, segment-attributed losses). Periodic
heartbeats use the existing sender/heartbeat path. Source, fully resolved
span, protected descriptors and body offsets/lengths match the shared
fixtures.

Python-compatible encoding (`wire/_spool.py:61–66`, `:181–247`):

```text
record: FWSPOOL1 | u32be(header length) | canonical UTF-8 header | body blob
        | SHA256(all preceding bytes), binary 32-byte trailer
batch:  FWSPOOLB | u32be(count) | repeated(u64be(frame length) | frame)
        | SHA256(all preceding bytes)
sealed: FWSPENC1 | 12 ASCII bytes key_id | 12 random nonce bytes
        | AES-256-GCM(inner record or batch, aad), ciphertext then 16-byte tag
aad:    FWSPENC1 | key_id | UTF-8 original record basename
key_id: kid- + first 8 hex of HMAC-SHA256(key, "fabric-spool/v1/kid")
```

Key is exactly 32 bytes, customer-supplied via existing secure key loading;
nonce is independently random per write. A fixed nonce is permitted only
in test vectors. The spool-key id is domain-separated from the identity
key id (`wire/_keys.py:65`); do not reuse `identity.ts:161` `keyId` for it.
Header, descriptors and bodies are encrypted together.
Rename under another basename fails authentication. Unknown key ids stay
charged and pending for an authorized drainer holding that key, not
destroyed as corrupt. Failed authentication, invalid frame/digest/schema,
symlink or invalid body ranges quarantine and account as corruption.
Never read plaintext when an encryption key is configured. Only explicit
local-profile migration may seal historical plaintext in place; production
quarantines it, and never enables migration from an environment default.

### 6.3 Durability and admission

All following I/O occurs at install or on the Fabric worker, never in an
application hook. Local owner-only directories 0700 and regular files
0600, no-follow opens, short-write loops, bounded reads and safe names.
Spool record files use Node `fs` (libuv opens with `O_CLOEXEC`); lock,
admission, registration and ledger files use only §4.4. Before admitting,
take a separate kernel `flock(.admit)` and count the shared on-disk bound
including pending files, temps from killed writers, quarantines, failed
retirements and receipts. Try-lock contention retries on the Fabric worker
within the Python admission deadline and then refuses; it never holds up
the monitored call. The bound is process-shared, not one budget per
writer. Reserve full encoded/encrypted size before creating the temp, and
hold admission ownership through write/rename/accounting.

Commit: create exclusive temp -> write frame/envelope -> fsync file ->
atomic rename -> fsync directory. Establish and verify the ancestor
directory barrier top-down to the configured durable boundary; fsync the
boundary too. Unknown fsync failure is not a proven durable boundary.
Only the qualified filesystem/refusal rules from 048 may stop the walk;
planting a symlink marker or recreating the root invalidates the barrier.
Successful flush requires the barrier; delivery may still progress when
the barrier fails, with `spool_undurable` reported.

One `flock(.lock)` drainer serves all writers. It drains stable filename
order and retires only after all bodies and trace/marker exports succeed
or are permanently rejected (§7.1). Delivery is at least once. Same ids
and bytes on replay; a crash after remote acceptance before retirement can
duplicate, never silently delete. Retirement failures retain their charge;
the same live drainer retries retirement before re-exporting. `.ack`
receipts for other writers count at least 128 bytes each, cap 4,096,
expire after the Python 3,600 s TTL; an expired/missing receipt cannot
turn a writer's flush into success. Receipt creation/rename/truncate/unlink
and every directory fsync failure must preserve conservative accounting,
including during concurrent rescan.

`queue_full` means admission bound/queue refusal; `disk_full` means
ENOSPC/EDQUOT. Preserve a preallocated (`allocate`), fsync'd 260 KiB
ledger inside the 1 MiB emergency reserve: 4 KiB header, 64 x 4 KiB slots,
Python `FWLEDGR1` and `FWLSLOT1` checksum layout, bounded loss/marker
headers only, each loss with its `segment_id` (R3). Use `recordLock` slot
locks on the one process-owned ledger handle; dead-owner slots are
recoverable by another drainer. Never place content in this ledger.
When reserve/ledger is also exhausted or torn, count the failure and leave
coverage unverified/partial; never claim that every loss was durable.

The memory-to-fsync window remains a loss window, as in Python. A crash
there persists no unprotected content and never justifies complete capture.
Epoch registration and the next manifest's unsealed-prior-epoch declaration
expose a wholly lost registered epoch. Power loss, spool deletion, full
disk on CoW filesystems and loss of an entire machine are bounded failure
cases, not promises of survival beyond local durable storage.

### 6.4 fork, cluster and worker_threads

| Execution mode | Source / ownership behavior |
|---|---|
| `child_process.fork`, `spawn`, `exec`; `cluster.fork` | A new process image (§4.4): fresh isolate, addon loaded afresh, fresh epoch and registration, its own Fabric worker and connection pools, no inherited Fabric descriptor or lock. Same configured clear source/key maps to the one bound logical source; do not append the PID to the bound source. Capture only if the child inherits the preload: `fork` and `cluster.fork` pass `process.execArgv` and the environment by default; `spawn`/`exec` pass `NODE_OPTIONS` only through the environment |
| Application `worker_threads` | Attached isolates (§4.5) share the process allocator, epoch, byte/entry reservations, spool worker and sender; hook subscriptions are per isolate. Isolate teardown settles its outstanding positions as `shutdown` losses through `takeDetachedEnvs`; no second final heartbeat. Unattached isolates are a declared limit |
| Fabric's own worker | `execArgv: []`, `env: {}`, internal marker; never autoloads capture or recurses. It runs Fabric transformations/delivery only. Its crash is recovered without resetting the source counter (§10) |
| Raw native `fork()` without exec | Unsupported; the child's addon returns `FORKED` and it captures nothing |
| Generic spawn/exec of other runtimes | Capture only if the customer inherits preload/env in that child. Fabric never changes child argv/env/stdio or injects propagation. Missing preload is an explicit coverage limit |

Keep canonical run/segment state in the shared control block; ALS
carries only scope references and safe identity. Synchronous segment
transitions use the bounded try-lock of §4.5. A worker finishing must not
close another isolate's descriptors or sender. Abrupt isolate cleanup
runs only native code; never invoke JS in a dead isolate.

No automatic parent/child run joining. Within a host, pass the same clear
run id (`FABRIC_RUN_ID` or in-process) plus a token from `resumeToken()`
or `resumeTokens(n)` through application-owned messaging; across services
or hosts pass only tokens (R1). Structured clone does not preserve
`EmittedId`, and ALS is not inherited across threads. Resumed/forked
processes use 050's predecessor/declared-branch rules. Registration before
a fresh Node child's application code closes the pre-first-record gap
only for that installed process; a child killed before installation or
started without preload remains invisible absent declared branches. Do not
claim stronger Python `Pool()` coverage than CONTEXT permits.

One production Node binds exactly one agent source today. Many processes
may use that logical source with distinct epochs; unrelated sources need
separate Nodes. Multi-source/host ingress remains P4 (053, R11).

## 7. Sender, manifests and reconstruction

### 7.1 Node delivery

Use a private always-on Fabric delivery path; do not install or replace a
global OTel provider or context manager. Capture parent ids on entry, build
spans on the worker and spool before export. A protected host provider
never receives wire spans/markers (install and emission checks, D3).
Host sampling never removes the authoritative spooled record.

Send protected content as OTLP logs with `event_class=content` to the
configured 048 content receiver (normally `/v1/logs`), as Python's
`wire/_content.py` does since #289: up to
`FABRIC_WIRE_CONTENT_BATCH_BODIES` records (default 32, at most 256 and
about 4 MiB) per request and up to `FABRIC_WIRE_CONTENT_CONCURRENCY`
requests in flight (default 4, at most 16). **A request the Node refuses
as a whole (400, 413, 415, 422, or a reply with rejected records) is
sent again one record per request**, so only the refused records count
as rejected. Accepted bodies are remembered per record file and never
resent. A record's span is exported only after every body of its file was
accepted or permanently rejected, files in name order. Then send the
immutable `fabric.model_call` OTLP trace to `/v1/traces`. Setting both
variables to 1 restores one record per request. Use `content-log-record-v1.schema.json`, including
descriptor-only outcomes, and the common content writer; local profile
uses its governed local backend through the same writer. Do not send body
text as span attributes, events, names or diagnostic logs. Build trace
batches from closed registry keys. Use OTLP/HTTP protobuf with
`application/x-protobuf` by default for logs and traces, matching
Python's content client. Pin proto definitions in the build; the encoder
accepts BigInt/exact decimal int64, never a Number conversion. OTLP JSON
integer-string vectors are interoperability checks, not permission to emit
quoted integer tokens in the spool/canonical JSON.

Keep 047 keys and forms: `fabric.wire.exchange_id`, `fabric.run.id`,
`fabric.run.scope_id`, `fabric.source_id`, `fabric.source.epoch`,
`fabric.source.sequence`, `fabric.wire.api`, `fabric.wire.response_state`,
`fabric.wire.truncated`, `fabric.wire.store_status`, `fabric.wire.store_reason`,
`fabric.content.request_ref`, `fabric.content.result_ref`,
`fabric.wire.request_sha256`, `fabric.wire.response_sha256`,
HTTP method/status and permitted `gen_ai.*` metadata. New 049 emissions
include `fabric.event_id`, `fabric.capture.input=wire`,
`fabric.capture.point=<point>@<capture-point-version>`,
`fabric.capture.source=observed` (registry row added by 050 WP-00, R15),
`fabric.run.segment_id`, `fabric.wire.endpoint_id` (C35), step
kind/actor/lifecycle/status, `fabric.error.domain` and first-chunk offset
where applicable. Generated key constants must use exact
registry/allowlist strings. Built `_sha256` telemetry values are bare hex;
descriptor/new `_digest` values are `sha256:<hex>`.

Roles are exactly `model.exchange.request`, `model.exchange.response`,
`model.exchange.part`; descriptors use `provenance=protocol`,
`boundary=provider_bound`. Preserve media type/encoding, exact/split/
redacted/tokenized/unavailable representation, mode/status, policy
id/version/digest, transformation id/version and part/review links.
Model labels follow existing model-name vectors/exposure rules, never
arbitrary provider text. Extract metadata only from policy-permitted
protected evidence; no raw-body parse that leaks original fields through
telemetry when the role was withheld or masked.

Same tenant/source binding and ingress credentials on both paths.
The agent never sets `fabric.source.authenticated` or descriptor
`source_authenticated`. fabricguard/fabriccontent own those stamps;
reconstruct trusts them only on trusted Node/store readback. Cross-source,
cross-tenant and duplicate-key batches are refused. A local direct writer
cannot claim production authentication.

**Short-lived processes** follow #289: the default exit budget is the
bounded `beforeExit` drain of §9.4; `FABRIC_WIRE_DRAIN_ON_EXIT_S` lets an
exiting process wait until its spool is delivered (an opt-in the
customer sets; Fabric never delays exit by default). A process that
exits leaving records with no live drainer writes the content-free exit
note (`.exit-backlog`, schema `fabric.wire-exit-backlog/v1`,
`wire/_spool.py:102–104`), and the status document reports it with the
remedies.

**Outcome classes**, matching `wire/_content.py:127–205` and
`wire/_sender.py:613–656`:

| Response | Class | Agent behavior |
|---|---|---|
| 2xx | `ok` | Body progress advances |
| 3xx | `retry` | Never follow `Location`; retry with backoff |
| 408, 429, 5xx, connection/timeout errors | `retry` | Capped backoff from 0.5 s to 30 s; honor bounded `Retry-After` only under the delivery policy. The record stays pending and charged |
| 400, 413, 415, 422, or a partial-success response that rejects the record | `rejected` (permanent) | Count `content_rejected`, report it in status, log one class-only warning per epoch, advance body progress past that object. The span is still exported (its seal digest was fixed at spool time and is never rewritten), and the file is retired once all its bodies and spans are settled. Reconstruct reports the object `not_captured(store_failed)`. Never retried forever, never relabelled stored |

A permanent rejection is therefore an evidence failure that is retired,
not a pending record that blocks the spool. With 050 WP-21 (R10) the Node
(not built on main; see §10) runs the stateless checks (record parse, length and digest recompute,
descriptor role/protection/link consistency, tenant allowlist, source
binding) before acknowledging. HTTP 200 means the record passed every
check that needs no store read and was queued; the conflict check stays
after the queue, with drop and log. Acceptance is still not durability:
sender success is not durable content proof, and readback/missing objects
must make that run partial/unverified. A Node without WP-21 may still drop
after 200; that variant cannot verify complete. Internal `.ack` files are
spool coordination, not public delivery receipts or 046 evidence.

### 7.2 Loss, manifest and run parity

Emit `fabric.capture_loss` and `fabric.capture_heartbeat` with the shared
`fabric.loss.*`/`fabric.heartbeat.*` keys, including the loss
`segment_id` (R3). Coalesce compatible ranges only within one segment;
different reason/source/epoch/run/segment windows never merge. Each
heartbeat/loss/marker/manifest has a stable event id and no
`fabric.capture.input`; marker event ids are persisted uuid4 (R2).
Periodic heartbeat default is Python's 30 s and includes the latest
manifest sequence. Final heartbeat is emitted only after orderly settled
capture; it is not a substitute for segment seals.

Manifest 0 precedes source position 0, `after_source_sequence=-1`.
Manifests use their own contiguous counter and canonical digest chain;
spool as `marker(kind=manifest)` and export `fabric.capture_manifest` with
the registry's closed manifest-span mapping. State changes append a
manifest at a precise allocator boundary. Policy, keys, limits/profile
or identity-mode changes require a new epoch. Include exact limits,
endpoint-set digest, source-auth intent, encrypted-spool/key id, runtime
Node patch, capture-point version, role-table version, identity mode,
both inputs, unsupported and uncaptured classes (including
`node_worker_unattached` when any isolate is unattached),
`chunk_boundaries_retained=false`, and prior unsealed epochs (bounded list
plus exact count). Never put paths, config secrets or dependency
inventories into a manifest free-text field.

Initial unqualified transport state is `unsupported(unsupported_version)`
or `unsupported_runtime`; explicit switch-off is `disabled(hook_disabled)`;
an installed healthy point with no eligible activity is
`installed_inactive`; active means qualified and observing, not that content
is necessarily retained. A healthy transport with production privacy
disabled still emits safe metadata plus per-exchange store reason. Runtime
failure appends `failed(internal_error)` at the effective position. Never
upgrade a missing body channel to active based on metadata events.

Port 050's run markers, deadlines, tokens, correlation ids, declared
branch ids and seals exactly (§4.3). Seal only settled positions, sorted by
allocation sequence, not finish order. Receiver-owned authentication
stamps are excluded from record digests. 050's resume-token,
manifest-chain, manifest-span, run-marker, seal-digest, seal-parity,
span-category and records-span vectors are mandatory TS tests. Default
capture does not use or modify the 045/046 journal.

### 7.3 Verifier/projection

Use the existing Python `fabric.reconstruct` as the authoritative offline
reader. No JS provider-specific reconstruction engine or Activity v2
extension is needed. No TS work package edits `reconstruct/**` (R13): 050
WP-30–WP-33 own the P1 reader and projection, and 051 WP2-9 the P2
additions. TS capture points are recognized through the registry rows
WP-01 adds; if the reader needs a code change for a registered TS point,
that is a request to the 050 reader owner (§9.1), not a TS edit. TS
supplies fixtures and runs the Python reader as a subprocess in its
tests. Preserve the same field wrappers, literal locators, parser
versions, status classes and no-false-complete rules. A runtime boundary
difference does not justify comparing compressed bytes to decoded bytes:
qualify equal boundary/encoding cases together.

Compare Python and TS byte fixtures exactly, then compare reconstructed
model-call semantics after a documented substitution of minted ids,
source epoch, timings and producer/capture-point labels. Do not erase
privacy modes, statuses, counts, missing fields, provenance, locators or
digests to force parity. Event/spool replay identity is compared exactly
within each run. Truncated SSE/JSON cannot prove a field `absent`; unknown
items stay opaque; provider-held references are unresolved, never fetched.
A 047/048-era reader is unsupported for `sequence_unit=record` captures.

## 8. Contract deltas to implement in the build

This spec changes no contract files; unit `055-t1` applies the rows
below in one PR and `055-t2` adds the byte vectors. Revision 2 placed
these rows in a serialized contract chain behind 051–054. That chain no
longer applies: 050 WP-00 is built, and 051–054 are not scheduled before
this lane. Rows marked *TS-only* are added only by 055; rows marked
*Shared* touch a registry other specs also edit, so `055-t1` rebases and
regenerates if a spec 057 unit lands a registry change first. The 049
generated blocks are regenerated with the existing generator, never
hand-edited.

| Artifact / row | Required delta (unit `055-t1`) |
|---|---|
| *TS-only.* `contracts/coverage/v1/registry/capture-points-v1.json`, row `wire.ts.undici` | Keep id, kind `W`, input `wire`. Runtime: `Node.js 24+, exact qualified bundled/external undici builds; Fabric native addon prebuild`. Activation: explicit wire install/preload with undici enabled. Observes: matched POST request/response body publications, timing, status, error class and run scope. Cannot-observe: unmatched/non-model/GET, headers beyond allowed metadata/C40, unqualified producers, Node <24, nondelegating custom fetch, HTTP/2 unless separately qualified, unattached worker isolates, TLS/provider receipt. Passivity gate `TS-1U, TS-1D (055 §9)`. State remains unsupported until qualified; supplies exact §1.1 list |
| *TS-only.* Same registry, new row `wire.ts.node_http` | Kind `W`, input `wire`, runtime `Node.js 24+, qualified HTTP/1.x implementation; Fabric native addon prebuild`; process-global `yes (request lifecycle/write/end and IncomingMessage.push hooks)`; separately opt-in. Observes and supplies same §1.1 list; cannot-observe includes HTTP/2, nondelegating fetch, preloaded cached/overridden paths that bypass hooks, and shared undici exclusions. Gate `TS-1H, TS-1D (055 §9)`; unsupported until qualified |
| *Shared.* `field-registry-v1.json` | For each id in §1.1 add `wire.ts.undici` and `wire.ts.node_http` to `observed_by` (undici already appears for N01; do not duplicate). Derive both supplies sets from these rows; no new field ids |
| *Shared.* `capture-points-v1.json`, `run.scope` runtime and `fabric.self` observes | Include TS qualified run/marker support and shared worker-isolate implementation; no new point for each framework |
| *Shared.* `vocabularies-v1.json`, `capture_input[wire]` | Add Node core HTTP alongside undici in meaning only; no enum member change |
| *Shared.* `telemetry-keys-v1.json`, row `fabric.capture.point` | No new telemetry key. Keep current id@version syntax; add examples `wire.ts.undici@1.0.0` and `wire.ts.node_http@1.0.0` and require registry resolution in semantic validation. The present regex alone does not establish a registered or qualified point |
| `content-roles-v1.json` | No role, boundary, provenance, cap or privacy-mode widening. Reuse three model.exchange roles and existing review-copy links |
| *TS-only.* `coverage/v1/schema/capture-manifest-v1.schema.json` and `capture/v1/schema/capture-manifest-record-v1.schema.json`, `uncaptured_classes` enum | Add `node_worker_unattached` (an application worker isolate that did not attach, §4.5). Until it lands, emit `other_runtime`. Cross-validator must resolve the new registry ids. Remove `node_http` from uncaptured classes only when that point is active; remove `axios` only for a specifically qualified delegating adapter |
| *Shared.* `coverage/v1/schema/step-projection-v1.schema.json` | No shape change; cross-validation accepts registered TS evidence. Add valid/invalid fixtures, no relaxed absent/conflict/authentication rules |
| Other capture/v1 schemas; content/v2 | No TS-specific schema or fork. Tighten validators/fixtures if an emitter mismatch is found; do not admit unknown attributes |

Shared rows TS consumes (owner: 050 WP-00; all built on main, §2.3):
the 260-object exchange and 8-object record bounds and their
fixtures (R6); the `fr3/` resume-token grammar carrying the correlation
id, resume-token-v2 vectors and `fabric.run.id_basis` (X49) (R1); uuid4
marker `event_id` required on every marker kind (R2); `segment_id` on loss
records, ledger slots and loss spans (R3); the three status inputs (R4);
the descriptor-only body representation (R5); the evidence carrier (R7);
the `fabric.capture.source` registry row and `fabric.wire.endpoint_id`
(C35) (R15); the X08 registry definition (decision 22).

Two additions to revision 2's list, both `055-t1`:
- a `fix` value for each TS registry row where spec 058's
  `integration-rows-v1.json` reads one (the preload line for
  `wire.ts.undici`; `FABRIC_WIRE_NODE_HTTP=1` for `wire.ts.node_http`);
  if that registry is not on main yet, the text goes in the row's
  `activation` field;
- a schema for the qualification table of §9.4
  (`contracts/coverage/v1/schema/wire-qualification-v1.schema.json`)
  with valid and invalid fixtures (an active claim for a tuple with no
  report hash is invalid).

Add valid TS manifests (active U, active H, both, privacy-disabled,
Node 22, old Node 24 bundled undici, native addon missing, unattached
worker, key rotation), mixed-input spool and split/redacted exchange
fixtures; invalid rounded epoch >2^53, unregistered point,
unsupported-build active claim, original-digest leak, false complete and
spoofed authentication fixtures. Integer rounding needs a value-preserving
fixture validator, not just JSON Schema `integer`. Add cross-language
encrypted record/batch, ledger and registration vectors (fixed test
nonce/name; `spool-bytes-v1.json`, unit `055-t2`) alongside capture
fixtures; content/coverage manifest digests and generated artifacts are
refreshed by their contract owner. No requirement to expose spool keys or
random ciphertext in public telemetry.

## 9. Work packages, build units and qualification

### 9.1 Work packages and ownership

Work packages (WP) name ownership areas; other specs cite them (051
WP2-11 and 052 WP3-6 depend on WP-08a and WP-08b). Build units (§9.5)
are the PRs: each unit builds one WP or a named part of one. Each WP owns
tests in a matching `sdk/typescript/test/wire/<area>/` directory unless
another path is named.

**Python files (R13).** No unit hand-edits a file under
`sdk/python/src/`, with one exception that spec 058 §16.6 assigns to
this spec: unit `055-t18` adds the Node branch to the `fabric` CLI
(`fabric.cli`), which is tooling, not the SDK's capture code. Generated
Python modules that mirror a contract (`_catalogue_data.py`,
`_manifest_fields_generated.py`, `_records_keys_generated.py`) are
regenerated by their existing generators when a 055 unit changes that
contract; their tests require it. `055-t1` also changes one Python test,
`sdk/python/tests/test_diagnostics_catalogue.py`, for the `sdk` field of
§4.7. Units may add new Python test
helpers and vector generators under `scripts/` and
`qualification/node-wire/`. **Python exit gates never depend on a 055
unit.**

External dependencies (owned elsewhere), with their state on main:

| Id | Owner | What TS needs | State at `be39aca6` | Effect on the build |
|---|---|---|---|---|
| E1 | 050 WP-00 | Shared contract rows and vectors (§2.3) | Built | None |
| E2 | 050 WP-01 | Frozen P1 interface names | Built (`_capture_types.py`, `_records.py`) | `p1-types.ts` ports them as they are |
| E3 | 050 WP-11a, WP-11b | Records input, seal, `record`/marker/loss spool kinds, 260/8 check, segment-attributed ledger | Built | Cross-language frame reads can be tested from `055-t7` |
| E4 | 050 WP-21 | Node pre-acknowledgement validation (R10) | **Not built** | Not a blocker. The sender's outcome classes (§7.1) are the same either way. Until WP-21 lands the Node may drop a record after HTTP 200, so every TS verification reads back from the store, as Python's does |
| E5 | 050 WP-30–WP-33 | P1 reader, seal recompute, graph, projection | Built | Request R-TS-1 below |
| E6 | 050 WP-12, WP-14 | Python run API, C35/C40 emission | Built | Parity tests run against them |
| E6b | 050 WP-50 | LR-1 harness `qualification/run-structure/` | Not built (an end-to-end test exists) | `055-t22` runs the model-call part of LR-1 in `qualification/node-wire/` with a Python continuation; it does not wait for the harness |
| E7 | R16 | `test/agent-matrix` and `test/chaos` merged to main | **Not done** | TS qualification is self-contained (§9.3, OQ-7) |
| E8 | H0 | Decision-line privacy fixes | Shipped in v0.8.0 | None |
| E9 | 058 WP8-4, WP8-9, WP8-13 | `fabric run`, the npm launcher, the injector | Not built. 058 E1a is built (#291): the `fabric.cli` command table, where `run` still reports `FC-010`, the diagnostics catalogue, the endpoint table and the status file | `055-t18` builds the Node branch on whatever is in its base and records the rest (§13.1) |

Request R-TS-1 to the reader owner (050 reader WPs; spec 057 P1a for the
wire-derivation rules): the reader resolves capture points from the
registry and selects wire exchanges by `fabric.capture.input=wire`, never
by a Python point id. If `wire.ts.*` points need a code change in
`reconstruct/**`, unit `055-t13` files it as an issue with a failing
fixture and the owner fixes it; a 055 unit does not edit the reader.

| WP / owner area | Deliverables | Built by units |
|---|---|---|
| WP-01 contracts and interfaces: §8's rows and fixtures; the catalogue entries and status schema of §4.7; `native/fabric_wire_abi.h`; `wire/{types,p1-types,config,match,codec}.ts` and the generated endpoint table and catalogue modules; TS-0 audit; compatibility table | Frozen DTOs, P1 port types, §4.4 ABI header, environment mapping, exact int64/canonical vectors, version/boundary qualification table | `055-t1`, `055-t2` |
| WP-02a native addon: `native/**`, `binding.gyp`, `wire/native.ts`, `scripts/typescript/prebuild/**`, `.github/workflows/typescript-native-prebuilds.yml` | §4.4 exactly | `055-t3` |
| WP-02b JS shared runtime: `wire/{runtime,arena,queue,exchange,registration,isolate}.ts` | §4.5; epoch registration (050 §3.2) | `055-t4`, `055-t5`; isolate attach in `055-t19` |
| WP-02c run structure: `wire/{scope,segments,seal,manifest,loss,run-api}.ts` | §4.3, §7.2 | `055-t9`, `055-t10`, `055-t11` |
| WP-03 undici: `wire/undici.ts` | §3.2 | `055-t6` |
| WP-04 core HTTP: `wire/node-http.ts` | §3.3 | `055-t21` |
| WP-05 protection and content writer: `wire/{worker,protect,parts,writer}.ts`; scoped changes to `deployment-policy.ts`, `redaction.ts` if needed | §5 | `055-t8` (whole-object modes), `055-t15` (split parts, review copies) |
| WP-06 durable spool: `wire/{spool,ledger,spool-codec}.ts` | §6.2, §6.3 | `055-t7`, `055-t16` |
| WP-07 sender and readback: `wire/{sender,node-content,delivery,otlp}.ts`; tests that run the Python reader as a subprocess | §7.1, §7.3 | `055-t12`, `055-t13` |
| WP-08a records bridge (integration owner of `decision.ts`, `calls.ts`, `byte-evidence.ts`): those files and `wire/records-input.ts` | §6.1; the seam of §13.2 | `055-t20` |
| WP-08b packaging and preload (integration owner of `src/index.ts`, `package.json`, `tsup.config.ts`): those files, `wire/index.ts`, `src/register.ts`, `wire/status.ts`, package-artifact tests, wire docs | §9.4 | `055-t14` |
| WP-09 qualification: `qualification/node-wire/**`, CI jobs of §9.2, release workflow TS steps | §9.2, §9.3 | `055-t17` (TS-1U, TS-1D), `055-t22` (TS-1H, full) |

**Shared files and integration owners.**

| File(s) | Integration owner | Order and handoff |
|---|---|---|
| `sdk/typescript/src/decision.ts`, `calls.ts`, `byte-evidence.ts` | 055 WP-08a (`055-t20`) | `055-t20` → 057 WP7-16 → 051 WP2-11 → 052 WP3-6. `055-t20` lands every TS-1 change and freezes the `wire/records-input.ts` seam with a header comment naming the regions it changed. Later specs add methods through that seam and change its signatures only through the integration owner |
| `sdk/typescript/src/index.ts`, `package.json`, `tsup.config.ts` | 055 WP-08b (`055-t14`) | 058 WP8-9 adds only the `bin` key and its launcher file; 058 WP8-19 only the peer range (done by #286). Whichever lands second rebases; the keys do not overlap. 051 WP2-11, 052 WP3-6 and 057 WP7-16 add exports afterwards |
| `sdk/typescript/src/identity.ts` | 051 WP2-11 (`V2_TYPES`) | 055 does not edit it |
| `sdk/typescript/src/deployment-policy.ts` | 055 WP-05 for wire needs; 057 WP7-16 for the `security_context` section | WP-05 first |
| `sdk/typescript/src/records*.ts`, `control-evidence.ts` | 051 WP2-11, 052 WP3-6, 057 WP7-16 | 055 creates no file matching these names; its seam is `src/wire/records-input.ts` |
| `binding.gyp`, `native/**` | 055 WP-02a | `055-t1` owns only `native/fabric_wire_abi.h` |
| `src/wire/worker.ts` (worker entry) | 055 WP-05 | WP-06/07 export modules it imports |
| `.github/workflows/recorder-ci.yml` | Each unit adds only its own job or step | Jobs are named in §9.2 |
| Contracts and 049 generated blocks | `055-t1` | The serialized contract chain of revision 2 no longer applies: 050 WP-00 is built and 051–054 are not scheduled before this lane. `055-t1` applies every row of §8 in one PR and regenerates the 049 blocks with the existing generator (`scripts/contracts/generate_p0_contracts.py`). If a 057 unit lands a contract change first, `055-t1` rebases and regenerates |

Any fix requiring a foreign ownership area is coordinated with its owner
before editing it.

### 9.2 Passivity and privacy gates, measured in CI

Every gate below is a CI job that fails the PR. A gate is never a
statement in a document. The jobs run from the built package (from the
packed npm artifact once `055-t14` lands), on `ubuntu-latest` with the
minimum qualified Node 24 patch; the nightly workflow repeats them on
the other qualified tuples (Linux arm64, macOS arm64, the newest Node 24
patch). Each job writes a JSON report and uploads it as a build
artifact; `055-t17` and `055-t22` commit the reports of the claimed
tuples under `qualification/node-wire/results/`.

| CI job (in `recorder-ci.yml`) | Added by | What it measures | Fails when |
|---|---|---|---|
| `ts-wire-passivity` step **hook cost** | `055-t6` | Isolated processes: baseline, installed-disabled and enabled, warmed JIT, at least 30 alternating trials. Median added hook time for a matched non-streaming exchange, one stream chunk and one non-matching request, with 1 KiB bodies and chunks, against deterministic transport fixtures and a real local HTTP/SSE server | Scaled median exceeds 50 µs, 2 µs or 5 µs respectively |
| `ts-wire-passivity` step **calibration** | `055-t6` | A pinned deterministic JS workload (20,000 map/property updates and integer-to-string conversions). `scale = clamp(min(before, after) / reference, 1, 4)` from the minimum of 30 runs each side, as 047 §4.10. The reference ns is committed with the harness (`qualification/node-wire/passivity/reference.json`) and never recalibrated silently: a change to it is a reviewed diff | Calibration differs more than 2x between `before` and `after` (the run is void and repeats once; a second void run fails) |
| `ts-wire-passivity` step **gate self-test** | `055-t6` | Injects a stall of twice each scaled budget into the hook, and a main-loop stall above the delay ceiling | The gate does **not** fail on the injected stall |
| `ts-wire-passivity` step **event loop** | `055-t6`; sustained case from `055-t13` | `monitorEventLoopDelay({resolution: 1})` on the application loop with matching baseline sampling, `performance.eventLoopUtilization()`, and a monotonic scheduled-timer drift probe (so a synchronous workload cannot produce an empty histogram). 60 s sustained SSE and fan-out, including one 40 MiB mutable request | Baseline-subtracted main-loop p99 delay exceeds 2 ms × scale, maximum exceeds 25 ms × scale, or utilization delta exceeds 0.05 |
| `ts-wire-passivity` step **no forbidden work in hooks** | `055-t6`; extended by `055-t21` | While a hook callback runs, trip-wires on synchronous `fs`, `net`/`tls`/`http` sends, `crypto` hashing, `JSON.parse`/`stringify`, `Atomics.wait`, `console` and `process.stdout`/`stderr` writes | Any trip-wire fires inside a hook |
| `ts-wire-passivity` step **behaviour identity** | `055-t6`; extended by `055-t14`, `055-t21` | For every client row of §9.3: host-off versus host-on server-received bytes, response bytes and chunk boundaries seen by the application, event and chunk object identity and order, thrown and rejected error object identity, abort and backpressure behaviour, exit code | Any difference |
| `ts-wire-passivity` step **stalled recorder** | `055-t13`; `055-t16` | Stalled fsync, sender, redaction service, admission lock and saturated capture worker (fault injection) | Host throughput, chunks or cancel behaviour change beyond the hook budgets; any recorder error reaches the application |
| `ts-wire-passivity` step **memory bound** | `055-t6`; `055-t13` | RSS, external, `SharedArrayBuffer` and native memory and queue/slab high-water marks under tiny-chunk storms and many zero-body requests | Exceeds configured payload + scratch + §4.5's per-entry and slab overhead, or grows linearly after saturation |
| `ts-wire-passivity` step **large shapes** (report, not averaged) | `055-t8`; 40/70 MiB from `055-t15` | 0 B, 64 KiB, 1 MiB, 32 MiB, 40 MiB inline-media and 70 MiB oversize: bytes copied and synchronous time per chunk size | A single synchronous snapshot stall exceeds 25 ms × scale. These shapes are never averaged into the small-body medians |
| `ts-wire-privacy` step **canary scan** | `055-t8`; extended by `055-t13`, `055-t16`, `055-t20`, `055-t21` | Canary strings are planted in the prompt, tool schema, response, URL path and query, request and response headers (authorization, cookies, API keys), error message and `Error.name`, clear caller ids, resource attributes and the environment. The scanner reads every byte Fabric produced: spool files raw and decrypted, temp, quarantine and ledger files, registration files, the status file and exit note, Fabric's log output, the OTLP requests the sink received (traces and logs), the Node's persistent queue and the store in the e2e cases, and the reader's reports | A canary appears anywhere except inside a content object whose role policy authorizes retention; under `omit`, `metadata_only`, `redact`, `masked_only` and `tokenize` it appears nowhere, encrypted or not; an original digest or range appears for a withheld or transformed object |
| `ts-wire-privacy` step **scanner self-test** | `055-t8` | A test-only fault leaks one canary into a span attribute and one into a spool header | The scanner does **not** report both |
| `ts-wire-privacy` step **network** | `055-t12` | Hostile `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY` and Node's startup proxy mode; 301/302/303/307/308 from the delivery and redaction endpoints; a recording socket on every non-configured address | Any Fabric byte or header reaches a proxy, a redirect target or an address that was not configured; a provider probe is sent |
| `ts-wire-privacy` step **artifact** | `055-t14` | The packed tarball: file list, `package.json` scripts, strings in `dist/` and `prebuilds/` | An install script, a source map with embedded source, a forbidden OSS-boundary term (the list of `scripts/tests/test_recorder_release_boundary.py`), a framework dependency or an exported symbol beyond §4.4 is present |
| `typescript-native` (`typescript-native-prebuilds.yml`, called from `recorder-ci.yml`) | `055-t3` | Builds the addon on the six targets and runs the ABI tests on each (QEMU for the non-native Linux targets) | Any target fails, the digest table differs from the built files, or a symbol beyond §4.4 is exported |
| `ts-wire-parity` | `055-t13`; extended to the claim matrix by `055-t17` | Runs the same protocol fixtures through Python and TypeScript; compares spool frames byte for byte after the §7.3 substitution; runs `python -m fabric.reconstruct` over the TypeScript capture | Frames differ; the reader does not report the run `complete` and `terminated`; a projection differs from Python's |

The budgets are the ones 047 §4.10 set for Python (50/2/5 µs) plus the
Node scheduling budgets (p99, maximum, utilization), which are new and
need the owner's confirmation (§14 OQ-3). If a budget fails, do not
claim passivity by moving parsing to `setImmediate` or dropping
retention limits; the affected shape stays unsupported until snapshot
cost is qualified (§4.5). A failed job may be re-run once when the
calibration step voided the run; any other re-run needs a code change.

Instrument worker loops separately; their histograms cannot stand in
for the main loop. Histogram values are ns, resolution is ms: see Node's
[performance measurement API](https://nodejs.org/docs/latest-v24.x/api/perf_hooks.html#perf_hooksmonitoreventloopdelayoptions).
Pin the numeric caps of §4.5 in `055-t2`'s fixtures.

### 9.3 Client matrix and chaos

The harness is self-contained in `qualification/node-wire/` (R16 is not
done, §2.4): `matrix.json`, `README.md`, `package.json`,
`package-lock.json`, `clients/` (one script per row), `harness/` (a
scripted provider server and a recording sink, reusing
`scripts/tests/_wire_capture_sink.py` and `_wire_capture_common.py`),
`chaos/`, `passivity/` and `results/`. When the `test/agent-matrix` and
`test/chaos` branches reach main, their owner may fold this tree into
theirs; nothing in 055 waits for that.

Reports use public synthetic data only, with artifact SHA,
Node/undici/SDK and client versions, boundary, role, profile, capture
point and gate results. No live provider access or credentials are
required for acceptance. A live-provider smoke can supplement, never
replace, deterministic byte parity; `055-t17` runs one such smoke (at
most 20 calls) and reports it in its PR, not in a gate.

**Rows are transports and model clients, never agent frameworks.**
Revision 2 listed rows named after agent frameworks. They are removed:
capture attaches to the model wire, `AGENTS.md` forbids depending on a
framework, and a framework's traffic is already one of the transport
shapes below. A row describes how bytes reach undici or core HTTP.

| Row | Gate | Required scenarios / assertions |
|---|---|---|
| Global `fetch` | TS-1U | ESM and CJS; in-memory and streamed request bodies; JSON and SSE responses; compressed JSON/SSE; abort before headers, mid-body and after completion; paused consumer; keep-alive reuse; non-matching requests untouched |
| External `undici` package (`fetch`, `request`, `Client`, `Pool`) | TS-1U | Each qualified external version; pipelining; the same scenarios as global `fetch`; an unqualified version reports `unsupported(unsupported_version)` and the mixed process is not `complete` |
| Official `openai` client | TS-1U | Chat Completions, Responses (hosted tools, previous-response references), legacy Completions and Embeddings where supported; non-stream and SSE; SDK retry, timeout and cancel; the server-received request body is byte-identical with capture off |
| Official `@anthropic-ai/sdk` client | TS-1U | Messages JSON and SSE; thinking, redacted thinking and server-tool fixtures; error before and after headers; cancel; SDK event objects and behaviour preserved |
| Custom `fetch` passed to a client | TS-1U | A wrapper that delegates to global `fetch` is captured once; a wrapper that does not reach a qualified point is reported uncaptured, never guessed |
| Tool loop and fan-out shapes (a plain script, no framework) | TS-1D | Multi-turn tool loop; 16 parallel requests joined; streamed output cancelled mid-turn; a retry after a transport error is a second attempt. Every transport attempt is matched; one run id; seals verify |
| Core `http`/`https` | TS-1H | Write/end overloads, duplex, cork, backpressure, `setEncoding`, delayed read, partial request, reused sockets, library-driven redirect hops and failures |
| A pinned HTTP/1 client library that sends through core `http` (optional) | TS-1H | Qualifies only through `wire.ts.node_http`; other adapters of that library remain uncaptured |
| `worker_threads` pools and `cluster` | TS-1D after `055-t19` | Attached workers share one allocator; `eval` and `execArgv: []` workers report unattached; cluster workers register their own epochs |

Each positive row runs against exact pinned packages on the minimum
passing Node 24 patch and another current qualified 24 patch, each
declared OS/architecture, both local and authenticated production
profiles, pseudonymous identity mode, plus a clear-mode case per R8.
Negative rows: Node 22, Node 24.0 with its old undici, a missing native
prebuild, an unqualified custom transport, HTTP/2 dispatchers,
Gemini/Bedrock/gRPC/WebSocket/realtime endpoints, Bun and Deno: each
reports unsupported or uncaptured with its reason and the agent runs
unchanged. Do not import any client into the default runtime package.
Pin actual versions when the harness is created.

For every row compare host-off/on outputs, exact errors, event/chunk
object identity and order, timing/backpressure and server-received
bytes; run the same protocol fixture through Python and TS and compare
§7.3 projections. Test SSE split at every byte boundary (including UTF-8
and CRLF), comments, multiline data, missing terminators/DONE, malformed
events, multi-choice tool deltas, empty bodies and response truncation.
Snapshot-mutation tests reuse pooled/subarray buffers after callbacks
and verify stored bytes never change. Concurrent hostile mutation of
shared memory is a negative case.

`qualification/node-wire/chaos/` ports the Python spool
hardening/accounting/barrier/shared-bound cases: 2/4 real processes,
mixed TS/Python frame recovery, 128 short-lived writers, drainer
death/takeover, kill before protection/after admission/during
retirement, Node down then return, ENOSPC/EDQUOT/EIO at
write/fsync/rename/truncate/unlink/stat, unknown key, AEAD tamper/wrong
filename, corrupt batch member, ledger exhaustion/torn slots, receipt
expiry, recreated ancestor, stopped worker and queue overflow.
TS-specific cases: application Worker terminated mid-exchange (positions
settle as `shutdown`), Fabric worker crash and restart (handles and
counter survive), parent SIGKILL with a live `child_process.fork` child
(the parent's registration becomes an orphan), try-lock contention
storm, 400/413/415/422 content rejection retiring records, a refused
content batch resent one record per request. After every randomized
operation assert disk accounting and no false complete; export all
admitted evidence after recovery or name its loss.

Conformance mapping: TS-0 and TS-1U/H/D satisfy 049 decision 9; C0-1..5
contract/registry/vocabulary/id/admission/artifact consistency; C0A-1..4
role e2e, privacy, production gate and caller-id mapping; C1-1 stable
event replay, C1-2 manifest chains, C1-3 projection, C1-4 split
reassembly, C1-5 no false complete. `055-t22` repeats the model-call
portion of LR-1 with TS processes and a Python consumer/continuation:
declared branches, token-only hops with a lost middle segment (A → B → C
keeps one run id through the correlation id), fan-in with conflicting
correlation ids, missing terminal, key rotation, skew, conflict and
store-recomputed seal variants. Never use plain `r-` strings as an
identity bypass. P1-A mixed capture cases cover explicit withholding and
response outliving scope. Do not claim TS-2/P2/P3 or 046 conformance
from these tests.

### 9.4 Autoload, qualification table and artifact exit

Ship one preload for both module formats (the name spec 058 §5.5 uses):

```sh
FABRIC_WIRE_AUTOLOAD=1 NODE_OPTIONS="--import=@singleaxis/fabric/register" node agent.mjs
FABRIC_WIRE_AUTOLOAD=1 NODE_OPTIONS="--import=@singleaxis/fabric/register" node agent.cjs
FABRIC_WIRE_AUTOLOAD=1 NODE_OPTIONS="--require=@singleaxis/fabric/register" node agent.cjs
```

`--import` runs before the entry point whether the entry point is ESM or
CommonJS, so one flag serves both; `--require` is kept for launchers
that only pass `-r`. Registration must synchronously install hooks
before application imports; no top-level-await requirement in either
path. Gate on `FABRIC_WIRE_AUTOLOAD=1`; without it importing the
preload is inert (reason `autoload_off`). Do not overwrite existing
`NODE_OPTIONS` in deployment instructions or tooling; append the entry.
Ordinary wire installation enables undici; core HTTP requires its
separate switch (`FABRIC_WIRE_NODE_HTTP=1`). Duplicate preload plus
explicit install uses a process singleton and compatible configuration;
an incompatible explicit reinstall closes/rotates deliberately or throws
fixed-text configuration errors, never produces duplicate capture.

**Qualification table.** `sdk/typescript/wire-qualification.json`
(shipped in the package as `dist/wire-qualification.json` and exported as
`@singleaxis/fabric/wire-qualification.json`) is the single source for
"which runtime builds may be active":

```json
{
  "schema_version": "fabric.wire-qualification/v1",
  "gates": { "TS-1U": "not_passed", "TS-1D": "not_passed", "TS-1H": "not_passed" },
  "tuples": [
    {
      "point": "wire.ts.undici",
      "node": "24.13.1",
      "undici": "7.18.2",
      "undici_origin": "bundled",
      "platform": "linux-x64-glibc",
      "boundary": "post_decompression",
      "report_sha256": "sha256:<hex>"
    }
  ]
}
```

The values above show the shape; `055-t1` writes the audited ones. A
capture point is active only for a tuple in this table. A tuple enters
the table in the unit that proves its body publications (`055-t6` for
undici, `055-t21` for core HTTP). The `gates` block flips to `passed`
only in `055-t17` (TS-1U, TS-1D) and `055-t22` (TS-1H). The release
workflow test (`scripts/tests/test_npm_release_workflow.py`) refuses to
publish a tarball that exports `./register` while `TS-1U` or `TS-1D` is
`not_passed`, so an unqualified build cannot reach npm. Spec 058's CLI
reads this file to decide the Node zero-code path (§13.1).

Qualify child/cluster/application-worker preload inheritance as actually
launched (§4.5, §6.4); users can suppress inheritance through their own
argv/env. Fabric's worker opts out through `env: {}` and its marker. Test
the npm packed artifact, not source imports, with both module formats, no
host OTel, late install, existing OTel instrumentation and missing native
prebuild. Mark only the preload entry files as package side effects; root
import is inert. Provide wire type declarations and conditional exports,
no default framework dependencies and no install scripts. A missing or
unsupported native addon is visible status, never a runtime exception
escaping preload.

Use bounded best-effort `beforeExit` drain with unref'd timers/workers;
`exit`, `process.exit()`, SIGKILL and worker termination cannot promise an
async flush. `FABRIC_WIRE_DRAIN_ON_EXIT_S` is the customer's opt-in to
wait longer (§7.1). Do not install signal handlers that intercept
application shutdown or keep a process alive indefinitely. Explicit
`close` stops new capture, settles or records losses, drains within
deadline and emits final only if justified. Its result is false on loss,
unresolved durability or undelivered evidence, even when another process
silently removed a file.

Installed-artifact content tests reject legacy assurance, judges, red-team,
runtime control, policy enforcement, fleet/UI and private topology code or
advertising. 045/046 opt-in artifacts remain separate. Release docs include
the exact qualification tuples, startup limitations and 049 production
upgrade prerequisites; no `>=24` blanket byte-capture claim.

### 9.5 Build units

One unit is one PR, built by one agent and then reviewed by another. Units
are stacked in this order (lane `055`); each builds on the previous one.
A unit is about 2,000 changed lines or fewer, tests included (generated
files, lockfiles, fixtures and prebuilt binaries not counted). If a unit
cannot fit, it lands the part its unit prompt marks "May defer" in the
next unit and says so in its PR; it never drops a listed test silently. Every unit
runs the CI-equivalent checks for what it touches (`npm ci`, lint,
typecheck, build, `vitest`, the contract validators, `pytest
scripts/tests`) and adds a plain-language CHANGELOG entry.

Until `055-t17`, the release qualification table has no passed gate, so
no published build can activate capture; tests activate it through the
table in the source tree. "Newly visible" says what a person or the
reader can see after the unit that they could not see before.

| Unit | Builds | Exact acceptance tests (all must pass in CI) | Newly visible |
|---|---|---|---|
| `055-t1` contracts, ABI header, runtime audit | WP-01 (contract part): every row of §8; the diagnostics catalogue entries, `sdk` field and `wire-status-v1.schema.json` of §4.7; `native/fabric_wire_abi.h`; `sdk/typescript/wire-qualification.json` with audited candidate tuples; `scripts/typescript/audit-undici-channels.mjs` | `scripts/contracts/validate_coverage_contracts.py`, `validate_capture_contracts.py` and `pytest scripts/tests/test_coverage_contracts.py scripts/tests/test_capture_contracts.py scripts/tests/test_contract_generators.py` pass with the new rows; valid and invalid fixtures of §8 each accepted or refused; `sdk/python/tests/test_diagnostics_catalogue.py` passes with the `sdk` field (Python entries still all emitted, `typescript`-only entries exempt there), `_catalogue_data.py` and `docs/diagnostics.md` regenerate with no diff, and a new `scripts/tests/test_wire_status_schema.py` validates Python's install, failure and exit status documents against the status schema; 049 generated blocks regenerate with no diff; the audit script, run in CI on Node 22.x, 24.0.0, the candidate minimum and the newest 24.x, records which body-chunk channels each build publishes for one local `fetch` POST, and the table matches its output; a header test compiles `fabric_wire_abi.h` and checks every name and value of §4.4 | The registry describes both TypeScript points and their limits; a checked-in table says which Node builds publish request and response bytes. No runtime change |
| `055-t2` codec, configuration, matcher, P1 pure functions | WP-01 (code part): `wire/{types,p1-types,config,match,codec}.ts`; generated `wire/endpoint-table.generated.ts` and `wire/catalogue.generated.ts` with their generator `scripts/typescript/sync-contract-data.mjs`; record digest, seal digest, token parse/issue and run-identity rules as pure functions; `contracts/capture/v1/fixtures/vectors/spool-bytes-v1.json` and its generator `scripts/contracts/generate_ts_wire_vectors.py`; TS-0 audit | `test/wire/codec/`: canonical JSON and int64 vectors through 2^63−1 (escaping, surrogatepass ids, integral floats, ordering); every case of `resume-token-v1/v2`, `seal-digest-v1`, `seal-parity-v1`, `manifest-chain-v1`, `manifest-span-v1`, `run-marker-v1`, `records-span-v1`, `span-category-v1` and `pseudonym-v2` byte for byte; `test/wire/match/`: property tests against a table generated from `wire/_match.py`; `test/wire/config/`: the Python-to-TS environment mapping fixture (unset versus empty, `*_FILE` variants, 058 names, `FABRIC_OTLP_*` precedence over `OTEL_EXPORTER_OTLP_*`), every malformed value produces the catalogue id Python produces for it (a shared table generated from `wire/_diagnose.py`); both generated modules equal their contracts; the built-in matchers equal Python's for `table` and `legacy`; every id the code can produce is in the catalogue; `test/wire/ts0/`: identity and new-key parity, the inventory of automatic `String()`/`JSON.stringify` of application objects (R9), cross-language id privacy canaries; `pytest scripts/tests/test_capture_contracts.py` regenerates `spool-bytes-v1.json` from the Python writer with no diff | TypeScript computes Python's digests, tokens and ids byte for byte. No runtime change |
| `055-t3` native addon | WP-02a: `native/**`, `binding.gyp`, `wire/native.ts`, prebuild scripts, CI job `typescript-native` | C unit tests; one JS test per function and code of §4.4; two-process `flock` and `recordLock` conflict; Python `fcntl.flock`/`lockf` interop both ways; a fork/exec child holds no inherited lock after the parent is SIGKILLed; Worker terminate reaches `takeDetachedEnvs`; each disabled reason of §4.4 from a missing, corrupt, wrong-ABI and self-test-failing prebuild; no symbol beyond §4.4 exported; all six targets green | `wire/native.ts` loads or names why not. No capture yet |
| `055-t4` shared runtime (one isolate) and Fabric worker | WP-02b part 1: `wire/{runtime,arena,queue,exchange}.ts`, worker bootstrap in `worker.ts` | `test/wire/runtime/`: allocation uniqueness and monotonic order under 8 concurrent producers (simulated isolates on one control block); slab, chunk-vector, exchange-slot and ring exhaustion each produce the named loss and never a partial body labelled exact; finish-once under every race of §4.6; no `Atomics.wait` on the installing isolate (trip-wire); try-lock timeout yields `internal_error` loss; Fabric worker starts with `execArgv: []`, `env: {}`, is `unref`'d, never loads the preload (checked with `NODE_OPTIONS` set) and is recreated after a crash without resetting the counter | Internal only |
| `055-t5` epoch registration and allocator binding | WP-02b part 2: `wire/registration.ts`; `store64` mirror; orphan scan | `test/wire/registration/`: the registration file is byte-identical with Python's for the same inputs (`spool-bytes-v1.json`); a Python process reads a live TS registration as live and a killed one as orphan, and the reverse; forced epoch collision redraws (8 at most); the mirror holds the next sequence after SIGKILL; registration never happens in a hook | A Python drainer or reader sees a Node process's epoch, including one that was killed |
| `055-t6` undici hook and passivity harness (TS-1U correctness) | WP-03: `wire/undici.ts`; `qualification/node-wire/passivity/`; CI job `ts-wire-passivity` (hook cost, calibration, self-test, event loop, forbidden work, behaviour identity, memory) | `test/wire/undici/`: byte fixtures for JSON, SSE (split at every byte boundary), gzip/br/deflate, zero-byte, early close, abort at three points, transport error, redirect hop, informational response; matched-only capture; request identity never leaks; subscriber fault injection never reaches the application; mutable-buffer property tests (pooled and subarray reuse); the captured bytes equal the server-received and application-received bytes. The passivity job passes on each tuple the unit adds to the table | With a test sink, the exact request and response bytes of every matched `fetch` call, and the hook's measured cost, per qualified Node build |
| `055-t7` durable spool I | WP-06 part 1: `wire/spool-codec.ts`, `wire/spool.ts` (frames, batch files, AES-256-GCM envelope, admission lock and shared bound, commit sequence, drainer lock, stable-order recovery scan, quarantine of corrupt records) | `test/wire/spool/`: every `contracts/capture/v1/fixtures/valid/spool-record-*.json` round-trips; `spool-bytes-v1.json` vectors (record, batch, sealed, wrong basename, unknown key id) byte for byte; **Python reads TS frames and TS reads Python frames** (subprocess); property test of disk accounting within bound + reserve after every operation; fault at every write/fsync/rename; two real processes share one bound; the no-I/O-in-hook trip-wire still passes | Captured exchanges survive a process kill on disk, encrypted, in the format Python's drainer reads |
| `055-t8` PROTECT I and the capture pipeline | WP-05 part 1: `wire/{worker,protect,writer}.ts`: role policy, the whole-object modes (`omit`, `metadata_only`, `retain_original`, `redact`, `masked_only`, `tokenize`), production gate, descriptors, the `fabric.model_call` span of §7.1, 260/8 bound check; CI job `ts-wire-privacy` (canary scan, self-test) | `test/wire/protect/`: one golden per mode and failure (timeout, redirect, non-200, oversized, malformed, saturated → `protection_failed`); production gate precedence (`missing_capture_policy`, `missing_id_key`, `missing_spool_key`); span attributes equal Python's for the shared exchange fixtures after the §7.3 substitution; crash before protect leaves no unprotected byte on disk; worker CPU stall does not move the hook medians; the privacy job passes | Protected model-call records in the spool; content policy is enforced before anything is written |
| `055-t9` manifests and heartbeats | WP-02c part 1: `wire/manifest.ts`; `wire/manifest-fields.generated.ts` (from the registry, as Python's `_manifest_fields_generated.py`); marker spool records for manifests and heartbeats | `test/wire/manifest/`: `manifest-chain-v1` and `manifest-span-v1` vectors; manifest 0 precedes position 0; state-change manifests at exact allocator boundaries; each fixture of §8 (active U, privacy-disabled, Node 22, old Node 24 undici, native missing, unattached worker, key rotation) validates; prior unsealed epochs listed (bounded) with exact count; no path, secret or inventory in any field | The record states what this Node process could and could not capture |
| `055-t10` losses and the seal accumulator | WP-02c part 2: `wire/loss.ts`, `wire/seal.ts` | `test/wire/seal/`: `seal-digest-v1` and `seal-parity-v1` through the accumulator (not only the pure function); settle only after the record is spooled; forced non-terminal seal at 1,000,000 positions (scaled-down bound in test); losses keyed by segment never coalesce across segments, reasons, sources, epochs or runs; `shutdown` losses at `close()` precede `final`; persisted uuid4 marker ids replay unchanged | A lost or dropped exchange is a named, segment-attributed gap; segment digests can be recomputed |
| `055-t11` run scopes, segments, tokens and the run API | WP-02c part 3: `wire/{scope,segments,run-api}.ts` | `test/wire/run/`: one test per seal-trigger row of 050 §3.6; the five identity rules with `id_basis`; token accept/reject vectors; `endRun` statuses (each literal of §4.3); fan-in conflict; `FABRIC_RUN_ID` and `FABRIC_RUN_RESUME_TOKEN`; ALS propagation through promises, timers and `queueMicrotask`; thrown and rejected object identity through `run()`; caller-id and environment canaries; strict mode throws, default fails open | Model calls are grouped into runs that another process, Python or Node, can continue |
| `055-t12` delivery clients | WP-07 part 1: `wire/otlp.ts` (pinned protobuf encoder for the OTLP trace and logs requests, exact int64), `wire/node-content.ts`, `wire/delivery.ts` (private agents, no redirect, proxy rules); `ts-wire-privacy` network step | `test/wire/delivery/`: encoder output equals the Python exporter's bytes for the shared span and content fixtures; mock status matrix for every code of §7.1; batch refused as a whole is resent one record per request; `Retry-After` bounded; loopback always direct; `FABRIC_WIRE_PROXY` CONNECT with certificate verification; the network privacy step passes | Internal only |
| `055-t13` sender and the first verified record | WP-07 part 2: `wire/sender.ts` (drain order, progress, retirement, flush/close, exit note); the fixture replayer `test/wire/fixtures/replay.ts` (§13.2); CI job `ts-wire-parity`; sustained and stalled-recorder passivity steps | `test/wire/sender/`: restart delivers every admitted record with the same ids and bytes; a rejected record retires and the reader reports `not_captured(store_failed)`; `scripts/tests/test_node_wire_capture_e2e.py`: a Node script calling global `fetch` (explicit `install()`), a scripted provider and the recording sink; **`python -m fabric.reconstruct` reports the run `complete` and `terminated`, exit code 0, and replays the request and response bytes**; the same fixtures through Python produce identical frames after substitution | **First verified, replayable record of a Node agent** (in CI, with `install()` from the source build) |
| `055-t14` packaging and preload | WP-08b: `wire/index.ts`, `src/register.ts`, `wire/status.ts`, `package.json` exports `./wire`, `./register`, `./wire-qualification.json`, one CJS wire core, prebuilds in the tarball, README and `docs/` Node page; `ts-wire-privacy` artifact step | `test/package-artifact.node.mjs` extended: root import installs no hook; `--import` and `--require` preloads from the packed tarball in ESM and CJS apps; duplicate preload plus `install()` is one runtime; missing prebuild is a status, never a throw; no install script; `autoload_off` without the variable; `envStatus()` and the status file validate against `wire-status-v1.schema.json` for each disabled reason of §4.4 and §4.7, and every `typescript` catalogue entry is emitted by some code path; **unmodified scripts using global `fetch`, the official `openai` client and the official `@anthropic-ai/sdk` client, started only with `NODE_OPTIONS` and environment variables, each produce a run the Python reader verifies**; behaviour-identity step extended to these three | **Zero-code capture for `fetch`, `openai` and `@anthropic-ai/sdk` from the packed package**, and one command (`envStatus()`, §4.7) that names every reason and its fix. Not yet releasable (gates not passed) |
| `055-t15` PROTECT II: split parts and review copies | WP-05 part 2: `wire/parts.ts`; `original_plus_masked`; large shapes | `test/wire/parts/`: byte-offset scan equals Python's `find_parts` on the shared split fixtures; a 40 MiB request with one inline image keeps its text and reassembles to `source_sha256`; a 70 MiB side is `truncated(body_cap)`; a part beyond the object cap is descriptor-only `part_cap`; a failed review withholds both objects; an exchange above 260 objects is an `internal_error` loss; large-shape passivity report within the stall ceiling | Large multimodal requests keep their text and reassemble; review copies exist |
| `055-t16` durable spool II | WP-06 part 2: `wire/ledger.ts`; `.ack` receipts for other writers; ancestor directory barrier; unknown-key retention; plaintext migration rule | `test/wire/ledger/`: `FWLEDGR1`/`FWLSLOT1` layout equals Python's (`spool-bytes-v1.json`); dead-owner slot recovery; ledger exhaustion and torn slots leave coverage partial, never complete; receipt cap, TTL and conservative accounting under fault at every create/rename/truncate/unlink; barrier walk and `spool_undurable`; ENOSPC/EDQUOT → `disk_full`; Python drains a spool TS wrote under disk-full and reports the same losses | Losses under a full disk or a crash are durable and visible; several processes can share one spool safely |
| `055-t17` TS-1U and TS-1D qualification and claim | WP-09 part 1: `qualification/node-wire/` matrix rows for TS-1U and TS-1D, chaos cases except worker and core-HTTP ones, bound-source e2e against the real Fabric Node (the collector image, as `scripts/tests/test_wire_capture_node_e2e.py` does), committed result reports; registry state of `wire.ts.undici`; `gates` flipped; release workflow check; docs and CHANGELOG | Every TS-1U and TS-1D row of §9.3 on each claimed tuple; every CI gate of §9.2 green on each claimed tuple with reports committed; chaos suite; production-profile e2e through the Node with store readback (`complete`, authenticated source); C0-1..5, C0A-1..4, C1-1..5 mapping table filled with test names; `scripts/tests/test_npm_release_workflow.py` refuses a tarball with an unpassed gate | **`wire.ts.undici` is qualified**: the manifest reports it `active` on listed builds and the package may be released with the undici-only claim |
| `055-t18` spec 058 switch to the zero-code Node path | §13.1: the Node branch of `fabric run`, `plan`/`verify` rows, the npm launcher's `run`, the injector's `"node"` annotation, `ttfr-laptop-node` in its after-TS-1U form; each part only where its 058 host code is in the base | For each part present: 058 G8 passivity matrix for Node (`NODE_OPTIONS` appended, never overwritten; nothing changed when the package or a qualified Node is absent; fail-open); `--print-env` goldens shared by the Python CLI and the npm launcher; `ttfr-laptop-node` meets G1's targets with `node`; injector test: annotated pod gets the variables, a pod that already sets `NODE_OPTIONS` is left unchanged with a reason. Parts whose host code is absent are listed in the PR and in §13.1 | **`fabric run -- node agent.js` records and verifies a Node agent with no code change** |
| `055-t19` application worker threads | WP-02b part 3: `wire/isolate.ts`; `envAttach`/`takeDetachedEnvs` consumer | `test/wire/isolate/`: 8 attached Workers share one allocator with no duplicate position; a terminated Worker's positions settle as `shutdown` in their own segments within 200 ms; `eval`, `execArgv: []` and pre-install Workers are counted and declared `node_worker_unattached`; ring `OVERFLOW` path; preload-reach cases of §4.5 on the minimum patch; matrix row for pools and `cluster` | Model calls made inside worker threads are recorded; unattached threads are declared |
| `055-t20` records bridge | WP-08a: `wire/records-input.ts`; `wire/records-keys.generated.ts` (the records-class key table, generated from the registry); `decision.ts`, `calls.ts`, `byte-evidence.ts` routed through it when the runtime is installed | `test/wire/records/`: `records-span-v1` and `span-category-v1` through the bridge; wire exchanges and decision/call/byte records interleave on one source and the reader verifies the run; sticky withholding and `deferred_to_explicit` (P1-A cases); sampled-out host provider does not create a gap; exception identity; R9 bounds; without the runtime every explicit API behaves exactly as before (existing tests unchanged); TS-0 still green; seam signatures frozen (a type-level snapshot test) | Explicit TypeScript records are sequenced, sealed and verified with the model calls. The seam spec 057 WP7-16 builds on exists |
| `055-t21` core HTTP hook (TS-1H correctness) | WP-04: `wire/node-http.ts`; tuples added to the table | `test/wire/node-http/`: overload and delegation property tests for `write`/`end`; cork, backpressure (`write` returning false), paused read, `setEncoding`, `end(data)` counted once; original exceptions propagate as the same object; no `data` or `error` listener added (listener-count assertion); ESM and CJS builtin paths; reversible hooks; delegation with undici never double-captures; passivity and privacy jobs extended to this point | With the opt-in switch, model calls sent through `node:http`/`node:https` are recorded |
| `055-t22` TS-1H qualification and full exit | WP-09 part 2: TS-1H rows, remaining chaos cases, mixed-language LR-1 model-call portion, registry state of `wire.ts.node_http`, final reports, docs | Every TS-1H row of §9.3 and every CI gate on each claimed tuple; LR-1 variants of §9.3 with a Python continuation; the full chaos list; `gates.TS-1H` flipped; 049 delta table of §11 applied to the registries by the existing generator | **`wire.ts.node_http` is qualified**; the full scope of this spec exits |

**Milestones.** M1 = `055-t13` (first verified record). M2 = `055-t14`
(zero-code for `fetch`, `openai`, `@anthropic-ai/sdk`). M3 = `055-t17`
(releasable undici-only claim). M4 = `055-t18` (058 zero-code Node
path). M5 = `055-t20` (records bridge; 057 WP7-16 can start). M6 =
`055-t22` (TS-1H).

## 10. Settled decisions and risks

Existing decisions are fixed: Node 24 major floor, parallel TS track,
customer-run redaction, caller-string mapping in pseudonymous mode,
one-source Node binding, no framework adapters, separate 045/046 mode.
Do not reopen them to simplify this implementation.

### 10.1 Cross-spec revision decisions R1–R16

Revision 2 marked every R decision "pending owner confirmation".
Revision 3 checks each against main. **Confirmed** means the Python side
has built it as written and released it, so TypeScript ports the built
behaviour and the shared vectors; nothing is left to decide.

| Code | Decision | State | Evidence on main |
|---|---|---|---|
| R1 | Run correlation id in every token; `fr3/` grammar; `id_basis` | Confirmed | `_segments.py:96`, `:158–183`, `:210–241`; `resume-token-v2.json` |
| R2 | Persisted uuid4 marker event ids | Confirmed | `_loss.py:11`; `run-marker-v1.json` |
| R3 | Segment-attributed losses | Confirmed | `_loss.py:69`, `:349`; `wire/_spool.py:114`; `wire/_ledger.py:21` |
| R4 | Three status inputs | Confirmed | `_records.py:494–497`; `_capture_types.py:43–48` |
| R5 | Descriptor-only bodies | Confirmed | `_capture_types.py:64–65`; `_records.py:130` |
| R6 | 260 objects per exchange, 8 per record | Confirmed | `wire/_spool.py:118`; `_capture_types.py:104`; `spool-record-v1.schema.json:437`; fixture `spool-record-exchange-260.json` |
| R7 | One structured-evidence carrier | Confirmed | `_evidence.py`; `_capture_types.py:108–114`; `record-evidence-v1.json` |
| R8 | One identity rule; clear mode is an explicit opt-in in every profile | Confirmed | `_sequence.py:124`, `:147`; `src/identity.ts:253–257`; `pseudonym-v2.json`. The proposal to restrict clear mode to the local profile was not adopted by Python and is closed |
| R9 | Fail-open APIs, `FABRIC_RECORDS_STRICT`, bounded encoders | Confirmed | `_capture_types.py:123–174`; `src/decision.ts:528` |
| R10 | Content validation before acknowledgement | Decided (050 OD-1), **not built** (050 WP-21) | No TS decision depends on it: §7.1's outcome classes are the same before and after. TS verification always reads back from the store (§9.1 E4) |
| R11 | Static dedicated Node ingress groups | Not used by 055 | One bound source per Node (§6.4) |
| R12 | Minimal Node-API addon for locks; allocator and queue in JavaScript | **Open: owner decision** (§14 OQ-1) | TypeScript-only; nothing on main |
| R13 | No TS unit edits Python SDK files | Confirmed, with the one tooling exception of §9.1 (`055-t18`, assigned by 058 §16.6) | — |
| R14 | Split work packages with explicit dependencies | Applied | §9.5 |
| R15 | C35, C40, `fabric.capture.source` | Confirmed | `wire/_attrs.py:45–81` |
| R16 | Agent-matrix and chaos harnesses merged to main | **Not done** | Branches `origin/test/agent-matrix`, `origin/test/chaos`. TS qualification is self-contained (§9.3; §14 OQ-7) |

### 10.2 Revision 2's TS decisions

Rows that revision 2 listed as "recommended, reviewers concur" and that
involve no product choice are settled here as rules of this spec. Rows
that are a product choice are in §14.

| Rev 2 id | Decision | State |
|---|---|---|
| TS-OD-1 | Minimum Node 24 patch and external undici builds | The rule is settled (lowest build that passes the audit and every gate; no claim for 24.0). The *number* is produced by `055-t1` and `055-t6`; §14 OQ-2 asks the owner to accept the rule |
| TS-OD-2 | Native addon scope | Open: §14 OQ-1 |
| TS-OD-3 | Mutable chunk copying versus passivity | Settled: snapshot exact bytes, measure every declared size, keep the affected shape unsupported if a budget fails. No delayed mutable references, detachment, hidden caps or benchmark exceptions |
| TS-OD-4 | Node scheduling budgets | Open: §14 OQ-3 |
| TS-OD-5 | Core HTTP default | Settled: opt-in via `nodeHttp` / `FABRIC_WIRE_NODE_HTTP=1`; a default change is a later, declared activation change |
| TS-OD-6 | Unversioned diagnostic publishers | Settled: a pinned qualified transport inventory; an unknown publisher makes that process unsupported for a complete claim. No dependency scanning, environment dumping or network probes |
| TS-OD-7 | Clear identity mode | Settled by R8 as built |
| TS-OD-8 | Run identity | Settled: 050 §3.6 as built (R1) |
| TS-OD-9 | Fail open versus configuration errors | Settled by R9 as built: recorder calls fail open; malformed configuration throws fixed text at explicit `install()` and the preload catches it; missing prerequisites are disabled states with a reason (§4.7) |
| TS-OD-10 | Integration owner of `decision.ts`, `calls.ts`, `byte-evidence.ts` | Settled: 055 WP-08a (`055-t20`); 057 WP7-16, 051 WP2-11 and 052 WP3-6 follow its seam (§9.1, §13.2) |
| TS-OD-11 | Unattached worker isolates | Settled: declared with `node_worker_unattached` (§8); no per-worker allocator under the process epoch |
| TS-OD-12 | Shared spool across languages | Settled as a rule (same contract revision for mixed drainers); when it is *supported* is §14 OQ-6 |
| TS-OD-13 | Fabric worker crash and pre-fsync tail | Settled: fail open; account allocated positions or the registered epoch as loss or unsealed; recreate the worker without resetting the counter; never manufacture completion |

### 10.3 Risks

| Risk | Mitigation in the build |
|---|---|
| No bundled undici build publishes both body channels on a supported platform | `055-t1` audits before any hook code is written. If none passes, global-fetch coverage stays `unsupported` and the lane stops at `055-t1` with a report; nothing is claimed |
| Snapshot copy cost of large requests breaks the event-loop budget | Measured from `055-t6`; large shapes reported separately (§9.2). The shape stays unsupported rather than weakening retention |
| GitHub-hosted runner noise makes µs gates flaky | Calibration scale, alternating trials, medians, a void-run rule and the gate self-test (§9.2). A gate that cannot be made stable is reported to the owner, never loosened in place |
| The native addon narrows platform support (no Windows, no unlisted CPU) | Declared, with a reason and a fix (§4.7); OQ-1 |
| The reader keys a wire rule on a Python point id | Request R-TS-1; `055-t13` proves it with a failing or passing fixture |
| 058's CLI is not on main when `055-t18` runs | The unit builds what its base allows and records the rest (§13.1) |

## 11. Spec 049 deltas

Do not edit 049's prose in this lane, except through the registries and
their generator (`055-t1`, `055-t22`). References are lines of 049
rev 6.8 on main `be39aca6`. Registry-derived lines must be changed in
their registries and regenerated, not hand-edited inside generated
blocks.

| Location / exact current text | Proposed replacement / addition |
|---|---|
| 049:3543–3548: "TS-1: `wire.ts.undici` on Node.js 24+, for qualified undici versions only; subscribers bounded, exception-contained, never throwing, retaining immutable data, with a queue bound and a latency gate … spool and sender per 048. Gate: capture goldens byte-identical with Python; the same exchanges reconstruct identically." | Add: "Implementation and qualification are specified in 055. TS-1U covers qualified undici publishers on exact Node 24 builds; TS-1H independently qualifies `wire.ts.node_http` HTTP/1.x; TS-1D covers their shared PROTECT, encrypted spool, sender and lifecycle, bound to the P1 run/records/seal contract of 050. Node 24 major alone does not establish body-channel availability. Mutable chunks require an owned snapshot and measured copy cost. Kernel locks come from a Fabric Node-API addon; without it capture is disabled. Until its own gates pass each capture point is unsupported. Python phase gates are unchanged." |
| 049:1008 registry row `wire.ts.undici`, observes "global `fetch` model exchanges: request/response body chunks"; cannot-observe "axios, `node:http`, custom fetch, Node.js below 24, unqualified undici versions"; supplies `N01` | Apply §8's exact undici row and field additions; add separately gated `wire.ts.node_http`. Remove blanket custom-fetch exclusions only for explicitly qualified delegates; keep unmatched/non-model and unqualified publishers excluded |
| 049:992–994: "until `wire.ts.undici` passes TS-1 … every field it would supply as `unsupported(unsupported_runtime)`." | "Until each TS capture point passes its gate, its manifest reports unsupported with `unsupported_runtime` for an unsupported runtime or a missing native addon, or `unsupported_version` for an unqualified Node/transport build; supplied fields retain that reason. A supported Node major with missing body publications remains unsupported." |
| 049:1613 N01 `observed_by` and the other §1.1 rows | Add TS points to `observed_by` for §1.1's exact list; keep parsed/inferred fields on reconstruct points. Apply through registries and regenerate both transport supplies lists |
| 049:1112–1114: "… `clear` reproduces today's `decision()` behaviour." | Add (R8): "The rule is the same in every language and phase: in `clear` mode caller ids are emitted as given; in pseudonymous mode they are always mapped whatever their shape. Ids Fabric mints (run correlation, segment, scope, event, attempt) are never caller ids in either mode." |
| 049:164: "In-process, both inputs share one durable agent spool (the fsync'd, flock-admitted, fork-safe wire spool, 048 §2), one allocator per (source, epoch) …"; 049:3359: "one `SourceAllocator` per process for both inputs" | Add: "Node worker isolates that attach after install share that process allocator, retained-byte accounting and durable runtime; an isolate that cannot attach is declared `node_worker_unattached`, never given its own counter under the process epoch. Node's `child_process.fork()` and `cluster.fork()` start fresh processes that register new epochs. See 055 §4.5, §6.4." |
| 049:3078: "the review copy is one masked object per side"; 049:3167: "the construction of `byte_spool.py`" | Clarify: "A separately configured original-plus-masked part also has its own review object; the shared exchange bound is 260 objects (050, R6). The wire envelope uses FWSPENC1 and spool-key id HMAC domain `fabric-spool/v1/kid`, as `wire/_spool.py` / `_keys.py` specify; the identity-key id uses its separate v2 domain." |
| 049:151 and 049:498: "undici on the TypeScript track" | Include the separately qualified Node HTTP point; retain exactly two inputs. No new framework input/layer |

No new phase, control runtime, content role, Activity Envelope export or
Python dependency on TS is proposed.

## 12. Revision 2 review disposition

Kept as the record of revision 2. Where a row cites §9 or §10, read the
revision 3 sections of the same number; "TS-OD" ids are mapped in §10.2.

| Finding | Resolution |
|---|---|
| TS run/delivery semantics diverge: required run id, combined token API, waits for durable seals, no outcome on `endRun`, “any content failure keeps pending” | §4.3 binding table and language-differences table; §7.1 outcome classes with permanent-rejection retirement |
| Native POSIX locking: approve minimal addon; freeze allocator/queue/FD ownership and worker-cleanup ABI; allocator and queue in JS | §4.4 frozen ABI; §4.5 JS runtime with `SharedArrayBuffer` and `Atomics` |
| WP-02 too large; ABI design cannot be left to the implementing agent | WP-02 split into WP-02a/02b/02c; ABI frozen in §4.4 and committed as a header by WP-01; WP-08 also split |
| WP-06/WP-07 own Python `wire/_spool.py` and `reconstruct/**` | Removed; dependencies E1–E6 and request R-TS-1 in §9.1 |
| WP-08 edits the same TS files as 051 WP2-11 and 052 WP3-6 | Integration owners and handoff table in §9.1; TS-OD-10 |
| 260-object bound fix belongs in the shared foundation | §5 and §8 reference 050 WP-00/WP-11b; TS only checks the bound |
| TS content sender batches records; one bad record would 400 the batch | Revision 2: one content record per request. Superseded in revision 3 by #289's design: batches with a one-record-per-request resend when a batch is refused (§4.2, §7.1) |
| Post-ack validation listed as fixed while 050 builds pre-ack | §7.1 and §10 bind to R10 / 050 WP-21 |
| Caller-id rule differs across specs; 055 rejected clear mode | R8 applied in §4.3 and §5; TS-OD-7 |
| Marker event ids uuid5 versus uuid4 | R2 in §4.3 and §7.2 |
| Losses not segment-attributed | R3 in §4.3, §6.3, §7.2 |
| Lifecycle/outcome inputs | R4 in §4.3 |
| Descriptor-only failure bodies | R5 in §4.3 |
| `fabric.capture.source` registry row; C35 persisted selector; C40 | §1.1, §7.1, §8 shared rows owned by 050 |
| Resume tokens carry a clear source label under clear labels | §4.3 identity paragraph |
| Agent-matrix and chaos harnesses unmerged | §2 and §9.3 reference the merged trees (R16, E7) |
| Python qualification depends on non-gating TS WPs | §1 and §9.1: Python exit gates never depend on a 055 WP. The 051/052 dependency lists are theirs to fix |
| MD046 code-block style | All code blocks fenced, as in the other specs |

Rejected or not adopted:
- The proposed restriction of clear mode to the local profile is not
  adopted. R8 does not include it and Python has built R8 without it;
  revision 3 closes the question (§10.1).
- Rev 1's native owned-byte queue, external `ArrayBuffer`s and native
  metadata arenas are withdrawn rather than frozen, because R12 and the
  spec review put allocator and queue in JavaScript.

## 13. Alignment with specs 058 and 057

### 13.1 Spec 058 (easy integration)

Spec 058 is accepted and on main (revision 2.1; E1a built in #291). It
does not build Node capture; its
§16.6 says "when 055 TS-1U ships, `run`, the injector and G2 switch to
the zero-code Node path with no CLI interface change". This section is
the contract between the two specs. Unit `055-t18` builds the switch.

| 058 item | What 055 provides | Who builds the switch |
|---|---|---|
| `fabric run` Node branch (058 §5.5 step 3) | The preload specifier is exactly 058's: `--import=@singleaxis/fabric/register`. `fabric run` **appends** it to `NODE_OPTIONS` and sets `FABRIC_WIRE_AUTOLOAD=1` when all three hold: the command's runtime is Node; `@singleaxis/fabric/wire-qualification.json` resolves from the agent's working directory with `gates.TS-1U` and `gates.TS-1D` both `passed`; the Node version is in a listed tuple for this platform. Otherwise it changes nothing and reports the reason (new `FC-` entries in `contracts/diagnostics/v1/messages-v1.json`, the next free ids when `055-t18` lands): package not installed (with the `npm i @singleaxis/fabric` line), Node not qualified (with the versions that are), platform unsupported | `055-t18`, in `fabric.cli` (`sdk/python/src/fabric/cli/`), if 058 WP8-4 is in its base |
| Environment (058 §5.5 "All", §6.5) | TypeScript reads the same variable names as Python, including the `*_FILE` key variants and `FABRIC_OTLP_*` (§4.2), so `.fabric/compiled.env` needs no Node-specific entries | `055-t2` (configuration) |
| `fabric plan` / `verify` coverage rows (058 §12) | Registry rows `wire.ts.undici` and `wire.ts.node_http` with runtime, state, cannot-observe and a `fix` (the preload line; `FABRIC_WIRE_NODE_HTTP=1`). "Model calls" becomes `recorded` for a qualified Node, `fix` when the preload is absent, `invisible` with reason below Node 24. After TS-1H, `wire.ts.node_http` joins the row's capture points | `055-t1` (registry); `055-t18` (the `integration-rows-v1.json` entries, if that registry exists); `055-t22` (TS-1H) |
| `fabric doctor`, `verify` reasons (058 §13.1, §13.2) | The status document of §4.7 at `FABRIC_WIRE_STATUS_FILE`: schema `fabric.wire-status/v1`, `warning_ids` and `notice_ids` holding catalogue ids, as Python writes it | `055-t2` (schema, catalogue entries); `055-t14` (writer) |
| npm launcher (058 §1.4, WP8-9) | 058 WP8-9 owns the `bin` key and the launcher file; 055 WP-08b owns `exports`, `files` and the preload. The launcher's `run` applies the same three-condition rule as `fabric run`, tested with the shared `--print-env` goldens | `055-t18` adds the Node branch to the launcher if WP8-9 is in its base; otherwise WP8-9's unit adds it from this table |
| Injector annotation `fabric.singleaxis.ai/inject: "node"` (058 §10.4) | The injector adds `FABRIC_WIRE_AUTOLOAD=1` and `NODE_OPTIONS=--import=@singleaxis/fabric/register` only when the pod sets no `NODE_OPTIONS` (058's rule: never override a variable the pod already sets). A pod that sets `NODE_OPTIONS` is left unchanged and `doctor` names the fix (`fabric run --print-env --format k8s`). The SDK must be in the agent image (058 OQ-6); nothing is copied into the pod | `055-t18`, if 058 WP8-13 is in its base |
| G2 and `ttfr-laptop-node` (058 §3.2, §3.3) | After `055-t17`: G1's targets with `node` in place of `python`, measured in a `node:24` container with no Python, with a plain `fetch` tool loop | `055-t18` switches the job to the after-TS-1U form if the TTFR harness is in its base |
| Reported TS records before capture exists (058 §13.3, WP8-19) | Unchanged by 055. After `055-t20` the same records are also sequenced and sealed when the runtime is installed | 058 WP8-19; `055-t20` |

Two points where 058's text needs a one-line follow-up, to be made by
`055-t18` in a 058 revision note (they do not change 058's interface):
- 058 §5.5 lists `FABRIC_WIRE_AUTOLOAD=1` under Python only; the Node
  preload has the same gate.
- 058 §5.5 says the entry is added "when the package resolves"; this
  spec adds the two further conditions above, so an unqualified build is
  never activated by tooling.

### 13.2 Spec 057 WP7-16 (TypeScript security-context parity)

WP7-16 runs after this lane (program unit `057-p1d`). It has two parts,
and this spec names the interface for each.

**(a) Record APIs** (`recordGrant`, the `recordControl` additions, a
`controlCheck` wrapper, `recordExtension`). They are records-input
producers. The interface is the seam `055-t20` freezes in
`sdk/typescript/src/wire/records-input.ts`:

```ts
// Found through the per-isolate slot; undefined when no runtime is installed.
export function currentRecords(): RecordsInput | undefined;

export interface RecordsInput {
  begin(kind: StepKind, point: string, options: BeginOptions): Attempt | undefined;
  modeOf(role: string): PrivacyMode;
  v2(prefix: string, value: string): string | undefined;
}
export interface BeginOptions {
  provenance: 'reported' | 'observed';
  stepId?: string;
  parentAttempt?: Attempt;
  aliases?: readonly string[];
}
export interface Attempt {
  emit(phase: Phase, options: EmitOptions): boolean;
}
```

`EmitOptions` is §4.3's (`nameHint`, `attributes`, `startNs`, `endNs`,
`lifecycle`, `resultStatus`, `otlpStatus`, `bodies`, `evidence`,
`eventId`, `spanIds`). Rules WP7-16 relies on:
- every call fails open (`undefined`/`false`, counted) and throws only
  under `FABRIC_RECORDS_STRICT=1`;
- attributes pass rule A of 050 §3.4: only keys of the generated
  records-class table are kept, so WP7-16 regenerates
  `wire/records-keys.generated.ts` from the registry (which already
  holds the 057 keys) and adds no hand-written key list;
- the capture points are the registry's `records.grant`,
  `records.control` and `records.extension`, with
  `provenance: 'reported'` and `enforced_by_fabric=false` on every
  control record;
- with no wire runtime installed the new APIs record nothing and return
  normally, as Python's do without a capture handle;
- WP7-16 puts its code in a new file (`sdk/typescript/src/records-security.ts`
  and its exports in `src/index.ts`), not in `wire/**`, and changes the
  seam's signatures only through the 055 integration owner.

WP7-16 also owns accepting the `security_context` section in
`src/deployment-policy.ts` (§2.1) and the manifest fields derived from
it; `wire/manifest.ts` takes manifest fields from the generated manifest
field table, so that needs no change to 055 code.

**(b) Offered-grant, safety-map and denial-marker derivation "over 055
wire bytes".** These rules (`wire.offered_grant`, `wire.safety_map`,
`wire.tool_result_flag`, `wire.tool_result_marker`, built by 057 P1a)
live in the Python reader. 055 §7.3 keeps one reader and builds no
JavaScript reconstruction engine, so there is **no TypeScript
derivation code**. The interface is the evidence 055 delivers:
- `fabric.model_call` spans with `fabric.capture.input=wire` and
  `fabric.capture.point=wire.ts.undici@<version>` (or
  `wire.ts.node_http@<version>`), and the `model.exchange.request`,
  `model.exchange.response` and `model.exchange.part` content objects,
  byte-compatible with Python's (TS-1D);
- the fixture replayer `055-t13` adds
  (`sdk/typescript/test/wire/fixtures/replay.ts`:
  `replayExchange(fixture) → spool directory`), which sends a recorded
  request/response fixture through the real hook and pipeline.

WP7-16 replays 057 P1a's dialect fixtures through that replayer, runs
`python -m fabric.reconstruct` on the result and compares with P1a's
goldens after the §7.3 substitution. The rules must select exchanges by
input `wire`, not by a Python capture-point id (request R-TS-1, §9.1).

## 14. Open questions for the owner

Build agents follow the recommendation unless the owner changes it. The
lane starts when the owner accepts this table (program hold
`holds/055-accept`).

| Id | Question | Recommendation | Consequence if the owner chooses otherwise |
|---|---|---|---|
| OQ-1 | **Native addon (R12).** Node has no `flock`, record-lock or `mmap` API. May the npm package ship a small Node-API addon (C, six prebuilds for Linux x64/arm64 glibc and musl and macOS x64/arm64, no install script, digest-checked before load) that provides only kernel locks, file descriptors, one shared mapping and a worker-teardown notice (§4.4)? | **Yes, as §4.4.** It is the only way a Node process and a Python process can share one spool safely and for a killed process to be detected by the kernel, not by guesswork. Without the addon capture is off with a named reason and fix; the agent is never affected. Windows and other platforms are unsupported in this build and say so | Without an addon: a JavaScript lock-file scheme. Each Node process would need a private spool directory, a killed process's records would wait for a time-based sweep, Python and Node could not drain each other's spools, and §4.4–§4.5, §6.3 and units `055-t3`–`055-t5`, `055-t7`, `055-t16` would need a redesign and a new review before the lane could start |
| OQ-2 | **Supported Node versions.** The package keeps installing on Node 22.18+ (explicit APIs work there). Model-call capture is active only on the exact Node 24 builds the audit and gates pass, starting from the lowest passing 24.x patch (candidate: 24.13.1 with bundled undici 7.18.2); Node 22, Node 24.0 and unlisted builds report `unsupported(unsupported_version)` with the fix "use a listed Node 24 build" | **Accept the rule**; the numbers come from `055-t1` and `055-t6` and are listed in the release notes | A blanket ">= 24" claim would be false for 24.0 (its undici publishes no body chunks). Supporting Node 22 needs a different hook (replacing global `fetch`), which changes the application's objects and is not passive |
| OQ-3 | **Passivity budgets for Node, enforced in CI (§9.2).** Hook medians of 50 µs per matched exchange, 2 µs per stream chunk and 5 µs per non-matching request (the Python budgets), plus new Node scheduling budgets: main-loop p99 delay ≤ 2 ms and maximum ≤ 25 ms over baseline, event-loop utilization delta ≤ 0.05, each scaled by a pinned calibration workload, with a self-test that proves the gate can fail | **Approve these numbers as PR-blocking gates.** They are measurable on hosted runners with the calibration scale; if a number proves unstable on those runners the unit reports it with data instead of loosening it | Looser numbers weaken the "never delays the agent" promise; no numbers leaves passivity as a claim, which the product boundary does not allow |
| OQ-4 | **One preload name, 058's.** Spec 058 §5.5 uses `--import=@singleaxis/fabric/register`; revision 2 of this spec used `@singleaxis/fabric/wire/register`. The gate variable stays `FABRIC_WIRE_AUTOLOAD=1`, as in Python | **Adopt 058's name as the only preload**, and keep `@singleaxis/fabric/wire` for the explicit API. `055-t18` adds the two one-line clarifications to 058 listed in §13.1 | Two names would both have to be supported and documented forever |
| OQ-5 | **Release staging.** May `@singleaxis/fabric` be released with the undici-only claim after `055-t17` (global `fetch`, external qualified undici, the official `openai` and `@anthropic-ai/sdk` clients; worker threads declared uncaptured; core HTTP and libraries built on it declared uncaptured), before `055-t19`–`055-t22` land? | **Yes.** This is the earliest point a Node agent gets a verified, replayable record, and every limit is declared in the manifest and in `fabric plan`. The release workflow refuses any earlier tarball that exports the preload | Waiting for TS-1H delays Node capture by five units for clients that the first claim does not need |
| OQ-6 | **Python and Node processes sharing one spool directory.** The frame, lock and ledger formats are identical and cross-read tests run from `055-t7`; the full mixed-language chaos suite runs in `055-t17` | **Supported from the `055-t17` claim** (not before). `fabric run` may then give a Node agent and its Python children the same spool directory, as it does for Python parents and children | Separate spool directories per language would need `fabric init`/`run` to manage two directories and two drainers |
| OQ-7 | **Where TS qualification lives (R16 not done).** The agent-matrix and chaos harnesses are still on unmerged branches | **A self-contained `qualification/node-wire/` tree**, reusing the sink and e2e helpers already on main. Whoever merges the old branches later may fold it in | Waiting for R16 blocks `055-t17` on work no unit in the program owns |
| OQ-8 | **No agent-framework rows in the qualification matrix.** Revision 2 named rows after agent frameworks; `AGENTS.md` and the build rules forbid tests or fixtures that depend on or are named after one | **Rows are transports and model clients only** (§9.3): global `fetch`, external undici, the two official provider clients, custom `fetch`, plain tool-loop and fan-out scripts, core HTTP. Framework-driven traffic is exercised by the field harness outside this repository, as a supplement | Keeping framework rows would put framework names and dependencies into the repository's tests |
| OQ-9 | **Order of the later units.** After the undici claim and the 058 switch: worker threads (`055-t19`), then the records bridge that 057 WP7-16 needs (`055-t20`), then core HTTP (`055-t21`, `055-t22`) | **Keep this order.** Worker threads close a declared gap for the clients already claimed; the records bridge unblocks 057's TypeScript unit; core HTTP serves clients that do not use `fetch` and is the largest remaining passivity risk | Moving the records bridge first lets `057-p1d` start one unit earlier at the cost of leaving worker-thread calls uncaptured longer; moving core HTTP first delays `057-p1d` by two units |
| OQ-10 | **One diagnostics catalogue for both SDKs.** Spec 058's catalogue (`contracts/diagnostics/v1/messages-v1.json`, built in #291) lists Python's messages, and Python's test requires every entry to be emitted by Python code. Node needs nine entries of its own (§4.7) | **Add the Node entries to the same catalogue** with an optional `sdk` list on each entry, so `fabric doctor`, the docs page and the status file use one id space for both languages. This is a small additive change to a 058 contract and to one Python test, made by `055-t1` | A separate TypeScript message table would give the same failure two ids and two texts, and `fabric doctor` would need a second lookup |
