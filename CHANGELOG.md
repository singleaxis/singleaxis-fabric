# Changelog

All notable changes to SingleAxis Fabric will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Groundwork for recording an agent's security context (spec 057 P0, part
one): the contracts for permissions, control decisions, hooks and extensions,
and the first record-only APIs. Fabric records decisions other systems made;
it never makes, applies, waits for or returns one.

### Added

- **`fabric.records.record_control`** records one decision an external
  control made (a guardrail, a policy service, a permission request and its
  answer, an approval, a rate limit, a budget): kind, phase, decision, the
  request it resolves, the step or action it gated, who decided, the policy
  and a proof reference, with optional checked/reason/approval content. Every
  control record carries `enforced_by_fabric=false` and
  `authentication=unverified_caller_report`. It returns a `ControlRef` with
  ids only, never raises, never waits, and records a combination outside the
  phase × decision matrix as `unknown` (never `allow`). A caller's clear
  control id is pseudonymised (`ctl-`), so a resolution recorded in another
  process or run with the same clear id joins its request.
  `Decision.record_control` does the same inside a decision.
- **`fabric.records.record_run_context`** records the run's declared
  execution mode, approval policy, permissions (their count on telemetry,
  the lists only as `run.permissions` content) and agent policy.
- **The records core** behind both: bounded serialisation that never runs
  application code, reported links, timing, update records, and handles that
  expose ids only. `fabric.records.context(...)` binds a default actor and
  the conversation and turn ids (`conv-`/`turn-` pseudonyms).
- **The reader** projects control steps (decision, phase, invariants, the
  `resolves` and `gates` links) and a request's resolution state
  (`resolved`, `pending`, `revoked`, or `conflict` when answers disagree)
  across every run of the input, and merges `record_run_context` into the
  run's fields. A forged or missing invariant is shown as a conflict;
  `pending` is never turned into a decision.
- **Contracts** (`contracts/coverage/v1` 1.4.0, `capture/v1` 1.9.0,
  `content/v2` 2.4.0, `deployment-policy/v1` 1.2.0): field rows, vocabularies
  and telemetry keys for grants, control decisions, hooks and extensions; the
  grant-snapshot and control-observation v2 schemas with digest,
  de-duplication and pseudonym vectors; the provider safety-signal map
  skeleton; an optional `security_context` section in the capture policy
  (control hosts, hook programs, watched paths, denial markers); the OTLP
  mapping-profile schema; activity 2.1.0 beside 2.0.0; and the `controls`
  chain in the reconstruction report. Spec 049 is amended as revision 6.6,
  and as revision 6.7 so the hook record carries the hook's name, phase,
  `modified` flag and hashes.
- **`fabric.records.record_grant`** records what the agent was given or
  allowed: a declared permission configuration (tool rules, MCP servers,
  filesystem and network scopes, sandbox, credential names and scopes,
  models, limits), or the tools offered to a model call Fabric does not see
  on the wire. Rules are kept verbatim and never interpreted; credential
  values are never read. Telemetry carries only the shape (basis, modes,
  counts) and a keyed `grt-` id; the document is `run.permissions` content
  in which every path, host, credential name and MCP server launch command
  or URL (`server_ref`, which can carry an API key or token) is replaced by
  a keyed pseudonym (`pth-`, `net-`, `crd-`, `src-`). The capture policy can
  keep a group clear (`security_context.grant.pseudonymise`, e.g.
  `sources: false`). Without an id key such a document is withheld, never
  stored in clear. `record_run_context(permissions=...)` now
  records the same kind of declared grant.
- **`fabric.records.control_check`** records the outcome of a permission
  check in your own code without changing it: decorate the check function
  (sync or `async`) or wrap the block that runs it. `True` is recorded as
  allow, `False` as deny, a raised `PermissionError` as deny, any other
  exception as error, anything else as unknown (never allow); a
  `decision_map` maps other literal return values. The check runs exactly
  once and its own return value or exception comes back unchanged. A
  recording failure is counted and never reaches the check, even under
  `FABRIC_RECORDS_STRICT=1`. Capture off, it is a direct call.
- **`record_control` additions**: a `control=` label for the check, the
  stage, engine, gated kind, the provider tool-call id it gated (stored only
  as a keyed `p-` id), latency, a bounded reason code, the control's mode,
  the grant in force and an error class. `phase` and `decision` now default
  to `observation` and `unknown`, so one line records an in-code check;
  existing calls are unchanged.
- **`fabric.records.record_extension`** records a skill, plugin, MCP server,
  hook bundle, subagent or tool pack that was present, with its signature
  status, scope, enabled state and contribution counts. Its source (URL,
  path, launch command) is stored only as a keyed `src-` id.
- **`Decision.record_hook` and `Decision.record_skill`** take new optional
  keywords: what the hook did (passed, modified, blocked, escalated,
  errored), its own event name, latency, the tool call it gated, the bundle
  that contributed it, a reason code and whether it ran as a separate
  program or a callback; and a skill's kind, source kind, signature status,
  scope, enabled state and contributions. With capture installed, each call
  also emits a hook or extension record; the existing span events are
  unchanged. `record_hook(outcome="modified")` now sets `modified=True`
  when you do not pass it; a `modified` value that contradicts the outcome
  is kept and counted as misuse.
- **`ControlObservation` v2**: new optional fields (kind, phase, resolves,
  the deciding actor, and the spec 057 stage, engine, mode, reason code and
  derivation); v1 documents and v1 construction keep working.
- **The reader shows the security context** (`python -m fabric.reconstruct`
  and its `actions` view, spec 057 §6). Each control decision and hook
  outcome is joined to the tool call it names: by the provider tool-call id,
  by a reported step, by its request across runs, or, when the agent passed
  neither, by position. One tool call still waiting for its result gives a
  certain link; several give an `ambiguous` link that lists every candidate
  instead of picking one. Grants, extension loads, control and hook rows
  appear in the view under the calls they name. The report gains a fifth
  chain, `controls`, and a `security_context` object with counts only
  (grants by basis, controls by kind, decision and how the decision was
  obtained, link methods, hooks, extensions) and the closed list of facts
  F1–F14, such as "deny gates a tool call and no effect is attributed to it"
  or "decision recorded with no matching call". A fact is co-occurrence, and
  the reader never says whether a call was right.
- **Helm: trust a private CA for an S3-compatible content store.**
  `content.s3.caSecret` names a Secret holding the store's CA bundle; the
  Node mounts it read-only and sets `AWS_CA_BUNDLE` for content-store
  requests only. Before, a store signed by a private CA (MinIO, Ceph,
  SeaweedFS) needed a `kubectl set env` that Helm reverted on the next
  upgrade.
- **Helm: egress for the host sensors.** With the NetworkPolicy on and a
  `host.ebpf` or `host.auditd` ingress group, the chart renders an egress
  policy for the shipped eBPF emitter and auditd sensor pods
  (`networkPolicy.hostSensorEgress`, on by default): their own group ports
  on the Node, cluster DNS and, for the emitter's pod selector, the API
  server. The namespace's deny-default policy blocked the shipped DaemonSet
  before, so it delivered nothing. The API server's addresses are read at
  install; the install notes say how to set them for `helm template` or
  GitOps renders.
- **`make verify-prod-groups`**, and `make verify-prod` detects ingress
  groups from the env file: it probes the agent group under
  `FABRIC_AGENT_SOURCE_ID` and checks that each host group's port refuses an
  unauthenticated export. Before, the documented ingress-group setup always
  failed verification with "ports not published ... (make up-prod)".
- **`host-bindings.py --emitter-image <repository>@sha256:<digest>`** writes
  `host-emitter-daemonset.yaml` next to the per-node files, with the
  tenant, namespace and image digest filled in, ready to apply. The shipped
  manifest stays a template (zero digest, empty tenant) and its header now
  gives the exact commands, including the id-key Secret's key `id_key`.
- **Boundary tests for the security-context records (spec 057 B1–B9).**
  Tests now check that no records API returns a decision or waits, that the
  `control_check` wrapper hands back the check's own result and exception,
  that a failing, stalled or full recorder never reaches the agent, that
  both invariants are on every control record, that the reader can print no
  word that judges a call, and that no new module depends on or is named
  after an agent framework, agent SDK or guardrail library. Another test
  checks that importing, installing or autoloading Fabric leaves an
  application's own functions exactly as they were: no import hook, no trace
  or profile function, no wrapping by name.
- **Acceptance runs for P0 (SC-0 and SC-CP).** A plain tool loop on a
  fixture model is captured for real and read back. SC-0 reports a grant
  and a change, an approval, a policy deny, a blocked and a failed hook, and
  an extension, and must match a golden report and view. SC-CP checks an
  in-code permission check three ways against the harness's own ledger:
  unchanged (no decision is recorded, only calls, results and effects),
  decorated with `control_check` (one row per check, linked to its call), and
  passing the tool-call id. Tool results, process output and exit codes are
  the same with capture off and on, also when the recorder fails.
- **`AGENTS.md` scope wording for security-context recording** (spec 057
  section 11, approved as OD-20), with a test that the file differs from its
  previous text by exactly that wording.
- **Release checks:** the wheel and sdist qualifier now refuses any data file
  inside the package and any shipped OTLP mapping profile or filled
  classification list (control hosts, hook programs, watched paths, denial
  markers). A repository test checks the same for charts, Node build files,
  images and the published contract families.

### Changed

- **`ControlObservation.to_dict()` emits v2**
  (`fabric.external-control-observation/v2`); the invariant
  `enforcement_performed_by_fabric` is now spelled `enforced_by_fabric`, and
  `requires_review` is recorded as `escalate`. `from_dict` reads both.
- **Behaviour change: `control.checked` content is off by default.** The
  local default no longer retains what a control checked (usually the prompt
  or output it flagged). Name the role in the capture policy to keep it.
- **System and developer instructions in production**
  (`model.request.instructions`) are retained only when the capture policy
  names the role. A production policy already omits every role it does not
  name, so a deployment that relied on it names it in its policy.
- **Reports: a fifth chain.** A run that has an effect channel, a host
  sensor or any security record now carries `chains.controls` and
  `security_context`. With no security record they are `not_observed` and
  all zero, and the rest of the report is unchanged. A `partial` controls
  chain (a decision naming a call that is not in the run, a request never
  answered, an ambiguous link, a missing invariant) makes the run `partial`
  and the reader's exit code `1`. A tool call that a deny gates and that has
  no effect is counted as `effects_not_observed.control_denied` instead of
  `none_in_window`.
- **Behaviour change (TypeScript SDK): plain HTTP to a non-loopback OTLP
  endpoint now turns capture off**, the rule the Python SDK already applies.
  When `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT`
  is `http://` to anything other than `localhost`, `127.0.0.1` or `[::1]`
  (for example `http://fabric-node:4318`), a new `Fabric` client produces no
  spans and no content objects instead of sending the record and the ingress
  token unencrypted. Your agent runs unchanged and nothing is thrown.
  `fabric.captureStatus()` and the new `captureStatus()` say why and how to
  fix it (use `https://`, or reach the Node over loopback); set
  `FABRIC_WIRE_DIAGNOSTICS=stderr` to have it printed once on stderr. The
  rule for both SDKs is now on one page (privacy and security, "Span
  delivery rule").
- **Deprecated:** the v1 policy, tool-authorization and escalation verdict
  shapes (connect `policy_verdict`, `authorization_verdict`, `escalation`;
  activity v1 `fabric.policy.evaluation`, `fabric.tool.authorization`,
  `fabric.escalation`) follow the guardrail path and are replaced in v2 by the
  control decision record (`docs/api-stability.md`).
- **`python -m fabric.reconstruct` prints one line per run by default**,
  for example `r-…: partial (2 exchanges, 3 gaps: seal_mismatch,
  sequence_gap, unmatched_tool_call)`, as the README shows. It used to
  print the full JSON report (about 320 lines). `--json` prints the report
  on stdout, and `--out FILE` still writes it to a file. Exit codes are
  unchanged. A script that read the JSON from stdout adds `--json`.
- **Commands that run before the agent's first model call no longer make
  the run `partial`** (spec 056 revision 11). OpenAI-style client libraries
  run `uname -p` to describe the platform before their first request, so
  with the exec hook every run read `partial(unattributed_effect)`. Such a
  command is now a **startup effect**: listed and counted in
  `attribution.startup_effects` and in the actions view, never attributed
  to a model call, and not a reason for `partial`. A command after the first
  model call with no open tool call is still unattributed, and so is one
  behind a lost sequence position, which might have been a model call.
- **Helm: no profile creates the release namespace.** `shadow-dev` and
  `shadow-production` set `namespace.create: false`. With `true`, the
  documented installs failed: Helm stores the release in that namespace
  before creating anything, so it must exist, and then the chart's
  Namespace object cannot be adopted (`namespaces "fabric-system" already
  exists`). Install with `--create-namespace`, or create the namespace and
  its Secrets first (production). A pipeline that applies rendered
  manifests itself (`helm template`, GitOps) and took the namespace from
  the render passes `--set namespace.create=true` before upgrading, or it
  may prune the namespace.

### Fixed

- **`python -m fabric.wire status` gives the reason and the fix when capture
  is not installed.** It used to print only the error's class name
  (`ValueError`). Now it says, for example, that plaintext `http://` to a
  host that is not loopback (such as a Compose service name) is refused,
  and to use `https://` with a CA or a loopback address. The same text
  appears with `FABRIC_WIRE_DIAGNOSTICS=stderr`. URLs keep only their
  scheme, host and port, key-like values are hidden, and a message from
  another library is reported by its class name only, so no secret is
  printed. An invalid `FABRIC_WIRE_ENDPOINTS` is reported by line and column,
  never by its text.
- **`status` warns when spans have nowhere to go.** With no OTLP endpoint,
  capture was on but every span was dropped, and `status` said
  `warnings: []`. It now reports `span_destination: none` and the warning
  `spans have no destination`, with the variable to set. The documented
  "record your own application" steps in the README now include a
  destination and, for a model host Fabric does not know,
  `FABRIC_WIRE_ENDPOINTS`.
- **A model call to a host no endpoint matches is no longer silent.** A
  `POST` to an OpenAI- or Anthropic-style API path on an unknown host is
  still sent unchanged and not recorded, but it is now counted
  (`stats().unmatched_model_calls`), listed in `handle.status()` as
  `unmatched_model_hosts` with the `FABRIC_WIRE_ENDPOINTS` value that would
  record it, and logged once per host on Fabric's diagnostics channel. It
  never prints into the agent's own output: the `fabric.wire` logger now has
  a `NullHandler`, so with Fabric installed in code and no logging configured,
  its diagnostics no longer reach stderr through Python's last-resort handler.
  An app that configures logging still receives them.
- **`status` says when the policy withholds content.** Content capture can
  be enabled while the capture policy masks roles (`redact`, for example on
  `terminal.argv`) that the autoload cannot transform, so their content is
  withheld and commands read `exec pid N`. `status` now lists those roles in
  `content_withheld_roles` with a warning and the fix.
- **The reader explains `no runs reconstructed`.** It now says what the
  inputs hold and what is missing: explicit-API spans with no capture
  record (as the TypeScript SDK sends), spans from a process where capture
  was not installed, capture records with no model call, or a `--run` that
  matches nothing.
- **The reader accepts a directory of OTLP/JSON exports.** A `--spans`
  directory now stands for its `*.otlp`, `*.json` and `*.jsonl` files (an
  OpenTelemetry Collector file exporter writes `.jsonl`), and the error for
  an empty directory names the forms it accepts.
- **`record_grant` is faster.** A declared grant spent about 60 µs on the
  calling thread, above the 50 µs budget for an active capture point. The
  canonical JSON used for the grant digest now runs in the standard
  library's C encoder whenever the result is guaranteed identical (no
  fractional numbers, safe integers, ASCII keys), and a document is no
  longer normalised twice or copied when nothing in it needs a pseudonym.
  Grant ids and stored documents are unchanged.
- **Every records call is faster on the calling thread.** CI runners measured
  `record_control` at 21–23 µs against its 20 µs budget (spec 051 §4.11).
  The attribute check every record runs now remembers its recent answers for
  short repeated values (capture point, kinds, source and run ids), the check
  loop no longer re-wraps plain values, and a record outside a run computes
  its fallback run id once per process epoch instead of once per record.
  What is recorded is unchanged.
- **Latency-budget tests no longer flake on shared CI runners.** Each budget
  test now measures in a fresh interpreter after a warm-up, in several
  batches, judges each batch against the machine speed measured between its
  own calls (so a runner busy with other work slows both alike), and takes
  the best batch; it measures again only while a budget is
  missed, at most three times. The budgets themselves are unchanged, and
  each test still runs a deliberately blocking case that must fail.
- **A record with a fractional number no longer breaks its segment's seal.**
  A `control_check` record always carries its measured latency as a
  fraction of a millisecond, and `record_control(latency_ms=...)` can too.
  The record digest refused fractional numbers, so the agent never sealed
  that segment and the reader reported the record as unverifiable. The
  digest now encodes a finite floating-point number as a tagged value, and
  the agent and the reader agree on it, also when an OTLP/JSON export writes
  a whole-number double without a fraction (`412` for 412.0) (spec 057 revision 3.4, spec 049
  revision 6.8).
- **The TypeScript SDK installs with current OpenTelemetry packages.** Its
  README installed 2 packages while its example imported 5, and the SDK
  accepted only `@opentelemetry/api` 1.9, so installing today's OTLP
  exporter failed with `ERESOLVE` (and forcing an older exporter crashed at
  import). The SDK now accepts `@opentelemetry/api` 1.9 and 1.10. The README
  gives one complete install line with versions that are tested together
  (OpenTelemetry JS 3.x), a second for projects on OpenTelemetry JS 2.x, and
  an example that runs as written. CI now runs those exact commands in an
  empty directory on every change, sends the example's spans to a local
  receiver, and checks them.
- **The TypeScript README says what the SDK records and what can be
  verified from it.** The verifier (`fabric.reconstruct`) does not read
  TypeScript records today and reports `no runs reconstructed` for them; the
  README, the SDK overview and the top-level README now say so plainly.
- TypeScript SDK tests: the local content-store tests now pass on macOS,
  where the default temp directory is a symlink. The SDK was already right:
  `LocalFilesystemContentStore` resolves its configured root to the real path
  once and issues every `file://` URI under that path, as the Python store
  does. The tests built URIs by hand from the unresolved temp path, so the
  strict containment check correctly rejected them. The tests now resolve
  their temp roots, and the parent-alias test checks that URIs use the real
  path and that a URI spelled through the alias is not owned. SDK behaviour
  is unchanged.
- **The eBPF emitter finds pods under any kubelet cgroup root.** Its pod
  selector looked only for `kubepods.slice` or `kubepods` at the top of the
  cgroup mount, so on kind (`kubelet.slice/kubelet-kubepods.slice`) and
  other `--cgroup-root` layouts it scoped no pod and said nothing. It now
  searches every kubelet hierarchy (systemd and cgroupfs drivers; cgroup v2,
  or the v2 hierarchy of a hybrid host), searches again while a matching
  pod has no cgroup, and reports `pod_selector_matched` and
  `pod_cgroups_found` on its health line, with a warning when they differ.
- **The eBPF emitter says why an export fails.** It logged only
  `error_type=*status.Error`, once a second. It now logs the gRPC code, the
  status message (sanitized: no credentials, bounded) and the likely fix,
  once per change and then every 30 s with a repeat count, in its own log.

## [0.12.1] - 2026-11-08

Fabric 0.12.1 is a patch release that fixes what the 0.12.0 real-agent
acceptance run found. The fix that matters most: with capture on, every
Python process an agent started (a tool's `python -c`, a pytest run)
printed Fabric's autoload warnings on its stderr, which is part of the tool
result the agent's model reads, so turning capture on changed 8 tool
results. A process's output is now identical with capture on and off. Read
the warnings with the new `python -m fabric.wire status`, or set
`FABRIC_WIRE_DIAGNOSTICS=stderr` to print them. Note the behaviour change:
the process the operator launches is quiet too, so warnings that used to
reach its stderr or its logging now appear only through those two routes
(or `status()` in process). The eBPF emitter now confirms a clock step
before declaring it, so a step that reverses at once no longer widens the
declared clock uncertainty, and the reconstruct reader applies each host
record's own clock uncertainty instead of the widest one its source
declared (spec 056 revision 10). The operations docs now give Collector
counters their `_total` names, and the production setup page explains the
queue-size warning on small hosts. There are no breaking changes.

### Added

- **`python -m fabric.wire status`.** Run with the agent's environment, it
  prints the configuration warnings the zero-code autoload would log, as one
  JSON line: wire and content capture, each hook's state (for example
  `remote.sandbox` `disabled(unsupported_provider)`) and a `warnings` list.
  It exits 1 when there is at least one warning. It installs nothing and
  never captures itself.
- **`FABRIC_WIRE_DIAGNOSTICS=stderr`** prints Fabric's diagnostics on stderr
  from every autoloaded process, for debugging.

### Fixed

- **Autoload warnings no longer change what an agent's tools print.** Every
  Python process an agent starts (a tool's `python -c`, a pytest run)
  inherits the autoload. Each one printed Fabric's configuration warnings on
  stderr, such as "remote.sandbox is disabled (unsupported_provider)" or
  "invalid hook configuration", and that stderr is part of the tool result
  the model reads. In the 0.12.0 acceptance run, turning capture on changed
  8 tool results. The autoload now gives the `fabric` logger its own handler
  and stops it propagating, so its warnings reach neither stderr nor the
  application's logging. A process's stdout and stderr are now the same with
  capture on and off. Capture and the records are unchanged. Read the
  warnings with `python -m fabric.wire status` (or `status()` in process),
  or set `FABRIC_WIRE_DIAGNOSTICS=stderr`.
- **Metric names in the operations docs.** `docs/operations/README.md`,
  `docs/operations/dr.md` and the Compose README named Collector counters
  without the `_total` suffix the Prometheus endpoint adds, for example
  `otelcol_exporter_send_failed_spans_total` and
  `fabriccontent_dropped_records_total`. The queue series and
  `fabric_delivery_loss_records_pending` are gauges and keep their names.
- **Queue sizing on small hosts.** `docs/production-setup.md` now explains
  preflight's worst-case queue warning (for example 80 GB on a laptop with
  58 GB free), which values to lower, and what each change costs.
- **The eBPF emitter confirms a clock step before declaring it.** The 0.12.0
  acceptance run logged a +65.536 ms step and its exact reversal 0.7 s
  later, which widened the source's declared clock uncertainty to 67.5 ms
  for the 60 s settle window. Each offset sample is now the tightest of four
  bracketed reads; a sample whose bracket is wider than 100 µs (the emitter
  was descheduled mid-read) is taken again. A change beyond slewing is
  re-sampled at once. When the re-sample is back at the old offset, the
  change is not followed, logged or widened, and is counted as
  `clock_rejected_samples=` on the health line. A confirmed step is still
  detected at the refresh that first sees it, and `EMIT_CLOCK_STEP_MIN` and
  `EMIT_CLOCK_SETTLE` work as before. A clock that is really set forward and
  back again is still two steps, since records stamped across either change
  may be off by its size.
- **The reconstruct reader applies each host record's own clock
  uncertainty.** Before, it applied the widest value a source's manifests
  declared to every event of that source, so one clock step widened every
  eBPF link in a long export (to 67.5 ms in the 0.12.0 acceptance run). Now
  each host record takes the value of the manifest in force for it: the
  manifest whose `after_source_sequence` precedes the record's sequence, up
  to the next manifest (spec 049 §2.4; spec 056 revision 10). The widest
  value is still used when that manifest cannot be known, for example when
  a manifest is missing from the export, and for the source's coverage
  checks. No existing rule fixture changed; the new fixture
  `edge-clock-per-manifest` covers a base, widened, base sequence.

## [0.12.0] - 2026-11-08

Fabric 0.12.0 has one breaking change: the TypeScript SDK
`@singleaxis/fabric` now requires Node.js 22.18 or later, because Node 20
reached end of life on 2026-04-30. Node 20 users should stay on 0.11.x or
upgrade Node; the SDK is tested on Node 22 and 24. The release also brings
the dependency backlog, including OpenTelemetry Collector v0.164 for the
Fabric Node with unchanged metric names (#250). The reconstruct reader no
longer attributes a previous container's processes to the next container's
run, and the eBPF emitter's widened clock uncertainty no longer ratchets
(#253). The TypeScript SDK builds with tsup 9 and vitest 5 (#256), lint
moves to ruff 0.17.3 (#257), and CI moves off the deprecated node20 Actions
runtime (#269).

### Changed (breaking)

- **The TypeScript SDK requires Node.js 22.18 or later.** Node 20 reached
  upstream end of life on 2026-04-30. `@singleaxis/fabric` now declares
  `engines.node` `>=22.18.0` (was `>=20.6.0`); 22.18 is the lowest Node 22
  release the SDK's build tools (tsup 9, vitest 5) support. Node 20 users
  should stay on 0.11.x or upgrade Node. CI tests the SDK on Node 22 and 24,
  and the release job builds and qualifies it on Node 22. The connector
  manifest records the `Node.js >=22.18` runtime.

### Changed

- **TypeScript SDK build tools on Node 22.** vitest 5.0.5 (was 4.1.12),
  tsup 9.0.0 (was 8.5.1) and the `esbuild` override 0.28.2 (was 0.28.1;
  tsup 9 requires `^0.28.2`). `@types/node` stays on 22.20.5, the newest
  22.x, to match the Node floor. TypeScript stays on 5.7.3: TypeScript 7
  typechecks the SDK, but typescript-eslint 8 rejects it and tsup's
  declaration bundler needs the compiler API that TypeScript 7 does not ship.
  The built JavaScript and source maps are byte-identical. The `.d.ts` files
  export the same 145 names, with the same type-only split; tsup 9 only
  formats them differently. No runtime dependencies were added.
  Dependabot holds `@opentelemetry/api` at 1.9.x (the published peer range
  is `<1.10`), `@opentelemetry/context-async-hooks` at 2.x (sdk-trace-node
  2.x pins it) and `@types/node` at 22.x. The holds are update-type rules,
  so they never block security updates.
- **Dependency batch.** Collector core v0.150.0 → v0.164.0 (stable modules
  v1.56.0 → v1.70.0), contrib extensions → v0.164.1 and OCB v0.164.0 across
  all seven Go modules, the OCB manifest, Dockerfile and CI; with it
  `go.uber.org/zap` 1.28.0, `go.opentelemetry.io/otel` 1.47.0,
  `klauspost/compress` 1.20.3 (GO-2026-6865), `google.golang.org/grpc`
  1.85.0 and `golang.org/x/sys` 0.49.0. The patched `bearertokenauth` keeps
  the same fail-closed `require_single_token` rules on v0.164.1. The
  production Compose configs now pin the Prometheus reader's
  `without_type_suffix`, `without_units` and `without_scope_info` to false:
  since v0.151 an explicit reader defaults them to true, which would have
  dropped `_total` from `fabric_delivery_*` and `otelcol_*` counters. Metric
  names are unchanged. Python:
  pydantic 2.14.2 (GHSA-qpmf-fgh3-ff25, GHSA-3r8g-cqwr-jr29), boto3
  1.43.123, and the dev group (mypy 2.4.1, pytest 9.2.0, cryptography
  50.0.2, openai 3.41.0, anthropic 2.3.0, jsonschema 4.26.0). TypeScript SDK
  development tools: eslint 10, typescript-eslint 8.72.1, prettier 3.9.10,
  `@opentelemetry/*` 2.12.0, and a package-wide `minimatch` 11.0.5 override
  (GHSA-g3hv-75wg-m249 via eslint 10); the published package is
  byte-identical.
  Actions: `github/codeql-action` v4.39.1, `azure/setup-helm` v5.0.1,
  `actions/setup-python` v7.1.0, `actions/setup-go` v7.0.0 and
  `osv-scanner-action` v2.7.0, whose scan now actually runs on every
  released lockfile. The local S3 test store `chrislusf/seaweedfs` is 4.50.
- **ruff 0.17.3** in the SDK dev group, both uv locks and the pre-commit
  hook (supersedes #255, with openai 3.42.0). ruff 0.17 widens its default
  rule set, so a new root `ruff.toml` governs files outside a package
  config (`scripts/`, `examples/`, `deploy/`): Python 3.11 target, the old
  E4/E7/E9/F checks kept, and BLE001, RUF100 and TRY004 disabled with a
  reason each. The SDK config also ignores the newly stable PLR0917, as it
  does PLR0913, and both keep Markdown out of the formatter, which 0.17
  would otherwise apply to the hand-laid-out docs code blocks. The
  remaining findings are fixed in code with no behaviour change, and the 17
  shebang scripts are now executable.
- **CI actions off the deprecated node20 runtime.** `actions/setup-node`
  v4.4.0 → v7.1.0, `actions/upload-artifact` v4.6.2 → v7.0.2 and
  `helm/kind-action` v1.10.0 → v1.15.2 now run on node24. No input changes
  were needed: no `package.json` declares `packageManager`, so setup-node's
  automatic caching stays off, and the npm publish job never relied on the
  `NODE_AUTH_TOKEN` placeholder v7 removed. The kind jobs keep kind v0.23.0
  and the `kindest/node:v1.30.0` image and now pin kubectl v1.30.0, since
  kind-action's default moved to v1.37. `pre-commit/action` v3.0.1 is still
  the latest release and still wraps `actions/cache@v4` on node20.
  Dependabot holds TypeScript at 5.x for the SDK (major updates only, so
  security updates still flow): typescript-eslint does not support
  TypeScript 7 yet, and tsup's declaration build needs the compiler API that
  TypeScript 7 does not ship. The top-level README now states the Node.js
  22.18 floor next to the npm install command.

### Fixed

- **One container's processes no longer show up in the next container's
  run (0.11.2 replay).** Back-to-back agent containers reuse a pid namespace
  number, and after a clock step the sensor declared 3 s of uncertainty, so
  each run's window reached 4 s into its neighbours'. The previous
  container's `git` grandchild, whose exec the sensor stamped 1 ms before its
  parent's, escaped the walk that removes another agent's descendants and
  was listed (and, since B3, shown as a row) as the next run's own
  unexplained activity. `fabric.reconstruct` now proves the agent's start
  tick (its known start, or the start of the init pid its certain anchors
  name) and treats any process that started earlier as another process:
  outside the run, listed at report level as `other_process` unless its own
  run lists it (trace `H4-earlier-process`). When nothing proves which agent
  a process belongs to and two runs both link it, neither gets it: each
  run's link is `ambiguous` with both runs as `candidates`, and its
  `corroboration` is `partial(ambiguous_attribution)`. Spec 056 revision 9;
  new rule fixture `edge-previous-container-descendant`, and no other
  fixture changes.
- **The emitter's widened clock uncertainty no longer ratchets.** After a
  detected `CLOCK_REALTIME` step the wider value stayed until the emitter
  restarted, and Docker Desktop's routine 8–10 ms VM resyncs counted as
  steps, so it only grew. An offset change below `EMIT_CLOCK_STEP_MIN`
  (default 20 ms, ten times the 2 ms base) is now followed but is not a
  step: no log line, no `clock_steps` count (it is counted as
  `clock_small_steps=`), nothing widened. After a real step the widened
  value holds for every record stamped up to the step's detection, and for
  later records until the offset has been stable for `EMIT_CLOCK_SETTLE`
  (default 60 s; a further step restarts the window); then the source
  declares the base again, staged only after every pending record, so the
  narrower manifest governs only records stamped after the step and the
  window. The step log line and counter are unchanged. The host-records
  library gains `Source.DeclareClockUncertainty`. The reconstruct reader
  still applies the widest value a source's manifests declare to all its
  events.

## [0.11.2] - 2026-11-07

Fabric 0.11.2 fixes what a real-agent acceptance run of 0.11.1 on DeepSeek
V4.1 Flash found, and ships the supply-chain and scanner hardening merged
since 0.11.1. The headline is a security fix: under `redact`, `masked_only`
and `tokenize`, a model response sent with `Content-Encoding: gzip` reached
the redaction service still compressed and was stored with its secrets while
labelled `redacted`. Redaction now runs over the decoded body, and a body
Fabric cannot decode is withheld. The eBPF emitter follows wall-clock steps,
the actions view shows every unexplained host exec (including `os.system`),
records from one process no longer get a cross-source clock margin, and an
unsupported remote-sandbox provider disables only that hook. Customers who
ran a redaction policy against a provider that compresses responses should
review the "Security" entry below.

### Security

- **Redaction now runs over the decoded body (0.11.1 acceptance B1, high).**
  Under `redact`, `masked_only`, `tokenize` and the review copy of
  `original_plus_masked`, the wire PROTECT stage handed content-encoded
  bytes (a gzip model response) to the redaction service unchanged and
  labelled the result `redacted`; the stored object kept every secret.
  PROTECT now undoes the `Content-Encoding` first (gzip, x-gzip, deflate,
  stacked codings; `br` and `zstd` when their module is present), bounded
  by `max_body_bytes`, and the transformed object records
  `content_encoding: identity`. A body Fabric cannot decode (unknown or
  unsupported coding, corrupt or truncated stream) is withheld as
  `not_captured(protection_failed)` and counted in the new
  `WireStats.protection_undecodable`; a decoded body over the bound is
  `not_captured(body_cap)`. Retained originals still store the wire bytes.
  The HTTP channel no longer records a request body sent with a
  `Content-Encoding` (as already for responses). The Fabric Node now
  refuses a `redacted` object whose `content_encoding` is neither
  `identity` nor `base64`, so a 0.11.1 agent cannot store a mislabelled
  object through a 0.11.2 Node. Spec 049 revision 6.5 records the rule.
  Customers who ran `redact`/`masked_only` against a provider that
  compresses responses should treat `model.exchange.response` objects
  with `content_encoding` other than `identity` as unredacted.
- **Patched dependencies.** Python: `mcp` 1.29.0 → 2.3.0 in the SDK lock and
  the optional `mcp` extra's floor raised to `mcp>=1.30,!=2.0.*,!=2.1.*`
  (GHSA-5h93-6whr-6q8j, GHSA-84m7-p3x7-pcfv, GHSA-rwrf-2pqf-9j8j,
  GHSA-w4fh-qvv9-3v23); OpenTelemetry 1.41.0 → 1.45.2 in the SDK and
  reference-agent locks (GHSA-xcq7-p3pf-p88h). The SDK's
  `opentelemetry-*>=1.41` floors are unchanged. Go:
  `go.opentelemetry.io/otel/sdk` v1.44.0 → v1.46.0 in the content exporter,
  envelope and no-redirect extension modules (GHSA-8wmf-6v46-5gfg). The
  built Collector already resolved v1.46.0; Collector core is unchanged.
  TypeScript SDK (development dependencies only): vitest 4.1.12, vite 8.3.6,
  source-map-js 1.2.2 and minimatch 11.0.5 under typescript-eslint.
- **Pinned supply chain.** Every GitHub Actions `uses:` is pinned to a full
  commit SHA with a `# vX.Y.Z` comment. `docker/login-action` v4.8.0,
  `actions/download-artifact` v8.0.2, `docker/setup-buildx-action` v4.4.1
  and `dorny/paths-filter` v4.0.3 are drop-in upgrades. CI and release jobs
  now install Python packages from `sdk/python/uv.lock` with
  `pip --require-hashes` (`scripts/ci/install-python-locked.sh`) and build
  with the locked hatchling. The license inventory runs a lockfile-pinned
  scanner (`scripts/license/s3-peer`) instead of `npx --yes`. The example
  redaction service's base image is pinned by digest. Dependabot now covers
  every live manifest (all Go modules, the TypeScript SDK, uv locks,
  Dockerfiles, Compose) with a 7-day cooldown for version updates.
  `scripts/tests/test_supply_chain_pins.py` keeps all of this from
  regressing.
- `deploy/kubernetes/host-bindings.py`: the Secret-name constant is renamed
  so the name is not mistaken for secret material (CodeQL
  `py/clear-text-logging-sensitive-data` false positive). Its output is
  unchanged.
- **Scanner backlog.** The byte resolver, native-witness store and governed
  store now walk store paths holding one directory descriptor at a time and
  close each one explicitly on every path, which CodeQL `py/file-not-closed`
  can see (the previous `ExitStack` already released them). Reads are
  unchanged. Dependabot groups the `github/codeql-action` sub-actions, which
  fail when their versions differ. `golang.org/x/net` v0.60.0 → v0.62.0
  (CVE-2026-78661, HTML parser denial of service) in the host emitter,
  host-records and no-redirect extension modules and the built Node; this
  also moves `x/sys` to v0.49.0, `x/text` to v0.43.0 and `x/crypto` to v0.58.0.

### Fixed

- **Host emitter wall clock follows a clock step (0.11.1 acceptance B2).**
  The eBPF emitter derived wall time from an offset fixed at start, so after
  a `CLOCK_REALTIME` step (Docker Desktop resyncing its VM clock, an NTP
  step) records were mis-stamped by the step (2.82 s in the acceptance run)
  while declaring 2 ms of uncertainty. The offset is now re-sampled with
  nanosecond precision before events are translated and every 250 ms; a
  change beyond 1 ms plus 500 ppm of elapsed time is a detected step,
  logged with its size, counted (`clock_steps=` on the health line), and in
  production mode the source stages a manifest declaring
  `clock.uncertainty_ns` = 2 ms + the largest step. The host-records library
  gains `Source.WidenClockUncertainty`. `fabric.sensor.boot_time_s` follows
  the step too.
- **`actions` shows unexplained host exec events as rows (B3).** Unexplained
  events no rule links (an `os.system` child, an exec while the exec hook is
  off) were only counted and id-listed. Each now has a timeline row with
  pid, parent pid and time, in the text and `--json` views. The run report
  is unchanged.
- **No clock margin inside one process (B4).** A tool-call window opened
  or closed by an exchange of the effect's own epoch is no longer widened by
  `FABRIC_CLOCK_UNCERTAINTY_MS` (default 1 s): the wire and exec records of
  one process share one clock. The margin still applies to a close on
  another epoch, the segment end and every host-event comparison. An effect
  that started after its call visibly closed no longer reads ambiguous
  (smoke1: `docker inspect` was `T1|T2`). Spec 056 revision 8; the
  `edge-clock-margin-boundary` rule fixture now expects `A4` (no window),
  and no other fixture changes.
- **An unsupported sandbox provider no longer disables every hook (B5).**
  `FABRIC_WIRE_REMOTE_SANDBOX=modal` (any provider other than `e2b`) was
  treated as malformed, so the exec and HTTP hooks were off too. The
  provider is now dropped with one warning; only `remote.sandbox` stays off,
  and `fabric.hooks` `status()` reports it as
  `disabled(unsupported_provider)`. Supported providers in the same list
  (`e2b,modal`) are enabled.

### Added

- `fabric.wire.install_from_env(transformations=...)` names the customer
  transformation of each masking role, so the masking recipe needs no
  private import (`fabric.wire._config` is no longer in any document).
- `deploy/compose`: `FABRIC_ENV_FILE` points the Makefile, Compose
  (`--env-file`), `preflight-prod.sh` and `verify-prod.sh` at an env file
  outside the checkout (default `.env`, as before). `make up-prod-groups`
  and `make up-prod` now print the Compose project and the ports actually
  configured (environment, then that env file, then the default) instead
  of fixed numbers.

### Documentation

- `docs/production-setup.md` (0.11.1 acceptance, section 5): the Node's env
  file lives with the key material (`$FABRIC_ENV_FILE`), never in the
  checkout; a new "Two stacks on one host" section (`COMPOSE_PROJECT_NAME`,
  ports, derived network and container names); the agent image's
  `singleaxis-fabric[otlp]` extra; the policy example no longer keeps
  arguments, output or HTTP bodies in clear, and says that zero-code
  `redact` withholds them (commands read `exec pid N`) and how to get masked
  ones (redaction service plus `install_from_env(transformations=...)`); a
  real "Agents that start containers" recipe (Docker socket,
  `--cgroup-parent` for agent-started containers and the emitter's sandbox
  root, what `docker exec` and `docker run --rm` link to, `--sandbox-peer`,
  `--in-process-tool`); Docker Desktop notes on the sandbox root, VM clock
  steps and the clock margin. `scripts/tests/test_production_setup_doc.py`
  checks the new commands.
- `examples/redaction-service/README.md` and `contracts/redaction/v1` show
  wire-capture roles (`model.exchange.request`) where the example used an
  explicit-API role, and the masking recipe in
  `docs/privacy-and-security.md` uses the public API.

### Known limitations

- A command run with `docker exec` inside an agent-started container is
  tied to that container's `docker run` effect (rule H5), not to the
  `docker exec` effect or the tool call that ran it; a `docker run --rm`
  prints no id and its events stay counted in `sandbox_events_unlinked`.
- `os.system`, `os.exec*`, `os.posix_spawn` and `pty` are still not hooked:
  their processes now appear as unexplained `actions` rows (pid, parent pid,
  time) but carry no command line, since host records never do.
- Remote sandboxes other than E2B (Modal, Daytona) remain invisible beyond
  the agent's connections to them.
- An undecodable body under a masking mode is reported with the existing
  `protection_failed` reason (counted separately in
  `WireStats.protection_undecodable`); a distinct `undecodable` reason would
  need a content-contract change across the SDK and the Node.

## [0.11.1] - 2026-11-06

Fabric 0.11.1 fixes what a user-acceptance run of 0.11.0 with a real agent
found. A process that made no model call now gets a run of its own in a
reconstruction instead of disappearing from it, the release images carry
an accurate description, the production Compose setup refuses a content
backend it cannot serve, and preflight passes on Docker Desktop. A new
[production setup](docs/production-setup.md) page gives one tested recipe
for an agent, a production Node and the eBPF emitter.

A fault-injection run then found that a destination answering 403 made the
Node drop data it had already acknowledged, with no gap in the record.
0.11.1 retries credential and availability failures without dropping
anything, and when a destination refuses the bytes themselves (400, 409,
413, 422) the Node writes a durable `destination_rejected` loss record
before giving up (capture contract 1.8.0). Re-run under a 503/403/slow
destination, a permanent 400, agent kills, a Node SIGKILL, partitions and
destination outages, every record was delivered or reported lost, with
none silently missing. The release also adds `python -m fabric.wire drain`
for spools with no agent running, retries transient store reads in the
verifier, and keeps Fabric's own warnings off the agent's stderr.

### Added

- **The release names every GHCR package it publishes.** Legacy images
  (`fabric-redteam-runner`, `fabric-presidio-sidecar`, ...) stayed on GHCR
  after their sources were removed, and nothing said which packages are
  current. `release-policy.json` now lists them in `ghcr_packages`
  (`fabric-otelcol`, `fabric-host-emitter`, `charts/fabric`), and the
  release qualification runs `scripts/release/check_ghcr_packages.py`
  before anything is published. It reads every workflow and fails on a push
  outside the list, a push it cannot name, a `packages: write` job that
  publishes nothing it recognizes, or a listed package that no workflow
  publishes. `docs/verify-release.md` lists what a release publishes;
  anything else on GHCR is stale.

### Changed

- **Contract: `fabric.run-reconstruction/v1` (spec 056 revision 6).**
  `chains.decisions` may be `not_observed` (without reasons) only for a run
  with no captured model call (no exchange); the validator refuses it for a
  run with one. A consumer that assumed every run has at least one exchange
  should expect runs that list only effects.
- **The `actions` view lists non-model HTTP requests.** Requests the
  `http.nonmodel` hook recorded appear as `http` rows marked `(recorded;
  not attributed)`, and the footer counts them, so a request a tool made
  never reads as missing.
- **`FABRIC_COMPOSE_EXTRA`** (`deploy/compose`): your own Compose override
  files, appended last by `make up-prod` and `make up-prod-groups`, so a
  site change such as trusting a private CA for the destination never edits
  a shipped file.

### Fixed

- **`python -m fabric.wire drain` delivers a spool's backlog with no agent
  running.** An agent delivers its backlog only while it runs, and it waits
  at most its 2 s exit budget at exit. In the reliability run, thousands of
  records waited on the spool volume after the last process exited, and a
  one-shot container with no later run on that volume would never have
  delivered them. The drainer reads the agent's own environment, builds the
  same spool sender, takes the spool lock once no live process holds it, and
  delivers exactly as an agent would. It installs no capture, even under
  `FABRIC_WIRE_AUTOLOAD=1`, which now skips the drainer process.
  `--until-empty` exits 0 when nothing deliverable is left, or 1 at
  `--timeout` with the records kept on disk. Without it, the drainer runs as
  a sidecar until SIGTERM. One JSON summary line goes to stdout.
  `docs/production-setup.md` ("One-shot agent containers") and
  `docs/wire-capture-deployment.md` ("Draining a spool with no agent
  running": one-shot step, Kubernetes native sidecar, preStop) show how to
  run it.

- **Fabric's exporter warnings no longer appear on the agent's stderr.**
  While the Node was down, the capture exporter's "Transient error
  ConnectionError encountered while exporting span batch, retrying" warnings
  reached the agent's root logger and, with no logging configured, Python's
  last-resort stderr handler. An agent's output therefore differed with
  capture on and off (107 lines in the reliability run). Records emitted
  inside a Fabric export, which the SDK already sanitized, now go only to the
  non-propagating `fabric.otel` logger. Opt in by adding a handler to it or
  by setting `FABRIC_OTEL_DIAGNOSTICS=stderr`. The host's own OpenTelemetry
  exporters log exactly as before. A live test runs an agent through a Node
  outage with capture on and off and compares its stderr byte for byte.

- **A destination 403 no longer drops data the Node had acknowledged.** The
  pinned upstream OTLP/HTTP exporter retries only 429, 502, 503 and 504.
  Every other status, including 401, 403, 404 and 500, was a permanent
  error, and the queue dropped the batch ("Exporting failed. Dropping
  data."). In the 0.11.1 reliability run, a 40-second 403 removed 30 whole
  agent runs, and nothing reported the gap. The Node's `noredirect` client
  middleware, which fabric-gate already requires on every OTLP/HTTP exporter,
  is now the destination response policy:
  - Credential, availability and configuration failures (401, 403, 404,
    405, 407, 408, 410, 5xx, any status not listed here) are retried with
    backoff and never dropped. A full queue back-pressures the agent spools.
  - A permanent rejection (400, 409, 413, 422) is released only after a
    `destination_rejected` loss record for each source position in the batch
    is fsynced to a loss outbox on the queue volume (`loss_outbox.directory`,
    set in every shipped Node config and in the Helm chart when persistence is
    on). The outbox delivers these records once the destination accepts again,
    and `fabric.reconstruct` reports the affected runs as `partial` with a
    `loss` gap, including an epoch whose every record was rejected. Without an
    outbox, or when a loss cannot be recorded, the batch is retried instead.
  - New metrics: `fabric_delivery_held_responses`,
    `fabric_delivery_rejected_batches`, `fabric_delivery_lost_positions`,
    `fabric_delivery_loss_records_pending` (also logged while above 0) and
    `fabric_delivery_loss_records_delivered`.
  - Capture contract 1.8.0 (additive) adds the loss reason
    `destination_rejected`. Only the Node writes it: fabricguard strips it
    from a source's loss record.
  - The content exporter already retried every S3 failure except
    PreconditionFailed; new tests pin that for AccessDenied, ExpiredToken,
    InvalidAccessKeyId, SignatureDoesNotMatch and NoSuchBucket.
  - New Compose e2e tests cover a 403 window (everything is delivered after
    recovery) and a permanent 400 (the run is reported lost).

- **The reader no longer reports stored S3 objects as missing after one
  failed read.** `python -m fabric.reconstruct` read each object once. In the
  reliability run, 30 objects that were in S3 came back
  `missing(read_error)` and the run read `partial(missing_object)`. botocore
  retries the GetObject call, but not a body that stops streaming. Reads now
  retry transient failures (throttling, 5xx, a reset connection, a timeout, a
  streaming error, including wrapped ones) up to 5 times with about 3 s of
  backoff in all. An absent object (`NoSuchKey`, 404) is still `missing`
  (`absent`). A reader the store refuses (AccessDenied, ExpiredToken,
  InvalidAccessKeyId, SignatureDoesNotMatch, a local permission error) is a
  setup error with exit 2 and fixed text, not a `missing_object` gap; before,
  an AccessDenied object read as `missing(read_error)`. Unit tests use a fake
  S3 client.

- **A container's agent process is no longer linked into the previous
  container's run (spec 056 revision 7).** When agent containers start back
  to back, the kernel reuses the pid namespace's number, so the next agent
  has the same `pid_ns` and `ns_pid` as the last one, and its first events
  fell inside the previous run's window widened by the clock margin. Rule
  H4 compared only those numbers, so the next agent's exec was also
  `part_of` the previous run (`process_anchor · tentative`; 4 of 16 runs in
  the 0.11.1 acceptance run). H4 now also checks the process's identity:
  an event whose start tick differs from the agent's known start, whose
  init-namespace pid is not the parent the run's certain anchors name, or
  that started after one of the agent's own children is another process,
  outside the run: neither linked nor listed as unexplained. On the
  acceptance export, no host event appears in more than one run. Three new
  rule fixtures pin the rule.
- **That other container's child processes leave the run too.** Its agent
  forked children inside the previous run's window. They don't carry the
  agent's pids, so the run listed them as unexplained: 7 execs (3 children,
  4 grandchildren) in each of 3 runs on the 0.11.1 acceptance export. H4
  now follows an other process's descendants along the recorded parent-pid
  chain (the H3 walk: same host, init-namespace pids, start ticks) and moves
  them out of the run with it (trace `H4-other-lineage`). They are then
  listed in `unattributed_host_events` with reason `other_process`. The
  walk starts only where identity proves the parent pid can't name the
  agent: its init pid differs from the one the anchors name, or it started
  after the agent. Time alone never moves an event out of a run. New rule
  fixture `edge-other-process-children`.
- **Captured host activity that belongs to no run is listed, not dropped.**
  A host event that no run linked, listed as unexplained or counted was
  silently missing from the report: an event outside every run's window
  (65 of 471 on the 0.11.1 acceptance export), and, after the H4 identity
  fix above, a later container's events with a run's agent pids (9). The
  report now has a top-level `unattributed_host_events` (count per reason
  `other_process`, `out_of_scope` or `no_run`, and the first 64 events), the
  `actions` view ends with a `session` footer of those counts, and
  `actions --json` lists every one. It is omitted with `--run` and bounds
  no run verdict. Capture contract 1.7.0 (additive); spec 056 §4.3 "Host
  events in no run".
- **A transcript manifest no longer shows a failed item as pending.** With
  `durability="inline"`, two inline workers can write two revisions of one
  manifest at once: decision close's (the item still pending, its object
  write past the 50 ms deadline) and the settlement's (the item failed or
  stored). If the older write landed last, the destination kept the stale
  `pending` revision, and `flush()` still reported nothing pending. The
  writer now orders writes per manifest and skips a revision older than
  the one already written. The flaky
  `test_runtime_manifests_validate_against_contract` was a separate test
  timing issue: an inline manifest write past the deadline finishes in the
  background, so the test now waits on `flush()` instead of `close()`.
  Both cases have deterministic tests.
- **Preflight warns when the test-only S3 store is enabled.**
  `preflight-prod.sh` now prints a warning on every run whose
  `FABRIC_COMPOSE_EXTRA` (environment or `.env`) names
  `docker-compose.content-s3-local-tls.yml`, saying it is a test-only store
  that must never hold real content. It is a warning, not a failure, so the
  [production setup](docs/production-setup.md) test recipe still runs.
- **A flaky SDK test.** `test_wire_spool.py::test_node_mode_delivers_content_then_span_and_empties_the_spool`
  read `spool_bytes` right after `flush()`. `flush()` returns once its
  records are delivered, but the spool releases a delivered record's bytes
  from its count only after the directory fsync that follows the unlink, so
  the count could briefly still include it. The test now waits for the count
  to reach zero. Delivery itself is unchanged.

- **Processes with no model call no longer vanish from a reconstruction
  (spec 056 revision 6).** A process recording with Fabric on whose effects
  were captured and delivered but which made no model call (a tool-worker
  process, or an agent killed before its first call) used to get no run,
  no gap and no verdict, and `--run source:<id>:<epoch>` reported "no runs
  reconstructed". Every such source epoch is now a run of its own: its
  effects are listed, none attributed to a decision (`effects:
  partial(unattributed_effect)`), its `decisions` chain is `not_observed`
  when its record verifies, and a process that ended without a final
  heartbeat (SIGKILL, crash) is `tail_unverified(no_final_heartbeat)`, with
  `decisions: unverified`. The `actions` view says so in words. Runs that
  made model calls are reported exactly as before. The contract change is
  listed under Changed below.
- **Release images carry an accurate description.** The published 0.11.0
  `fabric-otelcol` and `fabric-host-emitter` images were labelled with the
  GitHub repository's description and name, which advertised capabilities
  Fabric does not ship (evaluation, guardrails and similar). Only the
  title and description labels were wrong, not what the images contain.
  From 0.11.1 the release workflow sets `org.opencontainers.image.title` and
  `.description` from `scripts/release/release-policy.json`
  (`image_metadata`) on the image labels and on the manifest and index
  annotations, and `scripts/release/check_image_metadata.py` refuses any
  other value, or any label or annotation naming an evaluation, judge,
  guardrail, escalation, red-team or enforcement capability. The check runs
  in release qualification (Dockerfile labels), on the metadata-action
  output before the build, and on the pushed image before it is signed.
  Release qualification applies the same deny-list
  (`forbidden_capability_terms`) to the wheel, sdist and Helm package
  metadata. The host emitter's Dockerfile gains its own title and
  description labels.
- **A cleanly closed process no longer leaves
  `spool/.epochs/<epoch>.orphan`.** On a filesystem that does not enforce
  `flock` between two open files (a Docker Desktop bind mount from macOS),
  the agent's own drainer took its live epoch registration's lock in its
  periodic scan and declared that epoch an orphan; the writer then set
  `final` in the renamed file and could not remove it. The scan now never
  declares a registration its own process holds, a finished writer removes
  its file under either name, and `fabric.wire.install()` warns once when
  the spool's filesystem does not enforce locks.
- **A Node asked for content that it cannot store refuses to start.**
  `FABRIC_CONTENT_BACKEND=file` with ingress groups (`make up-prod-groups`,
  whose content path is S3 only) ran the Node telemetry-only without a word
  when preflight was bypassed. The Compose production overlay now passes
  `FABRIC_CONTENT_BACKEND` to the Node, and `fabric-gate` refuses a
  configuration with no content exporter of that backend.
- **Preflight passes on Docker Desktop.** `preflight-prod.sh` required each
  secret to be readable by group 65532, which needs `sudo` on macOS and does
  not apply there: Docker Desktop maps bind-mounted ownership to the
  container user. It now detects Docker Desktop (`docker info`) and checks
  that each secret is readable by you and closed to others;
  `FABRIC_BIND_MOUNT_OWNERSHIP=mapped|native` overrides the detection.
- **The agent-orchestration demo passes as shipped.** `build_journal.py`
  expected tool names in clear, but `run.sh` emitted them omitted (no id
  key), and fabricguard drops clear labels. `run.sh` now pins the demo's
  identity policy (pseudonymous, a fresh per-run demo id key, no clear
  labels) and the journal checks the tool spans by the `lbl-` labels that
  policy emits, naming them locally for the viewer; its honesty caveats are
  unchanged.

### Documentation

- **[Production setup](docs/production-setup.md)** (new). One
  copy-pasteable recipe for an agent, a production Node with ingress groups
  and S3 content, and the eBPF emitter in production mode (`docker run`
  flags, capabilities, mounts, `--pid=host`, `--cgroupns=host` and the
  cgroup scope on either Docker cgroup driver), the agent's
  `FABRIC_WIRE_HTTP_HOSTS` format and `network.*` policy roles, which
  addresses `--endpoint-peer` and `--known-peer` need and why, a
  destination behind a private CA, and what differs on Docker Desktop.
  Linked from the README, the docs index, the quickstart and host sensors.
  Corrected after a second acceptance run followed it literally: the
  Compose network is `fabric-node-production_fabric-node`; the reader
  commands are given per backend (`--content-key-file` only with
  `--store-root`) with the S3-compatible settings (`--s3-endpoint-url`,
  `--s3-path-style`, `--s3-region`, read-only reader credentials,
  `AWS_CA_BUNDLE`), and the page states that S3 objects are protected by
  the bucket's server-side encryption, not sealed by Fabric, so read access
  to the prefix is read access to retained content; certificates are
  signed with a random serial so `tls/` holds only what the Node mounts;
  and a test-only TLS S3 store
  (`deploy/compose/docker-compose.content-s3-local-tls.yml`, added through
  `FABRIC_COMPOSE_EXTRA`) lets the recipe run without a cloud bucket and
  pass preflight unchanged. `scripts/tests/test_production_setup_doc.py`
  checks the page's network, container and volume names, reader commands,
  `make` targets, `.env` variables and certificate commands against the
  shipped files.
- **AR-1 live's `systemd` requirement is the harness's, not the
  emitter's.** The harness creates systemd slice units; the emitter also
  scopes agents on the `cgroupfs` driver (`--cgroup-parent=/fabric-agents`),
  as the 0.11.0 acceptance run did. The harness message and the docs say
  so.

### Known limitations

- **Non-model HTTP is not attributed to tool calls.** Spec 056 defines
  effects as subprocesses and remote sandbox calls only: an `http.nonmodel`
  request is recorded and delivered, but no rule links it to the tool call
  that made it, and the agent's host `connect` events to that host are not
  joined to it (they stay `unexplained` unless the host's addresses are
  given with `--known-peer`). Joining them needs a peer-address rule that
  today's records cannot support (host records carry keyed peer addresses,
  the HTTP record a host name). See
  [action reconstruction](docs/action-reconstruction.md#what-is-not-covered-yet).
- **Spool disk latency.** No spool `fsync` runs on the monitored call's
  thread (now pinned by a test), but the capture worker's `fsync`s compete
  for the disk: on a slow-`fsync` mount shared with the agent's own files,
  the acceptance run measured 20–270 ms added per subprocess and 9–22 ms on
  an unobserved file write (2–10 ms per subprocess on a local disk). Put
  the spool on a local disk or named volume
  ([deployment](docs/deployment.md#what-the-agent-needs), "Spool disk").
- **Spools on filesystems without `flock`.** Several processes sharing a
  spool on a filesystem that does not enforce locks (a Docker Desktop bind
  mount) can still declare each other's live epochs orphaned; use a named
  volume.

- **Model-call latency while a backlog replays.** In the 0.11.1 reliability
  run, a few model calls stalled for 0.5 to 3.5 s (4 of 2,400 calls in S3 and
  11 of 3,280 in S4, worst 3.53 s), all in the process that was replaying a
  backlog. The median did not change. No path on the model-call thread
  waits on the replay. The call allocates a position and puts the exchange on
  a non-blocking queue. Spool I/O, decryption, span rebuilding and export run
  on the capture worker and spool sender threads, and neither holds a lock
  the call path needs during I/O. The stalls did not recur in the
  re-run on this branch, which had a stack watchdog that dumps every thread
  of a call over 400 ms:
  - S3 replay windows: p50 5.7 ms, p95 37 ms, max 170 ms, against 4.1, 34
    and 57 ms before the faults.
  - S4 replay windows: p50 3.1 ms, p95 27 ms, max 117 ms, against 5.1, 24
    and 67 ms.
  - Locally, a 4,000-record node-mode replay with every core saturated:
    p95 24 ms and max 109 ms, against 20 and 109 ms with capture off.

  The remaining explanation is CPU and GIL contention from the replay thread
  on a host whose CPU is already saturated. In the chaos run, Docker
  Desktop's few vCPUs also ran the Node, S3, the sink and the emitter. This
  is not fixed. Throttling replay would trade delivery time for latency, and
  nothing measured here justifies that.

- **Node delivery policy edges.** A destination that answers 2xx with an
  OTLP `partial_success` still loses the items it rejected (the upstream
  exporter logs the count; it does not say which items, so no loss record is
  written). Loss records are delivered with the exporter's most recent
  request headers (static headers and bearer tokens). Request-signing
  authentication leaves them pending, and the pending metric says so. Markers
  and heartbeats in a permanently rejected batch get no loss record of their
  own. The verifier still detects their absence as `tail_unverified`, an
  unclosed run or an unsealed segment.

## [0.11.0] - 2026-11-05

Fabric 0.11.0 takes agent action reconstruction (spec 056 milestone M2,
the production profile) from a local test Node to production. A host
sensor, the eBPF emitter or the auditd receiver, can now report to a
production-profile Node as an authenticated source of its own, through a
dedicated ingress group with its own token and listener. Its records carry
positions, heartbeats, a manifest, the process start time and the pid
namespace, so the verifier can tie a command the agent ran to the
operating system's exec event with certainty (rule H1), also when the agent
runs in a container or a Kubernetes pod. Containers the agent starts are
linked by the id the container runtime printed (rule H5), a new hook
records commands sent to an E2B remote sandbox, and another records
non-model HTTP calls to hosts you list. The AR-1 acceptance test passes in
CI against a production Node: replayed on macOS and Linux
(`production-replay`), live on Linux with the eBPF emitter in production
mode (`production-live`), and with the auditd sensor collector on a fixture
audit log (`production-auditd`). Every new hook and sensor mode is opt-in;
agents and Nodes that set none of the new options behave as in 0.10.
Fabric stays a passive recorder: hooks and sensors observe and never
approve, block, delay or change what the agent does.

### Added

- **Host-records library (Go, spec 056 M2, WP4-07a).** New module
  `components/otel-collector-fabric/hostrecords`, shared by both production
  sensors: label and v2 pseudonyms, the id key file reader
  (`ReadIDKeyFile`), peer address text, container and pod ids from cgroup
  names, and an AES-256-GCM encrypted staging area. Every host record and
  marker is sealed there with its positions and ids before it is first
  sent, and replayed after a restart with the same ids; heartbeats carry
  one upstream-loss span per reason (unknown loss stays unknown), and
  manifest and final markers close each epoch. The test-only
  `hostrecords-replay` command is built by no image or release.
- **eBPF emitter production mode (WP4-07c).** `EMIT_PRODUCTION=true` exports
  host records as OTLP/gRPC traces through the host-records library, with
  an encrypted spool. Events carry the group leader's start time, the
  namespace-local pid and parent pid and the pid-namespace inode. Scope is
  a set of cgroup roots: static agent and sandbox roots
  (`EMIT_AGENT_CGROUP_ROOTS`, `EMIT_SANDBOX_CGROUP_ROOTS`, at most 8 each)
  or, on Kubernetes, the pods of `EMIT_AGENT_POD_SELECTOR` on the emitter's
  node (at most 64; a root installed after its pod started is `scope_late`
  upstream loss). Sandbox-scope events carry the container or pod id read
  from the cgroup names. Ring-buffer and rate-limit drops are upstream
  loss; a batch the Node refuses is quarantined as `span_dropped`. New
  `EMIT_ENDPOINT_FILE` and `fabric-host-emitter print-source-id`.
  Production mode requires tenant, source and host labels and id and state
  key files, refuses `EMIT_CGROUP_PATH` and deduplication, and refuses
  `EMIT_INSECURE=true` to a non-loopback endpoint. Local mode is unchanged.
- **auditd receiver production mode (WP4-07b).** `mode: production` makes the
  audit receiver one host source inside a customer-deployed sensor
  collector (it never runs inside a Node), emitting host records and
  markers through the host-records library. The logfile cursor advances
  only after every staged batch is acknowledged; rotation gaps, truncation,
  netlink socket overflow, rate limiting and the kernel's lost counter are
  upstream loss. Local mode is unchanged.
- **Authenticated per-source host ingress groups (gate and fabricguard,
  WP4-08a, WP4-08b).** A production Node can serve several sources, each
  through a static ingress group with its own bearer token file,
  listener(s) and `fabricguard/<group>` instance, so a batch's source is
  fixed by the ingress it arrived on. `fabric-gate` checks spec 053 §6.1
  rules 1–10 and §6.2.6 rules 1–5 over the merged configuration: group
  names; 64 groups by default, 256 at most (`FABRIC_GATE_MAX_GROUPS`);
  credentials that differ byte for byte, at start and after every rotation;
  no cross-wired receivers, guards or content exporters; TLS unless
  loopback; host groups on a traces pipeline only; no audit receiver in a
  Node. A sensor-collector profile covers the auditd collector.
  fabricguard gains `source_kind` (`agent`, `host.auditd`, `host.ebpf`) and
  `host_digests`: a host instance admits only host records and its own
  source's markers that match its binding, removes any supplied
  authentication stamp, strips keys outside the host placement and stamps
  what it admits; an agent instance refuses any `fabric.sensor.*` key or
  sensor capture point. The legacy single binding is unchanged; mixing it
  with groups is refused.
- **Per-node bindings in the chart, Compose and Kubernetes (WP4-09).** Chart
  values `otel-collector.receiver.sourceBindings[]` render one group per
  source (token mounts, Service ports, NetworkPolicy peers) and the profile
  `profiles/shadow-production-host-ingress.yaml`; the chart packages no
  sensor workload. Compose: `docker-compose.host-ingress*.yml` (agent group,
  eBPF group on gRPC 4417, auditd group on OTLP/HTTP 4428),
  `docker-compose.sensor-auditd.yml`, `make up-prod-groups`,
  `make up-sensor-auditd`, `preflight-prod.sh --groups` and
  `qualify-sensor-auditd.sh`. Kubernetes: a production eBPF DaemonSet with
  per-node hostPath provisioning and source label `$(NODE_NAME)/ebpf`, an
  auditd sensor-collector example, and `deploy/kubernetes/host-bindings.py`,
  which generates one group per node.
- **Exec record for production and containers (Python, WP6-08).** The
  `exec.subprocess` hook adds `fabric.process.start_ns`, read on the calling
  thread right after the child starts, so a child that exits at once keeps
  it (Linux, `SC_CLK_TCK` 100 only); `fabric.process.pid_ns`; and
  `fabric.sandbox.created_id`, the pseudonym of the container or pod id
  printed by `docker`/`podman`/`nerdctl run -d` or `create`, or by
  `kubectl run`/`create`/`apply` with `-o jsonpath={.metadata.uid}` or
  `-o json`. Output is parsed on the capture worker; no id is recorded
  under `omit` or without an id key.
- **Non-model HTTP channel (Python, WP6-09a).** Opt-in capture point
  `http.nonmodel` on the records input for httpx requests to hosts you list
  (`fabric.hooks.install(http_hosts=…)` or `FABRIC_WIRE_HTTP_HOSTS`): exact
  canonical host match (never a substring), one attempt per redirect hop,
  responses in 256 KiB pieces, early close and cancellation as end records,
  no header recorded. A route table (`wire/_routes.py`) decides each
  request once; with no rule registered, model routing is unchanged.
- **E2B remote-sandbox hook (Python, WP6-09b, optional extra
  `hooks-sandbox-e2b`).** Capture point `remote.sandbox` records the
  `commands.run` and `run_code` calls of the pinned E2B SDK (`e2b` 2.62.x,
  `e2b-code-interpreter` 2.11.x; sync and async; a background run ends at
  its `wait`) as effects with their results. Turn it on with
  `install(remote_sandbox=("e2b",))` or `FABRIC_WIRE_REMOTE_SANDBOX=e2b`;
  `sandbox_hosts=` / `FABRIC_WIRE_SANDBOX_HOSTS` declares provider hosts.
  Other SDK versions are refused at install (`unsupported_version`).
  Callbacks are never wrapped or called, the hook never calls the provider,
  and API keys and environment values are never stored. Install with
  `pip install "singleaxis-fabric[hooks-sandbox-e2b]"`; the default wheel
  installs no provider SDK.
- **Production-profile reconstruction (WP6-12).** `python -m
  fabric.reconstruct actions --profile production` reads host records from
  the same Node export as the agent's (`--host-records` is optional), keeps
  each host source's records and markers out of the agent's sources,
  segments and seals, and verifies each host source by its positions,
  heartbeats (a tail without heartbeats is `source_gap`), upstream loss
  and the Node's authentication stamp (`unverified(source_unauthenticated)`
  without it). Rule H1 joins an effect to its exec event on the
  namespace-local pid, the parent pid and the start tick
  (`process_anchor · certain`), also for an agent in its own pid namespace
  and for children spawned from a pool thread; each host source is joined
  in its own pid-namespace mode. Rule H5 links a container's sandbox-scope
  events, on any host source, to the effect that printed its id
  (`sandbox_report · certain`); sandbox events no reported id names are
  counted in `sandbox_events_unlinked`. `remote.sandbox` effects are
  attributed to tool calls (A1), and connections to a declared sandbox
  provider while that hook is off are listed in `remote_sandbox_calls`
  (effects reason `remote_sandbox`). The action view gains sandbox rows.
  New options `--host-source`, `--host-pid-namespace`,
  `--agent-pid-namespace` and `--sandbox-peer`; `--host-coverage-declared`
  is refused for production records.
- **Contracts (WP6-11).** coverage/v1 1.3.0 and capture/v1 1.6.0: registry
  rows for the host-record keys (namespace pids, pid namespace, scope, pod
  id), upstream loss on heartbeats (with `scope_late`), the new
  `exec.subprocess` keys and the `http.nonmodel` keys; the `remote.sandbox`
  capture point; the `fabric.http.observation/v1` and
  `fabric.sandbox.observation/v1` evidence types; the `sandbox_report`
  inference method; vectors `peer-address-v1`, `sandbox-id-v1`,
  `id-key-file-v1` and the host-state envelope; host-record fixtures with
  the Node admission reference; ingress-group configuration goldens; the
  M2 rule fixtures and reference rules. The connect manifests of the eBPF
  emitter, the auditd connector and the Python SDK describe the production
  modes.
- **AR-1 production (spec 056 M2, WP6-10).** `run_ar1.py --profile
  production` runs the acceptance scenario against a production-profile
  Node, with step 8 (`docker run -d` under the sandboxes' slice, linked by
  the reported container id) and step 9 (an E2B `commands.run`).
  `--mode replay` (macOS and Linux) uses the native Node with static
  ingress groups (agent, eBPF and a quiet second node), TLS, a token per
  group, node-mode content and verified HTTPS delivery to an authenticated
  sink, and stages the host side through the host-records library with the
  test-only `hostrecords-replay` command; `--mode live` (Linux) uses the
  Compose production Node, the eBPF emitter in production mode and the
  agent in a container. Variants f (remote sandbox hook off), g (no
  reported container id) and h (swapped group credentials) are new. New CI
  jobs `production-replay`, `production-live` and `production-auditd` in
  `action-record.yml`; the release-boundary tests now check that the wheel
  installs no provider SDK, the chart has no privileged workload, nothing
  shipped builds `hostrecords-replay`, and no artifact gains an evaluation
  or enforcement component.

### Changed

- **Reconstruction rules.** H3 now follows a child that forks without exec
  (a subshell, a reaper, a double fork) from its first connect or file
  event, bounded and start-time checked like an exec child. Each tool call
  is judged by its own effect channel: with `exec.subprocess` off and
  `remote.sandbox` on, a call outside a sandbox-provider window is
  `channel_disabled`, not `none_in_window`.
- **Host-emitter image** is built from the `components/` context, so it
  links the host-records library; the replay command and tests never enter
  the image.

### Fixed

These were found before release, in the M2 review and in its first CI runs
on main.

- **eBPF emitter shutdown.** On SIGTERM, production mode staged only its
  in-memory batch, so up to 4096 queued events and whatever the BPF ring
  still held were dropped with no loss recorded, and the final marker
  sealed an epoch that verified complete. Shutdown now detaches the
  programs and stages the queue and the ring to the end before the final
  marker; if the ring cannot be drained within 5 s, the epoch first
  declares unknown upstream loss.
- **Hook latency.** On GitHub runners the subprocess hook's start overhead
  (P4-EXEC, 50 µs budget) and the HTTP hook's per-chunk overhead (P4-HTTP)
  exceeded their budgets. The exec hook now reads `/proc/<pid>/stat`
  through libc without releasing the GIL and mints ids from a per-thread
  pool of random bytes; the HTTP hook joins streamed response pieces on the
  capture worker instead of the caller's thread. The records are the same.
- **`host-bindings.py`** builds the lines it prints apart from the data that
  holds keyed source ids, so nothing derived from a token or the id key
  can reach standard output.
- **Host-records library** refuses a plaintext above 1 GiB before sealing,
  so the envelope length cannot overflow.
- **Tests and qualification.** The auditd rotation-gap test used the wrong
  log-numbering convention and was flaky under `-race`; the AR-1 production
  replay gave each event of one process its own start time, so on Linux a
  connect read as another process. Synthetic id-key-file test vectors are
  baselined in gitleaks.

### Known limitations

- **The host id is not bound to the ingress group yet.** A host group binds
  one source id and one token, but the `hst-` host id in a sensor's records
  is only format-checked, so a sensor holding one group's credentials can
  name another host.
- **bwrap's default pid-1 reaper breaks lineage.** No host sensor reports
  forks, so an exec whose parent only forked and produced no event of its
  own (bwrap `--unshare-pid` without `--as-pid-1`) is listed unexplained.
  Run bwrap with `--as-pid-1`, as AR-1 does.
- **The pod-selector scope needs cluster-wide pod read.**
  `EMIT_AGENT_POD_SELECTOR` uses a ClusterRole with `get`, `list` and
  `watch` on pods. RBAC cannot limit that to one node, so every node's
  emitter can read every pod object, inline environment values included.
  Use static cgroup roots or a dedicated node pool where that is not
  acceptable.
- Remote sandboxes other than E2B, and file, database, MCP and SSH hooks,
  are not built.

## [0.10.0] - 2026-11-04

Fabric 0.10.0 can show what an agent actually did in a run, not only what
it said to its model. Everything a process records (model calls and SDK
records) now goes into one ordered run record that the verifier can check
end to end. An opt-in subprocess hook records the commands the agent runs,
and `python -m fabric.reconstruct actions` links each command to the tool
call that caused it and, on a local-profile Node, to the process starts
and connections a host sensor saw. Every link says how sure it is, and
anything no tool call explains is listed. The AR-1 acceptance test passes
in CI, with a real eBPF sensor on Linux. Wire capture keeps its 0.9
behaviour for agents that use none of the new options, and Fabric stays a
passive recorder: the hook observes subprocesses and never approves,
blocks, delays or changes them.

### Added

- **Run record (spec 050 P1, Python SDK and verifier).** One shared
  allocator per process for wire exchanges and SDK records, the records
  input (`WireHandle.records`), random registered epochs, immutable
  segments with seals that the verifier recomputes from the store, `fr3/`
  resume tokens (`fabric.wire.resume_token()`, `resume_tokens(n)`,
  `end_run()`), new `fabric.wire.run()` arguments, a records-only install
  (`fabric.wire.install(patch_httpx=False, patch_aiohttp=False)`), capture
  manifests, and the `FABRIC_RUN_ID`, `FABRIC_RUN_RESUME_TOKEN`,
  `FABRIC_RUN_OPEN_DEADLINE_S`, `FABRIC_CLOCK_UNCERTAINTY_MS` and
  `FABRIC_RECORDS_MAX_OBJECT_BYTES` settings. `CallRecorder` and the
  byte-boundary adapters can write through the records input. The Fabric
  Node (fabricguard) admits the records class. `decision()` records
  (WP-15), Node validation before acknowledgement (WP-21) and P1-A are not
  built. See [the P1 run record](docs/run-record.md).
- **Step projection.** `python -m fabric.reconstruct` reads records,
  manifests and seals, orders segments into a run graph with run states,
  and writes `fabric.step-projection/v1` with `--projection FILE`. New
  options: `--coverage-profile`, `--evaluated-at`, `--clock-uncertainty`
  and `--max-clock-uncertainty`.
- **Subprocess hook (`exec.subprocess`, spec 053 §5.1).** Opt-in with
  `FABRIC_WIRE_EXEC=1` or `fabric.hooks.install(exec=True)` after a
  capturing `fabric.wire.install()`. It records each child started through
  `subprocess.Popen` (and `run`, `check_output`, `call`) or asyncio's
  `create_subprocess_exec`/`create_subprocess_shell`: arguments, working
  directory, environment variable names (never values), output, exit
  status, pid and parent pid, through the `terminal.*` content roles of the
  capture policy. `FABRIC_HOST_LABEL` names the host for the host join. The
  capture manifest records whether the channel was active or disabled.
- **Agent action view (spec 056 M1).** `python -m fabric.reconstruct
  actions` lists, per run, model calls and their tool calls, the effects
  linked to them (`output_match`, `sequence_bracket`, ambiguous candidates,
  unattributed effects) and host events, with a verdict for each of the
  `decisions`, `actions`, `effects` and `corroboration` chains; `--json`
  prints the same rows. The report command adds `chains`, `attribution`
  and `sensor_events` to each run.
- **Host-sensor linking (local profile).** `--host-records FILE` reads
  eBPF-emitter or auditd-receiver records exported by a local-profile
  Node and joins them to effects by pid and parent pid and through the
  process tree, with `--host-label`, `--host-source`,
  `--host-coverage-declared`, `--endpoint-peer`, `--known-peer`,
  `--agent-pid` and `--in-process-tool`. Host events no rule explains are
  listed. Local-profile host records carry no process start time, so these
  links are `tentative`. A shell that execs its command in place (`bash -c`,
  `dash` for the last command of a list) is read as one process (an exec
  chain, spec 056 §4.3), unless the hook saw that pid exit in between.
- **Contracts (drafts, additive).** capture/v1 1.3.0 (P1), 1.4.0 (wire
  enrichment) and 1.5.0 (spec 056 chains and attribution in the run
  reconstruction); coverage/v1 1.1.0 (P1) and 1.2.0 (spec 056 link methods,
  reason values and the `fabric.process.*` keys), with rule fixtures in
  `contracts/coverage/v1/fixtures/action-record/`.
- **AR-1 acceptance harness** (`qualification/action-record/`, workflow
  `action-record.yml`). The hermetic mode runs a real agent, the hook, a
  natively built Node and the verifier against recorded host-sensor
  events, plus the negative variants, on macOS and Linux. The live mode
  runs the same agent under the real eBPF emitter on Linux and passes in
  CI; the auditd fallback is not run live in CI.
- **`FABRIC_WIRE_SHUTDOWN_TIMEOUT_S`.** The exit budget (seconds, 0 to 300,
  default 2) can now be set from the environment, so a zero-code
  (autoload) process on a slow disk can give its last records time to
  reach the spool instead of declaring them a `shutdown` loss. A close
  still returns as soon as everything is delivered.

### Changed

- `python -m fabric.reconstruct` exits `1` for a run whose run state is
  `open` (a resumable run that has not ended); `0` still requires a
  complete run. Captures made before P1 carry no run state and are
  unaffected.
- The run verdict also follows the new chain verdicts (spec 056 §4.5): it
  is never `complete` while an observed chain is `partial`. A run whose
  captured response asks for a tool call that no later request answers is
  now `partial` (`actions: partial(tool_result_missing)`) where it was
  complete before. No API declares a call outstanding yet.
- **npm:** each stable release of `@singleaxis/fabric` is published to the
  `latest` dist-tag (it was `beta`, which needed a manual `npm dist-tag add`
  after every release); release candidates go to `next`. Install with
  `npm install @singleaxis/fabric`. The SDK's maturity is still beta.

### Fixed

- **Tests:** the forked-child epoch registration test failed intermittently
  (Python 3.12 on main). The surviving forked child legitimately becomes the
  spool's drainer once its parent is killed and declares the parent's epoch
  itself, so the test's own scan found nothing left. The test now asserts
  that the registration lock is free and that the epoch is declared exactly
  once; a new deterministic test covers the child declaring it.
- **AR-1:** the live run failed once with three of five model calls
  missing. The agent had made every call; a disk stall of about 2 s on the CI
  runner held the capture worker past the agent's default 2 s exit budget,
  and the run's tail became a declared `shutdown` loss. The AR-1 agent now
  runs with a 15 s exit budget (`FABRIC_WIRE_SHUTDOWN_TIMEOUT_S`).

### Known limits

- Action reconstruction is claimed for the local profile only (spec 056
  milestone M1); local-profile host anchors are `tentative`.
- No host sensor reports process exits, so a pid reused under the same
  parent pid within the H2 window by a process the hook did not start is
  read as one exec chain (`tentative`) on the local profile
  ([agent action reconstruction](docs/action-reconstruction.md)).
- Production host ingress, process start times on host records, container
  and remote sandboxes, and the other execution channels (file, database,
  non-model HTTP, MCP, SSH) are not built.

## [0.9.1] - 2026-11-04

Fabric 0.9.1 fixes the package pages on PyPI and npm and deprecates the
evaluation elements left in the v1 contracts. Capture, protection,
delivery and verification behave as in 0.9.0.

### Fixed

- **Packages:** the PyPI and npm package pages link to the documentation on
  GitHub; the relative links in the package READMEs did not resolve there.
  The PyPI Documentation URL points at the documentation index.
- **Tests:** the asyncio fan-out capture test flushes before its agent exits,
  so a slow runner no longer turns the bounded exit drain into a failure.

### Changed

- **Contracts:** activity v1 example data uses neutral values. The
  `interaction_tagged` golden carries `example:category` and `example:label`
  instead of attack-taxonomy tags, `content_ref_stamped` names the policy
  `stub-redactor:canary`, and the `hook` golden names `example-redactor`. The
  capture v1 and content v2 masking fixtures name the transformation
  `example-mask` instead of `acme-pii-mask`. The manifest digests are
  re-pinned; the redaction interface is unchanged. New Python and TypeScript
  SDK tests reproduce the re-valued `hook` and `interaction_tagged` goldens;
  the activity v1 `support` declarations are documented as historical.

### Deprecated

- **Contracts:** the evaluation, judge and guardrail-verdict elements left in
  the v1 contracts are deprecated in Fabric v0.9 and dropped at Fabric v1.0.
  Fabric records activity and does not evaluate it. Contract schemas are
  immutable, so v1 is not edited in place: every document that validates
  today still validates, and no field, event or enum value is removed.
  - `contracts/connect/v1` (published): the `guardrail_verdict` and
    `evaluation` values of the semantic-surface enum. No shipped connector
    manifest declares them. Fabric v1.0 removes them in a new connect
    contract version (v2).
  - `contracts/activity/v1` (unpublished, pinned historical contract; the
    release policy ships activity v2 only): the `fabric.guardrail` (including
    its PII `fabric.guardrail.entities` labels), `fabric.eval` and
    `fabric.judge.queued` events; the decision-span attributes
    `fabric.blocked`, `fabric.blocked.policies`, `fabric.eval_count`,
    `fabric.eval_rubrics`, `fabric.judge_queued_count` and
    `fabric.judge_rubrics`; and `fabric.escalation.rubric_id` and
    `fabric.escalation.triggering_score` on the decision span and the
    `fabric.escalation` event. Each carries JSON Schema `"deprecated": true`.
    Fabric v1.0 drops them by retiring activity v1.
  - The policy, tool-authorization and escalation verdict elements are not
    deprecated by this change; their status is an open owner decision.
  - Neither SDK emits any of these, so no runtime warning is added. See
    [API stability](docs/api-stability.md#deprecated-contract-elements).

## [0.9.0] - 2026-11-03

Fabric 0.9.0 narrows the repository and packages to the recorder and its
current direction. It removes the last evaluation and red-team leftovers,
including one public Python API, rewrites the README and documentation
around what Fabric records, and publishes the design specs for one run
record across every input (050) and agent action reconstruction (056).
Capture, protection, delivery and verification behave as in 0.8.0.

### Removed

- **Breaking (Python SDK):** the bundled MITRE ATLAS and OWASP LLM reference
  taxonomies (`fabric/taxonomies/*.json`), the `fabric.taxonomy` helper and
  its root exports (`Taxonomy`, `TaxonomyEntry`, `bundled_taxonomy_names`,
  `load_bundled_taxonomies`, `validate_tag`) are removed. Open-vocabulary
  `tags=` / `fabric.tags` capture is unchanged; validate tags against your
  own vocabulary if you need to. This is a documented pre-1.0 break under
  [API stability](docs/api-stability.md): the exports were never documented
  in `docs/`, so no deprecation period applies.
- Archived documentation (`docs/archive/`) is removed. Every page had a
  current replacement under `docs/`; the history stays in git.
- Archived specs 001 (product vision), 025 (product planes and packaging) and
  037 (enterprise deployment and control applicability) are removed. They
  described evaluation, judge, red-team, regulatory and platform scope outside
  the OSS recorder. Their numbers are retired, and the history stays in git.

### Changed

- **Local Compose trial stack renamed from "evaluation" to "local trial".**
  `docker-compose.s3-eval.yml` is now `docker-compose.s3-local.yml`; the make
  targets are `up-s3-local` / `down-s3-local` / `reset-s3-local` (the
  `-s3-eval` names remain as aliases); the overlay's services, volume and
  variables are `s3-local`, `s3-local-init`, `s3-local-data` and
  `FABRIC_S3_LOCAL_*` (rename `FABRIC_S3_EVAL_*` in your `.env`). The default
  tenant id is `local-trial`, the Compose project is `fabric-node-local`, so
  an existing local stack starts with fresh volumes. Production overlays are
  unchanged.
- The reference redaction service's sample rules
  (`examples/redaction-service/rules.example.json`) are now one neutral,
  illustrative marker rule (`CANARY-...` -> `[masked]`) instead of
  email/SSN/card/phone patterns. The transformation id `example-mask`
  version `1` is unchanged.
- `examples/governed-content/evaluate.py` is renamed to `verify.py` (function
  `verify_transcript()`); it reads and verifies a governed transcript.
- Spec 034 is retitled "Transcript export and governed-content qualification"
  (`specs/034-transcript-export-and-qualification.md`). The
  `fabric.transcript-export/v1` format is unchanged.

### Documentation

- The README, `docs/README.md`, `docs/limitations-and-roadmap.md` and the
  specs index name the current work: spec 056, agent action reconstruction.
  The specs index now lists specs 050–056, and spec statuses match the
  shipped code.

## [0.8.0] - 2026-11-02

Fabric 0.8.0 is the first stable release of the passive recorder for AI
agents: CAPTURE -> PROTECT -> DELIVER. It adds zero-code capture of model
calls at the LLM wire for Python (`fabric.wire`), protection of captured
content on the agent before it reaches disk, governed content delivery through
the Fabric Node to a customer-chosen directory or S3 store, and offline
verification of a run with `python -m fabric.reconstruct`. The explicit
(app-reported) line now defaults to privacy: caller identifiers are emitted as
keyed pseudonyms or omitted, metadata-only recording carries no payload
digests, and recording fails open instead of affecting the application.

This release also contains everything in 0.8.0-rc.1 and 0.8.0-rc.2 (below).
The documentation was rewritten to describe exactly this release
([docs/README.md](docs/README.md)); superseded pages moved to `docs/archive/`
and superseded specs to `specs/archive/`.

### Upgrading from 0.7.x

- Read **Breaking** below and the 0.8.0-rc.1 and 0.8.0-rc.2 sections.
- **Identifiers and labels.** The explicit line (`Fabric.decision()`,
  `record_*`, the MCP wrapper and the explicit recorders) runs in the
  `pseudonymous` identity mode by default: with `FABRIC_WIRE_ID_KEY` set,
  caller ids, provider ids and operator labels are emitted as keyed
  pseudonyms; without the key they are omitted. Host spans record only the
  exception class, and payload digests are emitted only for roles whose
  original is retained. To keep the 0.7.x output, set
  `FABRIC_IDENTITY_MODE=clear` on every agent (Python
  `FabricConfig(identity_mode="clear")`, TypeScript
  `new Fabric({ identityMode: "clear" })`) **and** run the Fabric Node's
  `fabricguard` with `identity_mode: clear` (Helm
  `otel-collector.fabric.guard.identityMode: clear`) so it keeps admitting
  the clear values. `FABRIC_WIRE_LABELS=clear` (Node `capture_labels: clear`)
  keeps only operator labels clear. In either clear setting you guarantee the
  values contain no personal data.
- **Framework capture.** The CrewAI adapter and Python auto-instrumentation
  (and the `openai`, `anthropic`, `bedrock`, `otel-langchain` and `cohere`
  extras) are removed. Use wire capture (`FABRIC_WIRE_AUTOLOAD=1` or
  `fabric.wire.install()`) and the explicit record APIs.
- **Concurrent decisions.** Overlapping use of one `Decision` no longer raises
  `ConcurrentDecisionUseError`; set `FABRIC_RECORDS_STRICT=1` in tests to get
  the error back.
- **MCP inventory.** `InstrumentedMCPSession.snapshot_inventory()` no longer
  calls the server; call `list_tools()`, `list_resources()` and
  `list_prompts()` through the proxy to record inventories.
- **Fabric Node configuration.** The Node image validates its configuration at
  start (`fabric-gate`), and the production profile needs a source binding
  (and, with content, a content key). Custom collector configurations and
  `.env` / Helm values must be updated as described below; the shipped
  Compose and Helm configurations comply.

### Breaking

- **Default identity output.** In the default `pseudonymous` identity mode
  (`FABRIC_IDENTITY_MODE` unset), caller data on the decision line is no
  longer exported in clear: ids, idempotency keys, document ids, provider and
  request ids, tool, step, workflow, prompt and skill names, tags and side
  effect targets are keyed pseudonyms with `FABRIC_WIRE_ID_KEY` and omitted
  without it. Free-text tool descriptions are recorded only in the clear
  mode. See **Changed** for the per-key mapping and the upgrade note above
  for the clear mode.
- **Exceptions on host spans.** `fabric.decision`, LLM and tool call spans and
  `fabric.execution` record only `exception.type`: no `exception.message`, no
  `exception.stacktrace` and no message in the status description (the
  TypeScript SDK already did this). The clear identity mode keeps them.
- **Payload digests.** `*_hash` keys that digest an original payload
  (`fabric.retrieval.query_hash` and `result_hashes`,
  `fabric.memory.content_hash`, `fabric.side_effect.request_hash` and
  `result_hash`, `fabric.interaction.payload_hash` and `metadata_hash`,
  `fabric.tool.arguments_hash` and `result_hash`) are emitted only when the
  content role retains the original (governed content capture, or in Python
  the memory and side-effect payloads written to a legacy `content_store`).
  Caller-supplied digests follow the same rule. Metadata-only recording
  therefore carries no payload digest: a digest of a low-entropy payload
  reveals it.
- **Removed framework capture.** The CrewAI adapter (`fabric.adapters.crewai`,
  `attach_callbacks`) is removed; `fabricguard` no longer allowlists
  `fabric.crewai.*` attributes, and `fabric.crewai.step` / `fabric.crewai.task`
  events normalize to `fabric.activity`; telemetry from older SDKs that
  still emits them loses those attributes. Python auto-instrumentation
  (`fabric.auto_instrument`, `Fabric.enable_auto_instrumentation`) and the
  `openai`, `anthropic`, `bedrock`, `otel-langchain` and `cohere` extras that
  pulled the upstream `opentelemetry-instrumentation-*` hooks are removed.
  `install_default_provider` is unchanged; the protected managed span export
  is documented in `docs/python-span-export-protection.md`.
- **Fabric Node production profile.** Node mode is the `production` profile
  (spec 049; this supersedes spec 048 §1). An agent in node mode records
  content only with a capture policy (`FABRIC_CAPTURE_POLICY`),
  `FABRIC_WIRE_ID_KEY` and `FABRIC_WIRE_SPOOL_KEY`; otherwise content stops
  and metadata continues, and every exchange span reports
  `fabric.wire.store_reason`. The TypeScript `ByteEvidenceRecorder` applies
  the same gate (`idKey` or `FABRIC_WIRE_ID_KEY`). The application never
  fails; Compose preflight, Compose itself and the Helm render fail until the
  Node is configured:
  - Compose `.env` needs `FABRIC_TENANT_ID` and `FABRIC_SOURCE_ID` (the
    agents' source id as it travels, `s-<32 hex>`), and with content
    `FABRIC_CONTENT_KEY_FILE` (a Compose secret).
  - Helm `shadow-production` pins `fabric.profile: production` and needs
    `receiver.workloadAuthentication.sourceId`, and with content
    `content.encryption.keySecret`.
  - The bound source id is the keyed pseudonym of the agent's id:
    `s-` + HMAC-SHA256(`FABRIC_WIRE_ID_KEY`, agent `FABRIC_SOURCE_ID`). A
    configured source id is pseudonymised even when it is already shaped
    `s-` + 32 hex.
- **`fabric-gate` at Node start.** The gate refuses a configuration unless:
  - every `otlphttp` / `otlp_http` exporter lists the `noredirect` client
    middleware (`middlewares: [{id: noredirect}]`), defined under
    `extensions` and enabled in `service.extensions`, so a 3xx is never
    followed;
  - every `traces` and `logs` pipeline runs `fabricguard` itself, followed
    only by `batch` / `memory_limiter` (a pipeline without processors, or one
    relying on a sibling pipeline's guard, is refused);
  - no `--feature-gates` flag is passed (a gate such as
    `confmap.enableMergeAppendOption` changes how `--config` sources merge);
  - receivers, protocols, `auth` / `tls` blocks, extensions, processors,
    pipelines, pipeline component lists and `service.extensions` are literal
    YAML (a whole-value `${env:...}` is refused; leaf fields may still use
    `${env:...}`);
  - a content receiver is at least as strict as the telemetry receivers: same
    authenticator, TLS with no older `min_version` when they serve TLS, and
    client certificates when they require mTLS;
  - in the production profile, one single-token bearer authenticator is shared
    by the OTLP and `otlp/content` receivers and no other receiver is
    configured.
- **Source authentication at the Node.** `fabricguard`'s
  `evidence_source_binding` covers every trace span. A span, resource or scope
  that names another source (`fabric.source_id`) or tenant
  (`fabric.tenant_id`) is a forgery signal and the whole batch is refused with
  `INVALID_ARGUMENT`; a span that names no source (such as an application
  span batched with capture records in global-tracer mode) is dropped on its
  own and counted. Admitted spans are stamped
  `fabric.source.authenticated=true`; an agent-supplied value is stripped.
- **Node identity validators.** Under `identity_mode: pseudonymous` (the
  default), `fabricguard` admits `fabric.session_id` only as `sess-<32 hex>`,
  `fabric.delegation.to_agent` only as `agt-<32 hex>`, and the decision-line
  keys only in the forms listed under **Changed**; clear values from older
  agents or third-party instrumentation under these keys are dropped.

### Added

- **Zero-code LLM wire capture for Python** (`fabric.wire`, spec 047). An
  in-process tee of `httpx`, `httpx2` and `aiohttp` records the exact request
  and response bytes of chat completions, responses, completions, embeddings
  and messages calls. It covers the official `openai` (>= 3 on httpx2,
  earlier on httpx) and `anthropic` (>= 1) SDKs, LiteLLM and DSPy (aiohttp
  by default; also the OpenAI SDK's `DefaultAioHttpClient`) and frameworks
  built on them. Enabled only by `FABRIC_WIRE_AUTOLOAD=1` with the autoload
  directory on `PYTHONPATH`, or by `fabric.wire.install()`;
  `FABRIC_WIRE_AIOHTTP=0` (`patch_aiohttp=False`) turns the aiohttp tee off.
  Each call emits one digest-only span with sequenced loss records and
  heartbeats; run scopes bracket exchanges with run markers.
  - A POST to a matched model endpoint through `requests` or `urllib3` is
    recorded as an `uninstrumented_client` loss (method and URL only are
    read), so its run is `partial`. `WireHandle.status()` reports
    `capture_points` and `uninstrumented_clients`;
    `WireStats.uninstrumented_calls` counts the calls.
  - `OTEL_SDK_DISABLED=true` disables capture with one warning and `status()`
    reports `capture: disabled` (`otel_sdk_disabled`).
  - The tracer provider is resolved at emit time: records are never sent
    through a Fabric-protected (metadata-only) route; without a private
    provider they are counted as `span_dropped` losses and `flush()` returns
    `False`.
  - The capture worker writes queued exchanges in batches (up to 64, one
    spool file and one `fsync` per batch); the capture queue is bounded by
    bytes (256 MiB) with a 16,384-entry cap.
    `scripts/qualification/bench_wire_capture_throughput.py` measures
    per-process throughput.
- **Durable agent spool** (spec 048). Captured calls are fsync'd to an
  AES-256-GCM encrypted spool (`FABRIC_WIRE_SPOOL_KEY`) and delivered at least
  once, with replay after a restart. A preallocated loss ledger (`.ledger`,
  260 KiB) keeps loss ranges and run markers when the volume fills (`ENOSPC`,
  `EDQUOT`, reason `disk_full`), and the next drainer exports them
  (`disk_full_drops`, `markers_held`, `ledger_recovered`). Local file mode
  (`FABRIC_WIRE_STORE=file://…`) spools by default at
  `<store>/.fabric-wire-spool/<tenant>` when an OTLP endpoint is set;
  `FABRIC_WIRE_SPOOL_DIR=off` restores direct export. The wire spool refuses
  a directory another spool owns.
- **Multiprocessing.** Forked workers close capture on normal exit, the
  draining process delivers every record pending at its close, and the parent
  records each forked worker's last allocated sequence so a lost worker is
  never reported complete. Pools ended with `close()` / `join()` deliver every
  call. On macOS a forked child answers `getproxies` / `proxy_bypass` from a
  snapshot taken at install instead of the system proxy lookup.
- **Content delivery through the Fabric Node** (spec 048). Agents deliver
  bodies to the Node's `fabriccontent` exporter, so only the Node writes to a
  directory store or an S3 / S3-compatible store (SSE required) and the agent
  holds no store credentials.
  - `fabriccontent` is driven by the `contracts/coverage/v1` content-roles-v1
    table (boundary, provenance, media type and cap per role;
    `max_body_bytes` default 32 MiB, at most 63 MiB). It accepts `redacted` /
    `tokenized`, descriptor-only `not_captured`, the privacy fields, split
    skeletons and parts, `masked_only`, `original_plus_masked` review copies
    and `protection_failed` withholding. It takes the same source binding as
    `fabricguard`, drops other sources (`source_unbound`) and writes the
    receiver-owned `source_authenticated: true` into every persisted
    descriptor.
  - The directory store writes objects and descriptors into hash-sharded
    subdirectories (`evidence/<h0h1>/<h2h3>/`) and still reads flat objects;
    upgrade `fabric.reconstruct` together with the Node.
  - Content upload requires verified HTTPS, or plain HTTP to a loopback host
    only.
  - The Compose content path is the opt-in `docker-compose.content.yml`
    (`FABRIC_CONTENT_BACKEND=s3`, or `file` with
    `FABRIC_CONTENT_REQUIRE_SSE=false`, mirroring Helm's
    `content.requireServerSideEncryption`); the Compose production overlay is
    otherwise telemetry only. The S3 evaluation overlay is
    `docker-compose.s3-eval.yml` (`make up-s3-eval`, SeaweedFS), replacing
    the MinIO overlay whose pinned image is no longer published.
- **Encryption at rest on the Node.** The `fabricenvelope` storage extension
  seals everything the persistent `fabric_content` queue holds (AES-256-GCM,
  Node-side customer key from a file; delivery semantics unchanged), and
  `fabriccontent` `file.encryption_key_file` seals every object and
  descriptor of the directory backend. Both are required in production; S3
  keeps mandatory SSE. The envelope format is pinned by
  `contracts/content/v2/fixtures/node-envelope-v1.json`.
- **Agent-side content protection before disk** (spec 049): seven privacy
  modes per content role, keyed pseudonyms (v2), encryption at rest for the
  agent spool, the production profile gate and typed extraction of large
  inline media. An extracted `model.exchange.part` under
  `original_plus_masked` gets a masked review copy, and a failed copy
  withholds the part too.
- **Customer-run redaction service** (`contracts/redaction/v1`). Fabric never
  runs customer redaction code in-process, in a child process or in a worker.
  `redact`, `masked_only` and the review copy of `original_plus_masked` are
  performed by a service the customer runs beside the application:
  `POST /v1/transform` with the raw bytes of one object and the
  `X-Fabric-Transformation`, `X-Fabric-Transformation-Version`, `X-Fabric-Role`
  and `X-Fabric-Mode` headers; `200` returns the masked bytes. `tokenize`,
  `omit`, `metadata_only` and `retain_original` need no service.
  - Configure `FABRIC_REDACTION_ENDPOINT` (or Python
    `redaction=RedactionService(...)`, TypeScript `redaction: { endpoint }`):
    only `unix:///absolute/path.sock`, `http://127.0.0.1:<port>` or
    `http://[::1]:<port>`; anything else raises at `install()` or
    construction. No proxy, no redirect (a `3xx` is a failure), no TLS on
    loopback. An optional bearer token is read once from
    `FABRIC_REDACTION_TOKEN_FILE` (a `0600` file owned by the process user)
    and never logged.
  - A transformation is only its identity: Python
    `Transformation(id, version)`,
    `BytePrivacyPolicy(mode, transformation_id, transformation_version)`,
    `ContentProtector(policy, transformations={role: Transformation(...)},
    redaction=...)`; TypeScript
    `ContentProtector(policy, { transformations: { role: { id, version } },
    redaction })`. Callables and module references raise at construction with
    a pointer to `docs/wire-capture-deployment.md#redaction-service`.
  - Calls run only on the recorder's worker (the capture worker thread in
    Python, the recorder's asynchronous drain in Node.js), over one connection
    pool per recorder that `close()` closes. Each call has a hard timeout
    (`RedactionService.timeout_s` / `timeoutMs`, default 5 s, at most 300 s)
    and at most two are in flight per recorder (`max_in_flight` /
    `maxInFlight`); above the bound a call is withheld at once and counted.
    Any failure (non-200 status, timeout, oversized answer, connection error,
    saturation) withholds the object as `not_captured(protection_failed)`,
    with no raw fallback and no error body or exception text kept. The
    redacted result is re-checked against `payload_max_bytes` before
    persistence. Counters: `redaction_stats()`, `WireStats.redaction_timeouts`,
    `redaction_saturated` and `redaction_failures`;
    `ContentProtector.needs_redaction_service` / `needsRedactionService`.
  - Stored masked objects of a deployment-policy role carry
    `transformation_id` and `transformation_version` in both SDKs.
  - `examples/redaction-service/` is a stdlib-only reference service (Unix
    socket or loopback HTTP, regex rules from JSON, Dockerfile, Compose and
    Kubernetes sidecar snippets). It is an example, not a release artifact.
- **Offline verification**: `python -m fabric.reconstruct` grades a run
  `complete_for_declared_scope`, `complete_for_observed_scopes`, `partial` or
  `unverified`. It validates exchange claims before marker classes and checks
  each content descriptor against the full content-v2 contract and the
  exchange identity. A response the transport did not finish (`closed_early`,
  `abandoned`, `error`) whose bytes do not prove their own end (a whole JSON
  document, or a stream ending at `[DONE]`, `message_stop`,
  `response.completed` / `incomplete` / `failed` or a provider `error`) is a
  `truncated` gap (`stream_closed_early` or `transport_incomplete`), so the
  run is `partial`. Source gaps list up to 16 segments per stretch and
  summarise longer stretches as one gap per reason (exact ranges stay in
  `sources[].missing_sequences`), and the report is streamed, so heavy loss
  does not exhaust memory.
- **Explicit capture APIs.** Python and TypeScript `ByteEvidenceRecorder`;
  Python `CallRecorder` and byte-boundary adapters; opt-in qualified-run
  mode (spec 049 §2.13). The Python capture reference build provides
  protected metadata export, the encrypted durable byte spool and
  journal-backed metadata replay; `DeploymentPolicy` validates and digests
  the capture configuration. Durable governed-content joins and fresh
  authorized reconstruction validate policy, identity, representation, digest
  and length.
- **Governed content `durability` modes.** Python `durability="inline"` runs
  the write on a small pool of daemon worker threads and the caller waits at
  most `ContentCaptureConfig.inline_deadline_ms` (default 50 ms); after that
  the item stays `pending` and the write settles in the background. A forked
  child gets fresh workers, and a slow or hung store never holds interpreter
  exit past `close()`'s bound. TypeScript `durability: "inline"` never runs
  the write on the caller's stack: the record call queues it and returns at
  once with the item `pending`, the write runs on the next event-loop turn,
  and `flush()` / `close()` wait for it. The queued write keeps the process
  alive until it has run, so a process that records and exits without
  `flush()` still delivers the object and the manifest its span references.
  A synchronous store still occupies the event loop while its write runs, so
  `inline` does not mean "durable before the call returns" in TypeScript:
  call `flush()` when you need that. TypeScript manifests that settle during
  `close()` keep a valid rollup.
- **Explicit-line identity** (spec 049 §2.9). With `FABRIC_WIRE_ID_KEY` set
  in the `pseudonymous` mode, descriptors, `CallRecorder` snapshots, journals
  and seals, `SyntheticCaptureSession` events and the call OTLP projection
  carry the run id as `r-`, the source id as `s-`, the agent id as `agt-`
  and any other caller id (operation, attempt, stream, parent call) as the
  keyed operator label `lbl-`. Only ids the recorder minted or emitted map to
  themselves, so parent joins hold. Provenance is carried by type, never
  inferred from shape: emitted ids are typed values (Python
  `fabric._sequence.EmittedId`, a `str` subclass; TypeScript `EmittedId`),
  and a plain string of any shape, or an emitted id that lost its type, is
  caller input and is pseudonymised. Continuity across processes comes from
  passing the same clear id (the keyed mapping is deterministic per key).
  New: `ByteEvidenceRecorder.emitted_source_id()` / `emittedSourceId()`,
  `emitted_run_id()` / `emittedRunId()` and `emitted_ids`. A `CallRecorder` /
  `SyntheticCaptureSession` source spool is keyed by the emitted run id (a
  spool keyed by the clear run id is refused); qualified-run expectations,
  independent feeds and attestations bind the emitted ids. In the production
  profile without `FABRIC_WIRE_ID_KEY`, the explicit line emits no
  caller-supplied id: a random per-process source id, a generated run id and
  generated ids for the rest. The verifier shows an `s-` source id read from
  a record as is.
- **Coexistence of the two capture lines.** Inside an explicit model call
  (`CallRecorder` or `ByteBoundaryAdapter` with `kind="model"`) the wire tee
  defers ("explicit wins") for exactly as long as the call; a response that
  outlives the call is wire-captured, and `fabric.bind_capture_context()`
  keeps the call's scope on thread-pool workers. A Fabric-protected global
  tracer provider never carries wire spans; `fabric-gate` and the Helm chart
  refuse the content path on a dedicated evidence ingress.
- **Fabric Node and deployment.** `fabric-gate`, Helm (`shadow-dev`,
  `shadow-production`) and Compose (local and production profiles) for the
  Node; the `profile: local|production` setting on `fabricguard` and
  `fabriccontent`; auditd (with logfile cursor and recovery) and eBPF host
  sensors (corroboration only, local profile only, not qualified for
  production).
- **Contracts.** capture/v1 1.2.0, content/v2 2.2.0, deployment-policy/v1
  1.1.0 (`masked_only`, `original_plus_masked`), the new
  `contracts/redaction/v1`, and the new loss reasons `uninstrumented_client`,
  `disk_full` and `missing_spool_key`.
- **Specification.** Spec 049 (draft): the four-layer capture coverage plan
  (context, structure, content, decisions and effects), building on the
  explicit evidence line (specs 035–046) and wire capture (specs 047/048).
  Record-only; no evaluation or enforcement.

### Changed

- **Decision-line passivity** (`Fabric.decision()` in both SDKs and the Python
  MCP wrapper, spec 049 §7.1, §7.2):
  - Concurrent use of one `Decision` no longer raises
    `ConcurrentDecisionUseError` into the application (it could even replace
    the application's own exception on `delegate()` exit). An overlapping
    mutating call is recorded without serialisation (its events are kept; the
    rolling counters may be off), counted in `Decision.concurrent_use_count` /
    `concurrentUseCount` and reported as `capture_health` status `partial`,
    with one class-only warning per process. `FABRIC_RECORDS_STRICT=1`
    restores the error, as a test mode only.
  - MCP `traced_call_tool` and `InstrumentedMCPSession.call_tool` never raise
    because of recording: a recording failure after `call_tool` returned no
    longer replaces the result, a failure before it no longer skips the call,
    and an exception from `call_tool` is re-raised as the same object.
    `InstrumentedMCPSession.call_tool` passes further arguments
    (`read_timeout_seconds`, `progress_callback` ...) to the wrapped session.
  - `InstrumentedMCPSession` makes no requests of its own. When the
    application calls `list_tools()`, `list_resources()` or `list_prompts()`
    through the proxy, the call is forwarded unchanged and its returned value
    is recorded as the `fabric.mcp.inventory` event. **Deprecated:**
    `snapshot_inventory()` is now a no-op that records nothing and returns the
    last inventory recorded from an observed listing, or `None` (return type
    `MCPInventory | None`), with a `DeprecationWarning`. It will be removed in
    a later minor release.
  - Recording fails open. A tracer, span or span processor that raises no
    longer escapes a reporting API (`record_*`, `remember`, `checkpoint`,
    `set_attribute` ...) and never replaces the application's own exception
    on exit from a decision, `delegate`, LLM call, tool call or execution
    block: that exception object always propagates unchanged. Caught failures
    are counted and make `capture_health` `partial`. A delegation whose
    carrier injection fails proceeds with an empty carrier. Argument
    validation errors are unchanged.
  - Recording never waits on storage. Python legacy `content_store=` writes go
    to a bounded background queue (`Fabric(content_store_queue_items=1024)`);
    a full queue drops the write and counts it (`Fabric.content_store_stats()`),
    and `flush_content()` / `close()` wait for the queue. The event's
    `fabric.content.ref` is the store's deterministic `ref_for()` of the
    content digest, stamped only when the write was accepted; a custom store
    without `ref_for` gets no ref.
  - Diagnostics are class-only and never raise: Fabric's logs carry an
    exception's class name, never its message or traceback, and no id, key or
    path; a log handler that raises drops the diagnostic instead of reaching
    the application (this also covers the MCP wrapper).
- **Decision-line privacy in the pseudonymous mode** (spec 049 §2.9, §4.2,
  §7.5, §7.6). With `FABRIC_WIRE_ID_KEY`; without it these values are omitted.
  Values returned to the application (records, `MCPInventory`) and
  propagation carriers are unchanged.
  - `gen_ai.memory.store.id` is `mst-` + 32 hex (pseudonym v2).
    `fabric.side_effect.idempotency_key`, `fabric.tool.idempotency_key` and
    each `fabric.retrieval.source_document_ids` entry are `lbl-` + 32 hex.
  - Operator labels are `lbl-` + 32 hex, or as given with
    `FABRIC_WIRE_LABELS=clear`: `fabric.checkpoint.step_name`, the tool names
    in `fabric.mcp.tools` (`lbl-<32 hex>:<12 hex>`), `fabric.tags`,
    `fabric.memory.tags`, side-effect `target_system` and `operation`,
    `fabric.side_effect_systems`, `gen_ai.workflow.name`,
    `gen_ai.prompt.name` / `version` and `fabric.skill.name` / `version`.
  - Tool names on tool spans (the span name, `gen_ai.tool.name`,
    `fabric.tool.name` and the duration metric) are operator labels; without
    a key the span is named `execute_tool` and carries no tool name.
  - Provider ids (`gen_ai.request.previous_response.id`,
    `gen_ai.response.id`, `gen_ai.tool.call.id`, `fabric.tool.call.id`,
    `fabric.side_effect.parent_tool_call_id`) are the keyed v2 `p-` form, the
    same function as the wire line's provider ids; `fabric.request_id` and, in
    Python, `gen_ai.data_source.id` (also in the retrieval span's name) are
    `lbl-`.
  - A caller-supplied `fabric.side_effect.side_effect_id` is `lbl-` (a minted
    uuid4 stays as is), in the event and in
    `fabric.replay.suppressed_side_effect_ids`.
  - A caller's `fabric.execution_id`, `fabric.workflow_id`,
    `fabric.decision_id`, `fabric.execution.attempt_id`,
    `fabric.execution.retry.previous_attempt_id`, `fabric.step.id`,
    `fabric.step.attempt_id`, `fabric.step.retry.previous_attempt_id`,
    `fabric.parent_decision_id`, `fabric.replay.execution_id` and
    `fabric.replay.decision_id` are `lbl-`. A decision or execution id the
    SDK minted (uuid4) is emitted as is; a parent decision id from a carrier
    is always treated as caller input. A workflow name that falls back to the
    workflow id is the mapped id. `gen_ai.agent.name` is the keyed v2 `agt-`
    form, also in the tool duration metric.
  - TypeScript: an exported `ToolCall` or `LlmCall` built outside a decision
    resolves the identity mode from the environment, as Python's do, and
    keeps a payload digest only in the clear mode.
- **Fabric Node (`fabricguard`) admission of decision-line keys** under
  `identity_mode: pseudonymous`: idempotency keys, document ids,
  `fabric.request_id` and `gen_ai.data_source.id` only as `lbl-` + 32 hex;
  provider ids only as `p-` + 32 hex (never the unkeyed 16-hex form);
  side-effect ids as uuid4 or `lbl-`; execution and decision ids (also in
  replay metadata) as uuid4 or `lbl-`; workflow, attempt, step and parent
  decision ids as `lbl-`; the agent name as `agt-`; the checkpoint step name,
  MCP tool entries, tool names, side-effect targets and operations, and
  workflow, prompt and skill names and versions as `lbl-` unless
  `capture_labels` or `identity_mode` is `clear`. The Node now admits the
  SDK's `mst-` `gen_ai.memory.store.id` and `lbl-` lists under `fabric.tags`
  and `fabric.memory.tags`, and categorises a tool span without a tool name
  as a tool call. A span, event or log record keeps its category when a clear
  value under one of these keys is dropped (a third-party tool span with a
  clear `gen_ai.tool.name` stays `fabric.tool_call`).
- **One source per production Node.** A production Node binds exactly one
  agent source (one tenant, one `fabric.source_id`, one ingress token).
  Agents with different source ids need one Node each; pods that should share
  a Node must run with the same `FABRIC_SOURCE_ID`.
- `fabricguard` recognises capture records by their marker keys only, so a
  second guard pass leaves governed LLM spans unchanged.
- Documented Python reference support and the narrower TypeScript capture
  subset, including target-specific production qualification gates.
- `examples/kind-quickstart/up.sh` installs `singleaxis-fabric[otlp]` and, for
  a real model run, the `anthropic` client the demo agent imports; the README
  and quickstart point at `examples/wire-capture`.

### Removed

- The CrewAI adapter, Python auto-instrumentation and the five
  instrumentation extras (see **Breaking**). The Python SDK connector
  manifest declares `framework_lifecycle` as `caller_reported`; the connector
  capability manifests in `contracts/connect/v1/manifests` are the
  machine-readable capability declaration.
- The release policy and wheel qualifier treat the removed modules as
  forbidden wheel/sdist members and the five removed extras as forbidden
  extras. The same applies to modules that existed only on the development
  branch and are not part of any release (`fabric.capture_capabilities`,
  `fabric.coverage_manifest`, `fabric.enterprise`,
  `fabric.enterprise_preflight`, `fabric.deployment_state`,
  `fabric.capture_identity`, `fabric.capture_readback`,
  `fabric.control_protocol`, `fabric.reference_receipts`,
  `fabric.distributed_closure`). Policy rollout, approval, readback and
  external control are outside the recorder; qualified-run mode verifies
  delivery v1 receipt sets and attestations offline.
- Legacy source trees that 0.8.0-rc release artifacts already excluded:
  `components/fabric-relay`, `langfuse-bootstrap`, `nemo-sidecar`,
  `presidio-sidecar`, `prompt-guard-sidecar`, `redteam-runner` and
  `update-agent`, and the Collector's `fabricpolicyprocessor`,
  `fabricredactprocessor` and `fabricsamplerprocessor`. The Node image no
  longer includes the `zpages` extension.
- The standalone example agent scripts under `examples/` (customer support,
  coding, data analysis, RAG, multi-agent supervisor, human-in-the-loop,
  guardrail-judge, content-governance and treasury demos) and the manual
  `examples/e2e-smoke` script; `examples/harness-smoke` and the `e2e.yml`
  fixture path cover the same check.
- Documentation that described removed scope (assurance findings, decision
  graph, compliance mappings, capture-control compatibility and enterprise
  journeys).
- Unused qualification tooling and historical records: laptop-stage rehearsal
  scripts and the local "GO" simulation, the composed-collector journey, the
  C8 network journey and capture-acceptance runner, and the historical
  `qualification/` records and `docs/cloud-qualification-2026-10-02.md`. Only
  the four `qualification/synthetic-slice/kind-production-*.yaml` files that
  `e2e-production-profile.yml` installs remain.

### Fixed

- `fabricguard` refuses a batch that repeats a `fabric.*` key or a binding key
  on any attribute map, so a duplicate key can no longer pose as the bound
  source.
- Confined Python local content adapter operations through no-follow
  directory descriptors, including replacements after initialization, and
  verified effective local directory permissions before persistence.
- Rejected TypeScript content-store symlink redirection and nonregular
  objects, using opened file descriptors for file-type decisions (a remaining
  ancestor-replacement race is documented).
- Bounded propagated context headers and rejected deeply nested malformed or
  oversized inbound context.
- Preserved truncated partial-output status, bounded terminal child lifetime
  after pipe closure, and removed raw exception and identifier values from
  SDK diagnostics.
- Required exact protected readback and source-bound release evidence;
  rejected incomplete artifact sets and cross-tenant nested descriptors.
- Corrected TypeScript transcript serialization against the published
  contract, handled partial local writes, and retained pending spool bytes
  when recovered-manifest reconciliation fails. An empty transcript is no
  longer published when no content observations exist; an empty string
  remains an explicit content observation.
- Aligned the draft evidence-event contract with closed governed-content
  bindings and observed call lifecycle records.
- Corrected Compose privacy and recovery checks and protocol TLS preflight,
  isolated Helm test pods from runtime selectors, and preserved explicit zero
  PodDisruptionBudget limits.
- Corrected native audit netlink framing, rule structure and constants,
  architecture filters, control response matching and bounded assembly loss
  reporting.
- Repaired the orchestration reconstruction root and synthetic audit
  provenance.
- Made TLS minimums explicit without reducing stronger platform defaults.
- Made missing-instrumentor and asynchronous permission tests deterministic
  without weakening their assertions.

### Security

- Bumped `github.com/cilium/ebpf` to v0.22.0 in the host emitter (integer
  overflow in `LoadCollectionSpecFromReader`).
- License enforcement now covers the host emitter, the entrypoint gate, the
  published optional dependencies and the patched Collector, requires the
  durable governed modules in released Python artifacts, and rejects
  malformed, restrictive, conflicting and missing license inventories; a
  missing tool fails the scan.
- The live qualification harness rejects S3 bucket names the run does not
  own.

### Known limitations

See also [docs/limitations-and-roadmap.md](docs/limitations-and-roadmap.md).

- No customer production deployment has been qualified. Local reference
  evidence does not qualify a customer deployment or establish universal
  performance claims. This release adds no client portal UI and no action
  enforcement.
- TypeScript wire capture is not built.
- Wire capture covers `httpx`, `httpx2` and `aiohttp`. Calls through
  `requests` and `urllib3` are not captured (they are reported as
  `uninstrumented_client` losses); `boto3`, gRPC and other clients are not
  captured or detected. Model endpoints other than chat completions,
  responses, completions, embeddings and messages are not captured.
- A `with Pool()` block (SIGTERM) can lose calls a worker had not yet
  written; the loss is accounted (never `complete`). Use
  `pool.close(); pool.join()`.
- Capture is GIL-bound under heavy CPU contention: with about 16 or more
  CPU-bound threads in one process it sheds load as `queue_full` losses
  (every loss is recorded and the run reported `partial`).
- A production Node binds exactly one agent source and does not accept host
  sensors; both are planned for a later release.
- The four-layer run structure, context, and decisions and effects of spec
  049 are not built beyond what is listed above.
- Python `process` and `spooled` governed-content durability: the background
  content worker is not restarted in a forked child. Writes from the child
  are reported pending or dropped, never as stored.
- Dedicated v2 prefixes for idempotency keys, document ids, request ids, data
  source ids and caller side-effect ids are planned for a later release; they
  use the generic keyed `lbl-` until then. The `fabricguard` rules for the
  older decision-line keys are hand-written until they move into the
  generated telemetry-key registry.
- Digests without a content role are emitted as given in every mode:
  caller-supplied `fabric.checkpoint.state_hash`, `fabric.replay.state_hash`,
  `fabric.replay.tool_result_hashes`, `fabric.hook.input_hash` /
  `output_hash`, `fabric.file.content_hash` and `fabric.skill.manifest_hash`;
  the SDK's `fabric.interaction.target_hash` and `fabric.file.path_hash`
  (unkeyed SHA-256 of the target or path); and the MCP `fabric.mcp.tools_hash`
  and per-tool definition digests. A digest of a low-entropy value reveals
  it: avoid putting personal data in these inputs.
- Retry reasons (`fabric.execution.retry.reason`, `fabric.step.retry.reason`),
  `fabric.skill.source`, hook names and LLM span names (`{operation}
  {model}`) are emitted as given.
- Governed content keeps its decision bindings (session, request, tool-call,
  decision, execution, workflow and step ids) as given in descriptors and
  manifests: the content store is the customer's destination for content,
  whose bodies carry the same ids.
- Cross-service lineage in the pseudonymous mode: a child's
  `fabric.parent_decision_id` is the `lbl-` form of the carrier's decision
  id, and an execution id passed on from a carrier is mapped as a caller id.
  When the parent's id was minted (emitted as is), joining the two needs the
  id key.
- The concurrent-use and fail-open counters (`capture_health`,
  `concurrent_use_count`) are local; no telemetry key reports them yet.
- On a pseudonymous Node, `fabricguard` does not restrict the values of the
  bare log envelope keys (`decision_id`, `request_id` and similar). No Fabric
  SDK emits them; a third-party log source that does is admitted as given.

## [0.8.0-rc.2] - 2026-08-31

### Added

- Added an isolated end-to-end shadow workload example that uses the public
  Python SDK to record a synthetic healthcare-scenario agent execution
  containing model, retrieval, tool, held side-effect, and checkpoint
  activity.
- Added retained CI evidence for causal reconstruction, metadata-only export,
  destination outage, persistent queue recovery, and Collector recreation.

### Changed

- Release artifacts now contain only the passive recorder product:
  `CAPTURE -> PROTECT -> DELIVER`. Legacy assurance, management, judge,
  red-team, runtime-control, and regulatory surfaces are excluded by
  artifact-content tests.
- The Collector allowlist and both SDK vocabularies now preserve compatible
  causal reconstruction fields while continuing to exclude raw content by
  default.

### Fixed

- Fixed persistent queue volume ownership and restart recovery in the
  production Helm posture.
- Fixed release qualification fail-safety, dependency/version drift, the
  `fabricctl` YAML runtime dependency, and high-severity vulnerabilities in
  the exact TypeScript and Collector-image release artifacts.

### Security

- The credential-free end-to-end example workflow shows that synthetic raw
  content does not reach the destination, reconstructable metadata retains
  its causal structure, and at-least-once delivery recovers after an outage.
  It makes no exactly-once or arbitrary-destination persistence claim.
  Separate chart tests show that the production recorder exposes no sampling
  control.
- Security qualification now scans the exact image and package bytes intended
  for publication and fails closed on high or critical findings.

## [0.8.0-rc.1] - 2026-08-31

### Added

- Added Activity Envelope v2, recorder configuration, privacy assertion,
  delivery receipt, and connector capability contracts as independently
  verifiable public interoperability artifacts.
- Added the recorder-only `fabricctl` surface for local initialization,
  validation, digesting, help, and version reporting.
- Added `shadow-dev` and fail-closed `shadow-production` Helm postures for the
  Collector-only Fabric Node.
- Added persistent at-least-once queueing, restart recovery, blocking overflow,
  direct-to-persistent-queue production handoff, indefinite transient retry,
  mTLS ingress, authenticated HTTPS egress, and explicit ingress/exporter
  NetworkPolicy peers.
- Added exact Python wheel/sdist, npm package, Helm package, Collector image,
  CLI binary, and public-contract release qualification.

### Changed

- Refocused Fabric OSS on the customer-controlled passive recorder pipeline:
  `CAPTURE -> PROTECT -> DELIVER`.
- Removed policy, guardrail, prompt-time PII, judge, red-team, assurance-tier,
  governance, and management implementations from recorder SDKs, binaries,
  charts, images, installer commands, and packaged contracts.
- Python now matches TypeScript's safer defaults by hashing generic interaction
  targets and file paths unless raw metadata is explicitly requested.
- Recorder CI and license gates now qualify only released recorder surfaces;
  legacy source cannot define release readiness.
- Documentation now separates export minimization from PII detection, passive
  recording from enforcement, and destination acceptance from durable
  persistence.

### Security

- Fabric Node uses a non-disableable exact metadata allowlist in the named
  production profile and removes raw bodies, caller-controlled names, native
  text channels, sensitive keys, structured escape hatches, oversized values,
  and invalid hash-labelled values before export.
- Production rejects custom allowlist extensions, plaintext or unauthenticated
  transport, missing ingress/egress peers, non-durable queues, finite retry,
  debug export, and audit sampling.
- Release promotion requires successful exact-commit CI, security, CodeQL,
  license, and live kind delivery evidence, plus SBOM, provenance, signatures,
  and coordinated version checks.

### Known limitations

- Fabric captures only activity exposed by the selected SDK, adapter, gateway,
  vendor API, or existing telemetry source; it cannot infer hidden reasoning.
- Metadata-only protection is not semantic PII detection or legal
  de-identification. Customers must use opaque identifiers and qualify their
  allowed metadata.
- Delivery is at least once. Destinations must deduplicate and supply separate
  evidence when durable persistence must be proven.

## [0.7.1] - 2026-08-25

### Added

- Added canonical, versioned public contracts for Fabric activity records,
  connector capabilities, Assurance findings, and `FabricDeployment`
  management profiles, including digest-pinned fixtures and deterministic
  release bundles.
- Added `fabricctl` environment diagnostics, configuration inspection and
  validation, local trace verification, deployment validation and digesting,
  and deterministic offline deployment planning for assurance levels A0-A3.
- Added connector capability manifests for the Python SDK, TypeScript SDK,
  OTLP receiver, and discovery-only eBPF integration, with fail-loud
  validation against capability overclaims.
- Added durable Collector delivery using persistent file-storage queues,
  retained per-replica volumes, bounded backpressure, unlimited transient
  retry, and authenticated OTLP/HTTP export.
- Added receiver mTLS, private-CA and client-certificate support, explicit
  exporter NetworkPolicy destinations, embedded Presidio UDS deployment, and
  a versioned reference policy bundle for regulated profiles.
- Added strict umbrella and Collector Helm values schemas, v0.6-to-v0.7
  upgrade fixtures, security render tests, and an artifact-level Collector
  startup qualification test.
- Added qualified TypeScript ESM, CommonJS, and type-definition packaging with
  npm trusted publishing and provenance, plus signed public-contract release
  artifacts.
- Added the public product-plane and packaging design of record: Connect,
  Control, Observe, Assurance, Governance, and Management, with a precise OSS
  distribution boundary and vertical implementation-slice template.

### Changed

- Hardened telemetry redaction across logs, spans, events, links, resources,
  and scopes; invalid UTF-8 now fails closed under secure byte handling and
  sanitized errors no longer echo sensitive content.
- The EU high-risk profile now requires OTLP receiver mTLS, authenticated TLS
  export, persistent queues, explicit egress peers, active policy/redaction
  controls, fail-closed admission, and cert-manager-owned webhook keys.
- Release publication now builds each package once, qualifies the exact bytes,
  requires successful CI/security evidence for the tagged commit, verifies the
  changelog entry, and publishes only the qualified artifacts.
- Python and TypeScript conformance suites now consume the same canonical
  activity contract and fixtures instead of maintaining SDK-local copies.
- Public documentation now separates the OSS Connect/Observe/Relay spine from
  optional Control and Assurance components and external Governance and
  Management implementations, without exposing internal product planning.

### Security

- Bumped `aiohttp` to 3.14.3 and `cryptography` to 50.0.0 in the SDK lockfile
  (CVE-2026-69244, CVE-2026-69247); same for the NeMo sidecar's `aiohttp`.
- Known issue: chromadb 1.5.8 (transitive via the `[crewai]` extra only) is
  affected by CVE-2026-45829 (pre-auth code execution). **No fixed release
  exists upstream yet**; newer crewai resolutions pull older, still-affected
  chromadb versions. The core SDK does not depend on chromadb — only
  installs using the `[crewai]` extra are exposed. Tracked for the next
  crewai/chromadb upstream releases.

### Fixed

- Collector redaction now applies tag-mode replacements to logs and traces
  instead of treating `hashed=false` as passthrough.
- EU profile locks now require trace processing and active guard/redaction
  chains in both telemetry pipelines; the admission backstop is enabled on
  first install rather than waiting for a namespace lookup on upgrade.
- Update-agent TLS rotation now rolls self-signed deployments and watches
  projected certificate files so cert-manager rotations restart uvicorn onto
  the new leaf before the webhook CA bundle diverges.
- Sidecar shared-token auth is explicitly TCP-only; UDS requests continue to
  rely on owner-only socket permissions, matching the shipped SDK clients.
- Red-team configuration now rejects empty and malformed `${env:...}` values
  so authenticated probes cannot silently degrade to blank credentials.
- Docs reconciled to v0.7.x across root README, docs README, and SDK README
  (a 0.7.0-era note incorrectly claimed these already said v0.6.x).
- Quickstart and walkthrough now teach `llm_call(provider=...)` instead of the
  deprecated `system=` alias.
- Removed a phantom `[model]` extra from api-stability docs; corrected
  `[langchain]` → `[otel-langchain]` in auto-instrumentation docs; fixed a
  nonexistent `from_env(enable_auto_instrumentation=True)` reference.
- `GuardrailNotConfiguredError` now names the exact remedy (env vars / kwargs)
  instead of only stating the problem.
- `PolicyAdapterError` on HTTP transport failure now states the fail-closed
  deny consequence explicitly.

## [0.7.0] - 2026-07-31

### Added

- **OpenTelemetry GenAI semantic conventions.** Python and TypeScript now
  emit current provider/operation, agent/workflow/conversation, inference,
  embeddings, tool, retrieval, memory, evaluation, token/cache, response,
  and opt-in content attributes. LLM spans use the standard
  `{operation} {model}` name and tool spans use the tool name with
  `gen_ai.operation.name=execute_tool`; Python adds the standard token,
  duration, time-to-first-chunk, and tool-duration histograms. Raw prompts,
  messages, tool payloads, retrieval content, and memory content remain
  disabled unless `capture_content=True`.
  The deprecated `system=` API and legacy attributes remain available for
  v0.6 migrations. See
  [`docs/genai-semantic-conventions.md`](docs/genai-semantic-conventions.md).
- **Agent surface logging (Python SDK).** Fabric now captures every way
  an agent touches the outside world, each as an additive `fabric.*`
  span event with metadata + SHA-256 hashes (raw data never on the
  span). New `Decision` methods: `record_skill`, `delegate` /
  `adelegate` (first-class sub-agent edge; `parent_agent_id` propagates
  via `tracestate`), `record_hook`, and `record_file_access` (file
  names + content hash, never the data; `redact_path` hashes the path).
  MCP gains inventory capture — `InstrumentedMCPSession.snapshot_inventory()`
  and `record_mcp_inventory(...)` hash each tool *definition* so a
  tool changing underneath the agent (shadow/poison) is detectable. See
  `docs/capturing-interactions.md` (since removed).
  (spec 022)
- **Generic interaction capture (Python SDK).** A universal
  `Decision.record_interaction(kind, target, …)` captures *any*
  interaction (`http.request`, `db.query`, `shell.exec`, …) — `kind` is
  free-form. A one-shot `fabric.coverage` signal flags interaction
  types captured only generically (the coverage loop). Three
  surface-agnostic capabilities — usable on any `record_*` call:
  `Baseline.load(...).check(...)` ("is this the approved hash?" for any
  hashed thing → `fabric.baseline.status`); open-vocabulary `tags=`
  (`fabric.tags`) with MITRE ATLAS + OWASP LLM reference taxonomies
  shipped as drop-in data (add a framework = drop a JSON file, zero
  code); and `verify_signature(...)` (`ed25519` via the `[signing]`
  extra, `hmac-sha256` via stdlib) → `fabric.signature.verified`. New
  public exports: `Baseline`, `BaselineCheck`, `verify_signature`,
  `SignatureResult`, `SignatureCheck`, `Taxonomy`, `TaxonomyEntry`,
  `bundled_taxonomy_names`. All additive: the conformance goldens stay
  byte-identical and `fabric.schema_version` remains `1.0`. (spec 023)

### Changed (chart defaults — **behaviour change**)

- **The OTel Collector now installs by default.**
  `otelCollector.enabled` in `charts/fabric/values.yaml` flips
  `false` → `true`. Previously a bare
  `helm install fabric ./charts/fabric` rendered **zero** Kubernetes
  resources — every subchart was gated off and `namespace.create` was
  `false` — so an operator following the README without a profile got
  a successful-looking no-op install and no telemetry anywhere. A
  Fabric install with no collector captures nothing, so this default
  was wrong. Every other subchart (Presidio, NeMo, Langfuse, red-team
  runner, update agent) stays opt-in: each needs a secret, a signing
  key, or an external database the operator must supply.
- **An unset exporter endpoint no longer fails the render — it falls
  back to the debug exporter.** `otel-collector.exporter.endpoint`
  still has no default, but the `otlphttp/fabric` exporter is now
  rendered only when it is set. With it empty the logs and traces
  pipelines use `debug`, so spans land in the collector pod's stdout
  and are readable with `kubectl logs`, and `NOTES.txt` prints a loud
  post-install warning. **Nothing is silently dropped — but stdout is
  not durable and is not an audit trail.** This replaces the previous
  `exporter.acceptUnsetEndpoint=true` escape hatch, which rendered a
  live `otlphttp` exporter pointed at `""` and failed every export
  with no operator-visible signal.
- **HMAC tail sampling ships off.**
  `otel-collector.fabric.sampler.enabled` flips `true` → `false`. It
  could not render without a key an operator has to supply, and
  auto-generating one would rotate it on every `helm upgrade`,
  silently changing every deterministic sampling decision. Off is also
  the conservative choice for an audit trail: the sampler *reduces*
  data (`rates.decision_summary: 0.1` drops 90% of decision
  summaries), so a default install now keeps every event. Both shipped
  profiles set `enabled` explicitly and are unaffected.
- **`permissive-dev` no longer exports to itself.** The profile set
  `otel-collector.exporter.endpoint: http://localhost:4318`, which is
  the collector's *own* OTLP/HTTP receiver (it binds `0.0.0.0:4318`) —
  every span was re-exported into the pod that emitted it. The
  endpoint is now unset, so the profile uses the debug exporter.
- **`otel-collector` subchart `0.2.0` → `0.3.0`**, with the matching
  constraint bump in `charts/fabric/Chart.yaml`. Both must move
  together or `helm dependency build` fails.

### Changed (docs / scope)

- **README OCI publishing claim corrected — it was inverted.** The
  README claimed the `otel-collector` subchart publishes standalone at
  `oci://ghcr.io/singleaxis/charts/otel-collector` and that
  umbrella-chart OCI publishing was still to come. Both were wrong:
  the `publish-chart` job in `.github/workflows/release.yml` packages
  and cosign-signs **only** the umbrella, at
  `oci://ghcr.io/singleaxis/charts/fabric`, exactly as
  `charts/fabric/README.md` already said. `docs/deployment.md` no
  longer lists umbrella OCI publishing as roadmap.
- **TypeScript SDK parity stated plainly.** The README Status section
  and `docs/enterprise-readiness.md` now say what the TypeScript SDK
  is: an **emit-surface-only** capture library — 7 modules against
  Python's 58, reproducing 19 of the 39 shared conformance goldens,
  with no framework adapters, no guardrail or policy transports, no
  MCP instrumentation, no host-side I/O helpers, not published to npm,
  and gated by an advisory rather than required CI job. It is not a
  drop-in substitute for the Python SDK, and there is no Go SDK.
  Outstanding mirror work: `docs/typescript-parity-backlog.md` (since removed).
- **Presidio sidecar is bundled, not missing.** `docs/deployment.md`
  said the umbrella did not yet bundle the Presidio subchart. It has
  been a declared dependency since the subchart landed; the accurate
  statement is that the `eu-ai-act-high-risk` profile does not
  *enable* it, because it needs a real tenant HMAC key. Wording
  corrected; no values changed.
- **Bundled Langfuse documentation corrected on three counts.**
  `docs/exporting-to-your-observability-backend.md` claimed
  `langfuse.enabled=true` runs "Langfuse + Postgres inside
  `fabric-system`" — the subchart bundles **no** database and
  fail-closes at render without an external DSN. Its Service resolves
  at `<release>-langfuse`, not `langfuse`, so the recommended
  `http://langfuse:3000` endpoint pointed at nothing. And the pinned
  upstream version (`appVersion 2.93.0`) is not a verified OTLP sink,
  so the page no longer recommends aiming the collector at it. The
  example command now includes the required DSN flag.
- **`docs/enterprise-readiness.md` counts and claims trued up.** Test
  suite 653 → **757**; conformance goldens 31 → **39**; the NIST AI
  RMF / ISO 42001 row no longer links to `docs/compliance/`, which
  contains no mapping files and says so — per-control mappings are
  roadmap (spec 009). The `~10–30 ms` per-decision figure is now
  labelled a design budget rather than a measurement, matching the
  README's existing posture and the spec 005 correction in 0.5.0. The
  page's "generally available" framing is now "beta", reconciling it
  with the "Pre-1.0" statement two sections below and with the README.
- **README status reconciled to the release line.** "Beta — Phase 1a
  shipping" → "Beta — v0.6.x"; `docs/deployment.md`'s operational
  posture table drops its stale "Phase 1a state" column header and
  no longer defers the Update Agent to "Phase 2" (it ships as an
  opt-in subchart today).
- **`docs/architecture.md` no longer says L2 components are in this
  repo.** The sentence "everything else in the repo (judge workers,
  escalation service, decision graph, telemetry bridge, update agent,
  admin UI)" listed five components that are commercial and absent
  here; only the update agent is in-tree. The page's own scope note
  already said so.
- **README no longer implies the full human-in-the-loop loop ships in
  OSS.** "Fabric ships all five" is now explicit that the escalation
  item is partial: the OSS distribution gives the pause-and-emit
  primitive and the adapter wiring, not the reviewer queue or the
  signed-verdict resume (spec 007).
- **`docs/quickstart.md` backend-rendering claim softened.** It
  asserted that Phoenix and Langfuse "render Fabric traces natively
  from this release onward" — a claim about third-party UI behaviour
  with no recorded smoke render behind it. It now says the `gen_ai.*`
  conventions are emitted correctly and stops short of per-backend
  verification. The Langfuse bootstrap sentence is now conditional on
  the subchart being enabled, which no shipped profile does.

### Changed (spec status)

- **Spec front-matter moved off blanket `draft`.** Per the vocabulary
  in `specs/000-overview.md`, 006 (LLM-as-Judge), 007 (Escalation),
  019 (Policy Engine), 020 (Execution & Step), 021 (ReplayMetadata),
  022 (Surface Logging) and 023 (Generic Interaction Capture) are now
  `implemented` — each carries an explicit L1 OSS scope boundary and
  each OSS primitive it names ships with frozen conformance goldens.
  001, 002, 003, 004, 008, 009, 010 and 012 move to `accepted`:
  decided designs whose remaining halves are commercial or unbuilt,
  where `implemented` would promise an OSS reader code they cannot
  obtain. 005 (Inline Guardrails) and 011 (Roadmap) stay `draft` —
  005's in-process transport claim is contradicted by the shipped UDS
  sidecars, and a roadmap is never `implemented`. The index table in
  `specs/README.md` gains the two missing rows for 022 and 023 and a
  note that 013–018 and 024 are allocated elsewhere in the same
  numbering series, so the next unused public number is 025.

### Removed

- **`components/telemetry-bridge/` is gone from the OSS working tree,
  and is now gitignored.** To be precise about what did and did not
  happen: the directory was **never tracked and never released** —
  `git log -- components/telemetry-bridge` was empty — so no consumer
  ever had it and no published artifact changes. It was uncommitted
  Layer 2 work sitting at a Layer 1 path, one `git add .` away from
  being published under Apache-2.0 while its own README called it
  commercial. It has been relocated to the SingleAxis private
  repository, and `/components/telemetry-bridge/` is now in
  `.gitignore` so it cannot reappear here. `components/README.md`
  already listed it under "Not here (Layer 2 / Layer 3)" and needed no
  edit; spec `004-telemetry-bridge.md` (removed)
  stays as the public design of record.

### Operator action required

If you install `charts/fabric` **without** `--values profiles/<name>.yaml`
and were relying on the previous all-subcharts-off default, a bare
`helm install`/`helm upgrade` now creates a collector Deployment,
Service, ServiceAccount and ConfigMap. Pass
`--set otelCollector.enabled=false` to keep the old empty render.
Installs that use either shipped profile are unaffected — both set the
toggle explicitly.

If you installed with `--set otel-collector.exporter.acceptUnsetEndpoint=true`,
drop the flag. An unset endpoint is now a supported (loudly warned)
posture that routes spans to the collector pod's stdout, rather than a
live exporter pointed at an empty string.

If you relied on the collector's default HMAC tail sampling to hold
telemetry volume down, it is now off: re-enable it explicitly with
`--set otel-collector.fabric.sampler.enabled=true` plus
`--set otel-collector.fabric.sampler.hmacKeySecret.name=<secret>`.

If `helm dependency build` fails with "the lock file (Chart.lock) is
out of sync with the dependencies file (Chart.yaml)", you have a stale
`Chart.lock` from an earlier checkout — it is intentionally
uncommitted. Run `helm dependency update` to regenerate it.

## [0.6.0] - 2026-06-02

### Added

- **LLM/Tool call telemetry (Python SDK).** New opt-in, emit-only
  setters tighten `llm_call` / `tool_call` child-span telemetry. Each is
  stamped only when called, so existing calls stay byte-identical.
  `LLMCall.set_cache_usage(cache_read_tokens=..., cache_creation_tokens=...)`
  emits `fabric.llm.usage.cache_read_tokens` /
  `fabric.llm.usage.cache_creation_tokens` (plus the OTel GenAI mirrors
  `gen_ai.usage.cache_read_input_tokens` /
  `gen_ai.usage.cache_creation_input_tokens`).
  `LLMCall.set_streaming(ttft_ms=..., chunk_count=...)` emits
  `fabric.llm.streaming.ttft_ms` / `fabric.llm.streaming.chunk_count`.
  `LLMCall.set_retry(count=..., reason=...)` and
  `ToolCall.set_retry(count=..., reason=...)` record per-call
  provider/transport retries (`fabric.llm.retry.*` /
  `fabric.tool.retry.*`), distinct from the step-/execution-level
  attempt/retry taxonomy. `ToolCall.set_idempotency(idempotent=...,
  key=...)` emits `fabric.tool.idempotent` /
  `fabric.tool.idempotency_key`. A new exported `ToolErrorCategory`
  string enum (`rate_limit`, `timeout`, `invalid_request`,
  `authentication`, `permission`, `not_found`, `server_error`,
  `network`, `cancelled`, `content_filter`, `unknown`) gives
  `ToolCall.record_error` a canonical, aggregatable category set;
  `record_error` still accepts a raw string for back-compat. The
  conformance schema gains all new fields (optional) and two new frozen
  goldens (`llm_call_rich`, `tool_call_error`) cover them; every
  pre-existing golden is byte-identical.
- **Expanded Python conformance coverage (no SDK change).** New
  deterministic conformance scenarios + frozen goldens exercise existing
  SDK behaviour that previously lacked golden coverage:
  `decision_id`-distinct-from-`request_id`, config-level
  workflow/execution propagation onto a standalone decision, memory
  erase (`forget`, `tenant_scope`) and invalidation
  (`remember(invalidates=...)`), policy `warn`/`escalate`/`redact`
  verdicts, and the parent-tool-call → side-effect linkage
  (`record_side_effect(parent_tool_call_id=...)`). New goldens only;
  every pre-existing golden is byte-identical and no SDK source or wire
  behaviour changed.
- **Versioned ReplayMetadata envelope (Python SDK).** A new emit-only
  `Decision.record_replay_metadata(*, state_hash=None,
  tool_result_hashes=None)` method emits a single `fabric.replay` span
  event bundling the metadata a (commercial) replay engine needs to
  reconstruct a decision. The envelope carries its own
  `fabric.replay.metadata_version` (`"1"`), independent of
  `SCHEMA_VERSION`, so it can evolve without a wire-schema bump. Most
  fields are assembled automatically from the decision's accumulated
  state — `fabric.replay.decision_id`, `fabric.replay.execution_id`
  (only when inside an execution), `fabric.replay.checkpoint_ids` (the
  recorded checkpoint ids), and `fabric.replay.suppressed_side_effect_ids`
  (only side effects recorded with `replay_behavior == "suppress"`).
  Two fields are host-supplied because the decision cannot derive them:
  `fabric.replay.state_hash` and `fabric.replay.tool_result_hashes`. The
  arrays are omitted when empty. Emit-only: the SDK assembles and emits
  the envelope; it never reconstructs, orchestrates, or replays — that is
  the commercial layer. The conformance schema gains a `fabric.replay`
  event; among existing goldens nothing changes, plus one new
  `replay_metadata.json`. `SCHEMA_VERSION` remains `1.0`. See
  specs/021-replay-metadata.md.
- **Step taxonomy on `llm_call` / `tool_call` child spans (Python SDK).**
  A "step" is one operation inside an execution (an LLM call, a tool
  call); the taxonomy is emit-only and additive. Every child span now
  auto-stamps a canonical, deterministic `fabric.step.type` —
  `"llm_call"` on the LLM-call span, `"tool_call"` on the tool-call span —
  host-overridable via a new `step_type=` parameter (e.g. `"plan"` /
  `"act"`). Opt-in, stamped only when supplied: a stable logical
  `fabric.step.id` (same across retries of the same operation; never
  auto-minted, so goldens stay byte-identical) and step-level retry
  metadata mirroring the execution model but per-operation and fully
  independent of it — `fabric.step.attempt_id`, `fabric.step.attempt`
  (integer ≥ 1), `fabric.step.retry.reason`, and
  `fabric.step.retry.previous_attempt_id`. `Decision.llm_call(...)` /
  `Decision.tool_call(...)` (and the underlying `LLMCall` / `ToolCall`)
  gain the matching `step_id` / `step_type` / `step_attempt_id` /
  `step_attempt` / `step_retry_reason` / `step_retry_previous_attempt_id`
  parameters. The conformance schema gains the `fabric.step.*` fields on
  both child spans (kept optional in `required` for lenient older
  consumers); among existing goldens only `llm_call.json` and
  `tool_call.json` change (each gaining `fabric.step.type`), plus one new
  `step_retry.json`. `SCHEMA_VERSION` remains `1.0`. See
  specs/020-execution-step-capture.md.
- **Optional `fabric.execution(...)` lifecycle span with attempt/retry
  metadata (Python SDK).** A new first-class, emit-only `Execution` primitive
  demarcates and correlates a run of related decisions without scheduling,
  orchestrating, retrying, or reconstructing anything (that remains the
  commercial layer — see specs/012). `Fabric.execution(*, execution_id=None,
  workflow_id=None, execution_attempt_id=None, execution_attempt=None,
  execution_retry_reason=None, execution_retry_previous_attempt_id=None,
  attributes=None)` returns a context manager usable as both `with` and
  `async with` (mirroring `Decision`); each attempt/retry param defaults to the
  corresponding `FabricConfig` value when omitted. On enter it opens a
  `fabric.execution` span (kind=INTERNAL) carrying all seven correlation
  fields — `fabric.execution_id` (supplied or a minted uuid4),
  `fabric.workflow_id`, `fabric.execution.status`,
  `fabric.execution.attempt_id`, `fabric.execution.attempt` (integer ≥ 1),
  `fabric.execution.retry.reason`, and
  `fabric.execution.retry.previous_attempt_id` — alongside
  `fabric.schema_version` / `fabric.tenant_id` / `fabric.agent_id` /
  `fabric.profile`; on exit it sets `fabric.execution.status` to `completed`,
  or `failed` (recording the exception) on error. A `Decision` opened inside an
  execution inherits its `execution_id` / `workflow_id` **and** the attempt/
  retry metadata via a `contextvars.ContextVar` for correlation, and that
  metadata also rides W3C `tracestate` cross-service propagation. Precedence:
  for `execution_id` / `workflow_id`, **explicit kwarg > active Execution >
  `FabricConfig`**; the attempt/retry fields (no per-decision kwarg) resolve
  **active Execution > `FabricConfig`**, so a decision with attempt config but
  no active execution still stamps from config. (Step-level retry metadata
  stays separate — a later PR adds `fabric.step.*` attempt fields on child
  spans.) Compatibility: additive and emit-only — a decision opened outside any
  execution is byte-identical to before (all 18 existing conformance goldens
  are unchanged; one new `execution.json` golden is added). The conformance
  schema gains an optional `execution_span` object (now including the four
  attempt/retry fields) while `decision_span` / `events` / `child_spans` remain
  the only required roots. See specs/020-execution-step-capture.md.
- **Stable `side_effect_id` on every side effect (Python SDK).** Each
  `SideEffectRecord` now carries a `side_effect_id` — minted as a uuid4 by
  default (covering both `SideEffectRecord.from_payloads` and direct
  construction), or supplied explicitly for idempotent re-emission. It is
  stamped on the `fabric.side_effect` span event as
  `fabric.side_effect.side_effect_id`, giving downstream consumers a stable
  anchor to reference a specific mutation for replay-suppression / rollback
  lineage. All existing side-effect fields (`parent_tool_call_id`,
  `idempotency_key`, `replay_behavior`, `request_hash`, `result_hash`,
  `approval_required`, `committed`, `rollback_supported`) are unchanged.
  Compatibility: additive and emit-only — the conformance schema keeps the
  attribute optional for older consumers, and the only golden that changes is
  `side_effect.json`, which gains exactly one normalized key.
- **Canonical `fabric.decision_id` protocol primitive (Python SDK).** A
  `Decision` now carries an explicit, stable decision identity, distinct from
  `request_id` (which is unchanged — still a separate per-turn id). Supply it
  via `fabric.decision(..., decision_id=...)` to correlate one decision across
  turns or services, or omit it to have the SDK mint a uuid4. It is stamped on
  the decision span as `fabric.decision_id`, threaded into policy evaluation
  records (`PolicyEvaluation.decision_id`) and judge requests
  (`JudgeRequest.decision_id`) — which previously doubled the `request_id` for
  this purpose — and rides W3C `tracestate` cross-service propagation under a
  new short member key (`FabricContext.decision_id`). Compatibility: additive
  and backward compatible — `request_id` behaviour is untouched, `decision_id`
  defaults to a minted uuid when not supplied, and existing traces simply gain
  one additive `fabric.decision_id` attribute on the decision span (all 18
  conformance goldens change by exactly that one normalized key).
- **TypeScript SDK — full wire-contract parity with the Python SDK.** The TS
  `Decision` now records the complete Fabric event surface, not just
  `llm_call` / `tool_call` / guardrail: `recordRetrieval`, `remember` /
  `recall` / `forget` (memory read/write/erase), `recordSideEffect`,
  `checkpoint`, `recordEval`, `queueJudge`, `recordPolicyEvaluation`,
  `recordToolAuthorization`, `requestEscalation`, and a `contentRef` field on
  the guardrail result. Each hashes raw content locally (so raw payloads
  never reach the trace) and folds the same rolling counters / distinct-value
  set attributes onto the decision span as Python. Policy input is hashed
  with a Python-compatible canonical JSON serializer so `input_hash` matches
  byte-for-byte. The TS conformance suite now reproduces **all 18** shared
  goldens (up from 3) and includes a guard test that fails if a new Python
  golden lands without matching TS coverage. The package versions
  independently of the Python SDK and is published from its own `ts-vX.Y.Z`
  tag via a new `publish-npm` workflow (npm provenance / OIDC).
- The TypeScript SDK is a pure capture library by design: host-side
  integration helpers that perform I/O (Presidio/NeMo sidecar clients,
  OPA/Cedar/HTTP policy engines, SQS/NATS/Redis queue transports, LangGraph/
  CrewAI adapters) remain Python-only — in TS the host runs the engine and
  passes the verdict to the matching `record*` method. The emitted telemetry
  is identical either way.

### Fixed

- **Helm release now publishes the `fabric` umbrella chart.** The
  `publish-chart` release job previously packaged and pushed the
  `otel-collector` *subchart* (`oci://ghcr.io/singleaxis/charts/otel-collector`),
  not the umbrella users actually install — so the documented one-command
  install referenced a chart that was never published. It now packages and
  publishes the `charts/fabric` umbrella as `oci://ghcr.io/singleaxis/charts/fabric`.
- **Chart versions track the release.** The umbrella chart `version` /
  `appVersion` and the Fabric-owned subcharts' `appVersion` (which drives
  their image tag) were pinned at `0.2.0`, so a fresh install pulled stale
  `0.2.0` images. They are now stamped from the release tag at publish time
  (and bumped to `0.5.1` in-repo). The third-party `langfuse` subchart is
  excluded — its `appVersion` is the upstream Langfuse version.

- **Hardening from adversarial stress testing (Python SDK).** Six
  pre-existing robustness gaps surfaced by pre-release stress testing,
  all fixed with no change to the wire contract — every conformance
  golden is byte-identical:
  - **Total content hashing.** The SHA-256 helpers behind memory,
    retrieval, tool-call, side-effect, and content-store hashing now
    encode UTF-8 with `surrogatepass`, so content containing lone
    surrogates hashes deterministically instead of raising
    `UnicodeEncodeError` mid-call.
  - **Non-finite span attributes rejected.** `Decision.set_attribute`
    now raises `ValueError` on `NaN`/`Inf` floats (invalid OTLP values
    that backends drop), consistent with its existing fail-loud type
    check; `bool` and finite floats are unaffected.
  - **In-SDK policy timeout.** `evaluate_policy` now enforces
    `timeout_seconds` itself by running the adapter on a worker thread
    with a hard deadline and failing closed to `deny` on timeout — a
    blocking or non-cooperative engine can no longer hang the caller.
  - **Closed policy vocabulary.** A verdict whose `decision` falls
    outside the five-value `PolicyDecision` set now fails closed to
    `deny` instead of being recorded verbatim.
  - **W3C tracestate value cap.** `propagation.inject` now enforces the
    W3C 256-char per-value limit (replacing the looser 512-byte member
    budget), so an oversized identity field fails loud rather than
    emitting a header strict validators would reject.
  - **Bounded attribute length.** `install_default_provider` now sets a
    `max_span_attribute_length` span limit so a pathological multi-MB
    attribute value can't bloat a span.

## [0.5.1] - 2026-05-30

### Added

- **TypeScript SDK — first-class guardrail API.** `Decision` now exposes
  `recordGuardrail(result)` and `recordBlock(result)` (plus a `blocked`
  accessor), mirroring the Python SDK's guardrail event + block bookkeeping.
  Previously a TS integrator had to hand-roll `getSpan().addEvent(
  "fabric.guardrail", {...})` with raw attribute keys, with no guarantee the
  keys/shape stayed in lockstep with the shared wire contract. The new
  helpers own the `fabric.guardrail.*` / `fabric.blocked` / status formatting
  and are verified against the SAME shared `guardrail_redaction` /
  `guardrail_block` conformance goldens the Python SDK uses. `entities` are
  emitted as `category:count` strings exactly as Python does.

### Fixed

- **CrewAI adapter:** the step callback now captures the agent's reasoning
  across CrewAI versions. It previously read only `.log`, a field that
  exists on legacy (langchain-derived) `AgentAction` objects but was
  dropped in current crewai (>=1.x), whose parser objects carry the
  reasoning in `.thought` / `.text` and whose `AgentFinish` uses
  `.output`. On modern crewai this made `fabric.crewai.log_preview`
  silently blank. The callback now probes `thought` → `log` → `output` →
  `text` and records the first non-empty value, restoring the reasoning
  preview without coupling to a single crewai version. Fail-safe behaviour
  is unchanged (a missing field records no preview; a hostile attribute is
  swallowed).
- **SDK (audit):** tag-mode PII redaction is now recorded on the
  `fabric.guardrail` span event. The guardrail chain previously gated the
  entity/policy record on the Presidio result's `hashed` flag, which is
  only set in HMAC mode — so tag-mode redactions (the value rewritten to
  `<EMAIL_1>`-style placeholders, `hashed=False`) silently produced no
  `fabric.guardrail.entities` / `policies` attributes, leaving the
  redaction invisible to the audit trail. The chain now records whenever a
  `pii_category` is returned, regardless of mode.
- **TypeScript SDK:** the callback forms (`decision`, `llmCall`, `toolCall`)
  no longer end their span synchronously when handed an `async` callback.
  Previously the span closed before the awaited body resolved, so setters
  like `setUsage` / `setResult` called after an `await` were silently
  dropped. Span-ending is now async-aware — a sync callback still ends the
  span synchronously, while an `await`ed callback keeps the span open until
  the returned promise settles (recording the exception + `ERROR` status on
  rejection). The decision span stays active across the `await` so child
  spans opened after it parent correctly.

## [0.5.0] - 2026-05-30

### Added

- **TypeScript SDK:** first-party `@singleaxis/fabric` npm package under
  `sdk/typescript/` — the core capture substrate (`fabric.decision` plus
  `fabric.llm_call` / `fabric.tool_call` child spans) emitting the same
  `fabric.*` / `gen_ai.*` wire contract as the Python SDK. Proven by a
  conformance test that deep-equal-asserts normalized TypeScript spans
  against the *same* shared golden fixtures the Python conformance suite
  uses (`bare_decision`, `llm_call`, `tool_call`). Ships CJS + ESM +
  types, with sha-256 hashing byte-identical to Python's `hashlib`.
  Adapters, sidecar clients, and the remaining recording primitives are
  explicit follow-ons. Added an advisory, path-filtered `typescript-sdk`
  CI job.
- **docs:** `docs/api-stability.md` — the public-surface / `schema_version`
  wire-contract / deprecation policy enterprise adopters can build against,
  linked from the README.

### Changed

- **spec 005:** corrected the §Enforcement wording — the benchmark suite is
  opt-in and informational (`python -m benchmarks.run`), not a per-PR CI gate;
  the latency budget is a design target, not a CI-enforced SLO.

### Added (SDK)

- **SDK:** `workflow_id` and `execution_id` now propagate across service
  boundaries via the W3C `tracestate` `singleaxis` member. `FabricContext`
  gains optional `workflow_id` / `execution_id` fields (encoded under the
  short keys `w` / `e`, mirroring the existing `t` / `a` / `s` / `r`), and
  `Decision` exposes matching read-only properties. `inject_decision` now
  carries both onto the carrier, closing the gap where they were emitted
  as decision-span attributes but did *not* actually cross the wire. Fully
  backward compatible: `tracestate` members without `w` / `e` decode with
  those fields as `None`, and the emitted decision-span schema is
  unchanged.
- **SDK:** memory lineage now supports *invalidation* and *right-to-erasure*
  markers. `Decision.remember` gains an optional `invalidates=<prior_key>`
  argument that, when set, emits `fabric.memory.invalidates` on the
  `fabric.memory` event — a lineage edge marking the prior key this write
  supersedes. New `Decision.forget(kind, key, *, tenant_scope=False)` emits a
  `fabric.memory` event with `direction="erase"` (a new `MemoryDirection`
  value) and the referenced `key`; `tenant_scope=True` adds
  `fabric.memory.tenant_scope` for a tenant-wide erasure marker. A rolling
  `fabric.memory_erase_count` attribute is kept on the decision span,
  symmetric with the read/write counters. `MemoryRecord` gains
  `invalidates` / `tenant_scope` fields and a `from_erase` constructor; an
  erase record references a key (no content), so its `content_hash` is
  `None`. The OSS SDK only *emits* these markers — acting on an erasure
  marker (the actual purge) is the commercial Decision Graph's job. Fully
  backward compatible: the new attributes are emitted only when the new
  features are used, so existing memory events are byte-identical.

## [0.4.1] - 2026-05-30

### Added

- **CI:** live OTLP span-landing assertion in the kind E2E smoke. The
  `kind cluster install + smoke` job now runs a real SDK `Decision`
  flow (`examples/e2e-smoke/flow.py`) on the runner, exports it over
  OTLP/HTTP to the in-cluster collector, and asserts the
  `fabric.decision` span — plus a `fabric.llm_call` child span and the
  `fabric.tenant_id` attribute — lands in the collector (scraped from
  the `debug` exporter's stdout). This is the first end-to-end proof
  that an SDK span flows SDK → OTLP → collector intact; the prior
  suite only used the in-memory exporter. The collector's `debug`
  exporter is added to the traces pipeline whenever
  `debugExporter.enabled` is set (already on under `permissive-dev`);
  production installs are unchanged.
- **SDK:** `Decision` now enforces its single-use / no-concurrent-use
  contract at runtime. Every mutating method (`guard_input`,
  `guard_output_chunk`, `guard_output_final`, `record_block`,
  `request_escalation`, `record_retrieval`, `remember`, `recall`,
  `record_side_effect`, `checkpoint`, `record_eval`, `queue_judge`,
  `evaluate_policy`, `authorize_tool_call`, `set_attribute`) is wrapped
  in a non-blocking overlap sentinel: two operations that *genuinely
  overlap in time* on the same instance now raise the new
  `ConcurrentDecisionUseError` instead of silently racing the internal
  record lists and rolling span-counter attributes. Sequential calls —
  including the async `a*` offload path, where each `await` completes
  before the next begins — are unaffected. Re-entering an already-entered
  or already-exited `Decision` (sync or async) raises `RuntimeError`.
  This is a behavior change: previously-silent concurrent misuse now
  fails loud. Open one `Decision` per agent turn — the `Fabric` client
  itself remains safe to share. See the concurrency contract in
  `fabric.decision`.
- **SDK:** async API. `Decision`, `LLMCall`, and `ToolCall` are now
  usable as `async with` (alongside the existing sync `with`), and the
  sidecar-I/O methods have non-blocking variants — `aguard_input`,
  `aguard_output_chunk`, `aguard_output_final`, `aevaluate_policy`,
  `aauthorize_tool_call`, `aqueue_judge` — which run the blocking call
  off the event loop via `asyncio.to_thread`. Pure-CPU recording methods
  (`record_retrieval`, `remember`, `record_side_effect`, `record_eval`,
  `checkpoint`, …) stay synchronous and are safe to call from async
  code. The emitted spans are byte-identical whether the sync or async
  call style is used.
- **adapters:** the CrewAI `step` / `task` callbacks are now fail-safe —
  a failure reading a malformed or adversarial CrewAI event object is
  logged and swallowed instead of propagating into the host crew's
  `kickoff()`. Observability never breaks the run.

### Fixed (redteam-runner)

- Dockerfile now installs `garak==0.9.0.15.*` and `pyrit==0.5.0.*` into
  separate virtualenvs (`/opt/venv/garak`, `/opt/venv/pyrit`) inside a
  single image, so the two libraries' conflicting `mistralai` pins no
  longer collapse the build. The runner CLI gains `--garak-venv` and
  `--pyrit-venv` (env: `FABRIC_REDTEAM_GARAK_VENV`,
  `FABRIC_REDTEAM_PYRIT_VENV`) which default to those paths in the
  published image; the drivers shell out to the matching venv's Python.
  SPEC 014 §4.1 row #1.

## [0.4.0] - 2026-05-28

### Added

- **otel-collector chart**: render an OTLP `traces:` pipeline alongside
  the existing `logs:` pipeline, gated on
  `fabric.guard.traceProcessingEnabled` (default `true`). The SDK has
  shipped trace spans since v0.2.0, but the chart only wired a `logs:`
  pipeline so spans were silently dropped at the collector. Set
  `fabric.guard.traceProcessingEnabled=false` to opt out. See
  spec 016 §4.1.
- **SDK:** One-shot stderr warning (`PIIShapedIdentifierWarning`,
  subclass of `UserWarning`) when `tenant_id`, `agent_id`, `user_id`,
  `session_id`, or `request_id` is constructed with a value that looks
  like an email address or phone number. These identifier values
  attach to every emitted decision span, so an email or phone there
  is a silent PII leak to the trace backend. The warning fires once
  per call site per process via the default `warnings` filter; set
  `FABRIC_QUIET_PII_WARN=1` to suppress. `*_name` fields are
  deliberately not checked — they are explicitly human-readable. See
  specs/016-foundational-fixes.md §4.5. (#TBD)

### Changed (presidio-sidecar)

- The Presidio sidecar entry point now wires the real
  `PresidioAnalyzer` by default when the `[presidio]` extra is
  installed, and **fails fast** on startup when it is not. This
  closes a v0.2.0 gap where a misconfigured image could silently
  start in `PassthroughAnalyzer` mode and redact nothing. The new
  `--allow-passthrough` flag is the explicit opt-in for dev / CI
  smoke clusters that intentionally run without the extra; it
  emits a startup warning so operators see the no-op mode in
  logs. When the real analyzer is wired, an INFO log records the
  wire-up. (SPEC 012 §4.2)

### Added (SDK)

- `GuardrailAction` extended from 3 to 5 values: `allow`, `redact`,
  `warn`, `block`, `escalate`. The new `allow` value lets a
  guardrail explicitly say "I let this through"; `escalate` defers
  to a human reviewer. (PR #78)
- `FabricConfig` accepts optional `workflow_id` and `execution_id`
  fields. When set, they appear on every decision span as
  `fabric.workflow_id` / `fabric.execution_id`, enabling
  cross-decision lineage queries on the Decision Graph. (PR #78)
- `decision.recall(kind, key, content)` — symmetric to
  `decision.remember()`. Emits a `fabric.memory` event with
  `direction="read"`. Lets the Decision Graph answer "which
  memories influenced this decision?". (PR #79)
- `decision.checkpoint(step_name, state_hash=...)` — emits a
  `fabric.checkpoint` event for the replay engine (commercial) to
  consume. The SDK leaves breadcrumbs; the replay engine restores
  state. (PR #80)
- `decision.record_eval(rubric_id, score, dimension, evaluator_name)`
  — attach a synchronous score to the decision span. Validates score
  in `[0, 1]`. (PR #81)
- `decision.queue_judge(rubric_id, dimensions, context, transport)` +
  `JudgeContext` + `JudgeRequest` + `QueueTransport` protocol +
  `LocalQueueTransport` reference. Captures judge context at
  decision time and ships it via a separate transport from the OTel
  trace stream. Privacy contract: raw content never lands on the
  trace; only `fabric.judge.queued` metadata does. (PR #82)
- `SimpleLLMJudge` reference judge worker. Zero-dependency
  LLM-as-judge with operator-supplied prompt template; demonstrates
  the `JudgeWorker` protocol without pulling DeepEval or Ragas. (PR #83)
- `decision.evaluate_policy(engine, policy_id, input)` + `PolicyEngine`
  protocol + `HTTPPolicyAdapter` + `OPAAdapter` (behind `[opa]`
  extra). Normalized 5-value `PolicyDecision` vocabulary across
  engines. Fail-closed on adapter exceptions. Audit posture: silent
  denies not permitted (non-allow decisions require a `reason`). (PR #84)
- `DeepEvalJudge` adapter behind `[deepeval]` pyproject extra. Maps
  `JudgeContext` to deepeval's `LLMTestCase` and emits an
  `EvalRecord` with the metric class name. (PR #85)
- `examples/reference-agent --enable-v04-primitives` flag
  demonstrates every v0.4 primitive in one decision, including the
  in-process judge worker that drains the LocalQueueTransport. (PR #86)

### Changed (privacy posture)

- The judge queue is now an architectural separation from the OTel
  trace stream. The SDK never emits raw `JudgeContext` content as
  span attributes; content flows exclusively via `QueueTransport`.
  This makes the "raw content off by default" claim enforceable by
  architecture rather than configuration. See `docs/architecture.md`
  for the dual-pipeline rule.

## [0.2.0] - 2026-05-01

Fabric earns the "open-source observability + control plane for
AI agents" framing by capturing LLM operations natively. Three
substantive additions over the v0.1.x line: per-LLM-call child
spans with `gen_ai.*` semantic conventions, auto-instrument extras
for the popular LLM SDKs, and a trace pipeline on the OTel
collector's custom guard processor so the chart's privacy promise
actually applies to the SDK's spans (not just future L2 bridge
log records).

This release subsumes the **never-tagged 0.1.3 audit follow-up**
work (round-2 audit fixes across SDK, components, charts, docs,
and specs). 0.1.3 was prepped on the `chore/v0-1-3-audit-followup`
branch and merged to main, but the new public API additions in
that branch (`Decision.llm_call`, `Decision.tool_call`, the
`[openai]/[anthropic]/...` extras, `fabricguardprocessor` trace
processing) are semver-minor work, not patch — so we skip the
0.1.3 tag and ship everything as 0.2.0. The audit-follow-up
section below preserves the full per-component fix list.

### Added (SDK)

- `Decision.llm_call(system=..., model=...)` opens a `fabric.llm_call`
  child span (kind=CLIENT) under the active decision span. Writes
  the OpenTelemetry GenAI semantic conventions
  (`gen_ai.system`, `gen_ai.request.model`,
  `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`,
  `gen_ai.response.finish_reasons`) plus matching `fabric.llm.*`
  mirrors. The returned context manager exposes
  `.set_usage(input_tokens, output_tokens, finish_reason)`,
  `.set_response_model(model)`, and `.set_attribute(key, value)` for
  attaching response data on exit. Phoenix LLM views, Langfuse cost
  dashboards, and any backend keying off either namespace render
  Fabric traces natively from this release onward.
- `Decision.tool_call(name, call_id=None)` follows the same pattern
  for tool/function invocations. Writes `gen_ai.tool.name`,
  `gen_ai.tool.call.id`, plus `fabric.tool.*` mirrors. Setter
  `.set_result_count(count)` records how many results the tool
  returned.
- `LLMCall` and `ToolCall` exposed at the package level for callers
  building custom instrumentation patterns.
- Auto-instrumentation extras — one `pip install` covers governance
  and LLM-call observability for the popular SDK families:
  - `singleaxis-fabric[openai]` →
    `opentelemetry-instrumentation-openai-v2`
  - `singleaxis-fabric[anthropic]` →
    `opentelemetry-instrumentation-anthropic`
  - `singleaxis-fabric[bedrock]` →
    `opentelemetry-instrumentation-bedrock`
  - `singleaxis-fabric[otel-langchain]` →
    `opentelemetry-instrumentation-langchain`
  - `singleaxis-fabric[cohere]` →
    `opentelemetry-instrumentation-cohere`
- `Fabric.enable_auto_instrumentation(only=..., capture_content=...)`
  lazy-detects which extras are installed and invokes each
  Instrumentor's `.instrument()`. Content capture (raw prompts /
  completions on spans) is **off by default** per Fabric's
  compliance posture; override with `capture_content=True` or
  `FABRIC_CAPTURE_LLM_CONTENT=true` env. Silently skips uninstalled
  extras; warns and continues when an upstream Instrumentor raises
  rather than crashing agent startup.
- Reference agent (`examples/reference-agent/`) now wraps its
  simulated LLM call in `decision.llm_call` so users see the
  canonical pattern in the runnable example.

### Added (OTel collector)

- `fabricguardprocessor` registers a Traces pipeline variant
  alongside the existing Logs variant. Spans are filtered by an
  attribute-key namespace allowlist (default:
  `fabric.`, `gen_ai.`, `llm.`, `tool.`, `service.`, `telemetry.`,
  `otel.`, `http.`, `net.`, `rpc.`, `db.`). Anything outside these
  prefixes is stripped before egress; spans whose attributes become
  empty are dropped. Operators tighten / extend via
  `trace_attribute_prefixes`; trace processing is OFF by default
  (`trace_processing_enabled: false`) so existing operator config
  files work unchanged. Closes the gap where the chart's privacy/
  policy enforcement only applied to L2-bridge-shaped log records,
  while the SDK's spans bypassed the processor entirely.

### Changed (docs / scope)

- L1/L2 boundary now load-bearing across all narrative docs.
  README hero is "open-source observability and control plane for
  AI agents"; specs 003 (Decision Graph), 004 (Telemetry Bridge),
  006 (LLM-as-Judge), 007 (Escalation Workflow) gain explicit "L2
  commercial control plane / not in this OSS distribution"
  disclaimers — the implementation lives in a separate private
  repository, the spec is retained for partner/auditor
  transparency.
- Spec 002 §L2 wording corrected from "OpenTelemetry +
  OpenLLMetry" to "OpenTelemetry + GenAI semantic conventions" —
  the conventions are joint OTel/Traceloop work; "OpenLLMetry" is
  a project name, not a spec name. Fabric does not depend on
  `traceloop-sdk`.
- Spec 011 (roadmap) recast as "L2 + L4 + L5 + L1 adapters" of
  the 8-layer agent stack: that's the OSS scope. v0.2.x = capture-
  everything SDK; v0.3.x+ = additional language SDKs + broader
  rails catalog + conformance test suite.
- Spec 009 (compliance mapping) rewritten to make explicit that
  per-regulation mappings ship with the L2 commercial control
  plane; the L1 OSS chart provides regulatory profiles as
  hardened presets only.
- New `docs/exporting-to-your-observability-backend.md` — concrete
  Helm wire-ups for Langfuse, Phoenix, Datadog, Honeycomb, Grafana
  Cloud, custom collectors. Replaces the implicit
  "fabric-ingest:8080" assumption.
- New `docs/how-fabric-fits-in-your-agent-stack.md` — 8-layer
  picture with where Fabric ships code (★) vs adapter/integration
  vs out-of-scope (◆), plus end-to-end ASCII diagram showing the
  L1 OSS / L2 commercial boundary.
- New `sdk/python/SCOPE.md` — what the SDK does and explicitly
  does NOT do.

### Fixed (CI)

- Pre-existing CI red on the audit-followup branch resolved
  (5 of 5 red checks): SDK ruff RUF100 unused `# noqa: SLF001`
  directives in `test_tracing.py`, SIM117 nested `with` in
  `test_retrieval.py`, three nemo-sidecar CLI tests
  (`test_cli_invokes_uvicorn_on_uds/tcp`,
  `test_cli_unlinks_stale_socket`) updated to pass
  `--allow-passthrough` after the round-1 security tightening
  made `--rails-config` mandatory by default.

### Round-3 audit follow-up (PR #49)

Re-audit of the v0.2.0 surface flagged a handful of correctness
gaps; all CRITICAL/HIGH/MEDIUM findings are fixed in this release.

**SDK:**

- `LLMCall` and `ToolCall` context managers now reject re-entry
  without prior exit. Previously, calling `__enter__` twice on the
  same instance silently overwrote the underlying tracer span,
  orphaning the first span (memory leak + mis-parented children).
  Fail-loud `RuntimeError` now.
- `LLMCall.set_usage(input_tokens=..., output_tokens=...)` now
  rejects non-int values up front with a `TypeError`. Previously a
  string token count would raise an opaque `<` comparison error;
  the type-check happens before the negative-check now.
- `ToolCall.set_result_count(count)` same fix — explicit
  `isinstance(int)` validation.
- `bool` is rejected as a token-count value (it's a subclass of
  `int` but accepting `True`/`False` for "how many tokens" is a
  semantic foot-gun).
- `auto_instrument._try_enable` now wraps both the Instrumentor's
  constructor AND `.instrument()` call in the same try/except.
  Some upstream Instrumentors check peer-dep imports in `__init__`
  rather than `instrument()`; previously a constructor exception
  would crash agent startup. Now logs a warning and skips.

**Collector (`fabricguardprocessor`):**

- Trace path now filters span event attributes and Resource-level
  attributes (not just span-level attributes). Previously a
  misbehaving SDK that put sensitive metadata on
  `ResourceSpans.Resource()` (deployment names, internal hostnames)
  or in span events would bypass the namespace allowlist.
- Drop-on-empty refined: a span is dropped only when both its own
  attributes AND every event's attributes have been fully stripped.
  Previously a span with foreign span-level attrs but a valid
  event trail would have been dropped, losing signal.
- `tool.` prefix ownership documented in
  `DefaultTraceAttributePrefixes` so operators don't collide with
  Fabric's `tool.*` namespace.

### Audit follow-up (folded from never-tagged 0.1.3)

Round-2 audit fixes. 5 parallel deep-audit agents flagged ~80
issues across SDK code-correctness, components, charts, specs, and
production-readiness. The following per-component fix list was
prepped under the `chore/v0-1-3-audit-followup` branch and merged
to main as PR #44, but the surrounding work added new public API
(`Decision.llm_call`, `Decision.tool_call`, auto-instrument extras,
collector trace processing) so we skip the 0.1.3 tag and roll
everything into 0.2.0.

### Fixed (SDK)

- `FabricConfig` and `Fabric.from_env` now strip whitespace from
  `tenant_id`, `agent_id`, `profile` and reject empty-after-strip.
  Trailing newlines in `.env` files / Helm values no longer ship as
  span attributes.
- `Decision.__exit__` now records `blocked_and_escalated` status
  when both fire on the same Decision, instead of silently
  collapsing the escalation behind the block status.
- `Decision.record_block` and `Decision.request_escalation` are now
  first-wins; the second call raises `RuntimeError` rather than
  silently overwriting.
- `Decision.set_attribute` validates value type and raises
  `TypeError` on dict/list/None, matching OTel's actual contract
  rather than relying on OTel to silently drop unsupported values.
- `RetrievalRecord.from_query` now enforces 1:1 parity between
  `result_hashes` and `result_count` when supplied. Mismatched
  partial supply was silently corrupting downstream Decision Graph
  projections. `source_document_ids` remains free-form (N chunks
  may share M < N source documents).
- `_chain.GuardrailChain` no longer pushes NeMo rail names into
  `entities_detected` (`EntitySummary` represents PII entity
  classes, not rail names). NeMo rails appear only in
  `policies_fired`.
- `install_default_provider` refuses to silently re-install when an
  existing real `TracerProvider` is configured. Returns the existing
  provider with a warning; OTel's own API documents that
  re-installation is not allowed.
- New: `fabric.tracing` emits a one-shot warning at first
  `get_tracer()` if the global TracerProvider is the OTel no-op
  default. Without this, hosts who skip `install_default_provider`
  ship instrumented agents that emit zero-trace_id spans silently.

### Fixed (components)

- NeMo sidecar refuses to start without `--rails-config` unless the
  operator explicitly passes `--allow-passthrough`. Previously a
  missing volumeMount silently produced an "allow-everything" engine
  that disabled jailbreak/policy defence with only a docstring
  warning.
- NeMo sidecar `FABRIC_LIMIT_CONCURRENCY` parsing emits a clear
  parser error on non-int input rather than crashing the whole
  process at uvicorn boot.
- Update-agent webhook refuses to fall back to plaintext on the
  admission path when only one of `--tls-cert` / `--tls-key` is
  present. Plaintext on a webhook causes either every-admission-
  failure (failurePolicy=Fail) or every-admission-bypass
  (failurePolicy=Ignore); both are customer outages. Fully-
  plaintext mode is opt-in via `FABRIC_UPDATE_AGENT_ALLOW_PLAINTEXT=1`
  for local smoke tests only.

### Fixed (charts)

- Umbrella chart now fail-renders on empty `tenant.id` for any
  profile other than `permissive-dev`. Empty tenant ID stamps every
  emitted span with no attribution and was the most common
  silent-misconfiguration footgun.
- Per-subchart `NetworkPolicy` allow templates now ship for
  `otel-collector`, `nemo-sidecar`, and `update-agent`. Each opens
  the minimum surface (collector OTLP receivers, sidecar service
  port, webhook ingress) plus DNS to `kube-system`. Default off so
  CNIs without enforcement aren't penalised; the
  `eu-ai-act-high-risk` profile re-enables `networkPolicy.denyDefault:
  true` paired with these allow rules.
- `PodDisruptionBudget` templates added to all three subcharts,
  honoured only when `replicaCount > 1`. `update-agent` is the
  load-bearing one — losing both webhook replicas during a node
  drain blocks ConfigMap/Secret CREATE/UPDATE cluster-wide.
- `otel-collector` and `nemo-sidecar` readiness probe initial
  delays bumped (from 5s/3s to 15s/20s) so rolling deploys on slow
  networks don't mark pods Unready repeatedly during cold-start.
- **`otel-collector.exporter.endpoint`** default flipped from the
  phantom `http://fabric-ingest:8080` (which resolved to a non-existent
  service in any L1-only deploy) to the empty string, paired with a
  render-time validator that fails the chart install if the field is
  unset. Previously: spans dropped silently because the configured
  exporter target had no service behind it. Now: operator must point
  at a real backend (bundled Langfuse, Datadog, Honeycomb, your own
  collector chain, or — for partner deployments — the SingleAxis
  commercial Telemetry Bridge). CI smoke renders set
  `otel-collector.exporter.acceptUnsetEndpoint=true` to bypass.
- `eu-ai-act-high-risk` profile now sets explicit `ingressFrom` /
  `egressTo` defaults on otel-collector and nemo-sidecar
  NetworkPolicies — ingress restricted to `fabric-system` namespace
  rather than the previous `namespaceSelector: {}` (which permitted
  any namespace under denyDefault). Operators bridging from agent
  pods in other namespaces extend `ingressFrom` to permit them.

### Fixed (docs)

- **Hero repositioning.** README + SDK pyproject description shifted
  from "audit-ready substrate" to "open-source observability and
  control plane for AI agents." The old framing implied this OSS
  distribution generated audit trails on its own; in fact the
  collection infrastructure ships here and evidence-bundle generation
  / signed audit trails ship with the SingleAxis commercial control
  plane. Engineer-vocabulary hero, honest L1/L2 boundary, no
  compliance-tool buyer mismatch.
- README NIST AI RMF / ISO/IEC 42001 / SR 11-7 / HIPAA profiles list
  now explicitly marked as roadmap (only `eu-ai-act-high-risk` and
  `permissive-dev` ship in `charts/fabric/profiles/`).
- README + docs/README no longer link to `docs/compliance/mappings/`
  as if it contained authoritative content; the only thing landing
  there is an in-progress stub. Pointer is now to spec 009.
- `docs/architecture.md` latency framing softened to "design budget"
  to match the README v0.1.2 wording. Numbers are unchanged but
  no longer claimed as measured P99s.
- `charts/fabric/README.md` no longer claims readiness probes
  enforce latency budgets (today's probes are simple HTTP
  `/healthz` checks; latency-aware readiness gate is roadmap).
- `Pre-alpha` → `Beta` framing reconciled across the README and the
  SDK README to match the `pyproject.toml` classifier
  (`Development Status :: 4 - Beta`) introduced in 0.1.2.

### Operator action required

If you run `helm install fabric` with a non-`permissive-dev` profile,
you must now pass `--set tenant.id=<uuid>` (previously this was
documented as required but only warned in NOTES.txt).

If you want fail-closed network posture, NetworkPolicy
`denyDefault: true` is no longer enabled by the EU profile — flip it
in your tenant values once you have allow-rules for your cluster.

If you used `--allow-passthrough` semantics by relying on a missing
`--rails-config` to NeMo sidecar (probably nobody — but flagging it
as a behaviour change), pass `--allow-passthrough` explicitly.

## [0.1.2] - 2026-04-27

Pre-launch hardening pass following an enterprise-grade audit.
Functionally identical SDK surface; this release fixes
documentation, packaging, and supply-chain hygiene that the audit
flagged.

### Fixed

- **README 60-second example** now compiles end-to-end. Pinned the
  `[otlp]` extra requirement, switched to explicit
  `Fabric(FabricConfig(...))` so it runs without environment setup,
  replaced placeholder names (`session.id`, `req.body`, `my_llm`)
  with literal strings.
- **`eu-ai-act-high-risk` Helm profile** now renders under
  `helm template` with the documented `--set` overrides
  (`update-agent.config.allowPlaceholderKey=true` and
  `otel-collector.fabric.redact.acceptMissingProvider=true`).
  Production install still fail-closes on the placeholder key —
  the override only affects dry-renders for compliance review.
  `docs/deployment.md` documents both paths.
- **OTel Collector binary version stamp** now matches the chart
  and image tag (was reporting `0.1.0` under the `0.1.1` tag).
- **Chart versions** bumped across the umbrella, all five
  subcharts, and the `ocb-config.yaml` to track the release tag.
- **mypy --strict** passes cleanly — removed an unused
  `# type: ignore[import-not-found]` in
  `sdk/python/src/fabric/adapters/langgraph.py`.
- **Quickstart step 2** no longer references an undefined `my_llm`
  symbol.
- **`docs/quickstart.md` and `examples/reference-agent`** now
  install a real `TracerProvider` so `trace_id` is a real 32-hex
  value rather than the all-zeros sentinel.
- **README compliance frameworks** list reconciled with
  `docs/compliance/mappings/README.md` (initial mappings target
  EU AI Act, NIST AI RMF, ISO/IEC 42001; SR 11-7, HIPAA, GDPR are
  roadmap).
- **LICENSE** trademark clause restored to verbatim Apache-2.0
  wording so license scanners do not flag the file as modified.

### Changed

- **`sdk/python/pyproject.toml`** classifier from
  `Development Status :: 2 - Pre-Alpha` to `4 - Beta` — matches
  the released GA posture.
- **`Decision` concurrency contract** documented in
  `sdk/python/src/fabric/decision.py`: one `Decision` per agent
  turn; do not share across coroutines or threads.
- **`release.yml`** workflow permissions narrowed — workflow-level
  default is `contents: read`; each job that needs writes
  escalates explicitly. Reduces the blast radius of any compromise
  to one step.
- **README latency claims** softened to "design budget" framing —
  the `<1ms` and `<100ms` P99 numbers are budgets enforced by
  readiness probes, not measured benchmarks (which land in a
  follow-up release).

### Operator action required

If you are upgrading from `0.1.1` and using `helm template` /
`helm lint` against the `eu-ai-act-high-risk` profile, add:
`--set update-agent.config.allowPlaceholderKey=true`
`--set otel-collector.fabric.redact.acceptMissingProvider=true`.
A real `helm install` is unaffected.

PyPI `0.1.1` will be yanked after `0.1.2` is verified live;
`pip install singleaxis-fabric` will resolve to `0.1.2`.

## [0.1.1] - 2026-04-27

**First publishable GA on PyPI.** Functionally identical to `0.1.0`;
cut as a fresh version because the PyPI `0.1.0` slot was occupied
by a yanked artifact and `skip-existing: true` on the publish
action prevented the GA build from overwriting it.

`pip install singleaxis-fabric` resolves to `0.1.1`. Container
image `ghcr.io/singleaxis/fabric-otelcol:0.1.0` and the OCI Helm
chart at `0.1.0` are unaffected and remain the canonical names
there.

See `[0.1.0]` below for the complete shipping surface.

## [0.1.0] - 2026-04-27

**Initial general-availability release** of SingleAxis Fabric — the
open-source substrate for audit-ready AI agents.

Functionally identical to `0.1.0-rc.6`; this tag stamps the
release-candidate verification as the canonical `0.1.0` artifact set.

### What ships in 0.1.0

**Fabric Python SDK** (`pip install singleaxis-fabric`)

- `Fabric` client and `Decision` context manager — one OpenTelemetry
  span per agent turn, tagged with tenant / agent / session /
  request / user
- Inline guardrail chain — Microsoft Presidio (PII redaction) and
  NVIDIA NeMo Guardrails (Colang policy rails) over Unix domain
  sockets, fail-loud by design (`GuardrailNotConfiguredError` if a
  rail is invoked but not wired)
- Retrieval recording (SHA-256 hashed locally; raw text never leaves
  the span) and memory-write recording mapping onto the provenance
  graph
- Escalation pause primitive returning a framework-agnostic payload
  for human-in-the-loop review
- First-class adapters for **LangGraph**, **Microsoft Agent
  Framework**, and **CrewAI**, each gated behind an install extra so
  the core install stays framework-neutral
- OTel helpers: `get_tracer`, `install_default_provider`
- Tested across Python 3.11, 3.12, 3.13

**Guardrail sidecars**

- Presidio sidecar — UDS PII redaction with default recognizers
- NeMo Guardrails sidecar — UDS Colang rails, multi-stage Dockerfile
  builds the `annoy` C++ extension cleanly

**OTel Collector distribution**

- Pre-configured Fabric processor chain: tail sampling, attribute
  allowlisting, tenant scoping
- Fans out to Langfuse, Tempo, Jaeger, Honeycomb, Datadog — anything
  that speaks OTLP
- Published to `ghcr.io/singleaxis/fabric-otelcol:0.1.0`, signed
  with cosign (keyless via Fulcio), multi-arch (amd64 + arm64)

**Helm chart**

- Umbrella chart at `charts/fabric/` with two regulatory profiles:
  `permissive-dev` for evaluation, `eu-ai-act-high-risk` for
  production under the EU AI Act
- Subcharts gated behind `*.enabled` toggles so operators can start
  small (just collector) and layer on guardrails / observability /
  red-team as needed
- `otel-collector` subchart published as an OCI artifact at
  `oci://ghcr.io/singleaxis/charts/otel-collector:0.1.0` (signed)

**Reference agent**

- End-to-end example exercising every SDK surface (decision span,
  retrieval, guardrails, memory, escalation) — runs offline against
  a simulated LLM and judge

**Supply-chain integrity**

- All artifacts (Python wheels, container images, OCI chart, source
  tarball, SBOMs) are signed with [Sigstore cosign](https://sigstore.dev)
  keyless via Fulcio
- SBOMs in CycloneDX and SPDX formats accompany every release
- SLSA build provenance attestations for images and tarballs

**Specs (design of record)**

- 14 specs covering overview, product vision, architecture,
  decision graph, telemetry bridge, inline guardrails, LLM-as-judge,
  escalation workflow, deployment model, compliance mapping,
  development standards, and the phased roadmap

### Status

**Pre-alpha** (development status 2 in `pyproject.toml`). The SDK
public surface above is stable for the duration of `0.1.x`; the
Python distribution version is derived from the git tag at build
time so pinning works as expected. Anything labeled "Phase 2",
"roadmap", or "planned" in any document is exactly that — not
shipping in `0.1.x`.

### Known boundaries

- The agent request path **never** blocks on a Fabric HTTP call —
  SDK work is in-process (`<1ms` P99), guardrail sidecars run over
  UDS (`<100ms` P99), everything else (judges, escalation
  bookkeeping, provenance writes) is async off the OTel stream
- Raw agent traces, retrieved context, and user content **never**
  egress the tenant VPC by default — the Telemetry Bridge that
  egresses sanitized summaries is opt-in and not part of this
  release
- "Audit-ready" means Fabric produces the evidence trail an audit
  requires, not that Fabric issues certifications — certification
  remains the tenant's process

### Acknowledgements

Fabric stands on the shoulders of OpenTelemetry, Microsoft
Presidio, NVIDIA NeMo Guardrails, LangGraph, Microsoft Agent
Framework, CrewAI, Langfuse, and Sigstore. Thank you to those
project teams for the foundations.

### Operator action required

None for fresh installs. There is no prior stable release to
upgrade from.

## [0.1.0-rc.6] - 2026-04-27

Re-cut of `0.1.0-rc.5` to refresh release artifacts. No functional
or SDK changes; tenant-facing API stable. PyPI artifacts for rc.1
through rc.5 have been yanked.

Anyone with a prior clone or fork must re-clone or hard-reset.

## [0.1.0-rc.5] - 2026-04-27

Hardening pass over the v0.1.0 release surface. Bundles the four PRs
landed since rc.4 (#20, #21, #22, #23). No functional SDK changes;
tenant-facing API stable.

### Changed

- **README rewritten** for customer clarity (#22). Adds badges, a
  "why Fabric" framing, concrete feature list with tech-stack
  links, copy-paste 60-second example, working Helm-from-source
  install, ASCII request-path diagram, and a documentation lookup
  table. Replaces the OSS-vs-services-first intro that buried the
  install path.
- **Apache copyright legal entity** corrected to *AI5Labs Research
  OPC Private Limited* and role emails switched to `singleaxis.ai`
  (#20).
- **GitHub Actions bumped to latest majors** (#23): `checkout` v4 →
  v6, `setup-python` v5 → v6, `setup-go` v5 → v6, `codeql-action` v3
  → v4, `action-gh-release` v2 → v3. All Node 20 → 24 runtime bumps
  with no flag-affecting API change.
- **`cryptography`** upper bound widened to `<47.0` for the
  update-agent (#23). Patches CVE-2026-39892, CVE-2026-34073,
  CVE-2026-26007.
- **OpenTelemetry floor** raised to `>=1.41` across `api`, `sdk`, and
  `otlp` exporter (#23). Previous floor of 1.27 was three years
  stale.
- **`langgraph`** and **`crewai`** upper bounds widened to `<2.0`
  (#23) so the optional adapter extras pick up langgraph 1.x and
  crewai 1.x without manual intervention.
- **`litellm`** force-pinned to `>=1.83.7` (#22) to fix
  GHSA-xqmj-j6mv-4862 (HIGH, RCE in LiteLLM Proxy `/prompts/test`).
  Transitive via `crewai`; core install unaffected.
- **`nemo-sidecar` Dockerfile** rewritten as multi-stage (#21) so
  the `annoy` C++ extension builds against `build-essential` in a
  builder stage and the runtime image stays slim.
- **`charts/fabric` defaults** flipped `nemoSidecar.enabled: false`
  (#21) so a stock install does not `ImagePullBackOff` against an
  image that does not yet publish.
- **Signing posture aligned** across `SECURITY.md`,
  `docs/deployment.md`, and `charts/fabric/README.md` (#21, #22).
  Documents now agree: cosign + SLSA + SBOM ship from `0.1.0`; Helm
  `.prov` provenance is a roadmap item.

### Added

- **Sidecar image build (PR smoke)** matrix CI job (#21) — builds
  all five sidecar Dockerfiles on every PR so a regression like the
  rc.4 nemo build break surfaces in review, not at release.

### Fixed

- **DCO check skips merge commits** (#22) via `git rev-list
  --no-merges`. The synthetic merge commit GitHub creates on
  "Update branch" has no DCO trailer and was failing the check
  even when every authored commit was signed off.
- **`commitlint` subject-case rule disabled** (#23). Was rejecting
  Dependabot's `Bump X from Y to Z` capitalization and silently
  blocking every dep update.
- **CodeQL Go autobuild Go version pin** corrected to 1.25 (#23).
  Latent issue exposed by `setup-go@v6` enforcing local toolchain;
  the otel-collector processors require Go 1.25 in their `go.mod`.
- **Lychee link-check excludes** for `slsa.dev` (#22) and
  `securityscorecards.dev` (#23). Both flake on connection-reset
  under CI crawl bursts.

### Operator action required

None for tenants upgrading from rc.4. Bumping `litellm` and OTel
floors is transparent at install; pinned environments continue to
resolve.

## [0.1.0-rc.4] - 2026-04-24

Re-cut of `0.1.0-rc.3` (yanked on PyPI) with the Python distribution
version now derived from the git tag at build time, plus the GitHub
org rebrand from `ai5labs` to `singleaxis`. No functional changes to
Fabric itself.

rc.3 was yanked because the SDK hardcoded `_version.py = "0.1.0"`
while the tag was `v0.1.0-rc.3`. PEP 440 would have normalized the
tag to `0.1.0rc3`, but the static version meant PyPI received the
pre-release artifact in the stable `0.1.0` slot — pre-release code
masquerading as GA. rc.4 moves the version source to the tag (via
hatch-vcs) so every build wears the version its tag commits to.

### Changed

- **Python version is now derived from the git tag** via `hatch-vcs`
  (`[tool.hatch.version] source = "vcs"`). The previous static
  `_version.py` is replaced by an `importlib.metadata` runtime
  lookup that reads whatever PyPI gave the installed distribution.
  Dev checkouts without a tag resolve to `0.0.0.dev0`.
- **GitHub org** `ai5labs/singleaxis-fabric` → `singleaxis/singleaxis-fabric`.
  GitHub creates redirects for old URLs, but hardcoded refs have been
  rewritten: 4 collector-processor `go.mod` declarations,
  `ocb-config.yaml` gomod + replace directives, `sdk/python/pyproject.toml`
  project URLs, quickstart clone URL, lychee URL exclusions,
  CHANGELOG link-refs, ISSUE_TEMPLATE contact links, CODEOWNERS
  comment.
- **Container image** published to `ghcr.io/singleaxis/fabric-otelcol`
  (was `ghcr.io/ai5labs/...`). Release workflow uses
  `${{ github.repository_owner }}` so this change is automatic.

### Fixed

- **OpenSSF Scorecard workflow permissions** — top-level
  `permissions: security-events: write` was rejecting Sigstore/Fulcio
  webapp publishing with HTTP 400. Scoped `security-events: write`
  per-job (`trivy-fs`, `semgrep`); Scorecard's job keeps its own
  block. Top-level stays read-only so Fulcio accepts the SARIF.

### Operator action required

- If you were tracking a PyPI pending-publisher on `ai5labs/singleaxis-fabric`,
  update the owner to `singleaxis`. Trusted publishing is bound to
  the full `owner/repo` path, so the old config stops matching after
  the transfer. Done before this tag was cut.

## [0.1.0-rc.3] - 2026-04-24

Re-cut of `0.1.0-rc.2` with the Python distribution renamed and an
actual PyPI publish step wired in. Up to rc.2 the quickstart told
prospects to `pip install fabric-sdk` — that name is squatted on
PyPI by an abandoned unrelated Hyperledger SDK, so anyone following
the quickstart got the wrong package. No functional changes to
Fabric itself.

### Changed

- **Python distribution renamed** `fabric-sdk` → `singleaxis-fabric`.
  Import path is unchanged: `from fabric import ...` still works
  (the module name stays `fabric`, only the PyPI distribution name
  changed). Mirrors the standard pattern where distribution name
  and module name differ (`opencv-python` / `cv2`, `PyYAML` / `yaml`).
- **OTel instrumentation scope** constant `FABRIC_SDK_NAME` now
  emits `singleaxis-fabric-python` instead of `fabric-sdk-python`,
  so dashboards keying off `telemetry.sdk.name` see the new name.

### Added

- **`release.yml` `publish-pypi` job** using PyPA trusted publishing
  (no PyPI API token needed — keyless OIDC exchange). Builds both
  sdist and wheel from `sdk/python/` and uploads on every `v*.*.*`
  tag. `skip-existing: true` so a re-run on the same version is a
  no-op rather than a hard failure.

### Operator action required

- Before tagging `v0.1.0-rc.3`, configure a **pending publisher**
  on [pypi.org](https://pypi.org/manage/account/publishing/):
  project = `singleaxis-fabric`, owner = `ai5labs`, repo =
  `singleaxis-fabric`, workflow = `release.yml`. Takes ~2 min and
  is only needed once; after the first successful publish PyPI
  promotes it to a regular trusted publisher automatically.

## [0.1.0-rc.2] - 2026-04-23

Re-cut of `0.1.0-rc.1` to exercise the signing path end-to-end. No
functional changes to Fabric itself — same code, same charts, same
SDK — only a release-pipeline fix so chart signatures actually land.

### Fixed

- **`release.yml` / `publish-chart`**: cosign sign was hitting
  `GET /ghcr.io/token ... UNAUTHORIZED` on `rc.1`. `helm registry login`
  writes to `~/.config/helm/registry/config.json`; cosign reads
  `~/.docker/config.json`. Added a `docker/login-action` step before the
  sign step so cosign can pull the just-pushed manifest by digest.
  `publish-image` was already doing this — `publish-chart` just never
  was.

### Known issues

- Carried forward from `rc.1`: `OpenSSF Scorecard` currently fails on
  `main` because top-level `security-events: write` trips
  scorecard-action's workflow verification. Cosmetic, not
  release-blocking. Will be cleaned up before `0.1.0`.

## [0.1.0-rc.1] - 2026-04-20

First public pre-release of SingleAxis Fabric — the Layer-1 OSS substrate
for audit-ready AI agents. This release cut is a release candidate: the
code, charts, and SDK are frozen against this tag so operators can
install, inspect, and file issues, but the release pipeline itself
(cosign signing, SBOM attachment, GHCR image + chart push) has not yet
been exercised against a real tag. See Known issues below.

### Added

- **Umbrella Helm chart `charts/fabric`** with five optional Layer-1
  subcharts gated by `*.enabled` toggles so operators can start with
  just the collector and layer on guardrails/observability/red-team as
  the deployment matures
  (`008-deployment-model.md` (removed)):
  - `otel-collector` — Fabric OTel Collector distribution with the
    `fabricguard`, `fabricpolicy`, `fabricsampler`, and `fabricredact`
    processors.
  - `nemo-sidecar` — NeMo Colang inline guardrails sidecar, Deployment
    form for dev; per-pod sidecar injection lands in Phase 2
    (`005-guardrails-inline.md` (removed)).
  - `langfuse` — single-Deployment Langfuse v2 wrapper as the default
    observability sink; tenants at scale swap in the upstream chart.
  - `redteam-runner` — CronJob running Garak + PyRIT against the
    tenant's agent endpoint, emitting results as OTel spans. Opt-in
    (see Security below).
  - `update-agent` — ValidatingAdmissionWebhook over `fabric-system`
    that denies resources whose Fabric signature / version / schema
    annotations don't verify.
- **Two ship-ready regulatory profiles** (`charts/fabric/profiles/`):
  - `permissive-dev` — minimum-viable path for local clusters.
  - `eu-ai-act-high-risk` — fail-closed redact provider, signed updates,
    observability required
    (`009-compliance-mapping.md` (removed)).
- **Python SDK `singleaxis-fabric`** (`sdk/python`) with inline guardrails,
  decision/escalation helpers, Presidio + NeMo clients over UDS,
  HMAC-signed sampler hints, retrieval/memory wrappers, OTel tracing,
  and orchestration adapters for LangGraph, Microsoft Agent Framework,
  and CrewAI as opt-in extras
  (`011-roadmap.md` (removed)).
- **Six Python components** with matching Docker/Helm surfaces:
  `presidio-sidecar`, `nemo-sidecar`, `langfuse-bootstrap`,
  `redteam-runner`, `update-agent`, plus the OTel collector
  distribution under `components/otel-collector-fabric`
  (Go / OCB-built).
- **Go Telemetry Bridge** scaffold under `_internal/` as the Layer-2
  ingest path (`004-telemetry-bridge.md` (removed));
  not shipped in the public OSS release.
- **Release pipeline** (`.github/workflows/release.yml`): CI-green gate
  on the tagged SHA, tag-must-be-on-main check, CHANGELOG extraction,
  SPDX + CycloneDX SBOMs, cosign-keyless-signed source archive, signed
  multi-arch collector image to GHCR, signed Helm chart push to GHCR
  OCI, SLSA build-provenance attestations, and a draft GitHub Release.
- **Design-of-record specs** (`specs/000-overview.md` through
  `specs/011-roadmap.md`) covering product vision, architecture,
  Decision Graph, Telemetry Bridge, guardrails, judges, escalation,
  deployment, compliance mapping, development standards, and
  roadmap.

### Changed

- CI scaffolding graduated to enforceable gates: lint + test + security
  scan + DCO, with the release workflow hard-requiring a successful
  `ci.yml` run on the tagged SHA before any artifact is built.

### Security

- **Ed25519 manifest verification** — `update-agent` refuses any
  resource whose Fabric signature does not verify against the
  installed trusted key; the default placeholder
  `REPLACE_AT_INSTALL_TIME` causes the webhook to fail closed until
  operators install a real key
  (`008-deployment-model.md` (removed)).
- **Fabric-canonical JSON** for signable manifest bytes so verification
  is deterministic across producers.
- **HMAC-signed sampler hints** — SDK-emitted sampling hints carry an
  HMAC the `fabricsampler` processor validates before honouring, so
  downstream callers can't forge sampling decisions.
- **PII redaction via UDS** — `fabricredact` processor requires an
  `existingSocketProvider` pointing at a Presidio-compatible redaction
  socket and fails closed unless the operator explicitly sets
  `acceptMissingProvider=true` (dev-only escape hatch).
- **Admission webhook gates** — the `update-agent` webhook must admit a
  resource for it to apply in `fabric-system`; signature, version, and
  schema annotations are all required.
- **Supply chain** — release pipeline produces SPDX + CycloneDX SBOMs,
  keyless cosign signatures via Fulcio for the source archive / image /
  chart, and GitHub attestations for SLSA build provenance. Images are
  signed by immutable digest.
- **Red-team runner opt-in** — `redteamRunner.enabled` defaults to
  false because the CronJob launches live adversarial traffic against
  the tenant's own endpoint; operators must set the flag explicitly.
- **CHANGELOG-must-exist gate** — the release workflow's `changelog`
  job fails loudly if no `## [<version>]` section exists, refusing to
  publish a release with a placeholder body.

### Known issues

- **Single maintainer.** Bus factor of one. Issue triage and PR review
  SLOs are best-effort until a second maintainer is on-board
  ([MAINTAINERS.md](MAINTAINERS.md)).
- **GHCR images and charts do not yet exist.** The
  `ghcr.io/ai5labs/fabric-otelcol` image and the `charts/otel-collector`
  Helm OCI artifact are published by the release workflow; until this
  tag is cut and the workflow succeeds end-to-end, neither is
  resolvable. Installs that pull these refs will fail until first
  successful release.
- **Release pipeline is untested against a real tag.** `release.yml`
  has been linted and shape-reviewed but has never run against an
  actual `v*.*.*` tag. The first cut of `v0.1.0-rc.1` is also the
  first live exercise of cosign + SBOM + SLSA + OCI chart push; expect
  workflow-level fixes in subsequent rc's.
- **Saved views are render-only.** The umbrella chart lints and renders
  against both shipped profiles, but there is no in-cluster E2E test
  yet — no smoke test harness spins up the collector + sidecars + a
  reference agent and asserts end-to-end guardrail + telemetry flow.
  That lands before `v0.1.0` final.
- **Phase-1a scope.** Judge-workers, escalation-service,
  decision-graph, telemetry-bridge, and NATS broker are not part of
  this distribution; operators deploying the OSS umbrella get
  inline guardrails + collector + opt-in red-team, not the full
  async judge loop.


[Unreleased]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.12.1...HEAD
[0.12.1]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.11.2...v0.12.0
[0.11.2]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.11.1...v0.11.2
[0.11.1]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.8.0-rc.2...v0.8.0
[0.8.0-rc.2]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.8.0-rc.1...v0.8.0-rc.2
[0.8.0-rc.1]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.7.1...v0.8.0-rc.1
[0.7.1]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.6.0
[0.5.1]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.5.1
[0.5.0]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.5.0
[0.4.1]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.4.1
[0.4.0]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.4.0
[0.2.0]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.2.0
[0.1.2]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.2
[0.1.1]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.1
[0.1.0]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0
[0.1.0-rc.6]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.6
[0.1.0-rc.5]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.5
[0.1.0-rc.4]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.4
[0.1.0-rc.3]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.3
[0.1.0-rc.2]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/singleaxis/singleaxis-fabric/releases/tag/v0.1.0-rc.1
