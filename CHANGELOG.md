# Changelog

All notable changes to SingleAxis Fabric will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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
  [`docs/capturing-interactions.md`](docs/capturing-interactions.md).
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
  ([008-deployment-model.md](specs/008-deployment-model.md)):
  - `otel-collector` — Fabric OTel Collector distribution with the
    `fabricguard`, `fabricpolicy`, `fabricsampler`, and `fabricredact`
    processors.
  - `nemo-sidecar` — NeMo Colang inline guardrails sidecar, Deployment
    form for dev; per-pod sidecar injection lands in Phase 2
    ([005-guardrails-inline.md](specs/005-guardrails-inline.md)).
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
    ([009-compliance-mapping.md](specs/009-compliance-mapping.md)).
- **Python SDK `singleaxis-fabric`** (`sdk/python`) with inline guardrails,
  decision/escalation helpers, Presidio + NeMo clients over UDS,
  HMAC-signed sampler hints, retrieval/memory wrappers, OTel tracing,
  and orchestration adapters for LangGraph, Microsoft Agent Framework,
  and CrewAI as opt-in extras
  ([011-roadmap.md](specs/011-roadmap.md)).
- **Six Python components** with matching Docker/Helm surfaces:
  `presidio-sidecar`, `nemo-sidecar`, `langfuse-bootstrap`,
  `redteam-runner`, `update-agent`, plus the OTel collector
  distribution under `components/otel-collector-fabric`
  (Go / OCB-built).
- **Go Telemetry Bridge** scaffold under `_internal/` as the Layer-2
  ingest path ([004-telemetry-bridge.md](specs/004-telemetry-bridge.md));
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
  ([008-deployment-model.md](specs/008-deployment-model.md)).
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


---

[Unreleased]: https://github.com/singleaxis/singleaxis-fabric/compare/v0.5.1...HEAD
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
