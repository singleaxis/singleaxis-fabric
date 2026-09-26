# Run, Variant, Artifact, and Outcome Capture — Change List

> **Status: SUPERSEDED — historical design document, do not implement.**
> This plan predates the recorder-v1 scope (`specs/027-recorder-v1.md`).
> It describes evaluation/judge surfaces, a tenant judge queue, and a
> Telemetry Bridge projection — these are **not part of recorder v1** and
> do not belong to the OSS recorder (`CAPTURE -> PROTECT -> DELIVER`).
> Retained as design history only.

**Status:** superseded (historical design plan)
**Date:** 2026-07-13
**Scope:** public `singleaxis-fabric` capture layer, with named internal dependencies

## Objective

Give companies building agentic systems one consistent way to:

- monitor execution health, latency, cost, retries, and side effects;
- identify the exact harness, models, prompts, tools, policies, and environment
  used by a run;
- inspect textual and non-textual outputs at every operation;
- evaluate real task outcomes rather than only the final assistant message;
- compare variants such as frontier planner + small executor versus one
  frontier model;
- reproduce and explain why one variant performs better for a class of tasks.

The public SDK captures facts. The commercial control plane aligns runs,
resolves authorized evidence, evaluates, compares, recommends, and reports.

## Existing foundation

Do not create a parallel telemetry model. Reuse these existing primitives:

- `fabric.execution` as the outer run and correlation span;
- `fabric.decision` and child LLM/tool spans as the operation graph;
- `fabric.execution_id`, workflow, attempt, and retry lineage;
- step ids and retry metadata;
- tool, retrieval, memory, interaction, checkpoint, side-effect, and replay
  records;
- `ContentStore` and content-addressed integrity hashes;
- synchronous/queued evaluation and policy events;
- Python/TypeScript conformance goldens and the OTel collector.

The gaps are first-class variant identity, caller-declared model roles, binary
artifacts, real-world outcomes, evidence references across every operation,
current OTel GenAI semantics, and end-to-end projection into the comparison
control plane.

## Canonical terminology

| Term | Meaning |
|---|---|
| **Execution** | One run. Keep `fabric.execution_id` as the canonical run id. |
| **Variant** | Immutable harness + model-role assignments + prompt/tool/policy sets. |
| **Task case** | The input fixture/business task against which variants are compared. |
| **Operation** | One addressable span: agent, LLM, tool, retrieval, memory, or control. |
| **Artifact** | Text, workbook, document, image, file, database snapshot, or other output. |
| **Outcome check** | Versioned verifier result establishing whether the task succeeded. |
| **Benchmark** | A set of task cases executed across variants; aggregated internally. |

`comparison_id`, win rate, rankings, and recommended variant are derived
commercial records. They do not need to be emitted by the agent SDK.

## P0 — Capture contract required for trustworthy comparison

### 1. Add a public specification

Author a new public spec defining:

- `VariantManifest`, `ModelAssignment`, `EnvironmentSnapshot`, `ArtifactRef`,
  `OutcomeCheck`, and generalized `EvidenceRef`;
- Python/TypeScript wire parity;
- privacy and storage behavior;
- schema evolution and conformance scenarios;
- which properties live on the execution span versus external manifests.

Do not add every manifest field as a queryable span attribute. Put only stable,
low-cardinality identifiers and hashes on spans; store the full manifest in
tenant-controlled storage.

### 2. Extend `fabric.execution` into a comparable run

Files:

- `sdk/python/src/fabric/execution.py`
- `sdk/python/src/fabric/client.py`
- `sdk/python/src/fabric/_attributes.py`
- `sdk/typescript/src/execution.ts`
- `sdk/typescript/src/attributes.ts`

Add optional, additive inputs:

```python
with fabric.execution(
    execution_id="run-123",
    task_case_id="invoice-reconciliation-v4/case-018",
    variant=variant_manifest,
    environment=environment_snapshot,
) as run:
    ...
```

Execution span attributes:

```text
fabric.task.case_id
fabric.variant.id
fabric.variant.manifest_ref
fabric.variant.manifest_hash
fabric.harness.name
fabric.harness.version
fabric.harness.revision
fabric.environment.id
fabric.environment.fingerprint
```

`variant_id` MUST be content-addressed or supplied with an immutable manifest
hash. Reusing an id for different configuration is invalid.

### 3. Add `VariantManifest`

Create a small public model module, for example
`sdk/python/src/fabric/variant.py`, containing:

```text
VariantManifest
  harness: name, version, revision, manifest hash/ref
  model_assignments[]
  prompt_set: id, version, hash/ref
  tool_set: id, version, hash/ref
  policy_set: id, version, hash/ref
  memory_strategy: id, version
  orchestration_parameters
  created_at
```

`ModelAssignment` contains a caller-declared role such as `planner`,
`executor`, `critic`, or `summarizer`, plus requested provider/model and safe
generation parameters. Role is open vocabulary; Fabric MUST NOT infer that a
call is planning from span order or prompt text.

Secrets, raw prompts, credentials, and tool schemas stay out of the span and
manifest body. Use content references and hashes.

### 4. Modernize every LLM span

Files:

- `sdk/python/src/fabric/_calls.py`
- `sdk/python/src/fabric/decision.py`
- TypeScript equivalents

Add to `Decision.llm_call(...)`:

```python
with decision.llm_call(
    provider="openai",
    model="...",
    role="planner",
    operation_name="chat",
) as call:
    ...
```

Emit current OTel GenAI semantics:

```text
gen_ai.operation.name
gen_ai.provider.name
gen_ai.request.model
gen_ai.response.model
gen_ai.usage.*
fabric.model.role
fabric.variant.id
```

Migrate from legacy `gen_ai.system` while providing a documented compatibility
window. The requested model comes from the call; the actual served model is
recorded from the response.

### 5. Generalize content storage to binary artifacts

Current `ContentStore.put` accepts only `str`, which cannot safely represent an
XLSX, image, PDF, or arbitrary tool-created file.

Add a backwards-compatible binary protocol, either by extending the existing
store or introducing `ArtifactStore`:

```python
put_bytes(
    data: bytes,
    *,
    media_type: str,
    key_hint: str | None = None,
    metadata: Mapping[str, str] | None = None,
) -> ArtifactRef
```

`ArtifactRef`:

```text
artifact_id
kind
role: input | intermediate | output
uri
sha256
size_bytes
media_type
schema_version
semantic_manifest_ref
capture_status
producer_trace_id
producer_span_id
```

Capture states are mandatory:

```text
captured | redacted | truncated | not_captured | store_failed
```

Never silently omit evidence when storage fails.

### 6. Add artifact recording to `Execution` and operations

Add:

```python
run.record_artifact(...)
tool.set_output_artifact(...)
decision.record_artifact(...)
```

Emit an additive `fabric.artifact` event or span with references and integrity
metadata only. The artifact bytes never enter the OTel stream.

Artifacts MUST be attachable to an exact producer span. This allows the
comparison UI to show the workbook or document version produced at each step,
not only the final file.

### 7. Attach evidence references to every evaluatable operation

Today content references are applied mainly to guardrail/policy inputs. Extend
them consistently to:

- LLM instructions, input messages, output messages, and tool definitions;
- tool arguments and results;
- retrieval query and each retrieved document/chunk including score/metadata;
- memory query and records read/written;
- side-effect request, result, approval, and observed external state;
- generic interaction payloads;
- input, intermediate, and final artifacts.

Use a shared evidence envelope instead of inventing a different ref field for
every primitive.

### 8. Make tool, retrieval, and memory operations independently evaluatable

Emit real child spans using standard logical operations where available:

```text
execute_tool
retrieval
search_memory
upsert_memory
```

Keep existing Fabric events during a compatibility window, but a reviewer
must be able to address each logical operation by `trace_id` + `span_id`, attach
evidence, and write an evaluation result against it.

### 9. Add real-world outcome capture

Extend `Execution` with explicit outcome APIs:

```python
run.set_outcome(
    status="succeeded" | "failed" | "partial" | "cancelled",
    summary_ref=...,
)

run.record_check(
    check_id="totals-match-source",
    verifier="xlsx-formula-verifier",
    verifier_version="1.2.0",
    status="pass" | "fail" | "error" | "not_applicable",
    score=1.0,
    expected_ref=...,
    observed_ref=...,
    evidence_refs=(...),
)
```

Execution completion without an exception is operational success, not proof
that the business task succeeded. Keep these statuses separate.

### 10. Add a verifier protocol

Define a public extension protocol so ecosystems can provide deterministic
task verifiers without depending on the commercial control plane:

```python
class OutcomeVerifier(Protocol):
    name: str
    version: str
    def verify(self, task: TaskCase, artifacts: Sequence[ArtifactRef]) -> Sequence[OutcomeCheck]: ...
```

Verifier results are capture facts and belong in OSS. Benchmark aggregation,
ranking, and recommendations remain internal.

### 11. Emit standard evaluation results with exact targets

Update `record_eval`/judge contracts to support:

```text
target_trace_id
target_span_id
scope: span | trace | artifact | outcome
rubric_id + version
evaluator_name + version
score value/label
explanation_ref
evidence refs actually used
```

Emit `gen_ai.evaluation.result` where applicable and dual-emit `fabric.eval`
during migration. A trace-level score must not replace per-span evaluation.

### 12. Fix collector content-egress controls before broader capture

The Helm trace pipeline currently applies `fabricguard` without
`fabricredact`, and the trace namespace allowlist permits all `gen_ai.*`
attributes. Before enabling richer capture:

- deny raw standard GenAI content attributes from untrusted trace egress;
- add trace redaction or a dedicated content-stripping processor;
- allow only references, hashes, capture states, and approved scalar metadata;
- add zero-leak tests for messages, tool arguments/results, retrieval
  documents, memory records, and artifact bytes;
- route the tenant-local evaluation destination separately from external
  observability exporters.

## P1 — Real-world artifact adapters

### 13. Add an XLSX semantic artifact adapter

Create an optional package such as `fabric.artifacts.xlsx`.

It should produce a normalized semantic manifest containing:

- workbook and sheet structure;
- cells changed, values, formulas, and number formats;
- tables, named ranges, charts, pivots, and data validations;
- formula errors and broken references;
- macros/external links/data connections as declared capabilities;
- unexpected changes outside allowed ranges;
- optional rendered-sheet image references.

Do not compare XLSX ZIP bytes as the quality signal; archive metadata may
change without a meaningful workbook change.

Capture the Excel/runtime version, calculation mode, locale, timezone, and
recalculation state in `EnvironmentSnapshot`.

### 14. Add generic file/document/image/database adapters

Use the same artifact contract for:

- DOCX/PDF semantic structure and rendered pages;
- images/screenshots and vision-evaluation inputs;
- code patches and repository state;
- browser DOM/screenshot state;
- database schema/query snapshots;
- CRM/ticketing state before and after side effects.

Adapters produce manifests and checks; they do not change the core trace
model.

### 15. Add task-case fixtures

Define a portable `TaskCase` manifest:

```text
case_id + version
instruction_ref/hash
initial_artifacts[]
environment_fixture_id/fingerprint
allowed capabilities
forbidden side effects
expected outcome-check definitions
rubric set
```

Comparable runs must use the same task-case version and initial environment
fingerprint, or the comparison UI must flag them as non-equivalent.

## P1 — Schema, parity, and projection

### 16. Update conformance schemas and goldens

Add Python and TypeScript scenarios for:

- variant manifest identity and execution inheritance;
- planner/executor model roles;
- text and binary artifact references;
- all capture-status values including `store_failed`;
- span-targeted and trace-targeted evaluations;
- task outcomes and deterministic checks;
- backward compatibility when the new APIs are unused.

Update `fabric.schema_version` only according to the compatibility policy;
additive fields should not silently break existing goldens.

### 17. Update the Telemetry Bridge projection

The committed trace remains canonical. The bridge should derive sanitized
summaries containing:

- execution/run id, task-case id, and variant id;
- harness/model-role summary;
- artifact kinds and capture completeness, never artifact bytes;
- task outcome and check aggregates;
- cost, latency, token, retry, and side-effect aggregates;
- originating W3C trace/root span ids.

The current local bridge transform is untracked and Fabric-name-specific. It
must be committed in the correct repository, updated to normalize standard
OTel operations, and tested against the canonical schemas.

### 18. Preserve dual-destination routing

Collector/deployment configuration needs explicit destinations:

```text
observability export: safe metadata only
tenant evaluation ingest: complete operation graph + evidence refs
tenant judge queue: bounded raw/encrypted context or authorized refs
optional external bridge: sanitized projections only
```

Document and test every egress path.

## Internal control-plane dependencies

These do not belong in the public SDK, but public capture is incomplete until
an integration test proves them:

1. Persist spec 024 Evaluation Ingest traces/evaluations in Postgres.
2. Materialize full operation/span hierarchy into the Decision Graph.
3. Add a Variant Catalog keyed by immutable manifest hash.
4. Add an Artifact Metadata Index and audited Evidence Resolver.
5. Make judge tasks target span, trace, artifact, or outcome-check records.
6. Add a Benchmark service to schedule task-case × variant matrices.
7. Add the Comparison Workbench with aligned waterfall, evidence diffs,
   artifact-specific views, and comparative evaluation.
8. Compute win/tie/loss, quality distributions, task success, failure modes,
   cost per success, latency, and robustness by variant/task segment.
9. Recommend variants only for a declared task segment and sample size; never
   emit a universal “best model” conclusion.
10. Seal the canonical records and references into the Evidence Bundle.

## P2 — Monitoring and operational experience

### 19. Add capture-completeness metrics

Expose by tenant/service/variant:

- traces received and rejected;
- incomplete parent graphs;
- evidence captured/redacted/truncated/not-captured/store-failed;
- artifact storage latency/failures;
- judge queue age and failures;
- outcome-check pass/fail/error;
- unresolvable evidence references;
- schema/semantic-convention version drift.

### 20. Add quality and efficiency views

The control plane should separate:

- operational health: errors, latency, retries, cost, queue depth;
- process quality: tool choice, retrieval relevance, policy compliance;
- artifact correctness: semantic verifier results;
- task outcome: succeeded/partial/failed;
- comparative quality: human/automated scores and pairwise preference.

Do not collapse these into one opaque score.

## Ordered implementation sequence

1. Public spec and canonical models.
2. Variant manifest + execution/task-case identity.
3. Current GenAI semantics + caller-declared model roles.
4. Binary `ArtifactStore`/`ArtifactRef` and shared evidence envelope.
5. Evidence refs and capture states on every operation.
6. Artifact and outcome/check APIs.
7. Tool/retrieval/memory child spans and targeted evaluation results.
8. Collector zero-leak and dual-destination routing.
9. Python/TypeScript conformance parity.
10. Evaluation Ingest durable store and Decision Graph projection.
11. XLSX reference adapter and deterministic workbook verifier.
12. Variant catalog, benchmark scheduling, and Comparison Workbench.
13. Full cluster golden path and evidence sealing.

## Required golden-path acceptance tests

### Text comparison

- Run the same task case with at least two variants.
- One variant uses a frontier planner and small executor; another uses a
  frontier model for both roles.
- Verify model roles and actual served models are visible on exact spans.
- Compare input, context, tool calls, intermediate output, final output, cost,
  latency, span scores, and trace score.

### Excel comparison

- Start both variants from the same workbook hash and environment fingerprint.
- Capture each tool operation and intermediate workbook artifact.
- Store final XLSX artifacts and normalized semantic manifests.
- Verify formulas, values, formatting, charts, required changes, forbidden
  changes, and calculation errors.
- Grade process, artifact, outcome, safety, and efficiency separately.
- Confirm the final assistant text cannot cause a failed workbook to pass.

### Privacy and resilience

- Prove no raw prompt, tool payload, retrieved document, memory record, or
  artifact bytes reach the external observability/bridge destination.
- Deny cross-tenant artifact resolution and audit every allowed read.
- Make artifact storage fail and verify `store_failed` remains visible.
- Restart collector/ingest/judge services and preserve the complete run.
- Replay identical events idempotently and reject conflicting manifests.

## Definition of done

Companies can instrument one execution once and use the resulting record for
monitoring, debugging, human review, automated evaluation, artifact
verification, run comparison, benchmarking, and evidence export without
provider-specific parsing or a separate logging integration.
