# Devin implementation brief: governed capture for production audit and evaluation

## Task and intended outcome

Extend SingleAxis Fabric so a customer can explicitly enable capture of actual model inputs,
outputs, and observable context into customer-controlled storage. Authorized downstream reviewers
and evaluation harnesses must be able to reconstruct the recorded interaction and verify its content
integrity. Preserve metadata-only operation as the default.

Write the design documents and acceptance criteria FIRST. Then implement against them, test the
actual packaged artifacts, and deliver a reviewable change. Do not stop after drafting the
documents. Do not describe a draft or untested capability as implemented.

The product remains CAPTURE -> PROTECT -> DELIVER. Evaluation engines, judges, findings, enterprise
policy authoring, and runtime enforcement remain outside Fabric OSS. Content capture and retrieval
interoperability support external evaluators; they do not bring an evaluation service into the
recorder.

## Product positioning to incorporate

A recording plane is necessary for reliable production review when equivalent recording does not
already exist, but is not sufficient for evaluation. Fabric itself is optional: an existing customer
system can supply these capabilities.

Development and offline evaluation do not require Fabric. A harness can record and read its own
local transcripts directly. Do not route those transcripts through a content-stripping collector or
require production infrastructure for local evaluation. Offline datasets can still require privacy,
access, and retention controls; do not claim they inherently have no security or durability
concerns.

Metadata-only export supports operational and structural review: calls, timing, usage, retries,
relationships, and reported outcomes. It cannot support content-level judgments about correctness,
grounding, instruction following, leakage, or tool appropriateness without separately accessible
content.

Content evaluators must run where the content is authorized to be read, or use an explicitly
authorized content-access path. Merely changing collector settings does not recover content that was
never captured. Keeping OTLP metadata-only is compatible with deep review when authorized consumers
can resolve governed content references. Verifiability and content visibility are not inherently
mutually exclusive.

## Current implementation and gaps to verify

Inspect the current checkout before implementing. There are pre-existing edits; preserve them. The
following findings describe the checkout examined for this brief, not a guarantee about a later
branch.

| Area | Existing foundation | Work required |
|---|---|---|
| Trace capture | Python/TypeScript SDKs, model/tool spans, surface events, source identity and correlation | Bind actual content objects to the exact operation, attempt, and content role |
| Protection | Exact attribute allowlists, native OTLP text scrubbing, metadata-only production profile | Preserve this protection while creating a separately governed content path |
| Python content storage | `ContentStore`, `ContentRef`, local filesystem and S3 adapters | Extend the primitives into a documented, reliable production path |
| Python content wiring | Memory and side-effect methods call the content store | Complete model inputs/outputs, system instructions, tools, retrieval and relevant context coverage |
| Raw content options | `capture_content` / `captureContent` can emit raw model/tool content into spans | Resolve compatibility deliberately; raw span emission is not governed evidence storage and is stripped by Fabric Node |
| TypeScript | Metadata capture and raw content flags | Equivalent governed storage, write lifecycle, references and resolution contracts |
| Store behavior | Synchronous `put`, URI plus hash; Python helper logs write failure and omits ref | Bounded asynchronous capture, durable handoff where promised, retry, explicit gaps and completion status |
| Local/S3 adapters | Content-addressed object writes | Tenant isolation, atomicity, exact-byte hashing, overwrite/corruption checks, storage policy and explicit guarantees |
| Consumer access | Reference attributes admitted by collector | Authorized resolution, integrity verification, deterministic transcript reconstruction and export |
| Contracts/config | Recorder content modes, Activity Envelope, privacy/delivery contracts | Executable mode configuration and content lifecycle contracts; configuration presence is not proof of runtime behavior |

Start with these sources:

- `AGENTS.md`, `specs/027-recorder-v1.md`, `specs/README.md`.
- `sdk/python/src/fabric/content_store/{base,local,s3}.py`.
- `sdk/python/src/fabric/{client,decision,_calls}.py` and content-store tests.
- `sdk/typescript/src/{client,decision,calls}.ts`.
- `components/otel-collector-fabric/processor/fabricguardprocessor/{allowlist,processor}.go`.
- `contracts/{activity,connect,privacy,delivery,recorder}`.
- Current SDK packaging qualifiers, recorder artifact-boundary tests and deployment profiles.

A local file existing or an S3 write acknowledgment must not automatically become a claim of
immutable evidence, complete capture, or guaranteed retention. Current hashes and source identifiers
also do not establish source truth or independently verified identity.

## Phase 1 — documentation before implementation

Create a gap assessment with file/function evidence and a requirements-to-test matrix. Write these
five specifications, using available numbers after checking the repository; do not assume this brief
assigns final spec numbers:

1. **Governed content capture and configuration.** Modes, activation, supported content roles,
   capture boundaries, compatibility, consent/configuration scope, limits and exclusions.
2. **Content object and transcript contracts.** Versioned object/reference schemas, exact bytes,
   integrity, correlation, ordering, completeness and missing-data semantics.
3. **Passive capture and durable content delivery.** Async lifecycle, bounded resources, ownership
   transfer, retries, crash recovery, reference publication and failure behavior.
4. **Customer storage and authorized resolution.** Local/S3 support, identity, isolation,
   encryption, access, retention, deletion and verifiable reads.
5. **External evaluation interoperability and qualification.** Transcript export, an offline
   example, production integration, test gates and honest coverage documentation.

Each spec must state goals/non-goals, API/config/schema changes, compatibility, failure semantics,
acceptance tests and rollout. Include at least one complete model -> tool -> model transcript
example and one incomplete transcript.

Update product and capture documentation to distinguish metadata-only, governed content, and
harness-owned offline transcripts. Reconcile governed content with spec 027 and AGENTS.md
explicitly: this extends customer-controlled recording; it does not introduce evaluation or control
services. Locate the internal product-direction document if available; if it is unavailable, record
that fact and any unresolved product conflict rather than inventing approval. Follow repository
governance for spec acceptance and release; do not falsely mark a proposal accepted. Continue
implementation in a reviewable branch where allowed.

Commit or otherwise present the documentation as a distinct reviewable change before runtime
implementation. This task authorizes the implementation; routine API choices do not require repeated
permission requests.

## Phase 2 — required implementation

### A. Explicit capture modes and coverage

Keep metadata-only as the zero-configuration default. Provide an explicit governed-content mode
referencing customer storage and capture policy. Align configuration spellings with the existing
contracts or version them; do not silently reinterpret existing flags.

In governed mode, support the following when exposed by the caller or adapter:

- The effective model request: ordered messages and roles, system/developer instructions where
  exposed, relevant conversation history, tool definitions, model parameters and provider/model
  identifiers.
- Model outputs: structured messages, generated tool calls, finish state, streamed output assembly,
  and partial output on failure/cancellation.
- Tool requests and responses: actual serialized arguments/results and association with the
  model-issued tool call and specific attempt.
- Retrieval: query, supplied result content, source/document identifiers and versions,
  ordering/rank, and an explicit relationship to the model request that used it.
- Relevant memory reads/writes and side-effect requests/results.
- Explicitly supplied files or other context with media type and bytes/reference. For v1, define a
  clear supported text/JSON scope and explicit unsupported markers for binary/multimodal content if
  full support is deferred.

Record what actually crossed an observable boundary. Do not reconstruct missing system prompts,
invent hidden provider context, or claim access to hidden reasoning. A retrieval result is not proof
the model received it; the recorded effective request provides that evidence where visible.

Provide a coverage matrix for manual SDK APIs and each supported adapter. Wire at least the existing
first-party model/tool paths and a maintained integration end to end. Do not promise every
provider/framework automatically works.

### B. Versioned objects, manifests and completeness

Define an immutable versioned content-object descriptor with opaque object ID, tenant scope, content
role, media type, encoding, byte length, integrity digest, capture time and representation. Bind it
to trace/span, execution/decision, step, attempt and tool-call identity where available. Preserve
source provenance instead of upgrading assertions to observations.

Specify exact-byte hashing and serialization in both languages, including Unicode, JSON ordering,
empty versus absent values and streaming assembly. Hash the precise representation returned to the
consumer. When content is transformed, distinguish the captured and stored representations and their
digest scopes; never verify redacted bytes against an original-content digest.

Use a transcript manifest with ordered references and explicit statuses: pending, available, not
captured, redacted, truncated, dropped, failed, expired/deleted and unsupported as appropriate.
Define which are lifecycle states versus completeness reasons. Missing content must never look like
an empty input or successful complete capture.

Do not infer causal order from timestamp sorting alone. Preserve message order, source sequences and
explicit links; retain uncertainty for concurrent or uncorrelated events. Export completeness and
coverage information with every transcript.

### C. Passive asynchronous recording and delivery

Move object-store I/O off model/tool execution paths. Define bounded CPU, memory, enqueue time,
payload size and queue capacity, with flush/shutdown behavior and an opt-in awaitable flush for
tests and graceful shutdown. Snapshot mutable inputs safely at capture time.

Specify the durability boundary precisely. A nonblocking in-process enqueue is not a durable
acknowledgment. There is an unavoidable interval in which process failure can lose buffered content
unless a durable handoff has completed. Document it and expose completeness/gap reporting. Do not
claim zero overhead, zero loss and unconditional nonblocking behavior simultaneously.

Provide bounded retries and durable local spooling for the production content path where promised,
with protected local storage, crash recovery, idempotent delivery and explicit terminal failures.
Destination outage, disk full, quota exhaustion or content rejection must not change application
output or authorization decisions. Do not silently discard content while reporting a complete
transcript.

Solve the two-destination consistency problem explicitly: OTLP metadata can arrive before its
content object or vice versa. Use stable pending references and a resolvable manifest/state
mechanism or another documented design. Publish availability only after successful storage;
distinguish pending and permanently unavailable references. Define orphan cleanup and retention
without making atomic cross-store delivery claims.

### D. Storage, access and protection

Support a local adapter for development and an S3-compatible production adapter in both SDK
ecosystems, or a shared customer-side writer with equivalent SDK access. Choose and justify one
architecture in Phase 1; do not add a new mandatory runtime for metadata-only users.

Keep tenant namespaces and authorization separate even for identical content. Use opaque externally
exposed references; never embed credentials or signed bearer URLs in telemetry. Scope digest-based
deduplication and document content-fingerprint leakage risks. Treat digests as integrity checks, not
authorization.

Local writes must be atomic and validate pre-existing objects rather than trusting a hash-named
file. Production storage must support customer encryption/access settings and validate required
configuration. Use existing cloud IAM/KMS capabilities where suitable; do not build a new enterprise
identity system. Define retention/deletion behavior and how expired references resolve. Retention
claims must reflect actual storage settings.

Provide an authorized resolver/library and CLI or equivalent export command. Verify object size and
digest before returning content. Allow only configured stores and namespaces; a telemetry-provided
URI must not grant arbitrary network or filesystem access. Test cross-tenant access, traversal and
unapproved-host rejection.

Document the content protection policy separately from OTLP protection. Saving approved raw content
requires explicit authorization and storage controls. If transformation/redaction is supported,
specify it exactly and record it; do not claim universal PII detection. Content mode must not bypass
the collector allowlist. Secrets/content must not leak into error logs or queue diagnostics.

### E. External evaluator integration

Deliver a versioned JSON/JSONL transcript export containing readable inputs, outputs, context and
tool interactions plus provenance, integrity and completeness information. External tools must be
able to consume it without SingleAxis Platform or a Fabric evaluation service.

Provide a small example consumer that reads an authorized transcript and runs a deterministic
assertion demonstrating content access, plus a harness-owned local transcript example that does not
install/run Fabric Node. Keep these examples outside production recorder runtime artifacts.

Document that content enables richer evaluation but does not establish correctness on its own:
grading criteria, expected outcomes, provenance and evaluator design still matter. The resolver must
not execute tools, replay side effects or claim deterministic replay.

### F. Packaging and migration

Make Python and TypeScript governed-content behavior equivalent at the public API/contract level.
Keep storage dependencies optional. Extend packaging tests to prove the new APIs are shipped and
evaluation/control services remain absent. Update connector capabilities, examples, schema fixtures,
manifest digests, SDK docs, configuration validation and qualification status.

Existing metadata users must retain their behavior. Explicitly document the migration from raw span
flags; never silently enable content persistence for existing users. Do not loosen default OTLP
protection to make tests pass.

## Release acceptance gates

1. Metadata-only mode writes no content objects and exports no raw payloads.
2. In a synthetic model -> tool -> model flow, an authorized consumer retrieves the actual
   instructions, input messages, output, tool arguments/results and supplied context, byte-verified
   and linked to the right attempt.
3. The same flow produces correct references through the real Fabric Node while raw values are
   absent from protected OTLP, collector logs and the metadata queue.
4. Python and TypeScript pass shared contract and byte/hash fixtures, including Unicode, structured
   output, retries, empty input and partial streams.
5. Every requested capture surface is either demonstrated or marked unsupported/missing; no silent
   claims of full coverage.
6. Source mutation after capture does not change recorded content. Concurrent calls remain distinguishable.
7. Store outage, worker crash, recorder restart, queue exhaustion, disk full and shutdown produce
   the documented retry/gap behavior while preserving application behavior. Crash tests distinguish
   in-memory loss from durably acknowledged content.
8. A content reference arriving before its object resolves as pending; failures/deletion resolve
   explicitly. Duplicate writes and corrupted pre-existing objects are tested.
9. Unauthorized/cross-tenant resolution and malicious references fail; corrupted bytes fail
   verification. Retention and deletion are demonstrable.
10. An external consumer reads and evaluates the exported transcript without a proprietary service.
    Offline harness evaluation also runs without Fabric.
11. Packaged artifacts pass existing recorder boundary gates plus new governed-content
    qualification. Test production storage integration separately from mocks; list any
    environment-dependent gates not run.
12. Documentation accurately states latency overhead, durability limits, supported adapters and
    security responsibilities. No claims of hidden reasoning capture, universal context visibility,
    immutable evidence or complete retention without supporting evidence.

## Implementation order and handoff

After the documentation change, implement contracts/configuration; storage/write lifecycle and
resolver; Python model/tool/context capture; TypeScript parity; real collector and external-consumer
integration; then packaging and qualification. Adapt this sequence to dependency findings while
keeping deliverables explicit.

Deliver the specs, gap matrix, code, migration notes, runnable end-to-end example, test evidence and
final requirement-by-requirement status. Distinguish completed, unsupported, deferred and externally
blocked items. Do not stop after scaffolding or tests against a fake store. Do not deploy to
customer systems, publish a release, or migrate/delete existing evidence as part of this task.
