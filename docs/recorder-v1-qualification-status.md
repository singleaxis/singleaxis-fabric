# Recorder v1 qualification status

This document distinguishes implemented runtime behavior from public contracts
and from checks that require the release CI environment. It is a development
status record, not a certification or legal compliance statement.

## Implemented in release artifacts

| Area | Implemented behavior |
|---|---|
| Capture | Python and TypeScript SDK surfaces; OTLP trace and log ingestion through Fabric Node; opt-in governed content capture to customer-controlled storage (specs 028/032) |
| Protect | Non-disableable exact metadata allowlist; raw bodies and unapproved native OTLP strings removed before export; named production profile rejects custom allowlist extensions; governed content never enters OTLP — only `fabric.content.{ref,request_ref,result_ref,manifest_ref}` is admitted |
| Deliver | OTLP/HTTP export, persistent file queue, no production pre-queue batch window, blocking overflow, restart recovery, and unbounded retry; governed content delivered by bounded SDK writers (`inline`/`process`/`spooled`) with durable local spooling, bounded retries, and explicit gap reporting |
| Deployment | Collector-only Helm chart with `shadow-dev` and fail-closed `shadow-production` profiles |
| Setup | Recorder-only `fabricctl` init, validate, digest, help, and version commands |
| Packaging | Explicit release allowlists for SDKs, chart, image, CLI, and public contract families |

The released recorder artifacts do not contain or install judges, red-team
runners, prompt-time PII controls, guardrail engines, policy/tool authorization,
assurance tiers, governance workflows, or management-plane services.

## Public contracts, not automatic runtime evidence yet

Activity Envelope v2, privacy assertions, and delivery batches/receipts define
interoperability shapes and validation rules. Recorder v1 does not yet claim
that Fabric Node materializes Activity Envelope v2 on its OTLP wire path,
automatically emits a signed privacy assertion for every batch, or obtains
durable-persistence proof from arbitrary destinations.

### Governed content (specs 028–034)

Implemented in the SDKs today:

- versioned `fabric.content-object/v1` descriptors and
  `fabric.transcript-manifest/v1` / `fabric.transcript-export/v1` contracts,
  with shared byte/hash fixtures passing in both languages;
- local filesystem and S3-compatible governed stores (tenant-namespaced,
  content-addressed, descriptor sidecars, by-decision manifest aliases);
- bounded writer with `inline`/`process`/`spooled` durability, spool
  recovery, and exact stored/pending/dropped/failed accounting;
- governed capture across `llm_call` (request, output, partial output),
  `tool_call` (arguments, result), retrieval, memory, side-effect,
  context, and interaction surfaces in both SDKs;
- authorized resolution confined to configured stores and tenant
  namespaces, with digest + byte-length verification and explicit
  available/pending/missing/denied/corrupted states.

Not yet qualified:

- adapter/framework auto-capture of governed content (manual `llm_call`
  surfaces only — auto-instrumentation content is not wired);
- binary or multimodal content (v1 is text/JSON; mark it `unsupported`);
- production S3 delivery against a live endpoint (adapter is
  contract-tested with fakes; run environment-dependent gates before
  relying on it);
- manifest_ref propagation through a live Fabric Node pipeline (the
  allowlist admits it; the end-to-end kind gate does not exercise
  governed mode yet).

An unsigned privacy assertion records what a processor claims it applied. It is
not independent proof and is not a legal de-identification determination.

## Locally qualified

The repository qualification suite covers:

- contract schema, digest, ordering, causality, and receipt invariants;
- guard processor unit, race, and static checks;
- chart schema, package boundary, production ingress/egress, and durable queue
  configuration checks;
- recorder-only CLI build and dependency graph;
- SDK unit, typing, lint, build, and exact package-surface checks;
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
