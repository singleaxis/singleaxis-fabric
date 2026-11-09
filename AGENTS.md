# SingleAxis Fabric OSS scope

This repository is the customer-controlled, open-source recording data plane.
Its product promise is intentionally narrow:

> Capture observable AI activity, protect the record before it crosses the
> customer boundary, and reliably deliver a verifiable record to a destination
> chosen by the customer.

Use this customer-facing model everywhere:

```text
CAPTURE -> PROTECT -> DELIVER
```

- **Connect** is an input/integration method (SDK, OTLP, HTTP, adapter or
  customer-specific connector), not a separate product layer.
- **Verify** is a cross-cutting property provided by configuration checks,
  integrity checks, canaries and delivery receipts, not a separate runtime
  layer.
- The default and first stable product is passive shadow capture. It must not
  alter, block or delay the monitored AI system.

## In scope for the OSS core

- public activity and connector contracts;
- optional SDK instrumentation and adapters;
- authenticated telemetry/event ingestion;
- preservation of OTLP identity and causal correlation supplied by the source;
- recording, as observed or reported evidence, the security context of a
  monitored agent: the tools and permissions it was given, decisions made
  about its actions by the model provider, the operating system, the
  customer's own controls and people, what hooks did, and which tool
  servers, plugins and skills were present. Capture attaches to the
  boundaries every agent crosses (the model wire, tool-protocol messages,
  processes and the operating system, network connections and OTLP
  telemetry), with an explicit API for decisions that cross none of
  them. It never depends on a particular agent framework. Every recorded
  decision carries `enforced_by_fabric=false`; Fabric never computes,
  applies, waits for or returns any of these decisions;
- a public Activity Envelope contract for downstream normalization, without
  claiming that recorder v1 materializes that envelope;
- export allowlisting and privacy protection;
- durable local buffering, retry and idempotent delivery;
- public delivery and integrity receipt contracts; recorder v1 does not
  automatically emit or obtain those receipts;
- local recorder initialization, configuration validation, digesting and
  offline verification;
- customer-selected destinations, with no required SingleAxis connection.

## Outside the OSS core

Do not add these to the default OSS runtime, installer or primary product
story:

- continuous evaluation services, judges or finding generation (recording
  a decision another system already made is in scope; producing, scoring
  or judging one is not);
- red-team campaign orchestration;
- proprietary PII, clinical, policy or regulatory packs;
- advisory recommendations or enforcement orchestration, including
  running a guardrail, policy engine, permission check, judge or approval
  flow, or any code path that can block, delay, modify or approve the
  monitored system;
- Decision Graph analytics, incidents, evidence workflows or underwriting;
- enterprise fleet management, approvals, policy authoring or rollout UI;
- SingleAxis private topology, customer overlays, business plans or roadmaps.

Public, vendor-neutral interchange contracts or optional adapters may exist
when needed for interoperability, but they must not expand the OSS product
promise or become required dependencies of capture and delivery.

Legacy assurance, management, runtime-control, judge, red-team, and
regulatory sources were removed from the repository when the recorder scope
became authoritative; their history lives in git. Recorder release artifacts
must never compile, bundle, expose, install, or advertise those
capabilities — enforce this with artifact-content tests, not only disabled
defaults. Do not reintroduce them.

## Product and repository boundary

- **Fabric OSS:** Capture -> Protect -> Deliver.
- **SingleAxis Platform/private systems:** Monitor -> Evaluate -> Govern.
- **Optional future customer-side Control Runtime:** Enforce customer-approved
  decisions. It is separate from the default recorder and is never enabled by
  installing Fabric OSS.

A separately installed Control Runtime, if any, reports its decisions to
the recorder through the same public control decision record as any other
external control. The recorder never depends on it.

When a document or older specification conflicts with this boundary, do not
silently implement the older direction. Flag the conflict and reconcile it
with the current internal product-direction document before changing scope.
