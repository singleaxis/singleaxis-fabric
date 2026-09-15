# How Fabric fits in an existing AI stack

Fabric OSS is a passive recorder, not an agent framework and not an enterprise
governance suite:

```text
observable activity -> CAPTURE -> PROTECT -> DELIVER -> chosen destination
```

## Choose one capture route

| Starting point | Integration | What it can observe |
|---|---|---|
| You own the agent code | Python or TypeScript SDK | Rich application semantics you explicitly instrument |
| The application already emits OTLP | Route OTLP through Fabric Node | Existing spans and events, limited by upstream instrumentation |
| A framework exposes hooks | Framework adapter | Only lifecycle events exposed by that framework |
| A vendor exposes a gateway or webhook | Customer/vendor adapter | Only payloads and metadata exposed by that interface |
| Traffic can be routed through a proxy | Telemetry gateway outside the request path | Protocol-visible activity; not hidden application state |

Network discovery alone is not semantic reconstruction. An integration must
publish its observed surfaces, ordering guarantees, identity source, content
visibility, and blind spots through the connector capability contract.

## Deploy the recorder

Fabric Node can run beside the application, as a shared cluster service, or in
a customer observability account. The production posture requires authenticated
ingress and egress, an explicit network path, and durable local queue storage.
The customer chooses whether the destination is its own OTLP backend, a private
SingleAxis deployment, or SingleAxis Platform.

## Add other systems without mixing layers

Customer PII tools, guardrails, authorization systems, and policy engines may
emit correlated outcomes into the same trace, but recorder v1 neither runs nor
controls them. SingleAxis monitoring, evaluation, incident, Decision Graph, and
governance services consume the protected record downstream. Optional inline
enforcement is a later, separately deployed request-path capability.

This separation allows an enterprise to begin in shadow mode without changing
agent behavior, prove coverage and delivery, then add advisory or enforcement
systems only where risk justifies them.
