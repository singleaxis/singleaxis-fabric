# Recorder v1 demo walkthrough

This five-minute demo proves one narrow claim: an enterprise can passively
shadow observable agent activity, remove unapproved export fields, and deliver
the protected telemetry to infrastructure it chooses.

## 1. State the boundary

Show the architecture:

```text
Agent or existing OTLP -> Fabric Node -> customer-selected destination
                         PROTECT       DELIVER
```

Explain that the recorder is not a judge, red-team runner, policy engine,
prompt-time PII control, or governance UI. It does not modify the monitored
agent.

## 2. Initialize locally

```bash
fabricctl init
fabricctl recorder validate fabric-recorder.yaml
fabricctl recorder digest fabric-recorder.yaml
```

Point out that initialization writes no credentials and does not install
anything. The digest lets a reviewer bind an approved configuration to later
deployment evidence.

## 3. Capture one operation

Use either the SDK quickstart or an existing OTLP source. Show one trace with a
decision, model call, and tool call. Explain that capture quality depends on the
integration; Fabric cannot infer events the source does not expose.

## 4. Demonstrate export protection

Send a span containing both approved recorder metadata and a unique forbidden
raw-content marker. Show that the approved metadata reaches the controlled sink
and the marker does not. Do not claim this key allowlist is semantic PII
detection or legal de-identification.

## 5. Demonstrate delivery behavior

Stop the sink, send telemetry, restart Fabric Node, and restore the sink. Show
that the persistent queue resumes delivery. Explain that delivery is at least
once and that destination acceptance is not automatically proof of durable
retention.

## 6. Close with enterprise qualification

Show `shadow-production` refusing to render without tenant identity, receiver
mTLS, explicit ingress and egress peers, authenticated HTTPS export, and
persistent storage. Finish with the customer-specific work still required:
connector coverage, identity, metadata classification, storage sizing,
deduplication, retention, alerting, and recovery testing.
