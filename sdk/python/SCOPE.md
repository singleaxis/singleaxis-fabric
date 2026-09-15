# Python SDK scope

The recorder SDK has one job: instrument observable agent activity and preserve
its identity, timing and causal relationships so a Fabric Node can protect and
deliver the record.

## Supported

- decision and execution correlation;
- model and tool call spans, including retries and failures;
- retrieval and memory events using hashes instead of raw content;
- side effects, checkpoints, delegation, MCP inventory, skills, hooks, file
  access and generic interactions;
- OpenTelemetry propagation and optional framework/provider instrumentation;
- customer-controlled content references and integrity metadata.

## Not part of recorder v1

- judges, evaluation queues or evaluation runners;
- red-team execution;
- prompt-time PII redaction, NeMo or guardrail enforcement;
- policy engines, tool authorization or escalation enforcement;
- deployment management, assurance tiers or regulatory profiles;
- a monitoring backend, Decision Graph or governance workflow.

Those systems may consume the delivered activity record elsewhere. They are
not enabled by installing this package.

## Artifact boundary

The wheel and source distribution contain only recorder code. Runtime-control,
judge, evaluation, policy, authorization, escalation and management modules,
extras and console commands are absent rather than hidden behind package-root
exports. Exact-archive qualification enforces this boundary before release.
