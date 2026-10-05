# Agent execution evidence contract v1 (draft)

This is the testable contract package for
[AEEP](../../../specs/035-agent-execution-evidence-profile.md) and
[spec 036](../../../specs/036-evidence-capture-implementation-plan.md).
It does not introduce a new transport. `evidence-event/v1` is a JSON
**projection for validation and fixtures** of an OTLP LogRecord whose
`EventName` is `event_name`, whose body is empty, and whose trace identity
is native OTLP identity. Sensitive bytes reside only in customer-controlled
[content objects](../../content/v2/README.md).

`source-capability/v1` declares what one pinned connector build can and
cannot observe, including per-surface roles, sampling behavior, bypass tests,
and loss detection. `run-manifest/v1` declares an approved bounded scope and
reconciles required sources, roles, items, receipts, and independent feeds.
Its source epochs carry start/terminal markers, sequence high-water, known
loss counters, and unknown-loss status. An exact stored item needs a
tenant/run/object/digest-bound verified destination-durable receipt, and
its observation event plus source start/stop events need separate durable
event receipts. A `verified_complete_for_declared_scope` verdict is only
about that declared scope; it does not mean complete capture of an
unconstrained agent.

The schemas are deliberately closed. The validator adds semantic checks
that JSON Schema cannot express, including exact byte digests, per-source
sequence continuity, event/content binding, and the run verdict. The
positive fixture binds a source capability, source start and stop events,
artifact event, exact binary object, receipt, and independent feed. A
second fixture has the opt-in SDK's caller-reported terminal-byte shape.

**The validator checks claimed proof identities and structural consistency;
it does not authenticate signatures, read the referenced bytes, resolve
receipts, check a customer's signed scope, or prove that the source inventory
is complete.** A production reconciler must use trusted keys/identities and
independent store/feed readback before setting any `verified` flags or a
complete verdict. Its trust policy must be outside the untrusted manifest.
Fabric's host-emitter `log.record.uid` and loss summary are useful dedupe and
gap signals, but do not alone establish AEEP `record_id`, epoch/sequence,
source health, or a complete run verdict.
