# Capturing observable interactions

Fabric records interactions exposed by your SDK calls, framework hooks,
gateway, vendor integration, or existing telemetry. It does not automatically
capture every action or hidden model reasoning.

## Privacy defaults

Recorder methods emit metadata, SHA-256 hashes, and governed references rather
than raw payloads. Caller-supplied SHA-256 values must be 64 lowercase
hexadecimal characters with no `sha256:` prefix. File paths and generic targets
are hashed by default.

Metadata can still contain sensitive information. Use opaque agent, tenant,
session, request, tool, and document identifiers. Route enterprise export
through Fabric Node, whose exact allowlist removes unapproved OTLP fields. That
allowlist is not semantic PII classification.

```python
payload_hash = "a" * 64

decision.record_interaction(
    "http.request",
    "https://api.example.com/v1/orders",
    direction="outbound",
    payload_hash=payload_hash,
    metadata={"status": 200, "method": "POST"},
)
```

The target is represented by a hash unless `redact_target=False` is explicitly
authorized. The same opt-out principle applies to file paths.

## First-class recorder surfaces

- model and tool calls, usage, errors, retries, and idempotency metadata;
- retrieval queries and result hashes;
- memory reads, writes, invalidation, and erasure requests;
- side-effect intent and outcome metadata;
- delegation and trace-context propagation;
- checkpoint and replay metadata without claiming deterministic replay;
- MCP inventory, skills, hooks, and file access; and
- generic interactions for observable protocols not otherwise modeled.

Use governed content references when an authorized evidence store must retain a
payload. Fabric telemetry should carry the reference and integrity hash, not the
object itself.

## Coverage statement

For each deployment, publish a connector capability manifest stating which
surfaces are observed, how identity is established, whether ordering is
preserved, whether content is visible, and known blind spots. Do not convert an
inferred or unavailable event into an observed fact.
