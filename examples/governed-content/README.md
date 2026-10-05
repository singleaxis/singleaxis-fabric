# governed-content example

Offline, harness-owned governed capture: a synthetic
`model -> tool -> model` decision writes content objects plus a
transcript manifest to a local governed store, then a separate
consumer process resolves the manifest, verifies every object's
SHA-256 digest and byte length, exports the transcript, and runs a
deterministic content assertion.

No Fabric Node, OTLP collector, or SingleAxis service is involved —
the recorder boundary is unchanged: governed content goes to
customer-controlled storage; telemetry (when an exporter is installed)
carries references and hashes only.

## Run

```bash
uv pip install -e "../../sdk/python"

python capture.py --root ./store
#   flush: FlushResult(stored=..., pending=0, dropped=0, failed=0)
#   decision_id=<uuid>
#   manifest_uri=file://.../manifests/<id>.json
#   store_root=./store

python evaluate.py --root ./store --decision-id <uuid>
#   PASS — transcript verified; deterministic content assertions hold
```

## What this demonstrates — and what it does not

- The consumer runs where the content is authorized to be read (the
  local store). Content evaluators need an authorized content-access
  path; changing collector settings alone never recovers content that
  was never captured.
- Integrity is byte-level: every materialized object passed digest +
  length verification. Digests are integrity checks, not proof of
  source truth or independently verified identity.
- A recorded retrieval result or context file proves the caller
  received it — not that the model consumed it. The recorded effective
  request (`model.request.messages`) is the evidence where visible.
- The resolver reads manifests and objects; it does not execute tools,
  replay side effects, or fetch arbitrary URIs — a telemetry-provided
  URI can only resolve inside the configured store's tenant namespace.
- Offline datasets still carry privacy, access, and retention
  responsibilities — the store enforces tenant namespacing and `0600`
  file modes, but retention/deletion is the operator's storage policy,
  not the SDK's claim.

## Files

- `capture.py` — records the flow with `durability="inline"` (objects
  land synchronously; `process` uses bounded in-memory delivery, while
  `spooled` adds an explicit durable handoff after its acknowledgement).
- `evaluate.py` — the authorized consumer: manifest resolution,
  verified transcript export, deterministic assertions.
