# Governed content contract v1

Public, versioned schemas for Fabric's opt-in governed content path
(draft specs [028–034](../../../specs/)). These contracts describe the content
objects the SDK writes to **customer-controlled storage**, the per-decision
transcript manifest, and the export an authorized resolver produces. Raw
content never enters OTLP; telemetry carries reference URIs and digests
only.

## Documents

| Schema | Document |
|---|---|
| `schema/content-object-v1.schema.json` | `fabric.content-object/v1` — immutable descriptor for one stored object: opaque `object_id`, tenant scope, content role, media type, exact byte length, `sha256:` digest over the stored bytes, capture time, representation, provenance source, status, and trace/step/tool-call bindings. |
| `schema/transcript-manifest-v1.schema.json` | `fabric.transcript-manifest/v1` — per-decision ordered item list with explicit statuses (`stored`, `pending`, `dropped`, `failed`, `not_captured`, `unsupported`, `truncated`, `redacted`), a completeness rollup, and coverage information. |
| `schema/transcript-export-v1.schema.json` | `fabric.transcript-export/v1` — resolver-produced transcript: ordered steps, materialized or referenced content, per-object integrity verification. Consumable without any SingleAxis service. |

## Byte fixtures

`fixtures/bytes/` pins shared byte+SHA-256 pairs (ASCII, multi-byte UTF-8,
canonical JSON, empty values, multiline). Python and TypeScript SDK test
suites must reproduce the pinned digest from the fixture value — this is
the cross-language byte-exactness gate.

## Pinning

`manifest.json` pins every artifact by exact file bytes
(`digest_scope: exact_file_bytes`). Adding or editing a fixture without
re-pinning fails validation. Validate with:

```bash
python scripts/contracts/validate_content_contracts.py
```

## Honest scope

- A descriptor's digest verifies the **stored** bytes. Truncated or
  transformed content is marked by `representation`; consumers never verify
  redacted bytes against an original-content digest.
- `pending` means the reference was published before the object was
  confirmed stored; `failed`/`dropped` mean it never will be. `not_captured`
  and `unsupported` are completeness reasons, not lifecycle states.
- Objects are immutable once stored; manifests may be rewritten once
  idempotently as pending items settle.
- Digest equality proves sameness, not authorization — access is scoped by
  the configured store's tenant namespace.
