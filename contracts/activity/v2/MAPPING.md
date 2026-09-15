# Wire attribute to Activity Envelope v2 mapping

Recorder v1 transports protected OTLP; it does not materialize the envelope on
the wire. This document maps the metadata-only OTLP attributes admitted by the
Fabric Node allowlist (`components/otel-collector-fabric` `EnvelopeAllowedFields`)
to the Activity Envelope v2 paths they populate during downstream
normalization. Two spellings are admitted for most attributes: the canonical
name and the `fabric.*` alias emitted by released SDKs.

## Identity, timing, and sequence

| Admitted wire attribute | Envelope v2 path | Notes |
|---|---|---|
| `event_id` / `fabric.event_id` | `events[*].event_id` | UUID; unique within a sequence |
| `event_type` / `fabric.event_type` | `events[*].event_type` | Envelope enum, e.g. `model.request` |
| `source_timestamp` / `fabric.source.timestamp` | `events[*].original_timestamp` | Source-side event time |
| `source_sequence` / `fabric.source.sequence` | `events[*].source_sequence` | Strictly increasing per `source_id` |
| `source_id` / `fabric.source_id` | `events[*].source.source_id` | See "Source identity" below |
| `capture_source` / `fabric.capture.source` | `events[*].capture_semantics` | `observed`, `reported`, or `inferred` |
| `content_mode` / `fabric.content_mode` | `events[*].content.mode` | `metadata`, `hash`, or `governed_reference` |
| `outcome` / `fabric.outcome` | `events[*].activity.outcome` | `requested`, `succeeded`, `failed`, `cancelled`, `unknown` |

## Identity block

| Admitted wire attribute | Envelope v2 path |
|---|---|
| `tenant_id` / `fabric.tenant_id` | `events[*].identity.tenant_id` |
| `system_id` / `fabric.system_id` | `events[*].identity.system_id` |
| `agent_id` / `fabric.agent_id` | `events[*].identity.agent_id` |
| `deployment_id` / `fabric.deployment_id` | `events[*].identity.deployment_id` |
| `environment` / `fabric.environment` | `events[*].identity.environment` |
| `release_id` / `fabric.release_id` | `events[*].identity.release_id` |

The envelope requires every `identity` field. Attributes a source does not
supply stay absent on the wire and must not be fabricated during
normalization; agentless integrations omit identifiers they do not know.

## Correlation

| Admitted wire attribute | Envelope v2 path | Notes |
|---|---|---|
| `trace_id` | `events[*].correlation.trace_id.value` | Also carried by W3C trace context |
| `span_id` | `events[*].correlation.span_id.value` | |
| `parent_span_id` | `events[*].correlation.parent_span_id.value` | |
| `execution_id` / `fabric.execution_id` | `events[*].correlation.execution_id.value` | UUID correlation |
| `decision_id` / `fabric.decision_id` | `events[*].correlation.decision_id.value` | UUID correlation |
| `attempt_id` / `fabric.execution.attempt_id` | `events[*].correlation.attempt_id.value` | UUID correlation |
| `causal_event_ids` / `fabric.causal_event_ids` | `events[*].correlation.causal_references` | See below |

The wire carries bare identifier values; the envelope wraps every correlation
identifier in `{value, provenance}`. Provenance (`observed`, `reported`,
`inferred`) is assigned during normalization — consistently with
`capture_semantics` — and is never upgraded to `observed` for reported or
inferred data.

Each entry in `causal_event_ids` becomes a `causal_references` member with
`scope: "sequence"` when it identifies an earlier event in the same sequence.
References to events in other sequences require `scope: "external"` with
`source_id` and `source_sequence`; the bare attribute list does not carry
those fields, so external references must be supplied by an integration that
knows them.

## Source block

| Admitted wire attribute | Envelope v2 path |
|---|---|
| `source_id` / `fabric.source_id` | `events[*].source.source_id` |
| `producer_name` / `fabric.producer.name` | `events[*].source.component` |
| `component_version` / `fabric.component.version` | `events[*].source.component_version` |
| `producer_version` / `fabric.producer.version` | `events[*].source.component_version` |
| `fabric.sdk.version` | `events[*].source.component_version` |

`source.kind` (`sdk`, `framework_adapter`, `gateway`, `otlp`,
`vendor_receiver`, `discovery`) is derived from the ingestion path, not from a
single attribute.

### Source identity

`source_id` (alias `fabric.source_id`) is the wire attribute carrying
`source.source_id`, the UUID that scopes `source_sequence` ordering and
`external` causal references. Current SDKs may not yet emit it; adapters and
operators may set it when the source identity is known. When it is absent,
normalization must not invent one — it derives `source_id` from verified
source metadata or leaves the sequence unassigned rather than fabricating a
stable identity.

## Admitted attributes without a dedicated envelope field

These attributes remain admitted on the wire so sources keep their identity
vocabulary, but envelope v2 defines no field for them. They are preserved as
metadata for downstream normalization, not dropped:

| Admitted wire attribute | Disposition |
|---|---|
| `event_class` / `fabric.event_class` | v1 log-class discriminator; no v2 field |
| `request_id` / `fabric.request_id` | Request-scoped identifier; no v2 field |
| `session_id` / `fabric.session_id` | Session grouping; no v2 field |
| `workflow_id` / `fabric.workflow_id` | Workflow grouping; no v2 field |
| `operation_id` | Operation grouping; no v2 field |
| `session_id_hash`, `user_id_hash` | Privacy-preserving hashes; no v2 field |
| `timestamp` | Record time; distinct from `original_timestamp` |
| `observed_status` / `fabric.observed_status`, `status` | Source status context; `activity.outcome` carries the normalized result |
| `fabric.execution.attempt` | Attempt ordinal; `attempt_id` carries the correlation UUID |
| `fabric.execution.retry.previous_attempt_id`, `fabric.execution.retry.reason` | Retry context; retries surface as `execution.retry` events with causal references |
| `schema_version` / `fabric.schema_version` | Wire attribute contract version; the envelope `schema_version` is the constant `2.0.0` |

## Vocabulary notes

- `content.mode` uses the underscore spelling `governed_reference` in this
  contract and on the wire. The `FabricRecorder` configuration contract
  deliberately spells the same mode `governed-reference`; the spellings are
  contract-specific and not interchangeable.
- Envelope-only fields — `contract`, `version`, `sequence_id`, each event's
  `contract`, `schema_version`, `content.classification`, `content.sha256`,
  `content.governed_reference`, and `activity` detail beyond `outcome` — are
  populated by schema constants, privacy classification, or typed surface
  attributes rather than by the shared identity attributes above.
