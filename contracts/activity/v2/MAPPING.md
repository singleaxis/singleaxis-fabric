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

## Activity 2.1.0: security context (spec 057 §5.7)

Activity 2.1.0 (`contracts/activity/v2.1`) is additive beside 2.0.0: four
event types (`grant.snapshot`, `control.decision`, `hook.completed`,
`extension.loaded`), each with its own `activity` object. A producer emits
them only to a destination that declares 2.1.0; otherwise it drops them with a
counted loss, and the OTLP wire still carries the keys below. Every
`control.decision` carries `enforced_by_fabric=false` and
`authentication=unverified_caller_report`, set by Fabric, never by a caller.
Identifiers are keyed pseudonyms on the wire and in the envelope.

| Admitted wire attribute | Envelope 2.1.0 path | Notes |
|---|---|---|
| `fabric.control.action_id` | `events[*].activity.control.gated.action_id` |  |
| `fabric.control.authentication` | `events[*].activity.control.authentication` |  |
| `fabric.control.decision` | `events[*].activity.control.decision` |  |
| `fabric.control.enforced_by_fabric` | `events[*].activity.control.enforced_by_fabric` |  |
| `fabric.control.gated_step_id` | `events[*].activity.control.gated.step_id` |  |
| `fabric.control.id` | `events[*].activity.control.control_id` |  |
| `fabric.control.kind` | `events[*].activity.control.kind` |  |
| `fabric.control.phase` | `events[*].activity.control.phase` |  |
| `fabric.control.policy_digest` | — | telemetry only (no 2.1.0 envelope field) |
| `fabric.control.policy_id` | — | telemetry only (no 2.1.0 envelope field) |
| `fabric.control.policy_version` | — | telemetry only (no 2.1.0 envelope field) |
| `fabric.control.proof_ref` | — | telemetry only (no 2.1.0 envelope field) |
| `fabric.control.resolves` | `events[*].activity.control.resolves` |  |
| `fabric.control.stage` | `events[*].activity.control.stage` |  |
| `fabric.control.engine.name` | `events[*].activity.control.engine.name` |  |
| `fabric.control.engine.version` | `events[*].activity.control.engine.version` |  |
| `fabric.control.gated_kind` | `events[*].activity.control.gated.kind` |  |
| `fabric.control.gated_tool_call_id` | `events[*].activity.control.gated.tool_call_id` |  |
| `fabric.control.latency_ms` | `events[*].activity.control.latency_ms` |  |
| `fabric.control.reason_code` | `events[*].activity.control.reason_code` |  |
| `fabric.control.mode` | `events[*].activity.control.mode` |  |
| `fabric.control.grant_id` | `events[*].activity.control.grant_id` |  |
| `fabric.control.error_class` | `events[*].activity.control.error_class` |  |
| `fabric.control.evidence_event_ids` | `events[*].activity.control.evidence_event_ids` |  |
| `fabric.control.signal` | `events[*].activity.control.signal` |  |
| `fabric.control.derivation` | `events[*].activity.control.derivation` |  |
| `fabric.grant.id` | `events[*].activity.grant.grant_id` |  |
| `fabric.grant.trigger` | `events[*].activity.grant.trigger` |  |
| `fabric.grant.previous_id` | `events[*].activity.grant.previous_id` |  |
| `fabric.grant.source_boundary` | `events[*].activity.grant.source_boundary` |  |
| `fabric.grant.permission_mode` | `events[*].activity.grant.permission_mode` |  |
| `fabric.grant.tools_allow.count` | `events[*].activity.grant.counts.tools_allow` |  |
| `fabric.grant.tools_deny.count` | `events[*].activity.grant.counts.tools_deny` |  |
| `fabric.grant.tools_ask.count` | `events[*].activity.grant.counts.tools_ask` |  |
| `fabric.grant.tools_offered.count` | `events[*].activity.grant.counts.tools_offered` |  |
| `fabric.grant.tools_listed.count` | `events[*].activity.grant.counts.tools_listed` |  |
| `fabric.grant.mcp_servers.count` | `events[*].activity.grant.counts.mcp_servers` |  |
| `fabric.grant.fs_rules.count` | `events[*].activity.grant.counts.fs_rules` |  |
| `fabric.grant.net_rules.count` | `events[*].activity.grant.counts.net_rules` |  |
| `fabric.grant.credentials.count` | `events[*].activity.grant.counts.credentials` |  |
| `fabric.grant.model_rules.count` | `events[*].activity.grant.counts.model_rules` |  |
| `fabric.grant.sandbox_kind` | `events[*].activity.grant.sandbox_kind` |  |
| `fabric.grant.network_default` | `events[*].activity.grant.network_default` |  |
| `fabric.grant.basis` | `events[*].activity.grant.basis` |  |
| `fabric.grant.tool_choice` | `events[*].activity.grant.tool_choice` |  |
| `fabric.grant.tool_choice.allowed_count` | — | telemetry only (no 2.1.0 envelope field) |
| `fabric.grant.parallel_tools` | — | telemetry only (no 2.1.0 envelope field) |
| `fabric.hook.outcome` | `events[*].activity.hook.outcome` |  |
| `fabric.hook.event_name` | `events[*].activity.hook.event_name` |  |
| `fabric.hook.latency_ms` | `events[*].activity.hook.latency_ms` |  |
| `fabric.hook.gated_tool_call_id` | `events[*].activity.hook.gated_tool_call_id` |  |
| `fabric.hook.extension_id` | `events[*].activity.hook.extension_id` |  |
| `fabric.hook.reason_code` | `events[*].activity.hook.reason_code` |  |
| `fabric.hook.basis` | `events[*].activity.hook.basis` |  |
| `fabric.hook.exit_code` | `events[*].activity.hook.exit_code` |  |
| `fabric.hook.signal` | `events[*].activity.hook.signal` |  |
| `fabric.hook.program_label` | `events[*].activity.hook.program_label` |  |
| `fabric.extension.id` | `events[*].activity.extension.extension_id` |  |
| `fabric.extension.kind` | `events[*].activity.extension.kind` |  |
| `fabric.extension.name` | `events[*].activity.extension.name` |  |
| `fabric.extension.version` | `events[*].activity.extension.version` |  |
| `fabric.extension.source_kind` | `events[*].activity.extension.source_kind` |  |
| `fabric.extension.source_ref` | `events[*].activity.extension.source_ref` |  |
| `fabric.extension.manifest_hash` | `events[*].activity.extension.manifest_sha256` |  |
| `fabric.extension.signature_status` | `events[*].activity.extension.signature_status` |  |
| `fabric.extension.scope` | `events[*].activity.extension.scope` |  |
| `fabric.extension.enabled` | `events[*].activity.extension.enabled` |  |
| `fabric.extension.contributes.tools` | `events[*].activity.extension.contributes.tools` |  |
| `fabric.extension.contributes.hooks` | `events[*].activity.extension.contributes.hooks` |  |
| `fabric.extension.contributes.commands` | `events[*].activity.extension.contributes.commands` |  |
| `fabric.extension.contributes.mcp_servers` | `events[*].activity.extension.contributes.mcp_servers` |  |
| `fabric.extension.contributes.subagents` | `events[*].activity.extension.contributes.subagents` |  |
| `fabric.extension.observed_via` | `events[*].activity.extension.observed_via` |  |
| `fabric.mcp.tools.read_only_count` | — | telemetry only (no 2.1.0 envelope field) |
| `fabric.mcp.tools.destructive_count` | — | telemetry only (no 2.1.0 envelope field) |
| `fabric.mcp.tools.open_world_count` | — | telemetry only (no 2.1.0 envelope field) |
| `fabric.mcp.tools.idempotent_count` | — | telemetry only (no 2.1.0 envelope field) |
| `fabric.mcp.server_ref` | — | telemetry only (no 2.1.0 envelope field) |
| `fabric.run.execution_mode`, `fabric.run.approval_policy` | `events[*].activity.grant.execution_mode`, `.approval_policy` | on a declared `grant.snapshot` |
