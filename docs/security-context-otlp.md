# Security context over OTLP

> **Status:** on main, not yet released (spec 057 P3a, WP7-14 and WP7-15).
> Implementation: fabricguard admission
> ([`allowlist.go`](../components/otel-collector-fabric/processor/fabricguardprocessor/allowlist.go))
> and the optional mapping processor
> ([`fabricmapprocessor`](../components/otel-collector-fabric/processor/fabricmapprocessor/)).
> Specification: [057 §4.5](../specs/057-security-context-recording.md).

A gateway, policy service, approval system or agent runtime that already
emits OpenTelemetry can report the security context of an agent to the
Fabric Node: the permissions it was given (grant), decisions another system
made about its actions (control), what its hooks did (hook), and which tool
servers, plugins and skills were present (extension). Fabric records what
the emitter reports. It never computes, applies, waits for or returns any of
these decisions, and every control record says so
(`fabric.control.enforced_by_fabric=false`).

There are two ways in:

1. **Write the neutral keys yourself.** An emitter that sets the attributes
   below needs nothing else: fabricguard admits each key with its closed
   check and drops everything else.
2. **Keep your own attribute names** and give the Node a **mapping profile**
   that rewrites them (see [Mapping profiles](#mapping-profiles)).

Everything that arrives over OTLP is recorded with provenance `reported`
(spec 057 §3): the Node does not verify the emitter's claims.

## Carriers

- **A span** with the neutral keys as span attributes. The Node keeps the
  span's trace id, span id, parent and times (so the record joins the
  agent's trace) and replaces its name with a public category.
- **A log record** with `event_class=security_context` and the neutral keys
  as attributes. Its body, severity text and event name are dropped. On a
  Node whose ingress is bound to one tenant and source
  (`receiver.evidenceSourceBinding`), the record must also carry that
  `tenant_id` and `source_id`, as AEEP evidence logs do.

## Rules every emitter follows

- **Closed values.** A value outside a key's check is dropped (the rest of
  the record is kept). Enumerations are closed; labels are pattern-checked.
- **Identifiers are keyed pseudonyms, never clear.** A provider tool-call id
  travels as `p-` + 32 hex, a grant as `grt-`, an extension as `ext-`, its
  source as `src-`: the keyed v2 pseudonym of spec 049 §2.9, made with the
  same id key as the agents' `FABRIC_WIRE_ID_KEY` so the record joins the
  agent's own. A clear id (for example `call_7Hq2…`) is dropped. If you
  cannot compute the pseudonym, send your own id names through a mapping
  profile and let the Node pseudonymise them.
- **The invariants are constants.** `fabric.control.enforced_by_fabric` is
  exactly `false` and `fabric.control.authentication` is exactly
  `unverified_caller_report`. Any other value (a forged `true`, or
  `verified`) is refused and does not reach the export.
- **No content on telemetry.** Prompts, outputs, reason text, rule text,
  paths, hosts, URLs, launch commands and credential names never belong in
  these attributes; a key that is not listed below is dropped.

## The attribute contract

The authoritative checks are
[`contracts/coverage/v1/registry/telemetry-keys-v1.json`](../contracts/coverage/v1/registry/telemetry-keys-v1.json);
field ids refer to spec 049 and spec 057 §5. A test keeps this table equal
to the mapping-profile target keys plus the invariants and the spec 022 hook
keys.

### `fabric.control.*`

| Key | Field | Value |
|---|---|---|
| `fabric.control.action_id` | D06 | string `^axn-[0-9a-f]{32}$` |
| `fabric.control.authentication` | D11 | exactly `"unverified_caller_report"` |
| `fabric.control.decision` | D04 | one of `allow`, `deny`, `modify`, `escalate`, `pending`, `timeout`, `cancelled`, `revoked`, `unknown`, `error` |
| `fabric.control.derivation` | D49 | one of `literal`, `configured_extract`, `configured_marker`, `configured_exit_map`, `reported`, `wrapped_check` |
| `fabric.control.enforced_by_fabric` | D11 | exactly `false` |
| `fabric.control.engine.name` | D38 | string `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$` |
| `fabric.control.engine.version` | D38 | string `^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$` |
| `fabric.control.error_class` | D45 | one of `timeout`, `exception`, `unavailable`, `misconfigured`, `other` |
| `fabric.control.evidence_event_ids` | D47 | array (≤ 8) of string `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$` |
| `fabric.control.gated_kind` | D39 | one of `tool_call`, `model_call`, `side_effect`, `mcp_call`, `process`, `input`, `output`, `run`, `other` |
| `fabric.control.gated_step_id` | D06 | string `^(?:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\|(?:lbl\|g)-[0-9a-f]{32})$` |
| `fabric.control.gated_tool_call_id` | D40 | string `^p-[0-9a-f]{32}$` |
| `fabric.control.grant_id` | D44 | string `^grt-[0-9a-f]{32}$` |
| `fabric.control.id` | D01 | string `^(?:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\|ctl-[0-9a-f]{32})$` |
| `fabric.control.kind` | D02 | one of `guardrail`, `policy`, `permission_request`, `approval`, `rate_limit`, `budget`, `other`, `provider_safety`, `elicitation`, `os_access`, `permission_check` |
| `fabric.control.latency_ms` | D41 | number ≥ 0 |
| `fabric.control.mode` | D43 | one of `enforcing`, `advisory`, `shadow`, `unknown` |
| `fabric.control.phase` | D03 | one of `request`, `resolution`, `revocation`, `observation` |
| `fabric.control.policy_digest` | D08 | string `^sha256:[0-9a-f]{64}$` |
| `fabric.control.policy_id` | D08 | operator label: `lbl-` + 32 hex; the clear label `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$` only on a Node with `fabric.guard.captureLabels: clear` |
| `fabric.control.policy_version` | D08 | integer ≥ 1 |
| `fabric.control.proof_ref` | D09 | string `^prf-[0-9a-f]{32}$` |
| `fabric.control.reason_code` | D42 | string `^[a-z0-9][a-z0-9._:-]{0,63}$` |
| `fabric.control.resolves` | D05 | string `^(?:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\|ctl-[0-9a-f]{32})$` |
| `fabric.control.signal` | D48 | one of `content_filter`, `refusal`, `guardrail_intervened`, `prompt_blocked`, `safety_stop`, `moderation_flag`, `other` |
| `fabric.control.stage` | D37 | one of `input`, `output`, `pre_model`, `post_model`, `pre_tool`, `post_tool`, `pre_effect`, `post_effect`, `effect`, `inventory`, `run`, `other`, `unknown` |

### `fabric.extension.*`

| Key | Field | Value |
|---|---|---|
| `fabric.extension.contributes.commands` | E19 | integer ≥ 0 |
| `fabric.extension.contributes.hooks` | E19 | integer ≥ 0 |
| `fabric.extension.contributes.mcp_servers` | E19 | integer ≥ 0 |
| `fabric.extension.contributes.subagents` | E19 | integer ≥ 0 |
| `fabric.extension.contributes.tools` | E19 | integer ≥ 0 |
| `fabric.extension.enabled` | E18 | boolean |
| `fabric.extension.id` | E10 | string `^ext-[0-9a-f]{32}$` |
| `fabric.extension.kind` | E11 | one of `skill`, `plugin`, `mcp_server`, `hook_bundle`, `subagent`, `tool_pack`, `other` |
| `fabric.extension.manifest_hash` | E15 | string `^[0-9a-f]{64}$` |
| `fabric.extension.name` | E12 | string `^[A-Za-z0-9@][A-Za-z0-9._:/@-]{0,127}$` |
| `fabric.extension.observed_via` | E23 | one of `mcp_initialize`, `mcp_tools_list`, `process_launch`, `path_open`, `reported` |
| `fabric.extension.scope` | E17 | one of `managed`, `user`, `project`, `local`, `session`, `unknown` |
| `fabric.extension.signature_status` | E16 | one of `verified`, `invalid`, `unsigned`, `unverified`, `unknown` |
| `fabric.extension.source_kind` | E13 | one of `registry`, `marketplace`, `git`, `local_path`, `url`, `process`, `builtin`, `unknown` |
| `fabric.extension.source_ref` | E14 | string `^src-[0-9a-f]{32}$` |
| `fabric.extension.version` | E12 | string `^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$` |

### `fabric.grant.*`

| Key | Field | Value |
|---|---|---|
| `fabric.grant.basis` | G12 | one of `offered`, `listed`, `declared` |
| `fabric.grant.credentials.count` | G07 | integer ≥ 0 |
| `fabric.grant.fs_rules.count` | G07 | integer ≥ 0 |
| `fabric.grant.id` | G01 | string `^grt-[0-9a-f]{32}$` |
| `fabric.grant.mcp_servers.count` | G07 | integer ≥ 0 |
| `fabric.grant.model_rules.count` | G07 | integer ≥ 0 |
| `fabric.grant.net_rules.count` | G07 | integer ≥ 0 |
| `fabric.grant.network_default` | G09 | one of `allow`, `deny`, `unknown` |
| `fabric.grant.parallel_tools` | G14 | boolean |
| `fabric.grant.permission_mode` | G05 | string `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$` |
| `fabric.grant.previous_id` | G03 | string `^grt-[0-9a-f]{32}$` |
| `fabric.grant.sandbox_kind` | G08 | one of `none`, `process`, `container`, `vm`, `remote`, `unknown` |
| `fabric.grant.source_boundary` | G04 | one of `llm_wire`, `mcp_wire`, `api`, `otlp`, `operator_snapshot`, `other` |
| `fabric.grant.tool_choice` | G13 | one of `auto`, `none`, `required`, `specific`, `allowed_subset`, `unknown` |
| `fabric.grant.tool_choice.allowed_count` | G14 | integer ≥ 0 |
| `fabric.grant.tools_allow.count` | G07 | integer ≥ 0 |
| `fabric.grant.tools_ask.count` | G07 | integer ≥ 0 |
| `fabric.grant.tools_deny.count` | G07 | integer ≥ 0 |
| `fabric.grant.tools_listed.count` | G07 | integer ≥ 0 |
| `fabric.grant.tools_offered.count` | G07 | integer ≥ 0 |
| `fabric.grant.trigger` | G02 | one of `run_start`, `change`, `resume`, `requested`, `derived`, `unknown` |

### `fabric.hook.*`

| Key | Field | Value |
|---|---|---|
| `fabric.hook.basis` | E07 | one of `process`, `callback`, `reported_unknown` |
| `fabric.hook.event_name` | E02 | string `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$` |
| `fabric.hook.exit_code` | E08 | 32-bit signed integer |
| `fabric.hook.extension_id` | E05 | string `^ext-[0-9a-f]{32}$` |
| `fabric.hook.gated_tool_call_id` | E04 | string `^p-[0-9a-f]{32}$` |
| `fabric.hook.input_hash` | E27 | string `^[0-9a-f]{64}$` |
| `fabric.hook.latency_ms` | E03 | number ≥ 0 |
| `fabric.hook.modified` | E26 | boolean |
| `fabric.hook.name` | E24 | string `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$` |
| `fabric.hook.outcome` | E01 | one of `passed`, `modified`, `blocked`, `escalated`, `errored`, `unknown` |
| `fabric.hook.output_hash` | E27 | string `^[0-9a-f]{64}$` |
| `fabric.hook.phase` | E25 | one of `pre_model`, `post_model`, `pre_tool`, `post_tool`, `pre_decision`, `post_decision` |
| `fabric.hook.program_label` | E09 | string `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$` |
| `fabric.hook.reason_code` | E06 | string `^[a-z0-9][a-z0-9._:-]{0,63}$` |
| `fabric.hook.signal` | E08 | integer ≥ 1 |

### `fabric.mcp.*`

| Key | Field | Value |
|---|---|---|
| `fabric.mcp.server_ref` | E21 | string `^src-[0-9a-f]{32}$` |
| `fabric.mcp.tools.destructive_count` | E20 | integer ≥ 0 |
| `fabric.mcp.tools.idempotent_count` | E20 | integer ≥ 0 |
| `fabric.mcp.tools.open_world_count` | E20 | integer ≥ 0 |
| `fabric.mcp.tools.read_only_count` | E20 | integer ≥ 0 |

## OpenTelemetry GenAI source keys

Fabric pins one version of the OpenTelemetry GenAI semantic conventions,
**1.42.0** (the version the Fabric SDKs emit; spec 057 OD-12). On a Node with
`fabric.mapping.genaiSourceKeys: "1.42.0"`, these keys are accepted **as
sources only** on a record that already carries `fabric.control.*` or
`fabric.hook.*` keys:

| Source key | Becomes | Note |
|---|---|---|
| `gen_ai.tool.call.id` | `fabric.control.gated_tool_call_id` or `fabric.hook.gated_tool_call_id` | pseudonymised as `p-` + 32 hex with the id key; kept as is when it already has that form |
| `gen_ai.operation.name` | `fabric.control.gated_kind` | `execute_tool` → `tool_call`; `chat`, `text_completion`, `generate_content` → `model_call`; other values state nothing |

The record's own `fabric.*` value always wins, and the source key is
removed from the record. Fabric never writes a `gen_ai.*` key as its own.
Records of no security-context family are left exactly as they were.

## Mapping profiles

A mapping profile is a JSON document of the schema
[`otlp-mapping-profile-v1.schema.json`](../contracts/capture/v1/schema/otlp-mapping-profile-v1.schema.json)
that you write for your emitter. Fabric ships no profile in any release
artifact; the image and the chart hold none.

```json
{
  "schema_version": "fabric.otlp-mapping-profile/v1",
  "profile_id": "my-approval-service",
  "profile_version": 1,
  "rules": [
    {
      "match": {"span_name": "approvals.decision"},
      "record": "control",
      "assertion_origin": "service",
      "map": [
        {"source": "approval.outcome", "target": "fabric.control.decision",
         "values": [{"from": "approved", "to": "allow"}, {"from": "rejected", "to": "deny"}]},
        {"source": "approval.engine", "target": "fabric.control.engine.name"},
        {"source": "approval.tool_call", "target": "fabric.control.gated_tool_call_id",
         "pseudonymise": "provider"},
        {"source": "approval.elapsed_ms", "target": "fabric.control.latency_ms"}
      ],
      "set": [
        {"target": "fabric.control.kind", "value": "approval"},
        {"target": "fabric.control.phase", "value": "resolution"}
      ]
    }
  ]
}
```

What the Node does with it (the `fabricmap` processor, directly before
fabricguard):

- A span or log record whose name (and listed literal attribute values)
  matches a rule is **rewritten to the rule's targets only**. Every other
  attribute, the body, span events, links, status message and trace state
  are dropped (drop-by-default). The span keeps its trace and span ids and
  times.
- A `values` map translates literal values; a value not in the map is
  omitted, never guessed.
- A target that is an identifier must name its pseudonym type
  (`pseudonymise`); the Node replaces the value with the keyed pseudonym
  before fabricguard sees it. The clear id never leaves the Node.
- The Node stamps `fabric.capture.source=reported`,
  `fabric.capture.point=otlp.mapping_profile@1`, the record's step kind,
  the invariants on a control record, and `fabric.control.derivation=reported`,
  `fabric.grant.source_boundary=otlp` or
  `fabric.extension.observed_via=reported`. A profile cannot map or set
  them to anything else.
- A record that matches no rule is untouched (fabricguard still applies).
- A profile that breaks a rule stops the Node at startup with the place and
  the fix, for example `mapping profile refused at $.rules[0].map[2]:
  identifier target fabric.control.gated_tool_call_id must name its
  pseudonym type; … add "pseudonymise": "provider"`.

### Enabling it with Helm

```yaml
otel-collector:
  fabric:
    mapping:
      enabled: true
      profileConfigMap: {name: approval-mapping, key: profile.json}
      idKeySecret: {name: fabric-id-key, key: key}   # the agents' FABRIC_WIRE_ID_KEY bytes
      genaiSourceKeys: ""                              # or "1.42.0"
```

The ConfigMap and Secret are yours (`kubectl create configmap
approval-mapping --from-file=profile.json`). Mapping is off by default and is
not available together with `receiver.sourceBindings` (ingress groups). On a
production Node with a bound ingress, mapped records are stamped with the
ingress binding so fabricguard keeps them; `fabric-gate` refuses a
configuration that runs `fabricmap` anywhere but directly before
`fabricguard`, or with a binding different from the guard's.
