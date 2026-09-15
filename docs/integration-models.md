# Integrating agents with Fabric

Fabric supports code-first agents, framework-managed agents, off-the-shelf
products, existing telemetry systems, and discovery of otherwise unknown
workloads. These integrations are not equivalent. For a regulated deployment,
choose the least invasive model that produces the reconstruction evidence
required, then record the residual blind spots.

The authoritative machine-readable claims live in the
[`Connect capability contract`](../contracts/connect/v1/README.md). Its
manifests distinguish what an integration observes, controls, authenticates,
propagates, and exports.

## Integration models

| Model | Deploy it | What it can know | Runtime control | Primary limitation |
| --- | --- | --- | --- | --- |
| In-process SDK | Inside agent code | Native decision, model, tool, and explicitly recorded activity | Possible before an action | Requires code access and complete instrumentation |
| Framework adapter | Registered with framework hooks | Lifecycle events exposed by that framework version | Possible where hooks are synchronous and blocking | Direct calls that bypass hooks are invisible |
| Gateway or proxy | Inline for LLM, MCP, HTTP, or tool traffic | Requests crossing known protocols; semantics may be inferred | Can block or transform traffic that must traverse it | Local or bypass traffic is invisible |
| OTLP receiver | Collector or gateway | Preserves telemetry an existing system already emitted | Telemetry acceptance/redaction/routing only | Cannot prevent an agent action that already occurred |
| Vendor receiver | Collector plugin or managed integration | Fields and history exposed by the vendor API | Usually telemetry processing only | Vendor sampling, schema, API, and retention constrain replay |
| eBPF-assisted discovery | Host agent or Kubernetes DaemonSet | Process, socket, network-flow, and file metadata | None in the Fabric discovery contract | Cannot establish prompts, decisions, tools, or policy semantics |

For an off-the-shelf agent, start with its supported audit export, OTLP output,
webhooks, or API. Put a gateway in front of provider and tool endpoints where
the product supports custom endpoints. Use eBPF only to discover processes and
bypass paths. If the product exposes neither semantic telemetry nor an inline
route, Fabric must report partial coverage; it cannot honestly reconstruct the
agent's internal reasoning from network metadata.

## Compose connectors into one trace

A regulated installation commonly composes more than one model:

```text
agent or product
  ├─ SDK / framework hook ── native decision and lifecycle spans
  ├─ gateway ─────────────── authenticated provider and tool calls
  ├─ vendor or OTLP export ─ preserved existing telemetry
  └─ eBPF discovery ──────── workload inventory and bypass indicators
                  │
                  ▼
              customer Fabric Node
              protect · queue · deliver
                  │
                  ▼
       customer backend or SingleAxis Platform
```

Correlation is reliable only when all inline components preserve W3C
`traceparent` and use the same authenticated tenant, agent, environment, and
deployment identity. A receiver can preserve an existing trace; it cannot
repair missing parents or prove that a caller-supplied tenant ID belongs to the
sender. A gateway can strengthen identity by mapping mTLS, workload identity,
or scoped credentials to tenant and agent attributes before forwarding.

Do not join unrelated records solely by timestamp, IP address, model name, or
user-supplied session ID. Those are investigation hints, not trustworthy
causal identity. When correlation is inferred, record the inference method and
confidence as provenance rather than rewriting it as a native decision edge.

## Regulated deployment gate

Before promoting a connector, retain its exact capability manifest with the
deployment approval. Verify at least:

1. the declared component version and supported protocol/runtime range;
2. observable surfaces against version-specific tests;
3. bypass behavior and known blind spots;
4. raw-content default, redaction point, and sensitive-field allowlist;
5. ingress and egress authentication, tenant binding, and credential storage;
6. W3C context propagation across every network boundary;
7. encrypted egress to an approved destination;
8. queue loss, retry, duplicate, and backend-retention boundaries; and
9. evidence paths and manifest SHA-256 digests.

The capability manifest is not a certification. It is a reviewable input to a
company's risk assessment, deployment profile, data-protection controls, and
change approval. A connector upgrade must be requalified when its hooks,
protocol mappings, identity behavior, content behavior, or blind spots change.

## Selecting the first integration

- **Code is available:** use the SDK; add framework adapters for coverage and
  a gateway when authenticated inline control is required.
- **No code, configurable endpoints:** use an authenticated gateway plus the
  product's OTLP or audit export.
- **No code, vendor telemetry exists:** build a versioned vendor receiver and
  document mapping loss and retention constraints.
- **No supported integration:** use discovery to inventory the workload and
  identify routes, but label decision reconstruction unavailable until a
  semantic or inline integration is added.

Fabric Node's metadata allowlist protects telemetry before export. It is not a
prompt firewall or a legal de-identification claim: preventing PII from reaching
a model requires a separately governed inline control before the provider call.
