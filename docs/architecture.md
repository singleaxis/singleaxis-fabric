# Architecture

SingleAxis Fabric is a customer-controlled recording data plane for AI
systems. One deployable runtime — **Fabric Node** — performs the whole product
pipeline:

```text
CAPTURE -> PROTECT -> DELIVER
```

- **Capture** — accept OTLP telemetry from SDKs, adapters, or an existing
  collector over an authenticated listener.
- **Protect** — strip everything except an exact metadata allowlist before
  records cross the customer boundary.
- **Deliver** — buffer records in a persistent queue and retry export to the
  customer-chosen destination until it succeeds. At least once, never best
  effort.

The recorder is **passive**: it observes telemetry and must never block,
alter, or delay the monitored AI system. The accepted design of record is
[spec 027](../specs/027-recorder-v1.md).

## System context

```mermaid
flowchart LR
    subgraph MONITORED["Monitored AI system (customer workload)"]
        AGENT["Agent application"]
        SDK["Fabric SDK<br/>Python / TypeScript"]
        OTLP["Existing OTLP pipeline"]
        ADP["Framework / vendor adapter"]
        AGENT --> SDK
        AGENT --> OTLP
        AGENT --> ADP
    end

    subgraph BOUNDARY["Customer-controlled boundary"]
        NODE["<b>Fabric Node</b><br/>capture · protect · deliver"]
        QUEUE[("Persistent queue<br/>file storage, fsync")]
        NODE <--> QUEUE
    end

    subgraph DEST["Destination (customer chooses)"]
        BACKEND["Customer OTLP backend<br/>Jaeger · Tempo · vendor"]
        PLATFORM["SingleAxis Platform<br/>(optional, downstream)"]
    end

    SDK -- "OTLP :4317/:4318<br/>+ auth" --> NODE
    OTLP -- "OTLP :4317/:4318<br/>+ auth" --> NODE
    ADP -- "OTLP :4317/:4318<br/>+ auth" --> NODE
    NODE -- "protected OTLP/HTTP + auth<br/>at-least-once" --> DEST

    BACKEND -. "monitor · search · investigate" .-> CONSUMER["Operators"]
    PLATFORM -. "evaluate · Decision Graph" .-> CONSUMER
```

Three boundaries matter:

1. **The monitored system is unaffected.** Telemetry flows one way; a Fabric
   Node outage cannot change an agent decision.
2. **Protection happens inside the customer boundary.** The allowlist runs in
   Fabric Node *before* export — not downstream, not "in transit".
3. **The destination is the customer's choice.** A private OTLP backend, a
   private SingleAxis deployment, or SingleAxis Platform — Fabric Node behaves
   identically toward each.

## Inside Fabric Node

Fabric Node is an OpenTelemetry Collector distribution with one job. The
pipeline is deliberately minimal — fewer stages, fewer failure modes:

```mermaid
flowchart TD
    subgraph IN["CAPTURE"]
        GRPC["OTLP gRPC :4317"]
        HTTP["OTLP HTTP :4318"]
        AUTH{"authenticated?"}
        GRPC --> AUTH
        HTTP --> AUTH
        AUTH -- "no token / bad cert" --> REJ["401 / TLS reject<br/>(record never enters)"]
    end

    subgraph PROC["PROCESSORS (in order)"]
        ML["memory_limiter<br/>512 MiB — bounded memory"]
        FG["<b>fabricguard processor</b><br/>metadata-only allowlist"]
        ML --> FG
    end

    subgraph OUT["DELIVER"]
        SQ["sending_queue<br/>persistent · fsync · block_on_overflow"]
        RT["retry_on_failure<br/>max_elapsed_time: 0 — never gives up"]
        EXP["otlp_http exporter<br/>HTTPS + Authorization header"]
        SQ --> RT --> EXP
    end

    EXT["Extensions:<br/>health_check :13133 · file_storage · bearertokenauth"]
    METRICS[("Internal metrics :8888<br/>queue depth · send failures")]

    AUTH -- "valid" --> ML
    FG --> SQ
    EXP -- "protected records" --> DEST2[("Customer destination")]

    AUTH -.-> EXT
    SQ -.-> METRICS
```

Design notes:

- **No batch processor before the queue.** A volatile in-memory batch window
  in front of the durable queue would be a silent-loss mode; records are
  persisted per-request.
- **`block_on_overflow: true`.** A full queue back-pressures the receiver —
  the exporter blocks until space frees rather than the record silently
  dropping. This is the fail-safe choice for a recorder: backpressure is
  visible, loss is not.
- **`max_elapsed_time: 0s`.** Retry never expires. A destination outage
  pauses delivery; it does not delete data.
- **`memory_limiter` first.** The node sheds load on itself before it can be
  OOM-killed mid-batch.
- **Two pipelines only: `traces` and `logs`.** The image entrypoint
  (`fabric-gate`) refuses to boot a config defining any other pipeline, and
  the distribution-qualification test
  (`tests/qualify-distribution-config.sh`) proves the refusal, so new signal
  types cannot widen the export surface accidentally. `fabric-gate` also
  supervises bearer-token material while the collector runs — a mid-run
  rotation to an unsafe token file stops the recorder instead of minting an
  empty credential.

## How PROTECT decides what crosses the boundary

The allowlist applies to the shipped traces and logs pipelines; `fabric-gate`
enforces that pipeline set at container startup inside the image (bare-binary
builds rely on the qualification test).

The `fabricguard` processor applies a per-record, per-attribute decision
cascade. Every attribute key must survive all four gates:

```mermaid
flowchart TD
    IN["Attribute on span / event / log record"]
    G1{"1. sensitive name?<br/>prompt · response · message · body · payload<br/>argument · result · header · cookie · token"}
    G2{"2. exact allowlist key?<br/>metadata fields only<br/>identifiers · enums · counts · hashes"}
    G3{"3. *hash key ⇒ valid SHA-256 hex?<br/>no freeform values smuggled in a hash field"}
    G4{"4. scalar / flat slice shape?<br/>maps and byte arrays removed<br/>strings ≤ 8 KiB"}

    IN --> G1
    G1 -- "yes (and not explicitly safe)" --> DROP1["REMOVED<br/>sensitive"]
    G1 -- "no" --> G2
    G2 -- "no" --> DROP2["REMOVED<br/>not_allowed"]
    G2 -- "yes" --> G3
    G3 -- "no" --> DROP3["REMOVED<br/>invalid_hash"]
    G3 -- "yes" --> G4
    G4 -- "no" --> DROP4["REMOVED<br/>oversized / structured"]
    G4 -- "yes" --> KEEP["EXPORTED"]
```

Two more rules complete the gate:

- **Log record bodies and severity text are cleared.** Only allowlisted
  attributes and a normalized `event_name` survive — a log body is a free-form
  string channel and is always treated as content.
- **Event names are normalized to a fixed vocabulary** (`fabric.decision`,
  `fabric.llm_call`/`fabric.model_call`, `fabric.tool_call`,
  `fabric.retrieval`, `fabric.memory`, `fabric.side_effect`,
  `fabric.interaction`, `fabric.file_access`, `fabric.delegation`,
  `fabric.checkpoint`, `fabric.replay`, `fabric.mcp.inventory`,
  `fabric.skill`, `fabric.hook`, `fabric.coverage`, `fabric.error`,
  `fabric.retry`, `fabric.cancellation`, `fabric.execution`, …). Unknown
  names map to `fabric.activity` or are dropped when
  `drop_unknown_classes` is on — a caller-controlled event name can never
  smuggle text out.

The allowlist is **exact-key, not namespaced**. `fabric.*` as a prefix is not
trusted — every field the SDKs emit was reviewed and individually admitted
(identifiers, workflow/delegation structure, token counts, enums, hashes).
Caller-controlled free text — `fabric.tags`, `user_id`, raw paths, raw
targets, memory keys — stays denied. Removing denied keys is not the same as
guaranteeing no sensitive data exists in the remaining metadata; customers
still own classification and retention.

## Delivery lifecycle

```mermaid
stateDiagram-v2
    [*] --> Accepted : valid OTLP + auth
    Accepted --> Queued : fabricguard passed,<br/>fsync to volume
    Queued --> Dispatched : consumer picks batch
    Dispatched --> Acknowledged : destination 2xx
    Dispatched --> Queued : timeout / 5xx / network<br/>(retry, exponential backoff)
    Queued --> [*] : delivered (at least once)

    note right of Queued
        fsync before the record is
        visible for dispatch — survives
        pod delete, container restart,
        hard reboot (volume permitting)
    end note

    note right of Acknowledged
        "Accepted" means the destination
        answered 2xx. Durable persistence
        at the destination is its own
        evidence — not implied by ours.
    end note
```

What each state means operationally:

| State | Meaning | Who observes it |
|---|---|---|
| Accepted | Fabric Node returned 2xx to the agent | agent SDK |
| Queued | record fsynced to the node's volume | `otelcol_exporter_queue_size` |
| Dispatched | batch sent to destination | exporter logs |
| Acknowledged | destination answered 2xx | retry counter stops |
| Delivered | destination durably persisted | **destination's own evidence** |

Node restart: on boot, `file_storage` reloads the queue index and compacts —
undelivered records re-enter `Dispatched`. Destination outage: records
accumulate in the queue (bounded by `queue_size` items — size the volume for
the expected outage window) and drain when the destination returns.

Duplicate delivery is possible after ambiguous acknowledgements. Destinations
must deduplicate on the preserved `trace_id`/`span_id`/`event_id` — identity
is deliberately retained for exactly this reason.

## What arrives at the destination

A monitored workflow lands as a standard OTLP trace — existing backends
render it without any Fabric-specific tooling:

```mermaid
flowchart TD
    D["<b>fabric.decision</b> span<br/>tenant_id · agent_id · session_id · request_id<br/>workflow_id · execution_id · trace/span ids"]
    LLM["llm_call span<br/>gen_ai.request.model · provider<br/>input/output tokens · finish_reason"]
    TOOL["tool_call span<br/>tool name · type<br/>arguments_hash · result_hash"]
    EV["span events on the decision:<br/>fabric.retrieval · fabric.memory<br/>fabric.side_effect · fabric.checkpoint<br/>fabric.delegation · fabric.interaction"]

    D --> LLM
    D --> TOOL
    D --> EV

    LLM --- CONTENT["content visible:<br/>model, provider, token counts,<br/>status — never the prompt/response"]
    TOOL --- CONTENT2["content visible:<br/>name, kind, hashes of payloads —<br/>never the payload"]
```

Cross-service agent workflows stay connected: SDK `inject()` writes W3C
`traceparent` plus Fabric identity into carriers, and the child decision
stamps `fabric.parent_agent_id` / `fabric.parent_decision_id`. A delegated
call chain reconstructs as one trace.

## Deployment topologies

### Single client VM (Docker, no Kubernetes)

```mermaid
flowchart LR
    subgraph HOST["Client VM"]
        subgraph AG["Agent workload"]
            APP["monitored agent<br/>(SDK or OTLP)"]
        end
        subgraph FN["docker compose (production overlay)"]
            NODE2["fabric-node container<br/>nonroot · read-only · cap_drop ALL"]
            V[("named volume<br/>fabric-queue")]
            NODE2 --- V
        end
    end

    APP -- "127.0.0.1:4318<br/>Authorization: Bearer" --> NODE2
    NODE2 -- "https + Authorization<br/>your OTLP backend" --> EXT["External destination"]

    subgraph OPS["Operate"]
        PF["make preflight-prod<br/>make verify-prod"]
        M["127.0.0.1:8888 metrics<br/>127.0.0.1:13133 health"]
    end
    FN -.-> OPS
```

Path: `deploy/compose/` — `make preflight-prod && make up-prod && make verify-prod`.
Ingress requires a bearer token (file secret); egress requires HTTPS + auth
header; receiver TLS is supported before binding beyond loopback.

### Kubernetes

```mermaid
flowchart LR
    subgraph NS["cluster namespace"]
        subgraph SVC["ClusterIP service"]
            POD["fabric-node-otel-collector-0<br/>StatefulSet + PVC queue<br/>NetworkPolicy · nonroot"]
            PVC[("PersistentVolumeClaim<br/>durable queue")]
            POD --- PVC
        end
    end

    AG2["agent workloads<br/>in-cluster"] -- "mTLS / bearer<br/>+ NetworkPolicy" --> POD
    POD -- "https + auth" --> EXT2["destination"]

    subgraph PROF["Profiles"]
        DEV["shadow-dev<br/>local evaluation"]
        PROD["shadow-production<br/>fail-closed: pinned image,<br/>TLS required, explicit peers"]
    end
    NS -.-> PROF
```

Path: `helm install fabric charts/fabric -f charts/fabric/profiles/shadow-production.yaml`
plus the required secrets. The production profile fails closed on unpinned
images, missing TLS, and unbounded network peers.

## Components

| Component | What it is | What it is not |
|---|---|---|
| **Fabric SDKs** (Python, TypeScript) | Optional instrumentation emitting rich agentic-workflow telemetry (decisions, LLM/tool calls, retrieval, memory, side effects, delegation, checkpoints) | Required — any OTLP source works; richer source, richer record |
| **Fabric Node** | The recorder runtime: OTel Collector + `fabricguard` + durable queue | A relay, a proxy, or a control plane — no second hop, no agent control |
| **`fabricctl`** | Offline CLI: `init` (interactive wizard), `recorder validate`, `recorder digest` | A deploy tool — `init` writes a config + receipt marked `not-installed` |
| **Helm chart** | `charts/fabric` with `shadow-dev` / fail-closed `shadow-production` profiles | A management plane |
| **Compose overlay** | `deploy/compose` production path for a plain VM | An orchestration framework — Docker + restart policy is the whole story |
| **Contracts** | Public schemas: Activity Envelope v2, connect capability, privacy assertion, delivery evidence, recorder config | Runtime behavior — the envelope is the downstream normalization target, not what the node emits on the wire |

## What the recorder does not do

The release binary/chart/package surfaces contain no judges, red-team
runners, prompt-time PII engines, guardrails, policy enforcement, tool
authorization, or management UI — enforced by artifact-content tests, not
just disabled defaults. Blocking or altering agent traffic requires an
inline placement the passive recorder never occupies; that is a separate,
deliberate decision for later.

Downstream services (SingleAxis Platform, or any backend) consume the
protected record for monitoring, evaluation, and Decision Graph analysis.
They are consumers, not hidden dependencies — Fabric Node delivers a
verifiable record with or without them.
