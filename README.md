<div align="center">

# SingleAxis Fabric

**A customer-controlled recorder for AI systems.**

Passively capture observable agent activity, protect it before export, and
reliably deliver a verifiable record to a destination you choose.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Recorder CI](https://github.com/singleaxis/singleaxis-fabric/actions/workflows/recorder-ci.yml/badge.svg)](https://github.com/singleaxis/singleaxis-fabric/actions/workflows/recorder-ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/singleaxis/singleaxis-fabric/badge)](https://securityscorecards.dev/viewer/?uri=github.com/singleaxis/singleaxis-fabric)

[Quickstart](docs/quickstart.md) ·
[Custom-agent recording](docs/custom-agent-recording.md) ·
[Architecture](docs/architecture.md) ·
[Deployment](docs/deployment.md) ·
[Recorder v1 specification](specs/027-recorder-v1.md) ·
[Security](SECURITY.md)

</div>

## One product, three responsibilities

```text
Agent or existing telemetry
            |
            v
      CAPTURE -> PROTECT -> DELIVER
            SingleAxis Fabric OSS
```

- **Capture** records explicitly instrumented model and tool calls, or accepts
  existing OpenTelemetry from SDKs, collectors and customer integrations.
- **Protect** applies a metadata-only export allowlist before telemetry crosses
  the customer boundary. Raw prompts, responses, tool payloads, headers,
  credentials, and tokens are denied by default.
- **Deliver** buffers and retries protected telemetry to the customer's own
  OTLP backend, a private SingleAxis deployment, or SingleAxis Platform.

The default deployment is passive shadow recording. Recording failures must
not block or change the agent's action. Storage and delivery run outside the
monitored call path; instrumentation still has CPU/memory overhead that must
be measured for the deployment.

## What data can be recorded

Tracing alone records the timeline and relationships between calls, not their
full contents. With explicit opt-in, the Python custom-agent recorder also
stores the actual input, output, context and ordered stream bytes supplied at
your agent's call boundary in a separate customer-controlled content store.
Calls retain agent, parent-call, operation and attempt identities, including
parallel work, retries, failures and cancellation.

Connect it at your existing dispatcher's final model/tool send and receive
points; no particular agent framework is required. See
[custom-agent integration](docs/custom-agent-recording.md) and
[privacy choices](docs/custom-agent-recording-privacy.md). Configure separate
access for original evidence and masked review copies. Masked or withheld
content cannot be treated as the original bytes.

Fabric does not automatically observe every reachable tool, remote machine
or database. A tool result records what the agent received; proving an
external change also requires the system's own records. The
[coverage inventory](docs/agent-activity-coverage.md) identifies these limits.

## What ships

| Artifact | Purpose |
|---|---|
| Fabric SDKs | Optional Python and TypeScript instrumentation |
| Fabric Node | One OpenTelemetry Collector distribution for capture, protection, buffering, and delivery |
| `fabricctl` | Local recorder initialization, configuration validation, digest, help, and version |
| Public contracts | Activity, connection, privacy, recorder, and delivery interoperability |

A SingleAxis account is not required. You can deliver to infrastructure you
operate and inspect every component in the customer trust boundary.

## What does not ship in recorder v1

Recorder v1 does not install judges, red-team runners, prompt-time PII or
guardrail engines, policy enforcement, assurance tiers, regulatory profiles,
Decision Graph analytics, incident workflows, or an enterprise management UI.

Those are consumers of the record or optional later runtime capabilities:

```text
Fabric OSS                 SingleAxis Platform          Optional later runtime
CAPTURE -> PROTECT ->      MONITOR -> EVALUATE ->       ENFORCE
DELIVER                    GOVERN
```

Removed capabilities remain in Git history only. Recorder artifact-content
tests prevent them from entering SDK packages, binaries, charts or installers.

## Start locally

Install the Python SDK when you control the agent code:

```bash
pip install "singleaxis-fabric[otlp]"
```

Send spans to a local Fabric Node:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

```python
import os

from fabric import Fabric, FabricConfig, install_default_provider
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

install_default_provider(
    service_name="claims-assistant",
    exporter=OTLPSpanExporter(
        endpoint=os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] + "/v1/traces"
    ),
)

fabric = Fabric(
    FabricConfig(tenant_id="example", agent_id="claims-assistant")
)

with fabric.decision(session_id="session-1", request_id="request-1") as decision:
    with decision.llm_call(provider="example", model="example-model") as call:
        response = run_your_agent()
        call.set_usage(input_tokens=10, output_tokens=20, finish_reason="stop")
```

If you do not control the agent code, send its existing OTLP telemetry to the
Fabric Node or place a supported telemetry gateway outside its request path.
See [integration models](docs/integration-models.md).

## Configure the recorder

Run the local wizard:

```bash
fabricctl init
```

It writes a recorder configuration without credentials and reports that the
configuration is prepared, not installed. Review it before applying any
deployment change.

For Kubernetes evaluation:

```bash
helm dependency build charts/fabric
helm upgrade --install fabric charts/fabric \
  --namespace fabric-system \
  --create-namespace \
  --values charts/fabric/profiles/shadow-dev.yaml
```

`shadow-dev` is intentionally non-production. The `shadow-production` profile
requires the operator to provide authenticated TLS ingress, authenticated HTTPS
egress, persistent storage, and explicit ingress and exporter network peers.
The chart must refuse an incomplete production configuration.

## Security posture

- Metadata-only protection is the default export mode.
- Fabric Node does not sample accepted audit traffic; upstream systems may
  still have their own sampling or blind spots.
- Production delivery uses persistent queue storage and at-least-once export;
  destinations must deduplicate using preserved trace/span identity or
  identities added by an adapter.
- Queued, transmitted, destination-accepted, and durably-persisted are distinct
  concepts in the public delivery contract. Fabric Node does not automatically
  emit a durable-persistence receipt, and HTTP success is not such proof.
- Fabric does not claim that metadata-only export, by itself, satisfies legal
  de-identification requirements. Customers remain responsible for data
  classification, retention, lawful basis, and destination controls.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and
[the recorder specification](specs/027-recorder-v1.md) for release gates.

## Project status

Recorder v1 is a pre-production release candidate. A bounded synthetic
model/tool/file workflow has passed installed-package and Linux Kubernetes
tests, including source restart, missing-record detection, authenticated
ingress and protected delivery. This is not universal capture or approval
for a critical production deployment.

Production qualification remains **NO-GO** until the declared deployment has
independent complete records, the required delivery/storage proofs, tested
privacy and retention controls, and named owner approval. The
[qualification status](docs/recorder-v1-qualification-status.md) records exact
artifacts, passed tests and remaining engineering and deployment work. Use
the [pinned-install guide](docs/install.md) for deployment preparation;
unreviewed source and an unpinned package are not a qualified release.

Apache-2.0. Contributions require DCO sign-off; see
[CONTRIBUTING.md](CONTRIBUTING.md).
