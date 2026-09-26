# Quickstart

This walkthrough runs the passive recorder locally:

```text
your OTLP trace -> Fabric Node -> metadata protection -> fsync test sink
```

It does not run guardrails, judges, red teams, policy enforcement, or a
SingleAxis management service.

## Prerequisites

- Docker with Compose
- Python 3.11+ when using the optional Python SDK

## 1. Start the evaluation harness

```bash
cd deploy/compose
make up
make status
```

Fabric Node receives OTLP/gRPC on `localhost:4317` and OTLP/HTTP on
`localhost:4318`. The controlled test sink stores received requests on a Docker
volume and acknowledges only after fsync.

This harness is plaintext and unauthenticated. Never use it across a trust
boundary.

## 2. Send one recorded operation

Install the SDK with its OTLP exporter:

```bash
pip install "singleaxis-fabric[otlp]==0.8.0rc1"
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

```python
import os

from fabric import Fabric, FabricConfig, install_default_provider
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

install_default_provider(
    service_name="example-agent",
    # Explicit endpoint must include the signal path — bare host:port
    # posts to "/" and gets a 404 on some exporter versions.
    exporter=OTLPSpanExporter(
        endpoint=os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] + "/v1/traces"
    ),
)

fabric = Fabric(FabricConfig(tenant_id="example", agent_id="example-agent"))

with fabric.decision(session_id="session-1", request_id="request-1") as decision:
    with decision.llm_call(provider="example", model="example-model") as call:
        # Replace this with the model invocation you already use.
        result = "example response"
        call.set_usage(input_tokens=5, output_tokens=2, finish_reason="stop")

print(result)
```

You can skip the Fabric SDK when the monitored system already emits compatible
OpenTelemetry. Point its exporter at `http://localhost:4318` instead.

## 3. Check delivery

```bash
cd deploy/compose
make smoke
```

The sink count should increase. Fabric exports approved metadata; raw prompt,
response, tool-payload, header, token, and credential fields are removed by the
default protection processor.

## 4. Exercise outage and restart recovery

```bash
cd deploy/compose
make qualify
```

The qualification harness checks that a known trace is protected, queued while
the destination is unavailable, retained across a Fabric Node restart, and
delivered after the sink returns.

At-least-once delivery can produce duplicates after ambiguous acknowledgements.
Destinations must deduplicate using preserved trace/span identity or identities
added by an upstream or destination adapter.

## 5. Prepare a recorder configuration

With the standalone Go `fabricctl` binary:

```bash
fabricctl init
fabricctl recorder validate fabric-recorder.yaml
fabricctl recorder digest fabric-recorder.yaml
```

Initialization writes `fabric-recorder.yaml` and
`recorder-init-receipt.json`. The receipt says `not-installed`: preparation is
not a deployment mutation.

## Next

- Read [deployment](deployment.md) before crossing a trust boundary.
- Choose an [integration model](integration-models.md) for an existing system.
- Review [architecture](architecture.md) and the
  [recorder-v1 release gates](../specs/027-recorder-v1.md).
