# otel-collector (subchart)

Deploys the SingleAxis Fabric OpenTelemetry Collector distribution
— the OCB build with `fabricguard`, `fabricpolicy`, `fabricredact`,
and `fabricsampler` wired in. The chart is also installable
standalone, which is the expected path while the umbrella chart is
scaffolded.

## Authoritative refs

- [`../../../../specs/004-telemetry-bridge.md`](../../../../specs/004-telemetry-bridge.md)
- [`../../../../specs/008-deployment-model.md`](../../../../specs/008-deployment-model.md)
- [`../../../../components/otel-collector-fabric/`](../../../../components/otel-collector-fabric/)

## Install (standalone)

```bash
helm install fabric-otelcol charts/fabric/charts/otel-collector \
  --namespace fabric-system --create-namespace \
  --set image.repository=ghcr.io/singleaxis/fabric-otelcol \
  --set image.tag=0.1.0 \
  --set exporter.endpoint=http://fabric-ingest.fabric-system.svc:8080
```

## Key values

| Key | Default | Notes |
| --- | --- | --- |
| `image.repository` | `ghcr.io/singleaxis/fabric-otelcol` | Published image (tick 4). |
| `fabric.guard.enabled` | `true` | Deny-by-default schema allowlist. Keep on. |
| `fabric.policy.enabled` | `true` | OPA gate. No-op until `bundlePath` is set. |
| `fabric.redact.enabled` | `false` | Needs a Presidio sidecar on `unixSocket`. |
| `fabric.sampler.enabled` | `true` | Requires `hmacKey` OR `hmacKeySecret`. |
| `exporter.endpoint` | `http://fabric-ingest:8080` | OTLP/HTTP egress target. |

The chart refuses to render if `fabric.sampler.enabled=true` but
neither `hmacKey` nor `hmacKeySecret.name` is set — see
`_helpers.tpl`'s `otel-collector.validateSampler`.

## Posture

- Distroless `nonroot` runtime (UID 65532).
- `readOnlyRootFilesystem: true`, drop all capabilities,
  `seccompProfile: RuntimeDefault`.
- ServiceAccount token **not** auto-mounted.
- No privileged paths in the default render.

## Health

The `health_check` extension listens on `:13133`. The liveness and
readiness probes hit `/` on that port. `helm test` spins a short-lived
curl pod that verifies the same endpoint end-to-end through the
Service.

## Known gaps

- Presidio sidecar is not bundled — `fabric.redact.enabled: true`
  assumes the sidecar is mounted externally.
- OPA bundle loader is not included — you must mount `bundlePath`
  yourself (the current template allocates an emptyDir so the path
  is always valid).
- PodDisruptionBudget, HPA, and NetworkPolicy are not yet templated.
  They land once the umbrella chart's cross-cutting templates do.
