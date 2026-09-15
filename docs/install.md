# Install a pinned Fabric recorder release

Install one qualified version and promote the same bytes through development,
staging, and production. Do not deploy `main`, a floating image tag, or an
unreviewed dependency range in a regulated environment.

Fabric recorder releases contain only:

| Artifact | Distribution | Purpose |
|---|---|---|
| Python SDK | PyPI and release wheel | Optional in-process capture |
| TypeScript SDK | npm and release package | Optional in-process capture |
| Fabric Node | `ghcr.io/singleaxis/fabric-otelcol` | Protect, buffer, and deliver OTLP |
| Helm chart | GHCR OCI and release package | Install Fabric Node |
| `fabricctl` | Release archives | Prepare and validate local recorder configuration |
| Public contracts | Release archive | Activity, connect, privacy, recorder, and delivery interoperability |

Installing Fabric does not certify a system or satisfy a regulation by itself.

## Before installation

1. Select an exact release candidate or stable version.
2. Read its changelog and `release-qualification.json`.
3. Follow [Verify a Fabric release](verify-release.md).
4. Record the release tag, commit, artifact hashes, OCI digests, verifier
   identity, review decision, and intended environment.
5. Mirror approved artifacts into controlled registries when company policy
   requires it.

Release candidates are for enterprise testing until their published evidence
and your own environment qualification support promotion.

## SDK installation

For normal development, pin the selected package version:

```bash
python -m pip install "singleaxis-fabric==VERSION"
npm install --save-exact "@singleaxis/fabric@VERSION"
```

For a controlled Python installation, download the exact wheel, compare its
SHA-256 with the qualification report, install approved dependencies from an
internal index, and install the wheel without resolving new dependencies:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --no-deps ./singleaxis_fabric-VERSION-py3-none-any.whl
python -m pip check
```

The SDK is optional. Existing systems can send compatible OTLP directly to
Fabric Node.

## Prepare local configuration

Download the `fabricctl` archive for the operator platform, verify it against
`fabricctl-SHA256SUMS`, and run:

```bash
fabricctl init
fabricctl recorder validate ./fabric-recorder.yaml
fabricctl recorder digest ./fabric-recorder.yaml
```

`fabricctl init` writes local configuration with mode `0600`; it does not
install workloads or contact a management service. Recorder v1 does not expose
the historical management, plan, approval, rollout, or assurance commands.

## Kubernetes evaluation

Pull or download one exact chart version. For a local test:

```bash
kubectl label namespace monitored-agents fabric.singleaxis.ai/agent=true

helm upgrade --install fabric ./fabric-VERSION.tgz \
  --namespace fabric-system \
  --create-namespace \
  --values charts/fabric/profiles/shadow-dev.yaml
```

`shadow-dev` may use plaintext input and pod logs. It is not durable and must
not cross a production trust boundary.

## Production shadow deployment

Start from `shadow-production`. Supply organization-owned TLS certificates,
client CA, export authorization Secret, HTTPS endpoint, persistent storage,
tenant identity, and explicit NetworkPolicy ingress and egress. The chart
refuses an incomplete production posture.

```bash
helm upgrade --install fabric ./fabric-VERSION.tgz \
  --namespace fabric-system \
  --create-namespace \
  --values charts/fabric/profiles/shadow-production.yaml \
  --set tenant.id=TENANT_UUID \
  --set otel-collector.exporter.endpoint=https://approved-otlp.example.com \
  --set 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true' \
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443' \
  --wait --atomic
```

The CIDR above is documentation-only. Route through an approved egress gateway
when the destination does not have a stable, reviewable network identity. See
[Deployment](deployment.md) for required Secrets and invariants.

## Promotion record

Retain, for every environment:

- exact tag, commit, wheel/package/chart hashes, and image digest;
- signature, provenance, and qualification output;
- reviewed Fabric values and Secret references, never Secret values;
- connector capability manifest and accepted blind spots;
- post-install capture, protection, restart, retry, and delivery test results;
- destination acknowledgement semantics and deduplication behavior;
- change approval, installer identity, time, and rollback target.

A source rebuild is a different artifact unless reproducible equivalence has
been independently established.
