# Disaster recovery

This page is the actionable DR runbook for a Fabric deployment. RPO,
RTO, and concrete restore commands are below; longer-form per-profile
runbooks (multi-region failover, automated cutover) remain Phase 2.

## RPO / RTO targets

| Component | RPO | RTO | Recovery approach |
|-----------|-----|-----|-------------------|
| **OTel Collector** | 0 (stateless) | 5 min | `helm rollout` |
| **Presidio sidecar** | 0 (stateless) | 5 min | `helm rollout` |
| **NeMo sidecar** | 0 (stateless) | 5 min | `helm rollout` |
| **Update-agent webhook** | 0 (config in Git) | 10 min | `helm rollout` + ArgoCD sync |
| **Langfuse Postgres** | ≤ 30 min (WAL archival) | ≤ 60 min | `pg_basebackup` restore |
| **Langfuse object store** | ≤ 24 hr (snapshot) | ≤ 60 min | S3/GCS snapshot restore |
| **Decision-span trail (downstream)** | tenant-owned | tenant-owned | Whatever your trace backend (Langfuse/Tempo/Honeycomb) provides |

Stateless components recover by redeploying the Helm chart against
a fresh cluster. Stateful components require the tenant's standard
backup channel; Fabric does not bundle backup tooling but the
chart's Postgres values support pointing at managed Postgres
(RDS, Cloud SQL, AlloyDB, Crunchy) where backup is the provider's
responsibility.

## Pre-incident readiness

Run weekly:

```bash
# 1. Verify Helm release is healthy and reachable from kubectl
helm -n fabric-system status fabric
kubectl -n fabric-system get pods,svc,validatingwebhookconfigurations

# 2. Verify Postgres backup is current (managed Postgres example)
aws rds describe-db-snapshots --db-instance-identifier fabric-langfuse \
  --query 'DBSnapshots[?Status==`available`].[SnapshotCreateTime,DBSnapshotIdentifier]' \
  --output table | head -5

# 3. Smoke-test the agent path: should produce a span in Langfuse
python -c "
from fabric import Fabric, FabricConfig
f = Fabric(FabricConfig(tenant_id='dr-canary', agent_id='dr-test'))
with f.decision(session_id='dr', request_id='dr-1') as d:
    d.set_attribute('dr.canary', 'true')
    print(d.trace_id)
"
# Wait 30s; query Langfuse for the trace_id.
```

A weekly dry-run that fails on any of these three is a leading
indicator the cluster will not recover cleanly.

## Recovery procedure

### Phase 1 — Provision the recovery cluster

```bash
# Pick a recovery region/cluster. Pin the chart version that was
# running pre-incident — record this in your incident channel.
export FABRIC_VERSION=0.2.0
export RECOVERY_NAMESPACE=fabric-system

# Provision the cluster (cloud-specific; not Fabric-specific).
# Confirm CNI is up and storage classes exist before proceeding.
kubectl get storageclasses
kubectl get csidrivers
```

### Phase 2 — Restore Postgres

```bash
# Managed Postgres (RDS example). Adjust for your provider.
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier fabric-langfuse-recovery \
  --db-snapshot-identifier <most-recent-snapshot> \
  --db-instance-class db.r6g.large

# Wait for endpoint to come up.
aws rds wait db-instance-available --db-instance-identifier fabric-langfuse-recovery

# Capture the new DSN.
export FABRIC_LANGFUSE_DSN=postgresql://<user>:<pass>@<endpoint>:5432/langfuse
```

### Phase 3 — Reinstall the chart

```bash
# Install Fabric, pinning the exact pre-incident version. Use your
# saved values.yaml (kept in Git per spec 008 — never edit live).
helm install fabric oci://ghcr.io/singleaxis/charts/fabric \
  --version "${FABRIC_VERSION}" \
  --namespace "${RECOVERY_NAMESPACE}" \
  --create-namespace \
  --values profiles/<your-profile>.yaml \
  --set tenant.id=<your-tenant-uuid> \
  --set langfuse.database.dsnSecret.name=fabric-langfuse-db \
  --set update-agent.config.trustedKeys[0].publicKey=<your-real-key>
```

### Phase 4 — Validate

```bash
# 1. All pods Ready
kubectl -n "${RECOVERY_NAMESPACE}" wait --for=condition=Ready pod \
  --selector=app.kubernetes.io/part-of=fabric --timeout=5m

# 2. Webhook is registered and reachable
kubectl get validatingwebhookconfiguration | grep fabric

# 3. Smoke-test the agent path (same as the weekly dry-run above)

# 4. Confirm the canary span lands in restored Langfuse — if not,
#    Postgres restore went wrong; rollback before serving traffic.
```

### Phase 5 — Cut traffic over

This is profile-specific and depends on your tenant DNS / load
balancer setup. Fabric components don't manage cutover; they're
ready to receive traffic once the cluster is up.

## Common failures and recovery

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `helm install` fails: `tenant.id is required` | Missing `--set tenant.id` | Add it; chart fail-renders by design (see CHANGELOG 0.2.0) |
| Webhook fails: `placeholder publicKey` | Forgot to pass real Ed25519 key | `--set update-agent.config.trustedKeys[0].publicKey=<base64>` |
| Pods CrashLoopBackOff with "Postgres unreachable" | DSN points at the wrong host or backup hasn't promoted | Verify DSN; verify pg_isready against the new host |
| Agent code's spans show up in old Langfuse, not new | Agent's `OTEL_EXPORTER_OTLP_ENDPOINT` still points at the dead cluster | Update the agent-side env var to point at the recovery collector |
| `cosign verify` fails on the published image | You're trying to install an unsigned tag (e.g. `latest` after a roll) | Pin to a specific signed version: `--version 0.2.0` |

## Backup schedule recommendations

Tenants own backup; Fabric makes recommendations:

- **Postgres**: daily full backup + WAL archival every 5 minutes.
  Provider-managed (RDS / Cloud SQL) covers this with `automated-backups`.
- **Object store** (Langfuse blobs, judge prompt cache): daily
  snapshot to a different region. 30-day retention minimum.
- **Helm values + secrets**: stored in Git (encrypted with SOPS or
  similar); tenant's CI restores them.

## What's NOT covered here (yet)

- **Multi-region active/active failover** — Phase 2.
- **Automated backup validation tooling** — Phase 2.
- **Per-profile runbooks** for non-shipped profiles (NIST RMF, ISO
  42001, SR 11-7, HIPAA) — Phase 2.
- **Context Graph and escalation-service recovery** — those run as
  SingleAxis-internal services, not in this distribution.

## Pointers

- Chart and subcharts: [`charts/fabric/`](../../charts/fabric/)
- Bootstrap Job: [`components/langfuse-bootstrap/`](../../components/langfuse-bootstrap/)
- Deployment model (source of record):
  [`specs/008-deployment-model.md`](../../specs/008-deployment-model.md)
- Deployment doc: [`../deployment.md`](../deployment.md)
