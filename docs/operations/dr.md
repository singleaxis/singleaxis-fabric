# Fabric Node recovery runbook

This runbook covers the OSS recorder only. The durable state is the Collector's
persistent sending queue; telemetry already accepted by a destination follows
that destination's backup and recovery process.

## Recovery objectives

Set customer-specific recovery objectives for:

- the maximum acceptable capture interruption;
- the maximum queue backlog and outage duration;
- the time required to restore authenticated ingress and egress; and
- the destination's retention and restore guarantees.

Fabric does not publish universal RPO or RTO numbers because storage class,
traffic volume, destination behavior, and cluster operations determine them.

## Before an incident

1. Pin the released image by digest and preserve its signed chart and SBOM.
2. Record the approved values digest, Secret references, certificate issuers,
   NetworkPolicy peers, storage class, destination, and connector manifests.
3. Size queue PVCs for the tested destination-outage window.
4. Monitor queue capacity, export failures, rejected spans, restarts, PVC state,
   certificate expiry, and destination health.
5. Test node drain, pod restart, destination outage, duplicate delivery, and
   credential rotation with the exact production configuration.

## Destination outage

- Keep Fabric Node running so the persistent queue can absorb the tested
  backlog.
- Do not enable debug output or weaken protection as a workaround.
- Restore the approved destination or approved failover route.
- Verify backlog drains and reconcile duplicate records at the destination.
- Preserve timestamps, configuration digest, and operational logs as incident
  evidence.

When the queue reaches capacity, the production configuration backpressures
OTLP senders. Upstream sender behavior then determines whether activity waits,
spools, or is lost; qualify that behavior explicitly.

## Fabric Node or cluster failure

1. Confirm the StatefulSet PVCs still exist; the chart retains them on delete
   and scale-down.
2. Restore cluster access, certificates, export credentials, and network paths.
3. Redeploy the same image digest and approved configuration against retained
   PVCs. Never mount one file-storage database into multiple replicas.
4. Verify readiness, queue recovery, destination delivery, and deduplication.
5. If a PVC is corrupt, preserve it for investigation before using the
   customer-approved storage restore procedure.

## Docker Compose deployments (client VM)

The same objectives apply to the single-node Compose overlay
(`deploy/compose/docker-compose.production.yml`). The durable state is the
`fabric-queue` named volume mounted at `/var/lib/fabric-node/queue`.

### Queue volume sizing

- `sending_queue.queue_size` bounds **items** (queued batches), not bytes.
  Estimate the worst-case batch size from qualified traffic, multiply by
  `queue_size`, then add headroom for file-storage overhead and compaction
  scratch space (the compaction directory lives inside the same volume). When
  the collector train supports `sending_queue.sizer: bytes` for persistent
  queues, migrate `queue_size` to a byte bound.
- Size the volume for the tested destination-outage window: peak ingest rate
  x outage duration, plus margin. When the queue fills,
  `block_on_overflow: true` backpressures OTLP senders; qualify what upstream
  agents do then.
- `file_storage` compacts on start and on rebound in this profile, so disk
  use recovers after a backlog drains. It does not impose a byte cap --
  disk-full is the real bound, so monitor volume utilization.

### Backup and restore of the queue volume

Backup (stop the recorder first so the queue is quiescent):

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml stop fabric-node
docker run --rm -v fabric-node-production_fabric-queue:/queue:ro -v "$PWD":/backup \
  alpine tar czf /backup/fabric-queue-$(date +%Y%m%d%H%M%S).tgz -C /queue .
docker compose -f docker-compose.yml -f docker-compose.production.yml start fabric-node
```

Restore onto a rebuilt or replaced VM:

```bash
docker volume create fabric-node-production_fabric-queue
docker run --rm -v fabric-node-production_fabric-queue:/queue -v "$PWD":/backup \
  alpine tar xzf /backup/<archive>.tgz -C /queue
make up-prod
```

`make up-prod` re-runs the production preflight. A direct
`docker compose ... up` bypasses its token-file, TLS, and bind-address gates.

Never mount one queue volume into two running collectors; file-storage
assumes exclusive access.

### What to alert on

- **Queue depth**: scrape the Prometheus endpoint published on
  `127.0.0.1:8888` (`/metrics`). Alert on `otelcol_exporter_queue_size`
  sustained growth and on it approaching
  `otelcol_exporter_queue_capacity`.
- **Delivery failures**: alert on rising
  `otelcol_exporter_send_failed_spans` /
  `otelcol_exporter_send_failed_log_records` and on
  `otelcol_receiver_refused_*` (rejected or backpressured ingress).
- **Liveness**: poll the health extension at `127.0.0.1:13133` and alert on
  container restarts (`docker compose ps`, `restart: unless-stopped` only
  covers process exits).
- **Host resources**: `fabric-queue` volume disk utilization, since the
  queue bounds items, not bytes.

## Evidence boundaries

Fabric Node cannot prove that an arbitrary destination durably persisted a
record. Preserve destination-specific receipts, immutable storage evidence,
access logs, and retention records in the system responsible for them.
