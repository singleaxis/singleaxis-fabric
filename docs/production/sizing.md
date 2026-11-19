# Sizing

Two buffers keep records when something downstream is slow or down: the
agent's spool (on the agent's disk) and the Node's durable queue.

- **Spool:** bounded by `FABRIC_WIRE_SPOOL_MAX_BYTES`; when full, the SDK
  records the loss (`queue_full`) and never blocks the agent. On Kubernetes the injector sets
  it to a quarter of the spool volume.
- **Node queue:** sized to the disk it is on;
  [queue size on a small host](../reference/manual-setup/production-setup.md#queue-size-on-a-small-host)
  shows the worst case and how to cap it. `preflight-prod` compares it with
  free disk.
- **Operations:** health, metrics and what to watch:
  [operations](../operations/README.md).
