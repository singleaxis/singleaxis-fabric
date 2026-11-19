# Sizing

Two buffers keep records when something downstream is slow or down: the
agent's spool (on the agent's disk) and the Node's durable queue.

- **Spool:** bounded by `FABRIC_WIRE_SPOOL_MAX_BYTES`; when full, the SDK
  records the loss (`queue_full`) and never blocks the agent. On Kubernetes the injector sets
  it to a quarter of the spool volume.
- **Node queue:** one setting, `node.queue_size` in `fabric.yaml` (or
  `fabric init --queue-size 20GiB`): the disk the queue may use. `auto`, the
  default, uses at most half of the free space of the disk it is on, and
  never more than the shipped queue holds. `fabric init` turns it into the
  Node's queue lengths (a telemetry batch counts up to 8 MiB, a content
  record up to 64 MiB) and warns when the setting is more than the disk has
  free (`FC-170`), with a size that fits, or when the disk is so full that
  the queue holds few batches (`FC-171`). Real batches are far smaller than
  this worst case, so these are advice, not failures.
  [Queue size on a small host](../reference/manual-setup/production-setup.md#queue-size-on-a-small-host)
  shows the same worst case for a Node you set up by hand, and
  `preflight-prod` compares it with free disk.
- **Operations:** health, metrics and what to watch:
  [operations](../operations/README.md).
