# Deploying LLM wire capture (moved)

> **Status:** a redirect page. Its redaction-service section describes built
> code, released in v0.8.0:
> [`fabric/redaction.py`](../sdk/python/src/fabric/redaction.py) and the
> reference service in
> [`examples/redaction-service/`](../examples/redaction-service/).

This page moved. Configuration files and scripts in `deploy/compose` still
point here.

- Agent and Node configuration: [deployment](deployment.md); spool disk
  requirements (`fsync` latency, file locks):
  [deployment](deployment.md#what-the-agent-needs) ("Spool disk").
- Content canary and verifying a run (formerly section 5):
  [operations](operations/README.md#verify-a-deployment) and
  [reconstruct](reconstruct.md).
- Encryption and source authentication:
  [privacy and security](privacy-and-security.md).

## Redaction service

The redaction-service setup (`FABRIC_REDACTION_ENDPOINT`,
`FABRIC_REDACTION_TOKEN_FILE`, transformations, bounds and failure
behaviour) is in
[privacy and security](privacy-and-security.md#redaction-service). Error
messages from the SDKs point to this anchor.

## Draining a spool with no agent running

An agent delivers its spool's backlog only while it runs. At exit it waits
only for its exit budget (`FABRIC_WIRE_SHUTDOWN_TIMEOUT_S`, 2 s by default),
so after a Node or destination outage, thousands of records can be left on
the spool volume. A later agent process on the same volume delivers them. If
none comes, as with a one-shot container or a scaled-down job, run the
drainer:

```text
python -m fabric.wire drain [--spool DIR] [--until-empty] [--timeout SECONDS]
```

- It reads the agent's own environment (`FABRIC_WIRE_*`,
  `OTEL_EXPORTER_OTLP_*`, the spool key) and delivers as the agent would:
  bodies to the Node, then spans. A record is deleted only after every part
  was accepted. As the spool's lock holder it also exports dead processes'
  loss-ledger slots and declares their orphaned epochs. It installs no
  capture and writes no epoch of its own, even when the environment sets
  `FABRIC_WIRE_AUTOLOAD=1`.
- While a live process holds the spool lock, the drainer waits, and it takes
  over when the lock is released. Two drainers never deliver the same
  record.
- `--until-empty` returns when nothing deliverable is left (exit 0) or at
  `--timeout` with records still on disk (exit 1; they stay for the next
  drainer or agent). Without it the drainer runs until SIGTERM or SIGINT,
  then makes a final drain attempt of up to 10 s. Exit 2 means a usage or
  configuration error. stdout gets one JSON summary line: `drained`,
  `delivered`, `remaining`, `undecryptable` (records sealed under another
  spool key, left on disk), `quarantined` and `seconds`.

Where to run it:

- **One-shot container.** Make it the container's last step, in the same
  container or a second one on the same volume:
  `python agent.py; python -m fabric.wire drain --until-empty --timeout 300`.
  The agent's own exit code is the job's result; the drainer's exit 1 only
  means records wait on the volume.
- **Kubernetes sidecar.** Run `python -m fabric.wire drain` (no
  `--until-empty`) as a native sidecar (an init container with
  `restartPolicy: Always`) that mounts the agent's spool volume and env.
  Kubernetes stops it after the agent container exits, so its final drain
  runs with the spool lock free. Set `terminationGracePeriodSeconds` at least
  15 s above the agent's own shutdown time. The spool must be on a volume
  that outlives the pod (a PersistentVolumeClaim) when a drain can stop
  early, for example when the Node is down. An `emptyDir` spool is deleted
  with the pod.
- **preStop hook.** `python -m fabric.wire drain --until-empty --timeout 20`
  in the agent container's `preStop` delivers the backlog before SIGTERM.
  The agent is still running then and holds the lock, so the hook mostly
  waits for the agent's own sender. Prefer the sidecar.
