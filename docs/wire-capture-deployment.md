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
