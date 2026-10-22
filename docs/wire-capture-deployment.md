# Deploying LLM wire capture (moved)

This page moved. Configuration files and scripts in `deploy/compose` still
point here.

- Agent and Node configuration: [deployment](deployment.md).
- Content canary and verifying a run (formerly section 5):
  [operations](operations/README.md#verify-a-deployment) and
  [reconstruct](reconstruct.md).
- Encryption and source authentication:
  [privacy and security](privacy-and-security.md).
- The previous version: [archive](archive/wire-capture-deployment.md).

## Redaction service

The redaction-service setup (`FABRIC_REDACTION_ENDPOINT`,
`FABRIC_REDACTION_TOKEN_FILE`, transformations, bounds and failure
behaviour) is in
[privacy and security](privacy-and-security.md#redaction-service). Error
messages from the SDKs point to this anchor.
