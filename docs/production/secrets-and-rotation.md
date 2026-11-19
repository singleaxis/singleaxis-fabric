# Secrets and rotation

On the laptop path and on Kubernetes, Fabric generates every secret: the
pseudonym id key, the spool key, the CA and certificates, and in a cluster
the ingest tokens, from the operating system's random source. They are
stored owner-only (files `0600` under `~/.local/state/fabric/`, or
Kubernetes Secrets), never written to `fabric.yaml`, never printed and
never put on a command line.

| Secret | Laptop (`fabric up`) | Kubernetes | Single production host |
|---|---|---|---|
| Id key, spool key | generated | generated | [by hand](../reference/manual-setup/production-setup.md#2-keys-tokens-and-certificates) |
| CA, Node certificate | generated; reissued by `fabric up` within 14 days of expiry | generated; [renewal](../reference/manual-setup/deployment.md#certificate-renewal) | by hand |
| Ingest tokens | not used (loopback) | generated per source | by hand |

The id key keys every pseudonym in your records: rotating it changes them
from the next run, and the old key is needed to read older records. Fabric
never rotates it on its own.
