# Secrets and rotation

Fabric generates every secret from the operating system's random source:
on a laptop and a single production host with `fabric init` (add
`--production` for the production ones), on Kubernetes in the cluster. They
are stored owner-only (files `0600` under `~/.local/state/fabric/`, or
Kubernetes Secrets), never written to `fabric.yaml`, never printed and
never put on a command line; `fabric init --json` lists their paths,
fingerprints and expiry dates only.

| Secret | Laptop (`fabric init`) | Kubernetes | Single production host (`fabric init --production`) |
|---|---|---|---|
| Id key | generated | generated | generated |
| Spool key, Node content key | not used | generated | generated |
| CA, Node certificate | generated; reissued by `fabric up` within 14 days of expiry | generated; [renewal](../reference/manual-setup/deployment.md#certificate-renewal) | generated |
| Ingest tokens | not used (loopback) | generated per source | generated per source: the agent, the host sensor and the canary `fabric verify` sends, each its own |
| Client certificates | not used | generated per agent namespace | generated per source |
| Trial destination material | not used | not used | generated with `--destination trial`: the test store's certificate, identities and key, the receiver's certificate |

`fabric init --production` also derives the source id the Node binds for
each source from the id key, as the agent and the sensor derive what they
send, and prints them; they are pseudonyms, not secrets.

Rotation is explicit, with `fabric init --rotate NAME`:

| Name | What happens |
|---|---|
| `tokens` | A new token for every source; the old ones are kept read-only under `retired/`. The Node takes one token per source, so restart it, then agents and the sensor. |
| `client-certs` | New client certificates from the CA; restart agents and the sensor. |
| `node-cert` | A new Node certificate from the same CA; nothing else changes. |
| `ca` | A new CA with new Node and client certificates; restart agents so they load it. |
| `id-key` | A new id key; the old one is kept read-only for the reader. Never part of `all`. |
| `all` | Everything above but the id key. |

The id key keys every pseudonym in your records: rotating it changes them
from the next run, and the old key is needed to read older records. Fabric
never rotates it on its own.
