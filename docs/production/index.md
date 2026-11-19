# Go to production

A production deployment records the same fields as the laptop path; what
changes is that the record is **authenticated, protected, durable and
encrypted**: TLS and a token on every hop, a capture policy you write, an
encrypted spool, a durable queue, and sensors bound to their own ingress.
Production needs no code change.

In this release the production path is the manual route below: each step
links to the exact commands, and `make -C deploy/compose preflight-prod`
checks a single host before you start it, each failure with its fix.
The one-command form of these steps (`fabric init --production`, `fabric
verify --production`) answers `FC-011` (not built in this release).

| Step | Single Linux host | Kubernetes | Checked by |
|---|---|---|---|
| 1. Choose where records go | [destinations](destinations.md) | [destinations](destinations.md) | `preflight-prod`: egress URL, Authorization header, CA |
| 2. Keys, tokens and certificates | [secrets](secrets-and-rotation.md) | generated in the cluster | `preflight-prod`: file modes, token strength, certificate names |
| 3. The capture policy | [privacy and security](../reference/privacy-and-security.md) | the chart's `injector.capturePolicy` | the SDK refuses production without one (`FW-008`) |
| 4. Start the Node, the destination and the sensor | [Linux host](linux-host.md) | [Kubernetes](kubernetes.md) | `preflight-prod`; `fabric verify --kubernetes` |
| 5. Size the queue and spool | [sizing](sizing.md) | [sizing](sizing.md) | `preflight-prod`: queue against free disk |
| 6. Read a run back | [read a run](../reference/manual-setup/production-setup.md#6-read-a-run) | `fabric verify --kubernetes` | the reader's verdict |
| 7. Upgrade | [upgrade](upgrade.md) | [upgrade](upgrade.md) | |

On Kubernetes the whole path is checked today:
[Get started with Kubernetes](../get-started/kubernetes.md) installs the
production profile with the host sensor and verifies a run.
