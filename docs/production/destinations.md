# Destinations

Fabric delivers to a destination you choose; nothing goes to SingleAxis.

On a single host, `fabric init --production --destination PRESET` sets the
destination from the identifiers you already own, given as flags; on a
terminal without a preset, `init` asks for them. It never asks for a
credential: a cloud store uses the Node's own identity (an instance role) or a
credentials file you name by path.

| Preset | Spans go to | Content (model bodies) goes to | Flags |
|---|---|---|---|
| `trial` | a TLS OTLP receiver `fabric up` provisions, writing files under `./fabric-data/spans` | a bundled S3-compatible test store with TLS | none; not durable storage (`FC-172`), for trying the production Node |
| `s3` | your OTLP/HTTP collector | your AWS S3 bucket, encrypted with KMS | `--bucket`, `--region`, `--otlp-endpoint`, `--otlp-headers-file`; optional `--sse-kms-key`, `--otlp-ca-file` |
| `s3-compatible` | your OTLP/HTTP collector | any S3 API store, encrypted with SSE-S3 | `--endpoint` (https), `--bucket`, `--otlp-endpoint`, `--otlp-headers-file`; optional `--region`, `--ca-file` (a private CA), `--credentials-file`, `--otlp-ca-file` |
| `otlp` | your OTLP/HTTP collector | nowhere: model bodies are not kept, so decisions cannot be checked against them (`FC-173`) | `--otlp-endpoint`, `--otlp-headers-file`; optional `--otlp-ca-file` |

The Node exports spans over OTLP only, so the S3 presets also name the
collector spans go to, and the headers file with the Authorization the
Node presents to it (one line `Authorization=Bearer%20TOKEN`, mode 0600):
`fabric up` does not start a Node that would export unauthenticated
(`FC-176`). Fabric cannot read spans back from your collector:
`fabric verify` reads its canary through a small, bounded tap on the Node
that only the canary's own ingress group writes to (never an agent's), and
reads your runs from an export you give it with `--spans PATH`. Model bodies
are read back from the S3 store with the credentials file you named (or the
host's own identity for AWS S3). A file named by a flag must exist and be readable, and
a credentials or headers file must be closed to other users (`FC-174`).
Azure Blob and Google Cloud Storage are reached today through the `otlp`
preset, to a collector of yours that writes there.

| Destination | Use | Set up by hand |
|---|---|---|
| Local directory | A laptop or a trial; `fabric verify` and `fabric show` read it | `fabric up` (the default) |
| OTLP/HTTP over TLS | Your collector, observability backend or SIEM | [production profile](../reference/manual-setup/deployment.md#production-profile); a private CA: [destination with a private CA](../reference/manual-setup/production-setup.md#a-destination-with-a-private-ca) |
| S3 or S3-compatible bucket | The content store: model bodies the reader checks decisions against | [production profile](../reference/manual-setup/deployment.md#production-profile); [minimal IAM](../reference/manual-setup/deployment.md#minimal-iam-s3) |

When the destination refuses data, the Node's queue holds it:
[when the destination refuses data](../reference/manual-setup/production-setup.md#when-the-destination-refuses-data).
Delivery is at least once; see
[duplicates at the destination](../reference/manual-setup/production-setup.md#duplicates-at-the-destination).
