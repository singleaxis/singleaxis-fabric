# Destinations

Fabric delivers to a destination you choose; nothing goes to SingleAxis.

| Destination | Use | Set up |
|---|---|---|
| Local directory | A laptop or a trial; `fabric verify` and `fabric show` read it | `fabric up` (the default) |
| OTLP/HTTP over TLS | Your collector, observability backend or SIEM | [production profile](../reference/manual-setup/deployment.md#production-profile); a private CA: [destination with a private CA](../reference/manual-setup/production-setup.md#a-destination-with-a-private-ca) |
| S3 or S3-compatible bucket | The content store: model bodies the reader checks decisions against | [production profile](../reference/manual-setup/deployment.md#production-profile); [minimal IAM](../reference/manual-setup/deployment.md#minimal-iam-s3) |

When the destination refuses data, the Node's queue holds it:
[when the destination refuses data](../reference/manual-setup/production-setup.md#when-the-destination-refuses-data).
Delivery is at least once; see
[duplicates at the destination](../reference/manual-setup/production-setup.md#duplicates-at-the-destination).
