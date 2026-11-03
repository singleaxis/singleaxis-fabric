# Recorder dependency reports

> **Status:** describes the built license-report tooling:
> [`scripts/license_scan.sh`](../../scripts/license_scan.sh) and
> [`scripts/license_check.py`](../../scripts/license_check.py).

The recorder license workflow generates Markdown, CSV, and JSON inventories
from the exact released Python SDK, TypeScript SDK, Fabric Node distribution,
and `fabricctl` command. Download `recorder-third-party-license-report` from the
tagged commit's `recorder-license.yml` run.

Generated reports are not committed here because a checked-in inventory can
silently become stale or describe historical components outside recorder v1.
Run `scripts/license_scan.sh` to create a local report under
`build/recorder-license-report/`.
