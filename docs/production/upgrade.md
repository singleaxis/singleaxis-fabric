# Upgrade

The SDK, the CLI, the Node image, the sensor image and the chart are released
together under one version; `fabric run` warns (`FC-049`) when an agent's SDK and
the CLI are more than one minor version apart.

- `fabric up` pins every image to the CLI's own release by digest; upgrading
  the CLI and running `fabric up` again updates the Node in place and keeps
  its volumes and your records.
- On Kubernetes, `fabric up --kubernetes` runs `helm upgrade --install` with
  the chart of the CLI's release; it restarts nothing of yours.
- Version-specific notes: [upgrading from earlier releases](../reference/manual-setup/deployment.md#upgrading-from-earlier-releases).
- Verify what you install: [verify a release](../verify-release.md).
