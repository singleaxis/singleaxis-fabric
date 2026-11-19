# Production on Kubernetes

[Get started with Kubernetes](../get-started/kubernetes.md) is the production
path, checked in CI on a cluster: one install with the
`production-host-sensor` preset, one namespace label, one pod annotation,
and `fabric verify --kubernetes`. Every Secret is generated in the cluster
by a hook Job; none is part of the Helm release.

What you bring is yours already: the destination and its credentials, the
content bucket, the capture policy, and NetworkPolicy egress for both.

- Presets, agent namespaces, the injector and certificate renewal:
  [Kubernetes without hand work](../reference/manual-setup/deployment.md#kubernetes-without-hand-work).
- Clusters that forbid hook Jobs: `fabric init --kubernetes --render DIR`
  writes the Secrets for your GitOps tool ([Kubernetes shape](../shapes/kubernetes.md)).
- Chart values reference: [the chart](../../charts/fabric/README.md).
