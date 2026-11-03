# Production-profile kind fixtures

Kind values and sink manifests used by the
[`e2e-production-profile.yml`](../../../.github/workflows/e2e-production-profile.yml)
workflow to install the `shadow-production` chart profile on a kind cluster
and read records back from a controlled sink. They are CI fixtures, not a
product feature or a deployment recommendation; use
[`charts/fabric/profiles/shadow-production.yaml`](../../../charts/fabric/profiles/shadow-production.yaml)
and [deployment](../../../docs/deployment.md) for a real install.
