# Langfuse subchart

Fabric's default **Layer 3 (observability)** sink. Ships a single-pod
Langfuse v2 wrapper so a fresh `helm install` gives tenants a working
trace UI without pulling in a second Helm chart.

## When to use this vs. upstream Langfuse

| Scenario | Use this subchart | Use upstream `langfuse/langfuse-k8s` |
| --- | --- | --- |
| Dev / smoke tests | ✅ | |
| Single-tenant pilot | ✅ | |
| Multi-replica HA | | ✅ |
| Clickhouse + Redis analytics backend | | ✅ |

The single-Deployment shape is intentional. Tenants that outgrow it
disable this subchart (`langfuse.enabled: false`) and install the
upstream chart alongside.

## Required configuration

One of the following must be set — the chart refuses to render
otherwise:

```yaml
langfuse:
  database:
    url: "postgresql://user:pass@host:5432/langfuse"
    # OR
    dsnSecret:
      name: my-langfuse-db
      key: url
```

Postgres must be reachable from the cluster. Pointing Langfuse at the
same Postgres instance used by `context-graph` is supported; Langfuse
creates its own `public.*` tables via Prisma migration.

## Auth secrets

On first install the chart generates `NEXTAUTH_SECRET` and `SALT` as
random 48/32-byte strings and stores them in
`<release>-langfuse-auth`. Upgrades re-use the existing Secret so
browser sessions survive `helm upgrade`.

For multi-replica deployments pre-create the Secret and point
`auth.existingSecret` at it — otherwise different pods would render
different auth keys.
