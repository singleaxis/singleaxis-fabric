# redteam-runner subchart

Renders a Kubernetes `CronJob` that runs the
[`fabric-redteam-runner`](../../../../components/redteam-runner) CLI on
a schedule against a tenant-specified agent endpoint. Output is a set
of OTel spans (`event_class = redteam_run | redteam_probe`) the Fabric
collector's allowlist recognizes and Langfuse dashboards filter on.

Disabled by default. Red-team CronJobs attack a live agent; the
operator has to opt in and point them at the correct target.

## Minimal install

```yaml
# values.yaml overrides
redteamRunner:
  enabled: true
  runConfig:
    inline: |
      tenant_id: acme-prod
      agent_id: support-bot
      profile: eu-ai-act-high-risk
      target:
        url: https://support-bot.acme.example.com/respond
        headers:
          Authorization: Bearer ${env:AGENT_BEARER}
      suites:
        - name: garak
          probes: [promptinject.HijackHateHumans]
        - name: pyrit
          scenarios: [jailbreak_fuzzer]
  extraEnv:
    - name: AGENT_BEARER
      valueFrom:
        secretKeyRef:
          name: fabric-redteam-creds
          key: bearer
```

## Image variants

| tag suffix | installed suites | use when |
|---|---|---|
| `""` (bare) | none — drivers short-circuit to `ERROR` | rehearsing the pipeline, CI |
| `-suites` (default) | Garak + PyRIT | production |

## Run-config reference

The chart mounts the config at `/etc/fabric/redteam/run.yaml`. Either:

- `runConfig.inline` — YAML string rendered into a chart-owned
  ConfigMap (the happy path), or
- `runConfig.existingConfigMap` — name of an operator-owned ConfigMap
  whose `run.yaml` key holds the config (wins over `inline`).

Placeholders of the form `${env:NAME}` in the config resolve at CLI
startup from the pod's environment — wire secrets through
`extraEnv[].valueFrom.secretKeyRef`.

## Schedule defaults

Weekly (`0 2 * * 0`, Sunday 02:00 UTC) with `concurrencyPolicy:
Forbid` so back-to-back runs never overlap. Regulatory profiles
override this via `charts/fabric/profiles/*.yaml`.

## What it doesn't do

- Pre-deploy gating (blocking a deploy until a red-team run passed)
  lives in the **update-agent** component, not here. This chart only
  runs the tests.
- No alerting — alerts are driven by the OTel spans + your
  observability stack (Langfuse saved view + paging).

## Security

- non-root (`runAsUser: 1000`), read-only root filesystem,
  `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`
- `/tmp` and `/home/fabric` are `emptyDir` with size caps so Garak
  model caches stay on the Pod (reclaimed on completion)
- ServiceAccount has no extra RBAC — the runner only needs egress to
  the target agent and the in-cluster OTel collector
