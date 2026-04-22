# update-agent subchart

Renders a `ValidatingAdmissionWebhook` that gates every
`create`/`update` into `fabric-system` (by default) behind a
three-step check:

1. **Signature** — Ed25519 over JCS-canonical JSON, keys pinned via
   `config.trustedKeys`.
2. **Version** — manifest's
   `fabric.singleaxis.dev/version-constraint` must admit the
   installed Fabric version.
3. **Schema** — JSON Schema for `(apiVersion, kind)` (ConfigMap +
   Secret built in).

Also renders an optional ArgoCD `AppProject` + `Application`
targeting the SingleAxis manifest channel.

Component source:
[`components/update-agent`](../../../../components/update-agent).

## Minimal install (self-signed TLS)

```yaml
updateAgent:
  enabled: true
  config:
    trustedKeys:
      - id: singleaxis-release
        publicKey: "<base64 raw 32-byte Ed25519 pubkey>"
```

## Production install (cert-manager + tenant mirror)

```yaml
updateAgent:
  enabled: true
  config:
    fabricVersion: "0.1.0"
    failClosed: true
    trustedKeys:
      - id: singleaxis-release
        publicKey: "<base64 raw 32-byte Ed25519 pubkey>"
    extraTrustedKeys:
      - id: tenant-mirror
        publicKey: "<base64 raw 32-byte Ed25519 pubkey>"
  tls:
    mode: certManager
    certManager:
      issuerRef:
        name: fabric-ca-issuer
        kind: ClusterIssuer
        group: cert-manager.io
  webhook:
    watchedNamespaces:
      - fabric-system
      - fabric-policy
```

## TLS modes

| `tls.mode`    | Cert source                                  | caBundle wiring |
|---------------|----------------------------------------------|-----------------|
| `selfSigned`  | chart-rendered `Secret` (365d, `genCA`)      | copied into `ValidatingWebhookConfiguration` inline |
| `certManager` | `cert-manager.io/v1 Certificate`             | `cert-manager.io/inject-ca-from` annotation |

Use `selfSigned` for dev + airgapped tenants. Use `certManager` when
the cluster already has an issuer and you want rotation handled
externally. Swapping modes is safe on upgrade — both modes write to
the same Secret name.

## Fail-closed vs fail-open

`config.failClosed: true` (default) denies any manifest in a
watched namespace that lacks both Fabric annotations. Drop to
`false` only when rolling out to a cluster with pre-existing
unsigned resources; flip back once the channel is authoritative.

## ArgoCD wiring

Off by default. Turn on with `argocd.enabled: true` to render:

- `AppProject` scoping source repos to the SingleAxis manifest
  channel and destinations to the fabric namespace.
- `Application` pointing at the manifest repo (`path: tenants/<id>`
  typical) with automated sync + self-heal.

## What it doesn't do

- No namespace admission — the webhook only gates resources *inside*
  the watched namespaces. Create the namespaces themselves via
  GitOps or the umbrella chart.
- No image-signing verification — that's a separate controller
  (e.g. Kyverno + cosign). This agent gates config/secret/manifest
  payloads, not image digests.
- No RBAC grants — the webhook runs as its own SA with zero cluster
  privileges; it doesn't read any in-cluster state.

## Security

- 2 replicas, `maxUnavailable: 0` (admission path must stay
  reachable to avoid `failurePolicy: Fail` blocking legitimate
  applies on rollout).
- non-root (`runAsUser: 1000`), read-only root filesystem,
  `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`.
- Serving cert + key mounted read-only from a Secret; `/tmp` is an
  `emptyDir` to preserve the read-only root.
- `AutomountServiceAccountToken: true` so the pod can answer the
  API server but the SA has no granted permissions.
