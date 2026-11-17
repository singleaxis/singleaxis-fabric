# Get started: Kubernetes

Record what the Python agents in one namespace of your cluster do, with
evidence from each node's kernel, and check the record. You need `kubectl`
and `helm` pointed at the cluster, Python 3.11 or later on your workstation,
and your agent's image with the Fabric SDK in it (one line in its
Dockerfile: `pip install singleaxis-fabric`). Fabric makes every key, token
and certificate inside the cluster: you create no Secret and copy nothing
onto a node.

## Your destination and content store

Fabric delivers records to a destination you run (an OTLP/HTTP endpoint
over TLS) and keeps your agents' model bodies in an S3 or S3-compatible
bucket you own, where `fabric verify` checks the agent's decisions against
them. Name both in a Helm values file, `destination.yaml`, with the Secrets
that hold their credentials and CAs, which you already have:

```yaml
otel-collector:
  exporter:
    endpoint: https://otlp.example.com:4318
    tls: {caSecret: {name: my-destination-ca, key: ca.crt}}
    auth: {secret: {name: my-destination-auth, key: authorization}}
    sendingQueue:
      persistence: {size: 1Gi, storageClass: standard,
                    encryptionAttestationRef: storage-review-2026-11}
  content:
    enabled: true
    backend: s3
    allowedTenants: [acme]
    s3: {bucket: acme-fabric-content, region: us-east-1,
         endpoint: https://s3.storage.internal:9000, usePathStyle: true,
         credentialsSecret: {name: my-store-writer},
         caSecret: {name: my-store-ca, key: ca.crt}}  # a private CA
  networkPolicy:
    exporterEgress:
      to: [{ipBlock: {cidr: 203.0.113.10/32}}]
      ports: [{protocol: TCP, port: 4318}]
    contentEgress:
      to: [{ipBlock: {cidr: 203.0.113.20/32}}]
      ports: [{protocol: TCP, port: 9000}]
```

On AWS S3 leave out `endpoint`, `usePathStyle` and `caSecret`.

## 1. Install the CLI

<!-- fabric-docs-test: path=kubernetes step=1 kind=install -->
```bash
pip install "singleaxis-fabric[cli,s3]"
```

## 2. Install Fabric in the cluster

<!-- fabric-docs-test: path=kubernetes step=2 -->
```bash
fabric up --kubernetes --preset production-host-sensor --tenant acme --agent-namespace agents --injector --values destination.yaml
# expect: FC-124
```

This runs one `helm upgrade --install` of the Fabric chart of this release
into `fabric-system`: the Node, the host sensor on every Linux node, and
the pod injector for the namespace `agents`. A hook Job generates the
Secrets; none is part of the Helm release. It restarts nothing of yours.

## 3. Turn capture on for your agents

<!-- fabric-docs-test: path=kubernetes step=3 -->
```bash
kubectl label namespace agents fabric.singleaxis.ai/injection=enabled
kubectl -n agents patch deployment support-agent -p '{"spec":{"template":{"metadata":{"annotations":{"fabric.singleaxis.ai/inject":"python"}}}}}'
```

Use your own deployment's name, or add the annotation
`fabric.singleaxis.ai/inject: "python"` to its pod template where you keep
it. Your agent's pods pick up capture when your rollout recreates them:
the injector adds settings and read-only mounts and never changes the
image, command or anything you set. If the injector is down, your pods
start as they would without Fabric, within 2 seconds.

## 4. Check the record

<!-- fabric-docs-test: path=kubernetes step=4 -->
```bash
fabric verify --kubernetes --spans destination-export
# expect: FC-069
# expect: corroboration: complete
```

`verify` checks the release, the Secrets, the injected pods and what the
host sensor sees on each node, then reads your agent's last run from your
destination's export (`--spans`) and its model bodies from your bucket, with
your own AWS configuration (read access is enough). It exits 0 when the
record is complete, your agent's model decisions were verified and the host
sensor corroborates the run. Each problem is printed with its fix.

## Next

- Something wrong: `fabric doctor --kubernetes`, and the
  [diagnostics catalogue](../diagnostics.md).
- What Fabric can see in a cluster before you install:
  `fabric plan --kubernetes`.
- A trial without a destination: `fabric up --kubernetes --agent-namespace agents --injector`.
- Remove it with `fabric down --kubernetes`; the generated Secrets stay
  unless you add `--purge`.
