# Deployment

A Fabric deployment has three parts you run and one you choose:

```text
agent (Python SDK, wire capture)  ──spans──►  Fabric Node  ──spans──►  your OTLP destination
   durable spool                  ──content─►  (Collector)  ──content─►  your file directory or S3 bucket
```

- **Agent.** The Python SDK in your application. In **node mode** it spools
  every record to disk and sends it to the Node. It holds no store
  credentials.
- **Fabric Node.** The Fabric OpenTelemetry Collector distribution
  (`ghcr.io/singleaxis/fabric-otelcol`), started through `fabric-gate`,
  which refuses unsafe configurations. Deploy it with Docker Compose
  (`deploy/compose`) or Helm (`charts/fabric`).
- **Content store.** A directory on the Node, or an S3 / S3-compatible
  bucket. Only the Node writes it.
- **OTLP destination.** Any OTLP/HTTP endpoint you choose. A SingleAxis
  account is not required.

Two profiles exist, and they are not interchangeable:

| | `local` | `production` |
|---|---|---|
| Purpose | Development, evaluation, offline runs | Anything crossing a trust boundary |
| Agent | `file://` store (direct) or node mode | node mode |
| Content needs | nothing (implicit `fabric.local-default` policy) | capture policy + id key + spool key |
| Node | plaintext loopback, no authentication (Compose `make up`, Helm `shadow-dev`) | single-token bearer ingress bound to one tenant and source, TLS, encrypted queue (Compose `make up-prod`, Helm `shadow-production`) |
| Verdicts | never production-qualified | can be authenticated on trusted readback |

## Local profile

### Compose

```bash
cd deploy/compose
make up          # builds the Node image, starts the Node and a test sink
make status
```

Ports, all on `127.0.0.1`: `4317` OTLP/gRPC, `4318` OTLP/HTTP, `4319`
content, `13133` health, `8080` test sink. The sink stores every span
request and acknowledges only after fsync; `make export-spans OUT=<dir>`
copies them for `fabric.reconstruct`. The Node writes content to the
`fabric-content` volume (unencrypted), with tenant `evaluation` by default.
This setup is plaintext and unauthenticated: never expose it beyond the
host.

Other targets: `make smoke` (send one fixture trace), `make qualify`
(destination outage and Node restart recovery), `make up-s3-eval` (a local
SeaweedFS S3 store with SSE, Node-only writer keys and a read-only reader),
`make down` / `make reset`.

Agent settings for the local Node with a direct `file://` store (the
[quickstart](quickstart.md) runs this). With an OTLP endpoint set, file
mode spools by default at `<store>/.fabric-wire-spool/<tenant>`: a captured
call survives the process (a crash, SIGKILL or a terminated worker) and the
next process capturing to the same store delivers it.
`FABRIC_WIRE_SPOOL_DIR=off` restores direct export.

```bash
export PYTHONPATH="$(python -m fabric.wire --print-autoload-path)${PYTHONPATH:+:$PYTHONPATH}"
export FABRIC_WIRE_AUTOLOAD=1
export FABRIC_TENANT_ID=demo
export FABRIC_WIRE_STORE=file:///absolute/path/to/store
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

### Helm

```bash
helm upgrade --install fabric charts/fabric \
  --namespace fabric-system --create-namespace \
  --values charts/fabric/profiles/shadow-dev.yaml
```

`shadow-dev` runs one replica without TLS, authentication or NetworkPolicy,
and uses the debug exporter when no endpoint is set. It is not a production
posture.

## Production profile

### What the agent needs

Node mode is the production profile. Content is recorded only when **all**
of these are present; otherwise content capture is disabled, metadata
continues, and every exchange span says why (`fabric.wire.store_reason`).
The application is never blocked.

| Variable | Value |
|---|---|
| `FABRIC_WIRE_AUTOLOAD=1` and `PYTHONPATH` | the autoload directory (`python -m fabric.wire --print-autoload-path`), prepended; or call `fabric.wire.install()` |
| `FABRIC_WIRE_CONTENT_ENDPOINT` | `https://<node>:4319/v1/logs`. Setting it selects node mode. Verified HTTPS, or plain HTTP to a loopback host only. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` (or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) | `https://<node>:4318` (`/v1/traces` is appended to the general variable) |
| `OTEL_EXPORTER_OTLP_HEADERS` | `Authorization=Bearer%20<ingress token>` (covers spans and content) |
| `OTEL_EXPORTER_OTLP_CERTIFICATE` | CA bundle of the Node's server certificate |
| `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_KEY` | agent client certificate (Helm `shadow-production` requires mTLS **and** the token) |
| `FABRIC_TENANT_ID` | the Node's single allowed tenant; must equal the policy's `tenant_id` |
| `FABRIC_SOURCE_ID` | this source's id; the Node is bound to its `s-` pseudonym (below) |
| `FABRIC_WIRE_SPOOL_DIR` | absolute directory for the durable spool (created `0700`, must be owned by the agent's uid) |
| `FABRIC_WIRE_SPOOL_KEY` or `FABRIC_WIRE_SPOOL_KEY_FILE` | 32-byte AES-256-GCM key (base64, or raw/base64 in the file) |
| `FABRIC_CAPTURE_POLICY` | path to a deployment-policy/v1 JSON file (below) |
| `FABRIC_WIRE_ID_KEY` | secret of at least 16 bytes (used as given, not base64) for pseudonyms |
| `FABRIC_TOKENIZATION_KEY` | only for `tokenize`: base64 of at least 32 bytes, distinct from the id key |
| `FABRIC_REDACTION_ENDPOINT`, `FABRIC_REDACTION_TOKEN_FILE` | only for `redact`, `masked_only` and `original_plus_masked`: your [redaction service](privacy-and-security.md#redaction-service) (Unix socket or loopback port) and its optional `0600` token file |
| `OTEL_SERVICE_NAME` | optional; emitted as an `svc-` pseudonym |

Other settings: `FABRIC_WIRE_ENDPOINTS` (extra model hosts, a JSON array of
matchers: `endpoint_id`, `dialect` `openai`/`anthropic`, `hosts` or
`host_suffixes`, optional `ports`, `path_prefix`, `schemes`,
`provider_name`), `FABRIC_WIRE_MODEL_ALLOWLIST`, `FABRIC_WIRE_MAX_BODY_BYTES`
(default 32 MiB, at most 63 MiB in node mode), `FABRIC_WIRE_QUEUE_MAX_ITEMS`
(default 16384; the capture queue is bounded by 256 MiB of retained bodies,
the entry cap only bounds per-entry overhead), `FABRIC_WIRE_SPOOL_MAX_BYTES`
(default 1 GiB), `FABRIC_WIRE_AIOHTTP=0` (stop capturing `aiohttp` calls;
on by default),
`FABRIC_WIRE_PROXY` (an explicit CONNECT proxy for Fabric's own delivery),
`FABRIC_WIRE_LABELS=clear`. `FABRIC_WIRE_STORE_SSE` and
`FABRIC_WIRE_STORE_KMS_KEY_ID` are refused: encryption is configured on the
Node. Source: `sdk/python/src/fabric/wire/_config.py`.

**Source id.** The Node is bound to one source id **as it travels**. The
agent always emits its `FABRIC_SOURCE_ID` as a keyed pseudonym, `s-` + the
first 32 hex of HMAC-SHA256(`FABRIC_WIRE_ID_KEY`, `FABRIC_SOURCE_ID`), even
when the value already looks like `s-` + 32 hex. Choose an opaque agent
value (letters, digits, `.`, `_`, `:`, `-`; at most 128 characters), then
compute the Node's value with the same key:

```bash
export FABRIC_SOURCE_ID=support-agent-prod
python3 -c 'import hashlib, hmac, os
print("s-" + hmac.new(os.environ["FABRIC_WIRE_ID_KEY"].encode(),
      os.environ["FABRIC_SOURCE_ID"].encode(), hashlib.sha256).hexdigest()[:32])'
```

It is also the `fabric.source_id` on the agent's capture spans. Only with
`FABRIC_WIRE_LABELS=clear` is the agent value sent, and bound, unchanged.

**Capture policy.** A deployment-policy/v1 document
(`contracts/deployment-policy/v1`). For wire capture name the
`model.exchange.*` roles; roles you do not name are `omit`:

```json
{
  "schema_version": "fabric.deployment-policy/v1",
  "policy_id": "support-agent-capture",
  "policy_version": 1,
  "tenant_id": "acme-prod",
  "workload_id": "support-agent",
  "privacy": {
    "model.exchange.request": "retain_original",
    "model.exchange.response": "retain_original",
    "model.exchange.part": "retain_original"
  },
  "storage": {"backend": "local", "region": "local", "key_id": "support-agent-key"},
  "retention": {"days": 30},
  "required_integrations": [],
  "deployment": {
    "profile": "production",
    "image_digest": "sha256:<64 hex of your agent image>",
    "tls_required": true,
    "encrypted_store_required": true
  }
}
```

All ten top-level keys are required; `storage.backend` must be `local`.
Modes are listed in
[privacy and security](privacy-and-security.md#protection-modes-the-protect-stage).
`redact`, `masked_only` and `original_plus_masked` need a
[redaction service](privacy-and-security.md#redaction-service) you run
beside the agent (`FABRIC_REDACTION_ENDPOINT`) and a transformation named in
code at `fabric.wire.install()`; zero-code autoload cannot name one and
withholds those roles.

**Running the redaction service.** Run it on the same host or in the same
Pod, reachable only over a Unix socket on a shared volume or a loopback
port. [`examples/redaction-service/`](../examples/redaction-service/README.md)
has a Dockerfile and Compose and Kubernetes sidecar snippets for its
reference service; replace its sample rules with your own detection.

### Compose production overlay

For one VM. `make up-prod` runs `preflight-prod.sh` first and refuses to
start on any failure; a direct `docker compose up` bypasses those checks.

Required in `deploy/compose/.env` (see `.env.example`):

| Variable | Meaning |
|---|---|
| `FABRIC_EXPORT_ENDPOINT` | your OTLP/HTTP destination, `https://` only |
| `FABRIC_EXPORT_AUTH_HEADER` | the `Authorization` value for the destination |
| `FABRIC_INGRESS_TOKEN_FILE` | file holding the agents' bearer token: 32–4096 printable characters, no trailing newline, owned by you, group 65532, mode `0440` |
| `FABRIC_TENANT_ID` | the agents' tenant |
| `FABRIC_SOURCE_ID` | the agents' source id as it travels (`s-<32 hex>`) |

Content (opt-in; without it the production Node is telemetry only):

| Variable | Meaning |
|---|---|
| `FABRIC_CONTENT_BACKEND` | `s3` or `file` |
| `FABRIC_CONTENT_KEY_FILE` | Node content key: 32 random bytes or their base64 (`openssl rand -base64 32`), group 65532, `0440`. Seals the content queue and the file store. |
| `FABRIC_CONTENT_S3_BUCKET`, `FABRIC_CONTENT_S3_REGION` | required for `s3` |
| `FABRIC_CONTENT_S3_PREFIX`, `_ENDPOINT`, `_PATH_STYLE`, `_SSE`, `_KMS_KEY_ID` | optional; SSE defaults to `aws:kms`; an endpoint must be `https://` with no path |
| `FABRIC_CONTENT_REQUIRE_SSE=false` | required to accept the `file` backend (no server-side encryption; the store is sealed with the content key) |

```bash
cd deploy/compose
make preflight-prod   # checks only
make up-prod
make verify-prod      # gate, health, unauthenticated refused, bound source accepted, other source refused
```

Ports bind to `127.0.0.1` unless you set `FABRIC_BIND_ADDR`; preflight then
requires TLS on every published receiver (uncomment the `tls:` stanzas and
set `FABRIC_INGRESS_TLS_DIR`). Health (`13133`) and metrics (`8888`) stay on
loopback. The Node writes S3 with the instance role (IMDSv2, hop limit 2)
or a credentials-file secret. Agents on the same host use
`http://127.0.0.1:4318` and `:4319` with the bearer header.

### Helm `shadow-production`

The profile pins 31 settings (TLS, client certificates, durable queue,
infinite retry, no debug exporter, NetworkPolicy, restricted security
context, `fabric.profile: production`, ...) and refuses to render without
the values below. Validate with `helm template`: `helm lint` reports the
refusals as informational and still exits 0.

Operator-created Secrets in the Node namespace:

| Secret | Keys | Purpose |
|---|---|---|
| `fabric-node-receiver-tls` | `tls.crt`, `tls.key` | Node server certificate |
| `fabric-node-client-ca` | `ca.crt` | CA that signs agent client certificates |
| `fabric-node-export-auth` | `authorization` | `Authorization` value for your destination |
| your token Secret | `token` | the agents' bearer token (`receiver.workloadAuthentication.tokenSecret.name`) |
| `fabric-node-content-key` | `key` | Node content key (with content) |

Values (a file passed after the profile):

```yaml
tenant:
  id: acme-prod
otel-collector:
  image:
    digest: sha256:<approved Node image digest>
  receiver:
    workloadAuthentication:
      tenantId: acme-prod                       # must equal tenant.id
      workloadId: support-agent
      sourceId: s-0123456789abcdef0123456789abcdef
      identityAttestationRef: <your credential review record>
      tokenSecret: {name: fabric-node-ingress-token, key: token}
  exporter:
    endpoint: https://otlp.example.internal:4318
    sendingQueue:
      persistence:
        storageClass: <encrypted StorageClass>  # or existingClaim
        encryptionAttestationRef: <your storage/KMS review record>
  content:                                      # optional
    enabled: true
    allowedTenants: [acme-prod]
    backend: s3                                 # file is refused in this profile
    s3: {bucket: acme-fabric-content, region: eu-west-1, sse: aws:kms, kmsKeyId: <key arn>}
    encryption:
      keySecret: {name: fabric-node-content-key}
  networkPolicy:
    ingressFrom:
      - namespaceSelector: {matchLabels: {fabric.singleaxis.ai/agent: "true"}}
    exporterEgress:
      to: [{ipBlock: {cidr: 10.20.0.0/16}}]
      ports: [{port: 4318, protocol: TCP}]
    contentEgress:                              # the store (and STS for IRSA)
      to: [{ipBlock: {cidr: 10.30.0.0/16}}]
      ports: [{port: 443, protocol: TCP}]
```

```bash
helm template fabric charts/fabric -n fabric-system \
  -f charts/fabric/profiles/shadow-production.yaml -f production-values.yaml > /dev/null
helm upgrade --install fabric charts/fabric -n fabric-system \
  -f charts/fabric/profiles/shadow-production.yaml -f production-values.yaml
```

The `file` content backend (allowed in Compose, refused in this profile)
stores objects at `<dir>/<tenant>/evidence/<h0h1>/<h2h3>/<object-id>`
(`h` = hex SHA-256 of the id; descriptors under `evidence/meta/` likewise).
Objects stored flat by earlier Nodes are still read and still count for
replay and conflict checks. Alert on the volume's inode use, not only
bytes. S3 keys are unchanged.

Put the Node's S3 writer role on `otel-collector.serviceAccount.annotations`
(IRSA), or name a credentials Secret in `content.s3.credentialsSecret` for an
S3-compatible store. `matchLabels` values must be strings (`"true"`; use
`--set-string` on the command line).

Under pseudonymous capture labels (the default) the chart refuses a
`sourceId` that is not `s-<32 hex>`. It cannot check that the value matches
your agents' key: a well-formed but wrong value renders, and then every agent
batch is refused at the Node.

Creating the certificates and Secrets with self-managed CAs (use your own
PKI if you have one; keep CA keys off the cluster):

```bash
NS=fabric-system
NODE=fabric-otel-collector.$NS.svc
openssl req -x509 -newkey rsa:3072 -sha256 -days 730 -nodes \
  -keyout node-ca.key -out node-ca.crt -subj "/CN=fabric-node-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -x509 -newkey rsa:3072 -sha256 -days 730 -nodes \
  -keyout client-ca.key -out client-ca.crt -subj "/CN=fabric-agent-client-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey rsa:3072 -sha256 -nodes -keyout node.key -out node.csr -subj "/CN=$NODE"
printf 'subjectAltName=DNS:%s,DNS:%s.cluster.local\nextendedKeyUsage=serverAuth\n' "$NODE" "$NODE" > node.ext
openssl x509 -req -in node.csr -CA node-ca.crt -CAkey node-ca.key -CAcreateserial \
  -days 90 -sha256 -extfile node.ext -out node.crt

kubectl -n "$NS" create secret tls fabric-node-receiver-tls --cert=node.crt --key=node.key
kubectl -n "$NS" create secret generic fabric-node-client-ca --from-file=ca.crt=client-ca.crt
umask 077; openssl rand -hex 32 | tr -d '\n' > ingress.token
kubectl -n "$NS" create secret generic fabric-node-ingress-token --from-file=token=ingress.token
umask 077; read -rs DEST_TOKEN; printf 'Bearer %s' "$DEST_TOKEN" > authorization; unset DEST_TOKEN
kubectl -n "$NS" create secret generic fabric-node-export-auth --from-file=authorization=authorization
openssl rand -base64 32 > content.key
kubectl -n "$NS" create secret generic fabric-node-content-key --from-file=key=content.key
rm -f authorization
```

Issue each agent a client certificate from `client-ca`
(`extendedKeyUsage=clientAuth`) and give it the Node CA. Mount the spool on
a subdirectory of a volume (the agent must own the directory); an
`emptyDir` survives container restarts but not Pod deletion, a PVC on an
encrypted StorageClass survives both.

## One source per production Node

A production Node binds exactly one tenant, one source id and one ingress
token. Agents with different source ids need one Node each; several pods
may share a Node only if they run with the same `FABRIC_SOURCE_ID` and
`FABRIC_WIRE_ID_KEY`.

## Minimal IAM (S3)

Agents need no store permissions. The Node writer needs `s3:PutObject` and
`s3:GetObject` on `arn:aws:s3:::<bucket>/<prefix><tenant>/evidence/*` (plus
`kms:GenerateDataKey` and `kms:Decrypt` for `aws:kms`). The reader that runs
`fabric.reconstruct` needs `s3:GetObject` (and `kms:Decrypt`). Neither
needs list or delete. Writes are conditional (`If-None-Match: *`): an object
is never overwritten. `<prefix>` defaults to `fabric/content/`.

## Upgrading from earlier releases

- **Node mode now requires a capture policy and keys.** An agent in node
  mode without `FABRIC_CAPTURE_POLICY`, `FABRIC_WIRE_ID_KEY` and
  `FABRIC_WIRE_SPOOL_KEY` stops recording content on upgrade (metadata
  continues; each span reports the missing item).
- **The Node needs its P0-A settings.** Compose preflight and the Helm
  render fail until `FABRIC_SOURCE_ID` /
  `receiver.workloadAuthentication.sourceId` (and, with content,
  `FABRIC_CONTENT_KEY_FILE` / `content.encryption.keySecret`) are set. The
  agents are never affected by a Node configuration error.
- **Customer redaction moved to a redaction service.** Module-reference
  and callable transformations (Python `Transformation(..., ref)`,
  `BytePrivacyPolicy.transform`, `ContentProtector` `redactors`) and
  TypeScript worker redactors (`{ module, exportName }`) are removed and
  raise at construction. Run a [redaction service](privacy-and-security.md#redaction-service),
  set `FABRIC_REDACTION_ENDPOINT`, and name each transformation by id and
  version.
- **`s-`-shaped source ids are now pseudonymised.** An agent
  `FABRIC_SOURCE_ID` that was already `s-` + 32 hex used to be sent
  unchanged; it is now mapped like any other value. Recompute the Node's
  `FABRIC_SOURCE_ID` / `sourceId` as shown under "Source id" above.
- **Node directory store layout.** New objects go to hash-sharded
  subdirectories; existing flat objects stay readable. Readers older than
  this release do not find sharded objects: upgrade `fabric.reconstruct`
  together with the Node.
- **Plaintext spool records.** With a spool key set, records written before
  it are quarantined in production. In the local profile,
  `FABRIC_WIRE_SPOOL_MIGRATE_PLAINTEXT=1` seals them in place once.
- **`fabric-gate` is stricter.** Hand-written collector configurations must
  attach the `noredirect` middleware to every OTLP/HTTP exporter, run
  `fabricguard` in every telemetry pipeline, and write receivers, pipelines
  and extensions literally. The shipped Compose and Helm configurations
  comply.
- See the [changelog](../CHANGELOG.md) for removed modules and changed APIs.

Before a release reaches production, verify its artifacts as described in
[verify a release](verify-release.md), and run the checks in
[operations](operations/README.md).
