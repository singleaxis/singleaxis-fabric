# Production setup: agent, Node and eBPF emitter

One recipe for the full production path on one Linux host: a Python agent in
a container, a production-profile Fabric Node with ingress groups and
content, and the eBPF host emitter in production mode, so that
`python -m fabric.reconstruct actions` can tie each command the agent ran to
the operating system's own exec event. It is derived from the AR-1
production live harness
([`qualification/action-record/ar1/live.py`](../qualification/action-record/ar1/live.py))
and the v0.11.0 and v0.11.1 user-acceptance runs. [Docker Desktop](#docker-desktop)
lists what differs on macOS.

Everything here is opt-in and passive: the hooks and the sensor observe, and
never approve, block, delay or change what the agent does. Reference pages:
[deployment](deployment.md) (every agent and Node variable),
[host sensors](host-sensors.md) (every emitter variable) and
[action reconstruction](action-reconstruction.md) (reading the result).

## 1. What you need

- Linux with cgroup v2 and kernel 5.8 or later built with BTF
  (`/sys/kernel/btf/vmlinux` exists), root on the host for the emitter.
- Docker Engine 24 or later with the Compose plugin 2.24 or later, and a
  checkout of this repository at the release tag (for `deploy/compose`).
- An HTTPS destination for the Node's export (your collector or SIEM, an
  OTLP/HTTP endpoint) and its bearer token.
  [A destination with a private CA](#a-destination-with-a-private-ca)
  covers a destination whose certificate comes from your own CA.
- An S3 bucket (or S3-compatible store) with server-side encryption for
  content. With ingress groups the Node stores content in S3 only. To try
  the recipe without a bucket, use the
  [local S3 store for testing](#a-local-s3-store-for-testing).
- Python 3.10 or later with `pip install "singleaxis-fabric[s3]"` where you
  read runs ([step 6](#6-read-a-run)). Agents never need the `s3` extra.

Pick names first. They appear in several places and must match:

```bash
export TENANT=acme-prod            # FABRIC_TENANT_ID on the agent and the Node
export AGENT_SRC=support-agent     # the agent's FABRIC_SOURCE_ID (clear label)
export HOST_LABEL=build-host-1     # FABRIC_HOST_LABEL = EMIT_HOST_LABEL
export EBPF_LABEL="$HOST_LABEL/ebpf"
export M="$PWD/fabric-material"    # keep it outside the repository
export FABRIC_REPO="$HOME/singleaxis-fabric"   # your checkout at the release tag
export FABRIC_ENV_FILE="$M/node.env"           # the Node's Compose env file
```

`FABRIC_ENV_FILE` is the Node's settings file. The Makefile in
`deploy/compose` reads it, and so do `docker compose --env-file`,
`preflight-prod.sh` and `verify-prod.sh`, so nothing is written into the
checkout: a read-only or shared checkout works. Without it they read
`deploy/compose/.env`, as before.

## 2. Keys, tokens and certificates

```bash
mkdir -p "$M/tls" "$M/secrets" && cd "$M" && umask 077
# A CA and the Node's server certificate. The SAN must name the address the
# agent and the emitter use: fabric-node on the Compose network, and
# localhost for checks from the host. The CA key, the request and the
# extension file stay in $M: tls/ is mounted into the Node and holds only
# ca.crt, server.crt and server.key (a random serial, so no serial file).
openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes -keyout ca.key \
  -out tls/ca.crt -subj "/CN=fabric-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey rsa:3072 -sha256 -nodes -keyout tls/server.key -out server.csr \
  -subj "/CN=fabric-node"
printf 'subjectAltName=DNS:fabric-node,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > server.ext
openssl x509 -req -in server.csr -CA tls/ca.crt -CAkey ca.key \
  -set_serial "0x$(openssl rand -hex 16)" \
  -days 365 -sha256 -extfile server.ext -out tls/server.crt
# One token per ingress group (agent, ebpf), no trailing newline, all different.
for t in agent ebpf; do openssl rand -hex 32 | tr -d '\n' > "secrets/$t.token"; done
openssl rand -base64 32 | tr -d '\n' > secrets/content.key     # Node content key
openssl rand -base64 32 | tr -d '\n' > secrets/spool.key       # agent spool key
openssl rand -base64 32 | tr -d '\n' > secrets/ebpf-state.key  # emitter state key
openssl rand -hex 24 | tr -d '\n' > secrets/id.key             # shared id key
```

The id key is shared by the agent (`FABRIC_WIRE_ID_KEY`, its bytes exactly),
the emitter (`EMIT_ID_KEY_FILE`) and the verifier (`--id-key-env`): with
different keys nothing joins.

File ownership: the Node runs as uid and gid 65532. On native Linux,
`preflight-prod.sh` wants each secret owned by you, group 65532, mode 0440,
and the certificates readable (on Docker Desktop, skip the `sudo chgrp`
line; see [Docker Desktop](#docker-desktop)):

```bash
sudo chgrp 65532 secrets/agent.token secrets/ebpf.token secrets/content.key tls/server.key
chmod 0440 secrets/agent.token secrets/ebpf.token secrets/content.key tls/server.key
chmod 0444 tls/ca.crt tls/server.crt
chmod 0400 secrets/spool.key secrets/id.key secrets/ebpf-state.key
```

The capture policy (`deployment-policy/v1`, all ten keys required) names the
roles to keep. This one keeps the model exchanges (the decisions chain
needs them), never keeps subprocess arguments, output or non-model HTTP
bodies in clear, and records only the metadata of the execution context:

```bash
cat > policy.json <<EOF
{
  "schema_version": "fabric.deployment-policy/v1",
  "policy_id": "support-agent-capture",
  "policy_version": 1,
  "tenant_id": "$TENANT",
  "workload_id": "support-agent",
  "privacy": {
    "model.exchange.request": "retain_original",
    "model.exchange.response": "retain_original",
    "model.exchange.part": "retain_original",
    "terminal.argv": "redact",
    "terminal.context": "metadata_only",
    "terminal.stdout": "redact",
    "terminal.stderr": "redact",
    "record.evidence": "retain_original",
    "network.request": "metadata_only",
    "network.response": "metadata_only"
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
EOF
```

Roles you leave out are `omit`. Choose the modes your data allows
([privacy and security](privacy-and-security.md#protection-modes-the-protect-stage)):
`terminal.argv` and `terminal.stdout` often hold secrets, and with the S3
backend retained content is readable by anyone who can read the bucket
prefix ([step 6](#who-can-read-content-in-s3)).

**`redact` under zero-code capture withholds.** A `redact` role is masked by
your redaction service with a transformation you name in code; the
zero-code autoload of step 5 cannot name one, so those roles are stored as
descriptors only (`not_captured(protection_failed)`). The run still
reconstructs, but the actions view shows each command as `exec pid N`
instead of its command line, and output matching (rule A1) does not apply.
To get masked command lines, run a redaction service and name the
transformation ([masked arguments and output](#masked-arguments-and-output)).
`retain_original` keeps them in clear: only for data you may store that way.

## 3. The Node

The two source ids the Node binds, as they travel:

```bash
AGENT_S=$(python3 -c 'import hashlib,hmac,sys
print("s-"+hmac.new(open(sys.argv[1],"rb").read(), sys.argv[2].encode(),
      hashlib.sha256).hexdigest()[:32])' "$M/secrets/id.key" "$AGENT_SRC")
EBPF_S=$(docker run --rm --user "$(id -u)" -e EMIT_SOURCE_LABEL="$EBPF_LABEL" \
  -e EMIT_ID_KEY_FILE=/k/id.key -v "$M/secrets/id.key:/k/id.key:ro" \
  ghcr.io/singleaxis/fabric-host-emitter:<version> print-source-id)
```

The Node's env file, `$FABRIC_ENV_FILE` (mode 0600). Fill in the image
version, your destination, its token, the bucket and its region:

```bash
cat > "$FABRIC_ENV_FILE" <<EOF
FABRIC_NODE_IMAGE=ghcr.io/singleaxis/fabric-otelcol:<version>
FABRIC_NODE_PULL_POLICY=always
FABRIC_EXPORT_ENDPOINT=https://otlp.example.com:443
FABRIC_EXPORT_AUTH_HEADER=Bearer <destination token>
FABRIC_TENANT_ID=$TENANT
FABRIC_AGENT_SOURCE_ID=$AGENT_S
FABRIC_INGRESS_TOKEN_FILE=$M/secrets/agent.token
FABRIC_EBPF_SOURCE_ID=$EBPF_S
FABRIC_EBPF_TOKEN_FILE=$M/secrets/ebpf.token
FABRIC_INGRESS_TLS_DIR=$M/tls
FABRIC_CONTENT_BACKEND=s3
FABRIC_CONTENT_KEY_FILE=$M/secrets/content.key
FABRIC_CONTENT_S3_BUCKET=<bucket>
FABRIC_CONTENT_S3_REGION=<region>
EOF
chmod 0600 "$FABRIC_ENV_FILE"
```

For an S3-compatible store, also set `FABRIC_CONTENT_S3_ENDPOINT` (an
`https://` URL; preflight refuses plain HTTP), `FABRIC_CONTENT_S3_PATH_STYLE=true`
and `FABRIC_CONTENT_S3_SSE=AES256` (SSE-S3) when it has no KMS. The Node
takes S3 credentials from the AWS default chain of its container
([deployment](deployment.md#production-profile)): on EC2 the instance role,
for an S3-compatible store a credentials file mounted as a Compose secret
(as the [test store](#a-local-s3-store-for-testing) does). Never put keys in
the env file.

Two optional steps go before the Node starts: trusting a destination behind
a private CA, and the local S3 store for testing.

### A destination with a private CA

When the destination's certificate comes from your own CA (a local test
collector, an internal gateway), the Node must trust that CA for its export.
Do it with an override in your own directory, never by editing the shipped
`collector-config/*.yaml`:

```bash
cp <your CA certificate> "$M/tls/export-ca.crt" && chmod 0444 "$M/tls/export-ca.crt"
mkdir -p "$M/site" && cat > "$M/site/export-ca.yaml" <<'EOF'
exporters:
  otlp_http/fabric:
    tls:
      ca_file: /run/fabric-node/tls/export-ca.crt
EOF
cat > "$M/site/compose.export-ca.yml" <<EOF
services:
  fabric-node:
    command:
      - --config=/etc/fabric-node/collector-production-groups.yaml
      - --config=/etc/fabric-node/collector-production-groups-content.yaml
      - --config=/etc/fabric-node/site-export-ca.yaml
    volumes:
      - $M/site/export-ca.yaml:/etc/fabric-node/site-export-ca.yaml:ro
EOF
# Append to FABRIC_COMPOSE_EXTRA, keeping any file already listed.
extra=$(sed -n 's/^FABRIC_COMPOSE_EXTRA=//p' "$FABRIC_ENV_FILE" | tail -n 1)
echo "FABRIC_COMPOSE_EXTRA=${extra:+$extra }$M/site/compose.export-ca.yml" >> "$FABRIC_ENV_FILE"
```

`FABRIC_COMPOSE_EXTRA` (space-separated Compose files, absolute or relative
to `deploy/compose`; the last line in the env file counts) is appended last to the
files `make up-prod`/`up-prod-groups` use, so the override's `command`
replaces the shipped list: keep every `--config` of your profile in it (here
groups plus S3 content; without content, only the first line). The CA file
must be inside `FABRIC_INGRESS_TLS_DIR`, which is mounted at
`/run/fabric-node/tls`. Preflight does not read your override, so it neither
checks that file nor needs `FABRIC_EXPORT_CA_FILE`. The destination's
certificate must name the host in `FABRIC_EXPORT_ENDPOINT`, and the Node's
container must resolve it (a destination container on the
`fabric-node-production_fabric-node` network, or an `extra_hosts` entry in
the same override). The local trial's controlled sink (`make up`) is plain
HTTP and is refused in production.

### A local S3 store for testing

> **Test only.** This is a single SeaweedFS container with a test
> certificate and static keys, for trying the production Node without a
> cloud bucket. Never use it for real content. While `FABRIC_COMPOSE_EXTRA`
> names it, preflight prints a warning saying so on every run.

Preflight refuses a plain-HTTP content endpoint, so the local trial's
`make up-s3-local` store cannot stand in. The shipped overlay
[`docker-compose.content-s3-local-tls.yml`](../deploy/compose/docker-compose.content-s3-local-tls.yml)
runs the same store over HTTPS, with a certificate signed by the CA from
[step 2](#2-keys-tokens-and-certificates). The Node trusts that CA for S3
(`AWS_CA_BUNDLE`) and reads its keys from a credentials file mounted as a
Compose secret (`AWS_SHARED_CREDENTIALS_FILE`); preflight checks the
endpoint, bucket, region and SSE as it would for a real store. In the env file,
use `FABRIC_CONTENT_S3_BUCKET=fabric-content` and
`FABRIC_CONTENT_S3_REGION=us-east-1` in the env file, then:

```bash
cd "$M" && umask 077 && mkdir -p s3-tls
openssl req -newkey rsa:3072 -sha256 -nodes -keyout s3-tls/server.key -out s3.csr \
  -subj "/CN=s3-local-tls"
printf 'subjectAltName=DNS:s3-local-tls,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > s3.ext
openssl x509 -req -in s3.csr -CA tls/ca.crt -CAkey ca.key \
  -set_serial "0x$(openssl rand -hex 16)" \
  -days 30 -sha256 -extfile s3.ext -out s3-tls/server.crt
cp tls/ca.crt s3-tls/ca.crt
chmod 0444 s3-tls/server.crt s3-tls/ca.crt && chmod 0400 s3-tls/server.key
# Three identities: admin (creates the bucket), the Node's writer, a read-only reader.
for who in root node reader; do
  printf '[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n' \
    "fabric-$who-$(openssl rand -hex 4)" "$(openssl rand -hex 24)" > "secrets/s3-$who.credentials"
done
openssl rand -hex 32 | tr -d '\n' > secrets/s3-sse.kek   # the store's SSE-S3 key-encryption key
chmod 0400 secrets/s3-root.credentials secrets/s3-reader.credentials secrets/s3-sse.kek
chmod 0440 secrets/s3-node.credentials   # native Linux: sudo chgrp 65532 it, like the tokens
extra=$(sed -n 's/^FABRIC_COMPOSE_EXTRA=//p' "$FABRIC_ENV_FILE" | tail -n 1)
cat >> "$FABRIC_ENV_FILE" <<EOF
FABRIC_COMPOSE_EXTRA=${extra:+$extra }docker-compose.content-s3-local-tls.yml
FABRIC_CONTENT_S3_ENDPOINT=https://s3-local-tls:8333
FABRIC_CONTENT_S3_PATH_STYLE=true
FABRIC_CONTENT_S3_SSE=AES256
FABRIC_S3_LOCAL_TLS_DIR=$M/s3-tls
FABRIC_S3_LOCAL_TLS_ROOT_CREDENTIALS_FILE=$M/secrets/s3-root.credentials
FABRIC_S3_LOCAL_TLS_NODE_CREDENTIALS_FILE=$M/secrets/s3-node.credentials
FABRIC_S3_LOCAL_TLS_READER_CREDENTIALS_FILE=$M/secrets/s3-reader.credentials
FABRIC_S3_LOCAL_TLS_KEK_FILE=$M/secrets/s3-sse.kek
EOF
```

The store publishes its S3 port on `127.0.0.1:9000` only
(`FABRIC_S3_LOCAL_TLS_PORT` changes it), creates the bucket with default
SSE-S3 and a policy that denies deletes, lets the Node's writer read and
write the content prefix and the reader only read it. Its data lives in the
volume `fabric-node-production_s3-local-tls-data`: `make down-prod-groups`
keeps it, and `docker volume rm fabric-node-production_s3-local-tls-data`
deletes it after the Node is down.

### Start the Node

```bash
make -C "$FABRIC_REPO/deploy/compose" up-prod-groups   # runs preflight-prod.sh --groups first; refuses on any FAIL
```

It ends by printing the Compose project and the ports it published, read
from the same env file (`Project fabric-node-production, ingress groups on
127.0.0.1: agent 4317/4318, content 4319, ebpf 4417 ...`).

Content with ingress groups is S3 only. `FABRIC_CONTENT_BACKEND=file` is
refused by preflight, and since v0.11.1 also by the Node at startup
(`fabric-gate`), so it can no longer run telemetry-only by surprise when
preflight was bypassed. The Node listens for the agent group on 4317/4318
(telemetry) and 4319 (content), and for the ebpf group on 4417, all with TLS
and each group's own token, published on `127.0.0.1` unless you set
`FABRIC_BIND_ADDR`. The Compose project is `fabric-node-production`, so
containers on its network `fabric-node-production_fabric-node` reach the Node
as `fabric-node`, and the Node's container is
`fabric-node-production-fabric-node-1`.

### Queue size on a small host

Preflight compares the Node's worst-case queue size with the free disk and
warns when it does not fit, for example on a laptop: an 80 GB worst case
with 58 GB free. The worst case is `queue_size` times the largest request
the Node accepts: 10000 telemetry batches of up to 8 MiB, plus 64 content
records of up to 64 MiB each. Real batches are far smaller, so this is a
warning, not a failure. It means a long destination outage could fill the
disk before the queue is full.

To fit a small host, lower these values in the collector config your
target uses (`collector-config/collector-production-groups.yaml` for
`up-prod-groups`, `collector-production.yaml` for `up-prod`), then run
preflight again. It reads the same file.

- **`exporters.otlp_http/fabric.sending_queue.queue_size`** (10000). This is
  the main lever: 2000 gives a worst case of about 16 GB. The Node then
  holds fewer batches while the destination is down. When the queue is
  full, `block_on_overflow` pushes back on senders: an agent with a spool
  keeps its records on its own disk until the Node accepts them, and a
  sender without one may drop them.
- **The OTLP receivers' `max_request_body_size`** (8 MiB) **and
  `max_recv_msg_size_mib`** (8). Lowering them shrinks the worst case per
  batch, but the Node refuses any larger request outright, so keep them
  above the largest batch your senders send.
- **The content queue's `queue_size`** (64, in the `fabriccontent`
  exporters of the content overlay,
  `collector-config/collector-production-groups-content.yaml`). Each item
  can be 64 MiB, so 16 cuts that part to 1 GB. Bodies then wait for an
  unavailable store in a shorter queue. Leave the content receiver's
  64 MiB limit as it is: an agent sends bodies up to 63 MiB.

[Operations: queue volume sizing](operations/dr.md#queue-volume-sizing)
covers sizing for a production outage window.

### Two stacks on one host

The project name and the published ports are settings, so a second Node
(another tenant, a staging stack) needs only its own env file and material
directory. Give it its own `COMPOSE_PROJECT_NAME` and free ports:

```bash
cat >> "$FABRIC_ENV_FILE" <<EOF
COMPOSE_PROJECT_NAME=fabric-staging
FABRIC_OTLP_GRPC_PORT=5317
FABRIC_OTLP_HTTP_PORT=5318
FABRIC_OTLP_CONTENT_PORT=5319
FABRIC_EBPF_GRPC_PORT=5417
FABRIC_HEALTH_PORT=14133
FABRIC_METRICS_PORT=9888
EOF
```

(`FABRIC_S3_LOCAL_TLS_PORT` too when it runs the test store.) Every name the
rest of this page derives from the project follows: the network is
`<project>_fabric-node`, the Node's container `<project>-fabric-node-1` and
the volumes `<project>_<volume>`, so use those in the `--network` flags and
`docker inspect` commands of that stack. Containers on a stack's network
still reach its Node as `fabric-node` on the container ports (4317, 4318,
4319, 4417): only the host-published ports change. Run each stack's `make`
with its own `FABRIC_ENV_FILE`.

### When the destination refuses data

Once the Node accepts a record (the agent's spool deletes it), the Node never
drops it silently:

- **Credential, availability or configuration failures** (401, 403, 404,
  5xx, a redirect, any status not listed below) are retried with backoff for
  as long as the persistent queue has room. An expired or revoked egress
  credential costs nothing once it is fixed. When the queue is full, the Node
  refuses new records and the agents keep them in their spools, as they do
  when the Node is down. `fabric_delivery_held_responses_total{http_response_status_code}`
  counts these responses.
- **Permanent rejections** (400, 409, 413, 422: the destination refuses the
  bytes themselves) cannot be retried forever. Before the Node releases such a
  batch, it writes a `destination_rejected` loss record for every source
  position in the batch to `/var/lib/fabric-node/queue/loss-outbox` on the
  queue volume. Once the destination accepts an export again, the Node
  delivers those records, and `python -m fabric.reconstruct` then reports the
  affected runs with a `loss` gap. They are never `complete` and never
  missing from the report. If the Node cannot write a loss record, it keeps
  the batch and retries it.
- `fabric_delivery_loss_records_pending` is the number of loss records still
  on the Node's disk. While it is above 0, some lost positions are not yet
  visible at the destination, and the Node logs an error every 5 minutes.
  `fabric_delivery_rejected_batches_total` and
  `fabric_delivery_lost_positions_total` count what was given up. The
  metrics are on the Node's metrics port (8888).

## 4. The eBPF emitter

Scope the sensor to the agent's containers with a cgroup **parent**: every
agent container starts with `--cgroup-parent`, and the emitter's agent root
is that directory. Create it before the emitter starts (each root must exist
at start).

| Docker cgroup driver (`docker info --format '{{.CgroupDriver}}'`) | Agent containers | `EMIT_AGENT_CGROUP_ROOTS` | Create the root |
|---|---|---|---|
| `cgroupfs` | `--cgroup-parent=/fabric-agents` | `/sys/fs/cgroup/fabric-agents` | `sudo mkdir /sys/fs/cgroup/fabric-agents` |
| `systemd` | `--cgroup-parent=fabric-agents.slice` | `/sys/fs/cgroup/fabric.slice/fabric-agents.slice` | a `fabric-agents.slice` unit, started (`printf '[Slice]\n' \| sudo tee /run/systemd/system/fabric-agents.slice && sudo systemctl start fabric-agents.slice`) |

Both drivers work. (AR-1 live uses `systemd` slices because its harness
creates systemd units; the v0.11.0 UAT ran on `cgroupfs`.) Containers the
agent starts itself (sandboxes) go under a second parent, the sandbox root,
created the same way (`/sys/fs/cgroup/fabric-sandboxes` with
`--cgroup-parent=/fabric-sandboxes` on `cgroupfs`) and passed as
`-e EMIT_SANDBOX_CGROUP_ROOTS=/sys/fs/cgroup/fabric-sandboxes`; see
[agents that start containers](#agents-that-start-containers).

```bash
EMIT_ETC=/etc/fabric-host-emitter EMIT_VAR=/var/lib/fabric-host-emitter
sudo install -d -m 0700 -o root "$EMIT_VAR" "$EMIT_ETC"
sudo install -m 0400 -o root "$M/secrets/id.key"        "$EMIT_ETC/id.key"
sudo install -m 0400 -o root "$M/secrets/ebpf-state.key" "$EMIT_ETC/state.key"
sudo install -m 0400 -o root "$M/secrets/ebpf.token"    "$EMIT_ETC/token"
sudo install -m 0444 -o root "$M/tls/ca.crt"            "$EMIT_ETC/ca.crt"

docker run -d --name fabric-host-emitter --restart unless-stopped \
  --user 0 --read-only --pid=host --cgroupns=host \
  --cap-drop=ALL --cap-add=BPF --cap-add=PERFMON \
  --cap-add=SYS_RESOURCE --cap-add=DAC_READ_SEARCH \
  --security-opt no-new-privileges \
  --network fabric-node-production_fabric-node \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v "$EMIT_ETC:/etc/fabric-host-emitter:ro" \
  -v "$EMIT_VAR:/var/lib/fabric-host-emitter" \
  -e EMIT_PRODUCTION=true \
  -e EMIT_TENANT_ID="$TENANT" \
  -e EMIT_SOURCE_LABEL="$EBPF_LABEL" \
  -e EMIT_HOST_LABEL="$HOST_LABEL" \
  -e EMIT_ID_KEY_FILE=/etc/fabric-host-emitter/id.key \
  -e EMIT_STATE_KEY_FILE=/etc/fabric-host-emitter/state.key \
  -e EMIT_STATE_DIR=/var/lib/fabric-host-emitter \
  -e EMIT_AGENT_CGROUP_ROOTS=/sys/fs/cgroup/fabric-agents \
  -e EMIT_ENDPOINT=fabric-node:4417 \
  -e EMIT_BEARER_TOKEN_FILE=/etc/fabric-host-emitter/token \
  -e EMIT_TLS_CA_FILE=/etc/fabric-host-emitter/ca.crt \
  ghcr.io/singleaxis/fabric-host-emitter:<version>
docker logs fabric-host-emitter   # "production mode, bpf loaded, source s-..."
```

What each flag is for: `--user 0` with all capabilities dropped but `BPF`,
`PERFMON`, `SYS_RESOURCE` and `DAC_READ_SEARCH` loads and attaches the
programs (the image's default user is nonroot); `--pid=host` lets the
emitter read every process's `/proc` entry; `--cgroupns=host` makes the
cgroup paths it reports and the roots it watches the host's; the read-only
`/sys` mounts are BTF, tracefs, debugfs and cgroupfs. If the programs fail to
load with `operation not permitted`, your engine's seccomp profile does not
allow `bpf()` and `perf_event_open()` with these capabilities: use a profile
that does. `--privileged` is not a qualified fallback.

## 5. The agent

```bash
AGENT_IMAGE=<your agent image>
AUTOLOAD=$(docker run --rm "$AGENT_IMAGE" python -m fabric.wire --print-autoload-path)
cat > "$M/agent.env" <<EOF
FABRIC_WIRE_AUTOLOAD=1
PYTHONPATH=$AUTOLOAD
FABRIC_TENANT_ID=$TENANT
FABRIC_SOURCE_ID=$AGENT_SRC
FABRIC_WIRE_ID_KEY=$(cat "$M/secrets/id.key")
FABRIC_WIRE_CONTENT_ENDPOINT=https://fabric-node:4319/v1/logs
OTEL_EXPORTER_OTLP_ENDPOINT=https://fabric-node:4318
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20$(cat "$M/secrets/agent.token")
OTEL_EXPORTER_OTLP_CERTIFICATE=/fabric/ca.crt
FABRIC_WIRE_SPOOL_DIR=/var/lib/fabric-agent/spool
FABRIC_WIRE_SPOOL_KEY_FILE=/fabric/spool.key
FABRIC_CAPTURE_POLICY=/fabric/policy.json
FABRIC_WIRE_EXEC=1
FABRIC_HOST_LABEL=$HOST_LABEL
FABRIC_WIRE_HTTP_HOSTS=["pypi.org"]
EOF
chmod 0600 "$M/agent.env"

docker run --rm --name support-agent --cgroup-parent=/fabric-agents \
  --network fabric-node-production_fabric-node --env-file "$M/agent.env" \
  -v "$M/tls/ca.crt:/fabric/ca.crt:ro" -v "$M/secrets/spool.key:/fabric/spool.key:ro" \
  -v "$M/policy.json:/fabric/policy.json:ro" \
  -v fabric-agent-spool:/var/lib/fabric-agent \
  "$AGENT_IMAGE" python agent.py
```

- **Agent image.** Install the SDK with its `otlp` extra:
  `pip install "singleaxis-fabric[otlp]==<version>"` (OTLP export, the
  sealed spool's `cryptography`). The agent never needs `s3`.
- **Autoload path.** `PYTHONPATH` must name the directory
  `python -m fabric.wire --print-autoload-path` prints in the agent image;
  if the image already sets `PYTHONPATH`, append that directory to it.
- **Check the configuration.** Every Python process the agent starts
  inherits the autoload, so Fabric keeps its warnings off stdout and stderr:
  a tool's output reads the same with capture on or off. Read them instead
  with `python -m fabric.wire status`, run with the agent's environment
  (`docker run --rm --env-file "$M/agent.env" "$AGENT_IMAGE" python -m
  fabric.wire status`). It prints one JSON line: wire and content capture,
  each hook's state, and a `warnings` list, and exits 1 if that list is not
  empty. It installs nothing. To print the warnings from every autoloaded
  process while debugging, set `FABRIC_WIRE_DIAGNOSTICS=stderr`.
- **Scope.** `--cgroup-parent=/fabric-agents` is the `cgroupfs` form; on the
  `systemd` driver use `--cgroup-parent=fabric-agents.slice`
  ([step 4](#4-the-ebpf-emitter)).
- **Spool.** Put `FABRIC_WIRE_SPOOL_DIR` on a local disk or a named volume,
  as here, not on a slow or network mount and not on a Docker Desktop bind
  mount ([deployment](deployment.md#what-the-agent-needs), "Spool disk").
  The directory must be owned by the agent's uid: a new named volume is
  root's, so `chown` it once when the agent runs as another user.
- **Model endpoints.** The OpenAI and Anthropic APIs are built in; any other
  model host goes in `FABRIC_WIRE_ENDPOINTS`, a JSON array such as
  `[{"endpoint_id":"local-llm","dialect":"openai","hosts":["llm.internal"],"ports":[11434],"schemes":["http"]}]`
  ([deployment](deployment.md#what-the-agent-needs)).
- **Non-model HTTP** (`FABRIC_WIRE_HTTP_HOSTS`). A JSON array of hosts whose
  httpx and httpx2 requests are recorded (capture point `http.nonmodel`),
  at most 256: `"host"` or `"host:port"` means HTTPS on that port (443 by
  default), `"http://host[:port]"` plain HTTP. Hosts are matched exactly,
  never as a suffix: list `pypi.org` and `files.pythonhosted.org`
  separately. No path, query, user information or wildcard. Without a
  retaining policy only the method, status, keyed host id and an evidence
  object are recorded; the policy roles `network.request` (method, target
  and request body) and `network.response` (the response body) keep the
  bodies. Requests through `requests`, `urllib3` or `aiohttp` are not seen.
  In a reconstruction these requests are listed as recorded, but not
  attributed to a tool call yet
  ([action reconstruction](action-reconstruction.md#what-is-not-covered-yet)).
- **Subprocesses** (`FABRIC_WIRE_EXEC=1`) and the host label make the
  process anchor of spec 056: the label must equal the emitter's
  `EMIT_HOST_LABEL`.

### Masked arguments and output

To keep command lines and output masked rather than withheld, run the
[example redaction service](../examples/redaction-service/README.md) (or
your own, `contracts/redaction/v1`) next to the agent on a Unix socket in a
shared volume, set `FABRIC_REDACTION_ENDPOINT=unix:///run/fabric/redaction.sock`
in `agent.env`, and install capture from the agent's own entry point
instead of the autoload (drop `FABRIC_WIRE_AUTOLOAD` and the autoload
`PYTHONPATH` from `agent.env`):

```python
import json, os

from fabric import wire
from fabric.wire import Transformation

mask = Transformation("example-mask", "1")   # the id and version your service knows
policy = json.load(open(os.environ["FABRIC_CAPTURE_POLICY"]))
wire.install_from_env(transformations={
    role: mask for role, mode in policy["privacy"].items()
    if mode in ("redact", "masked_only", "original_plus_masked")
})
# ... then import and run the agent
```

`install_from_env` reads every `FABRIC_*` variable as the autoload does and
also installs the hooks they switch on (`FABRIC_WIRE_EXEC`,
`FABRIC_WIRE_HTTP_HOSTS`). Since 0.11.2 a masking transformation always runs
over the decoded body: a gzip response is decoded first, and a body Fabric
cannot decode is withheld, never stored as `redacted`. Child Python
processes the agent starts are captured only through the autoload: keep it
in their environment if you need them.

### Agents that start containers

An agent whose tools run commands in containers (a sandbox) needs, besides
step 5's flags:

- **The Docker socket.** `-v /var/run/docker.sock:/var/run/docker.sock` and
  the `docker` CLI in the image. Anyone with the socket controls the host's
  Docker daemon: give it only to an agent you would give that.
- **A sandbox parent.** The agent's tool must start each container with
  `--cgroup-parent=/fabric-sandboxes` (`fabric-sandboxes.slice` on the
  `systemd` driver), the sandbox root of [step 4](#4-the-ebpf-emitter), so
  the emitter scopes its events `sandbox`; a container started without it
  is outside both roots and unseen. With `FABRIC_WIRE_EXEC=1`, the id
  `docker run -d` (or `create`) prints becomes the effect's
  `fabric.sandbox.created_id`, and rule H5 ties the container's own events
  to that `docker run` effect (`sandbox_report · certain`).
- **What is linked to what.** A command run with `docker exec` into that
  container is part of the sandbox (H5), tied to the `docker run` effect,
  not to the `docker exec` effect or the tool call that ran it (known
  limitation). A `docker run --rm` prints no id: its events are counted in
  `sandbox_events_unlinked`, not linked.
- **Remote sandboxes** (Modal, Daytona and others besides E2B): the
  commands run elsewhere and are invisible here; only the agent's
  connections to the provider are seen. Declare its API hosts in
  `FABRIC_WIRE_SANDBOX_HOSTS` and its addresses to the reader with
  `--sandbox-peer ADDRESS:PORT`, so those connections are listed under
  `remote_sandbox_calls` rather than unexplained. Setting
  `FABRIC_WIRE_REMOTE_SANDBOX=modal` disables only that hook
  (`disabled(unsupported_provider)`, reported by `python -m fabric.wire
  status`); it never turns the other hooks off.
- **In-process tools** (file edits, `exec()` of model code, an HTTP client
  in the agent process): no process starts, so no effect exists. Name them
  to the reader with `--in-process-tool NAME` so their calls read
  `no_effect_channel` instead of `none_in_window`.

### One-shot agent containers

An agent delivers its spool's backlog while it runs. At exit it waits only
for its exit budget (`FABRIC_WIRE_SHUTDOWN_TIMEOUT_S`, 2 s by default), and
whatever is left stays on the spool volume until the next process that uses
it. When no later agent run will use the same volume, drain it once the
agent exits. Use the same image, env file, mounts and volume:

```bash
docker run --rm --network fabric-node-production_fabric-node --env-file "$M/agent.env" \
  -v "$M/tls/ca.crt:/fabric/ca.crt:ro" -v "$M/secrets/spool.key:/fabric/spool.key:ro" \
  -v "$M/policy.json:/fabric/policy.json:ro" \
  -v fabric-agent-spool:/var/lib/fabric-agent \
  "$AGENT_IMAGE" python -m fabric.wire drain --until-empty --timeout 600
```

The drainer builds the agent's sender from the env file and delivers exactly
as an agent would: bodies to the Node, then spans, and a record is deleted
only after every part was accepted. It captures nothing itself, even with
`FABRIC_WIRE_AUTOLOAD=1` in the env file. While a live agent holds the spool,
the drainer waits; it takes over once the spool is free. It prints one JSON
line (`drained`, `delivered`, `remaining`, `undecryptable`, `quarantined`,
`seconds`) and exits with 0 when nothing deliverable is left or 1 when
records remain on disk, for example while the Node is down. Run it again
later in that case. Without `--until-empty` it runs as a sidecar until
SIGTERM, then makes a final drain attempt of up to 10 s. Kubernetes patterns
are in [wire capture deployment](wire-capture-deployment.md#draining-a-spool-with-no-agent-running).

## 6. Read a run

Copy the destination's span export (the OTLP trace export requests it
received, `*.otlp` protobuf or OTLP/JSON `*.json`/`*.jsonl`, as a collector
file exporter writes them) into a directory `export/`. The
reader takes the content of each run from the store with its own
credentials, from the AWS default credential chain (environment variables,
`AWS_PROFILE`, a shared credentials file, an instance role). Give it a
read-only principal of its own, never the Node's writer keys: `s3:GetObject`
on `arn:aws:s3:::<bucket>/<prefix><tenant>/evidence/*`, plus `kms:Decrypt`
on the key with SSE-KMS ([minimal IAM](deployment.md#minimal-iam-s3)).

```bash
export FABRIC_WIRE_ID_KEY="$(cat "$M/secrets/id.key")"
NODE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
  fabric-node-production-fabric-node-1)
python -m fabric.reconstruct actions export/ \
  --store-uri s3://<bucket>/fabric/content/ --s3-region <region> --tenant "$TENANT" \
  --id-key-env FABRIC_WIRE_ID_KEY --trusted-source --profile production \
  --host-source "host.ebpf=$EBPF_S" \
  --endpoint-peer openai.default=<each address api.openai.com resolved to> \
  --known-peer "$NODE_IP" --known-peer 127.0.0.11
```

For an agent with remote sandboxes or in-process tools, add
`--sandbox-peer <provider address>:443` and `--in-process-tool <tool name>`
([agents that start containers](#agents-that-start-containers)).

**An S3-compatible store** needs three more settings on the reader:
`--s3-endpoint-url https://<host>:<port>` (the address the reader reaches
it at, which may differ from the Node's `FABRIC_CONTENT_S3_ENDPOINT`),
`--s3-path-style` when the store does not serve virtual-hosted bucket names
(MinIO, SeaweedFS and most on-premises stores), and `--s3-region` (any
region the store accepts). When its certificate comes from a private CA,
point `AWS_CA_BUNDLE` at that CA: the reader trusts it for S3 only. For the
[test store](#a-local-s3-store-for-testing), with its read-only keys:

```bash
export AWS_SHARED_CREDENTIALS_FILE="$M/secrets/s3-reader.credentials" AWS_CA_BUNDLE="$M/tls/ca.crt"
python -m fabric.reconstruct actions export/ \
  --store-uri s3://fabric-content/fabric/content/ --tenant "$TENANT" \
  --s3-endpoint-url https://127.0.0.1:9000 --s3-path-style --s3-region us-east-1 \
  --id-key-env FABRIC_WIRE_ID_KEY --trusted-source --profile production \
  --host-source "host.ebpf=$EBPF_S" \
  --endpoint-peer openai.default=<each address api.openai.com resolved to> \
  --known-peer "$NODE_IP" --known-peer 127.0.0.11
```

**The Node's directory backend** (`FABRIC_CONTENT_BACKEND=file`, only with
the single-binding `make up-prod` and `FABRIC_CONTENT_REQUIRE_SSE=false`;
never with ingress groups) seals every object with the Node content key, so
the reader needs that key and a copy of the `fabric-content` volume:

```bash
python -m fabric.reconstruct actions export/ \
  --store-root <copy of the fabric-content volume> --content-key-file "$M/secrets/content.key" \
  --tenant "$TENANT" --id-key-env FABRIC_WIRE_ID_KEY --trusted-source --profile production \
  --host-source "host.ebpf=$EBPF_S" --known-peer "$NODE_IP" --known-peer 127.0.0.11
```

`--content-key-file` applies to `--store-root` only; with `--store-uri` the
reader exits 2.

### Who can read content in S3

With the S3 backend, Fabric does not seal the objects. The Node's content
queue on its own disk is sealed with `content.key`, but each object goes to
the bucket as captured and is protected at rest by the bucket's server-side
encryption (`FABRIC_CONTENT_S3_SSE`; spec 049 §7.8). Server-side encryption
protects the disks, not the API: **read access to the content prefix is read
access to every retained original**, including any secret a
`retain_original` role kept from arguments or output. Restrict it:

- **IAM and the bucket policy.** Allow `s3:GetObject` on
  `arn:aws:s3:::<bucket>/<prefix><tenant>/evidence/*` only to the Node's
  writer and the people or jobs that may see content; deny `s3:GetObject`
  on that prefix to every other principal in the bucket policy; turn on
  Block Public Access. No one needs `s3:ListBucket` or `s3:DeleteObject`.
- **The KMS key policy.** Use `FABRIC_CONTENT_S3_SSE=aws:kms` with a
  customer-managed key (`FABRIC_CONTENT_S3_KMS_KEY_ID`) and allow
  `kms:Decrypt` only to the same principals: a principal with
  `s3:GetObject` but without `kms:Decrypt` reads nothing, and CloudTrail
  logs every decrypt. SSE-S3 (`AES256`) has no key policy, so the bucket
  policy is the only control.
- **The capture policy.** Keep only the roles you need as
  `retain_original` ([step 2](#2-keys-tokens-and-certificates)).

### Peers

Production host records carry no clear address: each peer is a keyed id.
The verifier keys the addresses you list with the same id key, so it can
tell the agent's expected connections from unexplained ones only for the
addresses you give it, as the agent's container saw them:

- `--endpoint-peer ENDPOINT_ID=ADDRESS`, repeated for **every** address of
  each model endpoint. A CDN-fronted API resolves to several addresses and
  they change; list all the agent may have used during the run (for
  example `getent ahosts api.openai.com` inside the agent container). An
  address you omit makes that connection `unexplained`.
- `--known-peer ADDRESS` for Fabric's own and the infrastructure's
  connections: the Node's address on the Compose network (`NODE_IP` above),
  the DNS resolver the container uses (Docker's embedded resolver
  `127.0.0.11` on a user-defined network; see `/etc/resolv.conf` in the
  container), and the addresses of the hosts in `FABRIC_WIRE_HTTP_HOSTS` if
  you do not want those connections listed as unexplained.

A connection is never hidden by these flags: it is linked to the run
(`process_anchor`) instead of listed under `unexplained host events`.
[Action reconstruction](action-reconstruction.md#read-a-run-python--m-fabricreconstruct-actions)
explains every row and verdict, including processes that made no model call
and the non-model HTTP rows.

## Docker Desktop

Docker Desktop (macOS) runs containers in a Linux VM, so the recipe works
with these differences:

- **Shell.** The commands are bash. Run them in `bash`; macOS's default
  `zsh` treats the trailing `# ...` comments as arguments unless you run
  `setopt interactivecomments` first.
- **Only containers are observed.** The emitter sees the VM's kernel: run
  the agent in a container; processes on macOS itself are invisible. The
  VM's kernel has BTF.
- **cgroup driver.** Docker Desktop uses `cgroupfs`. Create the agent root,
  and the sandbox root when the agent starts containers, inside the VM:
  `docker run --rm --privileged --cgroupns=host -v
  /sys/fs/cgroup:/sys/fs/cgroup alpine mkdir -p /sys/fs/cgroup/fabric-agents
  /sys/fs/cgroup/fabric-sandboxes`. Remove them when done (`rmdir` the same
  way, after their containers are gone).
- **Emitter directories.** `/etc` and `/var/lib` on macOS are not shared
  into the VM. Keep the emitter's files in a directory Docker Desktop shares
  (your home directory by default), without `sudo`; the `docker run` of
  step 4 is then unchanged:

  ```bash
  EMIT_ETC="$M/host-emitter/etc" EMIT_VAR="$M/host-emitter/state"
  install -d -m 0700 "$EMIT_VAR" "$EMIT_ETC"
  install -m 0400 "$M/secrets/id.key"        "$EMIT_ETC/id.key"
  install -m 0400 "$M/secrets/ebpf-state.key" "$EMIT_ETC/state.key"
  install -m 0400 "$M/secrets/ebpf.token"    "$EMIT_ETC/token"
  install -m 0444 "$M/tls/ca.crt"            "$EMIT_ETC/ca.crt"
  ```

- **File ownership.** Bind-mounted files appear owned by the container's
  user, so the image's uid 65532 reads any file you can read: no group 65532
  (and no `sudo chgrp`) is needed. `preflight-prod.sh` detects Docker Desktop
  (`docker info`) and checks that each secret is readable by you and closed
  to others; `FABRIC_BIND_MOUNT_OWNERSHIP=mapped` or `native` overrides the
  detection.
- **Spool.** A bind mount from macOS has slow `fsync` and does not enforce
  file locks: keep the agent's spool on a named volume, as in step 5.
- **Host services** (a model server on macOS) are `host.docker.internal`
  from the containers; list that address with `--endpoint-peer` or
  `--known-peer` as the agent saw it.
- **Clock steps.** When the Mac sleeps, the VM's clock falls behind and
  Docker Desktop steps it forward on wake. Before 0.11.2 the emitter kept
  its start-time offset and stamped events seconds early. It now follows
  the step within one batch, logs `CLOCK_REALTIME step detected step_ms=…`,
  and declares a wider clock uncertainty for that source (2 ms plus the
  step). Once the offset has been stable for 60 s (`EMIT_CLOCK_SETTLE`) it
  declares the 2 ms base again for later records. Docker Desktop's routine
  8–10 ms resyncs are below the 20 ms step threshold (`EMIT_CLOCK_STEP_MIN`):
  followed, counted as `clock_small_steps=`, never widening anything. A
  reading that a second sample at once does not confirm is counted as
  `clock_rejected_samples=` and also widens nothing. The reader gives each
  host record the margin of the manifest in force for it, so only the host
  links of records stamped around the step and during the settle window
  carry a margin of the step's size; the rest of the export keeps 2 ms.
  Check `docker logs fabric-host-emitter` after a sleep.
- **Clock margin.** Each agent process declares
  `FABRIC_CLOCK_UNCERTAINTY_MS` (default 1000) in its manifest. It widens
  comparisons across processes and hosts (an exchange of another epoch, a
  host sensor's event against the run window), not the tool-call windows
  inside one process, whose wire and exec records share one clock
  (0.11.2). Here the agent and the emitter read the same VM clock, so a
  smaller value (for example `FABRIC_CLOCK_UNCERTAINTY_MS=50` in
  `agent.env`) keeps host links from turning ambiguous.
