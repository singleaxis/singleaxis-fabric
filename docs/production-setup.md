# Production setup: agent, Node and eBPF emitter

One recipe for the full production path on one Linux host: a Python agent in
a container, a production-profile Fabric Node with ingress groups and
content, and the eBPF host emitter in production mode, so that
`python -m fabric.reconstruct actions` can tie each command the agent ran to
the operating system's own exec event. It is derived from the AR-1
production live harness
([`qualification/action-record/ar1/live.py`](../qualification/action-record/ar1/live.py))
and the v0.11.0 user-acceptance run. [Docker Desktop](#docker-desktop) lists
what differs on macOS.

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
  OTLP/HTTP endpoint) and its bearer token. [Section 6](#6-a-destination-with-a-private-ca)
  covers a destination whose certificate comes from a private CA.
- An S3 bucket (or S3-compatible store) with server-side encryption for
  content. With ingress groups the Node stores content in S3 only; see
  [step 3](#3-the-node).

Pick names first. They appear in several places and must match:

```bash
export TENANT=acme-prod            # FABRIC_TENANT_ID on the agent and the Node
export AGENT_SRC=support-agent     # the agent's FABRIC_SOURCE_ID (clear label)
export HOST_LABEL=build-host-1     # FABRIC_HOST_LABEL = EMIT_HOST_LABEL
export EBPF_LABEL="$HOST_LABEL/ebpf"
export M="$PWD/fabric-material"    # keep it outside the repository
```

## 2. Keys, tokens and certificates

```bash
mkdir -p "$M/tls" "$M/secrets" && cd "$M" && umask 077
# A CA and the Node's server certificate. The SAN must name the address the
# agent and the emitter use: fabric-node on the Compose network, and
# localhost for checks from the host.
openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes -keyout ca.key \
  -out tls/ca.crt -subj "/CN=fabric-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey rsa:3072 -sha256 -nodes -keyout tls/server.key -out server.csr \
  -subj "/CN=fabric-node"
printf 'subjectAltName=DNS:fabric-node,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > server.ext
openssl x509 -req -in server.csr -CA tls/ca.crt -CAkey ca.key -CAcreateserial \
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
and the certificates readable:

```bash
sudo chgrp 65532 secrets/agent.token secrets/ebpf.token secrets/content.key tls/server.key
chmod 0440 secrets/agent.token secrets/ebpf.token secrets/content.key tls/server.key
chmod 0444 tls/ca.crt tls/server.crt
chmod 0400 secrets/spool.key secrets/id.key secrets/ebpf-state.key
```

The capture policy (`deployment-policy/v1`, all ten keys required) names the
roles to keep. This one keeps model exchanges, subprocess arguments and
output, and non-model HTTP bodies:

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
    "terminal.argv": "retain_original",
    "terminal.context": "retain_original",
    "terminal.stdout": "retain_original",
    "terminal.stderr": "retain_original",
    "record.evidence": "retain_original",
    "network.request": "retain_original",
    "network.response": "retain_original"
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
`terminal.argv` and `terminal.stdout` often hold secrets.

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

`deploy/compose/.env` (mode 0600):

```bash
FABRIC_NODE_IMAGE=ghcr.io/singleaxis/fabric-otelcol:<version>
FABRIC_NODE_PULL_POLICY=always
FABRIC_EXPORT_ENDPOINT=https://otlp.example.com:443
FABRIC_EXPORT_AUTH_HEADER=Bearer <destination token>
FABRIC_TENANT_ID=acme-prod
FABRIC_AGENT_SOURCE_ID=<AGENT_S>
FABRIC_INGRESS_TOKEN_FILE=/abs/path/fabric-material/secrets/agent.token
FABRIC_EBPF_SOURCE_ID=<EBPF_S>
FABRIC_EBPF_TOKEN_FILE=/abs/path/fabric-material/secrets/ebpf.token
FABRIC_INGRESS_TLS_DIR=/abs/path/fabric-material/tls
FABRIC_CONTENT_BACKEND=s3
FABRIC_CONTENT_KEY_FILE=/abs/path/fabric-material/secrets/content.key
FABRIC_CONTENT_S3_BUCKET=<bucket>
FABRIC_CONTENT_S3_REGION=<region>
# An S3-compatible store: FABRIC_CONTENT_S3_ENDPOINT, FABRIC_CONTENT_S3_PATH_STYLE=true
# and FABRIC_CONTENT_S3_SSE=AES256 (SSE-S3) when it has no KMS.
```

Then, from `deploy/compose`:

```bash
make up-prod-groups        # runs preflight-prod.sh --groups first; refuses on any FAIL
```

Content with ingress groups is S3 only. `FABRIC_CONTENT_BACKEND=file` is
refused by preflight, and since v0.11.1 also by the Node at startup
(`fabric-gate`), so it can no longer run telemetry-only by surprise when
preflight was bypassed. S3 credentials come from the AWS default chain of the
Node's container ([deployment](deployment.md#production-profile)); never put
keys in `.env`. The Node listens for the agent group on 4317/4318 (telemetry)
and 4319 (content), and for the ebpf group on 4417, all with TLS and each
group's own token, published on `127.0.0.1` unless you set
`FABRIC_BIND_ADDR`. Containers on the Compose network
`fabric-node-local_fabric-node` reach it as `fabric-node`.

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
agent starts itself go under a second parent, set as
`EMIT_SANDBOX_CGROUP_ROOTS`, if you want them linked by rule H5.

```bash
sudo install -d -m 0700 -o root /var/lib/fabric-host-emitter
sudo install -d -m 0700 -o root /etc/fabric-host-emitter
sudo install -m 0400 -o root "$M/secrets/id.key"        /etc/fabric-host-emitter/id.key
sudo install -m 0400 -o root "$M/secrets/ebpf-state.key" /etc/fabric-host-emitter/state.key
sudo install -m 0400 -o root "$M/secrets/ebpf.token"    /etc/fabric-host-emitter/token
sudo install -m 0444 -o root "$M/tls/ca.crt"            /etc/fabric-host-emitter/ca.crt

docker run -d --name fabric-host-emitter --restart unless-stopped \
  --user 0 --read-only --pid=host --cgroupns=host \
  --cap-drop=ALL --cap-add=BPF --cap-add=PERFMON \
  --cap-add=SYS_RESOURCE --cap-add=DAC_READ_SEARCH \
  --security-opt no-new-privileges \
  --network fabric-node-local_fabric-node \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /etc/fabric-host-emitter:/etc/fabric-host-emitter:ro \
  -v /var/lib/fabric-host-emitter:/var/lib/fabric-host-emitter \
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
cat > "$M/agent.env" <<EOF
FABRIC_WIRE_AUTOLOAD=1
PYTHONPATH=<output of: python -m fabric.wire --print-autoload-path, in the agent image>
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
  --network fabric-node-local_fabric-node --env-file "$M/agent.env" \
  -v "$M/tls/ca.crt:/fabric/ca.crt:ro" -v "$M/secrets/spool.key:/fabric/spool.key:ro" \
  -v "$M/policy.json:/fabric/policy.json:ro" \
  -v fabric-agent-spool:/var/lib/fabric-agent \
  <your agent image> python agent.py
```

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

## 6. A destination with a private CA

When the destination's certificate comes from your own CA (a local test
collector, an internal gateway), the Node must trust that CA for its export.
Do it with an override in your own directory, never by editing the shipped
`collector-config/*.yaml`:

```bash
cp ~/my-ca.crt "$M/tls/export-ca.crt" && chmod 0444 "$M/tls/export-ca.crt"
mkdir -p ~/fabric-site && cat > ~/fabric-site/export-ca.yaml <<'EOF'
exporters:
  otlp_http/fabric:
    tls:
      ca_file: /run/fabric-node/tls/export-ca.crt
EOF
cat > ~/fabric-site/compose.export-ca.yml <<'EOF'
services:
  fabric-node:
    command:
      - --config=/etc/fabric-node/collector-production-groups.yaml
      - --config=/etc/fabric-node/collector-production-groups-content.yaml
      - --config=/etc/fabric-node/site-export-ca.yaml
    volumes:
      - ${HOME}/fabric-site/export-ca.yaml:/etc/fabric-node/site-export-ca.yaml:ro
EOF
echo "FABRIC_COMPOSE_EXTRA=$HOME/fabric-site/compose.export-ca.yml" >> deploy/compose/.env
make -C deploy/compose up-prod-groups
```

`FABRIC_COMPOSE_EXTRA` (space-separated Compose files) is appended last to
the files `make up-prod`/`up-prod-groups` use, so the override's `command`
replaces the shipped list: keep every `--config` of your profile in it (here
groups plus S3 content; without content, only the first line). The CA file
must be inside `FABRIC_INGRESS_TLS_DIR`, which is mounted at
`/run/fabric-node/tls`. Preflight does not read your override, so it neither
checks that file nor needs `FABRIC_EXPORT_CA_FILE`. The destination's
certificate must name the host in `FABRIC_EXPORT_ENDPOINT`, and the Node's
container must resolve it (a destination container on the
`fabric-node-local_fabric-node` network, or an `extra_hosts` entry in the
same override). The local trial's controlled sink (`make up`) is plain HTTP
and is refused in production.

## 7. Read a run

Copy the destination's export (OTLP protobuf or JSON span files), then:

```bash
export FABRIC_WIRE_ID_KEY="$(cat "$M/secrets/id.key")"
python -m fabric.reconstruct actions export/ \
  --store-uri s3://<bucket>/fabric/content/ --tenant "$TENANT" \
  --content-key-file "$M/secrets/content.key" \
  --id-key-env FABRIC_WIRE_ID_KEY --trusted-source --profile production \
  --host-source "host.ebpf=$EBPF_S" \
  --endpoint-peer openai.default=<each address api.openai.com resolved to> \
  --known-peer <the Node's address> --known-peer 127.0.0.11
```

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
  connections: the Node's address on the Compose network
  (`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'`
  on the Node container), the DNS resolver the container uses (Docker's
  embedded resolver `127.0.0.11` on a user-defined network; see
  `/etc/resolv.conf` in the container), and the addresses of the hosts in
  `FABRIC_WIRE_HTTP_HOSTS` if you do not want those connections listed as
  unexplained.

A connection is never hidden by these flags: it is linked to the run
(`process_anchor`) instead of listed under `unexplained host events`.
[Action reconstruction](action-reconstruction.md#read-a-run-python--m-fabricreconstruct-actions)
explains every row and verdict, including processes that made no model call
and the non-model HTTP rows.

## Docker Desktop

Docker Desktop (macOS) runs containers in a Linux VM, so the recipe works
with these differences:

- **Only containers are observed.** The emitter sees the VM's kernel: run
  the agent in a container; processes on macOS itself are invisible. The
  VM's kernel has BTF.
- **cgroup driver.** Docker Desktop uses `cgroupfs`. Create the agent root
  inside the VM: `docker run --rm --privileged --cgroupns=host -v
  /sys/fs/cgroup:/sys/fs/cgroup alpine mkdir -p /sys/fs/cgroup/fabric-agents`.
  Remove it when done (`rmdir` the same way).
- **Emitter directories.** `/etc/fabric-host-emitter` and
  `/var/lib/fabric-host-emitter` are macOS paths shared into the VM: keep
  them under your home directory instead of using `sudo install`, mode 0700
  for the directories and 0400 for the files.
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
