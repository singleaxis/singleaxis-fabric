#!/usr/bin/env bash
# Qualify the auditd sensor collector through its ingress group, end to end
# (spec 053 §6.2.8; spec 056 §7.3.3 (h)), on Linux with Docker:
#
#   sensor collector (docker-compose.sensor-auditd.yml, collector-config/
#   sensor-auditd.yaml, receiver in logfile mode on the checked-in
#   fixtures/sensor-auditd/audit.log; no kernel audit needed)
#     -> OTLP/HTTP + TLS + the auditd group's token
#     -> Fabric Node with ingress groups (make up-prod-groups: agent, ebpf and
#        auditd groups; preflight-prod.sh --groups first)
#     -> fabricguard/auditd (source_kind host.auditd)
#     -> the controlled TLS test sink
#
# and asserts that the sink holds authenticated host.auditd records, a capture
# manifest and periodic heartbeats of the expected source (s- + the pseudonym
# of the sensor's source label under the id key), nothing of another source,
# and none of the fixture's canaries (executable, comm, argv, cwd, path, peer
# address) and no token or key.
#
# Every credential is a throwaway generated here; nothing is printed but
# counts and fixed text. FABRIC_NODE_IMAGE reuses a built Node image (else it
# is built from components/otel-collector-fabric). Exit 0 only when every
# assertion holds. Run by WP6-10's production-auditd CI job.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"
compose="${COMPOSE:-docker compose}"
timeout_s="${QUALIFY_TIMEOUT_SECONDS:-180}"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
note() { printf '==> %s\n' "$*"; }

command -v docker >/dev/null 2>&1 || fail "docker is required"
command -v openssl >/dev/null 2>&1 || fail "openssl is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
[[ "$(uname -s)" == Linux ]] || printf 'WARN: qualified on Linux; bind-mount ownership may differ here\n' >&2

work="$(mktemp -d "${TMPDIR:-/tmp}/fabric-qualify-sensor.XXXXXX")"
project="fabric-qualify-sensor-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
files=(
  -f "${here}/docker-compose.yml"
  -f "${here}/docker-compose.production.yml"
  -f "${here}/docker-compose.host-ingress.yml"
  -f "${here}/docker-compose.host-ingress-auditd.yml"
  -f "${here}/docker-compose.sensor-auditd.yml"
  -f "${work}/qualify.override.yml"
)
dc() { (cd "${here}" && ${compose} -p "${project}" --profile test-sink "${files[@]}" "$@"); }
cleanup() {
  status=$?
  if [[ "${status}" -ne 0 && -f "${work}/qualify.override.yml" ]]; then
    printf -- '--- container logs (tail) ---\n' >&2
    dc logs --no-color --tail 60 fabric-node fabric-sensor-auditd 2>&1 | tail -n 120 >&2 || true
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  chmod -R u+rwX "${work}" 2>/dev/null || true
  rm -rf -- "${work}"
  exit "${status}"
}
trap cleanup EXIT

# --- throwaway credentials -------------------------------------------------------
note "generating the TLS chain, group tokens, id key and state key"
mkdir -m 0700 "${work}/tls" "${work}/secrets" "${work}/audit" "${work}/sensor-state" "${work}/sink-tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=fabric-qualify-ca" \
  -keyout "${work}/ca.key" -out "${work}/tls/ca.crt" >/dev/null 2>&1
for name in server sink; do
  openssl req -newkey rsa:2048 -nodes -subj "/CN=fabric-${name}" \
    -keyout "${work}/${name}.key" -out "${work}/${name}.csr" >/dev/null 2>&1
  printf 'subjectAltName=DNS:fabric-node,DNS:test-sink,DNS:localhost,IP:127.0.0.1\n' >"${work}/san.ext"
  openssl x509 -req -in "${work}/${name}.csr" -CA "${work}/tls/ca.crt" -CAkey "${work}/ca.key" \
    -CAcreateserial -days 2 -extfile "${work}/san.ext" -out "${work}/${name}.crt" >/dev/null 2>&1
done
cp "${work}/server.crt" "${work}/tls/server.crt"
cp "${work}/server.key" "${work}/tls/server.key"
cp "${work}/sink.crt" "${work}/sink.key" "${work}/sink-tls/"
cp "${work}/tls/ca.crt" "${work}/secrets/ca.crt"
random_token() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }
for name in agent ebpf auditd; do
  printf '%s' "$(random_token)" >"${work}/secrets/${name}.token"
done
printf '%s' "$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')" >"${work}/secrets/id_key"
openssl rand -base64 32 | tr -d '\n' >"${work}/secrets/state_key"
cp "${here}/fixtures/sensor-auditd/audit.log" "${work}/audit/audit.log"

# The Node runs as the image's user 65532 in this user's group (its queue
# volume is the image's); its files are 0440 for the group. The sensor runs as
# this user, which owns its 0700 state directory and its 0400 files.
gid="$(id -g)"
chmod 0440 "${work}/secrets/agent.token" "${work}/secrets/ebpf.token" "${work}/secrets/auditd.token" \
  "${work}/tls/server.key"
chmod 0444 "${work}/tls/server.crt" "${work}/tls/ca.crt" "${work}/secrets/ca.crt"
chmod 0750 "${work}/tls"
chmod 0400 "${work}/secrets/id_key" "${work}/secrets/state_key"
chmod 0444 "${work}/sink-tls/sink.crt" "${work}/sink-tls/sink.key"
chmod 0755 "${work}/audit" "${work}/sink-tls"
chmod 0444 "${work}/audit/audit.log"
chmod 0711 "${work}/secrets"
chmod 0711 "${work}"
# The sensor's own token is the auditd group's; Compose mounts it separately.
cp "${work}/secrets/auditd.token" "${work}/secrets/sensor.token"
chmod 0400 "${work}/secrets/sensor.token"

# s- + the first 32 hex of HMAC-SHA256(id key, label) (run-id-pseudonym-v1).
pseudonym() {
  python3 -I -c 'import hashlib, hmac, sys
key = open(sys.argv[1], "rb").read()
print("s-" + hmac.new(key, sys.argv[2].encode(), hashlib.sha256).hexdigest()[:32])' \
    "${work}/secrets/id_key" "$1"
}
sensor_label="qualify-host/auditd"
auditd_source="$(pseudonym "${sensor_label}")"
agent_source="$(pseudonym "qualify-host/qualify-agent")"
ebpf_source="$(pseudonym "qualify-host/ebpf")"
free_port() { python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }

# --- the Compose project ----------------------------------------------------------
image="${FABRIC_NODE_IMAGE:-}"
if [[ -z "${image}" ]]; then
  image="fabric/node:qualify-sensor"
  note "building the Node image"
  docker build -q -t "${image}" "${repo}/components/otel-collector-fabric" >/dev/null
fi
# The qualification's only additions: users and secret ownership as above, the
# sink's TLS, and the CA the Node's exporter trusts (the shipped groups config
# keeps its ca_file line commented, for a public destination).
cat >"${work}/export-ca.yaml" <<'EOF'
exporters:
  otlp_http/fabric:
    tls:
      ca_file: /run/fabric-node/tls/ca.crt
EOF
chmod 0444 "${work}/export-ca.yaml"
cat >"${work}/qualify.override.yml" <<EOF
# docker-compose.production.yml drops the local trial's sink volume.
volumes:
  sink-data:
services:
  test-sink:
    environment:
      SINK_TLS_CERT_FILE: /run/sink-tls/sink.crt
      SINK_TLS_KEY_FILE: /run/sink-tls/sink.key
    volumes:
      - ${work}/sink-tls:/run/sink-tls:ro
    healthcheck:
      test: ["CMD", "python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8080), 2)"]
  fabric-node:
    pull_policy: never
    user: "65532:${gid}"
    command:
      - --config=/etc/fabric-node/collector-production-groups.yaml
      - --config=/etc/fabric-node/collector-production-groups-auditd.yaml
      - --config=/etc/fabric-node/qualify-export-ca.yaml
    volumes:
      - ${work}/export-ca.yaml:/etc/fabric-node/qualify-export-ca.yaml:ro
    depends_on:
      test-sink:
        condition: service_healthy
  fabric-sensor-auditd:
    pull_policy: never
    user: "$(id -u):${gid}"
    depends_on:
      fabric-node:
        condition: service_started
EOF

export FABRIC_NODE_IMAGE="${image}" FABRIC_NODE_PULL_POLICY=never
export FABRIC_EXPORT_ENDPOINT="https://test-sink:8080"
export FABRIC_EXPORT_AUTH_HEADER="Bearer fabric-qualify-egress-not-a-secret"
export FABRIC_TENANT_ID="qualify-tenant"
export FABRIC_SOURCE_ID="${agent_source}" FABRIC_AGENT_SOURCE_ID="${agent_source}"
export FABRIC_EBPF_SOURCE_ID="${ebpf_source}" FABRIC_AUDITD_SOURCE_ID="${auditd_source}"
export FABRIC_INGRESS_TOKEN_FILE="${work}/secrets/agent.token"
export FABRIC_EBPF_TOKEN_FILE="${work}/secrets/ebpf.token"
export FABRIC_AUDITD_TOKEN_FILE="${work}/secrets/auditd.token"
export FABRIC_INGRESS_TLS_DIR="${work}/tls"
export FABRIC_BIND_ADDR=127.0.0.1
FABRIC_OTLP_GRPC_PORT="$(free_port)"; FABRIC_OTLP_HTTP_PORT="$(free_port)"
FABRIC_EBPF_GRPC_PORT="$(free_port)"; FABRIC_AUDITD_HTTP_PORT="$(free_port)"
FABRIC_HEALTH_PORT="$(free_port)"; FABRIC_METRICS_PORT="$(free_port)"; FABRIC_SINK_PORT="$(free_port)"
export FABRIC_OTLP_GRPC_PORT FABRIC_OTLP_HTTP_PORT FABRIC_EBPF_GRPC_PORT FABRIC_AUDITD_HTTP_PORT
export FABRIC_HEALTH_PORT FABRIC_METRICS_PORT FABRIC_SINK_PORT
export FABRIC_SENSOR_SOURCE_LABEL="${sensor_label}" FABRIC_SENSOR_HOST_LABEL="qualify-host"
export FABRIC_SENSOR_ENDPOINT="https://fabric-node:4428"
export FABRIC_SENSOR_TOKEN_FILE="${work}/secrets/sensor.token"
export FABRIC_SENSOR_ID_KEY_FILE="${work}/secrets/id_key"
export FABRIC_SENSOR_STATE_KEY_FILE="${work}/secrets/state_key"
export FABRIC_SENSOR_CA_FILE="${work}/secrets/ca.crt"
export FABRIC_SENSOR_AUDIT_LOG_DIR="${work}/audit"
export FABRIC_SENSOR_STATE_DIR="${work}/sensor-state"

note "preflight-prod.sh --groups"
(cd "${here}" && FABRIC_NODE_UID=65532 FABRIC_NODE_GID="${gid}" sh ./preflight-prod.sh --groups) \
  >"${work}/preflight.log" 2>&1 || { cat "${work}/preflight.log" >&2; fail "preflight refused the groups"; }

note "starting the sink, the Node (agent, ebpf, auditd groups) and the sensor collector"
dc up -d --no-build --wait --wait-timeout 120 test-sink fabric-node >/dev/null
dc up -d --no-build fabric-sensor-auditd >/dev/null

# --- readback ---------------------------------------------------------------------
cat >"${work}/readback.py" <<'EOF'
"""Decode the sink's OTLP/protobuf trace requests (stdlib only) and check them."""
import json
import sys
from pathlib import Path


def fields(buf):
    i = 0
    while i < len(buf):
        key, i = varint(buf, i)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, i = varint(buf, i)
        elif wire == 1:
            value, i = buf[i : i + 8], i + 8
        elif wire == 2:
            size, i = varint(buf, i)
            value, i = buf[i : i + size], i + size
        elif wire == 5:
            value, i = buf[i : i + 4], i + 4
        else:
            raise ValueError("unsupported wire type")
        yield number, wire, value


def varint(buf, i):
    shift = result = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def any_value(buf):
    for number, _, value in fields(buf):
        if number == 1:
            return value.decode()
        if number == 2:
            return bool(value)
        if number == 3:
            return value - (1 << 64) if value >= 1 << 63 else value
    return None


def spans(request):
    for n1, _, rs in fields(request):
        if n1 != 1:
            continue
        for n2, _, ss in fields(rs):
            if n2 != 2:
                continue
            for n3, _, span in fields(ss):
                if n3 != 2:
                    continue
                name, attrs = "", {}
                for n4, _, value in fields(span):
                    if n4 == 5:
                        name = value.decode()
                    elif n4 == 9:
                        kv = dict((n, v) for n, _, v in fields(value))
                        attrs[kv[1].decode()] = any_value(kv.get(2, b""))
                yield name, attrs


directory, source = Path(sys.argv[1]), sys.argv[2]
found = [s for f in sorted(directory.glob("traces-*.otlp")) for s in spans(f.read_bytes())]
mine = [(n, a) for n, a in found if a.get("fabric.source_id") == source]
summary = {
    "spans": len(found),
    "other_sources": len({a.get("fabric.source_id") for _, a in found} - {source}),
    "records": sum(1 for n, a in mine if n == "fabric.sensor_event"),
    "records_authenticated": sum(
        1 for n, a in mine
        if n == "fabric.sensor_event" and a.get("fabric.source.authenticated") is True
        and str(a.get("fabric.capture.point", "")).startswith("host.auditd@")
        and a.get("fabric.capture.input") == "records" and a.get("fabric.capture.source") == "observed"
    ),
    "exec_records": sum(1 for n, a in mine if n == "fabric.sensor_event" and a.get("fabric.sensor.event_class") == "exec"),
    "connect_records": sum(1 for n, a in mine if n == "fabric.sensor_event" and a.get("fabric.sensor.event_class") == "connect"),
    "manifests": sum(1 for n, a in mine if n == "fabric.capture_manifest" and a.get("fabric.source.authenticated") is True),
    "heartbeats": sum(1 for n, a in mine if n == "fabric.capture_heartbeat" and a.get("fabric.source.authenticated") is True),
}
print(json.dumps(summary, sort_keys=True))
EOF

note "waiting for host records, a manifest and heartbeats of the sensor's source"
readback="${work}/readback"
deadline=$((SECONDS + timeout_s))
summary=""
while (( SECONDS < deadline )); do
  rm -rf -- "${readback}"
  mkdir "${readback}"
  dc cp test-sink:/var/lib/fabric-test-sink/. "${readback}" >/dev/null 2>&1 || true
  summary="$(python3 -I "${work}/readback.py" "${readback}" "${auditd_source}")"
  if python3 -I -c 'import json, sys
s = json.loads(sys.argv[1])
ok = s["records"] >= 3 and s["records_authenticated"] == s["records"] and s["exec_records"] >= 2 \
    and s["connect_records"] >= 1 and s["manifests"] >= 1 and s["heartbeats"] >= 2
sys.exit(0 if ok else 1)' "${summary}"; then
    break
  fi
  sleep 3
done
printf '    sink: %s\n' "${summary}"
python3 -I -c 'import json, sys
s = json.loads(sys.argv[1])
assert s["records"] >= 3, "fewer than three host records of the auditd source"
assert s["records_authenticated"] == s["records"], "a host record is not authenticated host.auditd"
assert s["exec_records"] >= 2 and s["connect_records"] >= 1, "exec and connect records missing"
assert s["manifests"] >= 1, "no authenticated capture manifest of the auditd source"
assert s["heartbeats"] >= 2, "fewer than two authenticated heartbeats of the auditd source"
assert s["other_sources"] == 0, "the sink holds spans of another source"' "${summary}" \
  || fail "the sink does not hold the expected host.auditd evidence"

# --- protection -------------------------------------------------------------------
note "checking that no canary, token or key left the host"
canaries=(qualcanary 192.0.2.99 /opt/ "--secret-arg" cron "other-rule")
for secret in "${work}/secrets/auditd.token" "${work}/secrets/agent.token" "${work}/secrets/ebpf.token" \
  "${work}/secrets/id_key" "${work}/secrets/state_key"; do
  canaries+=("$(cat "${secret}")")
done
dc logs --no-color fabric-node fabric-sensor-auditd >"${work}/containers.log" 2>&1 || true
for canary in "${canaries[@]}"; do
  if grep -R -a -F -q -- "${canary}" "${readback}" "${work}/containers.log" "${work}/preflight.log"; then
    fail "a fixture canary or credential reached the sink or a log"
  fi
done
# The sensor's local state is sealed: no fixture text in clear.
for canary in qualcanary 192.0.2.99; do
  if grep -R -a -F -q -- "${canary}" "${work}/sensor-state"; then
    fail "the sensor state directory holds fixture text in clear"
  fi
done

printf 'PASS: auditd sensor collector -> auditd ingress group -> sink: authenticated host.auditd records, manifest and heartbeats of the expected source; no canary, token or key\n'
