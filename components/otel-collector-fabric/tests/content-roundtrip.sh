#!/usr/bin/env bash
# Live spec 043 content-path check against a built Fabric Node image: post
# content log records (OTLP/HTTP JSON) to otlp/content and assert that the
# fabriccontent file backend stored the exact body and the SDK-compatible
# descriptor, refused a digest-mismatched record with a content-free log
# line, and accepted an identical replay. Loopback, plain HTTP, throwaway
# container; no credentials are involved.

set -euo pipefail

readonly prefix="[content-roundtrip]"
image=""
container=""
runtime=""

fail() {
  printf '%s FAIL: %s\n' "${prefix}" "$*" >&2
  if [[ -n "${container}" ]]; then
    docker logs "${container}" >&2 2>&1 | tail -40 >&2 || true
  fi
  exit 1
}

cleanup() {
  if [[ -n "${container}" ]]; then
    docker rm -f "${container}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${runtime}" && -d "${runtime}" ]]; then
    rm -rf -- "${runtime}"
  fi
}
trap cleanup EXIT

[[ "${1:-}" == "--image" && $# -eq 2 ]] || {
  printf 'usage: %s --image IMAGE\n' "$0" >&2
  exit 2
}
image="$2"
command -v docker >/dev/null 2>&1 || fail "docker is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v curl >/dev/null 2>&1 || fail "curl is required"
docker image inspect "${image}" >/dev/null 2>&1 || fail "image not found: ${image}"

runtime="$(mktemp -d "${TMPDIR:-/tmp}/fabric-content-roundtrip.XXXXXX")"
chmod 0755 "${runtime}"

cat >"${runtime}/config.yaml" <<'EOF'
extensions:
  file_storage/fabric_content:
    directory: /var/lib/fabric-node/content-queue
    create_directory: true
    fsync: true
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
  otlp/content:
    protocols:
      http:
        endpoint: 0.0.0.0:4319
        max_request_body_size: 67108864
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 256
  fabricguard:
    event_class_attribute: event_class
    drop_unknown_classes: true
exporters:
  debug:
    verbosity: basic
  fabriccontent:
    allowed_tenants: [tenant-a]
    backend: file
    file:
      directory: /var/lib/fabric-node/content
    sending_queue:
      enabled: true
      queue_size: 8
      num_consumers: 1
      block_on_overflow: true
      storage: file_storage/fabric_content
    retry_on_failure:
      enabled: true
      max_elapsed_time: 0s
service:
  extensions: [file_storage/fabric_content]
  telemetry:
    logs:
      level: info
  pipelines:
    logs:
      receivers: [otlp]
      processors: [memory_limiter, fabricguard]
      exporters: [debug]
    logs/content:
      receivers: [otlp/content]
      processors: [memory_limiter]
      exporters: [fabriccontent]
EOF
chmod 0644 "${runtime}/config.yaml"

container="fabric-content-roundtrip-${RANDOM}-${RANDOM}"
docker run -d --name "${container}" \
  --mount "type=bind,src=${runtime},dst=/fabric-config-test,readonly" \
  -p 127.0.0.1::4319 \
  "${image}" --config=/fabric-config-test/config.yaml >/dev/null \
  || fail "failed to start ${image}"

port=""
for _ in $(seq 1 30); do
  port="$(docker port "${container}" 4319/tcp 2>/dev/null | head -1 | sed -E 's/.*:([0-9]+)$/\1/')" || true
  if [[ -n "${port}" ]] && curl -s -o /dev/null "http://127.0.0.1:${port}/v1/logs"; then
    break
  fi
  sleep 1
done
[[ -n "${port}" ]] || fail "content port was not published"

# Build the payloads and the expected descriptor bytes (Python json.dumps
# with sort_keys, exactly what fabric.reconstruct reads).
python3 - "${runtime}" <<'PY'
import base64, hashlib, json, sys
out = sys.argv[1]
body = b'{"model":"gpt-4o","messages":[{"role":"user","content":"caf\xc3\xa9 & <ok>"}]}'
digest = "sha256:" + hashlib.sha256(body).hexdigest()
oid = "0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a01"
attrs = {
    "event_class": "content", "schema_version": "fabric.content-object/v2",
    "object_id": oid, "tenant_id": "tenant-a", "role": "model.exchange.request",
    "media_type": "application/json", "content_encoding": "identity",
    "representation": "exact", "transformations": [], "provenance": "protocol",
    "boundary": "provider_bound", "status": "stored",
    "stored_byte_length": len(body), "stored_sha256": digest,
    "source_byte_length": len(body), "source_sha256": digest,
    "source_id": "wire-3f9a1c2b7d4e5f60", "source_epoch": 1791331200000000000,
    "source_sequence": 1, "run_id": "r-5f0c9a3e1b7d4c2a8e6f0b1d3c5a7e9f",
    "operation_id": "6f1d2c3e-8a4b-4c5d-9e6f-0a1b2c3d4e5f",
    "captured_at": "2026-10-07T00:00:01.120000+00:00",
}

def value(v):
    if isinstance(v, bool):
        raise TypeError
    if isinstance(v, int):
        return {"intValue": str(v)}
    if isinstance(v, list):
        return {"arrayValue": {"values": [{"stringValue": x} for x in v]}}
    return {"stringValue": v}

def payload(record_attrs, record_body):
    return {"resourceLogs": [{
        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "agent"}}]},
        "scopeLogs": [{"scope": {"name": "fabric.wire"}, "logRecords": [{
            "timeUnixNano": "1791331201120000000",
            "body": {"bytesValue": base64.b64encode(record_body).decode()},
            "attributes": [{"key": k, "value": value(v)} for k, v in record_attrs.items()],
        }]}],
    }]}

with open(f"{out}/good.json", "w") as f:
    json.dump(payload(attrs, body), f)
tampered = dict(attrs, object_id="0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a03")
with open(f"{out}/tampered.json", "w") as f:
    json.dump(payload(tampered, body + b" "), f)
with open(f"{out}/expected-body", "wb") as f:
    f.write(body)
descriptor = {k: v for k, v in attrs.items() if k != "event_class"}
descriptor["encoding"] = "binary"
descriptor["ref"] = f"file:///var/lib/fabric-node/content/tenant-a/evidence/{oid}"
with open(f"{out}/expected-descriptor", "wb") as f:
    f.write((json.dumps(descriptor, ensure_ascii=False, sort_keys=True) + "\n").encode())
PY

post() {
  local status
  status="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' --data-binary "@$1" \
    "http://127.0.0.1:${port}/v1/logs")"
  [[ "${status}" == "200" ]] || fail "POST $(basename "$1") returned ${status}"
}
post "${runtime}/good.json"
post "${runtime}/tampered.json"
post "${runtime}/good.json" # identical replay

oid="0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a01"
evidence="/var/lib/fabric-node/content/tenant-a/evidence"
mkdir "${runtime}/out"
for _ in $(seq 1 20); do
  if docker cp "${container}:${evidence}/meta/${oid}.json" "${runtime}/out/descriptor" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
[[ -f "${runtime}/out/descriptor" ]] || fail "descriptor was not written"
docker cp "${container}:${evidence}/${oid}" "${runtime}/out/body" >/dev/null \
  || fail "body was not written"
cmp -s "${runtime}/out/body" "${runtime}/expected-body" || fail "stored body differs from the posted bytes"
cmp -s "${runtime}/out/descriptor" "${runtime}/expected-descriptor" \
  || fail "stored descriptor differs from the SDK descriptor bytes"
if docker cp "${container}:${evidence}/0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a03" "${runtime}/out/tampered" >/dev/null 2>&1; then
  fail "digest-mismatched record was stored"
fi

logs="$(docker logs "${container}" 2>&1)"
grep -qF 'fabriccontent: dropped content record' <<<"${logs}" || fail "no drop log line for the tampered record"
grep -qF 'digest_mismatch' <<<"${logs}" || fail "drop log line does not name digest_mismatch"
for secret in tenant-a 0b8e1c52 gpt-4o r-5f0c9a3e1b7d4c2a8e6f0b1d3c5a7e9f; do
  if grep -qF -- "${secret}" <<<"${logs}"; then
    fail "collector logs contain ${secret}"
  fi
done
[[ "$(grep -cF 'fabriccontent: dropped content record' <<<"${logs}")" -eq 1 ]] \
  || fail "identical replay was refused"

printf '%s PASS: Node stored the exact body and SDK descriptor, refused a digest mismatch, accepted a replay\n' "${prefix}"
