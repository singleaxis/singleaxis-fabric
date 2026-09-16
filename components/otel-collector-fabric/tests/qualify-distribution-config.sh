#!/usr/bin/env bash
# Prove that a built Fabric Collector artifact accepts the regulated
# distribution configuration. This is a configuration-compatibility test,
# not a live OTLP delivery test.

set -euo pipefail

readonly prefix="[collector-config]"
mode=""
artifact=""
runtime=""
container_name=""
collector_pid=""

fail() {
  printf '%s FAIL: %s\n' "${prefix}" "$*" >&2
  exit 1
}

usage() {
  printf 'usage: %s (--binary PATH | --image IMAGE)\n' "$0" >&2
  exit 2
}

cleanup() {
  if [[ -n "${container_name}" ]]; then
    docker rm -f "${container_name}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${collector_pid}" ]] && kill -0 "${collector_pid}" 2>/dev/null; then
    kill -TERM "${collector_pid}" >/dev/null 2>&1 || true
    wait "${collector_pid}" 2>/dev/null || true
  fi
  if [[ -n "${runtime}" && -d "${runtime}" ]]; then
    rm -rf -- "${runtime}"
  fi
}

on_exit() {
  local status=$?
  trap - EXIT INT TERM
  cleanup
  exit "${status}"
}

trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

case "${1:-}" in
  --binary|--image)
    [[ $# -eq 2 ]] || usage
    mode="${1#--}"
    artifact="$2"
    ;;
  *) usage ;;
esac

command -v openssl >/dev/null 2>&1 || fail "openssl is required"
if [[ "${mode}" == "image" ]]; then
  command -v docker >/dev/null 2>&1 || fail "docker is required for --image"
  docker image inspect "${artifact}" >/dev/null 2>&1 || fail "image not found: ${artifact}"
else
  [[ -x "${artifact}" ]] || fail "collector binary is not executable: ${artifact}"
fi

runtime="$(mktemp -d "${TMPDIR:-/tmp}/fabric-collector-config.XXXXXX")"
chmod 0755 "${runtime}"
mkdir -m 0755 "${runtime}/queue"

# Generate a throwaway CA and server identity. Nothing under this temporary
# directory is committed or reused. The receiver config requires the CA as
# `client_ca_file`, which enables client-certificate verification (mTLS).
openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout "${runtime}/ca.key" -out "${runtime}/ca.crt" -days 1 \
  -subj "/CN=fabric-config-test-ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout "${runtime}/server.key" -out "${runtime}/server.csr" \
  -subj "/CN=localhost" >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' \
  >"${runtime}/server.ext"
openssl x509 -req -sha256 -days 1 \
  -in "${runtime}/server.csr" \
  -CA "${runtime}/ca.crt" -CAkey "${runtime}/ca.key" -CAcreateserial \
  -extfile "${runtime}/server.ext" -out "${runtime}/server.crt" \
  >/dev/null 2>&1
rm -f -- "${runtime}/ca.key" "${runtime}/ca.srl" \
  "${runtime}/server.csr" "${runtime}/server.ext"

# The distroless image runs as nonroot. Certificate material is ephemeral and
# read-only from the Collector's perspective; make it readable by that UID.
chmod 0644 "${runtime}/ca.crt" "${runtime}/server.crt" "${runtime}/server.key"

if [[ "${mode}" == "image" ]]; then
  config_root="/fabric-config-test"
else
  config_root="${runtime}"
fi

cat >"${runtime}/config.yaml" <<EOF
extensions:
  health_check:
    endpoint: 127.0.0.1:13133
  file_storage/fabric:
    directory: ${config_root}/queue
    create_directory: true
    fsync: true

receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
        max_recv_msg_size_mib: 8
        max_concurrent_streams: 64
        keepalive:
          enforcement_policy:
            min_time: 10s
            permit_without_stream: false
        tls:
          cert_file: ${config_root}/server.crt
          key_file: ${config_root}/server.key
          client_ca_file: ${config_root}/ca.crt
      http:
        endpoint: 127.0.0.1:4318
        read_header_timeout: 5s
        read_timeout: 30s
        idle_timeout: 120s
        max_request_body_size: 8388608
        tls:
          cert_file: ${config_root}/server.crt
          key_file: ${config_root}/server.key
          client_ca_file: ${config_root}/ca.crt

processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 128
  fabricguard:
    event_class_attribute: event_class
    drop_unknown_classes: true
    max_field_bytes: 8192

exporters:
  otlp_http/fabric:
    # Loopback port 1 is deliberately unreachable. No telemetry is emitted,
    # so the test never contacts an exporter; it only starts the pipeline.
    endpoint: https://127.0.0.1:1
    tls:
      insecure: false
      insecure_skip_verify: false
      ca_file: ${config_root}/ca.crt
    sending_queue:
      enabled: true
      queue_size: 32
      block_on_overflow: true
      storage: file_storage/fabric
    retry_on_failure:
      enabled: true
      max_elapsed_time: 0s

service:
  extensions: [health_check, file_storage/fabric]
  telemetry:
    logs:
      level: error
  pipelines:
    logs:
      receivers: [otlp]
      processors: [memory_limiter, fabricguard]
      exporters: [otlp_http/fabric]
    traces:
      receivers: [otlp]
      processors: [memory_limiter, fabricguard]
      exporters: [otlp_http/fabric]
EOF
chmod 0644 "${runtime}/config.yaml"

# These assertions keep future edits from accidentally weakening what the
# runtime-start check is meant to qualify. The process start below proves the
# named component types and fields are recognized by the built artifact.
[[ "$(grep -c 'cert_file:' "${runtime}/config.yaml")" -eq 2 ]] \
  || fail "both OTLP receivers must declare cert_file"
[[ "$(grep -c 'key_file:' "${runtime}/config.yaml")" -eq 2 ]] \
  || fail "both OTLP receivers must declare key_file"
[[ "$(grep -c 'client_ca_file:' "${runtime}/config.yaml")" -eq 2 ]] \
  || fail "both OTLP receivers must require client certificates"
grep -q 'max_recv_msg_size_mib: 8' "${runtime}/config.yaml" \
  || fail "gRPC receiver must cap messages at 8 MiB"
grep -q 'max_concurrent_streams: 64' "${runtime}/config.yaml" \
  || fail "gRPC receiver must cap concurrent streams"
grep -q 'min_time: 10s' "${runtime}/config.yaml" \
  || fail "gRPC receiver must enforce keepalive spacing"
grep -q 'max_request_body_size: 8388608' "${runtime}/config.yaml" \
  || fail "HTTP receiver must cap request bodies at 8 MiB"
grep -q 'read_header_timeout: 5s' "${runtime}/config.yaml" \
  || fail "HTTP receiver must bound header reads"
grep -q 'read_timeout: 30s' "${runtime}/config.yaml" \
  || fail "HTTP receiver must bound request reads"
grep -q 'idle_timeout: 120s' "${runtime}/config.yaml" \
  || fail "HTTP receiver must bound idle connections"
grep -q '^  otlp_http/fabric:' "${runtime}/config.yaml" \
  || fail "otlp_http/fabric exporter is missing"
grep -q '^  file_storage/fabric:' "${runtime}/config.yaml" \
  || fail "file-storage extension is missing"
grep -q 'storage: file_storage/fabric' "${runtime}/config.yaml" || fail "persistent queue binding is missing"
grep -q 'block_on_overflow: true' "${runtime}/config.yaml" \
  || fail "exporter must apply backpressure via block_on_overflow (default false drops records)"
if grep -n 'batch' "${runtime}/config.yaml" >/dev/null; then
  fail "qualified config must not contain a volatile pre-queue batch processor"
fi
# The guard only processes logs and traces. A qualified config must not
# define metrics or profiles pipelines, which would bypass the allowlist.
pipeline_names="$(awk '
    /^  pipelines:/ { inblock=1; next }
    inblock && /^  [^ ]/ { inblock=0 }
    inblock && /^    [a-z_]+:/ { sub(":$", "", $1); print $1 }
  ' "${runtime}/config.yaml" | sort)"
[[ "${pipeline_names}" == "$(printf 'logs\ntraces')" ]] \
  || fail "qualified config must define only logs and traces pipelines, got: ${pipeline_names}"
# shellcheck disable=SC2043 # Kept as a loop-shaped inventory assertion.
for processor in fabricguard; do
  count="$(grep -o "${processor}" "${runtime}/config.yaml" | wc -l | tr -d ' ')"
  [[ "${count}" -ge 3 ]] || fail "${processor} is not configured and wired into both pipelines"
done

if [[ "${mode}" == "image" ]]; then
  container_name="fabric-config-test-${RANDOM}-${RANDOM}"
  docker run -d --name "${container_name}" \
    --network none \
    --mount "type=bind,src=${runtime},dst=/fabric-config-test,readonly" \
    --tmpfs /fabric-config-test/queue:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=65532,gid=65532 \
    "${artifact}" --config=/fabric-config-test/config.yaml >/dev/null \
    || fail "failed to start image: ${artifact}"

  for _ in 1 2 3 4 5; do
    state="$(docker inspect --format '{{.State.Status}}' "${container_name}" 2>/dev/null || true)"
    [[ "${state}" == "running" ]] || {
      docker logs "${container_name}" >&2 || true
      fail "collector exited while loading qualified configuration (state=${state:-missing})"
    }
    sleep 1
  done
else
  # Binary mode still exercises the enforcement path: when dist/ carries
  # fabric-gate next to the collector, boot through it (the gate resolves
  # the sibling binary itself). A bare collector without its gate is
  # qualified but flagged — the runtime invariants are then unenforced.
  gate_bin="$(dirname "${artifact}")/fabric-gate"
  launcher="${artifact}"
  if [[ -x "${gate_bin}" ]]; then
    launcher="${gate_bin}"
  else
    printf '%s WARN: %s not found; qualifying the bare collector without entrypoint enforcement\n' \
      "${prefix}" "${gate_bin}" >&2
  fi
  "${launcher}" --config="${runtime}/config.yaml" >"${runtime}/collector.log" 2>&1 &
  collector_pid="$!"
  for _ in 1 2 3 4 5; do
    if ! kill -0 "${collector_pid}" 2>/dev/null; then
      cat "${runtime}/collector.log" >&2 || true
      fail "collector exited while loading qualified configuration"
    fi
    sleep 1
  done
fi

for prohibited in fabricredact fabricpolicy fabricsampler; do
  if grep -q "${prohibited}" "${runtime}/config.yaml"; then
    fail "recorder config unexpectedly contains ${prohibited}"
  fi
done

# The shipped image's fabric-gate entrypoint must refuse configurations the
# recorder cannot protect: non-traces/logs pipelines bypass fabricguard, and
# a newline-terminated token file mints an empty "Bearer " credential under
# the pinned bearertokenauth extension. Binary mode cannot exercise this
# (the gate wraps the image, not the collector artifact).
if [[ "${mode}" == "image" ]]; then
  badcfg="${runtime}/gate-reject.yaml"
  gate_expect_refusal() {
    local name="$1" why="$2"; shift 2
    docker run -d --name "${name}" "$@" "${artifact}" \
      --config=/fabric-config-test/bad.yaml >/dev/null \
      || fail "could not start gate test container: ${name}"
    sleep 2
    local state
    state="$(docker inspect --format '{{.State.Status}}' "${name}" 2>/dev/null || true)"
    if [[ "${state}" == "running" ]]; then
      docker rm -f "${name}" >/dev/null 2>&1 || true
      fail "image booted despite ${why}; fabric-gate did not refuse"
    fi
    docker logs "${name}" 2>&1 | grep -q "fabric-gate" \
      || { docker rm -f "${name}" >/dev/null 2>&1 || true; fail "rejected ${why} produced no fabric-gate refusal message"; }
    docker rm -f "${name}" >/dev/null 2>&1 || true
  }

  sed 's|^    traces:|    metrics:\n      receivers: [otlp]\n      processors: [memory_limiter]\n      exporters: [otlp_http/fabric]\n    traces:|' \
    "${runtime}/config.yaml" >"${badcfg}"
  gate_expect_refusal "${container_name}-gate" "a metrics pipeline" \
    --network none \
    --mount "type=bind,src=${runtime},dst=/fabric-config-test,readonly"

  # Unsafe token material: same config plus a newline-terminated token file.
  printf 'tok3n\n' >"${runtime}/bad.token"
  sed 's|^extensions:|extensions:\n  bearertokenauth:\n    filename: /fabric-config-test/bad.token|' \
    "${runtime}/config.yaml" >"${badcfg}"
  gate_expect_refusal "${container_name}-token" "a trailing-newline token file" \
    --network none \
    --mount "type=bind,src=${runtime},dst=/fabric-config-test,readonly"
  printf '%s PASS: image entrypoint refused unprotected pipelines and unsafe token material\n' "${prefix}"
elif [[ -x "$(dirname "${artifact}")/fabric-gate" ]]; then
  # Binary mode: the same refusal invariants run through dist/fabric-gate,
  # which resolves the sibling collector and exits non-zero before exec.
  gate_bin="$(dirname "${artifact}")/fabric-gate"
  badcfg="${runtime}/gate-reject.yaml"
  gate_expect_refusal_bin() {
    local why="$1"
    if "${gate_bin}" --config="${badcfg}" >/dev/null 2>&1; then
      fail "fabric-gate accepted ${why}"
    fi
  }
  sed 's|^    traces:|    metrics:\n      receivers: [otlp]\n      processors: [memory_limiter]\n      exporters: [otlp_http/fabric]\n    traces:|' \
    "${runtime}/config.yaml" >"${badcfg}"
  gate_expect_refusal_bin "a metrics pipeline"
  printf 'tok3n\n' >"${runtime}/bad.token"
  sed 's|^extensions:|extensions:\n  bearertokenauth:\n    filename: '"${runtime}"'/bad.token|' \
    "${runtime}/config.yaml" >"${badcfg}"
  gate_expect_refusal_bin "a trailing-newline token file"
  printf '%s PASS: fabric-gate binary refused unprotected pipelines and unsafe token material\n' "${prefix}"
fi

printf '%s PASS: recorder artifact accepted mTLS ingress, protection, and durable OTLP/HTTP export\n' "${prefix}"
printf '%s NOTE: configuration compatibility only; no telemetry delivery was attempted\n' "${prefix}"
