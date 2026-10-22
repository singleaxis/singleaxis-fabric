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

tmp_root="${TMPDIR:-/tmp}"
# fabriccontent requires a clean absolute directory: no "//" from a TMPDIR
# with a trailing slash (macOS).
runtime="$(mktemp -d "${tmp_root%/}/fabric-collector-config.XXXXXX")"
chmod 0755 "${runtime}"
mkdir -m 0755 "${runtime}/queue" "${runtime}/content-queue" "${runtime}/content"

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
  # Spec 048 content path: the content exporter's own durable queue.
  file_storage/fabric_content:
    directory: ${config_root}/content-queue
    create_directory: true
    directory_permissions: "0700"
    fsync: true
  # Spec 048 H1: refuses every redirect on the OTLP/HTTP exporter.
  noredirect: {}

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
  # Content ingress: OTLP/HTTP only, one 64 MiB body per request, same mTLS.
  otlp/content:
    protocols:
      http:
        endpoint: 127.0.0.1:4319
        read_header_timeout: 5s
        read_timeout: 120s
        idle_timeout: 120s
        max_request_body_size: 67108864
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
    # H4: the Node counterpart of FABRIC_WIRE_MODEL_ALLOWLIST; starting the
    # artifact proves the built processor recognizes the field.
    capture_model_allowlist: [acme-chat-v1, "acme-*"]

exporters:
  otlp_http/fabric:
    # Loopback port 1 is deliberately unreachable. No telemetry is emitted,
    # so the test never contacts an exporter; it only starts the pipeline.
    endpoint: https://127.0.0.1:1
    middlewares:
      - id: noredirect
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
  # Content writer (file backend): verifies descriptors, digests and tenants
  # and writes body + descriptor with the SDK store layout.
  fabriccontent:
    allowed_tenants: [tenant-a]
    backend: file
    file:
      directory: ${config_root}/content
    timeout: 60s
    queue_directory: ${config_root}/content-queue
    sending_queue:
      enabled: true
      queue_size: 16
      num_consumers: 2
      block_on_overflow: true
      storage: file_storage/fabric_content
    retry_on_failure:
      enabled: true
      max_elapsed_time: 0s

service:
  extensions: [health_check, noredirect, file_storage/fabric, file_storage/fabric_content]
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
    logs/content:
      receivers: [otlp/content]
      processors: [memory_limiter]
      exporters: [fabriccontent]
EOF
chmod 0644 "${runtime}/config.yaml"

# These assertions keep future edits from accidentally weakening what the
# runtime-start check is meant to qualify. The process start below proves the
# named component types and fields are recognized by the built artifact.
[[ "$(grep -c 'cert_file:' "${runtime}/config.yaml")" -eq 3 ]] \
  || fail "all three OTLP receivers must declare cert_file"
[[ "$(grep -c 'key_file:' "${runtime}/config.yaml")" -eq 3 ]] \
  || fail "all three OTLP receivers must declare key_file"
[[ "$(grep -c 'client_ca_file:' "${runtime}/config.yaml")" -eq 3 ]] \
  || fail "all three OTLP receivers must require client certificates"
grep -q 'max_recv_msg_size_mib: 8' "${runtime}/config.yaml" \
  || fail "gRPC receiver must cap messages at 8 MiB"
grep -q 'max_concurrent_streams: 64' "${runtime}/config.yaml" \
  || fail "gRPC receiver must cap concurrent streams"
grep -q 'min_time: 10s' "${runtime}/config.yaml" \
  || fail "gRPC receiver must enforce keepalive spacing"
grep -q 'max_request_body_size: 8388608' "${runtime}/config.yaml" \
  || fail "HTTP receiver must cap request bodies at 8 MiB"
grep -q 'max_request_body_size: 67108864' "${runtime}/config.yaml" \
  || fail "content receiver must cap request bodies at 64 MiB"
grep -q 'storage: file_storage/fabric_content' "${runtime}/config.yaml" \
  || fail "content exporter must use its own persistent queue"
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
grep -q -- '- id: noredirect' "${runtime}/config.yaml" \
  || fail "the OTLP/HTTP exporter must use the noredirect middleware"
[[ "$(grep -c 'block_on_overflow: true' "${runtime}/config.yaml")" -eq 2 ]] \
  || fail "both exporters must apply backpressure via block_on_overflow (default false drops records)"
if grep -n 'batch' "${runtime}/config.yaml" >/dev/null; then
  fail "qualified config must not contain a volatile pre-queue batch processor"
fi
# The guard only processes logs and traces. A qualified config must not
# define metrics or profiles pipelines, which would bypass the allowlist.
pipeline_names="$(awk '
    /^  pipelines:/ { inblock=1; next }
    inblock && /^  [^ ]/ { inblock=0 }
    inblock && /^    [a-z_\/]+:/ { sub(":$", "", $1); print $1 }
  ' "${runtime}/config.yaml" | sort)"
[[ "${pipeline_names}" == "$(printf 'logs\nlogs/content\ntraces')" ]] \
  || fail "qualified config must define only logs, logs/content and traces pipelines, got: ${pipeline_names}"
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
    --tmpfs /fabric-config-test/content-queue:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=65532,gid=65532 \
    --tmpfs /fabric-config-test/content:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=65532,gid=65532 \
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

# content_violation_configs BASE writes three overlays next to BASE (each is
# merged after a valid copy of the qualified config by an extra --config):
# the content receiver feeding the telemetry logs pipeline, the content
# pipeline exporting to the OTLP destination, and fabricguard on the content
# pipeline (it would scrub bodies).
content_violation_configs() {
  local dir
  dir="$(dirname "$1")"
  cp "${runtime}/config.yaml" "$1"
  printf 'service:\n  pipelines:\n    logs:\n      receivers: [otlp, otlp/content]\n' \
    >"${dir}/bad-content-recv.yaml"
  printf 'service:\n  pipelines:\n    logs/content:\n      exporters: [fabriccontent, otlp_http/fabric]\n' \
    >"${dir}/bad-content-dest.yaml"
  printf 'service:\n  pipelines:\n    logs/content:\n      processors: [memory_limiter, fabricguard]\n' \
    >"${dir}/bad-content-guard.yaml"
  # H2: a second fabriccontent exporter for another tenant behind the same
  # content receiver (each exporter alone allows one tenant).
  printf 'exporters:\n  fabriccontent/b:\n    allowed_tenants: [tenant-b]\n    backend: file\n    file:\n      directory: /tmp/fabric-content-b\nservice:\n  pipelines:\n    logs/content:\n      exporters: [fabriccontent, fabriccontent/b]\n' \
    >"${dir}/bad-content-tenants.yaml"
  # A credential-bearing destination URL (the secret must not be echoed).
  printf 'exporters:\n  otlp_http/fabric:\n    endpoint: https://user:QUALIFY_SECRET@127.0.0.1:1\n' \
    >"${dir}/bad-content-endpoint.yaml"
  # J3: a second tenant on a separate receiver and pipeline is still the
  # same Node. The second receiver serves the same mTLS as the qualified
  # receivers, so the tenant split is the only defect the gate can report.
  printf 'receivers:\n  otlp/content-b:\n    protocols:\n      http:\n        endpoint: 127.0.0.1:4320\n        tls:\n          cert_file: %s/server.crt\n          key_file: %s/server.key\n          client_ca_file: %s/ca.crt\nexporters:\n  fabriccontent/b:\n    allowed_tenants: [tenant-b]\n    backend: file\n    file:\n      directory: /tmp/fabric-content-b\nservice:\n  pipelines:\n    logs/content-b:\n      receivers: [otlp/content-b]\n      exporters: [fabriccontent/b]\n' \
    "${config_root}" "${config_root}" "${config_root}" \
    >"${dir}/bad-content-node-tenants.yaml"
  # J3: a fabriccontent block the gate cannot read (whole-block reference).
  # shellcheck disable=SC2016 # the reference is literal config text
  printf 'exporters:\n  fabriccontent: ${env:QUALIFY_CONTENT_BLOCK}\n' \
    >"${dir}/bad-content-block.yaml"
  # J4: the OTLP/HTTP exporter without the noredirect middleware.
  printf 'exporters:\n  otlp_http/fabric:\n    middlewares: []\n' \
    >"${dir}/bad-redirect.yaml"
  chmod 0644 "$1" "${dir}"/bad-content-*.yaml "${dir}/bad-redirect.yaml"
}

# The shipped image's fabric-gate entrypoint must refuse configurations the
# recorder cannot protect: non-traces/logs pipelines bypass fabricguard, a
# newline-terminated token file mints an empty "Bearer " credential under
# the pinned bearertokenauth extension, and a collector --set override (in
# either spelling) would be merged after the validated --config files. Each
# refusal must name its own reason, so a refusal for an unrelated cause (for
# example an unreadable config path) cannot pass for the intended one.
if [[ "${mode}" == "image" ]]; then
  # The runtime directory is mounted at /fabric-config-test, so the rejected
  # config must live at the path the container is given.
  badcfg="${runtime}/bad.yaml"
  # gate_expect_refusal NAME WHY REASON [COLLECTOR-ARG...]
  gate_expect_refusal() {
    local name="$1" why="$2" reason="$3"; shift 3
    docker run -d --name "${name}" \
      --network none \
      --mount "type=bind,src=${runtime},dst=/fabric-config-test,readonly" \
      "${artifact}" --config=/fabric-config-test/bad.yaml "$@" >/dev/null \
      || fail "could not start gate test container: ${name}"
    sleep 2
    local state
    state="$(docker inspect --format '{{.State.Status}}' "${name}" 2>/dev/null || true)"
    if [[ "${state}" == "running" ]]; then
      docker rm -f "${name}" >/dev/null 2>&1 || true
      fail "image booted despite ${why}; fabric-gate did not refuse"
    fi
    local logs
    logs="$(docker logs "${name}" 2>&1 || true)"
    docker rm -f "${name}" >/dev/null 2>&1 || true
    grep -qF "fabric-gate: refusing to start recorder" <<<"${logs}" \
      || fail "rejected ${why} produced no fabric-gate refusal message"
    grep -qF -- "${reason}" <<<"${logs}" \
      || fail "rejected ${why} for a different reason than expected: ${logs}"
    if grep -qF QUALIFY_SECRET <<<"${logs}"; then
      fail "refusal of ${why} echoed a credential"
    fi
  }

  sed 's|^    traces:|    metrics:\n      receivers: [otlp]\n      processors: [memory_limiter]\n      exporters: [otlp_http/fabric]\n    traces:|' \
    "${runtime}/config.yaml" >"${badcfg}"
  gate_expect_refusal "${container_name}-gate" "a metrics pipeline" 'uses signal "metrics"'

  # A traces pipeline that no longer runs fabricguard (e.g. an overlay that
  # replaced its processors) would export unfiltered spans.
  sed 's|processors: \[memory_limiter, fabricguard\]|processors: [memory_limiter]|' \
    "${runtime}/config.yaml" >"${badcfg}"
  gate_expect_refusal "${container_name}-noguard" "a pipeline without fabricguard" "does not run fabricguard"

  # Unsafe token material: same config plus a newline-terminated token file.
  printf 'tok3n\n' >"${runtime}/bad.token"
  sed 's|^extensions:|extensions:\n  bearertokenauth:\n    filename: /fabric-config-test/bad.token|' \
    "${runtime}/config.yaml" >"${badcfg}"
  gate_expect_refusal "${container_name}-token" "a trailing-newline token file" 'empty "Bearer " credential would authenticate'

  # A valid, guarded config plus a collector --set override that would drop
  # fabricguard after validation; both pflag spellings are refused.
  cp "${runtime}/config.yaml" "${badcfg}"
  gate_expect_refusal "${container_name}-set-eq" "a --set= override" "--set overrides are not accepted" \
    "--set=service.pipelines.traces.processors=[memory_limiter]"
  gate_expect_refusal "${container_name}-set-sep" "a --set override" "--set overrides are not accepted" \
    --set "service.pipelines.traces.processors=[memory_limiter]"

  # Spec 048 §5: content never reaches a telemetry pipeline or the OTLP
  # destination, and never passes fabricguard.
  content_violation_configs "${badcfg}"
  gate_expect_refusal "${container_name}-content-recv" "a content receiver in a telemetry pipeline" \
    "content receivers may only feed" --config=/fabric-config-test/bad-content-recv.yaml
  gate_expect_refusal "${container_name}-content-dest" "a content pipeline exporting to the OTLP destination" \
    "may export only to fabriccontent" --config=/fabric-config-test/bad-content-dest.yaml
  gate_expect_refusal "${container_name}-content-guard" "fabricguard on the content pipeline" \
    "only memory_limiter may run" --config=/fabric-config-test/bad-content-guard.yaml
  gate_expect_refusal "${container_name}-content-tenants" "two tenants across content exporters on one receiver" \
    "together allow more than one tenant" --config=/fabric-config-test/bad-content-tenants.yaml
  gate_expect_refusal "${container_name}-endpoint-userinfo" "a credential-bearing destination endpoint" \
    "must not contain user info, a query or a fragment" --config=/fabric-config-test/bad-content-endpoint.yaml
  gate_expect_refusal "${container_name}-node-tenants" "two tenants on separate content receivers of one Node" \
    "together allow more than one tenant" --config=/fabric-config-test/bad-content-node-tenants.yaml
  gate_expect_refusal "${container_name}-content-block" "a whole-block fabriccontent reference" \
    "is not a literal mapping" --config=/fabric-config-test/bad-content-block.yaml
  gate_expect_refusal "${container_name}-redirect" "an OTLP/HTTP exporter without the noredirect middleware" \
    "does not list the noredirect middleware" --config=/fabric-config-test/bad-redirect.yaml
  # Diagnostics identify sources by position and never echo them: a
  # malformed inline yaml: source carrying an Authorization header.
  gate_expect_refusal "${container_name}-inline-secret" "a malformed inline config source" \
    "--config #2 is not a valid YAML mapping" '--config=yaml:exporters: {otlp_http/x: {headers: {Authorization: "Bearer QUALIFY_SECRET"}'
  printf '%s PASS: image entrypoint refused unprotected pipelines, content misrouting, split tenants, unreadable content blocks, missing redirect refusal, credential URLs, unsafe token material and --set overrides without echoing sources\n' "${prefix}"
elif [[ -x "$(dirname "${artifact}")/fabric-gate" ]]; then
  # Binary mode: the same refusal invariants run through dist/fabric-gate,
  # which resolves the sibling collector and exits non-zero before exec.
  gate_bin="$(dirname "${artifact}")/fabric-gate"
  badcfg="${runtime}/gate-reject.yaml"
  gate_expect_refusal_bin() {
    local why="$1" reason="$2"; shift 2
    local out
    if out="$("${gate_bin}" --config="${badcfg}" "$@" 2>&1 </dev/null)"; then
      fail "fabric-gate accepted ${why}"
    fi
    grep -qF -- "${reason}" <<<"${out}" \
      || fail "fabric-gate rejected ${why} for a different reason than expected: ${out}"
    if grep -qF QUALIFY_SECRET <<<"${out}"; then
      fail "refusal of ${why} echoed a credential"
    fi
  }
  sed 's|^    traces:|    metrics:\n      receivers: [otlp]\n      processors: [memory_limiter]\n      exporters: [otlp_http/fabric]\n    traces:|' \
    "${runtime}/config.yaml" >"${badcfg}"
  gate_expect_refusal_bin "a metrics pipeline" 'uses signal "metrics"'
  sed 's|processors: \[memory_limiter, fabricguard\]|processors: [memory_limiter]|' \
    "${runtime}/config.yaml" >"${badcfg}"
  gate_expect_refusal_bin "a pipeline without fabricguard" "does not run fabricguard"
  printf 'tok3n\n' >"${runtime}/bad.token"
  sed 's|^extensions:|extensions:\n  bearertokenauth:\n    filename: '"${runtime}"'/bad.token|' \
    "${runtime}/config.yaml" >"${badcfg}"
  gate_expect_refusal_bin "a trailing-newline token file" 'empty "Bearer " credential would authenticate'
  cp "${runtime}/config.yaml" "${badcfg}"
  gate_expect_refusal_bin "a --set= override" "--set overrides are not accepted" \
    "--set=service.pipelines.traces.processors=[memory_limiter]"
  gate_expect_refusal_bin "a --set override" "--set overrides are not accepted" \
    --set "service.pipelines.traces.processors=[memory_limiter]"
  content_violation_configs "${badcfg}"
  gate_expect_refusal_bin "a content receiver in a telemetry pipeline" "content receivers may only feed" \
    --config="${runtime}/bad-content-recv.yaml"
  gate_expect_refusal_bin "a content pipeline exporting to the OTLP destination" "may export only to fabriccontent" \
    --config="${runtime}/bad-content-dest.yaml"
  gate_expect_refusal_bin "fabricguard on the content pipeline" "only memory_limiter may run" \
    --config="${runtime}/bad-content-guard.yaml"
  gate_expect_refusal_bin "two tenants across content exporters on one receiver" "together allow more than one tenant" \
    --config="${runtime}/bad-content-tenants.yaml"
  gate_expect_refusal_bin "a credential-bearing destination endpoint" "must not contain user info, a query or a fragment" \
    --config="${runtime}/bad-content-endpoint.yaml"
  gate_expect_refusal_bin "two tenants on separate content receivers of one Node" "together allow more than one tenant" \
    --config="${runtime}/bad-content-node-tenants.yaml"
  gate_expect_refusal_bin "a whole-block fabriccontent reference" "is not a literal mapping" \
    --config="${runtime}/bad-content-block.yaml"
  gate_expect_refusal_bin "an OTLP/HTTP exporter without the noredirect middleware" "does not list the noredirect middleware" \
    --config="${runtime}/bad-redirect.yaml"
  gate_expect_refusal_bin "a malformed inline config source" "--config #2 is not a valid YAML mapping" \
    '--config=yaml:exporters: {otlp_http/x: {headers: {Authorization: "Bearer QUALIFY_SECRET"}'
  printf '%s PASS: fabric-gate binary refused unprotected pipelines, content misrouting, split tenants, unreadable content blocks, missing redirect refusal, credential URLs, unsafe token material and --set overrides without echoing sources\n' "${prefix}"
fi

printf '%s PASS: recorder artifact accepted mTLS ingress, protection, durable OTLP/HTTP export and the content path\n' "${prefix}"
printf '%s NOTE: configuration compatibility only; no telemetry delivery was attempted\n' "${prefix}"
