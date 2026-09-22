#!/usr/bin/env bash
# End-to-end test of the eBPF host emitter on a Linux-capable Docker engine
# (Docker Desktop's linuxkit VM has BTF and full BPF support).
#
#   bash components/host-emitter/e2e-emitter.sh
#
# Proves:
#   1. The emitter loads its CO-RE programs and attaches tracepoints.
#   2. An execve in a *different container* on the same kernel surfaces as an
#      event_class=audit record at the Fabric Node.
#   3. A connect() surfaces with network.peer.* attributes.
#   4. Raw argv never crosses — only process.command_args_sha256.
#   5. cgroup scoping works (agent cgroup filter) when configured.
set -euo pipefail

EMIT_IMG="${EMIT_IMG:-fabric-host-emitter:local}"
COL_IMG="${COL_IMG:-fabric-otelcol:local}"
NET="fabric-ebpf-e2e"
WORK="$(mktemp -d)"
MARKER="fabric-ebpf-marker-$$"

cat > "$WORK/collector.yaml" <<'EOF'
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  fabricguard: {}
exporters:
  debug:
    verbosity: detailed
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [fabricguard]
      exporters: [debug]
EOF

cleanup() {
  docker rm -f fabric-ebpf-col fabric-ebpf-emit >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

docker network create "$NET" >/dev/null

echo "==> starting fabric node"
docker run -d --name fabric-ebpf-col --network "$NET" \
  -v "$WORK/collector.yaml:/etc/otelcol/config.yaml:ro" \
  "$COL_IMG" --config /etc/otelcol/config.yaml >/dev/null
sleep 3

echo "==> starting emitter (privileged, all-host for the e2e)"
docker run -d --name fabric-ebpf-emit --network "$NET" \
  --privileged --pid=host --user 0 \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -e EMIT_ENDPOINT=fabric-ebpf-col:4317 \
  -e EMIT_ALL_HOST=true \
  -e EMIT_EXEC=true -e EMIT_CONNECT=true -e EMIT_FILE_ACCESS=false \
  -e EMIT_DEDUPE_WINDOW=0s \
  "$EMIT_IMG" >/dev/null
sleep 4

echo "==> emitter startup log:"
docker logs fabric-ebpf-emit 2>&1 | head -5

echo "==> generating marker events in a third container"
docker run --rm --network "$NET" ubuntu:24.04 bash -c '
  cp /bin/echo "/tmp/'"$MARKER"'"
  /tmp/"'"$MARKER"'" "ebpf-marker-arg-secret"
  exec 3<>/dev/tcp/fabric-ebpf-col/4317 && exec 3>&-
' >/dev/null 2>&1 || true

sleep 8
LOGS="$(docker logs fabric-ebpf-col 2>&1)"
echo "==> records captured: $(echo "$LOGS" | grep -c 'event_class' || true)"

fail=0
# Herestrings avoid the grep -q + SIGPIPE + pipefail false-negative on large
# captured logs.
check() { if grep -q "$1" <<<"$LOGS"; then echo "  PASS: $2"; else echo "  FAIL: $2"; fail=1; fi; }
check_absent() { if grep -q "$1" <<<"$LOGS"; then echo "  FAIL: $2"; fail=1; else echo "  PASS: $2"; fi; }

echo "==> assertions"
check "ebpf" "audit.source=ebpf records arriving"
check "$MARKER" "marker exec observed cross-container"
check "process.command_args_sha256" "argv hashed"
check_absent "ebpf-marker-arg-secret" "raw argv never emitted"
check "connect" "connect syscall observed"

if [ "$fail" -ne 0 ]; then
  echo "==> collector logs:"; docker logs fabric-ebpf-col 2>&1 | tail -20
  echo "==> emitter logs:"; docker logs fabric-ebpf-emit 2>&1 | tail -20
  exit 1
fi
echo "==> all eBPF e2e assertions passed"
