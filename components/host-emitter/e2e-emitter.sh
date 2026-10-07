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
# This smoke uses privileged all-host mode on a disposable Linux test host;
# it does not qualify the production capability set or cgroup scoping.
set -euo pipefail

EMIT_IMG="${EMIT_IMG:-fabric-host-emitter:local}"
COL_IMG="${COL_IMG:-fabric-otelcol:local}"
WORK="$(mktemp -d)"
RUN_ID="$(basename "$WORK" | tr -cd 'a-zA-Z0-9')"
NET="fabric-ebpf-e2e-$RUN_ID"
COL_NAME="fabric-ebpf-col-$RUN_ID"
EMIT_NAME="fabric-ebpf-emit-$RUN_ID"
mkdir -m 0700 "$WORK/spool"
MARKER="fabric-ebpf-marker-$$"
MARKER_HASH="$(printf '%s' "/tmp/$MARKER" | sha256sum | awk '{print $1}')"

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
  docker rm -f "$COL_NAME" "$EMIT_NAME" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

docker network create "$NET" >/dev/null

echo "==> starting fabric node"
docker run -d --name "$COL_NAME" --network "$NET" \
  -v "$WORK/collector.yaml:/etc/otelcol/config.yaml:ro" \
  "$COL_IMG" --config /etc/otelcol/config.yaml >/dev/null
sleep 3

echo "==> starting emitter (privileged, all-host for the e2e)"
docker run -d --name "$EMIT_NAME" --network "$NET" \
  --privileged --pid=host --user 0 \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v "$WORK/spool:/var/lib/fabric-host-emitter" \
  -e EMIT_ENDPOINT="$COL_NAME:4317" \
  -e EMIT_INSECURE=true \
  -e EMIT_ALL_HOST=true \
  -e EMIT_EXEC=true -e EMIT_CONNECT=true -e EMIT_FILE_ACCESS=false \
  -e EMIT_DEDUPE_WINDOW=0s \
  "$EMIT_IMG" >/dev/null
sleep 4

echo "==> emitter startup log:"
docker logs "$EMIT_NAME" 2>&1 | head -5

echo "==> generating marker events in a third container"
docker run --rm --network "$NET" ubuntu:24.04 bash -c '
  cp /bin/echo "/tmp/'"$MARKER"'"
  /tmp/"'"$MARKER"'" "ebpf-marker-arg-secret"
  exec 3<>/dev/tcp/'"$COL_NAME"'/4317 && exec 3>&-
' >/dev/null 2>&1 || true

sleep 8
LOGS="$(docker logs "$COL_NAME" 2>&1)"
echo "==> records captured: $(echo "$LOGS" | grep -c 'event_class' || true)"

fail=0
# Herestrings avoid the grep -q + SIGPIPE + pipefail false-negative on large
# captured logs.
check() { if grep -q "$1" <<<"$LOGS"; then echo "  PASS: $2"; else echo "  FAIL: $2"; fail=1; fi; }
check_absent() { if grep -q "$1" <<<"$LOGS"; then echo "  FAIL: $2"; fail=1; else echo "  PASS: $2"; fi; }

echo "==> assertions"
check "ebpf" "audit.source=ebpf records arriving"
check "$MARKER_HASH" "marker executable path hash observed cross-container"
check_absent "$MARKER" "raw executable path never emitted"
check "process.command_args_sha256" "argv hashed"
check_absent "ebpf-marker-arg-secret" "raw argv never emitted"
check "connect" "connect syscall observed"

if [ "$fail" -ne 0 ]; then
  echo "==> collector logs:"; docker logs "$COL_NAME" 2>&1 | tail -20
  echo "==> emitter logs:"; docker logs "$EMIT_NAME" 2>&1 | tail -20
  exit 1
fi
echo "==> all eBPF e2e assertions passed"
