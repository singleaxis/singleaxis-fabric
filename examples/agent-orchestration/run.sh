#!/usr/bin/env bash
# Agent-orchestration demo: real collector (audit receiver + fabricguard)
# + demo OTLP sink + instrumented agent + reconstruction journal + viewer.
#
#   bash examples/agent-orchestration/run.sh
#
# This offline scripted-model demo uses an agent-emitted audit-format shim;
# it does not establish independent host observation or complete reconstruction.
set -euo pipefail
cd "$(dirname "$0")"
if [ "${FABRIC_DEMO_ISOLATED:-}" != "1" ]; then
  echo "refusing demo: set FABRIC_DEMO_ISOLATED=1 only in an isolated synthetic-only environment" >&2
  exit 2
fi
umask 077

PY="${PY:-../../sdk/python/.venv/bin/python}"
OTLP_PORT="${FABRIC_OTLP_PORT:-19318}"
GRPC_PORT="${FABRIC_GRPC_PORT:-19317}"
HEALTH_PORT="${FABRIC_HEALTH_PORT:-19133}"
SINK_PORT="${FABRIC_SINK_PORT:-19200}"
IMG="${IMG:-fabric-otelcol:local}"
for port in "$OTLP_PORT" "$GRPC_PORT" "$HEALTH_PORT" "$SINK_PORT"; do
  if [[ ! "$port" =~ ^[0-9]{1,5}$ ]] || (( 10#$port < 1 || 10#$port > 65535 )); then
    echo "invalid demo port" >&2
    exit 2
  fi
done
OUTPUT_ROOT="${FABRIC_DEMO_OUTPUT_ROOT:-$PWD/out/runs}"
mkdir -p "$OUTPUT_ROOT"
OUTPUT_ROOT="$(cd "$OUTPUT_ROOT" && pwd -P)"
RUN_OUT="$(mktemp -d "$OUTPUT_ROOT/$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
COL="fabric-demo-collector-$(basename "$RUN_OUT")"
COL_ID=""
SINK_PID=""

cleanup() {
  if [ -n "$COL_ID" ]; then
    docker rm -f "$COL_ID" >/dev/null 2>&1 || true
  fi
  [ -n "$SINK_PID" ] && kill "$SINK_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$RUN_OUT/audit" "$RUN_OUT/viewer" "$RUN_OUT/out"
touch "$RUN_OUT/audit/audit.log"
cp viewer/index.html "$RUN_OUT/viewer/index.html"
# The copied viewer resolves ../out/journal.js to this run's journal only.
ln -s ../journal.js "$RUN_OUT/out/journal.js"

echo "==> demo sink on :$SINK_PORT"
if curl -fsS --max-time 1 "http://127.0.0.1:$SINK_PORT/health" >/dev/null 2>&1; then
  echo "refusing to use occupied demo sink port $SINK_PORT" >&2
  exit 1
fi
FABRIC_SINK_PORT="$SINK_PORT" "$PY" sink.py "$RUN_OUT" &
SINK_PID=$!
for i in $(seq 30); do
  kill -0 "$SINK_PID" 2>/dev/null || { echo "demo sink exited" >&2; exit 1; }
  curl -sf "http://127.0.0.1:$SINK_PORT/health" >/dev/null && break
  sleep 0.3
done
curl -sf "http://127.0.0.1:$SINK_PORT/health" >/dev/null || { echo "demo sink did not become healthy" >&2; exit 1; }

echo "==> collector (otlp + audit logfile -> fabricguard -> otlphttp)"
if [ "$(id -u)" -eq 0 ]; then
  echo "refusing a root-owned demo audit source" >&2
  exit 1
fi
COL_ID="$(docker run -d --name "$COL" --user "$(id -u):$(id -g)" \
  --add-host host.docker.internal:host-gateway \
  -p "127.0.0.1:$OTLP_PORT:4318" -p "127.0.0.1:$GRPC_PORT:4317" \
  -p "127.0.0.1:$HEALTH_PORT:13133" \
  -v "$PWD/collector.demo.yaml:/etc/otelcol/config.yaml:ro" \
  -v "$RUN_OUT/audit:/demo-audit:ro" \
  -e "SINK_PORT=$SINK_PORT" \
  "$IMG" --config /etc/otelcol/config.yaml)"
for i in $(seq 60); do
  curl -sf --max-time 1 "http://127.0.0.1:$HEALTH_PORT/" >/dev/null && break
  sleep 0.5
done
if ! curl -sf --max-time 1 "http://127.0.0.1:$HEALTH_PORT/" >/dev/null; then
  docker logs "$COL_ID" > "$RUN_OUT/collector.log" 2>&1 || true
  echo "demo collector did not become healthy; see $RUN_OUT/collector.log" >&2
  exit 1
fi

echo "==> agent run (local demo spool; sink is not durable storage)"
FABRIC_OTLP_URL="http://127.0.0.1:$OTLP_PORT" FABRIC_DEMO_OUT="$RUN_OUT" \
  "$PY" agent.py | tee "$RUN_OUT/decision.json.tmp"
"$PY" -c 'import pathlib,sys; root=pathlib.Path(sys.argv[1]); lines=(root/"decision.json.tmp").read_text().splitlines(); (root/"decision.json").write_text(lines[-1])' "$RUN_OUT"

echo "==> waiting for sink drain"
for i in $(seq 60); do
  N=$(curl -sf "http://127.0.0.1:$SINK_PORT/count" | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')
  [ "$N" -ge 5 ] && break
  sleep 0.5
done
sleep 2  # audit tailer poll interval
N=$(curl -sf "http://127.0.0.1:$SINK_PORT/count" | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')
echo "    sink records: $N"

docker logs "$COL_ID" > "$RUN_OUT/collector.log" 2>&1 || true

echo "==> reconstruct"
FABRIC_DEMO_OUT="$RUN_OUT" "$PY" reconstruct.py

echo ""
echo "==> done"
echo "    journal : $RUN_OUT/journal.json"
echo "    viewer  : $RUN_OUT/viewer/index.html   (file:// works — journal.js is linked within this run)"
