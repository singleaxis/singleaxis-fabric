#!/usr/bin/env bash
# Agent-orchestration demo: real collector (audit receiver + fabricguard)
# + demo OTLP sink + instrumented agent + reconstruction journal + viewer.
#
#   bash examples/agent-orchestration/run.sh
#
# Host layer honesty: on macOS the audit records are written by the agent
# process itself in auditd format (audit_shim.py — real pid/exit/argv for
# processes it really spawned). On Linux, collect-audit-linux.sh produces
# the identical stream from kernel auditd; downstream is unchanged.
set -euo pipefail
cd "$(dirname "$0")"

PY="${PY:-../../sdk/python/.venv/bin/python}"
OTLP_PORT="${FABRIC_OTLP_PORT:-19318}"
GRPC_PORT="${FABRIC_GRPC_PORT:-19317}"
HEALTH_PORT="${FABRIC_HEALTH_PORT:-19133}"
SINK_PORT="${FABRIC_SINK_PORT:-19200}"
IMG="${IMG:-fabric-otelcol:local}"
COL="fabric-demo-collector"
SINK_PID=""

cleanup() {
  docker rm -f "$COL" >/dev/null 2>&1 || true
  [ -n "$SINK_PID" ] && kill "$SINK_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf out && mkdir -p out/audit && touch out/audit/audit.log

echo "==> demo sink on :$SINK_PORT"
FABRIC_SINK_PORT="$SINK_PORT" "$PY" sink.py out &
SINK_PID=$!
for i in $(seq 30); do curl -sf "http://127.0.0.1:$SINK_PORT/health" >/dev/null && break; sleep 0.3; done

echo "==> collector (otlp + audit logfile -> fabricguard -> otlphttp)"
docker rm -f "$COL" >/dev/null 2>&1 || true
docker run -d --name "$COL" \
  -p "127.0.0.1:$OTLP_PORT:4318" -p "127.0.0.1:$GRPC_PORT:4317" \
  -p "127.0.0.1:$HEALTH_PORT:13133" \
  -v "$PWD/collector.demo.yaml:/etc/otelcol/config.yaml:ro" \
  -v "$PWD/out/audit:/demo-audit" \
  -e "SINK_PORT=$SINK_PORT" \
  "$IMG" --config /etc/otelcol/config.yaml >/dev/null
for i in $(seq 60); do curl -sf "http://127.0.0.1:$HEALTH_PORT/" >/dev/null && break; sleep 0.5; done

echo "==> agent run (spooled durability)"
FABRIC_OTLP_URL="http://127.0.0.1:$OTLP_PORT" FABRIC_DEMO_OUT="$PWD/out" \
  "$PY" agent.py | tee out/decision.json.tmp
python3 -c "import json,sys; lines=open('out/decision.json.tmp').read().splitlines(); open('out/decision.json','w').write(lines[-1])"

echo "==> waiting for sink drain"
for i in $(seq 60); do
  N=$(curl -sf "http://127.0.0.1:$SINK_PORT/count" | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')
  [ "$N" -ge 5 ] && break
  sleep 0.5
done
sleep 2  # audit tailer poll interval
N=$(curl -sf "http://127.0.0.1:$SINK_PORT/count" | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')
echo "    sink records: $N"

docker logs "$COL" > out/collector.log 2>&1 || true

echo "==> reconstruct"
FABRIC_DEMO_OUT="$PWD/out" "$PY" reconstruct.py

echo ""
echo "==> done"
echo "    journal : $PWD/out/journal.json"
echo "    viewer  : $PWD/viewer/index.html   (file:// works — journal.js is inlined)"
