#!/bin/bash
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
#
# Every chaos scenario, one Node stack at a time (all stacks share the pre-created
# fabric-chaos-net bridge, where service DNS names would collide if run in parallel).
# About 4.5 h with the 120 min soak; SOAK_S=1800 for a 30 min soak.
#
#   uv venv .venv && uv pip install -p .venv -e ../../sdk/python httpx gunicorn uvicorn \
#       psutil brotli opentelemetry-proto
#   docker build -t fabric/node:chaos ../../components/otel-collector-fabric
#   ./run_all.sh
#
# Each scenario writes results/<name>/verdict.json and prints one line of held/failed
# invariants; reaudit.py re-checks end-to-end accounting offline from saved results.
set -u
cd "$(dirname "$0")"
PY=.venv/bin/python
SOAK_S=${SOAK_S:-7200}

run() {
  local name=$1
  shift
  echo "== $name"
  "$PY" "$@" --out "results/$name" 2>&1 | tee "results-$name.log" | tail -5
}

run s1 s1_concurrency.py
run s2-kill s2_kill_loop.py --iterations 200
run s2-fork s2_fork_workers.py
run s3-kill_restart s3_node_faults.py --case kill_restart
run s3-down10 s3_node_faults.py --case down10 --down-s 600
run s3-store_down s3_node_faults.py --case store_down --down-s 180
run s3-store_slow s3_node_faults.py --case store_slow --down-s 90
run s3-spool_full s3_node_faults.py --case spool_full --down-s 90
run s3-queue_full s3_node_faults.py --case queue_full --down-s 150
run s3-store_full s3_node_faults.py --case store_full --down-s 120
run s3-clock_skew s3_node_faults.py --case clock_skew
run s4 s4_network.py
run s5 s5_payload.py
run s6 s6_adversarial.py
run s7 s7_soak.py --duration-s "$SOAK_S"
"$PY" reaudit.py results/s*
