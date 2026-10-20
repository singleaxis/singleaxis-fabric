#!/usr/bin/env bash
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
#
# One entry point for the agent matrix.
#
#   qualification/agent-matrix/run.sh [setup] [local] [node] [privacy] [probes] [bench] [report]
#
# With no argument every stage runs in order. "node" and "privacy" need Docker and the
# Fabric Node image built from this worktree (MATRIX_NODE_IMAGE, default
# fabric/node:agent-matrix; MATRIX_BUILD_NODE=1 builds it from
# components/otel-collector-fabric, as the wire-capture e2e tests do).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PY="$HERE/.work/venvs/_harness/bin/python"
stages=("$@")
[ ${#stages[@]} -eq 0 ] && stages=(setup local node privacy probes bench report)

for stage in "${stages[@]}"; do
  echo "=== $stage"
  case "$stage" in
    setup)
      "$HERE/harness/setup_venvs.sh"
      if [ "${MATRIX_BUILD_NODE:-0}" = 1 ]; then
        docker build -t "${MATRIX_NODE_IMAGE:-fabric/node:agent-matrix}" \
          "$REPO/components/otel-collector-fabric"
      fi ;;
    local|node|privacy|probes|bench) "$PY" "$HERE/harness/run_matrix.py" "$stage" ;;
    report) "$PY" "$HERE/harness/report.py" > /dev/null && echo "wrote $HERE/REPORT.md" ;;
    *) echo "unknown stage: $stage" >&2; exit 2 ;;
  esac
done
