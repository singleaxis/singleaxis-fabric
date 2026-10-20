#!/usr/bin/env bash
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
#
# Build the Fabric wheel from this worktree, lock every framework's pins together
# with it, and create one isolated venv per framework (plus the harness venv).
# Framework code is untrusted downloaded code: it lives only in its venv, and the
# harness scripts that drive it stay outside every venv.
#
#   harness/setup_venvs.sh [framework ...]     (default: every frameworks/* dir)
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORK="$HERE/.work"
PY="${MATRIX_PYTHON:-3.12}"
mkdir -p "$WORK/dist" "$WORK/venvs"

rm -f "$WORK"/dist/singleaxis_fabric-*.whl
(cd "$REPO/sdk/python" && uv build --wheel -q -o "$WORK/dist")
WHEEL="$(ls "$WORK"/dist/singleaxis_fabric-*.whl | head -1)"

# Harness venv: the runner, the OTLP sink, reconstruct and the S3 reader side.
if [ ! -x "$WORK/venvs/_harness/bin/python" ]; then
  uv venv -q --python "$PY" "$WORK/venvs/_harness"
fi
uv pip install -q --python "$WORK/venvs/_harness/bin/python" --reinstall-package singleaxis-fabric \
  "${WHEEL}[otlp,s3]" pytest httpx cryptography

frameworks=("$@")
if [ ${#frameworks[@]} -eq 0 ]; then
  for d in "$HERE"/frameworks/*/; do frameworks+=("$(basename "$d")"); done
fi

for fw in "${frameworks[@]}"; do
  dir="$HERE/frameworks/$fw"
  venv="$WORK/venvs/$fw"
  echo "== $fw"
  # Lock the framework pins with Fabric's own dependencies resolved alongside them
  # (a customer installs both into one environment).
  if [ ! -f "$dir/requirements.lock" ]; then
    printf '%s\n' "-r $dir/requirements.in" "${WHEEL}[otlp]" > "$WORK/$fw.lock.in"
    (cd "$dir" && uv pip compile -q --python "$PY" --no-header "$WORK/$fw.lock.in" \
        | grep -v -E '^singleaxis-fabric|^ *# *via|^ *#' > requirements.lock)
  fi
  [ -x "$venv/bin/python" ] || uv venv -q --python "$PY" "$venv"
  uv pip install -q --python "$venv/bin/python" -r "$dir/requirements.lock"
  uv pip install -q --python "$venv/bin/python" --no-deps --reinstall-package singleaxis-fabric "$WHEEL"
done
