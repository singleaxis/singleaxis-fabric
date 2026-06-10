#!/usr/bin/env bash
# Tear down the fabric-quickstart kind cluster.
set -euo pipefail
kind delete cluster --name fabric-quickstart || true
rm -rf "$(dirname "$0")/.venv"
echo "torn down."
