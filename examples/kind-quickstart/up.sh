#!/usr/bin/env bash
# Fabric recorder end-to-end quickstart — 10-minute local install.
#
# What this does:
#   1. Creates a single-node kind cluster (fabric-quickstart)
#   2. Installs the Fabric Node umbrella chart with the shadow-dev profile
#      (passive recorder only: CAPTURE -> PROTECT -> DELIVER)
#   3. Port-forwards the collector's OTLP/HTTP receiver to localhost:4318
#   4. Runs a minimal demo agent on the explicit recorder APIs (not wire
#      capture) that exports spans to it; the model is a stub by default
#   5. Tails the collector logs so you SEE the spans arrive
#
# Prerequisites:
#   - kind, kubectl, helm, docker (running), python3
#   - ANTHROPIC_API_KEY in your env only with --real
#
# Usage:
#   ./up.sh           # stub model, no key needed (--mock is accepted too)
#   ./up.sh --real    # real model call (needs ANTHROPIC_API_KEY)
#   ./down.sh         # tear down the cluster
#
set -euo pipefail

MOCK=1
[[ "${1:-}" == "--real" ]] && MOCK=0

CLUSTER=fabric-quickstart
NS=fabric-system
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

PF_PID=""
TAIL_PID=""
cleanup() { kill $PF_PID $TAIL_PID 2>/dev/null || true; }
trap cleanup EXIT

step() { printf "\n\033[1;34m==> %s\033[0m\n" "$*"; }
note() { printf "    \033[2m%s\033[0m\n" "$*"; }

# 0. pre-flight
step "Pre-flight checks"
for bin in kind kubectl helm docker python3; do
  command -v $bin >/dev/null || { echo "missing: $bin"; exit 1; }
done
docker info >/dev/null 2>&1 || { echo "docker not running"; exit 1; }
if [[ $MOCK -eq 0 && -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "ANTHROPIC_API_KEY not set; --real needs it (run without --real for the stub)."
  exit 1
fi
note "tools: ok"

# 1. cluster
step "Creating kind cluster '$CLUSTER'"
if kind get clusters | grep -qx "$CLUSTER"; then
  note "cluster already exists, reusing"
else
  kind create cluster --name "$CLUSTER" --wait 60s
fi

# 2. Fabric Node chart (shadow-dev profile — plaintext, local trials only)
step "Installing Fabric Node chart (shadow-dev profile)"
helm upgrade --install fabric "${REPO_ROOT}/charts/fabric" \
  --namespace "$NS" \
  --values "${REPO_ROOT}/charts/fabric/profiles/shadow-dev.yaml" \
  --set tenant.id=acme-demo \
  --wait --timeout 5m
note "Fabric Node installed"

# 3. port-forward the OTLP/HTTP receiver so the host-run agent can reach it
step "Port-forwarding collector OTLP/HTTP to localhost:4318"
kubectl -n "$NS" port-forward service/fabric-otel-collector 4318:4318 &
PF_PID=$!
sleep 2

# 4. otel-collector log tail (background)
# shadow-dev enables the debug exporter, so arriving spans are printed here.
step "Tailing collector logs (spans will appear here as the agent runs)"
kubectl -n "$NS" logs -l app.kubernetes.io/name=otel-collector -f --tail=5 &
TAIL_PID=$!
sleep 2

# 5. run the demo agent
step "Running the demo agent"
cd "$(dirname "$0")"
python3 -m venv .venv
./.venv/bin/pip install -q "singleaxis-fabric[otlp]==0.10.0"
if [[ $MOCK -eq 0 ]]; then
  ./.venv/bin/pip install -q anthropic
fi
export OTEL_EXPORTER_OTLP_ENDPOINT="${OTEL_EXPORTER_OTLP_ENDPOINT:-http://localhost:4318}"
if [[ $MOCK -eq 1 ]]; then
  ./.venv/bin/python agent.py
else
  FABRIC_DEMO_REAL=1 ./.venv/bin/python agent.py
fi

echo
note "Done. Cluster left running so you can poke around: kubectl -n $NS get pods"
note "Tear down with:  ./down.sh"
