#!/usr/bin/env bash
# Fabric end-to-end quickstart — 10-minute local install.
#
# What this does:
#   1. Creates a single-node kind cluster (fabric-quickstart)
#   2. Installs Fabric via the OSS umbrella chart, permissive-dev profile
#   3. Builds + loads a minimal instrumented demo agent
#   4. Runs the agent against a real model
#   5. Tails the OTel collector logs so you SEE the spans flowing
#
# Prerequisites:
#   - kind, kubectl, helm, docker (running)
#   - ANTHROPIC_API_KEY in your env (or use --mock)
#
# Usage:
#   ./up.sh           # real model (needs ANTHROPIC_API_KEY)
#   ./up.sh --mock    # stub model, no key needed
#   ./down.sh         # tear down the cluster
#
set -euo pipefail

MOCK=0
[[ "${1:-}" == "--mock" ]] && MOCK=1

CLUSTER=fabric-quickstart
NS=fabric-system

step() { printf "\n\033[1;34m==> %s\033[0m\n" "$*"; }
note() { printf "    \033[2m%s\033[0m\n" "$*"; }

# 0. pre-flight
step "Pre-flight checks"
for bin in kind kubectl helm docker; do
  command -v $bin >/dev/null || { echo "missing: $bin"; exit 1; }
done
docker info >/dev/null 2>&1 || { echo "docker not running"; exit 1; }
if [[ $MOCK -eq 0 && -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "ANTHROPIC_API_KEY not set; re-run with --mock for a no-key demo."
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

# 2. namespace + tenant key
step "Creating namespace + tenant secrets"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create secret generic acme-tenant-key \
  --from-literal=key="$(openssl rand -hex 32)" \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Fabric chart (permissive-dev profile)
step "Installing Fabric umbrella chart (permissive-dev profile)"
helm upgrade --install fabric \
  oci://ghcr.io/singleaxis/charts/fabric \
  --namespace "$NS" \
  --values "$(dirname "$0")/../../charts/fabric/profiles/permissive-dev.yaml" \
  --set tenant.id=acme-demo \
  --set presidio-sidecar.tenantKeySecret=acme-tenant-key \
  --wait --timeout 5m
note "Fabric installed"

# 4. otel-collector log tail (background)
step "Tailing collector logs (spans will appear here as the agent runs)"
kubectl -n "$NS" logs -l app.kubernetes.io/name=otel-collector -f --tail=5 &
TAIL_PID=$!
trap "kill $TAIL_PID 2>/dev/null || true" EXIT

# 5. run the demo agent
step "Running the demo agent"
cd "$(dirname "$0")"
python3 -m venv .venv
./.venv/bin/pip install -q "singleaxis-fabric[anthropic,otlp]"
if [[ $MOCK -eq 1 ]]; then
  FABRIC_DEMO_MOCK=1 ./.venv/bin/python agent.py
else
  ./.venv/bin/python agent.py
fi

echo
note "Done. Cluster left running so you can poke around: kubectl -n $NS get pods"
note "Tear down with:  ./down.sh"
