#!/usr/bin/env bash
# Spec 058 E2 (WP8-11, WP8-12, WP8-13) on a real cluster (kind):
#
#  1. `helm install` with preset=local, one agent namespace and the injector:
#     the secrets hook Job creates every Secret (0 hand-made), none is in the
#     Helm release, the hook RBAC is gone, the webhook's caBundle is set.
#  2. An annotated Python pod in the labelled namespace is injected and its
#     model calls reach the Node; its stdout and exit code equal an
#     uninjected run of the same agent (passivity).
#  3. "env" mode and an unannotated pod; a namespace the chart does not serve.
#  4. Webhook outage: with the injector scaled to zero an annotated pod is
#     admitted within the 2 s timeout and runs, uncaptured and unchanged.
#  5. `helm upgrade` keeps every Secret byte for byte.
#  6. `fabric init --kubernetes --profile production` from a workstation
#     (kubectl) adds a production namespace whose ingress token and source id
#     match its agent Secret.
#  7. `helm uninstall` keeps the Secrets.
#
# Environment: KUBECONFIG (a kind cluster), KIND_CLUSTER (to load images),
# CLI_IMAGE, NODE_IMAGE, AGENT_IMAGE (built and loaded by the caller or here),
# FABRIC (the `fabric` command under test; default: fabric on PATH).
# Needs kubectl, helm, kind, jq and python3.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart="$(cd "${here}/../.." && pwd)"
: "${KUBECONFIG:?point KUBECONFIG at the test cluster}"
: "${CLI_IMAGE:?}" "${NODE_IMAGE:?}" "${AGENT_IMAGE:?}"
FABRIC="${FABRIC:-fabric}"
release=f058
ns=fabric-system
agents=f058-agents
other=f058-other
prod=f058-prod-agents
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

log() { printf '== %s\n' "$*"; }
fail() {
  printf 'FAIL: %s\n' "$*" >&2
  kubectl get pods -A -o wide >&2 || true
  kubectl -n "${ns}" logs -l app.kubernetes.io/name=fabric-injector --tail=50 >&2 || true
  exit 1
}
image_parts() { printf '%s %s' "${1%:*}" "${1##*:}"; }
secret_rv() { kubectl -n "$1" get secret "$2" -o jsonpath='{.metadata.resourceVersion}'; }
secret_key() { kubectl -n "$1" get secret "$2" -o "jsonpath={.data.$3}" | base64 -d; }

if [[ -n "${KIND_CLUSTER:-}" ]]; then
  for image in "${CLI_IMAGE}" "${NODE_IMAGE}" "${AGENT_IMAGE}"; do
    kind load docker-image "${image}" --name "${KIND_CLUSTER}" >/dev/null
  done
fi
read -r cli_repo cli_tag <<<"$(image_parts "${CLI_IMAGE}")"
read -r node_repo node_tag <<<"$(image_parts "${NODE_IMAGE}")"
values=(
  --set preset=local
  --set "agentNamespaces={${agents}}"
  --set injector.enabled=true
  --set "cliImage.repository=${cli_repo}" --set "cliImage.tag=${cli_tag}" --set cliImage.pullPolicy=Never
  --set "otel-collector.image.repository=${node_repo}" --set "otel-collector.image.tag=${node_tag}"
  --set otel-collector.image.pullPolicy=Never
)

# --- 1. install: zero hand-made Secrets -----------------------------------------
log "install"
for namespace in "${agents}" "${other}"; do
  kubectl create namespace "${namespace}" >/dev/null
  kubectl label namespace "${namespace}" fabric.singleaxis.ai/injection=enabled >/dev/null
done
helm install "${release}" "${chart}" -n "${ns}" --create-namespace "${values[@]}" --wait --timeout 5m >/dev/null
for pair in "${ns}/fabric-ca" "${ns}/fabric-node-receiver-tls" "${ns}/fabric-injector-tls" "${agents}/fabric-agent"; do
  managed="$(kubectl -n "${pair%%/*}" get secret "${pair#*/}" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/managed-by}')"
  [[ "${managed}" == fabric-cli ]] || fail "Secret ${pair} missing or not generated (${managed})"
done
kubectl -n "${other}" get secret fabric-agent >/dev/null 2>&1 && fail "a namespace not in agentNamespaces got a Secret"
helm get manifest "${release}" -n "${ns}" | grep -Eq '^kind: Secret$' && fail "a Secret is part of the Helm release"
helm get manifest "${release}" -n "${ns}" | grep -q 'BEGIN' && fail "key material in the Helm release"
[[ -z "$(kubectl get jobs,roles,rolebindings,clusterroles,clusterrolebindings -A -l app.kubernetes.io/component=secrets-job -o name)" ]] \
  || fail "the hook Jobs or their RBAC were left behind"
bundle="$(kubectl get mutatingwebhookconfiguration "fabric-injector-${ns}-${release}" -o jsonpath='{.webhooks[0].clientConfig.caBundle}')"
[[ "${bundle}" == "$(kubectl -n "${ns}" get secret fabric-ca -o jsonpath='{.data.ca\.crt}')" ]] \
  || fail "the webhook caBundle is not the generated CA"

# --- 2. an injected Python agent records; its output is unchanged ----------------
endpoints="$(python3 -c 'import json; print(json.dumps([{"endpoint_id": "local-8080", "dialect": "openai",
  "hosts": ["127.0.0.1"], "ports": [8080], "schemes": ["http"], "path_prefix": "/v1"}]))')"
run_agent() {  # NAMESPACE NAME MODE(python|env|none)
  local namespace="$1" name="$2" mode="$3" annotations='{}'
  [[ "${mode}" != none ]] && annotations="{\"fabric.singleaxis.ai/inject\": \"${mode}\"}"
  kubectl -n "${namespace}" apply -f - >/dev/null <<EOF
{"apiVersion": "v1", "kind": "Pod",
 "metadata": {"name": "${name}", "annotations": ${annotations}},
 "spec": {"restartPolicy": "Never",
          "containers": [{"name": "agent", "image": "${AGENT_IMAGE}", "imagePullPolicy": "Never",
                          "env": [{"name": "FABRIC_WIRE_ENDPOINTS", "value": $(jq -Rn --arg v "${endpoints}" '$v')},
                                  {"name": "FABRIC_WIRE_DRAIN_ON_EXIT_S", "value": "30"}]}]}}
EOF
  kubectl -n "${namespace}" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/${name}" --timeout=180s >/dev/null \
    || fail "pod ${namespace}/${name} did not succeed"
  kubectl -n "${namespace}" logs "${name}" >"${tmp}/${name}.log" 2>&1
  sed -n '/^--- fabric status ---$/q;p' "${tmp}/${name}.log" >"${tmp}/${name}.stdout"
}
log "injected python agent"
run_agent "${agents}" agent-python python
pod="$(kubectl -n "${agents}" get pod agent-python -o json)"
[[ "$(jq -r '.metadata.annotations["fabric.singleaxis.ai/injected"]' <<<"${pod}")" == 0.12.1 ]] \
  || fail "the injected annotation is missing"
jq -e '.spec.containers[0].env | map(.name) | (index("PYTHONPATH") and index("FABRIC_OTLP_ENDPOINT") and index("FABRIC_WIRE_AUTOLOAD"))' \
  <<<"${pod}" >/dev/null || fail "the injected variables are missing"
jq -e '[.spec.containers[0].env[] | select(.name == "FABRIC_WIRE_ENDPOINTS")] | length == 1' <<<"${pod}" >/dev/null \
  || fail "the pod's own FABRIC_WIRE_ENDPOINTS was duplicated or replaced"
jq -e '.spec.volumes | map(.name) | (index("fabric-secrets") and index("fabric-spool") and index("fabric-autoload"))' \
  <<<"${pod}" >/dev/null || fail "the injected volumes are missing"
grep -q '"installed": true' "${tmp}/agent-python.log" || { cat "${tmp}/agent-python.log" >&2; fail "capture is not installed in the injected pod"; }
deadline=$((SECONDS + 60))
until kubectl -n "${ns}" logs -l app.kubernetes.io/name=otel-collector --tail=-1 | grep -Eq 'spans"?: [1-9]'; do
  (( SECONDS < deadline )) || fail "no span reached the Node from the injected agent"
  sleep 2
done
log "baseline (same agent, not injected)"
kubectl create namespace f058-plain >/dev/null
run_agent f058-plain agent-plain none
diff -u "${tmp}/agent-plain.stdout" "${tmp}/agent-python.stdout" || fail "injection changed the agent's stdout"

# --- 3. env mode, an unannotated pod, an unserved namespace ----------------------
log "env mode and unmarked pods"
run_agent "${agents}" agent-env env
env_pod="$(kubectl -n "${agents}" get pod agent-env -o json)"
jq -e '.spec.containers[0].env | map(.name) | (index("FABRIC_OTLP_ENDPOINT") and (index("PYTHONPATH") | not))' \
  <<<"${env_pod}" >/dev/null || fail "env mode added the autoload or missed the variables"
run_agent "${agents}" agent-unmarked none
[[ "$(kubectl -n "${agents}" get pod agent-unmarked -o jsonpath='{.metadata.annotations}')" != *fabric.singleaxis.ai* ]] \
  || fail "a pod without the annotation was changed"
run_agent "${other}" agent-other python
[[ "$(kubectl -n "${other}" get pod agent-other -o jsonpath='{.spec.containers[0].env[*].name}')" != *FABRIC_OTLP* ]] \
  || fail "a namespace not in agentNamespaces was injected"

# --- 4. webhook outage -------------------------------------------------------------
log "webhook outage"
kubectl -n "${ns}" scale deployment "${release}-fabric-injector" --replicas=0 >/dev/null
kubectl -n "${ns}" wait --for=delete pod -l app.kubernetes.io/name=fabric-injector --timeout=120s >/dev/null || true
now_ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }
start="$(now_ms)"
kubectl -n "${agents}" run agent-outage --image="${AGENT_IMAGE}" --image-pull-policy=Never --restart=Never \
  --annotations=fabric.singleaxis.ai/inject=python >/dev/null
elapsed_ms=$(( $(now_ms) - start ))
(( elapsed_ms < 5000 )) || fail "admission took ${elapsed_ms} ms with the injector down (timeout is 2 s)"
kubectl -n "${agents}" wait --for=jsonpath='{.status.phase}'=Succeeded pod/agent-outage --timeout=180s >/dev/null \
  || fail "the annotated pod did not run with the injector down"
outage="$(kubectl -n "${agents}" get pod agent-outage -o json)"
jq -e '(.metadata.annotations["fabric.singleaxis.ai/injected"] == null) and ((.spec.containers[0].env // []) | length == 0)' \
  <<<"${outage}" >/dev/null || fail "a pod admitted during the outage was changed"
kubectl -n "${agents}" logs agent-outage | sed -n '/^--- fabric status ---$/q;p' >"${tmp}/outage.stdout"
diff -u "${tmp}/agent-plain.stdout" "${tmp}/outage.stdout" || fail "the outage changed the agent's stdout"
printf '   admission with the injector down: %d ms\n' "${elapsed_ms}"
kubectl -n "${ns}" scale deployment "${release}-fabric-injector" --replicas=2 >/dev/null

# --- 5. upgrade keeps every Secret --------------------------------------------------
log "upgrade"
before="$(for pair in "${ns}/fabric-ca" "${ns}/fabric-node-receiver-tls" "${ns}/fabric-injector-tls" "${agents}/fabric-agent"; do
  secret_rv "${pair%%/*}" "${pair#*/}"; done)"
helm upgrade "${release}" "${chart}" -n "${ns}" "${values[@]}" --wait --timeout 5m >/dev/null
after="$(for pair in "${ns}/fabric-ca" "${ns}/fabric-node-receiver-tls" "${ns}/fabric-injector-tls" "${agents}/fabric-agent"; do
  secret_rv "${pair%%/*}" "${pair#*/}"; done)"
[[ "${before}" == "${after}" ]] || fail "an upgrade changed a generated Secret"
[[ -n "$(kubectl get mutatingwebhookconfiguration "fabric-injector-${ns}-${release}" -o jsonpath='{.webhooks[0].clientConfig.caBundle}')" ]] \
  || fail "the upgrade dropped the caBundle"

# --- 6. the workstation route (kubectl), production -----------------------------
log "fabric init --kubernetes --profile production"
kubectl create namespace "${prod}" >/dev/null
"${FABRIC}" init --kubernetes --profile production --namespace "${ns}" --release "${release}" \
  --agent-namespace "${prod}=support-bot" >"${tmp}/init.out"
grep -q "kept Secret ${ns}/fabric-ca" "${tmp}/init.out" || fail "the workstation route made another CA"
grep -q "created Secret ${prod}/fabric-agent" "${tmp}/init.out" || fail "no agent Secret for ${prod}"
token="$(secret_key "${ns}" "fabric-ingress-${prod}" token)"
[[ "$(secret_key "${prod}" fabric-agent headers)" == "Authorization=Bearer%20${token}" ]] \
  || fail "the ingress token and the agent's headers differ"
id_key="$(secret_key "${prod}" fabric-agent 'id\.key')"
expected="$(ID_KEY="${id_key}" python3 -c 'import hashlib, hmac, os
print("s-" + hmac.new(os.environ["ID_KEY"].encode(), b"support-bot", hashlib.sha256).hexdigest()[:32])')"
[[ "$(secret_key "${ns}" "fabric-ingress-${prod}" source-id)" == "${expected}" ]] || fail "the source id is not the SDK's"
for value in "${token}" "${id_key}"; do
  grep -Fq -- "${value}" "${tmp}/init.out" && fail "fabric init printed a secret value"
done
"${FABRIC}" init --kubernetes --render "${tmp}/render" --namespace "${ns}" --agent-namespace "${agents}" >/dev/null
[[ "$(stat -c %a "${tmp}/render" 2>/dev/null || stat -f %Lp "${tmp}/render")" == 700 ]] || fail "--render directory is not private"

# --- 7. uninstall keeps the Secrets ----------------------------------------------------
log "uninstall"
helm uninstall "${release}" -n "${ns}" --wait >/dev/null
kubectl -n "${ns}" get secret fabric-ca >/dev/null || fail "uninstall deleted the generated CA"
kubectl -n "${agents}" get secret fabric-agent >/dev/null || fail "uninstall deleted the agent Secret"
kubectl get mutatingwebhookconfiguration "fabric-injector-${ns}-${release}" >/dev/null 2>&1 \
  && fail "uninstall left the webhook configuration"

printf 'PASS: secrets Job, injector and webhook outage on a real cluster\n'
