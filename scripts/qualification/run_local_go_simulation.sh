#!/usr/bin/env bash
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
# Synthetic laptop rehearsal only. Never issues a customer production GO.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
: "${FABRIC_SIM_KUBECONFIG:?set to the dedicated local kind kubeconfig}"
: "${FABRIC_SIM_CLUSTER:?set to the exact local kind cluster name}"
test -f "$FABRIC_SIM_KUBECONFIG"
test "$(kubectl --kubeconfig "$FABRIC_SIM_KUBECONFIG" config current-context)" = "kind-${FABRIC_SIM_CLUSTER}"
kind get clusters | grep -Fxq "$FABRIC_SIM_CLUSTER"
test -z "$(git status --porcelain)" || {
  echo 'simulation requires a clean, frozen source commit' >&2
  exit 1
}
for command in docker kind kubectl helm openssl curl jq uv python3.11 shasum; do
  command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 1; }
done

umask 077
evidence_dir="$(mktemp -d /private/tmp/fabric-go-sim.XXXXXX)"
namespace="fabric-sim-$(openssl rand -hex 3)"
commit="$(git rev-parse HEAD)"
tag="sim-${commit:0:12}-$(openssl rand -hex 2)"
image="fabric-otelcol:${tag}"
node_port="$(python3.11 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
sink_port="$(python3.11 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
while [[ "$sink_port" == "$node_port" ]]; do
  sink_port="$(python3.11 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
done
node_forward=''
sink_forward=''
cleanup() {
  result=$?
  if [[ -n "$node_forward" ]]; then kill "$node_forward" 2>/dev/null || true; fi
  if [[ -n "$sink_forward" ]]; then kill "$sink_forward" 2>/dev/null || true; fi
  if [[ "$result" -ne 0 ]]; then
    printf 'FAIL: rehearsal stopped; production verdict remains NO_GO\n' >&2
    printf 'Evidence directory: %s\nNamespace: %s\n' "$evidence_dir" "$namespace" >&2
  fi
}
trap cleanup EXIT
k() { kubectl --kubeconfig "$FABRIC_SIM_KUBECONFIG" "$@"; }

printf 'Evidence directory: %s\nNamespace: %s\nCandidate: %s\n' "$evidence_dir" "$namespace" "$commit"
k get nodes -o json > "$evidence_dir/nodes.json"
k -n kube-system get daemonset kindnet -o json > "$evidence_dir/kindnet.json"

docker build --platform linux/arm64 -t "$image" -f components/otel-collector-fabric/Dockerfile components/otel-collector-fabric
kind load docker-image "$image" --name "$FABRIC_SIM_CLUSTER"
helm package charts/fabric --destination "$evidence_dir"
chart="$(find "$evidence_dir" -maxdepth 1 -name 'fabric-*.tgz' -print -quit)"
test -n "$chart"
uv build --wheel sdk/python --out-dir "$evidence_dir/dist"
wheel="$(find "$evidence_dir/dist" -maxdepth 1 -name 'singleaxis_fabric-*.whl' -print -quit)"
test -n "$wheel"
uv venv --python 3.11 "$evidence_dir/venv"
uv pip install --python "$evidence_dir/venv/bin/python" "$wheel" 'opentelemetry-proto==1.44.0'

cert_dir="$evidence_dir/certs"
mkdir -m 700 "$cert_dir"
openssl req -x509 -newkey rsa:2048 -noenc -days 1 -subj '/CN=Fabric simulation ingress CA' -keyout "$cert_dir/ingress-ca.key" -out "$cert_dir/ingress-ca.crt" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -noenc -days 1 -subj '/CN=Fabric simulation sink CA' -keyout "$cert_dir/sink-ca.key" -out "$cert_dir/sink-ca.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -noenc -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' -addext 'extendedKeyUsage=serverAuth' -keyout "$cert_dir/node.key" -out "$cert_dir/node.csr" >/dev/null 2>&1
openssl x509 -req -in "$cert_dir/node.csr" -CA "$cert_dir/ingress-ca.crt" -CAkey "$cert_dir/ingress-ca.key" -CAcreateserial -days 1 -sha256 -copy_extensions copy -out "$cert_dir/node.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -noenc -subj '/CN=synthetic-simulation-client' -addext 'extendedKeyUsage=clientAuth' -keyout "$cert_dir/client.key" -out "$cert_dir/client.csr" >/dev/null 2>&1
openssl x509 -req -in "$cert_dir/client.csr" -CA "$cert_dir/ingress-ca.crt" -CAkey "$cert_dir/ingress-ca.key" -CAcreateserial -days 1 -sha256 -copy_extensions copy -out "$cert_dir/client.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -noenc -subj '/CN=fabric-test-sink' -addext 'subjectAltName=DNS:fabric-test-sink,DNS:localhost,IP:127.0.0.1' -addext 'extendedKeyUsage=serverAuth' -keyout "$cert_dir/sink.key" -out "$cert_dir/sink.csr" >/dev/null 2>&1
openssl x509 -req -in "$cert_dir/sink.csr" -CA "$cert_dir/sink-ca.crt" -CAkey "$cert_dir/sink-ca.key" -CAcreateserial -days 1 -sha256 -copy_extensions copy -out "$cert_dir/sink.crt" >/dev/null 2>&1
printf 'Bearer %s' "$(openssl rand -hex 32)" > "$cert_dir/authorization"

k create namespace "$namespace"
k -n "$namespace" create configmap fabric-test-sink --from-file=otlp_sink.py=deploy/compose/sink/otlp_sink.py
k -n "$namespace" create secret tls fabric-test-sink-tls --cert="$cert_dir/sink.crt" --key="$cert_dir/sink.key"
k -n "$namespace" create secret generic fabric-test-sink-auth --from-file=authorization="$cert_dir/authorization"
k -n "$namespace" create secret tls fabric-node-receiver-tls --cert="$cert_dir/node.crt" --key="$cert_dir/node.key"
k -n "$namespace" create secret generic fabric-node-client-ca --from-file=ca.crt="$cert_dir/ingress-ca.crt"
k -n "$namespace" create secret generic fabric-test-sink-ca --from-file=ca.crt="$cert_dir/sink-ca.crt"
k -n "$namespace" create secret generic fabric-node-export-auth --from-file=authorization="$cert_dir/authorization"
for manifest in qualification/synthetic-slice/kind-production-sink-*.yaml; do
  k -n "$namespace" apply -f "$manifest"
done
k -n "$namespace" rollout status deployment/fabric-test-sink --timeout=180s
helm install fabric-sim "$chart" --kubeconfig "$FABRIC_SIM_KUBECONFIG" --namespace "$namespace" --values charts/fabric/profiles/shadow-production.yaml --values qualification/synthetic-slice/kind-production-values.yaml --set tenant.id=synthetic-tenant --set "otel-collector.image.tag=$tag" --wait --timeout 5m
k -n "$namespace" wait --for=condition=ready pods -l app.kubernetes.io/name=otel-collector --timeout=300s
k -n "$namespace" get pvc -o yaml > "$evidence_dir/pvcs.yaml"

k -n "$namespace" port-forward "service/fabric-sim-otel-collector" "$node_port:4318" > "$evidence_dir/node-forward.log" 2>&1 &
node_forward=$!
k -n "$namespace" port-forward service/fabric-test-sink "$sink_port:8443" > "$evidence_dir/sink-forward.log" 2>&1 &
sink_forward=$!
for _attempt in $(seq 1 30); do
  if curl -fsS --cacert "$cert_dir/sink-ca.crt" "https://localhost:$sink_port/health" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS --cacert "$cert_dir/sink-ca.crt" "https://localhost:$sink_port/health" >/dev/null
if curl -fsS --cacert "$cert_dir/ingress-ca.crt" -X POST "https://localhost:$node_port/v1/logs" -H 'Content-Type: application/json' -d '{}' > "$evidence_dir/no-client-response.log" 2>&1; then
  echo 'unauthenticated client was accepted' >&2; exit 1
fi
# On some kind/kubectl versions a rejected TLS handshake also terminates
# port-forward. Start a fresh forward before the authorized client probe.
kill "$node_forward" 2>/dev/null || true
wait "$node_forward" 2>/dev/null || true
k -n "$namespace" port-forward "service/fabric-sim-otel-collector" "$node_port:4318" >> "$evidence_dir/node-forward.log" 2>&1 &
node_forward=$!
sleep 2
# A Node HTTP acceptance is not a sink receipt. With the namespace default
# deny active and no sink-ingress allowance yet, this synthetic audit probe
# must queue rather than arrive. Its non-evidence ID is ignored by the later
# exact AEEP record verifier.
probe='{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"synthetic policy probe"},"attributes":[{"key":"event_class","value":{"stringValue":"audit"}},{"key":"audit.syscall","value":{"stringValue":"execve"}},{"key":"audit.source","value":{"stringValue":"logfile"}},{"key":"record_id","value":{"stringValue":"sim-policy-probe"}}]}]}]}]}'
count_before="$(curl -fsS --cacert "$cert_dir/sink-ca.crt" "https://localhost:$sink_port/count" | jq -r .count)"
test "$count_before" -eq 0
curl -fsS --cacert "$cert_dir/ingress-ca.crt" --cert "$cert_dir/client.crt" --key "$cert_dir/client.key" -H 'Content-Type: application/json' --data-binary "$probe" "https://localhost:$node_port/v1/logs" > "$evidence_dir/node-probe-ack.json"
sleep 3
count_blocked="$(curl -fsS --cacert "$cert_dir/sink-ca.crt" "https://localhost:$sink_port/count" | jq -r .count)"
test "$count_blocked" -eq 0 || { echo 'default-deny did not block sink ingress' >&2; exit 1; }
k -n "$namespace" apply -f qualification/local-go-simulation/sink-ingress-policy.yaml
k -n "$namespace" get networkpolicy -o yaml > "$evidence_dir/network-policies.yaml"
count_allowed=0
for _attempt in $(seq 1 60); do
  count_allowed="$(curl -fsS --cacert "$cert_dir/sink-ca.crt" "https://localhost:$sink_port/count" | jq -r .count)"
  if [[ "$count_allowed" -gt 0 ]]; then break; fi
  sleep 1
done
test "$count_allowed" -gt 0 || { echo 'queued probe did not reach fsynced sink after policy allowance' >&2; exit 1; }
printf '{"blocked_before":%s,"delivered_after":%s}\n' "$count_blocked" "$count_allowed" > "$evidence_dir/policy-probe.json"

"$evidence_dir/venv/bin/python" scripts/qualification/run_synthetic_agent_pilot.py \
  --node-url "https://localhost:$node_port/v1/logs" --node-ca "$cert_dir/ingress-ca.crt" \
  --node-cert "$cert_dir/client.crt" --node-key "$cert_dir/client.key" \
  --sink-url "https://localhost:$sink_port" --sink-ca "$cert_dir/sink-ca.crt" \
  --report-path "$evidence_dir/pilot-report.json" \
  --work-dir "$evidence_dir/pilot-work"
sink_pod="$(k -n "$namespace" get pod -l app=fabric-test-sink -o jsonpath='{.items[0].metadata.name}')"
k -n "$namespace" cp "$sink_pod:/data" "$evidence_dir/sink-data"
"$evidence_dir/venv/bin/python" scripts/qualification/verify_synthetic_sink_readback.py \
  --report-path "$evidence_dir/pilot-report.json" --sink-dir "$evidence_dir/sink-data"
k -n "$namespace" logs -l app.kubernetes.io/name=otel-collector --tail=-1 > "$evidence_dir/node.log"
if grep -RFq 'PILOT_SECRET_CANARY_do_not_export' "$evidence_dir/sink-data" "$evidence_dir/node.log"; then
  echo 'privacy canary crossed the allowed content boundary' >&2; exit 1
fi

shasum -a 256 "$wheel" "$chart" charts/fabric/profiles/shadow-production.yaml qualification/synthetic-slice/kind-production-values.yaml > "$evidence_dir/artifact-sha256.txt"
python3.11 - "$evidence_dir/artifacts.json" "$commit" "$wheel" "$chart" "$image" "$FABRIC_SIM_CLUSTER" "$namespace" <<'PY'
import hashlib, json, pathlib, subprocess, sys
output, commit, wheel, chart, image, cluster, namespace = sys.argv[1:]
digest = lambda path: hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
image_id = subprocess.check_output(["docker", "image", "inspect", image, "--format", "{{.Id}}"], text=True).strip()
pathlib.Path(output).write_text(json.dumps({"git_commit": commit, "wheel_sha256": digest(wheel), "chart_sha256": digest(chart), "node_image_id": image_id, "cluster": cluster, "namespace": namespace, "local_policy_probe_passed": True, "target_network_policy_qualified": False, "storage": "kind-local-path-simulation-only"}, indent=2, sort_keys=True) + "\n")
PY
python3.11 scripts/qualification/summarize_local_go_simulation.py \
  --scope qualification/synthetic-slice/scope.v1.json \
  --pilot-report "$evidence_dir/pilot-report.json" \
  --artifacts "$evidence_dir/artifacts.json" \
  --output "$evidence_dir/decision.json"
printf 'Rehearsal complete: %s\nNamespace retained for inspection: %s\n' "$evidence_dir" "$namespace"
