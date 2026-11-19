#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart_dir="$(cd "${here}/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

archive="$(helm package "${chart_dir}" --destination "${tmp}" | sed -n 's/^Successfully packaged chart and saved it to: //p')"
[[ -n "${archive}" && -f "${archive}" ]]

listing="$(tar -tzf "${archive}")"
for forbidden_path in \
  'charts/nemo-sidecar' 'charts/presidio-sidecar' 'charts/langfuse' \
  'charts/redteam-runner' 'charts/update-agent' 'charts/fabric-relay' \
  'policy-configmap.yaml'; do
  if grep -Fq -- "${forbidden_path}" <<<"${listing}"; then
    printf 'FAIL: release package contains %s\n' "${forbidden_path}" >&2
    exit 1
  fi
done

mkdir "${tmp}/unpacked"
tar -xzf "${archive}" -C "${tmp}/unpacked"
for forbidden_config in \
  'fabricpolicy:' 'fabricredact:' 'fabricsampler:' \
  'ghcr.io/singleaxis/fabric-presidio-sidecar' \
  'name: presidio-redactor' 'name: sampler-key' 'name: policy-bundle'; do
  if grep -R -Fq -- "${forbidden_config}" "${tmp}/unpacked"; then
    printf 'FAIL: release package contains legacy deployment surface %s\n' "${forbidden_config}" >&2
    exit 1
  fi
done

if ! grep -Fq 'fabric/charts/otel-collector/Chart.yaml' <<<"${listing}"; then
  printf 'FAIL: Collector dependency is missing from release package\n' >&2
  exit 1
fi

# Spec 058 §10.4: the injector's autoload shim ships in the package (a ConfigMap
# renders it into each agent namespace).
if ! grep -Fxq 'fabric/files/autoload/sitecustomize.py' <<<"${listing}"; then
  printf 'FAIL: the package lacks the injector autoload shim\n' >&2
  exit 1
fi

if ! grep -Fxq 'fabric/charts/otel-collector/templates/tests/test-connection.yaml' <<<"${listing}"; then
  printf 'FAIL: packaged Collector health-test hook is missing\n' >&2
  exit 1
fi
if grep -Eq '^fabric/(tests/|charts/otel-collector/tests/)' <<<"${listing}"; then
  printf 'FAIL: package includes chart development tests\n' >&2
  exit 1
fi

# Spec 056 OD-10: no default render carries a privileged workload. The auditd
# sensor collector stays a customer-deployed example (deploy/kubernetes/), as
# the eBPF DaemonSet template does beside the chart's opt-in sensor (below). No
# render of the packaged chart without the host sensor, the host-ingress
# profile included, holds a DaemonSet, a
# host namespace, a hostPath volume, a privileged or root container, an added
# capability or an audit receiver.
packaged="${tmp}/unpacked/fabric"
fixtures="${chart_dir}/charts/otel-collector/tests/fixtures/source-bindings"
if [[ ! -f "${packaged}/profiles/shadow-production-host-ingress.yaml" ]]; then
  printf 'FAIL: release package lacks the host-ingress profile\n' >&2
  exit 1
fi
production=(
  --values "${packaged}/profiles/shadow-production.yaml"
  --values "${chart_dir}/tests/fixtures/production-assertions.yaml"
  --set tenant.id=customer-production
  --set otel-collector.exporter.endpoint=https://otlp.example.invalid
  --set-string 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'
)
{
  helm template boundary "${packaged}"
  printf -- '---\n'
  helm template boundary "${packaged}" --values "${packaged}/profiles/shadow-dev.yaml"
  printf -- '---\n'
  helm template boundary "${packaged}" "${production[@]}"
  printf -- '---\n'
  helm template boundary "${packaged}" \
    --values "${packaged}/profiles/shadow-production.yaml" \
    --values "${packaged}/profiles/shadow-production-host-ingress.yaml" \
    --values "${fixtures}/common.yaml" --values "${fixtures}/agent-ebpf-auditd.yaml"
  printf -- '---\n'
  # Spec 058 §10.2-10.4: the secrets hook Jobs and the opt-in injector.
  helm template boundary "${packaged}" --set preset=local --set 'agentNamespaces={agents}' \
    --set injector.enabled=true
  printf -- '---\n'
  helm template boundary "${packaged}" --set preset=production "${production[@]:2}" \
    --set 'agentNamespaces={agents}' --set injector.enabled=true
} >"${tmp}/renders.yaml"
python3 - "${tmp}/renders.yaml" <<'PY'
import sys

import yaml

failures = []
for doc in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")):
    if not doc:
        continue
    kind, name = doc.get("kind"), doc.get("metadata", {}).get("name")
    where = f"{kind}/{name}"
    if kind == "DaemonSet":
        failures.append(f"{where}: a DaemonSet")
    if kind == "ConfigMap":
        config = yaml.safe_load((doc.get("data") or {}).get("config.yaml") or "{}") or {}
        if any(r.split("/", 1)[0] == "audit" for r in config.get("receivers") or {}):
            failures.append(f"{where}: an audit receiver")
    spec = doc.get("spec") or {}
    pod = spec if kind == "Pod" else (spec.get("template") or {}).get("spec")
    if not isinstance(pod, dict):
        continue
    for field in ("hostPID", "hostNetwork", "hostIPC"):
        if pod.get(field):
            failures.append(f"{where}: {field}")
    if any("hostPath" in v for v in pod.get("volumes") or []):
        failures.append(f"{where}: a hostPath volume")
    for c in (pod.get("containers") or []) + (pod.get("initContainers") or []):
        security = c.get("securityContext") or {}
        if security.get("privileged") or (security.get("capabilities") or {}).get("add"):
            failures.append(f"{where}/{c.get('name')}: privileged or added capabilities")
        if security.get("runAsUser") == 0 or security.get("allowPrivilegeEscalation") is not False:
            failures.append(f"{where}/{c.get('name')}: root or privilege escalation")
for failure in failures:
    print(f"FAIL: the packaged chart renders {failure}", file=sys.stderr)
sys.exit(1 if failures else 0)
PY

# Spec 058 §10.5 takes OD-10's fallback: the host sensor DaemonSet, opt-in
# (hostSensor.enabled, the production-host-sensor preset). It is the only host
# workload of the release and never privileged: hostPID, root, the four
# capabilities eBPF needs and read-only host mounts (its own state directory
# aside); no host network or IPC, no privilege escalation.
helm template boundary "${packaged}" --set preset=production-host-sensor "${production[@]:2}" \
  --set 'agentNamespaces={agents}' --set injector.enabled=true --set 'hostSensor.nodes={node-a}' \
  --set otel-collector.image.digest="sha256:$(printf 'a%.0s' $(seq 64))" >"${tmp}/sensor.yaml"
python3 - "${tmp}/sensor.yaml" <<'PY'
import sys

import yaml

docs = [d for d in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")) if d]
failures = []
sets = [d for d in docs if d.get("kind") == "DaemonSet"]
if len(sets) != 1 or sets[0]["metadata"]["labels"].get("app.kubernetes.io/component") != "host-sensor":
    failures.append(f"want exactly the host sensor DaemonSet, got {[d['metadata']['name'] for d in sets]}")
for doc in docs:
    spec = doc.get("spec") or {}
    pod = (spec.get("template") or {}).get("spec") if isinstance(spec, dict) else None
    if not isinstance(pod, dict):
        continue
    where = f"{doc['kind']}/{doc['metadata']['name']}"
    sensor = doc in sets
    if pod.get("hostNetwork") or pod.get("hostIPC") or (pod.get("hostPID") and not sensor):
        failures.append(f"{where}: a host namespace")
    for c in (pod.get("containers") or []) + (pod.get("initContainers") or []):
        security = c.get("securityContext") or {}
        added = sorted((security.get("capabilities") or {}).get("add") or [])
        if security.get("privileged"):
            failures.append(f"{where}/{c['name']}: privileged")
        if security.get("allowPrivilegeEscalation") is not False:
            failures.append(f"{where}/{c['name']}: privilege escalation")
        if added and (not sensor or added != ["BPF", "DAC_READ_SEARCH", "PERFMON", "SYS_RESOURCE"]):
            failures.append(f"{where}/{c['name']}: capabilities {added}")
    if not sensor:
        if any("hostPath" in v for v in pod.get("volumes") or []):
            failures.append(f"{where}: a hostPath volume")
        continue
    host = {v["name"] for v in pod.get("volumes") or [] if "hostPath" in v}
    for c in pod.get("containers") or []:
        for m in c.get("volumeMounts") or []:
            if m["name"] in host and not m.get("readOnly") and m["name"] != "state":
                failures.append(f"{where}/{c['name']}: host mount {m['name']} is writable")
for failure in failures:
    print(f"FAIL: the host sensor render: {failure}", file=sys.stderr)
sys.exit(1 if failures else 0)
PY

printf 'PASS: packaged Fabric Node contains only the Collector recorder dependency\n'
