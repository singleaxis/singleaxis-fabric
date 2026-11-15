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

# Spec 056 OD-10: the package carries no privileged workload. The eBPF emitter
# and the auditd sensor collector are customer-deployed examples
# (deploy/kubernetes/); the chart adds only their ingress groups. No render of
# the packaged chart, the host-ingress profile included, holds a DaemonSet, a
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

printf 'PASS: packaged Fabric Node contains only the Collector recorder dependency\n'
