#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart_dir="$(cd "${script_dir}/.." && pwd)"
collector_dir="${chart_dir}/charts/otel-collector"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

expect_failure() {
  local description="$1" expected="$2"
  shift 2
  local output
  if output="$(helm template invalid "$@" 2>&1)"; then
    fail "${description}: invalid values rendered successfully"
  fi
  [[ "${output}" == *"${expected}"* ]] || {
    printf '%s\n' "${output}" >&2
    fail "${description}: expected '${expected}'"
  }
}

production_args=(
  "${chart_dir}"
  --values "${chart_dir}/profiles/shadow-production.yaml"
  --set tenant.id=customer-production
  --set otel-collector.exporter.endpoint=https://otlp.example.invalid
  --set 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'
)

helm lint "${chart_dir}" >/dev/null
helm lint "${collector_dir}" >/dev/null
helm template defaults "${chart_dir}" >/dev/null
helm template dev "${chart_dir}" --values "${chart_dir}/profiles/shadow-dev.yaml" >/dev/null
helm template production "${production_args[@]}" >/dev/null

expect_failure "removed guardrail toggle" "nemoSidecar" \
  "${chart_dir}" --set nemoSidecar.enabled=true
expect_failure "unknown Collector value" "requireTlS" \
  "${chart_dir}" --set otel-collector.exporter.requireTlS=true
expect_failure "invalid queue size" "queueSize" \
  "${collector_dir}" --set exporter.sendingQueue.queueSize=unbounded
expect_failure "invalid OTLP port" "otlpHttp" \
  "${collector_dir}" --set service.ports.otlpHttp=0

printf 'PASS: Fabric Node and Collector values schemas\n'
