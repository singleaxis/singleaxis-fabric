#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart_dir="$(cd "${script_dir}/.." && pwd)"
pass_count=0

pass() { pass_count=$((pass_count + 1)); printf 'ok %02d - %s\n' "${pass_count}" "$1"; }

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

render_ok() {
  local description="$1"; shift
  helm template fabric-test "$@" >/dev/null
  pass "${description}"
}

reject() {
  local description="$1" expected="$2"; shift 2
  local output
  if output="$(helm template fabric-invalid "$@" 2>&1)"; then
    printf 'not ok - %s: invalid posture rendered successfully\n' "${description}" >&2
    exit 1
  fi
  if ! grep -Fq -- "${expected}" <<<"${output}"; then
    printf 'not ok - %s: expected %q\n%s\n' "${description}" "${expected}" "${output}" >&2
    exit 1
  fi
  pass "${description}"
}

reject_any() {
  local description="$1"; shift
  if helm template fabric-invalid "$@" >/dev/null 2>&1; then
    printf 'not ok - %s: invalid posture rendered successfully\n' "${description}" >&2
    exit 1
  fi
  pass "${description}"
}

render_ok "default recorder renders" "${chart_dir}"
render_ok "shadow-dev renders" "${chart_dir}" --values "${chart_dir}/profiles/shadow-dev.yaml"
render_ok "shadow-production renders with customer-owned references" "${production_args[@]}"

reject "production requires tenant identity" "requires tenant.id" \
  "${chart_dir}" --values "${chart_dir}/profiles/shadow-production.yaml" \
  --set otel-collector.exporter.endpoint=https://otlp.example.invalid \
  --set 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true' \
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'
reject "production requires destination" "exporter.endpoint is empty" \
  "${chart_dir}" --values "${chart_dir}/profiles/shadow-production.yaml" --set tenant.id=test \
  --set 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'
reject "production requires explicit egress peer" "requires an operator-supplied networkPolicy.exporterEgress.to peer" \
  "${chart_dir}" --values "${chart_dir}/profiles/shadow-production.yaml" \
  --set tenant.id=test --set otel-collector.exporter.endpoint=https://otlp.example.invalid \
  --set 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'

reject "production requires explicit ingress peer" "requires an operator-supplied networkPolicy.ingressFrom peer" \
  "${chart_dir}" --values "${chart_dir}/profiles/shadow-production.yaml" \
  --set tenant.id=test --set otel-collector.exporter.endpoint=https://otlp.example.invalid \
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'

for case in \
  'unknown classes:otel-collector.fabric.guard.dropUnknownClasses:false' \
  'receiver TLS:otel-collector.receiver.requireTLS:false' \
  'client certificates:otel-collector.receiver.requireClientCertificate:false' \
  'HTTPS egress:otel-collector.exporter.requireTLS:false' \
  'authenticated egress:otel-collector.exporter.requireAuth:false' \
  'durable queue:otel-collector.exporter.requireDurableQueue:false' \
  'block on overflow:otel-collector.exporter.sendingQueue.blockOnOverflow:false' \
  'fsync:otel-collector.exporter.sendingQueue.persistence.fsync:false' \
  'indefinite retry:otel-collector.exporter.retry.maxElapsedTime:5m' \
  'pre-queue batching:otel-collector.batch.enabled:true' \
  'removed sampler surface:otel-collector.fabric.sampler.enabled:true' \
  'debug off:otel-collector.debugExporter.enabled:true' \
  'explicit ingress:otel-collector.networkPolicy.requireExplicitIngress:false' \
  'cluster-internal service:otel-collector.service.type:NodePort' \
  'non-root pod:otel-collector.podSecurityContext.runAsNonRoot:false' \
  'no privilege escalation:otel-collector.securityContext.allowPrivilegeEscalation:true' \
  'pinned image tag:otel-collector.image.tag:latest' \
  'deny-default:networkPolicy.denyDefault:false'; do
  IFS=: read -r label path value <<<"${case}"
  reject_any "production pins ${label}" \
    "${production_args[@]}" --set "${path}=${value}"
done

reject "production pins the Collector Service to ClusterIP" "otel-collector.service.type" \
  "${production_args[@]}" --set otel-collector.service.type=LoadBalancer
reject "production rejects an empty image tag" "pinned Collector image" \
  "${production_args[@]}" --set otel-collector.image.tag=
# An empty ingress peer must not merge with the indexed --set used in
# production_args, so this case passes the full flag set explicitly.
reject "production rejects an empty ingress peer" "empty peer" \
  "${chart_dir}" --values "${chart_dir}/profiles/shadow-production.yaml" \
  --set tenant.id=customer-production \
  --set otel-collector.exporter.endpoint=https://otlp.example.invalid \
  --set-json 'otel-collector.networkPolicy.ingressFrom=[{}]' \
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'
reject "production rejects a world ingress CIDR" "world CIDR" \
  "${production_args[@]}" --set 'otel-collector.networkPolicy.ingressFrom[0].ipBlock.cidr=0.0.0.0/0'
reject "production rejects a world exporter egress CIDR" "world CIDR" \
  "${production_args[@]}" --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=0.0.0.0/0'
reject "production rejects an empty egressTo peer" "empty peer" \
  "${production_args[@]}" --set-json 'otel-collector.networkPolicy.egressTo=[{}]'
reject "production rejects an unscoped health-port selector" "monitoringNamespaceSelector" \
  "${production_args[@]}" --set-json 'otel-collector.networkPolicy.monitoringNamespaceSelector={"matchLabels":{}}'
render_ok "a digest pin satisfies image identity" \
  "${production_args[@]}" --set otel-collector.image.tag= \
  --set otel-collector.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000

reject_any "production rejects custom log-field allowlist extensions" \
  "${production_args[@]}" \
  --set 'otel-collector.fabric.guard.extraAllowedFields.activity[0]=customer.region'
reject_any "production rejects custom trace-field allowlist extensions" \
  "${production_args[@]}" \
  --set 'otel-collector.fabric.guard.extraAllowedTraceFields[0]=customer.region'

printf 'PASS: %d Fabric Node profile checks\n' "${pass_count}"
"${script_dir}/test-package-boundary.sh"
