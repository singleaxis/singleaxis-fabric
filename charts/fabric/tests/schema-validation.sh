#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart_dir="$(cd "${script_dir}/.." && pwd)"
pass_count=0

pass() { pass_count=$((pass_count + 1)); printf 'ok %02d - %s\n' "${pass_count}" "$1"; }

production_args=(
  "${chart_dir}"
  --values "${chart_dir}/profiles/shadow-production.yaml" --values "${chart_dir}/tests/fixtures/production-assertions.yaml"
  --set tenant.id=customer-production
  --set otel-collector.exporter.endpoint=https://otlp.example.invalid
  --set-string 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'
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
  "${chart_dir}" --values "${chart_dir}/profiles/shadow-production.yaml" --values "${chart_dir}/tests/fixtures/production-assertions.yaml" \
  --set otel-collector.exporter.endpoint=https://otlp.example.invalid \
  --set-string 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true' \
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'
reject "production requires destination" "exporter.endpoint is empty" \
  "${chart_dir}" --values "${chart_dir}/profiles/shadow-production.yaml" --values "${chart_dir}/tests/fixtures/production-assertions.yaml" --set tenant.id=customer-production \
  --set-string 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'
reject "production requires explicit egress peer" "requires an operator-supplied networkPolicy.exporterEgress.to peer" \
  "${chart_dir}" --values "${chart_dir}/profiles/shadow-production.yaml" --values "${chart_dir}/tests/fixtures/production-assertions.yaml" \
  --set tenant.id=customer-production --set otel-collector.exporter.endpoint=https://otlp.example.invalid \
  --set-string 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'

reject "production requires explicit ingress peer" "requires an operator-supplied networkPolicy.ingressFrom peer" \
  "${chart_dir}" --values "${chart_dir}/profiles/shadow-production.yaml" --values "${chart_dir}/tests/fixtures/production-assertions.yaml" \
  --set tenant.id=customer-production --set otel-collector.exporter.endpoint=https://otlp.example.invalid \
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
  'content encryption:otel-collector.content.requireServerSideEncryption:false' \
  'explicit ingress:otel-collector.networkPolicy.requireExplicitIngress:false' \
  'cluster-internal service:otel-collector.service.type:NodePort' \
  'non-root pod:otel-collector.podSecurityContext.runAsNonRoot:false' \
  'no privilege escalation:otel-collector.securityContext.allowPrivilegeEscalation:true' \
  'immutable image digest:otel-collector.image.digest:' \
  'deny-default:networkPolicy.denyDefault:false'; do
  IFS=: read -r label path value <<<"${case}"
  reject_any "production pins ${label}" \
    "${production_args[@]}" --set "${path}=${value}"
done

reject "production pins the Collector Service to ClusterIP" "otel-collector.service.type" \
  "${production_args[@]}" --set otel-collector.service.type=LoadBalancer
reject "production rejects tag-only image identity" "pinned Collector image" \
  "${production_args[@]}" --set otel-collector.image.tag=release-1 --set otel-collector.image.digest=
# An empty ingress peer must not merge with the indexed --set used in
# production_args, so this case passes the full flag set explicitly.
reject "production rejects an empty ingress peer" "empty peer" \
  "${chart_dir}" --values "${chart_dir}/profiles/shadow-production.yaml" --values "${chart_dir}/tests/fixtures/production-assertions.yaml" \
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

# Spec 048 §7: the Node counterpart of FABRIC_WIRE_MODEL_ALLOWLIST is a
# production-compatible extension that reaches fabricguard unchanged.
model_config="$(helm template fabric-test "${production_args[@]}" \
  --set 'otel-collector.fabric.guard.captureModelAllowlist[0]=acme-chat-v1' \
  --set 'otel-collector.fabric.guard.captureModelAllowlist[1]=acme-*')"
if ! grep -A2 -F 'capture_model_allowlist:' <<<"${model_config}" | grep -Fq -- '- acme-*'; then
  printf 'not ok - captureModelAllowlist is not rendered into fabricguard\n' >&2
  exit 1
fi
pass "production passes captureModelAllowlist to fabricguard"
reject_any "captureModelAllowlist entries must be non-empty strings" \
  "${production_args[@]}" --set-json 'otel-collector.fabric.guard.captureModelAllowlist=[""]'

# Spec 048 J1: fabricguard admits only pseudonymous capture labels unless the
# operator opts in to clear labels (the Node side of FABRIC_WIRE_LABELS=clear).
labels_default="$(helm template fabric-test "${production_args[@]}")"
if ! grep -Fq 'capture_labels: "pseudonymous"' <<<"${labels_default}"; then
  printf 'not ok - fabricguard does not default to pseudonymous capture labels\n' >&2
  exit 1
fi
pass "production renders capture_labels: pseudonymous by default"
labels_clear="$(helm template fabric-test "${production_args[@]}" \
  --set otel-collector.fabric.guard.captureLabels=clear)"
if ! grep -Fq 'capture_labels: "clear"' <<<"${labels_clear}"; then
  printf 'not ok - captureLabels=clear is not rendered into fabricguard\n' >&2
  exit 1
fi
pass "captureLabels=clear reaches fabricguard"
reject_any "captureLabels accepts only pseudonymous or clear" \
  "${production_args[@]}" --set otel-collector.fabric.guard.captureLabels=plain

printf 'PASS: %d Fabric Node profile checks\n' "${pass_count}"
"${script_dir}/test-package-boundary.sh"
