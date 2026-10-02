#!/usr/bin/env bash
# Static render contract for secure, durable OTLP delivery.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart_dir="$(cd "${here}/.." && pwd)"
umbrella_dir="$(cd "${chart_dir}/../.." && pwd)"
profile="${umbrella_dir}/profiles/shadow-production.yaml"

passed=0
failed=0

pass() { printf 'ok: %s\n' "$*"; passed=$((passed + 1)); }
fail() { printf 'FAIL: %s\n' "$*" >&2; failed=$((failed + 1)); }

expect_contains() {
  local label="$1" haystack="$2" needle="$3"
  if grep -q -F -- "${needle}" <<<"${haystack}"; then
    pass "${label}"
  else
    fail "${label}: missing '${needle}'"
  fi
}

expect_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if grep -q -F -- "${needle}" <<<"${haystack}"; then
    fail "${label}: unexpectedly found '${needle}'"
  else
    pass "${label}"
  fi
}

expect_fail() {
  local label="$1" needle="$2"
  shift 2
  local output
  if output="$(helm template ci "${chart_dir}" "$@" 2>&1)"; then
    fail "${label}: render unexpectedly succeeded"
  elif [[ "${output}" != *"${needle}"* ]]; then
    fail "${label}: expected '${needle}', got: ${output}"
  else
    pass "${label}"
  fi
}

printf '\n=== Default and in-memory delivery ===\n'
default_render="$(helm template ci "${chart_dir}")"
expect_contains "default workload is a Deployment" "${default_render}" "kind: Deployment"
expect_not_contains "default has no file-storage extension" "${default_render}" "file_storage/fabric"
expect_not_contains "default has no queue PVC" "${default_render}" "volumeClaimTemplates:"
expect_contains "collector has startup probe" "${default_render}" "startupProbe:"

memory_render="$(helm template ci "${chart_dir}" \
  --set exporter.endpoint=https://otlp.example.com \
  --set exporter.insecure=false)"
expect_contains "in-memory queue is explicit" "${memory_render}" "sending_queue:"
expect_contains "in-memory queue is enabled" "${memory_render}" "enabled: true"
expect_not_contains "in-memory queue has no storage binding" "${memory_render}" "storage: file_storage/fabric"

printf '\n=== Production persistent delivery ===\n'
regulated_args=(
  --set exporter.endpoint=https://otlp.example.com
  --set exporter.requireEndpoint=true
  --set exporter.requireTLS=true
  --set exporter.insecure=false
  --set exporter.requireAuth=true
  --set exporter.auth.secret.name=fabric-otel-export-auth
  --set exporter.requireDurableQueue=true
  --set exporter.sendingQueue.persistence.enabled=true
  --set exporter.sendingQueue.persistence.fsync=true
  --set exporter.sendingQueue.blockOnOverflow=true
  --set exporter.retry.maxElapsedTime=0s
  --set batch.enabled=false
  --set replicaCount=2
)
regulated_render="$(helm template ci "${chart_dir}" "${regulated_args[@]}")"
expect_contains "persistence switches to StatefulSet" "${regulated_render}" "kind: StatefulSet"
expect_contains "one PVC template is rendered per replica" "${regulated_render}" "volumeClaimTemplates:"
expect_contains "PVCs are retained" "${regulated_render}" "whenDeleted: Retain"
expect_contains "file storage extension is configured" "${regulated_render}" "file_storage/fabric:"
expect_contains "file storage requests fsync" "${regulated_render}" "fsync: true"
expect_contains "queue binds file storage" "${regulated_render}" "storage: file_storage/fabric"
expect_contains "fsGroup lets the nonroot Collector write the queue PVC" "${regulated_render}" "fsGroup: 65532"
expect_contains "full queue backpressures senders" "${regulated_render}" "block_on_overflow: true"
expect_contains "transient retry has no time limit" "${regulated_render}" 'max_elapsed_time: "0s"'
expect_not_contains "durable path has no volatile pre-queue batch" "${regulated_render}" "batch:"
expect_contains "TLS verification is enabled" "${regulated_render}" "insecure_skip_verify: false"
expect_contains "credential comes from Secret" "${regulated_render}" "name: fabric-otel-export-auth"
expect_contains "ConfigMap references env provider" "${regulated_render}" "\${env:FABRIC_EXPORT_AUTH}"
expect_not_contains "credential value is not in ConfigMap" "${regulated_render}" "Bearer "

existing_render="$(helm template ci "${chart_dir}" \
  --set exporter.endpoint=https://otlp.example.com \
  --set exporter.insecure=false \
  --set exporter.sendingQueue.persistence.enabled=true \
  --set exporter.sendingQueue.persistence.existingClaim=preprovisioned-queue)"
expect_contains "existing claim is mounted" "${existing_render}" "claimName: preprovisioned-queue"
expect_not_contains "existing claim does not create claim template" "${existing_render}" "volumeClaimTemplates:"

printf '\n=== Fail-loud unsafe combinations ===\n'
expect_fail "TLS requirement rejects HTTP" "requires an https://" \
  --set exporter.endpoint=http://otlp.example.com \
  --set exporter.requireTLS=true \
  --set exporter.insecure=false
expect_fail "TLS requirement rejects insecure transport" "requires exporter.insecure=false" \
  --set exporter.endpoint=https://otlp.example.com \
  --set exporter.requireTLS=true
expect_fail "TLS requirement rejects skip-verify" "rejects exporter.insecureSkipVerify=true" \
  --set exporter.endpoint=https://otlp.example.com \
  --set exporter.requireTLS=true \
  --set exporter.insecure=false \
  --set exporter.insecureSkipVerify=true
expect_fail "required auth needs a Secret" "requires exporter.auth.secret.name" \
  --set exporter.endpoint=https://otlp.example.com \
  --set exporter.requireAuth=true
expect_fail "persistent queue needs an endpoint" "requires exporter.endpoint" \
  --set exporter.sendingQueue.persistence.enabled=true
expect_fail "persistent queue needs queueing" "requires exporter.sendingQueue.enabled=true" \
  --set exporter.endpoint=https://otlp.example.com \
  --set exporter.sendingQueue.persistence.enabled=true \
  --set exporter.sendingQueue.enabled=false
expect_fail "one existing claim cannot be shared" "can only be used with replicaCount=1" \
  --set exporter.endpoint=https://otlp.example.com \
  --set exporter.sendingQueue.persistence.enabled=true \
  --set exporter.sendingQueue.persistence.existingClaim=shared-queue \
  --set replicaCount=2
expect_fail "durability contract needs persistent queue" "requires an enabled persistent sending queue" \
  --set exporter.endpoint=https://otlp.example.com \
  --set exporter.requireDurableQueue=true
expect_fail "durability contract needs fsync" "requires exporter.sendingQueue.persistence.fsync=true" \
  --set exporter.endpoint=https://otlp.example.com \
  --set exporter.requireDurableQueue=true \
  --set exporter.sendingQueue.persistence.enabled=true \
  --set exporter.sendingQueue.blockOnOverflow=true \
  --set exporter.retry.maxElapsedTime=0s
expect_fail "durability contract rejects volatile pre-queue batching" "requires batch.enabled=false" \
  "${regulated_args[@]}" --set batch.enabled=true

printf '\n=== Shadow production profile ===\n'
profile_render="$(helm template ci "${umbrella_dir}" \
  --values "${profile}" --values "${umbrella_dir}/tests/fixtures/production-assertions.yaml" \
  --set tenant.id=customer-production \
  --set otel-collector.exporter.endpoint=https://otlp.example.com \
  --set 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true' \
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443')"
expect_contains "profile renders a durable StatefulSet" "${profile_render}" "kind: StatefulSet"
expect_contains "profile renders two replicas" "${profile_render}" "replicas: 2"
expect_contains "profile references export credential" "${profile_render}" "name: fabric-node-export-auth"

if helm template ci "${umbrella_dir}" \
  --values "${profile}" --values "${umbrella_dir}/tests/fixtures/production-assertions.yaml" \
  --set tenant.id=customer-production \
  --set otel-collector.exporter.endpoint=http://otlp.example.com \
  --set 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true' \
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443' >/dev/null 2>&1; then
  fail "shadow-production profile accepted plaintext export"
else
  pass "shadow-production profile rejects plaintext export"
fi

printf '\n--- summary: %d passed, %d failed ---\n' "${passed}" "${failed}"
exit $((failed > 0 ? 1 : 0))
