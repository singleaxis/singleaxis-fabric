#!/usr/bin/env bash
# Render contract for authenticated OTLP ingress and explicit exporter egress.

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
  if output="$(helm template ci "$@" 2>&1)"; then
    fail "${label}: render unexpectedly succeeded"
  elif [[ "${output}" != *"${needle}"* ]]; then
    fail "${label}: expected '${needle}', got: ${output}"
  else
    pass "${label}"
  fi
}

printf '\n=== Receiver TLS and Secret projection ===\n'
default_config="$(helm template ci "${chart_dir}" --show-only templates/configmap.yaml)"
expect_not_contains "development default does not claim receiver TLS" "${default_config}" "cert_file: /etc/fabric/receiver-tls/tls.crt"
expect_contains "gRPC request size is bounded" "${default_config}" "max_recv_msg_size_mib: 8"
expect_contains "gRPC stream concurrency is bounded" "${default_config}" "max_concurrent_streams: 64"
expect_contains "gRPC keepalive spacing is enforced" "${default_config}" "min_time: 10s"
expect_contains "HTTP request size is bounded" "${default_config}" "max_request_body_size: 8388608"
expect_contains "HTTP header reads are bounded" "${default_config}" "read_header_timeout: 5s"
expect_contains "HTTP request reads are bounded" "${default_config}" "read_timeout: 30s"
expect_contains "HTTP idle connections are bounded" "${default_config}" "idle_timeout: 120s"

receiver_args=(
  --set receiver.requireTLS=true
  --set receiver.requireClientCertificate=true
  --set receiver.tls.serverCertificateSecret.name=fabric-test-receiver-tls
  --set receiver.tls.clientCASecret.name=fabric-test-client-ca
)
receiver_config="$(helm template ci "${chart_dir}" --show-only templates/configmap.yaml "${receiver_args[@]}")"
receiver_workload="$(helm template ci "${chart_dir}" --show-only templates/deployment.yaml "${receiver_args[@]}")"

if [[ "$(grep -c -F 'cert_file: /etc/fabric/receiver-tls/tls.crt' <<<"${receiver_config}")" -eq 2 ]]; then
  pass "gRPC and HTTP receivers both load the server certificate"
else
  fail "server certificate was not configured on both OTLP protocols"
fi
if [[ "$(grep -c -F 'client_ca_file: /etc/fabric/receiver-tls/client-ca.crt' <<<"${receiver_config}")" -eq 2 ]]; then
  pass "gRPC and HTTP receivers both verify client certificates"
else
  fail "client CA was not configured on both OTLP protocols"
fi
expect_not_contains "receiver Secret names are absent from ConfigMap" "${receiver_config}" "fabric-test-receiver-tls"
expect_not_contains "client CA Secret name is absent from ConfigMap" "${receiver_config}" "fabric-test-client-ca"
expect_contains "server certificate is projected from Secret" "${receiver_workload}" "name: fabric-test-receiver-tls"
expect_contains "client CA is projected from Secret" "${receiver_workload}" "name: fabric-test-client-ca"
expect_contains "receiver TLS projection is read-only" "${receiver_workload}" "mountPath: /etc/fabric/receiver-tls"

printf '\n=== Receiver fail-closed invariants ===\n'
expect_fail "required TLS needs a server certificate Secret" "serverCertificateSecret.name" \
  "${chart_dir}" --set receiver.requireTLS=true
expect_fail "client certificate requirement implies TLS" "requires receiver.requireTLS=true" \
  "${chart_dir}" --set receiver.requireClientCertificate=true \
  --set receiver.tls.serverCertificateSecret.name=fabric-test-receiver-tls \
  --set receiver.tls.clientCASecret.name=fabric-test-client-ca
expect_fail "required client certificates need a client CA" "clientCASecret.name" \
  "${chart_dir}" --set receiver.requireTLS=true \
  --set receiver.requireClientCertificate=true \
  --set receiver.tls.serverCertificateSecret.name=fabric-test-receiver-tls
expect_fail "client CA cannot enable TLS without server identity" "client-certificate verification cannot run without receiver TLS" \
  "${chart_dir}" --set receiver.tls.clientCASecret.name=fabric-test-client-ca

printf '\n=== Explicit exporter egress contract ===\n'
expect_fail "explicit receiver ingress requires NetworkPolicy" "requires networkPolicy.enabled=true" \
  "${chart_dir}" --set networkPolicy.requireExplicitIngress=true
expect_fail "explicit receiver ingress requires a peer" "networkPolicy.ingressFrom peer" \
  "${chart_dir}" --set networkPolicy.enabled=true \
  --set networkPolicy.requireExplicitIngress=true

expect_fail "explicit exporter egress requires NetworkPolicy" "requires networkPolicy.enabled=true" \
  "${chart_dir}" --set exporter.endpoint=https://otlp.example.com \
  --set networkPolicy.exporterEgress.requireExplicit=true
expect_fail "explicit exporter egress requires a peer" "exporterEgress.to peer" \
  "${chart_dir}" --set exporter.endpoint=https://otlp.example.com \
  --set networkPolicy.enabled=true \
  --set networkPolicy.exporterEgress.requireExplicit=true
expect_fail "exporter peer without ports is rejected" "requires both non-empty to and ports lists" \
  "${chart_dir}" --set exporter.endpoint=https://otlp.example.com \
  --set networkPolicy.enabled=true \
  --set 'networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32'

egress_args=(
  --set exporter.endpoint=https://otlp.example.com
  --set networkPolicy.enabled=true
  --set networkPolicy.exporterEgress.requireExplicit=true
  --set 'networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32'
  --set 'networkPolicy.exporterEgress.ports[0].protocol=TCP'
  --set 'networkPolicy.exporterEgress.ports[0].port=443'
)
egress_render="$(helm template ci "${chart_dir}" "${egress_args[@]}")"
expect_contains "explicit exporter CIDR renders" "${egress_render}" "cidr: 203.0.113.10/32"
expect_contains "explicit exporter port renders" "${egress_render}" "port: 443"

printf '\n=== Degenerate peer rejection ===\n'
expect_fail "empty ingress peer is rejected" "empty peer" \
  "${chart_dir}" --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.ingressFrom=[{}]'
expect_fail "world ingress CIDR is rejected" "world CIDR" \
  "${chart_dir}" --set networkPolicy.enabled=true \
  --set 'networkPolicy.ingressFrom[0].ipBlock.cidr=0.0.0.0/0'
expect_fail "IPv6 world ingress CIDR is rejected" "world CIDR" \
  "${chart_dir}" --set networkPolicy.enabled=true \
  --set 'networkPolicy.ingressFrom[0].ipBlock.cidr=::/0'
expect_fail "empty exporter egress peer is rejected" "empty peer" \
  "${chart_dir}" --set exporter.endpoint=https://otlp.example.com \
  --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.exporterEgress.to=[{}]' \
  --set 'networkPolicy.exporterEgress.ports[0].protocol=TCP' \
  --set 'networkPolicy.exporterEgress.ports[0].port=443'
expect_fail "world exporter egress CIDR is rejected" "world CIDR" \
  "${chart_dir}" --set exporter.endpoint=https://otlp.example.com \
  --set networkPolicy.enabled=true \
  --set 'networkPolicy.exporterEgress.to[0].ipBlock.cidr=0.0.0.0/0' \
  --set 'networkPolicy.exporterEgress.ports[0].protocol=TCP' \
  --set 'networkPolicy.exporterEgress.ports[0].port=443'
expect_fail "empty egressTo peer is rejected" "empty peer" \
  "${chart_dir}" --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.egressTo=[{}]'
expect_fail "world egressTo CIDR is rejected" "world CIDR" \
  "${chart_dir}" --set networkPolicy.enabled=true \
  --set 'networkPolicy.egressTo[0].ipBlock.cidr=0.0.0.0/0'

printf '\n=== Health-port NetworkPolicy scoping ===\n'
np_default="$(helm template ci "${chart_dir}" --set networkPolicy.enabled=true \
  --show-only templates/networkpolicy.yaml)"
expect_not_contains "health port is not opened by default" "${np_default}" "port: 13133"
np_monitoring="$(helm template ci "${chart_dir}" --set networkPolicy.enabled=true \
  --set 'networkPolicy.monitoringNamespaceSelector.matchLabels.kubernetes\.io/metadata\.name=monitoring' \
  --show-only templates/networkpolicy.yaml)"
expect_contains "named monitoring namespace can reach health" "${np_monitoring}" "kubernetes.io/metadata.name: monitoring"
expect_contains "scoped health rule keeps the health port" "${np_monitoring}" "port: 13133"
expect_fail "empty monitoring selector is rejected" "monitoringNamespaceSelector" \
  "${chart_dir}" --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.monitoringNamespaceSelector={"matchLabels":{}}'

printf '\n=== Pod security ===\n'
default_workload="$(helm template ci "${chart_dir}" --show-only templates/deployment.yaml)"
expect_contains "pod never automounts a service-account token" "${default_workload}" "automountServiceAccountToken: false"
expect_contains "pod runs as the nonroot uid" "${default_workload}" "runAsUser: 65532"

printf '\n=== Health-test isolation ===\n'
health_test="$(helm template ci "${chart_dir}" --show-only templates/tests/test-connection.yaml)"
expect_contains "health hook has distinct component label" "${health_test}" "app.kubernetes.io/component: health-test"
expect_not_contains "health hook cannot match runtime Service selector" "${health_test}" "app.kubernetes.io/name:"
expect_contains "health hook never mounts an API token" "${health_test}" "automountServiceAccountToken: false"

printf '\n=== Shadow-production integration and locks ===\n'
production_args=(
  --values "${profile}" --values "${umbrella_dir}/tests/fixtures/production-assertions.yaml"
  --set tenant.id=customer-production
  --set otel-collector.exporter.endpoint=https://otlp.example.com
  --set 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'
)

expect_fail "production profile requires an operator exporter peer" "exporterEgress.to peer" \
  "${umbrella_dir}" --values "${profile}" --values "${umbrella_dir}/tests/fixtures/production-assertions.yaml" \
  --set tenant.id=customer-production \
  --set otel-collector.exporter.endpoint=https://otlp.example.com \
  --set 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'

expect_fail "production profile requires an operator ingress peer" "networkPolicy.ingressFrom peer" \
  "${umbrella_dir}" --values "${profile}" --values "${umbrella_dir}/tests/fixtures/production-assertions.yaml" \
  --set tenant.id=customer-production \
  --set otel-collector.exporter.endpoint=https://otlp.example.com \
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'

production_render="$(helm template ci "${umbrella_dir}" "${production_args[@]}")"
expect_contains "production profile enables receiver mTLS" "${production_render}" "client_ca_file: /etc/fabric/receiver-tls/client-ca.crt"
expect_contains "production profile names receiver identity Secret" "${production_render}" "name: fabric-node-receiver-tls"
expect_contains "production profile names client CA Secret" "${production_render}" "name: fabric-node-client-ca"
expect_contains "production profile renders explicit egress peer" "${production_render}" "cidr: 203.0.113.10/32"
expect_contains "production profile retains explicit image pull policy" "${production_render}" "imagePullPolicy: Always"

expect_fail "production receiver TLS cannot be disabled" "requires receiver TLS and client-certificate verification" \
  "${umbrella_dir}" "${production_args[@]}" \
  --set otel-collector.receiver.requireTLS=false \
  --set otel-collector.receiver.requireClientCertificate=false
expect_fail "production client certificate cannot be disabled" "requires receiver TLS and client-certificate verification" \
  "${umbrella_dir}" "${production_args[@]}" --set otel-collector.receiver.requireClientCertificate=false
expect_fail "production explicit egress cannot be disabled" "profile shadow-production requires" \
  "${umbrella_dir}" "${production_args[@]}" --set otel-collector.networkPolicy.exporterEgress.requireExplicit=false
expect_fail "production explicit ingress cannot be disabled" "profile shadow-production requires" \
  "${umbrella_dir}" "${production_args[@]}" --set otel-collector.networkPolicy.requireExplicitIngress=false
expect_fail "production namespace deny-default cannot be disabled" "profile shadow-production requires" \
  "${umbrella_dir}" "${production_args[@]}" --set networkPolicy.denyDefault=false

printf '\n--- summary: %d passed, %d failed ---\n' "${passed}" "${failed}"
exit $((failed > 0 ? 1 : 0))
