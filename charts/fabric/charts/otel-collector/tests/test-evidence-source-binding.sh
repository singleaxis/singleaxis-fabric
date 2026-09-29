#!/usr/bin/env bash
# Render contract for the opt-in, single-source authenticated evidence ingress.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart_dir="$(cd "${here}/.." && pwd)"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
contains() { grep -Fq -- "$2" <<<"$1" || fail "missing $2"; }
absent() { if grep -Fq -- "$2" <<<"$1"; then fail "unexpected $2"; fi; }
reject() {
  local expected="$1"
  shift
  local result
  if result="$(helm template ci "${chart_dir}" "$@" 2>&1)"; then
    fail "unsafe source binding rendered successfully"
  fi
  contains "${result}" "${expected}"
}

default="$(helm template ci "${chart_dir}")"
absent "${default}" 'evidence_source_binding:'
absent "${default}" 'bearertokenauth/evidence_source'
absent "${default}" 'evidence-source-token'

bound=(
  --set receiver.requireTLS=true
  --set receiver.tls.serverCertificateSecret.name=test-receiver-tls
  --set receiver.evidenceSourceBinding.enabled=true
  --set receiver.evidenceSourceBinding.tenantId=tenant-a
  --set receiver.evidenceSourceBinding.sourceId=agent-a
  --set receiver.evidenceSourceBinding.tokenSecret.name=source-token-secret
  --set exporter.endpoint=https://otlp.example.invalid
  --set exporter.requireTLS=true
  --set exporter.insecure=false
)
config="$(helm template ci "${chart_dir}" --show-only templates/configmap.yaml "${bound[@]}")"
workload="$(helm template ci "${chart_dir}" --show-only templates/deployment.yaml "${bound[@]}")"

[[ "$(grep -Fc 'authenticator: bearertokenauth/evidence_source' <<<"${config}")" -eq 2 ]] \
  || fail "both OTLP protocols must require the evidence-source bearer token"
contains "${config}" 'bearertokenauth/evidence_source:'
contains "${config}" 'filename: /etc/fabric/evidence-source/token'
contains "${config}" 'require_single_token: true'
contains "${config}" 'evidence_source_binding:'
contains "${config}" 'tenant_id: "tenant-a"'
contains "${config}" 'source_id: "agent-a"'
contains "${config}" 'processors: [memory_limiter, fabricguard, batch]'
contains "${config}" '- bearertokenauth/evidence_source'
absent "${config}" 'source-token-secret'
contains "${workload}" 'name: "source-token-secret"'
contains "${workload}" 'key: "token"'
contains "${workload}" 'mountPath: /etc/fabric/evidence-source'
contains "${workload}" 'readOnly: true'
contains "${workload}" 'defaultMode: 0440'
absent "${workload}" 'PRIVATE_TOKEN_CANARY'

reject 'requires receiver.requireTLS=true' "${bound[@]}" --set receiver.requireTLS=false
reject 'requires receiver.tls.serverCertificateSecret.name' "${bound[@]}" \
  --set receiver.tls.serverCertificateSecret.name=
reject 'requires a valid nonempty tenantId' "${bound[@]}" \
  --set receiver.evidenceSourceBinding.tenantId=
reject 'requires a valid nonempty sourceId' "${bound[@]}" \
  --set receiver.evidenceSourceBinding.sourceId=
reject 'requires a valid tokenSecret.name' "${bound[@]}" \
  --set receiver.evidenceSourceBinding.tokenSecret.name=
reject 'requires a valid nonempty tokenSecret.key' "${bound[@]}" \
  --set receiver.evidenceSourceBinding.tokenSecret.key=bad/key
reject 'requires exporter.requireTLS=true' "${bound[@]}" \
  --set exporter.requireTLS=false
reject 'requires an https://' "${bound[@]}" \
  --set exporter.endpoint=http://otlp.example.invalid
reject 'requires debugExporter.enabled=false' "${bound[@]}" \
  --set debugExporter.enabled=true
reject "additional properties 'value' not allowed" "${bound[@]}" \
  --set receiver.evidenceSourceBinding.tokenSecret.value=PRIVATE_TOKEN_CANARY

printf 'PASS: dedicated evidence-source chart render and invalid combinations\n'
