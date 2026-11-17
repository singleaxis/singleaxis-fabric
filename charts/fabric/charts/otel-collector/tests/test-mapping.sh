#!/usr/bin/env bash
# Render contract for the opt-in mapping of emitter telemetry (spec 057 §4.5,
# fabric.mapping): off by default, the profile and id key are the customer's
# ConfigMap and Secret, fabricmap runs directly before fabricguard and carries
# the guard's binding, and the chart never holds a profile.
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
    fail "invalid mapping values rendered successfully (expected: ${expected})"
  fi
  contains "${result}" "${expected}"
}

# Off by default: no processor, no mount, the pipelines as before.
default="$(helm template ci "${chart_dir}")"
absent "${default}" 'fabricmap'
absent "${default}" 'mapping-profile'
absent "${default}" 'mapping-id-key'
contains "${default}" 'processors: [memory_limiter, fabricguard, batch]'

mapped=(
  --set fabric.mapping.enabled=true
  --set fabric.mapping.profileConfigMap.name=gateway-mapping
  --set fabric.mapping.idKeySecret.name=fabric-id-key
)
config="$(helm template ci "${chart_dir}" --show-only templates/configmap.yaml "${mapped[@]}")"
workload="$(helm template ci "${chart_dir}" --show-only templates/deployment.yaml "${mapped[@]}")"
contains "${config}" 'fabricmap:'
contains "${config}" 'profile_file: /etc/fabric/mapping/profile.json'
contains "${config}" 'id_key_file: /etc/fabric/mapping-id-key/key'
[[ "$(grep -Fc 'processors: [memory_limiter, fabricmap, fabricguard, batch]' <<<"${config}")" -eq 2 ]] \
  || fail "fabricmap must run directly before fabricguard in both pipelines"
absent "${config}" 'source_binding:'
absent "${config}" 'genai_source_keys'
# The customer's objects are referenced, never copied into the config.
absent "${config}" 'gateway-mapping'
absent "${config}" 'fabric-id-key'
contains "${workload}" 'name: "gateway-mapping"'
contains "${workload}" 'key: "profile.json"'
contains "${workload}" 'mountPath: /etc/fabric/mapping'
contains "${workload}" 'name: "fabric-id-key"'
contains "${workload}" 'mountPath: /etc/fabric/mapping-id-key'
contains "${workload}" 'defaultMode: 0440'

# Source keys alone: no profile mount.
genai="$(helm template ci "${chart_dir}" --set fabric.mapping.enabled=true \
  --set fabric.mapping.genaiSourceKeys=1.42.0 --set fabric.mapping.idKeySecret.name=fabric-id-key)"
contains "${genai}" 'genai_source_keys: "1.42.0"'
absent "${genai}" 'profile_file'
absent "${genai}" 'mapping-profile'

# On a bound ingress fabricmap carries exactly fabricguard's binding.
bound=(
  --set receiver.requireTLS=true
  --set receiver.tls.serverCertificateSecret.name=test-receiver-tls
  --set receiver.evidenceSourceBinding.enabled=true
  --set receiver.evidenceSourceBinding.tenantId=tenant-a
  --set receiver.evidenceSourceBinding.sourceId=gateway-a
  --set receiver.evidenceSourceBinding.tokenSecret.name=source-token-secret
  --set exporter.endpoint=https://otlp.example.invalid
  --set exporter.requireTLS=true
  --set exporter.insecure=false
)
bound_config="$(helm template ci "${chart_dir}" --show-only templates/configmap.yaml "${bound[@]}" "${mapped[@]}")"
contains "${bound_config}" 'source_binding:'
[[ "$(grep -Fc 'tenant_id: "tenant-a"' <<<"${bound_config}")" -eq 2 ]] || fail "fabricmap and fabricguard must name the same tenant"
[[ "$(grep -Fc 'source_id: "gateway-a"' <<<"${bound_config}")" -eq 2 ]] || fail "fabricmap and fabricguard must name the same source"

# Every refusal names the value to change.
reject 'set fabric.mapping.profileConfigMap.name' --set fabric.mapping.enabled=true
reject 'needs fabric.mapping.idKeySecret.name' --set fabric.mapping.enabled=true \
  --set fabric.mapping.genaiSourceKeys=1.42.0
reject 'profileConfigMap.name must be the name of an existing ConfigMap' --set fabric.mapping.enabled=true \
  --set fabric.mapping.profileConfigMap.name=Bad_Name
reject 'profileConfigMap.key must be the ConfigMap key' "${mapped[@]}" \
  --set fabric.mapping.profileConfigMap.key=dir/profile.json
reject 'idKeySecret.name must be the name of an existing Secret' "${mapped[@]}" \
  --set fabric.mapping.idKeySecret.name=Bad_Name
reject 'idKeySecret.key must be the Secret key' "${mapped[@]}" \
  --set fabric.mapping.idKeySecret.key=bad/key
reject 'genaiSourceKeys' "${mapped[@]}" --set fabric.mapping.genaiSourceKeys=1.30.0
# Ingress groups (rendered through the umbrella chart, as its profiles are).
umbrella="$(cd "${chart_dir}/../.." && pwd)"
groups=(
  --values "${umbrella}/profiles/shadow-production.yaml"
  --values "${umbrella}/profiles/shadow-production-host-ingress.yaml"
  --values "${here}/fixtures/source-bindings/common.yaml"
  --values "${here}/fixtures/source-bindings/agent-ebpf-three-nodes.yaml"
)
helm template fabric "${umbrella}" -n fabric-system "${groups[@]}" >/dev/null \
  || fail "the ingress-group fixture no longer renders"
if result="$(helm template fabric "${umbrella}" -n fabric-system "${groups[@]}" \
  --set otel-collector.fabric.mapping.enabled=true \
  --set otel-collector.fabric.mapping.profileConfigMap.name=gateway-mapping 2>&1)"; then
  fail "mapping rendered together with ingress groups"
fi
contains "${result}" 'not available with receiver.sourceBindings'
# An inline profile is not a chart value: the profile is the customer's object.
if result="$(helm template ci "${chart_dir}" "${mapped[@]}" --set fabric.mapping.profile.rules=x 2>&1)"; then
  fail "an inline mapping profile value rendered successfully"
fi
grep -Eiq 'additional propert' <<<"${result}" || fail "missing schema rejection of an inline profile"

# The chart ships no profile: no file outside this test names the profile schema.
needle='mapping-profile''/v1'
if grep -rIl --exclude-dir=tests -- "${needle}" "${chart_dir}" >/dev/null 2>&1; then
  fail "a mapping profile document is present in the chart"
fi

printf 'PASS: mapping render, bindings and invalid combinations\n'
