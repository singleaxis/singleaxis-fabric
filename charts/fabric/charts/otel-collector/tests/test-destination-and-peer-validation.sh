#!/usr/bin/env bash
# Render contract for destination URLs and NetworkPolicy peer restriction.
#
# * exporter.endpoint and content.s3.endpoint: absolute http(s) URL, https
#   whenever exporter.requireTLS=true (shadow-production), no user info,
#   query or fragment, a valid host and port. Diagnostics are fixed text and
#   never echo the configured value (it may hold a pasted credential).
# * Every operator-supplied NetworkPolicy peer (ingressFrom, exporterEgress,
#   contentEgress, egressTo) must restrict something: an empty
#   namespaceSelector without a narrowing podSelector, an empty podSelector
#   alone, exclusion-only selectors and /0 ipBlocks are all "everything".

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart_dir="$(cd "${here}/.." && pwd)"
umbrella_dir="$(cd "${chart_dir}/../.." && pwd)"
profile="${umbrella_dir}/profiles/shadow-production.yaml"
marker="probe-secret-5e1b"

passed=0
failed=0

pass() { printf 'ok: %s\n' "$*"; passed=$((passed + 1)); }
fail() { printf 'FAIL: %s\n' "$*" >&2; failed=$((failed + 1)); }

# expect_fail LABEL NEEDLE helm-args...: the render fails, the error names
# NEEDLE, and the configured secret marker never appears in the output.
expect_fail() {
  local label="$1" needle="$2"
  shift 2
  local output
  if output="$(helm template ci "$@" 2>&1)"; then
    fail "${label}: render unexpectedly succeeded"
  elif [[ "${output}" == *"${marker}"* ]]; then
    fail "${label}: diagnostic echoed the configured value"
  elif [[ "${output}" != *"${needle}"* ]]; then
    fail "${label}: expected '${needle}', got: ${output}"
  else
    pass "${label}"
  fi
}

expect_ok() {
  local label="$1"
  shift
  local output
  if output="$(helm template ci "$@" 2>&1)"; then
    pass "${label}"
  else
    fail "${label}: render failed: ${output}"
  fi
}

production_args=(
  "${umbrella_dir}"
  --values "${profile}" --values "${umbrella_dir}/tests/fixtures/production-assertions.yaml"
  --set tenant.id=customer-production
  --set-string 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'
)
content_args=(
  --set otel-collector.content.enabled=true
  --set 'otel-collector.content.allowedTenants[0]=customer-production'
  --set otel-collector.content.backend=s3
  --set otel-collector.content.s3.bucket=customer-evidence
  --set otel-collector.content.s3.region=eu-west-1
  --set otel-collector.content.s3.sse=AES256
  --set 'otel-collector.networkPolicy.contentEgress.to[0].ipBlock.cidr=198.51.100.0/24'
  --set 'otel-collector.networkPolicy.contentEgress.ports[0].protocol=TCP'
  --set 'otel-collector.networkPolicy.contentEgress.ports[0].port=443'
)

printf '\n=== exporter.endpoint (sol3 #2) ===\n'
expect_ok "production accepts a plain https endpoint" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://otlp.example.com
expect_ok "production accepts host, port and path" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://otlp.example.com:4318/otlp
expect_ok "production accepts an IPv4 address" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://203.0.113.10:443
expect_ok "production accepts a bracketed IPv6 address" \
  "${production_args[@]}" --set 'otel-collector.exporter.endpoint=https://[2001:db8::10]:443'
# Main accepted a fully qualified name with the root label's trailing dot.
expect_ok "production accepts a trailing-dot FQDN" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://otlp.example.com.
expect_ok "production accepts a trailing-dot FQDN with port and path" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://otlp.example.com.:4318/otlp
expect_fail "a lone dot is not a host" "exporter.endpoint host" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://./v1
expect_fail "an empty label is still refused" "exporter.endpoint host" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://otlp..example.com

expect_fail "user info with a password is refused" "must not contain user info" \
  "${production_args[@]}" --set "otel-collector.exporter.endpoint=https://user:${marker}@otlp.example.com"
expect_fail "user info without a password is refused" "must not contain user info" \
  "${production_args[@]}" --set "otel-collector.exporter.endpoint=https://${marker}@otlp.example.com"
expect_fail "a query is refused" "must not contain a query or fragment" \
  "${production_args[@]}" --set "otel-collector.exporter.endpoint=https://otlp.example.com/v1?token=${marker}"
expect_fail "a fragment is refused" "must not contain a query or fragment" \
  "${production_args[@]}" --set "otel-collector.exporter.endpoint=https://otlp.example.com/#${marker}"
expect_fail "production refuses http" "requires an https:// exporter.endpoint" \
  "${production_args[@]}" --set "otel-collector.exporter.endpoint=http://otlp-${marker//_/-}.example.com"
expect_fail "a non-http scheme is refused without echo" "absolute http:// or https:// URL" \
  "${production_args[@]}" --set "otel-collector.exporter.endpoint=ftp://user:${marker}@otlp.example.com"
expect_fail "an empty host is refused" "exporter.endpoint host" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https:///v1
expect_fail "an invalid host is refused" "exporter.endpoint host" \
  "${production_args[@]}" --set "otel-collector.exporter.endpoint=https://otlp_${marker}.example.com"
expect_fail "an out-of-range IPv4 address is refused" "exporter.endpoint host" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://203.0.113.300
expect_fail "an empty port is refused" "exporter.endpoint port" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://otlp.example.com:
expect_fail "port 0 is refused" "exporter.endpoint port" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://otlp.example.com:0
expect_fail "port 65536 is refused" "exporter.endpoint port" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://otlp.example.com:65536
expect_fail "a non-numeric port is refused" "exporter.endpoint port" \
  "${production_args[@]}" --set "otel-collector.exporter.endpoint=https://otlp.example.com:${marker}"
expect_fail "whitespace is refused" "whitespace" \
  "${production_args[@]}" --set "otel-collector.exporter.endpoint=https://otlp.example.com/a b${marker}"
expect_fail "a backslash is refused" "backslash" \
  "${production_args[@]}" --set-string 'otel-collector.exporter.endpoint=https://otlp.example.com\\@evil.example'
# Outside production the scheme may be http, but the rest of the rule holds.
expect_ok "development accepts http" \
  "${chart_dir}" --set exporter.endpoint=http://collector.observability.svc:4318
expect_fail "development still refuses user info" "must not contain user info" \
  "${chart_dir}" --set "exporter.endpoint=http://user:${marker}@collector:4318"
rendered="$(helm template ci "${chart_dir}" --set exporter.endpoint=http://collector.observability.svc:4318 --show-only templates/configmap.yaml)"
if grep -q -F 'endpoint: "http://collector.observability.svc:4318"' <<<"${rendered}"; then
  pass "a valid endpoint renders unchanged"
else
  fail "a valid endpoint did not render unchanged"
fi

printf '\n=== content.s3.endpoint (sol3 #2) ===\n'
expect_ok "production accepts an https S3-compatible endpoint" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://otlp.example.com \
  "${content_args[@]}" --set otel-collector.content.s3.endpoint=https://minio.storage.svc:9000
expect_fail "S3 endpoint user info is refused" "content.s3.endpoint must not contain user info" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://otlp.example.com \
  "${content_args[@]}" --set "otel-collector.content.s3.endpoint=https://key:${marker}@minio:9000"
expect_fail "S3 endpoint query is refused" "content.s3.endpoint must not contain a query or fragment" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://otlp.example.com \
  "${content_args[@]}" --set "otel-collector.content.s3.endpoint=https://minio:9000/?X-Amz-Signature=${marker}"
expect_fail "production refuses an http S3 endpoint" "https:// content.s3.endpoint" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://otlp.example.com \
  "${content_args[@]}" --set "otel-collector.content.s3.endpoint=http://minio-${marker//_/-}:9000"
expect_fail "S3 endpoint port is validated" "content.s3.endpoint port" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://otlp.example.com \
  "${content_args[@]}" --set otel-collector.content.s3.endpoint=https://minio:99999
expect_fail "S3 endpoint host is validated" "content.s3.endpoint host" \
  "${production_args[@]}" --set otel-collector.exporter.endpoint=https://otlp.example.com \
  "${content_args[@]}" --set "otel-collector.content.s3.endpoint=https://-${marker}:9000"

printf '\n=== Unrestricted NetworkPolicy peers (sol3 #3) ===\n'
# Each peer list is supplied exactly once (a values file), so a probe peer is
# never merged with the default restricted peer by Helm's --set list merging.
ingress_ok='[{"namespaceSelector":{"matchLabels":{"fabric.singleaxis.ai/agent":"true"}}}]'
egress_ok='[{"ipBlock":{"cidr":"203.0.113.10/32"}}]'
content_ok='[{"ipBlock":{"cidr":"198.51.100.0/24"}}]'
peer_values="$(mktemp)"
trap 'rm -f "${peer_values}"' EXIT

# peers INGRESS EGRESS CONTENT [EGRESS_TO] -> helm args for a production
# content render whose four peer lists are exactly the given JSON/YAML.
peers() {
  {
    printf 'otel-collector:\n  networkPolicy:\n'
    printf '    ingressFrom: %s\n' "$1"
    printf '    exporterEgress:\n      to: %s\n      ports: [{"protocol":"TCP","port":443}]\n' "$2"
    printf '    contentEgress:\n      to: %s\n      ports: [{"protocol":"TCP","port":443}]\n' "$3"
    printf '    egressTo: %s\n' "${4:-[]}"
  } >"${peer_values}"
  peer_args=(
    "${umbrella_dir}" --values "${profile}" --values "${umbrella_dir}/tests/fixtures/production-assertions.yaml" --set tenant.id=customer-production
    --set otel-collector.exporter.endpoint=https://otlp.example.com
    --set otel-collector.content.enabled=true
    --set 'otel-collector.content.allowedTenants[0]=customer-production'
    --set otel-collector.content.backend=s3
    --set otel-collector.content.s3.bucket=customer-evidence
    --set otel-collector.content.s3.region=eu-west-1
    --set otel-collector.content.s3.sse=AES256
    --values "${peer_values}"
  )
}

# expect_peer_fail LABEL NEEDLE INGRESS EGRESS CONTENT [EGRESS_TO]
expect_peer_fail() {
  local label="$1" needle="$2"
  shift 2
  peers "$@"
  expect_fail "${label}" "${needle}" "${peer_args[@]}"
}
expect_peer_ok() {
  local label="$1"
  shift
  peers "$@"
  expect_ok "${label}" "${peer_args[@]}"
}

expect_peer_ok "production renders with restricted peers" "${ingress_ok}" "${egress_ok}" "${content_ok}"

# The exact Codex probe: {"namespaceSelector": {}} on each peer list.
open_ns='[{"namespaceSelector":{}}]'
expect_peer_fail "empty namespaceSelector ingress peer is refused" "networkPolicy.ingressFrom[0] does not restrict" \
  "${open_ns}" "${egress_ok}" "${content_ok}"
expect_peer_fail "empty namespaceSelector telemetry egress peer is refused" "networkPolicy.exporterEgress.to[0] does not restrict" \
  "${ingress_ok}" "${open_ns}" "${content_ok}"
expect_peer_fail "empty namespaceSelector content egress peer is refused" "networkPolicy.contentEgress.to[0] does not restrict" \
  "${ingress_ok}" "${egress_ok}" "${open_ns}"
expect_peer_fail "empty namespaceSelector egressTo peer is refused" "networkPolicy.egressTo[0] does not restrict" \
  "${ingress_ok}" "${egress_ok}" "${content_ok}" "${open_ns}"
expect_peer_fail "an open peer after a restricted one is refused" "networkPolicy.ingressFrom[1] does not restrict" \
  '[{"podSelector":{"matchLabels":{"app":"agent"}}},{"namespaceSelector":{}}]' "${egress_ok}" "${content_ok}"

expect_peer_fail "empty podSelector alone is refused" "networkPolicy.ingressFrom[0] does not restrict" \
  '[{"podSelector":{}}]' "${egress_ok}" "${content_ok}"
expect_peer_fail "both selectors empty is refused" "does not restrict" \
  '[{"namespaceSelector":{},"podSelector":{}}]' "${egress_ok}" "${content_ok}"
expect_peer_fail "empty matchLabels and matchExpressions are refused" "does not restrict" \
  '[{"namespaceSelector":{"matchLabels":{},"matchExpressions":[]}}]' "${egress_ok}" "${content_ok}"
expect_peer_fail "exclusion-only selector is refused" "does not restrict" \
  '[{"namespaceSelector":{"matchExpressions":[{"key":"team","operator":"NotIn","values":["x"]}]}}]' "${egress_ok}" "${content_ok}"
expect_peer_fail "DoesNotExist-only selector is refused" "does not restrict" \
  "${ingress_ok}" '[{"podSelector":{"matchExpressions":[{"key":"blocked","operator":"DoesNotExist"}]}}]' "${content_ok}"
expect_peer_fail "null selector peer is refused" "does not restrict" \
  '[{"namespaceSelector":null}]' "${egress_ok}" "${content_ok}"
expect_peer_fail "a /0 IPv4 block other than 0.0.0.0/0 is refused" "world CIDR" \
  "${ingress_ok}" '[{"ipBlock":{"cidr":"10.0.0.0/0"}}]' "${content_ok}"
expect_peer_fail "a /0 IPv6 block spelled differently is refused" "world CIDR" \
  "${ingress_ok}" "${egress_ok}" '[{"ipBlock":{"cidr":"0::/00"}}]'
expect_peer_fail "ipBlock with a selector is refused" "ipBlock cannot be combined" \
  "${ingress_ok}" '[{"ipBlock":{"cidr":"203.0.113.10/32"},"podSelector":{"matchLabels":{"a":"b"}}}]' "${content_ok}"
expect_peer_fail "unknown peer keys are refused" "may only contain" \
  '[{"podSelectr":{"matchLabels":{"a":"b"}}}]' "${egress_ok}" "${content_ok}"

expect_peer_ok "empty namespaceSelector narrowed by a podSelector is accepted" \
  '[{"namespaceSelector":{},"podSelector":{"matchLabels":{"app":"agent"}}}]' "${egress_ok}" "${content_ok}"
expect_peer_ok "a named namespace with an empty podSelector is accepted" \
  '[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"agents"}},"podSelector":{}}]' "${egress_ok}" "${content_ok}"
expect_peer_ok "an In expression restricts" \
  '[{"namespaceSelector":{"matchExpressions":[{"key":"team","operator":"In","values":["ai"]}]}}]' "${egress_ok}" "${content_ok}"
expect_peer_ok "an Exists expression restricts" \
  '[{"podSelector":{"matchExpressions":[{"key":"fabric-agent","operator":"Exists"}]}}]' "${egress_ok}" "${content_ok}"
expect_peer_ok "a pod selector names the store service" \
  "${ingress_ok}" "${egress_ok}" '[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"storage"}},"podSelector":{"matchLabels":{"app":"minio"}}}]'

peers "${ingress_ok}" "${egress_ok}" "${content_ok}"
expect_fail "monitoring selector with only NotIn is refused" "monitoringNamespaceSelector" \
  "${peer_args[@]}" --set-json 'otel-collector.networkPolicy.monitoringNamespaceSelector={"matchExpressions":[{"key":"a","operator":"NotIn","values":["b"]}]}'

# Outside production the rule is the same: an operator-supplied peer is an
# explicit restriction or it is refused (an empty ingressFrom keeps the
# documented development default).
expect_fail "development refuses an operator-supplied open peer" "does not restrict" \
  "${chart_dir}" --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.ingressFrom=[{"namespaceSelector":{}}]'
expect_ok "development keeps its default ingress when no peer is supplied" \
  "${chart_dir}" --set networkPolicy.enabled=true

printf '\n=== Label selector values are strings (sol2_3 #2) ===\n'
# Kubernetes types matchLabels as map<string,string>. `--set ...=true` makes a
# YAML boolean, which renders unquoted and is rejected by the API server at
# apply time; the chart refuses it at render time and names --set-string.
documented_peer=(
  "${umbrella_dir}" --values "${profile}" --values "${umbrella_dir}/tests/fixtures/production-assertions.yaml" --set tenant.id=customer-production
  --set otel-collector.exporter.endpoint=https://otlp.example.com
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'
)
agent_label='otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'
expect_fail "the boolean label value from --set is refused" \
  "networkPolicy.ingressFrom[0].namespaceSelector.matchLabels values must be strings" \
  "${documented_peer[@]}" --set "${agent_label}"
expect_fail "the refusal names the --set-string fix" "--set-string" \
  "${documented_peer[@]}" --set "${agent_label}"
expect_fail "a numeric label value from --set is refused" "matchLabels values must be strings" \
  "${documented_peer[@]}" \
  --set 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.team=42'
string_render="$(helm template ci "${documented_peer[@]}" --set-string "${agent_label}" \
  --show-only charts/otel-collector/templates/networkpolicy.yaml 2>&1)" || true
if grep -q -E '^ +fabric\.singleaxis\.ai/agent: "true"$' <<<"${string_render}"; then
  pass "the documented --set-string command renders the label value as the string \"true\""
else
  fail "--set-string did not render a quoted string label value: ${string_render}"
fi

expect_peer_fail "a boolean podSelector label in egress is refused" \
  "networkPolicy.exporterEgress.to[0].podSelector.matchLabels values must be strings" \
  "${ingress_ok}" '[{"podSelector":{"matchLabels":{"app":true}}}]' "${content_ok}"
expect_peer_fail "a numeric namespace label in content egress is refused" \
  "networkPolicy.contentEgress.to[0].namespaceSelector.matchLabels values must be strings" \
  "${ingress_ok}" "${egress_ok}" '[{"namespaceSelector":{"matchLabels":{"zone":1}}}]'
expect_peer_fail "a boolean label in egressTo is refused" \
  "networkPolicy.egressTo[0].podSelector.matchLabels values must be strings" \
  "${ingress_ok}" "${egress_ok}" "${content_ok}" '[{"podSelector":{"matchLabels":{"app":false}}}]'
expect_peer_fail "a boolean label beside a valid one is refused" "matchLabels values must be strings" \
  '[{"namespaceSelector":{"matchLabels":{"team":"ai","fabric.singleaxis.ai/agent":true}}}]' "${egress_ok}" "${content_ok}"
expect_peer_fail "a non-string matchExpressions value is refused" \
  "networkPolicy.ingressFrom[0].namespaceSelector.matchExpressions[0].values must be strings" \
  '[{"namespaceSelector":{"matchExpressions":[{"key":"tier","operator":"In","values":[1]}]}}]' "${egress_ok}" "${content_ok}"
expect_peer_fail "a matchLabels list is refused" "matchLabels must be a map" \
  '[{"namespaceSelector":{"matchLabels":["fabric"]}}]' "${egress_ok}" "${content_ok}"
expect_peer_fail "an invalid label value is refused without echoing it" "valid Kubernetes label values" \
  "[{\"namespaceSelector\":{\"matchLabels\":{\"team\":\"${marker} x\"}}}]" "${egress_ok}" "${content_ok}"
expect_peer_ok "a quoted \"true\" in a values file is accepted" \
  '[{"namespaceSelector":{"matchLabels":{"fabric.singleaxis.ai/agent":"true"}}}]' "${egress_ok}" "${content_ok}"
peers "${ingress_ok}" "${egress_ok}" "${content_ok}"
expect_fail "a boolean monitoring namespace label is refused" \
  "networkPolicy.monitoringNamespaceSelector.matchLabels values must be strings" \
  "${peer_args[@]}" --set 'otel-collector.networkPolicy.monitoringNamespaceSelector.matchLabels.monitoring=true'
expect_fail "outside production a boolean ingress label is refused too" "matchLabels values must be strings" \
  "${chart_dir}" --set networkPolicy.enabled=true \
  --set 'networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'

# Every shipped Helm command that sets a matchLabels value uses --set-string
# (docs, chart READMEs and these tests alike).
repo_root="$(cd "${umbrella_dir}/../.." && pwd)"
bad_docs="$(grep -rn -E --include='*.md' --include='*.sh' --include='*.txt' --include='*.yaml' \
  -e "--set +'?[^ ]*matchLabels\\.[^ ]*=" \
  "${repo_root}/docs" "${repo_root}/charts" "${repo_root}/deploy" \
  | grep -v -F "${BASH_SOURCE[0]##*/}" | sed -E 's/:[0-9]+:.*$//' | sort -u || true)"
if [[ -z "${bad_docs}" ]]; then
  pass "every documented and tested matchLabels value is passed with --set-string"
else
  fail "matchLabels values set with --set instead of --set-string in: ${bad_docs//$'\n'/ }"
fi

printf '\n=== One content exporter per Node (H2) ===\n'
peers "${ingress_ok}" "${egress_ok}" "${content_ok}"
content_render="$(helm template ci "${peer_args[@]}" --show-only charts/otel-collector/templates/configmap.yaml)"
count="$(grep -c -E '^      fabriccontent(/[^:]*)?:$' <<<"${content_render}" || true)"
if [[ "${count}" == "1" ]]; then
  pass "the chart renders exactly one fabriccontent exporter"
else
  fail "expected exactly one fabriccontent exporter, got ${count}"
fi

printf '\n--- summary: %d passed, %d failed ---\n' "${passed}" "${failed}"
exit $((failed > 0 ? 1 : 0))
