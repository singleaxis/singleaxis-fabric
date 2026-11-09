#!/usr/bin/env bash
# The production Kubernetes path a new user follows (docs/deployment.md, the
# host-ingress profile, deploy/kubernetes/):
#
# * No profile renders the release namespace: Helm stores the release there
#   before creating any object (so it must exist), and cannot adopt an
#   existing namespace. shadow-production's Secrets are created in it first.
# * With host.ebpf / host.auditd ingress groups and the policy on, the chart
#   renders egress for the shipped sensor DaemonSets, which the umbrella
#   deny-default policy also selects: their groups' ports on the Collector
#   pods, DNS and (eBPF emitter) the API server. Nothing without host groups.
# * content.s3.caSecret mounts a private CA bundle for an S3-compatible
#   content store and sets AWS_CA_BUNDLE; refused without the s3 backend.
#
# Needs helm and python3 with PyYAML.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
umbrella="$(cd "${here}/.." && pwd)"
fixtures="${umbrella}/charts/otel-collector/tests/fixtures/source-bindings"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
contains() { grep -Fq -- "$2" <<<"$1" || fail "missing $2"; }

groups=(
  --values "${umbrella}/profiles/shadow-production.yaml"
  --values "${umbrella}/profiles/shadow-production-host-ingress.yaml"
  --values "${fixtures}/common.yaml"
  --values "${fixtures}/agent-ebpf-auditd.yaml"
)
render() { helm template fabric "${umbrella}" -n fabric-system "$@"; }
reject() {
  local expected="$1" result
  shift
  if result="$(render "$@" 2>&1)"; then
    fail "rendered successfully (expected: ${expected})"
  fi
  contains "${result}" "${expected}"
}

# query FILE PY: evaluate a Python expression over `docs` (the rendered objects).
query() {
  python3 - "$1" "$2" <<'EOF'
import json, sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")) if d]
def one(kind, suffix=""):
    found = [d for d in docs if d["kind"] == kind and d["metadata"]["name"].endswith(suffix)]
    assert len(found) == 1, (kind, suffix, [d["metadata"]["name"] for d in found])
    return found[0]
def named(kind, name):
    return [d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name]
print(json.dumps(eval(sys.argv[2])))
EOF
}

# --- namespace ownership ------------------------------------------------------
# Helm stores the release in the release namespace before creating any
# object, so that namespace must exist (and then cannot be adopted): no
# profile renders it. namespace.create=true still renders it for pipelines
# that apply rendered manifests themselves.
render "${groups[@]}" >"${tmp}/groups.yaml"
[[ "$(query "${tmp}/groups.yaml" 'len([d for d in docs if d["kind"] == "Namespace"])')" == 0 ]] \
  || fail "shadow-production renders a Namespace: Secrets created first make the install fail"
[[ "$(render --values "${umbrella}/profiles/shadow-dev.yaml" | grep -c '^kind: Namespace$' || true)" == 0 ]] \
  || fail "shadow-dev renders a Namespace: helm install --create-namespace fails"
[[ "$(render "${groups[@]}" --set namespace.create=true | grep -c '^kind: Namespace$')" == 1 ]] \
  || fail "namespace.create=true no longer renders the Namespace"

# --- host sensor egress ----------------------------------------------------------
emitter='one("NetworkPolicy", "-host-emitter-egress")'
auditd='one("NetworkPolicy", "-auditd-sensor-egress")'
[[ "$(query "${tmp}/groups.yaml" "${emitter}[\"spec\"][\"podSelector\"]")" == '{"matchLabels": {"app.kubernetes.io/name": "fabric-host-emitter"}}' ]] \
  || fail "emitter egress policy does not select the DaemonSet's pods"
[[ "$(query "${tmp}/groups.yaml" "${emitter}[\"spec\"][\"policyTypes\"]")" == '["Egress"]' ]] \
  || fail "emitter policy must only add egress"
rule="$(query "${tmp}/groups.yaml" "${emitter}[\"spec\"][\"egress\"][0]")"
contains "${rule}" '"app.kubernetes.io/name": "otel-collector"'
contains "${rule}" '"app.kubernetes.io/instance": "fabric"'
contains "${rule}" '"port": 4417'
[[ "${rule}" != *4428* && "${rule}" != *4317* ]] || fail "emitter reaches another group's port: ${rule}"
contains "$(query "${tmp}/groups.yaml" "${emitter}[\"spec\"][\"egress\"][1]")" '"port": 53'
# An offline render cannot read the API server's addresses: no API rule.
[[ "$(query "${tmp}/groups.yaml" "len(${emitter}[\"spec\"][\"egress\"])")" == 2 ]] \
  || fail "an offline render invented API server peers"
rule="$(query "${tmp}/groups.yaml" "${auditd}[\"spec\"][\"egress\"][0]")"
contains "${rule}" '"port": 4428'
[[ "$(query "${tmp}/groups.yaml" "len(${auditd}[\"spec\"][\"egress\"])")" == 2 ]] \
  || fail "the auditd sensor got API server egress"
contains "$(query "${tmp}/groups.yaml" "${auditd}[\"spec\"][\"podSelector\"]")" 'fabric-auditd-sensor'

# Explicit API server peers.
render "${groups[@]}" \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.to[0].ipBlock.cidr=172.18.0.3/32' \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.to[1].ipBlock.cidr=10.96.0.1/32' \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.ports[0].port=6443' \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.ports[0].protocol=TCP' \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.ports[1].port=443' \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.ports[1].protocol=TCP' >"${tmp}/api.yaml"
rule="$(query "${tmp}/api.yaml" "${emitter}[\"spec\"][\"egress\"][2]")"
contains "${rule}" '172.18.0.3/32'
contains "${rule}" '10.96.0.1/32'
contains "${rule}" '"port": 6443'
render "${groups[@]}" --set otel-collector.networkPolicy.hostSensorEgress.apiServer.enabled=false \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.to[0].ipBlock.cidr=172.18.0.3/32' \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.ports[0].port=6443' \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.ports[0].protocol=TCP' >"${tmp}/noapi.yaml"
[[ "$(query "${tmp}/noapi.yaml" "len(${emitter}[\"spec\"][\"egress\"])")" == 2 ]] \
  || fail "apiServer.enabled=false still renders the API rule"

# Not rendered without host groups, or when switched off.
cat >"${tmp}/agent-only.yaml" <<'EOF'
otel-collector:
  receiver:
    sourceBindings:
      - name: agent
        kind: agent
        tenantId: tenant-a
        sourceId: s-b94f348e8d6890782b2af72c847dc77b
        tokenSecret: {name: fabric-ingress-agent, key: token}
        protocols: {grpc: 4317, http: 4318}
        content: {port: 4319}
EOF
render --values "${umbrella}/profiles/shadow-production.yaml" \
  --values "${umbrella}/profiles/shadow-production-host-ingress.yaml" \
  --values "${fixtures}/common.yaml" --values "${tmp}/agent-only.yaml" >"${tmp}/agent-only-render.yaml"
[[ "$(query "${tmp}/agent-only-render.yaml" 'len([d for d in docs if d["kind"] == "NetworkPolicy" and d["metadata"]["name"].endswith(("-host-emitter-egress", "-auditd-sensor-egress"))])')" == 0 ]] \
  || fail "sensor egress rendered without a host group"
[[ "$(render "${groups[@]}" --set otel-collector.networkPolicy.hostSensorEgress.enabled=false | grep -cE -- '-(host-emitter|auditd-sensor)-egress$' || true)" == 0 ]] \
  || fail "hostSensorEgress.enabled=false still renders sensor egress"

reject "hostSensorEgress.ebpfPodSelector must name matchLabels" "${groups[@]}" \
  --set 'otel-collector.networkPolicy.hostSensorEgress.ebpfPodSelector.matchLabels=null'
reject "apiServer.to requires apiServer.ports" "${groups[@]}" \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.to[0].ipBlock.cidr=172.18.0.3/32'
reject "world CIDR" "${groups[@]}" \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.to[0].ipBlock.cidr=0.0.0.0/0' \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.ports[0].port=443' \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.ports[0].protocol=TCP'

# --- private CA for an S3-compatible content store ----------------------------------
ca=(--set otel-collector.content.s3.endpoint=https://s3.store.svc:8333
  --set otel-collector.content.s3.usePathStyle=true
  --set otel-collector.content.s3.caSecret.name=fabric-node-s3-ca)
render "${groups[@]}" "${ca[@]}" >"${tmp}/ca.yaml"
pod='one("StatefulSet")["spec"]["template"]["spec"]'
[[ "$(query "${tmp}/ca.yaml" "[e for e in ${pod}[\"containers\"][0][\"env\"] if e[\"name\"] == \"AWS_CA_BUNDLE\"]")" == '[{"name": "AWS_CA_BUNDLE", "value": "/etc/fabric/content-s3-ca/ca.crt"}]' ]] \
  || fail "AWS_CA_BUNDLE not set for the content store CA"
contains "$(query "${tmp}/ca.yaml" "[m for m in ${pod}[\"containers\"][0][\"volumeMounts\"] if m[\"name\"] == \"content-s3-ca\"]")" '"mountPath": "/etc/fabric/content-s3-ca"'
contains "$(query "${tmp}/ca.yaml" "[v for v in ${pod}[\"volumes\"] if v[\"name\"] == \"content-s3-ca\"]")" '"name": "fabric-node-s3-ca"'
render "${groups[@]}" "${ca[@]}" --set otel-collector.content.s3.caSecret.key=bundle.pem | grep -Fq 'key: "bundle.pem"' \
  || fail "content.s3.caSecret.key not used"
if render "${groups[@]}" | grep -Fq AWS_CA_BUNDLE; then fail "AWS_CA_BUNDLE set without content.s3.caSecret"; fi
reject "content.s3.caSecret applies only with content.enabled=true and content.backend=s3" \
  --values "${umbrella}/profiles/shadow-production.yaml" --values "${umbrella}/tests/fixtures/production-assertions.yaml" \
  --set tenant.id=customer-production --set otel-collector.exporter.endpoint=https://otlp.example.invalid \
  --set-string 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.team=agents' \
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP' \
  --set otel-collector.content.s3.caSecret.name=fabric-node-s3-ca
# Schema: a Secret name, never a PEM blob or a path.
reject "caSecret" "${groups[@]}" --set 'otel-collector.content.s3.caSecret.name=/etc/ssl/ca.pem'

# --- NOTES name the emitter policy and a missing API server rule -----------------
# helm template does not render NOTES.txt: render it through a copy of the
# chart where a template passes it to tpl.
cp -R "${umbrella}" "${tmp}/chart"
cp "${tmp}/chart/templates/NOTES.txt" "${tmp}/chart/notes.txt"
printf 'notes: {{ tpl (.Files.Get "notes.txt") . | toJson }}\n' >"${tmp}/chart/templates/zz-notes.yaml"
notes() {
  helm template fabric "${tmp}/chart" -n fabric-system --show-only templates/zz-notes.yaml "$@" \
    | python3 -c 'import sys, yaml; print(yaml.safe_load(sys.stdin)["notes"])'
}
out="$(notes "${groups[@]}")"
contains "${out}" "Sensor egress: fabric-otel-collector-host-emitter-egress (eBPF emitter pods in fabric-system: their groups, DNS)"
contains "${out}" "WARNING: THE EMITTER EGRESS POLICY HAS NO API SERVER RULE."
contains "${out}" "hostSensorEgress.apiServer.to and .ports"
out="$(notes "${groups[@]}" \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.to[0].ipBlock.cidr=172.18.0.3/32' \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.ports[0].port=6443' \
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.ports[0].protocol=TCP')"
contains "${out}" "their groups, DNS, the API server)"
[[ "${out}" != *"NO API SERVER RULE"* ]] || fail "NOTES warn although apiServer.to is set"
out="$(notes "${groups[@]}" --set otel-collector.networkPolicy.hostSensorEgress.apiServer.enabled=false)"
[[ "${out}" != *"NO API SERVER RULE"* ]] || fail "NOTES warn although apiServer.enabled=false"
out="$(notes --values "${umbrella}/profiles/shadow-production.yaml" \
  --values "${umbrella}/profiles/shadow-production-host-ingress.yaml" \
  --values "${fixtures}/common.yaml" --values "${tmp}/agent-only.yaml")"
[[ "${out}" != *"Sensor egress"* && "${out}" != *"NO API SERVER RULE"* ]] \
  || fail "NOTES mention sensor egress without a host.ebpf group"

printf 'PASS: namespace ownership, host sensor egress, content store CA, NOTES\n'
