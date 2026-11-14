#!/usr/bin/env bash
# Spec 058 §10.2-10.4 (WP8-11, WP8-12, WP8-13): what the chart renders for
# generated Secrets, agent namespaces and the opt-in injector.
#
# * Nothing new for an install from the profile files alone (I8).
# * The secrets Job is a pre-install/pre-upgrade hook running the CLI image,
#   with get limited by name; no render holds a Secret object or value (I7).
# * agentNamespaces on a production Node: one ingress group per namespace,
#   source id read from the generated Secret, peers limited to the namespace.
# * The injector: off by default; failurePolicy Ignore, 2 s timeout,
#   sideEffects None, no reinvocation, both markers; no API token and no
#   egress; refused without agentNamespaces; the caBundle hook Job only when
#   needed.
# * The host-sensor + content worked example renders with real
#   host-bindings.py output.
#
# Needs helm and python3 with PyYAML.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart="$(cd "${here}/.." && pwd)"
repo="$(cd "${chart}/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
render() { helm template fabric "${chart}" -n fabric-system "$@"; }
# check FILE PY: run assertions over `docs` (the rendered objects).
check() {
  python3 - "$1" "$2" <<'EOF'
import json, sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")) if d]
def kinds(kind):
    return [d for d in docs if d["kind"] == kind]
def one(kind, suffix=""):
    found = [d for d in kinds(kind) if d["metadata"]["name"].endswith(suffix)]
    assert len(found) == 1, (kind, suffix, [d["metadata"]["name"] for d in found])
    return found[0]
def hook(d):
    return (d["metadata"].get("annotations") or {}).get("helm.sh/hook", "")
exec(sys.argv[2])
EOF
}
reject() {
  local expected="$1" output
  shift
  if output="$(render "$@" 2>&1)"; then
    fail "rendered successfully (expected: ${expected})"
  fi
  [[ "${output}" == *"${expected}"* ]] || { printf '%s\n' "${output}" >&2; fail "missing: ${expected}"; }
}

production=(
  --set tenant.id=acme-prod
  --set otel-collector.image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  --set otel-collector.exporter.endpoint=https://otlp.example.invalid
  --set otel-collector.exporter.sendingQueue.persistence.storageClass=enc
  --set otel-collector.exporter.sendingQueue.persistence.encryptionAttestationRef=review
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'
)
new_kinds='{"Job", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "MutatingWebhookConfiguration"}'

# --- I8: profile-file installs render nothing new ------------------------------
render >"${tmp}/default.yaml"
render --values "${chart}/profiles/shadow-dev.yaml" >"${tmp}/dev.yaml"
render --values "${chart}/profiles/shadow-production.yaml" --values "${here}/fixtures/production-assertions.yaml" \
  "${production[@]}" --set tenant.id=customer-production \
  --set-string 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.a=b' \
  >"${tmp}/manual-production.yaml"
for file in default dev manual-production; do
  check "${tmp}/${file}.yaml" "
assert not [d for d in docs if d['kind'] in ${new_kinds}], '${file}: new objects without a preset'
assert not [d for d in docs if 'fabric-injector' in d['metadata']['name']], '${file}: an injector'
" || fail "${file} renders objects of spec 058 E2 without being asked"
done

# --- the secrets Job ------------------------------------------------------------
render --set preset=local --set 'agentNamespaces={agents}' >"${tmp}/local-agents.yaml"
check "${tmp}/local-agents.yaml" "
job = one('Job', '-fabric-secrets')
assert hook(job) == 'pre-install,pre-upgrade', hook(job)
assert job['metadata']['annotations']['helm.sh/hook-delete-policy'] == 'before-hook-creation,hook-succeeded'
pod = job['spec']['template']['spec']
container = pod['containers'][0]
assert container['image'] == 'ghcr.io/singleaxis/fabric-cli:0.12.1', container['image']
assert container['args'][:3] == ['init', '--kubernetes', '--in-cluster'], container['args']
assert '--agent-namespace=agents=agents' in container['args']
assert '--profile=production' not in container['args']
assert container['securityContext']['allowPrivilegeEscalation'] is False
assert container['securityContext']['readOnlyRootFilesystem'] is True
assert pod['securityContext']['runAsNonRoot'] is True
roles = {(r['metadata']['namespace'], r['metadata']['name']): r for r in kinds('Role')}
release = roles[('fabric-system', 'fabric-fabric-secrets')]['rules']
assert release[0] == {'apiGroups': [''], 'resources': ['secrets'], 'verbs': ['get'],
                      'resourceNames': ['fabric-ca', 'fabric-node-receiver-tls']}, release
assert release[1] == {'apiGroups': [''], 'resources': ['secrets'], 'verbs': ['create']}
agent = roles[('agents', 'fabric-fabric-secrets')]['rules']
assert agent[0]['resourceNames'] == ['fabric-agent'], agent
assert all(hook(d) for d in docs if d['kind'] in ('Role', 'RoleBinding', 'ServiceAccount', 'Job')
           and 'secrets' in d['metadata']['name'])
assert not kinds('Secret'), 'a Secret object is part of the release'
# Agents in another namespace reach the Node over TLS with the generated certificate.
node = one('Deployment', '-otel-collector')
assert any(v.get('projected', {}).get('sources', [{}])[0].get('secret', {}).get('name')
           == 'fabric-node-receiver-tls' for v in node['spec']['template']['spec']['volumes'])
"
for file in "${tmp}"/*.yaml; do
  if grep -Eq '^kind: Secret$' "${file}"; then fail "$(basename "${file}") renders a Secret"; fi
done

render --set preset=local --set 'agentNamespaces={agents}' --set secretsJob.enabled=false >"${tmp}/no-job.yaml"
check "${tmp}/no-job.yaml" "assert not kinds('Job') and not kinds('Role')"

# A production preset alone generates the Node's own material.
render --set preset=production "${production[@]}" --values "${here}/fixtures/production-assertions.yaml" \
  --set otel-collector.receiver.workloadAuthentication.tenantId=acme-prod \
  --set-string 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.a=b' \
  --set otel-collector.content.enabled=true --set otel-collector.content.backend=s3 \
  --set otel-collector.content.s3.bucket=acme-content --set otel-collector.content.s3.region=eu-west-1 \
  --set 'otel-collector.content.allowedTenants={acme-prod}' \
  --set 'otel-collector.networkPolicy.contentEgress.to[0].ipBlock.cidr=203.0.113.20/32' \
  --set 'otel-collector.networkPolicy.contentEgress.ports[0].port=443' \
  --set 'otel-collector.networkPolicy.contentEgress.ports[0].protocol=TCP' >"${tmp}/production.yaml"
check "${tmp}/production.yaml" "
args = one('Job', '-fabric-secrets')['spec']['template']['spec']['containers'][0]['args']
for expected in ('--profile=production', '--secret-name=client-ca=fabric-node-client-ca',
                 '--content', '--secret-name=content-key=fabric-node-content-key'):
    assert expected in args, (expected, args)
egress = one('NetworkPolicy', '-fabric-secrets-egress')
assert 'pre-install' in hook(egress) and 'post-install' in hook(egress)
assert egress['spec']['egress'] == [{'ports': [{'protocol': 'TCP', 'port': 443}, {'protocol': 'TCP', 'port': 6443}]}]
"
# Explicit API server peers narrow the Job's egress.
render --set preset=production "${production[@]}" --set 'agentNamespaces={agents}' \
  --set 'secretsJob.apiServer.to[0].ipBlock.cidr=10.96.0.1/32' \
  --set 'secretsJob.apiServer.ports[0].port=443' --set 'secretsJob.apiServer.ports[0].protocol=TCP' \
  >"${tmp}/api.yaml"
check "${tmp}/api.yaml" "
rule = one('NetworkPolicy', '-fabric-secrets-egress')['spec']['egress']
assert rule == [{'to': [{'ipBlock': {'cidr': '10.96.0.1/32'}}], 'ports': [{'port': 443, 'protocol': 'TCP'}]}], rule
"

# --- agent namespaces on a production Node --------------------------------------
long=a-namespace-name-that-is-longer-than-forty-characters
render --set preset=production "${production[@]}" --set "agentNamespaces={agents,${long}}" \
  --set 'agentNamespaces[2].name=support' --set 'agentNamespaces[2].source=support-bot' \
  --set 'agentNamespaces[2].tenantId=acme-prod' >"${tmp}/groups.yaml"
check "${tmp}/groups.yaml" "
config = yaml.safe_load(one('ConfigMap', '-otel-collector-config')['data']['config.yaml'])
assert sorted(r for r in config['receivers']) == ['otlp/agents-0', 'otlp/agents-1', 'otlp/agents-2'], config['receivers']
assert config['receivers']['otlp/agents-2']['protocols']['http']['endpoint'] == '0.0.0.0:4524'
bindings = [p['evidence_source_binding'] for n, p in config['processors'].items() if n.startswith('fabricguard/')]
assert {b['source_id'] for b in bindings} == {'\${env:FABRIC_GROUP_SOURCE_ID_AGENTS_%d}' % i for i in range(3)}, bindings
assert {b['tenant_id'] for b in bindings} == {'acme-prod'}
node = one('StatefulSet', '-otel-collector')['spec']['template']['spec']['containers'][0]
refs = {e['name']: e['valueFrom']['secretKeyRef'] for e in node['env'] if e['name'].startswith('FABRIC_GROUP_SOURCE_ID_')}
assert refs['FABRIC_GROUP_SOURCE_ID_AGENTS_0'] == {'name': 'fabric-ingress-agents', 'key': 'source-id'}, refs
# The same name as fabric.cli._kube.ingress_secret_name (tests/test_cli_kubernetes.py).
assert refs['FABRIC_GROUP_SOURCE_ID_AGENTS_1']['name'] == 'fabric-ingress-a-namespace-name-that-is-longer-c9bbb667', refs
policy = one('NetworkPolicy', '-otel-collector')
peers = [rule['from'] for rule in policy['spec']['ingress']]
assert [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'support'}}}] in peers, peers
roles = {r['metadata']['namespace'] for r in kinds('Role')}
assert roles == {'fabric-system', 'agents', '${long}', 'support'}, roles
job = one('Job', '-fabric-secrets')['spec']['template']['spec']['containers'][0]['args']
assert '--agent-namespace=support=support-bot' in job, job
"
reject "agentNamespaces[1] repeats a namespace" --set preset=local --set 'agentNamespaces={a,a}'
reject "agentNamespaces[0] is the release namespace" --set preset=local --set 'agentNamespaces={fabric-system}'
reject "agentNamespaces" --set preset=local --set 'agentNamespaces={Not_A_Namespace}'

# --- the injector -----------------------------------------------------------------
reject "injector.enabled=true needs agentNamespaces" --set preset=local --set injector.enabled=true
render --set preset=local --set 'agentNamespaces={agents}' --set injector.enabled=true >"${tmp}/injector.yaml"
check "${tmp}/injector.yaml" "
hook_ = one('MutatingWebhookConfiguration')['webhooks'][0]
assert hook_['failurePolicy'] == 'Ignore' and hook_['timeoutSeconds'] == 2, hook_
assert hook_['sideEffects'] == 'None' and hook_['reinvocationPolicy'] == 'Never'
assert hook_['rules'] == [{'operations': ['CREATE'], 'apiGroups': [''], 'apiVersions': ['v1'], 'resources': ['pods'], 'scope': 'Namespaced'}]
assert hook_['namespaceSelector']['matchExpressions'] == [
    {'key': 'fabric.singleaxis.ai/injection', 'operator': 'In', 'values': ['enabled']},
    {'key': 'kubernetes.io/metadata.name', 'operator': 'In', 'values': ['agents']}], hook_
assert 'caBundle' not in hook_['clientConfig'], 'an offline render invented a caBundle'
deploy = one('Deployment', '-fabric-injector')['spec']['template']['spec']
assert deploy['automountServiceAccountToken'] is False
c = deploy['containers'][0]
assert c['command'] == ['python', '-m', 'fabric.cli._injector'], c['command']
assert c['securityContext']['allowPrivilegeEscalation'] is False and c['securityContext']['readOnlyRootFilesystem'] is True
policy = one('NetworkPolicy', '-fabric-injector')['spec']
assert policy['policyTypes'] == ['Ingress', 'Egress'] and policy['egress'] == [], policy
shim = [d for d in kinds('ConfigMap') if d['metadata']['name'] == 'fabric-autoload']
assert len(shim) == 1 and shim[0]['metadata']['namespace'] == 'agents'
assert 'def _run' in shim[0]['data']['sitecustomize.py']
config = json.loads(one('ConfigMap', '-fabric-injector')['data']['config.json'])
env = config['namespaces']['agents']['env']
assert env['FABRIC_OTLP_ENDPOINT'] == 'https://fabric-otel-collector.fabric-system.svc.cluster.local:4318', env
assert env['FABRIC_OTLP_CERTIFICATE'] == '/var/run/fabric/secrets/ca.crt'
assert 'FABRIC_OTLP_HEADERS_FILE' not in env  # a local Node takes no token
ca_job = one('Job', '-fabric-webhook-ca')
assert hook(ca_job) == 'post-install,post-upgrade'
assert ca_job['spec']['template']['spec']['containers'][0]['args'][-1] == '--webhook=fabric-injector-fabric-system-fabric'
cluster_role = one('ClusterRole')
assert cluster_role['rules'] == [{'apiGroups': ['admissionregistration.k8s.io'], 'resources': ['mutatingwebhookconfigurations'],
                                  'resourceNames': ['fabric-injector-fabric-system-fabric'], 'verbs': ['get', 'patch']}], cluster_role
assert '--injector' in one('Job', '-fabric-secrets')['spec']['template']['spec']['containers'][0]['args']
"
render --set preset=local --set 'agentNamespaces={agents}' --set injector.enabled=true \
  --set injector.caBundle=Y2EK --set-string 'injector.env.FABRIC_WIRE_EXEC=1' >"${tmp}/bundle.yaml"
check "${tmp}/bundle.yaml" "
assert one('MutatingWebhookConfiguration')['webhooks'][0]['clientConfig']['caBundle'] == 'Y2EK'
assert not [d for d in kinds('Job') if d['metadata']['name'].endswith('-fabric-webhook-ca')]
env = json.loads(one('ConfigMap', '-fabric-injector')['data']['config.json'])['namespaces']['agents']['env']
assert env['FABRIC_WIRE_EXEC'] == '1'
"
reject "PATH" --set preset=local --set 'agentNamespaces={agents}' --set injector.enabled=true \
  --set 'injector.env.PATH=/tmp'

# Production: the agent namespace's own group port, token and client certificate.
render --set preset=production "${production[@]}" --set 'agentNamespaces={agents}' \
  --set injector.enabled=true >"${tmp}/injector-production.yaml"
check "${tmp}/injector-production.yaml" "
env = json.loads(one('ConfigMap', '-fabric-injector')['data']['config.json'])['namespaces']['agents']['env']
assert env['FABRIC_OTLP_ENDPOINT'].endswith(':4518'), env
assert env['FABRIC_OTLP_HEADERS_FILE'] == '/var/run/fabric/secrets/headers'
assert env['FABRIC_OTLP_CLIENT_CERTIFICATE'] == '/var/run/fabric/secrets/tls.crt'
assert env['FABRIC_TENANT_ID'] == 'acme-prod' and env['FABRIC_SOURCE_ID'] == 'agents'
"

# --- the worked host-sensor + content example (audit D13) -----------------------
printf 'node-a\nnode-b\n' >"${tmp}/nodes.txt"
printf 'fabric-test-id-key-not-a-secret' >"${tmp}/host-id.key"
chmod 0400 "${tmp}/host-id.key"
python3 "${repo}/deploy/kubernetes/host-bindings.py" --nodes "${tmp}/nodes.txt" --tenant acme-prod \
  --id-key-file "${tmp}/host-id.key" --base-port 4417 --out "${tmp}/bindings" >/dev/null
digest="$(printf 'a%.0s' $(seq 64))"
sed -e "s/<approved Fabric Node image digest>/${digest}/" -e 's/<encrypted StorageClass>/enc/' \
  -e 's#<your storage/KMS review record>#review#' \
  "${chart}/examples/production-host-sensor-content.yaml" >"${tmp}/example.yaml"
render --set preset=production-host-sensor --values "${tmp}/example.yaml" \
  --values "${tmp}/bindings/source-bindings.yaml" >"${tmp}/example-render.yaml"
check "${tmp}/example-render.yaml" "
config = yaml.safe_load(one('ConfigMap', '-otel-collector-config')['data']['config.yaml'])
assert sorted(config['receivers']) == ['otlp/agents-0', 'otlp/content-agents-0', 'otlp/ebpf-0', 'otlp/ebpf-1'], sorted(config['receivers'])
assert config['receivers']['otlp/content-agents-0']['protocols']['http']['endpoint'] == '0.0.0.0:4519'
node = one('StatefulSet', '-otel-collector')['spec']['template']['spec']['containers'][0]
assert any(e['name'] == 'AWS_CA_BUNDLE' for e in node['env'])
args = one('Job', '-fabric-secrets')['spec']['template']['spec']['containers'][0]['args']
assert '--content' in args and '--agent-namespace=agents=agents' in args, args
"

printf 'PASS: secrets Job, agent namespaces and the injector render as spec 058 section 10 says\n'
