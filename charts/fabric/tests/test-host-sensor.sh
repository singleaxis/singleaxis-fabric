#!/usr/bin/env bash
# Spec 058 §10.5 (WP8-14): the host sensor DaemonSet is part of the chart.
#
# * Off by default, and off for an install from the profile files (I8).
# * `preset=production-host-sensor` renders it: the eBPF host emitter in
#   production mode, never `privileged`, read-only host mounts, the release's
#   image and tenant, one ingress group per node on the Node whose source id
#   and token come from that node's generated Secret.
# * The secrets Job is told the nodes and may read exactly their Secrets; no
#   render holds a Secret object or value (I7).
# * The injector labels an injected pod for the sensor and names its node.
# * The chart's own default-deny policy lets the sensor reach the Node and the
#   API server (audit workaround 2).
# * An operator's own host.ebpf groups keep the hand-deployed DaemonSet route.
# * The install-info ConfigMap names what was installed, never a secret.
#
# Needs helm and python3 with PyYAML.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart="$(cd "${here}/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
render() { helm template fabric "${chart}" -n fabric-system "$@"; }
check() {
  python3 - "$1" "$2" <<'EOF'
import hashlib, json, sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")) if d]
def kinds(kind):
    return [d for d in docs if d["kind"] == kind]
def one(kind, suffix=""):
    found = [d for d in kinds(kind) if d["metadata"]["name"].endswith(suffix)]
    assert len(found) == 1, (kind, suffix, [d["metadata"]["name"] for d in found])
    return found[0]
def node_secret(name):
    # fabric.cli._kube.host_secret_name (sdk/python/tests/test_cli_kubernetes.py pins it).
    return "fabric-host-" + hashlib.sha256(name.encode()).hexdigest()[:12]
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
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.to[0].ipBlock.cidr=10.96.0.1/32'
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.ports[0].port=443'
  --set 'otel-collector.networkPolicy.hostSensorEgress.apiServer.ports[0].protocol=TCP'
)
sensor=(--set preset=production-host-sensor "${production[@]}" --set 'hostSensor.nodes={node-a,node-b}'
  --set 'agentNamespaces={agents}')

# --- off by default, and for the profile files (I8) ------------------------------
render >"${tmp}/default.yaml"
render --set preset=production "${production[@]}" --values "${here}/fixtures/production-assertions.yaml" \
  --set otel-collector.receiver.workloadAuthentication.tenantId=acme-prod \
  --set-string 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.a=b' \
  >"${tmp}/production.yaml"
for file in default production; do
  check "${tmp}/${file}.yaml" "
assert not kinds('DaemonSet'), '${file}: a DaemonSet without hostSensor.enabled'
assert not [d for d in docs if 'host-sensor' in d['metadata']['name']], '${file}: host sensor objects'
"
done
check "${tmp}/default.yaml" "
assert not [d for d in kinds('ConfigMap') if d['metadata']['name'].endswith('-fabric-install')], 'install-info without a preset'
"

# --- the DaemonSet -----------------------------------------------------------------
render "${sensor[@]}" --set injector.enabled=true >"${tmp}/sensor.yaml"
check "${tmp}/sensor.yaml" "
ds = one('DaemonSet', '-fabric-host-sensor')
pod = ds['spec']['template']['spec']
c = pod['containers'][0]
assert c['image'] == 'ghcr.io/singleaxis/fabric-host-emitter:0.12.1', c['image']
ctx = c['securityContext']
assert 'privileged' not in ctx and ctx['allowPrivilegeEscalation'] is False and ctx['readOnlyRootFilesystem'] is True, ctx
assert ctx['capabilities'] == {'drop': ['ALL'], 'add': ['BPF', 'PERFMON', 'SYS_RESOURCE', 'DAC_READ_SEARCH']}, ctx
assert pod['hostPID'] is True and pod['hostNetwork'] is False and pod['automountServiceAccountToken'] is False
env = {e['name']: e.get('value') for e in c['env']}
assert env['EMIT_PRODUCTION'] == 'true' and env['EMIT_TENANT_ID'] == 'acme-prod', env
assert env['EMIT_ALL_HOST'] == 'false' and env['EMIT_AGENT_POD_SELECTOR'] == 'fabric.singleaxis.ai/agent=true'
assert env['EMIT_SOURCE_LABEL'] == '\$(NODE_NAME)/ebpf' and env['EMIT_HOST_LABEL'] == '\$(NODE_NAME)'
assert env['EMIT_ID_KEY_FILE'] == '/var/run/secrets/fabric-id-key/id_key'
assert env['EMIT_TLS_CERT_FILE'] == '/var/run/secrets/fabric/tls.crt', 'the production preset asks for client certificates'
assert env['EMIT_FILE_ACCESS'] == 'false' and env['EMIT_DIGESTS'] == 'omitted'
host = {v['name']: v['hostPath'] for v in pod['volumes'] if 'hostPath' in v}
assert sorted(host) == ['btf', 'cgroupfs', 'debugfs', 'state', 'tracefs'], host
mounts = {m['name']: m for m in c['volumeMounts']}
assert all(mounts[n]['readOnly'] for n in ('btf', 'cgroupfs', 'debugfs', 'tracefs', 'node-files', 'id-key', 'tls'))
assert mounts['node-files']['subPathExpr'] == '\$(NODE_NAME)'
terms = pod['affinity']['nodeAffinity']['requiredDuringSchedulingIgnoredDuringExecution']['nodeSelectorTerms']
assert [t['matchFields'][0]['values'] for t in terms] == [['node-a'], ['node-b']], terms
files = next(v for v in pod['volumes'] if v['name'] == 'node-files')['projected']['sources']
assert [s['secret']['name'] for s in files if 'secret' in s] == [node_secret('node-a'), node_secret('node-b')], files
assert {i['path'] for s in files if 'secret' in s for i in s['secret']['items']} == {
    'node-a/token', 'node-a/state_key', 'node-b/token', 'node-b/state_key'}
endpoints = one('ConfigMap', '-fabric-host-sensor')['data']
assert endpoints == {'ebpf-0.endpoint': 'fabric-otel-collector.fabric-system.svc.cluster.local:4417',
                     'ebpf-1.endpoint': 'fabric-otel-collector.fabric-system.svc.cluster.local:4418'}, endpoints
# Read-only on pods and RuntimeClasses, nothing else.
role = one('ClusterRole', 'fabric-host-sensor-fabric-system-fabric')
assert role['rules'] == [{'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get', 'list', 'watch']},
                         {'apiGroups': ['node.k8s.io'], 'resources': ['runtimeclasses'], 'verbs': ['get']}], role
assert not kinds('Secret'), 'a Secret object is part of the release'

# One ingress group per node on the Node; ids and tokens from the node's Secret.
config = yaml.safe_load(one('ConfigMap', '-otel-collector-config')['data']['config.yaml'])
assert sorted(config['receivers']) == ['otlp/agents-0', 'otlp/ebpf-0', 'otlp/ebpf-1'], sorted(config['receivers'])
assert config['receivers']['otlp/ebpf-1']['protocols']['grpc']['endpoint'] == '0.0.0.0:4418'
node = one('StatefulSet', '-otel-collector')['spec']['template']['spec']['containers'][0]
refs = {e['name']: e['valueFrom']['secretKeyRef'] for e in node['env'] if e['name'].startswith('FABRIC_GROUP_SOURCE_ID_EBPF')}
assert refs == {'FABRIC_GROUP_SOURCE_ID_EBPF_0': {'name': node_secret('node-a'), 'key': 'source-id'},
                'FABRIC_GROUP_SOURCE_ID_EBPF_1': {'name': node_secret('node-b'), 'key': 'source-id'}}, refs

# The secrets Job knows the nodes and may read exactly their Secrets.
job = one('Job', '-fabric-secrets')['spec']['template']['spec']['containers'][0]['args']
for expected in ('--host-sensor', '--host-node=node-a', '--host-node=node-b', '--profile=production',
                 '--secret-name=id-key=fabric-id-key', '--secret-name=host-tls=fabric-host-emitter-tls'):
    assert expected in job, (expected, job)
roles = {(r['metadata']['namespace'], r['metadata']['name']): r for r in kinds('Role')}
names = roles[('fabric-system', 'fabric-fabric-secrets')]['rules'][0]['resourceNames']
for expected in ('fabric-id-key', 'fabric-host-emitter-tls', node_secret('node-a'), node_secret('node-b')):
    assert expected in names, (expected, names)

# The injector labels the pod for the sensor and names its node.
injector = json.loads(one('ConfigMap', '-fabric-injector')['data']['config.json'])
assert injector['hostSensor'] == {'podLabels': {'fabric.singleaxis.ai/agent': 'true'}, 'hostLabelFromNode': True}, injector

# Audit workaround 2: under the chart's default-deny policy the sensor reaches the
# Node's ingress ports and the API server.
assert one('NetworkPolicy', '-deny-default')
egress = one('NetworkPolicy', '-host-emitter-egress')['spec']
assert egress['podSelector'] == {'matchLabels': {'app.kubernetes.io/name': 'fabric-host-emitter'}}, egress
ports = sorted(p['port'] for rule in egress['egress'] for p in rule.get('ports', []) if isinstance(p['port'], int))
assert 4417 in ports and 4418 in ports, ports
assert ds['spec']['template']['metadata']['labels']['app.kubernetes.io/name'] == 'fabric-host-emitter'

# What verify and doctor read: names and ports, never a secret.
info = json.loads(one('ConfigMap', '-fabric-install')['data']['info.json'])
assert info['schema'] == 'fabric.install-info/v1' and info['preset'] == 'production-host-sensor' and info['production'] is True
assert info['hostSensor']['daemonSet'] == 'fabric-fabric-host-sensor' and info['hostSensor']['podSelector'] == 'fabric.singleaxis.ai/agent=true'
assert [n['name'] for n in info['hostSensor']['nodes']] == ['node-a', 'node-b'] and info['hostSensor']['nodes'][1]['port'] == 4418
assert info['injector'] == {'enabled': True, 'deployment': 'fabric-fabric-injector',
                            'webhook': 'fabric-injector-fabric-system-fabric', 'tlsSecret': 'fabric-injector-tls'}, info['injector']
assert info['agentNamespaces'][0]['name'] == 'agents' and info['agentNamespaces'][0]['secret'] == 'fabric-agent'
assert info['node']['service'] == 'fabric-otel-collector' and info['node']['denyDefault'] is True
assert 'BEGIN' not in json.dumps(info) and 'token' not in info
"

# A digest wins over the tag; extra EMIT_* variables are passed on.
render "${sensor[@]}" --set hostSensor.image.digest=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --set-string 'hostSensor.env.EMIT_SYSCALL_RESULTS=true' --set hostSensor.events.fileAccess=true \
  --set-string 'hostSensor.nodeSelector.pool=agents' >"${tmp}/digest.yaml"
check "${tmp}/digest.yaml" "
pod = one('DaemonSet', '-fabric-host-sensor')['spec']['template']['spec']
c = pod['containers'][0]
assert c['image'] == 'ghcr.io/singleaxis/fabric-host-emitter@sha256:' + 'b' * 64, c['image']
env = {e['name']: e.get('value') for e in c['env']}
assert env['EMIT_SYSCALL_RESULTS'] == 'true' and env['EMIT_FILE_ACCESS'] == 'true', env
assert pod['nodeSelector'] == {'pool': 'agents'}
"

# --- refused with the cause and the fix -------------------------------------------
reject "hostSensor.enabled=true needs the names of the nodes" --set preset=production-host-sensor "${production[@]}" \
  --set 'agentNamespaces={agents}'
reject "needs the namespaces of your agents" --set preset=production-host-sensor "${production[@]}" \
  --set 'hostSensor.nodes={node-a}'
reject "hostSensor.enabled=true needs a production Node" --set preset=local --set hostSensor.enabled=true \
  --set 'hostSensor.nodes={node-a}'
reject "items at 0 and 1 are equal" --set preset=production-host-sensor "${production[@]}" \
  --set 'agentNamespaces={agents}' --set 'hostSensor.nodes={node-a,node-a}'
reject "hostSensor" --set preset=production-host-sensor "${production[@]}" --set 'agentNamespaces={agents}' \
  --set 'hostSensor.nodes={Not_A_Node}'
reject "EMIT_" "${sensor[@]}" --set-string 'hostSensor.env.PATH=/tmp'
reject "agentPodSelector" "${sensor[@]}" --set-string 'hostSensor.agentPodSelector=app!=agent'
reject "more than one Node serves" "${sensor[@]}" --set otel-collector.receiver.maxSourceBindings=1

# --- an operator's own host groups keep the hand-deployed route (I8) --------------
fixtures="${chart}/charts/otel-collector/tests/fixtures/source-bindings"
render --set preset=production-host-sensor --values "${fixtures}/common.yaml" \
  --values "${fixtures}/agent-ebpf-auditd.yaml" >"${tmp}/own.yaml"
check "${tmp}/own.yaml" "
assert not kinds('DaemonSet'), 'the chart added its DaemonSet beside the operator own host groups'
info = json.loads(one('ConfigMap', '-fabric-install')['data']['info.json'])
assert info['hostSensor'] == {'enabled': False}, info['hostSensor']
"

printf 'PASS: the host sensor DaemonSet renders as spec 058 section 10.5 says\n'
