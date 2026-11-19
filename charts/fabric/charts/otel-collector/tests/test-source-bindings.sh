#!/usr/bin/env bash
# Render contract for static dedicated ingress groups (spec 053 §6.1, §6.2.6;
# spec 056 §7.3.3 (f), (g)): receiver.sourceBindings[].
#
# * The agent-and-host-groups renders equal the ingress-group goldens
#   (contracts/capture/v1/fixtures/ingress-groups/valid/agent-ebpf-auditd.yaml
#   and valid/agent-ebpf-three-nodes.yaml) after their normalisation: the
#   collector configuration as YAML with sorted keys.
# * fabric-gate accepts each render over the fixture token tree (the prefix
#   /etc/fabric/ rewritten to a private copy), and refuses a cross-wired and a
#   duplicate-credential variant of it with the goldens' error texts.
# * 64 groups by default, 256 at most; legacy values keep their render (equal
#   to valid/legacy-single-binding.yaml); mixing the forms fails the render;
#   duplicate names, ports, sources and token Secret references fail.
#
# Needs helm, python3 with PyYAML and either FABRIC_GATE_BIN (a built
# fabric-gate) or go to build it from components/otel-collector-fabric/gate.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart_dir="$(cd "${here}/.." && pwd)"
umbrella="$(cd "${chart_dir}/../.." && pwd)"
repo="$(cd "${umbrella}/../.." && pwd)"
goldens="${repo}/contracts/capture/v1/fixtures/ingress-groups"
fixtures="${here}/fixtures/source-bindings"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
contains() { grep -Fq -- "$2" <<<"$1" || fail "missing $2"; }
absent() { if grep -Fq -- "$2" <<<"$1"; then fail "unexpected $2"; fi; }

profile=(
  --values "${umbrella}/profiles/shadow-production.yaml"
  --values "${umbrella}/profiles/shadow-production-host-ingress.yaml"
  --values "${fixtures}/common.yaml"
)
render() { helm template fabric "${umbrella}" -n fabric-system "${profile[@]}" "$@"; }
reject() {
  local expected="$1" result
  shift
  if result="$(render "$@" 2>&1)"; then
    fail "invalid source bindings rendered successfully (expected: ${expected})"
  fi
  contains "${result}" "${expected}"
}

# config FILE: the rendered ConfigMap's collector configuration, normalised as
# the goldens are (scripts/contracts/ingress_groups.py yaml_text).
config() {
  python3 - "$1" <<'EOF'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")) if d]
(cm,) = [d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"].endswith("-config")]
sys.stdout.write(yaml.safe_dump(yaml.safe_load(cm["data"]["config.yaml"]), sort_keys=True,
                                default_flow_style=False, width=4096))
EOF
}

# --- the gate -------------------------------------------------------------------
gate="${FABRIC_GATE_BIN:-}"
if [[ -z "${gate}" ]]; then
  command -v go >/dev/null 2>&1 || fail "fabric-gate is required: set FABRIC_GATE_BIN or install go"
  gate="${tmp}/fabric-gate"
  (cd "${repo}/components/otel-collector-fabric/gate" && go build -o "${gate}" .) \
    || fail "fabric-gate does not build"
fi
# The fixture token tree, private, at a temporary prefix.
tree="${tmp}/tree"
mkdir -p "${tree}"
cp -R "${goldens}/files/etc/fabric/." "${tree}/"
find "${tree}" -type d -exec chmod 0700 {} +
find "${tree}" -type f -exec chmod 0400 {} +

# gate_on FILE [MUTATION]: the configuration of FILE with the prefix rewritten
# (and an optional Python mutation of `cfg`) through fabric-gate.
gate_on() {
  local out="${tmp}/gate-config.yaml"
  python3 - "$1" "${tree}" "${2:-}" >"${out}" <<'EOF'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")) if d]
(cm,) = [d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"].endswith("-config")]
cfg = yaml.safe_load(cm["data"]["config.yaml"])
root = sys.argv[2].rstrip("/") + "/"
def rewrite(v):
    if isinstance(v, str):
        return root + v[len("/etc/fabric/"):] if v.startswith("/etc/fabric/") else v
    if isinstance(v, list):
        return [rewrite(x) for x in v]
    if isinstance(v, dict):
        return {k: rewrite(x) for k, x in v.items()}
    return v
cfg = rewrite(cfg)
exec(sys.argv[3])
sys.stdout.write(yaml.safe_dump(cfg, sort_keys=True))
EOF
  env -i PATH="${PATH}" FABRIC_EXPORT_AUTH="Bearer fixture-not-a-secret" \
    FABRIC_GATE_COLLECTOR_BIN="$(command -v true)" "${gate}" --config "${out}" 2>&1
}
gate_accepts() { local out; out="$(gate_on "$@")" || fail "fabric-gate refused $1: ${out}"; }
gate_refuses() {
  local file="$1" mutation="$2" rule="$3" want out
  want="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["errors"][sys.argv[2]])' \
    "${goldens}/index.json" "${rule}")"
  if out="$(gate_on "${file}" "${mutation}")"; then
    fail "fabric-gate accepted the ${rule} variant of $(basename "${file}")"
  fi
  contains "${out}" "${want}"
}

# --- goldens ----------------------------------------------------------------------
for shape in agent-ebpf-auditd agent-ebpf-three-nodes; do
  render --values "${fixtures}/${shape}.yaml" >"${tmp}/${shape}.yaml"
  config "${tmp}/${shape}.yaml" >"${tmp}/${shape}.config.yaml"
  diff -u "${goldens}/valid/${shape}.yaml" "${tmp}/${shape}.config.yaml" \
    || fail "the ${shape} render differs from valid/${shape}.yaml"
  gate_accepts "${tmp}/${shape}.yaml"
done
gate_refuses "${tmp}/agent-ebpf-auditd.yaml" \
  'cfg["service"]["pipelines"]["traces/ebpf"]["receivers"] = ["otlp/agent"]' r2
gate_refuses "${tmp}/agent-ebpf-auditd.yaml" \
  'cfg["receivers"]["otlp/ebpf"]["protocols"]["grpc"]["auth"]["authenticator"] = "bearertokenauth/agent"' r1
gate_refuses "${tmp}/agent-ebpf-three-nodes.yaml" \
  'cfg["extensions"]["bearertokenauth/ebpf-1"]["filename"] = root + "ingress/dup-a/token"; cfg["extensions"]["bearertokenauth/ebpf-2"]["filename"] = root + "ingress/dup-b/token"' r5

# The workload: one token mount per group, ports g<index>-<kind>, every port in
# the NetworkPolicy with the group's own peers; no token byte in the release.
workload="$(cat "${tmp}/agent-ebpf-auditd.yaml")"
python3 - "${tmp}/agent-ebpf-auditd.yaml" <<'EOF' || fail "group workload shape"
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")) if d]
by = lambda kind: [d for d in docs if d["kind"] == kind]
(sts,) = by("StatefulSet")
pod = sts["spec"]["template"]["spec"]
(node,) = pod["containers"]
mounts = {m["mountPath"]: m for m in node["volumeMounts"]}
volumes = {v["name"]: v for v in pod["volumes"]}
for i, (name, secret, key) in enumerate([("agent", "fabric-ingress-agent", "token"),
                                          ("ebpf", "fabric-node-host-ingress", "ebpf"),
                                          ("auditd", "fabric-node-host-ingress", "auditd")]):
    mount = mounts[f"/etc/fabric/ingress/{name}"]
    assert mount["readOnly"] is True and mount["name"] == f"ingress-token-{i}"
    projected = volumes[mount["name"]]["projected"]
    assert projected["defaultMode"] == 0o440
    (source,) = projected["sources"]
    assert source["secret"] == {"name": secret, "items": [{"key": key, "path": "token"}]}
want = [("g0-grpc", 4317), ("g0-http", 4318), ("g0-content", 4319), ("g1-grpc", 4417),
        ("g2-http", 4428), ("health", 13133)]
assert [(p["name"], p["containerPort"]) for p in node["ports"]] == want, node["ports"]
assert all(len(p["name"]) <= 15 for p in node["ports"])
service = [s for s in by("Service") if s["metadata"]["name"] == "fabric-otel-collector"][0]
assert [(p["name"], p["port"], p["targetPort"]) for p in service["spec"]["ports"]] == [
    (n, p, n) for n, p in want]
policy = [p for p in by("NetworkPolicy") if p["metadata"]["name"] == "fabric-otel-collector"][0]
rules = policy["spec"]["ingress"]
assert [[p["port"] for p in r["ports"]] for r in rules] == [[4317, 4318, 4319], [4417], [4428]]
agents = {"namespaceSelector": {"matchLabels": {"fabric.singleaxis.ai/agent": "true"}}}
assert rules[0]["from"] == [agents]
assert rules[1]["from"][0]["podSelector"] == {"matchLabels": {"app.kubernetes.io/name": "fabric-host-emitter"}}
assert rules[2]["from"][0]["podSelector"] == {"matchLabels": {"app.kubernetes.io/name": "fabric-auditd-sensor"}}
assert "fabric.singleaxis.ai/workload-id" not in sts["spec"]["template"]["metadata"]["annotations"]
EOF
absent "${workload}" 'fabric-fixture-ingress-token'
absent "${workload}" 'bearertokenauth/workload'
absent "${workload}" 'fabricguard:'

# --- limits: 64 by default, 256 at most -----------------------------------------------
groups() {
  python3 - "$1" "$2" <<'EOF'
import sys
count, extra = int(sys.argv[1]), sys.argv[2]
print("otel-collector:\n  content:\n    enabled: false\n  receiver:")
if extra:
    print(f"    maxSourceBindings: {extra}")
print("    sourceBindings:")
for i in range(count):
    print(f"      - {{name: ebpf-{i}, kind: host.ebpf, tenantId: tenant-a, "
          f"sourceId: s-{i:032x}, tokenSecret: {{name: fabric-node-host-ingress, key: ebpf-{i}}}, "
          f"protocols: {{grpc: {20000 + i}}}}}")
EOF
}
groups 64 "" >"${tmp}/g64.yaml"
render --values "${tmp}/g64.yaml" >/dev/null || fail "64 groups must render by default"
groups 65 "" >"${tmp}/g65.yaml"
reject 'more than receiver.maxSourceBindings (64)' --values "${tmp}/g65.yaml"
groups 256 256 >"${tmp}/g256.yaml"
render --values "${tmp}/g256.yaml" >"${tmp}/g256.render.yaml" || fail "256 groups must render with maxSourceBindings=256"
[[ "$(grep -c 'source_kind: "host.ebpf"' "${tmp}/g256.render.yaml")" -eq 256 ]] || fail "256 guards"
groups 257 256 >"${tmp}/g257.yaml"
if render --values "${tmp}/g257.yaml" >/dev/null 2>&1; then fail "257 groups rendered"; fi
groups 1 257 >"${tmp}/max257.yaml"
if render --values "${tmp}/max257.yaml" >/dev/null 2>&1; then fail "maxSourceBindings=257 rendered"; fi

# --- legacy and mixed forms ------------------------------------------------------------
legacy=(
  "${umbrella}"
  --values "${umbrella}/profiles/shadow-production.yaml"
  --values "${umbrella}/tests/fixtures/production-assertions.yaml"
  --set tenant.id=customer-production
  --set otel-collector.exporter.endpoint=https://otlp.example.invalid
  --set-string 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'
)
helm template fabric "${legacy[@]}" >"${tmp}/legacy.yaml"
config "${tmp}/legacy.yaml" >"${tmp}/legacy.config.yaml"
diff -u "${goldens}/valid/legacy-single-binding.yaml" "${tmp}/legacy.config.yaml" \
  || fail "the legacy single-binding render changed"
gate_accepts "${tmp}/legacy.yaml"
legacy_render="$(cat "${tmp}/legacy.yaml")"
contains "${legacy_render}" 'name: otlp-grpc'
absent "${legacy_render}" 'fabricguard/'
absent "${legacy_render}" '/etc/fabric/ingress/'

base=(--values "${fixtures}/agent-ebpf-auditd.yaml")
reject 'never both (spec 053 §6.1)' "${base[@]}" \
  --set otel-collector.receiver.workloadAuthentication.enabled=true
reject 'never both (spec 053 §6.1)' "${base[@]}" \
  --set otel-collector.receiver.evidenceSourceBinding.enabled=true

# --- duplicate and cross-kind negatives --------------------------------------------------
# mutate EXPRESSION: the agent-ebpf-auditd values with `groups` changed.
mutate() {
  python3 - "${fixtures}/agent-ebpf-auditd.yaml" "$1" >"${tmp}/mutated.yaml" <<'EOF'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
groups = doc["otel-collector"]["receiver"]["sourceBindings"]
exec(sys.argv[2])
sys.stdout.write(yaml.safe_dump(doc))
EOF
  printf '%s' "${tmp}/mutated.yaml"
}
reject 'repeats another group'"'"'s Secret reference' \
  --values "$(mutate 'groups[2]["tokenSecret"] = dict(groups[1]["tokenSecret"])')"
reject 'repeats another group'"'"'s name' --values "$(mutate 'groups[2]["name"] = "ebpf"')"
reject 'reuses a port' --values "$(mutate 'groups[2]["protocols"] = {"http": 4417}')"
reject 'reuses a port' --values "$(mutate 'groups[1]["protocols"] = {"grpc": 13133}')"
reject 'no two groups bind one source' --values "$(mutate 'groups[2]["sourceId"] = groups[1]["sourceId"]')"
reject 'a host group has no content receiver' --values "$(mutate 'groups[1]["content"] = {"port": 4420}')"
reject 'hostDigests applies to host groups only' --values "$(mutate 'groups[0]["hostDigests"] = "omitted"')"
reject 'sourceId must be s-<32 lowercase hex>' --values "$(mutate 'groups[1]["sourceId"] = "node-a-ebpf"')"
reject 'receiver.sourceBindings[1]' --values "$(mutate 'groups[1]["tenantId"] = ""')"
reject 'sourceBindings[1].tenantId to match tenant.id' --values "$(mutate 'groups[1]["tenantId"] = "tenant-b"')"
reject 'requires an agent group with content.port' --values "$(mutate 'groups[0].pop("content")')"
reject 'content.allowedTenants is not used with receiver.sourceBindings' "${base[@]}" \
  --set 'otel-collector.content.allowedTenants[0]=tenant-a'
reject 'requires fabric.profile=production' "${base[@]}" --set otel-collector.fabric.profile=local
reject 'requires ingress peers for receiver.sourceBindings[0]' "${base[@]}" \
  --set-json 'otel-collector.networkPolicy.ingressFrom=[]'
if render --values "$(mutate 'groups[1]["name"] = "content-ebpf"')" >/dev/null 2>&1; then
  fail "a group name starting with content rendered"
fi
if render --values "$(mutate 'groups[1]["kind"] = "host.other"')" >/dev/null 2>&1; then
  fail "an unknown group kind rendered"
fi
# sourceIdSecret (spec 058 §10.3): the id read from a Secret key at start, given once.
reject 'sets both sourceId and sourceIdSecret' \
  --values "$(mutate 'groups[0]["sourceIdSecret"] = {"name": "fabric-ingress-agents", "key": "source-id"}')"
reject 'sourceIdSecret requires the name and key' \
  --values "$(mutate 'groups[0]["sourceId"] = ""; groups[0]["sourceIdSecret"] = {"name": "Bad_Name", "key": "source-id"}')"
render --values "$(mutate 'groups[0]["sourceId"] = ""; groups[0]["sourceIdSecret"] = {"name": "fabric-ingress-agents", "key": "source-id"}')" \
  >"${tmp}/source-id-secret.yaml"
grep -Fq 'source_id: "${env:FABRIC_GROUP_SOURCE_ID_AGENT}"' "${tmp}/source-id-secret.yaml" \
  || fail "sourceIdSecret does not reach the agent group's binding"
grep -Fq 'name: FABRIC_GROUP_SOURCE_ID_AGENT' "${tmp}/source-id-secret.yaml" \
  || fail "sourceIdSecret is not read into the Node's environment"
# The profile alone (sourceIds still to fill in) never renders.
reject 'receiver.sourceBindings[0]' --set 'otel-collector.content.enabled=false'

printf 'PASS: ingress-group chart renders, goldens, fabric-gate and invalid combinations\n'
