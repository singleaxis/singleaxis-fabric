#!/usr/bin/env bash
# Spec 058 §10.1 (WP8-11): `preset` is one chart value instead of a profile
# file.
#
# * Each preset renders exactly what its profile files render (local =
#   shadow-dev; production = shadow-production; production-host-sensor =
#   shadow-production + shadow-production-host-ingress), with the same values
#   the operator gives either way.
# * The operator's own values win over the preset's.
# * An unknown preset is refused by the schema; no preset changes nothing.
# * presets/defaults.yaml (what a preset compares against) is not stale.
#
# Needs helm and python3 with PyYAML.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart="$(cd "${here}/.." && pwd)"
fixtures="${chart}/charts/otel-collector/tests/fixtures/source-bindings"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
render() { helm template fabric "${chart}" -n fabric-system "$@"; }
same() {
  local what="$1" a="$2" b="$3"
  diff -u "${a}" "${b}" >"${tmp}/diff" || { cat "${tmp}/diff" >&2; fail "${what}"; }
}
# without_secrets_job FILE: the render without the secrets Job's hook objects
# (a production preset adds them on purpose: tests/test-secrets-and-injector.sh),
# written to FILE.recorder; prints how many objects were set aside.
without_secrets_job() {
  python3 - "$1" <<'PY'
import sys
docs = open(sys.argv[1], encoding="utf-8").read().rstrip("\n").split("\n---\n")
kept = [d for d in docs if "app.kubernetes.io/component: secrets-job" not in d]
open(sys.argv[1] + ".recorder", "w", encoding="utf-8").write("\n---\n".join(kept) + "\n")
print(len(docs) - len(kept))
PY
}

python3 "${here}/sync-preset-defaults.py" --check

production=(
  --values "${here}/fixtures/production-assertions.yaml"
  --set tenant.id=customer-production
  --set otel-collector.exporter.endpoint=https://otlp.example.invalid
  --set-string 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'
)

# --- each preset equals its profile files --------------------------------------
render --set preset=local >"${tmp}/preset-local.yaml"
render --values "${chart}/profiles/shadow-dev.yaml" >"${tmp}/profile-local.yaml"
same "preset=local differs from -f profiles/shadow-dev.yaml" "${tmp}/profile-local.yaml" "${tmp}/preset-local.yaml"

render --set preset=production "${production[@]}" >"${tmp}/preset-production.yaml"
render --values "${chart}/profiles/shadow-production.yaml" "${production[@]}" >"${tmp}/profile-production.yaml"
[[ "$(without_secrets_job "${tmp}/preset-production.yaml")" == 5 ]] \
  || fail "preset=production no longer adds the secrets Job (ServiceAccount, Role, RoleBinding, NetworkPolicy, Job)"
[[ "$(without_secrets_job "${tmp}/profile-production.yaml")" == 0 ]] \
  || fail "-f profiles/shadow-production.yaml alone renders the secrets Job: a manual install changed (I8)"
same "preset=production differs from -f profiles/shadow-production.yaml" \
  "${tmp}/profile-production.yaml.recorder" "${tmp}/preset-production.yaml.recorder"

host=(--values "${fixtures}/common.yaml" --values "${fixtures}/agent-ebpf-auditd.yaml")
render --set preset=production-host-sensor "${host[@]}" >"${tmp}/preset-host.yaml"
render --values "${chart}/profiles/shadow-production.yaml" \
  --values "${chart}/profiles/shadow-production-host-ingress.yaml" "${host[@]}" >"${tmp}/profile-host.yaml"
without_secrets_job "${tmp}/preset-host.yaml" >/dev/null
same "preset=production-host-sensor differs from the two profile files" \
  "${tmp}/profile-host.yaml" "${tmp}/preset-host.yaml.recorder"

# The profile file and the preset together are the same posture again.
render --set preset=production --values "${chart}/profiles/shadow-production.yaml" "${production[@]}" \
  >"${tmp}/both.yaml"
same "preset plus its own profile file differs" "${tmp}/preset-production.yaml" "${tmp}/both.yaml"

# --- no preset: unchanged -------------------------------------------------------
render >"${tmp}/default.yaml"
render --set preset= >"${tmp}/empty.yaml"
same "an empty preset changes the default render" "${tmp}/default.yaml" "${tmp}/empty.yaml"
grep -q 'profile: "local"' "${tmp}/default.yaml" || fail "the default render is no longer the bare local Node"

# --- the operator's values win --------------------------------------------------
replicas="$(render --set preset=production "${production[@]}" --set otel-collector.replicaCount=3 \
  | python3 -c 'import sys, yaml
docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
print([d["spec"]["replicas"] for d in docs if d["kind"] in ("StatefulSet", "Deployment")][0])')"
[[ "${replicas}" == 3 ]] || fail "an operator value lost to the preset (replicas ${replicas})"
verbosity="$(render --set preset=local --set otel-collector.debugExporter.verbosity=detailed \
  | grep -c 'verbosity: detailed' || true)"
[[ "${verbosity}" == 1 ]] || fail "an operator value lost to preset=local"

# --- refusals -------------------------------------------------------------------
if output="$(render --set preset=staging 2>&1)"; then
  fail "an unknown preset rendered"
fi
[[ "${output}" == *preset* ]] || { printf '%s\n' "${output}" >&2; fail "unknown preset error does not name the value"; }
if output="$(render --set preset=production 2>&1)"; then
  fail "preset=production rendered without the operator's production values"
fi
[[ "${output}" == *requires* ]] || { printf "%s\n" "${output}" >&2; fail "production refusal does not say what to set"; }

printf 'PASS: presets equal their profile files and yield to operator values\n'
