#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart_dir="$(cd "${here}/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

archive="$(helm package "${chart_dir}" --destination "${tmp}" | sed -n 's/^Successfully packaged chart and saved it to: //p')"
[[ -n "${archive}" && -f "${archive}" ]]

listing="$(tar -tzf "${archive}")"
for forbidden_path in \
  'charts/nemo-sidecar' 'charts/presidio-sidecar' 'charts/langfuse' \
  'charts/redteam-runner' 'charts/update-agent' 'charts/fabric-relay' \
  'policy-configmap.yaml'; do
  if grep -Fq -- "${forbidden_path}" <<<"${listing}"; then
    printf 'FAIL: release package contains %s\n' "${forbidden_path}" >&2
    exit 1
  fi
done

mkdir "${tmp}/unpacked"
tar -xzf "${archive}" -C "${tmp}/unpacked"
for forbidden_config in \
  'fabricpolicy:' 'fabricredact:' 'fabricsampler:' \
  'ghcr.io/singleaxis/fabric-presidio-sidecar' \
  'name: presidio-redactor' 'name: sampler-key' 'name: policy-bundle'; do
  if grep -R -Fq -- "${forbidden_config}" "${tmp}/unpacked"; then
    printf 'FAIL: release package contains legacy deployment surface %s\n' "${forbidden_config}" >&2
    exit 1
  fi
done

if ! grep -Fq 'fabric/charts/otel-collector/Chart.yaml' <<<"${listing}"; then
  printf 'FAIL: Collector dependency is missing from release package\n' >&2
  exit 1
fi

printf 'PASS: packaged Fabric Node contains only the Collector recorder dependency\n'
