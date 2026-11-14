#!/usr/bin/env bash
# Assemble the build context of the test agent image (agent.Dockerfile) in DIR:
# the SDK wheel built from this tree, its [cli] extra's locked requirements
# (httpx and the OTLP exporter, with hashes), the TTFR fixture model and httpx
# agent, and the pod command. Needs uv and a Python with the `ci` group's build
# backend (scripts/ci/install-python-locked.sh --only-group ci).
#
#   charts/fabric/tests/kind/build-agent-context.sh DIR
#   docker build -f charts/fabric/tests/kind/agent.Dockerfile -t fabric-agent:e2e DIR
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "${here}/../../../.." && pwd)"
out="${1:?usage: build-agent-context.sh DIR}"
python="${FABRIC_PYTHON:-python3}"

rm -rf "${out}"
mkdir -p "${out}/wheels"
uv export --project "${repo}/sdk/python" --frozen --no-emit-project --no-header --no-default-groups \
  --extra cli --format requirements-txt --quiet --output-file "${out}/requirements.txt"
"${python}" -m build --wheel --no-isolation --outdir "${out}/wheels" "${repo}/sdk/python" >/dev/null
cp "${repo}/scripts/ttfr/model_server.py" "${repo}/scripts/ttfr/agents/httpx_tool_loop.py" \
  "${here}/run-agent.sh" "${out}/"
