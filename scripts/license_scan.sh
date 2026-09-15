#!/usr/bin/env bash
# Local equivalent of recorder-license.yml. It scans released recorder
# surfaces only and writes a disposable procurement report under build/.
set -euo pipefail

FABRIC_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${FABRIC_REPO_ROOT}"

FABRIC_RAW_DIR="$(mktemp -d)"
cleanup() {
  if [ -z "${FABRIC_KEEP_RAW:-}" ]; then
    rm -rf "${FABRIC_RAW_DIR}"
  else
    printf 'Raw inventories retained at %s\n' "${FABRIC_RAW_DIR}"
  fi
}
trap cleanup EXIT

FABRIC_PYTHON_BIN="${FABRIC_PYTHON_BIN:-}"
if [ -z "${FABRIC_PYTHON_BIN}" ]; then
  for candidate in python3.12 python3.13 python3.11 python3; do
    if command -v "${candidate}" >/dev/null 2>&1 && \
      "${candidate}" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'; then
      FABRIC_PYTHON_BIN="${candidate}"
      break
    fi
  done
fi
if [ -z "${FABRIC_PYTHON_BIN}" ]; then
  printf 'error: Python 3.11 or newer is required\n' >&2
  exit 2
fi

FABRIC_GATE_ARGS=()
FABRIC_PYTHON_VENV="${FABRIC_RAW_DIR}/python-venv"
"${FABRIC_PYTHON_BIN}" -m venv "${FABRIC_PYTHON_VENV}"
"${FABRIC_PYTHON_VENV}/bin/python" -m pip install --quiet --upgrade pip
"${FABRIC_PYTHON_VENV}/bin/pip" install --quiet pip-licenses './sdk/python[otlp]'
"${FABRIC_PYTHON_VENV}/bin/pip-licenses" --format=json \
  --ignore-packages pip-licenses prettytable wcwidth tomli pip setuptools wheel hatchling hatch-vcs pathspec trove-classifiers \
  > "${FABRIC_RAW_DIR}/python-sdk.json"
FABRIC_GATE_ARGS+=(--pip "sdk/python=${FABRIC_RAW_DIR}/python-sdk.json")

if command -v go >/dev/null 2>&1; then
  FABRIC_GO_BIN="$(go env GOPATH)/bin"
  if [ ! -x "${FABRIC_GO_BIN}/go-licenses" ]; then
    go install github.com/google/go-licenses@v1.6.0
  fi
  if [ ! -x "${FABRIC_GO_BIN}/builder" ]; then
    go install go.opentelemetry.io/collector/cmd/builder@v0.150.0
  fi
  (
    cd components/otel-collector-fabric
    "${FABRIC_GO_BIN}/builder" --config ocb-config.yaml
    cd dist
    go mod download
    "${FABRIC_GO_BIN}/go-licenses" report ./... \
      --ignore github.com/singleaxis/singleaxis-fabric \
      --ignore go.opentelemetry.io/collector/cmd/builder \
      > "${FABRIC_RAW_DIR}/go-fabric-node.csv"
  )
  (
    cd tools/fabricctl
    "${FABRIC_GO_BIN}/go-licenses" report ./cmd/fabricctl \
      --ignore github.com/singleaxis/singleaxis-fabric \
      > "${FABRIC_RAW_DIR}/go-fabricctl.csv"
  )
  FABRIC_GATE_ARGS+=(--go "fabric-node=${FABRIC_RAW_DIR}/go-fabric-node.csv")
  FABRIC_GATE_ARGS+=(--go "fabricctl=${FABRIC_RAW_DIR}/go-fabricctl.csv")
else
  printf 'warning: Go unavailable; Go recorder surfaces were not scanned\n' >&2
fi

if command -v npm >/dev/null 2>&1; then
  npm ci --silent --prefix sdk/typescript
  npx --yes license-checker-rseidelsohn --production --json \
    --start sdk/typescript > "${FABRIC_RAW_DIR}/npm-typescript.json"
  FABRIC_GATE_ARGS+=(--npm "sdk/typescript=${FABRIC_RAW_DIR}/npm-typescript.json")
else
  printf 'warning: npm unavailable; the TypeScript SDK was not scanned\n' >&2
fi

mkdir -p build/recorder-license-report
"${FABRIC_PYTHON_BIN}" scripts/license_check.py \
  --policy .github/license-allowlist.txt \
  "${FABRIC_GATE_ARGS[@]}" \
  --ignore go.opentelemetry.io/collector/cmd/builder \
  --ignore @singleaxis/fabric \
  --ignore singleaxis-fabric \
  --md build/recorder-license-report/THIRD-PARTY-LICENSES.md \
  --csv build/recorder-license-report/third-party-licenses.csv \
  --json build/recorder-license-report/third-party-licenses.json
