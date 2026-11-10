#!/usr/bin/env bash
# Local equivalent of recorder-license.yml. It scans released recorder
# surfaces only and writes a disposable procurement report under build/.
set -euo pipefail

FABRIC_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${FABRIC_REPO_ROOT}"

# A successful local gate covers every released recorder surface. uv exports
# the locked Python inventory (scripts/ci/install-python-locked.sh).
for required_tool in go npm uv; do
  if ! command -v "${required_tool}" >/dev/null 2>&1; then
    printf 'error: %s is required; license inventory would be incomplete\n' "${required_tool}" >&2
    exit 2
  fi
done

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
# Each published optional install surface is scanned in its own environment,
# installed from sdk/python/uv.lock with pip --require-hashes (as CI does). The
# SDK itself is not installed: license_check.py ignores singleaxis-fabric.
for extra in otlp s3 mcp signing cli; do
  FABRIC_PYTHON_VENV="${FABRIC_RAW_DIR}/python-venv-${extra}"
  "${FABRIC_PYTHON_BIN}" -m venv "${FABRIC_PYTHON_VENV}"
  FABRIC_PYTHON="${FABRIC_PYTHON_VENV}/bin/python" "${BASH}" scripts/ci/install-python-locked.sh \
    --no-default-groups --group license --extra "${extra}"
  "${FABRIC_PYTHON_VENV}/bin/pip-licenses" --format=json \
    --ignore-packages pip-licenses prettytable wcwidth tomli pip setuptools wheel hatchling hatch-vcs pathspec trove-classifiers \
    > "${FABRIC_RAW_DIR}/python-${extra}.json"
  FABRIC_GATE_ARGS+=(--pip "sdk/python=${FABRIC_RAW_DIR}/python-${extra}.json")
done

FABRIC_GO_BIN="$(go env GOPATH)/bin"
if [ ! -x "${FABRIC_GO_BIN}/go-licenses" ]; then
  go install github.com/google/go-licenses@v1.6.0
fi
if [ ! -x "${FABRIC_GO_BIN}/builder" ]; then
  go install go.opentelemetry.io/collector/cmd/builder@v0.164.0
fi
(
  cd components/otel-collector-fabric
  "${FABRIC_GO_BIN}/builder" --config ocb-config.yaml
  sh ./upstream/build-patched-bearertokenauth.sh
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
(
  cd components/host-emitter
  "${FABRIC_GO_BIN}/go-licenses" report ./... \
    --ignore github.com/singleaxis/singleaxis-fabric \
    > "${FABRIC_RAW_DIR}/go-host-emitter.csv"
)
(
  cd components/otel-collector-fabric/gate
  "${FABRIC_GO_BIN}/go-licenses" report ./... \
    --ignore github.com/singleaxis/singleaxis-fabric \
    > "${FABRIC_RAW_DIR}/go-fabric-gate.csv"
)
FABRIC_GATE_ARGS+=(--go "fabric-gate=${FABRIC_RAW_DIR}/go-fabric-gate.csv")
FABRIC_GATE_ARGS+=(--go "fabric-node=${FABRIC_RAW_DIR}/go-fabric-node.csv")
FABRIC_GATE_ARGS+=(--go "fabricctl=${FABRIC_RAW_DIR}/go-fabricctl.csv")
FABRIC_GATE_ARGS+=(--go "host-emitter=${FABRIC_RAW_DIR}/go-host-emitter.csv")

npm ci --silent --prefix sdk/typescript
# The optional S3 peer is scanned in its own locked project (see
# recorder-license.yml for why not in sdk/typescript), which also pins the
# license scanner. It must declare exactly the peer range sdk/typescript does.
FABRIC_S3_PEER_DIR="scripts/license/s3-peer"
"${FABRIC_PYTHON_BIN}" -c \
  'import json, sys; peer = json.load(open(sys.argv[1]))["peerDependencies"]["@aws-sdk/client-s3"]; scan = json.load(open(sys.argv[2]))["dependencies"]["@aws-sdk/client-s3"]; sys.exit(None if peer == scan else f"{sys.argv[2]} scans @aws-sdk/client-s3 {scan}, but the SDK declares {peer}")' \
  "${FABRIC_REPO_ROOT}/sdk/typescript/package.json" "${FABRIC_S3_PEER_DIR}/package.json"
npm ci --silent --prefix "${FABRIC_S3_PEER_DIR}" --ignore-scripts --no-audit --no-fund
FABRIC_LICENSE_CHECKER="${FABRIC_S3_PEER_DIR}/node_modules/.bin/license-checker-rseidelsohn"
"${FABRIC_LICENSE_CHECKER}" --production --json \
  --start sdk/typescript > "${FABRIC_RAW_DIR}/npm-typescript.json"
FABRIC_GATE_ARGS+=(--npm "sdk/typescript=${FABRIC_RAW_DIR}/npm-typescript.json")
"${FABRIC_LICENSE_CHECKER}" --production --json --excludePrivatePackages \
  --start "${FABRIC_S3_PEER_DIR}" > "${FABRIC_RAW_DIR}/npm-typescript-s3.json"
# Fail closed if the scan did not see the peer.
"${FABRIC_PYTHON_BIN}" -c \
  'import json, sys; sys.exit(not any(k.startswith("@aws-sdk/client-s3@") for k in json.load(open(sys.argv[1]))))' \
  "${FABRIC_RAW_DIR}/npm-typescript-s3.json"
FABRIC_GATE_ARGS+=(--npm "sdk/typescript=${FABRIC_RAW_DIR}/npm-typescript-s3.json")

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
