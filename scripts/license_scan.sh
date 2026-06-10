#!/usr/bin/env bash
#
# license_scan.sh — run the full license-compatibility scan locally, end to end.
#
# This is the local equivalent of .github/workflows/license.yml: it installs
# each dependency surface into a throwaway environment, runs the standard
# scanners (pip-licenses / go-licenses / license-checker), then applies the
# allowlist policy via scripts/license_check.py — which both gates (exit code)
# and regenerates the procurement report under docs/licenses/.
#
# Usage:   scripts/license_scan.sh            # scan every available surface
#          KEEP_RAW=1 scripts/license_scan.sh # keep raw/ inventories for debug
#
# Requires: python3 (+ venv), and optionally `go` and `npm` for those surfaces.
# Missing toolchains are skipped with a warning (so a Python-only machine can
# still exercise the Python surfaces). Exit code is the gate result.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

RAW="$(mktemp -d)"
trap '[ -n "${KEEP_RAW:-}" ] || rm -rf "${RAW}"' EXIT

# The SDK requires Python >=3.11. Pick a suitable interpreter (override with
# PYTHON=/path/to/python). CI's setup-python already pins 3.12.
PYTHON="${PYTHON:-}"
if [ -z "${PYTHON}" ]; then
  for cand in python3.12 python3.13 python3.11 python3; do
    if command -v "${cand}" >/dev/null 2>&1 &&
       "${cand}" -c 'import sys;sys.exit(0 if sys.version_info[:2]>=(3,11) else 1)' 2>/dev/null; then
      PYTHON="${cand}"; break
    fi
  done
fi
if [ -z "${PYTHON}" ]; then
  echo "error: no Python >=3.11 interpreter found (set PYTHON=...)" >&2
  exit 2
fi
echo ">> Using interpreter: $(${PYTHON} --version 2>&1) (${PYTHON})"

IGNORE_PIP="pip-licenses prettytable wcwidth tomli pip setuptools wheel hatchling hatch-vcs pathspec trove-classifiers"
GATE_ARGS=()

# --- Python surfaces --------------------------------------------------------
# package:extras pairs. Extras mirror .github/workflows/license.yml.
PY_SURFACES=(
  "sdk/python:[otlp,langgraph]"
  "components/presidio-sidecar:"
  "components/nemo-sidecar:"
  "components/prompt-guard-sidecar:"
  "components/langfuse-bootstrap:"
  "components/redteam-runner:"
  "components/update-agent:"
)

echo ">> Scanning Python surfaces"
for entry in "${PY_SURFACES[@]}"; do
  pkg="${entry%%:*}"
  extras="${entry#*:}"
  slug="${pkg//\//-}"
  out="${RAW}/python-${slug}.json"
  venv="${RAW}/venv-${slug}"
  echo "   - ${pkg}${extras}"
  "${PYTHON}" -m venv "${venv}"
  # shellcheck disable=SC1091
  "${venv}/bin/python" -m pip install --quiet --upgrade pip
  "${venv}/bin/pip" install --quiet pip-licenses "./${pkg}${extras}"
  # shellcheck disable=SC2086
  "${venv}/bin/pip-licenses" --format=json --ignore-packages ${IGNORE_PIP} > "${out}"
  GATE_ARGS+=(--pip "${pkg}=${out}")
done

# --- Go surface -------------------------------------------------------------
if command -v go >/dev/null 2>&1; then
  echo ">> Scanning Go collector surface"
  GOBIN="$(go env GOPATH)/bin"
  if ! command -v go-licenses >/dev/null 2>&1 && [ ! -x "${GOBIN}/go-licenses" ]; then
    echo "   installing go-licenses..."
    go install github.com/google/go-licenses@v1.6.0
  fi
  out="${RAW}/go-otel-collector-fabric.csv"
  (
    cd components/otel-collector-fabric/dist
    go mod download
    "${GOBIN}/go-licenses" report ./... \
      --ignore github.com/ai5labs/singleaxis-fabric > "${out}" 2>/dev/null
  )
  GATE_ARGS+=(--go "components/otel-collector-fabric=${out}")
else
  echo ">> SKIP Go surface (go toolchain not found)"
fi

# --- TypeScript surface -----------------------------------------------------
if command -v npm >/dev/null 2>&1; then
  echo ">> Scanning TypeScript SDK surface"
  out="${RAW}/npm-typescript.json"
  ( cd sdk/typescript && npm ci --silent )
  npx --yes license-checker-rseidelsohn --production --json \
    --start sdk/typescript > "${out}"
  GATE_ARGS+=(--npm "sdk/typescript=${out}")
else
  echo ">> SKIP TypeScript surface (npm not found)"
fi

# --- Apply policy + regenerate report --------------------------------------
echo ">> Applying allowlist policy"
mkdir -p docs/licenses
python3 scripts/license_check.py \
  --policy .github/license-allowlist.txt \
  "${GATE_ARGS[@]}" \
  --ignore "go.opentelemetry.io/collector/cmd/builder" \
  --ignore "@singleaxis/fabric" \
  --ignore "singleaxis-fabric" \
  --ignore "fabric-" \
  --md docs/licenses/THIRD-PARTY-LICENSES.md \
  --csv docs/licenses/third-party-licenses.csv \
  --json docs/licenses/third-party-licenses.json
