#!/usr/bin/env bash
# Render-time validation tests for `fabric.sampler.hmacKey`.
#
# The sampler requires a 64-char lowercase hex string (32 bytes). The
# Helm chart validates the format at render time so a bad key never
# becomes a running pod. See SPEC 016 §4.3.
#
# Run from the repo root:
#   ./charts/fabric/charts/otel-collector/tests/test-hmackey-validation.sh

set -euo pipefail

CHART_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMON_ARGS=(
  --set "exporter.acceptUnsetEndpoint=true"
)
VALID_HEX="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

pass=0
fail=0

note() { printf "\n=== %s ===\n" "$*"; }
ok()   { printf "  PASS: %s\n" "$*"; pass=$((pass + 1)); }
bad()  { printf "  FAIL: %s\n" "$*"; fail=$((fail + 1)); }

expect_fail() {
  local label="$1"; shift
  local needle="$1"; shift
  local output
  if output="$(helm template t "$CHART_DIR" "${COMMON_ARGS[@]}" "$@" 2>&1)"; then
    bad "$label — render should have failed but succeeded"
    return
  fi
  if [[ "$output" != *"$needle"* ]]; then
    bad "$label — error did not contain expected substring: $needle"
    printf "    got: %s\n" "$output"
    return
  fi
  ok "$label"
}

expect_success() {
  local label="$1"; shift
  if helm template t "$CHART_DIR" "${COMMON_ARGS[@]}" "$@" >/dev/null 2>&1; then
    ok "$label"
  else
    bad "$label — render failed but should have succeeded"
    helm template t "$CHART_DIR" "${COMMON_ARGS[@]}" "$@" 2>&1 | sed 's/^/    /'
  fi
}

note "Invalid hmacKey values must fail render-time"
expect_fail "non-hex string"           "openssl rand -hex 32" --set "fabric.sampler.hmacKey=not-hex"
expect_fail "too short (8 hex chars)"  "openssl rand -hex 32" --set "fabric.sampler.hmacKey=cafebabe"
expect_fail "too long (65 hex chars)"  "openssl rand -hex 32" --set "fabric.sampler.hmacKey=${VALID_HEX}a"
# All-A uppercase hex: keeps the case-sensitivity assertion but stays
# below gitleaks' generic-api-key entropy threshold.
expect_fail "uppercase hex rejected"   "openssl rand -hex 32" --set "fabric.sampler.hmacKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

note "Valid configurations must render"
expect_success "valid 64-char hex" --set "fabric.sampler.hmacKey=${VALID_HEX}"
expect_success "hmacKeySecret (no inline key)" --set "fabric.sampler.hmacKeySecret.name=fabric-sampler-key"
expect_success "sampler disabled (no key needed)" --set "fabric.sampler.enabled=false" --set "fabric.sampler.hmacKey="

printf "\n--- summary: %d passed, %d failed ---\n" "$pass" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
