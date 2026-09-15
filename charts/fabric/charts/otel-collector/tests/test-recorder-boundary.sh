#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart_dir="$(cd "${here}/.." && pwd)"
render="$(helm template recorder "${chart_dir}" \
  --set exporter.endpoint=https://otlp.example.invalid \
  --set exporter.insecure=false)"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

grep -Fq 'fabricguard:' <<<"${render}" || fail "fabricguard allowlist is missing"
grep -Fq 'processors: [memory_limiter, fabricguard, batch]' <<<"${render}" \
  || fail "logs/traces are not constrained to the recorder processor chain"

for forbidden in \
  fabricpolicy fabricredact fabricsampler presidio-redactor \
  'fabric-presidio-sidecar' policy-bundle sampler-key redaction-socket; do
  if grep -Fiq -- "${forbidden}" <<<"${render}"; then
    fail "released render contains legacy surface: ${forbidden}"
  fi
done

for removed_key in fabric.policy fabric.redact fabric.sampler; do
  if helm template rejected "${chart_dir}" --set "${removed_key}.enabled=true" >/dev/null 2>&1; then
    fail "released values schema accepted removed key ${removed_key}"
  fi
done

printf 'PASS: Collector chart renders only capture, allowlist protection, and delivery\n'
