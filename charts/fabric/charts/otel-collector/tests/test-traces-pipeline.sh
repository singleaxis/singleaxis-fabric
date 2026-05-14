#!/usr/bin/env bash
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
#
# Asserts the otel-collector chart renders the OTLP `traces:` pipeline
# when `fabric.guard.traceProcessingEnabled` is true (the default) and
# omits it when explicitly disabled.
#
# The SDK ships trace spans; without this pipeline the collector
# returns 404 on `/v1/traces` and the chart silently drops them on the
# floor. See spec 016 §4.1.
#
# Requires: helm 3, bash. Run from repo root or from this directory.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart_dir="$(cd "${here}/.." && pwd)"

# Common required values: sampler hmac key (chart-time validator) and
# exporter endpoint (no OSS default per chart README).
common_args=(
  --set fabric.sampler.hmacKey=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
  --set exporter.endpoint=http://otlp.example:4318
)

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

pass() {
  echo "ok: $*"
}

# Case 1: default render must contain a `traces:` pipeline block.
default_render=$(helm template ci "${chart_dir}" "${common_args[@]}")
if ! grep -qE '^[[:space:]]+traces:[[:space:]]*$' <<<"${default_render}"; then
  fail "default render is missing the 'traces:' pipeline block"
fi
pass "default render contains traces: pipeline"

# Case 2: traces pipeline uses exactly the processors + exporters spec 016 §4.1 mandates.
if ! grep -qE 'processors:[[:space:]]*\[memory_limiter, fabricguard, batch\]' <<<"${default_render}"; then
  fail "traces pipeline processors don't match spec 016 §4.1 ([memory_limiter, fabricguard, batch])"
fi
if ! grep -qE 'exporters:[[:space:]]*\[otlphttp/fabric\]' <<<"${default_render}"; then
  fail "traces pipeline exporters don't match spec 016 §4.1 ([otlphttp/fabric])"
fi
pass "traces pipeline has correct processors + exporters"

# Case 3: opt-out via traceProcessingEnabled=false drops the block.
disabled_render=$(helm template ci "${chart_dir}" \
  "${common_args[@]}" \
  --set fabric.guard.traceProcessingEnabled=false)
if grep -qE '^[[:space:]]+traces:[[:space:]]*$' <<<"${disabled_render}"; then
  fail "traces: pipeline still rendered when fabric.guard.traceProcessingEnabled=false"
fi
pass "traces: pipeline omitted when disabled"

# Case 4: the existing logs: pipeline is unaffected by the new gate.
if ! grep -qE '^[[:space:]]+logs:[[:space:]]*$' <<<"${default_render}"; then
  fail "regression: logs: pipeline missing from default render"
fi
if ! grep -qE '^[[:space:]]+logs:[[:space:]]*$' <<<"${disabled_render}"; then
  fail "regression: logs: pipeline missing when traces are disabled"
fi
pass "logs: pipeline present in both renders"

echo "all checks passed"
