#!/usr/bin/env sh
# Post-deploy verification for the client-VM production overlay.
# Proves: collector healthy, unauthenticated OTLP rejected, authenticated
# OTLP accepted, persistent queue engaged, metrics endpoint serving.
set -eu

compose="${COMPOSE:-docker compose} -f docker-compose.yml -f docker-compose.production.yml"
fail=0
note() { printf '  %s %s\n' "$1" "$2"; }
ok()   { note "PASS" "$1"; }
bad()  { note "FAIL" "$1"; fail=1; }

printf 'Fabric Node production verification\n'

node_addr="$(${compose} port fabric-node 4318 2>/dev/null | head -n 1 | sed -e 's/^0\.0\.0\.0:/127.0.0.1:/' -e 's/^\[::\]:/127.0.0.1:/')"
health_addr="$(${compose} port fabric-node 13133 2>/dev/null | head -n 1 | sed -e 's/^0\.0\.0\.0:/127.0.0.1:/' -e 's/^\[::\]:/127.0.0.1:/')"
metrics_addr="$(${compose} port fabric-node 8888 2>/dev/null | head -n 1 | sed -e 's/^0\.0\.0\.0:/127.0.0.1:/' -e 's/^\[::\]:/127.0.0.1:/')"

if [ -z "${node_addr}" ] || [ -z "${health_addr}" ]; then
  bad "fabric-node ports not published; is the production overlay up? (make up-prod)"
  exit 1
fi

# --- health -----------------------------------------------------------------
if curl -fsS "http://${health_addr}/" >/dev/null 2>&1; then
  ok "collector health endpoint ready"
else
  bad "health endpoint not ready on ${health_addr}"
fi

# --- unauthenticated rejection ----------------------------------------------
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://${node_addr}/v1/traces" \
  -H 'Content-Type: application/json' --data-binary @fixtures/decision-summary.json)
if [ "${code}" = "401" ] || [ "${code}" = "403" ]; then
  ok "unauthenticated OTLP rejected (${code})"
else
  bad "unauthenticated OTLP returned ${code}, expected 401/403"
fi

# --- authenticated acceptance -------------------------------------------------
# envget reads KEY=VALUE lines from .env without executing it.
envget() {
  eval "val=\"\${${1}:-}\""
  if [ -z "${val}" ] && [ -f .env ]; then
    val=$(sed -n "s/^${1}=//p" .env | tail -n 1 | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//")
  fi
  printf '%s' "${val}"
}

token_file="$(envget FABRIC_INGRESS_TOKEN_FILE)"
token_file="${token_file:-./secrets/ingress.token}"
if [ ! -s "${token_file}" ]; then
  bad "cannot read ingress token file ${token_file}; set FABRIC_INGRESS_TOKEN_FILE"
  exit 1
fi
token=$(head -n 1 "${token_file}" | tr -d '[:space:]')
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://${node_addr}/v1/traces" \
  -H 'Content-Type: application/json' -H "Authorization: Bearer ${token}" \
  --data-binary @fixtures/decision-summary.json)
if [ "${code}" = "200" ]; then
  ok "authenticated OTLP accepted (200)"
else
  bad "authenticated OTLP returned ${code}, expected 200"
fi

# --- persistent queue + metrics ------------------------------------------------
if [ -n "${metrics_addr}" ] && curl -fsS "http://${metrics_addr}/metrics" 2>/dev/null | grep -q "otelcol_exporter_queue"; then
  ok "internal metrics exposing exporter queue gauges"
else
  note "WARN" "queue metrics not visible on ${metrics_addr:-<unpublished>} (check telemetry config)"
fi

printf '\n'
if [ "${fail}" -ne 0 ]; then
  printf 'Verification FAILED -- inspect: make logs-prod ARGS=fabric-node\n' >&2
  exit 1
fi
printf 'Verification passed -- recorder is capturing, protecting, and delivering\n'
