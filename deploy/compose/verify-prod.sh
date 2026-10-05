#!/usr/bin/env sh
# Post-deploy verification for the client-VM production overlay.
# Checks HTTP health/auth acceptance and, when available, gRPC rejection
# and queue metrics. Does not prove protection or destination delivery.
set -eu

compose="${COMPOSE:-docker compose} -f docker-compose.yml -f docker-compose.production.yml"
fail=0
note() { printf '  %s %s\n' "$1" "$2"; }
ok()   { note "PASS" "$1"; }
bad()  { note "FAIL" "$1"; fail=1; }

# envget reads KEY=VALUE lines from .env without executing it.
envget() {
  eval "val=\"\${${1}:-}\""
  if [ -z "${val}" ] && [ -f .env ]; then
    val=$(sed -n "s/^${1}=//p" .env | tail -n 1 | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//")
  fi
  printf '%s' "${val}"
}

printf 'Fabric Node production verification\n'

# --- ingress TLS detection (same rule as preflight-prod.sh) ------------------
COLLECTOR_CONFIG=collector-config/collector-production.yaml
scheme=http
curl_tls=""
if [ -f "${COLLECTOR_CONFIG}" ] \
  && sed -n '/^receivers:/,/^processors:/p' "${COLLECTOR_CONFIG}" | grep -q '^[[:space:]]*tls:'; then
  scheme=https
  tlsdir="$(envget FABRIC_INGRESS_TLS_DIR)"
  tlsdir="${tlsdir:-./tls}"
  # Prefer a dedicated CA bundle; a self-signed server cert is itself the CA.
  if [ -s "${tlsdir}/ca.crt" ]; then
    curl_tls="--cacert ${tlsdir}/ca.crt"
  elif [ -s "${tlsdir}/server.crt" ]; then
    curl_tls="--cacert ${tlsdir}/server.crt"
  else
    note "WARN" "receiver TLS enabled but no ca.crt/server.crt under ${tlsdir}; probes run unverified"
  fi
fi

node_addr="$(${compose} port fabric-node 4318 2>/dev/null | head -n 1 | sed -e 's/^0\.0\.0\.0:/127.0.0.1:/' -e 's/^\[::\]:/127.0.0.1:/')"
grpc_addr="$(${compose} port fabric-node 4317 2>/dev/null | head -n 1 | sed -e 's/^0\.0\.0\.0:/127.0.0.1:/' -e 's/^\[::\]:/127.0.0.1:/')"
health_addr="$(${compose} port fabric-node 13133 2>/dev/null | head -n 1 | sed -e 's/^0\.0\.0\.0:/127.0.0.1:/' -e 's/^\[::\]:/127.0.0.1:/')"
metrics_addr="$(${compose} port fabric-node 8888 2>/dev/null | head -n 1 | sed -e 's/^0\.0\.0\.0:/127.0.0.1:/' -e 's/^\[::\]:/127.0.0.1:/')"

if [ -z "${node_addr}" ] || [ -z "${health_addr}" ]; then
  bad "fabric-node ports not published; is the production overlay up? (make up-prod)"
  exit 1
fi

# --- entrypoint gate ---------------------------------------------------------
# The image entrypoint must be fabric-gate: it refuses configs with
# non-traces/logs pipelines or unsafe bearer-token files, and keeps watching
# token files while the collector runs. An operator who overrode the
# entrypoint bypasses that enforcement; the check makes such a bypass
# visible here even though nothing can prevent it technically.
node_container="$(${compose} ps -q fabric-node 2>/dev/null | head -n 1)"
if [ -n "${node_container}" ]; then
  entrypoint="$(docker inspect --format '{{json .Config.Entrypoint}}' "${node_container}" 2>/dev/null || true)"
  if [ "${entrypoint}" = '["/fabric-gate"]' ]; then
    ok "container boots through fabric-gate (pipeline + token enforcement active)"
  else
    bad "fabric-node entrypoint is ${entrypoint:-<unset>}, expected [\"/fabric-gate\"] — gate enforcement is bypassed"
  fi
else
  note "WARN" "cannot resolve fabric-node container; entrypoint gate not verified"
fi

# --- health -----------------------------------------------------------------
if curl -fsS "http://${health_addr}/" >/dev/null 2>&1; then
  ok "collector health endpoint ready"
else
  bad "health endpoint not ready on ${health_addr}"
fi

# --- unauthenticated rejection ----------------------------------------------
# shellcheck disable=SC2086
code=$(curl ${curl_tls} -s -o /dev/null -w '%{http_code}' -X POST "${scheme}://${node_addr}/v1/traces" \
  -H 'Content-Type: application/json' --data-binary @fixtures/decision-summary.json)
if [ "${code}" = "401" ] || [ "${code}" = "403" ]; then
  ok "unauthenticated OTLP rejected (${code})"
else
  bad "unauthenticated OTLP returned ${code}, expected 401/403"
fi

# --- authenticated acceptance -------------------------------------------------
token_file="$(envget FABRIC_INGRESS_TOKEN_FILE)"
token_file="${token_file:-./secrets/ingress.token}"
if [ ! -s "${token_file}" ]; then
  bad "cannot read ingress token file ${token_file}; set FABRIC_INGRESS_TOKEN_FILE"
  exit 1
fi
if grep -q '^[[:space:]]*$' "${token_file}"; then
  bad "ingress token file contains a blank line; an empty 'Bearer ' credential would authenticate"
  exit 1
fi
if [ -z "$(tail -c1 "${token_file}")" ]; then
  bad "ingress token file ends with a newline; rewrite it without a trailing newline"
  exit 1
fi
ok "ingress token file has no empty-token entries"
token=$(head -n 1 "${token_file}" | tr -d '[:space:]')
# The token travels to curl through a stdin config file, never argv — a
# `-H "Authorization: Bearer $token"` flag would be visible to other users
# via process inspection for the duration of the request.
# shellcheck disable=SC2086
code=$(printf 'header = "Authorization: Bearer %s"\n' "${token}" \
  | curl ${curl_tls} -K - -s -o /dev/null -w '%{http_code}' -X POST "${scheme}://${node_addr}/v1/traces" \
  -H 'Content-Type: application/json' \
  --data-binary @fixtures/decision-summary.json)
if [ "${code}" = "200" ]; then
  ok "authenticated OTLP accepted (200)"
else
  bad "authenticated OTLP returned ${code}, expected 200"
fi

# --- gRPC ingress auth (same authenticator, second receiver) ------------------
if [ -n "${grpc_addr}" ]; then
  if command -v grpcurl >/dev/null 2>&1; then
    grpc_tls_opt="-plaintext"
    [ "${scheme}" = "https" ] && grpc_tls_opt="${curl_tls:+--cacert ${curl_tls#--cacert }}"
    [ "${scheme}" = "https" ] && [ -z "${curl_tls}" ] && grpc_tls_opt="-insecure"
    # Invoke a known OTLP method from a local descriptor. `grpcurl list`
    # depends on server reflection, so any reflection-disabled collector would
    # otherwise look like an authentication rejection regardless of auth.
    # shellcheck disable=SC2086
    if grpc_output="$(grpcurl ${grpc_tls_opt} \
      -import-path fixtures -proto otlp-trace-service.proto -d '{}' \
      "${grpc_addr}" opentelemetry.proto.collector.trace.v1.TraceService/Export 2>&1)"; then
      bad "unauthenticated gRPC OTLP export was accepted on ${grpc_addr}"
    elif printf '%s' "${grpc_output}" | grep -qi 'Code: Unauthenticated'; then
      ok "unauthenticated gRPC rejected on ${grpc_addr}"
    else
      bad "gRPC probe failed without proving an authentication rejection: ${grpc_output}"
    fi
    # grpcurl trims header values, so it cannot transmit the exact trailing
    # space in "Bearer ". The token-file checks above directly reject every
    # file shape that makes bearertokenauth v0.150.0 mint that credential.
  else
    note "WARN" "grpcurl not installed; gRPC ingress auth not exercised (install grpcurl to cover 4317)"
  fi
else
  note "SKIP" "gRPC port 4317 not published; HTTP auth checks above cover the shared authenticator"
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
printf 'Ingress checks passed -- see warnings for skipped probes; destination delivery and protection are not verified\n'
