#!/usr/bin/env sh
# Pre-flight checks for the client-VM production overlay. Run before
# `make up-prod` so a broken deployment fails here, not on the customer's box.
set -eu

fail=0
note() { printf '  %s %s\n' "$1" "$2"; }
ok()   { note "PASS" "$1"; }
bad()  { note "FAIL" "$1"; fail=1; }
warn() { note "WARN" "$1"; }

printf 'Fabric Node production preflight\n'

# --- tooling ----------------------------------------------------------------
if command -v docker >/dev/null 2>&1; then
  ok "docker present: $(docker version --format '{{.Server.Version}}' 2>/dev/null || printf 'daemon unreachable')"
else
  bad "docker not found; install Docker Engine >= 24"
fi
if docker compose version >/dev/null 2>&1; then
  ok "compose plugin: $(docker compose version --short 2>/dev/null) (need >= 2.24 for !reset/!override)"
else
  bad "docker compose v2 plugin not found"
fi

# --- env file ---------------------------------------------------------------
# envget reads KEY=VALUE lines from .env without executing it -- sourcing the
# file would run any shell code inside it. Exported environment wins over .env.
envget() {
  eval "val=\"\${${1}:-}\""
  if [ -z "${val}" ] && [ -f .env ]; then
    val=$(sed -n "s/^${1}=//p" .env | tail -n 1 | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//")
  fi
  printf '%s' "${val}"
}

if [ -f .env ]; then
  ok ".env present"
  # shellcheck disable=SC2012
  perms=$(ls -l .env | awk '{print $1}')
  case "${perms}" in
    -rw-------*) ok ".env permissions ${perms}" ;;
    *) warn ".env permissions ${perms}; chmod 0600 .env recommended (it holds egress credentials)" ;;
  esac
else
  warn "no .env; relying on exported environment variables"
fi

FABRIC_EXPORT_ENDPOINT="$(envget FABRIC_EXPORT_ENDPOINT)"
FABRIC_EXPORT_AUTH_HEADER="$(envget FABRIC_EXPORT_AUTH_HEADER)"
FABRIC_INGRESS_TOKEN_FILE="$(envget FABRIC_INGRESS_TOKEN_FILE)"
FABRIC_INGRESS_TLS_DIR="$(envget FABRIC_INGRESS_TLS_DIR)"
FABRIC_BIND_ADDR="$(envget FABRIC_BIND_ADDR)"

# --- required egress settings ------------------------------------------------
case "${FABRIC_EXPORT_ENDPOINT:-}" in
  "")        bad "FABRIC_EXPORT_ENDPOINT unset" ;;
  https://*) ok "egress endpoint is https" ;;
  http://*)  bad "FABRIC_EXPORT_ENDPOINT is http://; production egress requires https" ;;
  *)         bad "FABRIC_EXPORT_ENDPOINT is not a URL: ${FABRIC_EXPORT_ENDPOINT}" ;;
esac

if [ -z "${FABRIC_EXPORT_AUTH_HEADER:-}" ]; then
  bad "FABRIC_EXPORT_AUTH_HEADER unset; egress delivery would be unauthenticated"
else
  ok "egress Authorization header set"
fi

# --- ingress token ------------------------------------------------------------
if [ -z "${FABRIC_INGRESS_TOKEN_FILE:-}" ]; then
  bad "FABRIC_INGRESS_TOKEN_FILE unset; ingress would have no bearer token"
elif [ ! -f "${FABRIC_INGRESS_TOKEN_FILE}" ]; then
  bad "FABRIC_INGRESS_TOKEN_FILE points at a missing file: ${FABRIC_INGRESS_TOKEN_FILE}"
elif [ ! -s "${FABRIC_INGRESS_TOKEN_FILE}" ]; then
  bad "ingress token file is empty: ${FABRIC_INGRESS_TOKEN_FILE}"
else
  ok "ingress token file present and non-empty"
  # shellcheck disable=SC2012
  tperms=$(ls -l "${FABRIC_INGRESS_TOKEN_FILE}" | awk '{print $1}')
  case "${tperms}" in
    -rw-------*) ok "token file permissions ${tperms}" ;;
    *) warn "token file permissions ${tperms}; chmod 0600 recommended" ;;
  esac
fi

# --- ingress TLS (only if enabled in collector-production.yaml) ---------------
# Look for an uncommented tls: stanza inside the receivers: block only; the
# exporter's TLS-verify settings are always on and must not trip this check.
receiver_tls_enabled() {
  sed -n '/^receivers:/,/^processors:/p' collector-config/collector-production.yaml \
    | grep -q '^[[:space:]]*tls:'
}

if receiver_tls_enabled; then
  tlsdir="${FABRIC_INGRESS_TLS_DIR:-./tls}"
  if [ -s "${tlsdir}/server.crt" ] && [ -s "${tlsdir}/server.key" ]; then
    ok "ingress TLS cert/key present in ${tlsdir}"
  else
    bad "tls: stanzas enabled but ${tlsdir}/{server.crt,server.key} missing"
  fi
else
  ok "receiver TLS disabled (loopback-only deployment is consistent with this)"
fi

# --- bind address sanity ------------------------------------------------------
bind="${FABRIC_BIND_ADDR:-127.0.0.1}"
if [ "${bind}" != "127.0.0.1" ]; then
  if receiver_tls_enabled; then
    ok "non-loopback bind (${bind}) with TLS enabled"
  else
    bad "FABRIC_BIND_ADDR=${bind} publishes OTLP beyond loopback but receiver TLS is disabled"
  fi
else
  ok "OTLP ports bind loopback only"
fi

# --- optional reachability probe (warn-only: destination may not exist yet) ---
if [ -n "${FABRIC_EXPORT_ENDPOINT:-}" ]; then
  hostport=$(printf '%s' "${FABRIC_EXPORT_ENDPOINT}" | sed -e 's|^https\?://||' -e 's|/.*||')
  if command -v nc >/dev/null 2>&1; then
    if nc -z -w 3 "${hostport%%:*}" "${hostport##*:}" >/dev/null 2>&1 || nc -z -w 3 "${hostport%%:*}" 443 >/dev/null 2>&1; then
      ok "egress destination host reachable"
    else
      warn "egress destination not reachable yet (ok if provisioned later; queue buffers)"
    fi
  else
    note "SKIP" "nc not installed; skipping reachability probe"
  fi
fi

printf '\n'
if [ "${fail}" -ne 0 ]; then
  printf 'Preflight FAILED -- resolve the items above before make up-prod\n' >&2
  exit 1
fi
printf 'Preflight passed -- safe to run make up-prod\n'
