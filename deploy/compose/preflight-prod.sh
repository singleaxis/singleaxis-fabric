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
FABRIC_EXPORT_CA_FILE="$(envget FABRIC_EXPORT_CA_FILE)"
FABRIC_INGRESS_TLS_CERT_FILE="$(envget FABRIC_INGRESS_TLS_CERT_FILE)"
FABRIC_INGRESS_TLS_KEY_FILE="$(envget FABRIC_INGRESS_TLS_KEY_FILE)"
# The image runs as distroless nonroot (uid/gid 65532). Bind-mounted files
# keep their host owner and mode, so that user must be able to read them.
# Override only for an image built with a different nonroot user.
NODE_UID="$(envget FABRIC_NODE_UID)"; NODE_UID="${NODE_UID:-65532}"
NODE_GID="$(envget FABRIC_NODE_GID)"; NODE_GID="${NODE_GID:-65532}"

# file_meta PATH -> "uid gid mode" (GNU stat, then BSD stat).
file_meta() {
  stat -c '%u %g %a' "$1" 2>/dev/null || stat -f '%u %g %Lp' "$1" 2>/dev/null
}

# node_access PATH BIT -> 0 when the node user gets BIT (4=r, 1=x) on PATH.
node_access() {
  meta=$(file_meta "$1") || return 1
  # shellcheck disable=SC2086 # split "uid gid mode" into fields
  set -- ${meta} "$2"
  m="${3#"${3%???}"}"
  u=${m%??}; g=${m#?}; g=${g%?}; o=${m#??}
  if [ "$1" = "${NODE_UID}" ]; then [ $((u & $4)) -ne 0 ]; return; fi
  if [ "$2" = "${NODE_GID}" ]; then [ $((g & $4)) -ne 0 ]; return; fi
  [ $((o & $4)) -ne 0 ]
}

# other_bits PATH -> the "other" permission digit.
other_bits() {
  meta=$(file_meta "$1") || { printf '7'; return; }
  # shellcheck disable=SC2086 # split "uid gid mode" into fields
  set -- ${meta}
  printf '%s' "${3#"${3%?}"}"
}

# check_node_secret LABEL PATH: readable by the node user, closed to others.
check_node_secret() {
  if [ "$(other_bits "$2")" != "0" ]; then
    bad "$1 $2 is accessible to every host user; chown root:${NODE_GID} + chmod 0440 (or chown ${NODE_UID}:${NODE_GID} + chmod 0400)"
  elif ! node_access "$2" 4; then
    bad "$1 $2 is not readable by the container user ${NODE_UID}:${NODE_GID}; chown root:${NODE_GID} + chmod 0440 (or chown ${NODE_UID}:${NODE_GID} + chmod 0400)"
  else
    ok "$1 readable by container user ${NODE_UID}:${NODE_GID} and closed to other users"
  fi
}

# check_node_readable LABEL PATH: public material (certificates, CA bundles).
check_node_readable() {
  if node_access "$2" 4; then
    ok "$1 readable by container user ${NODE_UID}:${NODE_GID}"
  else
    bad "$1 $2 is not readable by the container user ${NODE_UID}:${NODE_GID}; chmod 0444 or chgrp ${NODE_GID}"
  fi
}

# host_tls_path CONTAINER_PATH -> host path under FABRIC_INGRESS_TLS_DIR, or
# fails when the path is outside the only mounted TLS directory.
host_tls_path() {
  case "$1" in
    *..*) return 1 ;;
    /run/fabric-node/tls/?*) printf '%s/%s' "${FABRIC_INGRESS_TLS_DIR:-./tls}" "${1#/run/fabric-node/tls/}" ;;
    *) return 1 ;;
  esac
}

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
elif grep -q '^[[:space:]]*$' "${FABRIC_INGRESS_TOKEN_FILE}"; then
  # bearertokenauth v0.150.0 splits the file on newlines and keeps EMPTY
  # entries: a blank line mints "Bearer " (empty token) as a valid
  # credential, which gRPC metadata preserves verbatim -- auth bypass.
  bad "ingress token file contains a blank line; an empty 'Bearer ' credential would authenticate -- remove blank lines"
elif [ -z "$(tail -c1 "${FABRIC_INGRESS_TOKEN_FILE}")" ]; then
  # Same extension quirk: a trailing newline produces a trailing empty
  # entry -> "Bearer " authenticates. The only safe file ends mid-line.
  bad "ingress token file ends with a newline; an empty 'Bearer ' credential would authenticate -- rewrite without trailing newline (printf %s, not echo or > from a newline-terminated source)"
else
  ok "ingress token file present, non-empty, single-entry-safe format"
  # Compose file secrets are bind mounts: owner and mode are the host's.
  check_node_secret "ingress token file" "${FABRIC_INGRESS_TOKEN_FILE}"
fi

# --- ingress TLS (only if enabled in collector-production.yaml) ---------------
# Look for an uncommented tls: stanza inside the receivers: block only; the
# exporter's TLS-verify settings are always on and must not trip this check.
COLLECTOR_CONFIG=collector-config/collector-production.yaml
if [ ! -f "${COLLECTOR_CONFIG}" ]; then
  bad "collector config missing: ${COLLECTOR_CONFIG} (run from deploy/compose)"
fi

# --- persistent queue disk headroom (warn-only) -----------------------------
if [ -f "${COLLECTOR_CONFIG}" ]; then
  # Worst case = queue_size items x max request size. Read the configured
  # receiver bound (max_request_body_size bytes / max_recv_msg_size_mib);
  # fall back to the collector's 20 MiB HTTP default when unset.
  read -r queue_size max_item_mb <<EOF
$(awk '
    /^[[:space:]]*sending_queue:[[:space:]]*$/ { in_queue = 1; next }
    in_queue && /^[[:space:]]*queue_size:[[:space:]]*/ {
      sub(/^[[:space:]]*queue_size:[[:space:]]*/, "")
      sub(/[[:space:]]*(#.*)?$/, "")
      queue_size = $0
      in_queue = 0
    }
    /^[[:space:]]*max_request_body_size:[[:space:]]*/ {
      sub(/^[[:space:]]*max_request_body_size:[[:space:]]*/, "")
      sub(/[[:space:]]*(#.*)?$/, "")
      max_body = $0 + 0
    }
    /^[[:space:]]*max_recv_msg_size_mib:[[:space:]]*/ {
      sub(/^[[:space:]]*max_recv_msg_size_mib:[[:space:]]*/, "")
      sub(/[[:space:]]*(#.*)?$/, "")
      max_recv = $0 + 0
    }
    END {
      # Round bytes up: flooring a non-MiB-aligned HTTP limit would
      # understate the worst-case queue disk estimate.
      http_mb = (max_body > 0) ? int((max_body + 1048575) / 1048576) : 20
      if (http_mb < 1) http_mb = 1
      grpc_mb = (max_recv > 0) ? max_recv : 4
      item_mb = (http_mb > grpc_mb) ? http_mb : grpc_mb
      print queue_size, item_mb
    }
  ' "${COLLECTOR_CONFIG}")
EOF
  case "${queue_size}" in
    ''|*[!0-9]*)
      warn "could not parse sending_queue.queue_size from ${COLLECTOR_CONFIG}; skipping disk-headroom check"
      ;;
    *)
      queue_estimate_mb=$((queue_size * max_item_mb))
      available_mb=$(df -Pm . 2>/dev/null | awk 'NR == 2 { print $4 }')
      case "${available_mb}" in
        ''|*[!0-9]*)
          warn "could not determine free space for compose project; skipping disk-headroom check"
          ;;
        *)
          if [ "${available_mb}" -lt "${queue_estimate_mb}" ]; then
            warn "queue disk headroom is ${available_mb} MiB; worst-case estimate is ${queue_estimate_mb} MiB (${queue_size} items at up to ${max_item_mb} MiB/request; typical records are far smaller)"
          else
            ok "queue disk headroom is ${available_mb} MiB (worst-case estimate ${queue_estimate_mb} MiB at ${max_item_mb} MiB/request)"
          fi
          ;;
      esac
      ;;
  esac
fi

receiver_tls_enabled() {
  [ -f "${COLLECTOR_CONFIG}" ] || return 1
  sed -n '/^receivers:/,/^processors:/p' "${COLLECTOR_CONFIG}" \
    | grep -q '^[[:space:]]*tls:'
}

tlsdir="${FABRIC_INGRESS_TLS_DIR:-./tls}"
if receiver_tls_enabled; then
  cert_path=$(host_tls_path "${FABRIC_INGRESS_TLS_CERT_FILE:-/run/fabric-node/tls/server.crt}") || cert_path=""
  key_path=$(host_tls_path "${FABRIC_INGRESS_TLS_KEY_FILE:-/run/fabric-node/tls/server.key}") || key_path=""
  if [ -z "${cert_path}" ] || [ -z "${key_path}" ]; then
    bad "FABRIC_INGRESS_TLS_CERT_FILE/KEY_FILE must be under /run/fabric-node/tls (the mounted FABRIC_INGRESS_TLS_DIR)"
  elif [ -s "${cert_path}" ] && [ -s "${key_path}" ]; then
    ok "ingress TLS cert/key present in ${tlsdir}"
    node_access "${tlsdir}" 1 || bad "TLS directory ${tlsdir} is not searchable by the container user ${NODE_UID}:${NODE_GID}"
    check_node_readable "ingress TLS certificate" "${cert_path}"
    check_node_secret "ingress TLS private key" "${key_path}"
  else
    bad "tls: stanzas enabled but ${cert_path} or ${key_path} missing"
  fi
else
  ok "receiver TLS disabled (loopback-only deployment is consistent with this)"
fi

# --- egress private CA (only if ca_file is enabled in collector-production.yaml)
export_ca_enabled() {
  [ -f "${COLLECTOR_CONFIG}" ] || return 1
  sed -n '/^exporters:/,/^service:/p' "${COLLECTOR_CONFIG}" \
    | grep -q '^[[:space:]]*ca_file:'
}

if export_ca_enabled; then
  ca_container="${FABRIC_EXPORT_CA_FILE:-/run/fabric-node/tls/ca.crt}"
  if ! ca_path=$(host_tls_path "${ca_container}"); then
    bad "FABRIC_EXPORT_CA_FILE=${ca_container} must be under /run/fabric-node/tls (the mounted FABRIC_INGRESS_TLS_DIR)"
  elif [ ! -s "${ca_path}" ]; then
    bad "egress ca_file enabled but ${ca_path} (container ${ca_container}) is missing or empty"
  else
    ok "egress CA bundle present: ${ca_path}"
    node_access "${tlsdir}" 1 || bad "TLS directory ${tlsdir} is not searchable by the container user ${NODE_UID}:${NODE_GID}"
    check_node_readable "egress CA bundle" "${ca_path}"
  fi
elif [ -n "${FABRIC_EXPORT_CA_FILE:-}" ]; then
  warn "FABRIC_EXPORT_CA_FILE is set but ca_file is commented out in ${COLLECTOR_CONFIG}; egress uses the system trust store"
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
