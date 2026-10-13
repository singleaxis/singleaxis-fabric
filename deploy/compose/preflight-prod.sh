#!/usr/bin/env sh
# Pre-flight checks for the client-VM production overlay. Run before
# `make up-prod` so a broken deployment fails here, not on the customer's box.
#
# Output never echoes a configured value (endpoints, paths, addresses, ids):
# any of them could hold a credential pasted into the wrong variable, and this
# output lands in terminals and CI logs. Messages name the variable instead.
# The only values printed are fixed text, values from a closed set after they
# matched it (e.g. the SSE mode), numeric uid/gids and file mode bits.
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
FABRIC_TENANT_ID="$(envget FABRIC_TENANT_ID)"
FABRIC_CONTENT_BACKEND="$(envget FABRIC_CONTENT_BACKEND)"
FABRIC_CONTENT_S3_BUCKET="$(envget FABRIC_CONTENT_S3_BUCKET)"
FABRIC_CONTENT_S3_PREFIX="$(envget FABRIC_CONTENT_S3_PREFIX)"
FABRIC_CONTENT_S3_REGION="$(envget FABRIC_CONTENT_S3_REGION)"
FABRIC_CONTENT_S3_ENDPOINT="$(envget FABRIC_CONTENT_S3_ENDPOINT)"
FABRIC_CONTENT_S3_PATH_STYLE="$(envget FABRIC_CONTENT_S3_PATH_STYLE)"
FABRIC_CONTENT_S3_SSE="$(envget FABRIC_CONTENT_S3_SSE)"
FABRIC_CONTENT_S3_KMS_KEY_ID="$(envget FABRIC_CONTENT_S3_KMS_KEY_ID)"
# The image runs as distroless nonroot (uid/gid 65532). Bind-mounted files
# keep their host owner and mode, so that user must be able to read them.
# Override only for an image built with a different nonroot user.
NODE_UID="$(envget FABRIC_NODE_UID)"; NODE_UID="${NODE_UID:-65532}"
NODE_GID="$(envget FABRIC_NODE_GID)"; NODE_GID="${NODE_GID:-65532}"
case "${NODE_UID}" in
  ''|*[!0-9]*) bad "FABRIC_NODE_UID must be a numeric uid"; NODE_UID=65532 ;;
esac
case "${NODE_GID}" in
  ''|*[!0-9]*) bad "FABRIC_NODE_GID must be a numeric gid"; NODE_GID=65532 ;;
esac

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

# The recommended ownership for a secret file: the operator who runs
# preflight owns it (so preflight can validate its content) and the image's
# group reads it (so the container can use it); nobody else can.
OPERATOR_UID="$(id -u 2>/dev/null || printf 'OPERATOR')"
SECRET_FIX="chown ${OPERATOR_UID}:${NODE_GID} + chmod 0440 (operator-owned, group ${NODE_GID}, no access for others)"

# check_node_secret LABEL PATH: readable by the node user, closed to others.
# LABEL is fixed text naming the file; PATH is never printed.
check_node_secret() {
  if [ "$(other_bits "$2")" != "0" ]; then
    bad "$1 is accessible to every host user; ${SECRET_FIX}"
  elif ! node_access "$2" 4; then
    bad "$1 is not readable by the container user ${NODE_UID}:${NODE_GID}; ${SECRET_FIX}"
  else
    ok "$1 readable by container user ${NODE_UID}:${NODE_GID} and closed to other users"
  fi
}

# check_node_readable LABEL PATH: public material (certificates, CA bundles).
check_node_readable() {
  if node_access "$2" 4; then
    ok "$1 readable by container user ${NODE_UID}:${NODE_GID}"
  else
    bad "$1 is not readable by the container user ${NODE_UID}:${NODE_GID}; chmod 0444 or chgrp ${NODE_GID}"
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
  *)         bad "FABRIC_EXPORT_ENDPOINT is not an https:// URL (value not shown)" ;;
esac

if [ -z "${FABRIC_EXPORT_AUTH_HEADER:-}" ]; then
  bad "FABRIC_EXPORT_AUTH_HEADER unset; egress delivery would be unauthenticated"
else
  ok "egress Authorization header set"
fi

# --- ingress token ------------------------------------------------------------
# token_blank_lines / token_last_byte print nothing when the file cannot be
# read, so a read failure is reported as such, never as a content problem.
token_blank_lines() {
  grep -c '^[[:space:]]*$' "$1" 2>/dev/null || true
}
token_last_byte() {
  # The trailing "x" keeps a final newline from being stripped by $(...).
  { tail -c1 "$1" 2>/dev/null && printf 'x'; } || true
}
if [ -z "${FABRIC_INGRESS_TOKEN_FILE:-}" ]; then
  bad "FABRIC_INGRESS_TOKEN_FILE unset; ingress would have no bearer token"
elif [ ! -f "${FABRIC_INGRESS_TOKEN_FILE}" ]; then
  bad "FABRIC_INGRESS_TOKEN_FILE points at a missing file"
elif [ ! -r "${FABRIC_INGRESS_TOKEN_FILE}" ]; then
  bad "cannot read ingress token file (FABRIC_INGRESS_TOKEN_FILE) as uid ${OPERATOR_UID}, so its format cannot be checked; ${SECRET_FIX}"
elif [ ! -s "${FABRIC_INGRESS_TOKEN_FILE}" ]; then
  bad "ingress token file (FABRIC_INGRESS_TOKEN_FILE) is empty"
elif blank_lines=$(token_blank_lines "${FABRIC_INGRESS_TOKEN_FILE}")
  last_byte=$(token_last_byte "${FABRIC_INGRESS_TOKEN_FILE}")
  [ -z "${blank_lines}" ] || [ -z "${last_byte}" ]; then
  bad "reading ingress token file (FABRIC_INGRESS_TOKEN_FILE) failed, so its format cannot be checked; ${SECRET_FIX}"
elif [ "${blank_lines}" != "0" ]; then
  # bearertokenauth v0.150.0 splits the file on newlines and keeps EMPTY
  # entries: a blank line mints "Bearer " (empty token) as a valid
  # credential, which gRPC metadata preserves verbatim -- auth bypass.
  bad "ingress token file contains a blank line; an empty 'Bearer ' credential would authenticate -- remove blank lines"
elif [ "${last_byte}" = "$(printf '\nx')" ]; then
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

# yaml_flatten FILE: one "<key|key|...>\t<value>" line per mapping key, for
# the block-style YAML subset collector configs use. Comment-only and blank
# lines are skipped, trailing comments and key quotes are stripped, sequence
# items are ignored. Commented-out stanzas therefore never count.
yaml_flatten() {
  [ -f "$1" ] || return 0
  awk -v q="'" '
    /^[[:space:]]*(#.*)?$/ { next }
    {
      line = $0
      sub(/[[:space:]]+#.*$/, "", line)
      match(line, /^ */)
      ind = RLENGTH
      body = substr(line, ind + 1)
      if (substr(body, 1, 1) == "-") next
      c = index(body, ":")
      if (c == 0) next
      key = substr(body, 1, c - 1)
      val = substr(body, c + 1)
      sub(/^[[:space:]]+/, "", val)
      sub(/[[:space:]]+$/, "", val)
      gsub(/"/, "", key)
      gsub(q, "", key)
      while (d > 0 && si[d] >= ind) d--
      d++
      si[d] = ind
      sk[d] = key
      path = sk[1]
      for (i = 2; i <= d; i++) path = path "|" sk[i]
      printf "%s\t%s\n", path, val
    }' "$1"
}
FLAT_CONFIG="$(yaml_flatten "${COLLECTOR_CONFIG}")"

# --- persistent queue disk headroom (warn-only) -----------------------------
# Worst case = queue_size items x max request size, per queue. Telemetry uses
# the larger otlp receiver bound (max_request_body_size bytes or
# max_recv_msg_size_mib; the collector's 20 MiB HTTP default when unset).
# The content queue (fabriccontent, spec 043) holds up to 64 MiB per item.
if [ -f "${COLLECTOR_CONFIG}" ]; then
  read -r queue_size max_item_mb content_queue content_item_mb <<EOF
$(printf '%s\n' "${FLAT_CONFIG}" | awk -F '\t' '
    { n = split($1, k, "|") }
    k[1] == "receivers" && k[n] == "max_request_body_size" {
      if (k[2] ~ /^otlp\/content/) { if ($2 + 0 > content_body) content_body = $2 + 0 }
      else if ($2 + 0 > max_body) max_body = $2 + 0
    }
    k[1] == "receivers" && k[n] == "max_recv_msg_size_mib" && k[2] !~ /^otlp\/content/ {
      if ($2 + 0 > max_recv) max_recv = $2 + 0
    }
    k[1] == "exporters" && n == 4 && k[3] == "sending_queue" && k[4] == "queue_size" {
      if (k[2] ~ /^fabriccontent(\/|$)/) { if ($2 + 0 > content_q) content_q = $2 + 0 }
      else if (queue_size == "" || $2 + 0 > queue_size + 0) queue_size = $2
    }
    END {
      # Round bytes up: flooring a non-MiB-aligned HTTP limit would
      # understate the worst-case queue disk estimate.
      http_mb = (max_body > 0) ? int((max_body + 1048575) / 1048576) : 20
      if (http_mb < 1) http_mb = 1
      grpc_mb = (max_recv > 0) ? max_recv : 4
      item_mb = (http_mb > grpc_mb) ? http_mb : grpc_mb
      content_mb = (content_body > 0) ? int((content_body + 1048575) / 1048576) : 20
      if (queue_size == "") queue_size = "-"
      print queue_size, item_mb, content_q + 0, content_mb
    }')
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
          if [ "${content_queue:-0}" -gt 0 ]; then
            content_estimate_mb=$((content_queue * content_item_mb))
            total_mb=$((queue_estimate_mb + content_estimate_mb))
            if [ "${available_mb}" -lt "${total_mb}" ]; then
              warn "content queue worst-case estimate is ${content_estimate_mb} MiB (${content_queue} items at up to ${content_item_mb} MiB/record); with telemetry ${total_mb} MiB exceeds ${available_mb} MiB free"
            else
              ok "content queue worst-case estimate ${content_estimate_mb} MiB (${content_queue} items at up to ${content_item_mb} MiB/record); ${total_mb} MiB with telemetry fits"
            fi
          fi
          ;;
      esac
      ;;
  esac
fi

# receiver_table: one "<id> <protocol> <port> <tls|plain> <auth|noauth>" line
# per protocol of every otlp receiver instance (otlp, otlp/content, ...).
# TLS counts as enabled only for an uncommented tls: mapping with non-empty
# cert_file AND key_file. A commented stanza, a childless "tls:", "tls: {}",
# "tls: null"/"~", or a stanza missing either file is disabled (spec 043 F9).
# An endpoint without a port gets the protocol default (4317 gRPC, 4318 HTTP).
receiver_table() {
  printf '%s\n' "${FLAT_CONFIG}" | awk -F '\t' -v q="'" '
    { n = split($1, k, "|") }
    k[1] != "receivers" || n < 4 || k[3] != "protocols" || k[2] !~ /^otlp(\/|$)/ { next }
    {
      id = k[2] " " k[4]
      if (!(id in seen)) { seen[id] = 1; order[++m] = id }
    }
    n == 5 && k[5] == "endpoint" {
      p = $2
      sub(/.*:/, "", p)
      gsub(/[^0-9]/, "", p)
      port[id] = p
    }
    n == 5 && k[5] == "tls" { tls[id] = 1; tlsval[id] = $2 }
    n == 6 && k[5] == "tls" && (k[6] == "cert_file" || k[6] == "key_file") {
      v = $2
      gsub(/"/, "", v)
      gsub(q, "", v)
      if (v != "" && v != "null" && v != "~") file[id, k[6]] = 1
    }
    n == 5 && k[5] == "auth" && $2 ~ /authenticator:[[:space:]]*[^[:space:],}]/ { auth[id] = 1 }
    n == 6 && k[5] == "auth" && k[6] == "authenticator" && $2 != "" { auth[id] = 1 }
    END {
      for (i = 1; i <= m; i++) {
        id = order[i]
        split(id, parts, " ")
        p = port[id]
        if (p == "") p = (parts[2] == "grpc") ? 4317 : 4318
        on = 0
        if (tls[id]) {
          v = tlsval[id]
          if (v == "") on = (file[id, "cert_file"] && file[id, "key_file"])
          else on = (v ~ /cert_file:[[:space:]]*[^[:space:],}"\047]/ && v ~ /key_file:[[:space:]]*[^[:space:],}"\047]/)
        }
        print parts[1], parts[2], p, (on ? "tls" : "plain"), (auth[id] ? "auth" : "noauth")
      }
    }'
}
RECEIVERS="$(receiver_table)"

receiver_tls_enabled() {
  printf '%s\n' "${RECEIVERS}" | awk '$4 == "tls" { found = 1 } END { exit(found ? 0 : 1) }'
}

# Every OTLP ingress, the content receiver included, must authenticate.
if [ -n "${RECEIVERS}" ]; then
  unauthenticated=$(printf '%s\n' "${RECEIVERS}" | awk '$5 == "noauth" { printf "%s.%s:%s ", $1, $2, $3 }')
  if [ -n "${unauthenticated}" ]; then
    bad "OTLP receivers without an authenticator: ${unauthenticated% }; every ingress (including otlp/content) needs auth: authenticator: bearertokenauth"
  else
    ok "every OTLP receiver requires the bearer token"
  fi
fi

tlsdir="${FABRIC_INGRESS_TLS_DIR:-./tls}"
if receiver_tls_enabled; then
  cert_path=$(host_tls_path "${FABRIC_INGRESS_TLS_CERT_FILE:-/run/fabric-node/tls/server.crt}") || cert_path=""
  key_path=$(host_tls_path "${FABRIC_INGRESS_TLS_KEY_FILE:-/run/fabric-node/tls/server.key}") || key_path=""
  if [ -z "${cert_path}" ] || [ -z "${key_path}" ]; then
    bad "FABRIC_INGRESS_TLS_CERT_FILE/KEY_FILE must be under /run/fabric-node/tls (the mounted FABRIC_INGRESS_TLS_DIR)"
  elif [ -s "${cert_path}" ] && [ -s "${key_path}" ]; then
    ok "ingress TLS cert/key present in FABRIC_INGRESS_TLS_DIR"
    node_access "${tlsdir}" 1 || bad "FABRIC_INGRESS_TLS_DIR is not searchable by the container user ${NODE_UID}:${NODE_GID}"
    check_node_readable "ingress TLS certificate" "${cert_path}"
    check_node_secret "ingress TLS private key" "${key_path}"
  else
    bad "tls: stanzas enabled but the certificate or key (FABRIC_INGRESS_TLS_CERT_FILE / FABRIC_INGRESS_TLS_KEY_FILE in FABRIC_INGRESS_TLS_DIR) is missing or empty"
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
    bad "FABRIC_EXPORT_CA_FILE must be under /run/fabric-node/tls (the mounted FABRIC_INGRESS_TLS_DIR)"
  elif [ ! -s "${ca_path}" ]; then
    bad "egress ca_file enabled but the CA bundle (FABRIC_EXPORT_CA_FILE in FABRIC_INGRESS_TLS_DIR) is missing or empty"
  else
    ok "egress CA bundle present"
    node_access "${tlsdir}" 1 || bad "FABRIC_INGRESS_TLS_DIR is not searchable by the container user ${NODE_UID}:${NODE_GID}"
    check_node_readable "egress CA bundle" "${ca_path}"
  fi
elif [ -n "${FABRIC_EXPORT_CA_FILE:-}" ]; then
  warn "FABRIC_EXPORT_CA_FILE is set but ca_file is commented out in ${COLLECTOR_CONFIG}; egress uses the system trust store"
fi

# --- bind address sanity ------------------------------------------------------
# Compose publishes 4317, 4318 and 4319 on FABRIC_BIND_ADDR: beyond loopback,
# EVERY receiver protocol serving one of those ports needs TLS genuinely
# enabled, or bearer tokens, telemetry and content cross the network in
# plaintext on that port.
PUBLISHED_OTLP_PORTS="4317 4318 4319"
bind="${FABRIC_BIND_ADDR:-127.0.0.1}"
case "${bind}" in
  127.*|localhost|::1|\[::1\]) loopback=1 ;;
  *) loopback=0 ;;
esac
if [ "${loopback}" -eq 1 ]; then
  ok "OTLP ports bind loopback only"
else
  exposure=$(printf '%s\n' "${RECEIVERS}" | awk -v ports=" ${PUBLISHED_OTLP_PORTS} " '
    index(ports, " " $3 " ") == 0 { next }
    { served = 1 }
    $4 != "tls" { plain = plain sprintf("%s.%s:%s ", $1, $2, $3) }
    END { printf "%d %s", served, plain }')
  served="${exposure%% *}"
  plaintext="${exposure#* }"
  if [ -n "${plaintext}" ]; then
    bad "FABRIC_BIND_ADDR publishes OTLP beyond loopback but TLS is not enabled on: ${plaintext% }; each needs an uncommented tls: mapping with non-empty cert_file and key_file (a commented, empty, {} or null tls: is disabled) -- or keep FABRIC_BIND_ADDR=127.0.0.1"
  elif [ "${served}" = "1" ]; then
    ok "non-loopback bind with TLS on every published OTLP receiver"
  else
    bad "FABRIC_BIND_ADDR publishes OTLP beyond loopback but no OTLP receiver serves ${PUBLISHED_OTLP_PORTS} in ${COLLECTOR_CONFIG}"
  fi
fi

# --- content path (spec 043) ---------------------------------------------------
# The Node is the only content writer. Values are checked for shape; URLs and
# secrets are never echoed.
content_configured() {
  printf '%s\n' "${FLAT_CONFIG}" | awk -F '\t' '
    { n = split($1, k, "|") }
    n == 2 && k[1] == "exporters" && k[2] ~ /^fabriccontent(\/|$)/ { found = 1 }
    END { exit(found ? 0 : 1) }'
}
matches() { printf '%s' "$2" | grep -Eq -- "$1"; }

if content_configured; then
  if [ -z "${FABRIC_TENANT_ID:-}" ]; then
    bad "FABRIC_TENANT_ID unset; the content exporter would accept no tenant"
  elif ! matches '^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$' "${FABRIC_TENANT_ID}"; then
    bad "FABRIC_TENANT_ID is not a safe tenant id (^[A-Za-z0-9][A-Za-z0-9._-]{0,255}\$)"
  else
    ok "content tenant set"
  fi
  content_rows=$(printf '%s\n' "${RECEIVERS}" | awk '$1 ~ /^otlp\/content/')
  if [ -z "${content_rows}" ]; then
    bad "fabriccontent is configured but no otlp/content receiver feeds it"
  elif printf '%s\n' "${content_rows}" | awk '$2 == "grpc" { found = 1 } END { exit(found ? 0 : 1) }'; then
    bad "the otlp/content receiver configures grpc; content ingress is HTTP only (fabric-gate refuses this)"
  else
    ok "content receiver is HTTP only"
  fi
  case "${FABRIC_CONTENT_BACKEND:-file}" in
    file)
      warn "content store is the local fabric-content volume; its encryption at rest is the host disk's (FABRIC_CONTENT_BACKEND=s3 adds server-side encryption)"
      ;;
    s3)
      [ -f collector-config/collector-content-s3.yaml ] && [ -f docker-compose.content-s3.yml ] \
        || bad "FABRIC_CONTENT_BACKEND=s3 needs collector-config/collector-content-s3.yaml and docker-compose.content-s3.yml"
      if matches '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' "${FABRIC_CONTENT_S3_BUCKET:-}"; then
        ok "content bucket name is valid"
      else
        bad "FABRIC_CONTENT_S3_BUCKET is unset or not a bucket name (no scheme, no path)"
      fi
      prefix="${FABRIC_CONTENT_S3_PREFIX:-fabric/content/}"
      if matches '/$' "${prefix}" && ! matches '^/|//|(^|/)\.\.?(/|$)' "${prefix}"; then
        ok "content prefix shape"
      else
        bad "FABRIC_CONTENT_S3_PREFIX must end with /, must not start with / and must not contain empty, . or .. segments"
      fi
      if [ -z "${FABRIC_CONTENT_S3_REGION:-}" ]; then
        bad "FABRIC_CONTENT_S3_REGION unset; set the bucket region"
      fi
      endpoint="${FABRIC_CONTENT_S3_ENDPOINT:-}"
      if [ -z "${endpoint}" ]; then
        ok "content store is AWS S3 (default endpoint)"
      elif matches '^https?://[^/?#@[:space:]]+(/[^?#@[:space:]]*)?$' "${endpoint}"; then
        case "${endpoint}" in
          https://*) ok "content store endpoint uses https" ;;
          *) bad "FABRIC_CONTENT_S3_ENDPOINT is plaintext http; content would leave the Node unencrypted in transit -- use https" ;;
        esac
      else
        bad "FABRIC_CONTENT_S3_ENDPOINT must be an http(s) URL without user info, query or fragment"
      fi
      case "${FABRIC_CONTENT_S3_PATH_STYLE:-false}" in
        true|false) ;;
        *) bad "FABRIC_CONTENT_S3_PATH_STYLE must be true or false" ;;
      esac
      sse="${FABRIC_CONTENT_S3_SSE:-aws:kms}"
      case "${sse}" in
        aws:kms|AES256) ok "content server-side encryption: ${sse}" ;;
        *) bad "FABRIC_CONTENT_S3_SSE must be aws:kms or AES256; production content is always encrypted at rest" ;;
      esac
      if [ -n "${FABRIC_CONTENT_S3_KMS_KEY_ID:-}" ] && [ "${sse}" != "aws:kms" ]; then
        bad "FABRIC_CONTENT_S3_KMS_KEY_ID is only valid with FABRIC_CONTENT_S3_SSE=aws:kms"
      fi
      ;;
    *)
      bad "FABRIC_CONTENT_BACKEND must be file or s3"
      ;;
  esac
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
