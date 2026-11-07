#!/usr/bin/env sh
# Pre-flight checks for the client-VM production overlay. Run before
# `make up-prod` so a broken deployment fails here, not on the customer's box.
#
# Output never echoes a configured value (endpoints, paths, addresses, ids):
# any of them could hold a credential pasted into the wrong variable, and this
# output lands in terminals and CI logs. Messages name the variable instead.
# The only values printed are fixed text, values from a closed set after they
# matched it (e.g. the SSE mode), numeric uid/gids and file mode bits.
#
# --groups checks the static dedicated ingress groups of `make up-prod-groups`
# (spec 053 §6.1, spec 056 §7.3.3 (h)) instead of the single binding: every
# enabled group's token file and source id, distinct token bytes and distinct
# source ids across groups, and receiver TLS on every listener.
set -eu

GROUPS_MODE=0
case "${1:-}" in
  '') ;;
  --groups) GROUPS_MODE=1 ;;
  *) printf 'usage: preflight-prod.sh [--groups]\n' >&2; exit 2 ;;
esac

fail=0
note() { printf '  %s %s\n' "$1" "$2"; }
ok()   { note "PASS" "$1"; }
bad()  { note "FAIL" "$1"; fail=1; }
warn() { note "WARN" "$1"; }

if [ "${GROUPS_MODE}" -eq 1 ]; then
  printf 'Fabric Node production preflight (ingress groups)\n'
else
  printf 'Fabric Node production preflight\n'
fi

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
# The env file: FABRIC_ENV_FILE (any path; the Makefile passes it), else .env here.
ENV_FILE="${FABRIC_ENV_FILE:-.env}"
# envget reads KEY=VALUE lines from .env without executing it -- sourcing the
# file would run any shell code inside it. Exported environment wins over .env.
envget() {
  eval "val=\"\${${1}:-}\""
  if [ -z "${val}" ] && [ -f "${ENV_FILE}" ]; then
    val=$(sed -n "s/^${1}=//p" "${ENV_FILE}" | tail -n 1 | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//")
  fi
  printf '%s' "${val}"
}

if [ -f "${ENV_FILE}" ]; then
  ok "env file ${ENV_FILE} present"
  # shellcheck disable=SC2012
  perms=$(ls -l "${ENV_FILE}" | awk '{print $1}')
  case "${perms}" in
    -rw-------*) ok "env file permissions ${perms}" ;;
    *) warn "env file permissions ${perms}; chmod 0600 it (it holds egress credentials)" ;;
  esac
else
  warn "no env file (${ENV_FILE}); relying on exported environment variables"
fi

FABRIC_EXPORT_ENDPOINT="$(envget FABRIC_EXPORT_ENDPOINT)"
FABRIC_EXPORT_AUTH_HEADER="$(envget FABRIC_EXPORT_AUTH_HEADER)"
# shellcheck disable=SC2034 # read through value_of by check_token
FABRIC_INGRESS_TOKEN_FILE="$(envget FABRIC_INGRESS_TOKEN_FILE)"
FABRIC_INGRESS_TLS_DIR="$(envget FABRIC_INGRESS_TLS_DIR)"
FABRIC_BIND_ADDR="$(envget FABRIC_BIND_ADDR)"
FABRIC_EXPORT_CA_FILE="$(envget FABRIC_EXPORT_CA_FILE)"
FABRIC_INGRESS_TLS_CERT_FILE="$(envget FABRIC_INGRESS_TLS_CERT_FILE)"
FABRIC_INGRESS_TLS_KEY_FILE="$(envget FABRIC_INGRESS_TLS_KEY_FILE)"
FABRIC_TENANT_ID="$(envget FABRIC_TENANT_ID)"
FABRIC_SOURCE_ID="$(envget FABRIC_SOURCE_ID)"
FABRIC_CONTENT_KEY_FILE="$(envget FABRIC_CONTENT_KEY_FILE)"
FABRIC_CONTENT_BACKEND="$(envget FABRIC_CONTENT_BACKEND)"
FABRIC_CONTENT_REQUIRE_SSE="$(envget FABRIC_CONTENT_REQUIRE_SSE)"
FABRIC_CONTENT_S3_BUCKET="$(envget FABRIC_CONTENT_S3_BUCKET)"
FABRIC_CONTENT_S3_PREFIX="$(envget FABRIC_CONTENT_S3_PREFIX)"
FABRIC_CONTENT_S3_REGION="$(envget FABRIC_CONTENT_S3_REGION)"
FABRIC_CONTENT_S3_ENDPOINT="$(envget FABRIC_CONTENT_S3_ENDPOINT)"
FABRIC_CONTENT_S3_PATH_STYLE="$(envget FABRIC_CONTENT_S3_PATH_STYLE)"
FABRIC_CONTENT_S3_SSE="$(envget FABRIC_CONTENT_S3_SSE)"
FABRIC_CONTENT_S3_KMS_KEY_ID="$(envget FABRIC_CONTENT_S3_KMS_KEY_ID)"
# The group variables below are read through value_of (by name).
# shellcheck disable=SC2034
FABRIC_AGENT_SOURCE_ID="$(envget FABRIC_AGENT_SOURCE_ID)"
# shellcheck disable=SC2034
FABRIC_EBPF_SOURCE_ID="$(envget FABRIC_EBPF_SOURCE_ID)"
# shellcheck disable=SC2034
FABRIC_EBPF_TOKEN_FILE="$(envget FABRIC_EBPF_TOKEN_FILE)"
FABRIC_AUDITD_SOURCE_ID="$(envget FABRIC_AUDITD_SOURCE_ID)"
FABRIC_AUDITD_TOKEN_FILE="$(envget FABRIC_AUDITD_TOKEN_FILE)"
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

# Docker Desktop (macOS, Windows, Docker Desktop for Linux) shares host files
# into its VM with their ownership mapped to the container's user: the image's
# uid reads any bind-mounted file the operator can read, and a host group
# 65532 is neither needed nor possible without sudo. FABRIC_BIND_MOUNT_OWNERSHIP
# =mapped|native overrides the detection (`docker info` names Docker Desktop).
BIND_MOUNT_OWNERSHIP="$(envget FABRIC_BIND_MOUNT_OWNERSHIP)"
case "${BIND_MOUNT_OWNERSHIP}" in
  '')
    if docker info --format '{{.OperatingSystem}}' 2>/dev/null | grep -q '^Docker Desktop'; then
      BIND_MOUNT_OWNERSHIP=mapped
    else
      BIND_MOUNT_OWNERSHIP=native
    fi ;;
  mapped|native) ;;
  *) bad "FABRIC_BIND_MOUNT_OWNERSHIP must be mapped (Docker Desktop) or native"; BIND_MOUNT_OWNERSHIP=native ;;
esac
if [ "${BIND_MOUNT_OWNERSHIP}" = mapped ]; then
  ok "bind mounts: Docker Desktop maps file ownership to the container user; files need only be readable by you and closed to others"
fi

# file_meta PATH -> "uid gid mode" (GNU stat, then BSD stat).
file_meta() {
  stat -c '%u %g %a' "$1" 2>/dev/null || stat -f '%u %g %Lp' "$1" 2>/dev/null
}

# node_access PATH BIT -> 0 when the node user gets BIT (4=r, 1=x) on PATH.
node_access() {
  if [ "${BIND_MOUNT_OWNERSHIP}" = mapped ]; then  # what the operator can read
    if [ "$2" = 1 ]; then [ -x "$1" ]; else [ -r "$1" ]; fi
    return
  fi
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
if [ "${BIND_MOUNT_OWNERSHIP}" = mapped ]; then
  SECRET_FIX="chmod 0400 (yours; Docker Desktop maps ownership to the container user)"
fi

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

# --- destination URL shape ----------------------------------------------------
# url_check URL: sets URL_PROBLEM to a fixed reason (empty when URL is valid),
# URL_SCHEME, URL_HOST (brackets stripped) and URL_PORT (empty when absent).
# Same rule as the Helm chart's otel-collector.validateURL: an absolute
# http(s) URL whose authority is exactly host[:port] -- a DNS name, a dotted
# IPv4 address or a bracketed IPv6 address, and a port 1-65535 -- plus an
# optional path. User info, a query or a fragment could carry a credential or
# a signed token into the collector config, so they are refused; credentials
# belong in FABRIC_EXPORT_AUTH_HEADER or the store's credential chain. Runs in
# the current shell (no subshell) and never prints anything.
url_check() {
  URL_PROBLEM=""; URL_SCHEME=""; URL_HOST=""; URL_PORT=""; URL_PATH=""
  case "$1" in
    https://*) URL_SCHEME=https; url_rest=${1#https://} ;;
    http://*) URL_SCHEME=http; url_rest=${1#http://} ;;
    *) URL_PROBLEM="is not an absolute http(s):// URL"; return 0 ;;
  esac
  case "$1" in
    *[[:space:]]*|*[[:cntrl:]]*|*\\*)
      URL_PROBLEM="must not contain whitespace, control characters or a backslash"; return 0 ;;
  esac
  case "$1" in
    *@*) URL_PROBLEM="must not contain user info (user:password@ or any '@')"; return 0 ;;
  esac
  case "$1" in
    *\?*|*\#*) URL_PROBLEM="must not contain a query or fragment ('?' or '#')"; return 0 ;;
  esac
  url_authority=${url_rest%%/*}
  URL_PATH=${url_rest#"${url_authority}"}
  url_has_port=0
  case "${url_authority}" in
    \[*\]) URL_HOST=${url_authority} ;;
    \[*\]:*) URL_HOST=${url_authority%%]:*}]; URL_PORT=${url_authority#*]:}; url_has_port=1 ;;
    \[*) URL_HOST="" ;;
    *:*) URL_HOST=${url_authority%:*}; URL_PORT=${url_authority##*:}; url_has_port=1 ;;
    *) URL_HOST=${url_authority} ;;
  esac
  url_host_ok=0
  case "${URL_HOST}" in
    \[*)
      if matches '^\[[0-9A-Fa-f.]*:[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*\]$' "${URL_HOST}"; then
        url_host_ok=1
        URL_HOST=${URL_HOST#\[}; URL_HOST=${URL_HOST%\]}
      fi
      ;;
    *[!0-9.]*|'')
      # A fully qualified name may end with the root label's dot (example.com.).
      url_name=${URL_HOST%.}
      if [ "${#url_name}" -le 253 ] \
        && matches '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$' "${url_name}"; then
        url_host_ok=1
      fi
      ;;
    *)
      if matches '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "${URL_HOST}"; then
        url_host_ok=1
        url_octets=${URL_HOST}
        while [ -n "${url_octets}" ]; do
          url_octet=${url_octets%%.*}
          [ "${url_octet}" -le 255 ] || url_host_ok=0
          case "${url_octets}" in *.*) url_octets=${url_octets#*.} ;; *) url_octets="" ;; esac
        done
      fi
      ;;
  esac
  if [ "${url_host_ok}" -ne 1 ]; then
    URL_PROBLEM="host must be a DNS name, a dotted IPv4 address or a bracketed IPv6 address"
    return 0
  fi
  if [ "${url_has_port}" -eq 1 ]; then
    if ! matches '^[1-9][0-9]{0,4}$' "${URL_PORT}" || [ "${URL_PORT}" -gt 65535 ]; then
      URL_PROBLEM="port must be a number from 1 to 65535"
    fi
  fi
  return 0
}
matches() { printf '%s' "$2" | grep -Eq -- "$1"; }

# --- required egress settings ------------------------------------------------
export_endpoint_ok=0
if [ -z "${FABRIC_EXPORT_ENDPOINT:-}" ]; then
  bad "FABRIC_EXPORT_ENDPOINT unset"
else
  url_check "${FABRIC_EXPORT_ENDPOINT}"
  if [ -n "${URL_PROBLEM}" ]; then
    bad "FABRIC_EXPORT_ENDPOINT ${URL_PROBLEM} (value not shown); put credentials in FABRIC_EXPORT_AUTH_HEADER"
  elif [ "${URL_SCHEME}" != https ]; then
    bad "FABRIC_EXPORT_ENDPOINT is http://; production egress requires https"
  else
    ok "egress endpoint is a valid https URL"
    export_endpoint_ok=1
    export_host=${URL_HOST}
    export_port=${URL_PORT:-443}
  fi
fi

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
# value_of VAR: the value of the variable named VAR (empty when unset).
value_of() {
  eval "printf '%s' \"\${${1}:-}\""
}

# check_token VAR LABEL UNSET: one bearer token file. VAR names the variable,
# LABEL is fixed text naming the file, UNSET the consequence of an unset VAR.
check_token() {
  token_path=$(value_of "$1")
  if [ -z "${token_path}" ]; then
    bad "$1 unset; $3"
  elif [ ! -f "${token_path}" ]; then
    bad "$1 points at a missing file"
  elif [ ! -r "${token_path}" ]; then
    bad "cannot read $2 ($1) as uid ${OPERATOR_UID}, so its format cannot be checked; ${SECRET_FIX}"
  elif [ ! -s "${token_path}" ]; then
    bad "$2 ($1) is empty"
  elif blank_lines=$(token_blank_lines "${token_path}")
    last_byte=$(token_last_byte "${token_path}")
    [ -z "${blank_lines}" ] || [ -z "${last_byte}" ]; then
    bad "reading $2 ($1) failed, so its format cannot be checked; ${SECRET_FIX}"
  elif [ "${blank_lines}" != "0" ]; then
    # The Node accepts exactly one token per file (require_single_token).
    # bearertokenauth up to v0.150.0 also kept EMPTY entries, so a blank line
    # minted "Bearer " (empty token) as a valid credential -- auth bypass.
    bad "$2 contains a blank line; the Node accepts exactly one token with no blank lines -- remove blank lines"
  elif [ "${last_byte}" = "$(printf '\nx')" ]; then
    # A trailing newline makes the file malformed for require_single_token
    # (the Node then accepts no token); up to v0.150.0 it also produced a
    # trailing empty entry -> "Bearer " authenticated. The file ends mid-line.
    bad "$2 ends with a newline; the Node would reject the token file -- rewrite without trailing newline (printf %s, not echo or > from a newline-terminated source)"
  else
    ok "$2 present, non-empty, single-entry-safe format"
    # Compose file secrets are bind mounts: owner and mode are the host's.
    check_node_secret "$2" "${token_path}"
  fi
}
check_token FABRIC_INGRESS_TOKEN_FILE "ingress token file" "ingress would have no bearer token"

# --- ingress groups (spec 053 §6.1): one credential and one source each -------
# A group is enabled by its token file (the agent and eBPF groups always are).
# Equal token bytes would let one group's sender present as another's source;
# equal source ids would bind one source twice. Neither value is ever printed.
if [ "${GROUPS_MODE}" -eq 1 ]; then
  check_token FABRIC_EBPF_TOKEN_FILE "eBPF group token file" "the ebpf ingress group would have no bearer token"
  group_tokens="FABRIC_INGRESS_TOKEN_FILE FABRIC_EBPF_TOKEN_FILE"
  group_sources="FABRIC_AGENT_SOURCE_ID FABRIC_EBPF_SOURCE_ID"
  if [ -n "${FABRIC_AUDITD_TOKEN_FILE:-}" ]; then
    check_token FABRIC_AUDITD_TOKEN_FILE "auditd group token file" "the auditd ingress group would have no bearer token"
    group_tokens="${group_tokens} FABRIC_AUDITD_TOKEN_FILE"
    group_sources="${group_sources} FABRIC_AUDITD_SOURCE_ID"
  elif [ -n "${FABRIC_AUDITD_SOURCE_ID:-}" ]; then
    warn "FABRIC_AUDITD_SOURCE_ID is set without FABRIC_AUDITD_TOKEN_FILE; the auditd group stays disabled"
  fi
  seen=""
  for variable in ${group_tokens}; do
    path=$(value_of "${variable}")
    for previous in ${seen}; do
      previous_path=$(value_of "${previous}")
      if [ -r "${path}" ] && [ -r "${previous_path}" ] && cmp -s "${path}" "${previous_path}"; then
        bad "${previous} and ${variable} hold the same token bytes; every ingress group needs its own credential (spec 053 §6.1 rule 5)"
      fi
    done
    seen="${seen} ${variable}"
  done
  seen=""
  for variable in ${group_sources}; do
    value=$(value_of "${variable}")
    if [ -z "${value}" ]; then
      bad "${variable} unset; an enabled ingress group binds exactly one source (spec 053 §6.1)"
    elif matches '^s-[0-9a-f]{32}$' "${value}"; then
      ok "${variable} set (pseudonymous s- form)"
    elif [ "${variable}" = FABRIC_AGENT_SOURCE_ID ] && matches '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' "${value}"; then
      warn "FABRIC_AGENT_SOURCE_ID is not an s-<32 hex> pseudonym; it binds only agents running with FABRIC_WIRE_LABELS=clear"
    else
      bad "${variable} must be s-<32 lowercase hex>: a host sensor's source id is the pseudonym of its source label (fabric-host-emitter print-source-id)"
    fi
    for previous in ${seen}; do
      if [ -n "${value}" ] && [ "${value}" = "$(value_of "${previous}")" ]; then
        bad "${variable} equals ${previous}; no two groups bind one source (spec 053 §6.1 rule 7) -- each sensor has its own source label"
      fi
    done
    seen="${seen} ${variable}"
  done
fi

# --- ingress TLS (only if enabled in collector-production.yaml) ---------------
# Look for an uncommented tls: stanza inside the receivers: block only; the
# exporter's TLS-verify settings are always on and must not trip this check.
COLLECTOR_CONFIG=collector-config/collector-production.yaml
[ "${GROUPS_MODE}" -eq 0 ] || COLLECTOR_CONFIG=collector-config/collector-production-groups.yaml
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
# The content path (spec 048) is opt-in: FABRIC_CONTENT_BACKEND=s3 or file
# makes `make up-prod` merge docker-compose.content.yml, which adds
# collector-content.yaml (and, for s3, collector-content-s3.yaml) after
# COLLECTOR_CONFIG. The checks below see those files too, the way the
# collector and fabric-gate see the merged configuration. Unset: telemetry
# only, exactly the production profile without content.
CONTENT_CONFIGS=""
if [ "${GROUPS_MODE}" -eq 1 ]; then
  # docker-compose.host-ingress-auditd.yml / -content.yml merge these.
  [ -z "${FABRIC_AUDITD_TOKEN_FILE:-}" ] || CONTENT_CONFIGS="collector-config/collector-production-groups-auditd.yaml"
  case "${FABRIC_CONTENT_BACKEND:-}" in
    s3) CONTENT_CONFIGS="${CONTENT_CONFIGS} collector-config/collector-production-groups-content.yaml" ;;
    file) bad "FABRIC_CONTENT_BACKEND=file is not available with ingress groups; use s3 (server-side encryption, as the Helm profile requires)" ;;
  esac
else
  case "${FABRIC_CONTENT_BACKEND:-}" in
    s3) CONTENT_CONFIGS="collector-config/collector-content.yaml collector-config/collector-content-s3.yaml collector-config/collector-content-s3-production.yaml" ;;
    file) CONTENT_CONFIGS="collector-config/collector-content.yaml" ;;
  esac
fi
FLAT_CONFIG="$(yaml_flatten "${COLLECTOR_CONFIG}")"
for content_config in ${CONTENT_CONFIGS}; do
  if [ -f "${content_config}" ]; then
    FLAT_CONFIG="${FLAT_CONFIG}
$(yaml_flatten "${content_config}")"
  else
    bad "FABRIC_CONTENT_BACKEND=${FABRIC_CONTENT_BACKEND} needs ${content_config} (run from deploy/compose)"
  fi
done

# --- persistent queue disk headroom (warn-only) -----------------------------
# Worst case = queue_size items x max request size, per queue. Telemetry uses
# the larger otlp receiver bound (max_request_body_size bytes or
# max_recv_msg_size_mib; the collector's 20 MiB HTTP default when unset).
# The content queue (fabriccontent, spec 048) holds up to 64 MiB per item.
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
# "tls: null"/"~", or a stanza missing either file is disabled (spec 048 F9).
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

# Spec 053 §6.1 rule 8: every ingress-group listener uses TLS (fabric-gate
# refuses a plaintext group listener even on a loopback-published port).
if [ "${GROUPS_MODE}" -eq 1 ] && [ -n "${RECEIVERS}" ]; then
  plain_groups=$(printf '%s\n' "${RECEIVERS}" | awk '$4 != "tls" { printf "%s.%s:%s ", $1, $2, $3 }')
  if [ -n "${plain_groups}" ]; then
    bad "ingress-group listeners without TLS: ${plain_groups% }; every group listener needs an uncommented tls: mapping with cert_file and key_file (spec 053 §6.1 rule 8)"
  else
    ok "every ingress-group listener serves TLS"
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
  ok "both receiver TLS stanzas not verified (loopback-only publication required)"
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
[ "${GROUPS_MODE}" -eq 0 ] || PUBLISHED_OTLP_PORTS="${PUBLISHED_OTLP_PORTS} 4417 4428"
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

# --- source binding (spec 049 §7.9, P0-A) ---------------------------------------
# The production profile rejects unauthenticated sources: fabricguard (and the
# content exporter) bind every batch to FABRIC_TENANT_ID and FABRIC_SOURCE_ID,
# the agents' source id as it travels (s-<32 hex> under their default
# pseudonymous labels). A Node configured before P0-A stops here, not in the
# application.
source_bound() {
  printf '%s\n' "${FLAT_CONFIG}" | awk -F '\t' '
    { n = split($1, k, "|") }
    k[1] == "processors" && k[2] == "fabricguard" && k[3] == "evidence_source_binding" { found = 1 }
    END { exit(found ? 0 : 1) }'
}
# group_bound GROUP: fabricguard/GROUP carries its evidence_source_binding.
group_bound() {
  printf '%s\n' "${FLAT_CONFIG}" | awk -F '\t' -v id="fabricguard/$1" '
    { n = split($1, k, "|") }
    k[1] == "processors" && k[2] == id && k[3] == "evidence_source_binding" { found = 1 }
    END { exit(found ? 0 : 1) }'
}
if [ "${GROUPS_MODE}" -eq 1 ]; then
  bound_groups="agent ebpf"
  [ -z "${FABRIC_AUDITD_TOKEN_FILE:-}" ] || bound_groups="${bound_groups} auditd"
  for group in ${bound_groups}; do
    if group_bound "${group}"; then
      ok "ingress group ${group} is bound (fabricguard/${group} evidence_source_binding)"
    else
      bad "fabricguard/${group} has no evidence_source_binding; every ingress group binds one source (spec 053 §6.1)"
    fi
  done
  if [ -z "${FABRIC_TENANT_ID:-}" ]; then
    bad "FABRIC_TENANT_ID unset; every ingress group binds one tenant (spec 053 §6.1)"
  elif ! matches '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' "${FABRIC_TENANT_ID}"; then
    bad "FABRIC_TENANT_ID is not a safe tenant id (^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\$)"
  else
    ok "bound tenant set"
  fi
elif source_bound; then
  if [ -z "${FABRIC_TENANT_ID:-}" ]; then
    bad "FABRIC_TENANT_ID unset; the production profile binds every agent batch to one tenant (spec 049 §7.9)"
  elif ! matches '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' "${FABRIC_TENANT_ID}"; then
    bad "FABRIC_TENANT_ID is not a safe tenant id (^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\$)"
  else
    ok "bound tenant set"
  fi
  if [ -z "${FABRIC_SOURCE_ID:-}" ]; then
    bad "FABRIC_SOURCE_ID unset; the production profile binds every agent batch to one source (spec 049 §7.9) -- set the agents' source id as it travels (s-<32 hex> under pseudonymous labels)"
  elif ! matches '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' "${FABRIC_SOURCE_ID}"; then
    bad "FABRIC_SOURCE_ID is not a safe source id (^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\$)"
  elif matches '^s-[0-9a-f]{32}$' "${FABRIC_SOURCE_ID}"; then
    ok "bound source set (pseudonymous s- form)"
  else
    warn "FABRIC_SOURCE_ID is not an s-<32 hex> pseudonym; it binds only agents running with FABRIC_WIRE_LABELS=clear (fabricguard capture_labels: clear)"
  fi
else
  bad "fabricguard has no evidence_source_binding; the production profile rejects unauthenticated sources (spec 049 §7.9)"
fi

# --- content path (spec 048) ---------------------------------------------------
# The Node is the only content writer. Values are checked for shape; URLs and
# secrets are never echoed.
content_configured() {
  printf '%s\n' "${FLAT_CONFIG}" | awk -F '\t' '
    { n = split($1, k, "|") }
    n == 2 && k[1] == "exporters" && k[2] ~ /^fabriccontent(\/|$)/ { found = 1 }
    END { exit(found ? 0 : 1) }'
}
case "${FABRIC_CONTENT_BACKEND:-}" in
  ''|file|s3) ;;
  *) bad "FABRIC_CONTENT_BACKEND must be s3 or file, or unset for a telemetry-only Node" ;;
esac
case "${FABRIC_CONTENT_REQUIRE_SSE:-true}" in
  true|false) ;;
  *) bad "FABRIC_CONTENT_REQUIRE_SSE must be true or false" ;;
esac
if content_configured; then
  if [ -z "${FABRIC_TENANT_ID:-}" ]; then
    bad "FABRIC_TENANT_ID unset; the content exporter would accept no tenant"
  elif ! matches '^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$' "${FABRIC_TENANT_ID}"; then
    bad "FABRIC_TENANT_ID is not a safe tenant id (^[A-Za-z0-9][A-Za-z0-9._-]{0,255}\$)"
  else
    ok "content tenant set"
  fi
  # Spec 049 §7.8: the content queue (and the directory store) are sealed
  # with the Node-side customer key, a file-backed Compose secret.
  if [ -z "${FABRIC_CONTENT_KEY_FILE:-}" ]; then
    bad "FABRIC_CONTENT_KEY_FILE unset; the production content queue and store are encrypted with the Node content key (spec 049 §7.8)"
  elif [ ! -f "${FABRIC_CONTENT_KEY_FILE}" ]; then
    bad "FABRIC_CONTENT_KEY_FILE points at a missing file"
  elif [ ! -r "${FABRIC_CONTENT_KEY_FILE}" ]; then
    bad "cannot read the content key file (FABRIC_CONTENT_KEY_FILE) as uid ${OPERATOR_UID}, so its format cannot be checked; ${SECRET_FIX}"
  else
    key_bytes=$(wc -c < "${FABRIC_CONTENT_KEY_FILE}" | tr -d ' ')
    key_text=$(tr -d '\n' < "${FABRIC_CONTENT_KEY_FILE}" 2>/dev/null || true)
    if [ "${key_bytes}" = "32" ] \
      || { { [ "${key_bytes}" = "44" ] || [ "${key_bytes}" = "45" ]; } \
           && [ "${#key_text}" = "44" ] && matches '^[A-Za-z0-9+/]{43}=$' "${key_text}"; }; then
      ok "content key file holds a 32-byte key"
      check_node_secret "content key file" "${FABRIC_CONTENT_KEY_FILE}"
    else
      bad "content key file (FABRIC_CONTENT_KEY_FILE) must hold 32 raw bytes or their base64 (openssl rand -base64 32)"
    fi
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
      # As the Helm shadow-production profile (content.requireServerSideEncryption):
      # the file backend has no server-side encryption, so production refuses
      # it unless the operator records that the host disk's encryption is
      # accepted instead.
      if [ "${FABRIC_CONTENT_REQUIRE_SSE:-true}" != false ]; then
        bad "the file content backend has no server-side encryption; production requires it (as the Helm shadow-production profile does). Use FABRIC_CONTENT_BACKEND=s3, or set FABRIC_CONTENT_REQUIRE_SSE=false to accept the host disk's encryption"
      else
        warn "content store is the local fabric-content volume; FABRIC_CONTENT_REQUIRE_SSE=false accepts the host disk's encryption at rest (FABRIC_CONTENT_BACKEND=s3 adds server-side encryption)"
      fi
      ;;
    s3)
      [ -f collector-config/collector-content-s3.yaml ] && [ -f docker-compose.content-s3.yml ] \
        && [ -f collector-config/collector-content.yaml ] && [ -f docker-compose.content.yml ] \
        || bad "FABRIC_CONTENT_BACKEND=s3 needs collector-config/collector-content.yaml, collector-config/collector-content-s3.yaml, docker-compose.content.yml and docker-compose.content-s3.yml"
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
      if [ -z "${FABRIC_CONTENT_S3_ENDPOINT:-}" ]; then
        ok "content store is AWS S3 (default endpoint)"
      else
        url_check "${FABRIC_CONTENT_S3_ENDPOINT}"
        if [ -n "${URL_PROBLEM}" ]; then
          bad "FABRIC_CONTENT_S3_ENDPOINT ${URL_PROBLEM} (value not shown); store credentials come from the instance role or the credentials-file overlay"
        elif [ -n "${URL_PATH}" ] && [ "${URL_PATH}" != / ]; then
          # The exporter refuses an endpoint path at startup (config.go).
          bad "FABRIC_CONTENT_S3_ENDPOINT must not contain a path: it is scheme://host[:port]; the bucket and FABRIC_CONTENT_S3_PREFIX are separate settings"
        elif [ "${URL_SCHEME}" != https ]; then
          bad "FABRIC_CONTENT_S3_ENDPOINT is plaintext http; content would leave the Node unencrypted in transit -- use https"
        else
          ok "content store endpoint uses https"
        fi
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
    *) ;;  # refused above
  esac
elif [ -n "${FABRIC_CONTENT_BACKEND:-}" ]; then
  bad "FABRIC_CONTENT_BACKEND is set but no fabriccontent exporter is configured"
fi

# --- site overlays (FABRIC_COMPOSE_EXTRA) -------------------------------------
# The shipped test-only S3 store must never hold real content, so say so on every
# run that enables it (a warning, not a failure: docs/production-setup.md uses it to
# try the production Node). Only the fixed file name is printed, after it matched.
FABRIC_COMPOSE_EXTRA="$(envget FABRIC_COMPOSE_EXTRA)"
test_store=0
set -f  # the list is split on whitespace; never glob-expand it
for extra in ${FABRIC_COMPOSE_EXTRA}; do
  [ "${extra##*/}" = docker-compose.content-s3-local-tls.yml ] && test_store=1
done
set +f
if [ "${test_store}" -eq 1 ]; then
  warn "FABRIC_COMPOSE_EXTRA enables docker-compose.content-s3-local-tls.yml, a TEST-ONLY local S3 store (one container, no replication, a test certificate, static keys): never use it for real content; for production remove it from FABRIC_COMPOSE_EXTRA and point FABRIC_CONTENT_S3_* at your own bucket"
fi

# --- optional reachability probe (warn-only: destination may not exist yet) ---
# Only a validated endpoint is probed, and nc receives its host and port only.
if [ "${export_endpoint_ok}" -eq 1 ]; then
  if command -v nc >/dev/null 2>&1; then
    if nc -z -w 3 "${export_host}" "${export_port}" >/dev/null 2>&1; then
      ok "egress destination host reachable"
    else
      warn "egress destination not reachable yet (ok if provisioned later; queue buffers)"
    fi
  else
    note "SKIP" "nc not installed; skipping reachability probe"
  fi
fi

# --- spec 049 §7.3: agent-side requirements (048 §1 superseded) --------------
# Not checkable from the Node: stated on every run so an upgrade cannot miss it.
note "INFO" "spec 049 P0-A: agents in node mode are the production profile; they record content only with a capture policy (FABRIC_CAPTURE_POLICY) and FABRIC_WIRE_ID_KEY, otherwise metadata only (spec 048 §1 superseded)"

printf '\n'
if [ "${fail}" -ne 0 ]; then
  if [ "${GROUPS_MODE}" -eq 1 ]; then
    printf 'Preflight FAILED -- resolve the items above before make up-prod-groups\n' >&2
  else
    printf 'Preflight FAILED -- resolve the items above before make up-prod\n' >&2
  fi
  exit 1
fi
printf 'Preflight checks passed -- runtime certificate/configuration validation still required\n'
