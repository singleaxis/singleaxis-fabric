#!/usr/bin/env sh
set -eu

compose="${COMPOSE:-docker compose}"
fixture="fixtures/decision-summary.json"

# `docker compose port` prints one host:port line per bound address family;
# take the first and map wildcard binds back to loopback for local curl.
published_port() {
  ${compose} port "$1" "$2" 2>/dev/null | head -n 1 \
    | sed -e 's/^0\.0\.0\.0:/127.0.0.1:/' -e 's/^\[::\]:/127.0.0.1:/'
}

otlp_address="$(published_port fabric-node 4318)"
sink_address="$(published_port test-sink 8080)"

if [ -z "${otlp_address}" ] || [ -z "${sink_address}" ]; then
  printf 'required service ports are not published; is the stack up?\n' >&2
  exit 1
fi

# If the script exits while the sink is stopped (failure, Ctrl-C, kill), put
# it back so the evaluation stack is not left degraded.
sink_stopped=0
restore_sink() {
  if [ "${sink_stopped}" -eq 1 ]; then
    printf 'restoring test-sink before exit\n' >&2
    ${compose} start test-sink >/dev/null 2>&1 || true
  fi
}
trap restore_sink EXIT
trap 'exit 1' INT TERM HUP

# The sink returns a deliberately narrow JSON shape. Reject unavailable,
# malformed, or unexpected readback rather than interpreting it as absence.
contains() {
  response="$(curl --max-time 10 -fsS "http://${sink_address}/contains?needle=$1")" || return 1
  response="$(printf '%s' "$response" | tr -d '[:space:]')"
  case "$response" in
    '{"found":true}') printf true ;;
    '{"found":false}') printf false ;;
    *) printf 'invalid sink readback\n' >&2; return 1 ;;
  esac
}

wait_for_request() {
  attempts=0
  while [ "$attempts" -lt 30 ]; do
    observed="$(contains "$request_id")" || return 1
    [ "$observed" = true ] && return 0
    attempts=$((attempts + 1))
    sleep 1
  done
  printf 'fresh request marker not observed at sink\n' >&2
  return 1
}

# A fresh exported request attribute correlates readback to this invocation.
# This is a controlled-sink byte-marker check, not full OTLP reconstruction.
request_id="req-qualify-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
[ "${#request_id}" -eq 44 ] || exit 1
fixture_copy="$(mktemp)"
cleanup() {
  restore_sink
  rm -f "$fixture_copy"
}
trap cleanup EXIT
sed "s/req-curl/${request_id}/g" "$fixture" > "$fixture_copy"
[ "$(contains "$request_id")" = false ] || exit 1
curl --max-time 10 -fsS -X POST "http://${otlp_address}/v1/traces" \
  -H 'Content-Type: application/json' --data-binary "@${fixture_copy}" >/dev/null
wait_for_request

if [ "$(contains MUST_NOT_LEAVE_FABRIC_NODE)" != false ]; then
  printf 'forbidden marker present or privacy readback failed\n' >&2
  exit 1
fi
printf 'PASS: default-deny export protection removed the forbidden marker\n'

request_id="${request_id}-restart"
sed "s/req-curl/${request_id}/g" "$fixture" > "$fixture_copy"
[ "$(contains "$request_id")" = false ] || exit 1
sink_stopped=1
${compose} stop test-sink >/dev/null
curl --max-time 10 -fsS -X POST "http://${otlp_address}/v1/traces" \
  -H 'Content-Type: application/json' --data-binary "@${fixture_copy}" >/dev/null
# Let the receiver hand the request to the persistent exporter queue while the sink is
# unavailable, then restart Fabric Node to prove the queue is not memory-only.
sleep 3
${compose} restart fabric-node >/dev/null
${compose} start test-sink >/dev/null
sink_stopped=0
wait_for_request
printf 'PASS: fresh request marker observed after destination outage and Fabric Node restart\n'
printf 'NOTE: this checks correlated recovery to the controlled fsync sink, not exactly-once delivery or persistence semantics of arbitrary destinations.\n'
