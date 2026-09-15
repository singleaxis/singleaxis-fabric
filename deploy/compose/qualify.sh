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

count() {
  value="$(curl -fsS "http://${sink_address}/count" 2>/dev/null \
    | sed -n 's/.*"count": *\([0-9][0-9]*\).*/\1/p')"
  printf '%s' "${value:-0}"
}

wait_for_growth() {
  baseline="$1"
  attempts=0
  while [ "${attempts}" -lt 30 ]; do
    current="$(count)"
    if [ "${current}" -gt "${baseline}" ]; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  printf 'sink count did not grow beyond %s\n' "${baseline}" >&2
  return 1
}

before="$(count)"
curl -fsS -X POST "http://${otlp_address}/v1/traces" \
  -H 'Content-Type: application/json' --data-binary "@${fixture}" >/dev/null
wait_for_growth "${before}"

if curl -fsS "http://${sink_address}/contains?needle=MUST_NOT_LEAVE_FABRIC_NODE" \
  | grep -q '"found": true'; then
  printf 'non-allowlisted marker crossed the Fabric Node boundary\n' >&2
  exit 1
fi
printf 'PASS: default-deny export protection removed the forbidden marker\n'

before_outage="$(count)"
${compose} stop test-sink >/dev/null
sink_stopped=1
curl -fsS -X POST "http://${otlp_address}/v1/traces" \
  -H 'Content-Type: application/json' --data-binary "@${fixture}" >/dev/null
# Let batch hand the request to the persistent exporter queue while the sink is
# unavailable, then restart Fabric Node to prove the queue is not memory-only.
sleep 3
${compose} restart fabric-node >/dev/null
${compose} start test-sink >/dev/null
sink_stopped=0
wait_for_growth "${before_outage}"
printf 'PASS: queued request survived destination outage and Fabric Node restart\n'
printf 'NOTE: this proves at-least-once recovery to the controlled fsync sink, not exactly-once delivery or persistence semantics of arbitrary destinations.\n'
