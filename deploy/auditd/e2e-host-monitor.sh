#!/usr/bin/env bash
# End-to-end test of the auditd host connector on a Linux-capable Docker
# engine.
#
#   bash deploy/auditd/e2e-host-monitor.sh
#
# What it proves:
#   1. The collector's audit receiver tails audit.log, assembles multi-record
#      events, and emits event_class=audit records through fabricguard.
#   2. execve/connect/openat events surface with the allowlisted attributes.
#   3. Raw argv never appears — only process.command_args_sha256.
#   4. The netlink source binds and joins multicast; on capability-masked
#      kernels (Docker Desktop) manage_rules degrades gracefully.
set -euo pipefail

IMG="${IMG:-fabric-otelcol:local}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CFG="$HERE/collector-e2e.yaml"
NET="fabric-audit-e2e"
WORK="$(mktemp -d)"
LOGDIR="$WORK/audit"
mkdir -p "$LOGDIR"
touch "$LOGDIR/audit.log"
MARKER="fabric-e2e-marker-$$"

cleanup() {
  docker rm -f fabric-audit-col >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

docker network create "$NET" >/dev/null

echo "==> starting collector (logfile source)"
docker run -d --name fabric-audit-col --network "$NET" \
  --user 0 \
  -v "$CFG:/etc/otelcol/config.yaml:ro" \
  -v "$LOGDIR:/var/log/audit:ro" \
  "$IMG" --config /etc/otelcol/config.yaml >/dev/null
sleep 3

# Append audit-format records to the tailed log — exactly what auditd writes.
# Serials are unique; multi-record events share the serial.
cat >> "$LOGDIR/audit.log" <<EOF
type=SYSCALL msg=audit(1726000000.001:201): arch=c000003e syscall=59 success=yes exit=0 ppid=10 pid=42 auid=1000 uid=0 comm="$MARKER" exe="/tmp/$MARKER" key="fabric"
type=EXECVE msg=audit(1726000000.001:201): argc=3 a0="$MARKER" a1="--exfil" a2="secret-flag-value"
type=CWD msg=audit(1726000000.001:201): cwd="/tmp"
type=PROCTITLE msg=audit(1726000000.001:201): proctitle=6661627269632D6532652D6D61726B6572
type=EOE msg=audit(1726000000.001:201):
type=SYSCALL msg=audit(1726000000.002:202): arch=c000003e syscall=42 success=yes exit=0 ppid=10 pid=42 auid=1000 comm="agent-tool" exe="/usr/bin/agent-tool" key="fabric"
type=SOCKADDR msg=audit(1726000000.002:202): saddr=020000350A0000050000000000000000
type=EOE msg=audit(1726000000.002:202):
type=SYSCALL msg=audit(1726000000.003:203): arch=c000003e syscall=59 success=no exit=-13 ppid=10 pid=43 auid=1000 comm="rm" exe="/usr/bin/rm" key="fabric"
type=EOE msg=audit(1726000000.003:203):
type=SYSCALL msg=audit(1726000000.004:204): arch=c000003e syscall=257 success=yes exit=3 ppid=10 pid=44 auid=1000 comm="cat" exe="/usr/bin/cat" key="fabric"
type=PATH msg=audit(1726000000.004:204): item=0 name="/etc/shadow" nametype=UNKNOWN
type=EOE msg=audit(1726000000.004:204):
type=SYSCALL msg=audit(1726000000.005:205): arch=c000003e syscall=59 success=yes exit=0 ppid=10 pid=45 auid=1000 comm="noisy" exe="/usr/bin/noisy" key="other"
type=EOE msg=audit(1726000000.005:205):
EOF

sleep 4
LOGS="$(docker logs fabric-audit-col 2>&1)"

fail=0
# Herestrings avoid the grep -q + SIGPIPE + pipefail false-negative on large
# captured logs.
check() { if grep -q "$1" <<<"$LOGS"; then echo "  PASS: $2"; else echo "  FAIL: $2"; fail=1; fi; }
check_absent() { if grep -q "$1" <<<"$LOGS"; then echo "  FAIL: $2 (leaked: $1)"; fail=1; else echo "  PASS: $2"; fi; }

echo "==> assertions"
check "$MARKER" "exec event for marker binary surfaced"
check "process.command_args_sha256" "argv emitted as sha256"
check_absent "secret-flag-value" "raw argv never emitted"
check "connect" "connect syscall recorded"
check "10.0.0.5" "peer address decoded from saddr"
check "failed:EACCES" "denied execve recorded as failure"
check_absent "/etc/shadow" "file_access off → openat dropped"
check_absent '"noisy"' "foreign rule_key filtered"

if [ "$fail" -ne 0 ]; then
  echo "==> collector logs:"
  docker logs fabric-audit-col 2>&1 | tail -30
  exit 1
fi

echo "==> netlink-mode check (bind + multicast join; rules need real host auditd)"
docker rm -f fabric-audit-col >/dev/null
docker run -d --name fabric-audit-col --network "$NET" \
  --cap-add AUDIT_READ --user 0 \
  -v "$HERE/collector-host-monitor-e2e-netlink.yaml:/etc/otelcol/config.yaml:ro" \
  "$IMG" --config /etc/otelcol/config.yaml >/dev/null 2>&1 || true
sleep 3
NLOGS="$(docker logs fabric-audit-col 2>&1)"
if grep -q "Everything is ready" <<<"$NLOGS"; then
  echo "  PASS: netlink source bound and receiver started"
else
  echo "  FAIL: netlink source did not start"
  echo "$NLOGS" | tail -15
  fail=1
fi
if grep -q "manage_rules failed; continuing as passive listener" <<<"$NLOGS"; then
  echo "  PASS: manage_rules degraded gracefully on masked kernel"
fi

[ "$fail" -eq 0 ] && echo "==> all auditd e2e assertions passed" || exit 1
