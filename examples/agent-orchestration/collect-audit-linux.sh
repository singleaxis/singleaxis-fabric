#!/usr/bin/env bash
# Real auditd collection for the demo on Linux hosts.
#
# Replaces audit_shim.py entirely: kernel auditd produces the same
# record stream (same format, same -k fabric tagging) that the
# collector's audit receiver tails in logfile mode, or consumes live
# over netlink with CAP_AUDIT_READ.
#
#   sudo bash examples/agent-orchestration/collect-audit-linux.sh start
#   … run agent.py …
#   sudo bash examples/agent-orchestration/collect-audit-linux.sh stop
set -euo pipefail
cd "$(dirname "$0")"
RULES="$(pwd)/../../deploy/auditd/fabric.rules"
LOG="$(pwd)/out/audit/audit.log"
mkdir -p out/audit

case "${1:-}" in
  start)
    auditctl -R "$RULES"
    # Point the demo collector at the real audit log instead of the
    # shim path: mount /var/log/audit read-only over ./out/audit.
    touch "$LOG"   # path kept for config compatibility; real data in /var/log/audit
    echo "auditd rules loaded (-k fabric). Point the collector's"
    echo "audit receiver at /var/log/audit/audit.log, or bind-mount:"
    echo "  -v /var/log/audit:/demo-audit:ro"
    ;;
  stop)
    auditctl -D -k fabric || auditctl -R <(grep -v '^-a' "$RULES" | head -0) || true
    echo "fabric rules removed"
    ;;
  *) echo "usage: $0 start|stop"; exit 2 ;;
esac
