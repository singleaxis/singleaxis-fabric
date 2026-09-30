#!/usr/bin/env bash
# This demo intentionally does not install or remove host-wide audit rules.
# Host collection requires a separately approved, isolated disposable Linux
# environment and scoped rules with an independently reviewed cleanup plan.
set -euo pipefail

case "${1:-}" in
  start|stop)
    echo "Refusing host audit rule changes: this demo has no approved scoped rule set." >&2
    echo "Use a separately reviewed isolated Linux qualification environment; see deploy/auditd/README.md." >&2
    exit 2
    ;;
  *) echo "usage: $0 start|stop (both refuse until a scoped plan is approved)" >&2; exit 2 ;;
esac
