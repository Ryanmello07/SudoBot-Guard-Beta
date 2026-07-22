#!/usr/bin/env bash
# Dead-man's-switch: pings HEARTBEAT_URL only while sudobot-guard.service
# is actually active. If the service dies, this stops pinging and the
# monitoring provider (e.g. healthchecks.io) alerts on the missed ping --
# the one failure mode the bot itself can never self-report to its own
# Discord log channel.
set -euo pipefail
MONITORING_ENV="/etc/sudobot-guard/monitoring.env"
[[ -f "${MONITORING_ENV}" ]] && source "${MONITORING_ENV}"

[[ -n "${HEARTBEAT_URL:-}" ]] || exit 0

if systemctl is-active --quiet sudobot-guard.service; then
    curl -fsS -m 10 --retry 2 "${HEARTBEAT_URL}" >/dev/null 2>&1 || true
fi
