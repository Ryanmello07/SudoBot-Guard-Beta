#!/usr/bin/env bash
# Alerts if / crosses 85% used. WAL/backups are the most likely cause if
# this ever fires -- see backup-base.sh's retention pruning.
set -euo pipefail
MONITORING_ENV="/etc/sudobot-guard/monitoring.env"
[[ -f "${MONITORING_ENV}" ]] && source "${MONITORING_ENV}"

USAGE="$(df --output=pcent / | tail -1 | tr -dc '0-9')"
if (( USAGE >= 85 )); then
    MSG="sudobot-guard host disk usage at ${USAGE}% on / -- check ${BACKUP_ROOT:-/var/backups/sudobot-guard} for unpruned backups/WAL."
    echo "${MSG}"
    if [[ -n "${DISK_ALERT_EMAIL:-}" ]] && command -v mail &>/dev/null; then
        echo "${MSG}" | mail -s "sudobot-guard: disk usage ${USAGE}%" "${DISK_ALERT_EMAIL}"
    fi
fi
