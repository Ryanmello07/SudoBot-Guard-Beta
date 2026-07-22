#!/usr/bin/env bash
# Runs a fresh pg_basebackup, then prunes anything older than the last 2
# daily base backups plus the WAL segments needed to recover from the
# older of those two -- bounded disk usage, recovery to any point within
# roughly the last 24-48 hours. Run by sudobot-guard-backup.timer nightly,
# and safe to run manually.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

BASE_DIR="${BACKUP_ROOT}/base"
WAL_DIR="${BACKUP_ROOT}/wal"
STAMP="$(date +%Y%m%d-%H%M%S)"

mkdir -p "${BASE_DIR}" "${WAL_DIR}"

log_info "Taking base backup ${STAMP}..."
sudo -u "${BACKUP_SVC_USER}" env PGPASSFILE=/etc/sudobot-guard/pgpass pg_basebackup \
    -h 127.0.0.1 -U "${DB_BACKUP_ROLE}" \
    -D "${BASE_DIR}/${STAMP}" -Fp -Xs -P

# Keep only the 2 most recent base backups.
mapfile -t backups < <(find "${BASE_DIR}" -maxdepth 1 -mindepth 1 -type d | sort)
if (( ${#backups[@]} > 2 )); then
    to_remove=$(( ${#backups[@]} - 2 ))
    for i in $(seq 0 $((to_remove - 1))); do
        log_info "Pruning old base backup: ${backups[$i]}"
        rm -rf "${backups[$i]}"
    done
fi

# Keep only WAL segments newer than the oldest remaining base backup.
mapfile -t remaining < <(find "${BASE_DIR}" -maxdepth 1 -mindepth 1 -type d | sort)
if (( ${#remaining[@]} > 0 )); then
    oldest_base="${remaining[0]}"
    find "${WAL_DIR}" -type f -not -newer "${oldest_base}" -delete
fi

log_info "Base backup complete: ${BASE_DIR}/${STAMP}"
