#!/usr/bin/env bash
# Restores Postgres to a specific point in time using the nearest base
# backup plus WAL replay. Usage: ./restore.sh "2026-07-22 14:30:00"
#
# This STOPS the bot and the live Postgres cluster and replaces the data
# directory -- it is a destructive recovery operation, not a drill you run
# against a live production instance without meaning to.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"
require_root

TARGET_TIME="${1:-}"
[[ -n "${TARGET_TIME}" ]] || die "Usage: $0 \"YYYY-MM-DD HH:MM:SS\""

BASE_DIR="${BACKUP_ROOT}/base"
WAL_DIR="${BACKUP_ROOT}/wal"

mapfile -t backups < <(find "${BASE_DIR}" -maxdepth 1 -mindepth 1 -type d | sort)
(( ${#backups[@]} > 0 )) || die "No base backups found in ${BASE_DIR}"
LATEST_BASE="${backups[-1]}"

log_warn "About to restore to '${TARGET_TIME}' using base backup: ${LATEST_BASE}"
read -rp "This stops the bot and replaces the live Postgres data directory. Type 'yes' to continue: " confirm
[[ "${confirm}" == "yes" ]] || die "Aborted."

# Must run BEFORE stopping postgres -- SHOW data_directory needs a live
# connection, and there's no safe hardcoded fallback: Ubuntu's packaged
# layout is /var/lib/postgresql/<version>/main, not .../data, so a guessed
# path here would feed a wrong directory into the mv/chown -R below. Fail
# closed instead of guessing.
local_pg_data="$(sudo -u postgres psql -tAc 'SHOW data_directory;')" \
    || die "Could not determine Postgres data directory (is the cluster running?)"
[[ -n "${local_pg_data}" && -d "${local_pg_data}" ]] \
    || die "Resolved data directory '${local_pg_data}' does not exist -- refusing to proceed."

log_info "Stopping bot and Postgres..."
systemctl stop "${SERVICE_NAME}" || true
systemctl stop postgresql

BACKUP_OF_LIVE="${local_pg_data}.pre-restore-$(date +%s)"
log_info "Backing up current data directory to ${BACKUP_OF_LIVE} before overwriting..."
mv "${local_pg_data}" "${BACKUP_OF_LIVE}"

mkdir -p "${local_pg_data}"
cp -a "${LATEST_BASE}/." "${local_pg_data}/"
chown -R postgres:postgres "${local_pg_data}"
chmod 700 "${local_pg_data}"

cat > "${local_pg_data}/recovery.signal" <<EOF
EOF
{
    echo "restore_command = 'cp ${WAL_DIR}/%f %p'"
    echo "recovery_target_time = '${TARGET_TIME}'"
    echo "recovery_target_action = 'promote'"
} >> "${local_pg_data}/postgresql.auto.conf"

log_info "Starting Postgres in recovery mode (this can take a moment)..."
systemctl start postgresql
log_info "Restore initiated. Check 'journalctl -u postgresql' to confirm recovery completed and promoted."
log_info "Once confirmed healthy, start the bot: systemctl start ${SERVICE_NAME}"
log_info "The pre-restore data directory was preserved at ${BACKUP_OF_LIVE} -- remove it manually once you've verified the restore is good."
