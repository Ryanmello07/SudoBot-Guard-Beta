#!/usr/bin/env bash
# Shared constants and helper functions for every deploy/*.sh script.
# Sourced, never executed directly.
set -euo pipefail

readonly SERVICE_USER="sudobot"
readonly APP_DIR="/home/sudobot/app"
readonly SERVICE_NAME="sudobot-guard.service"
readonly REPO_URL="https://github.com/Ryanmello07/SudoBot-Guard-Beta"
readonly RELEASE_BIN="${APP_DIR}/target/release/sudobot_guard"
readonly ENV_FILE="${APP_DIR}/.env"
readonly DB_NAME="sudobot_guard"
readonly DB_APP_ROLE="sudobot_app"
readonly DB_BACKUP_ROLE="sudobot_backup"
readonly BACKUP_SVC_USER="sudobot_backup_svc"
readonly BACKUP_ROOT="/var/backups/sudobot-guard"

log_info()  { echo -e "\033[1;32m[INFO]\033[0m $*"; }
log_warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }
log_error() { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; }
die()       { log_error "$*"; exit 1; }

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "This script must be run as root (e.g. via sudo)."
    fi
}
