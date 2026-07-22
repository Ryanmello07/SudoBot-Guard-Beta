#!/usr/bin/env bash
# Redeploy: pull latest code, audit dependencies, rebuild, restart.
# Run as root: sudo ./deploy.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"
require_root

log_info "Pulling latest code..."
sudo -u "${SERVICE_USER}" git -C "${APP_DIR}" pull

log_info "Running cargo audit..."
sudo -u "${SERVICE_USER}" bash -c "
    source \"\$HOME/.cargo/env\"
    cd '${APP_DIR}'
    if ! command -v cargo-audit &>/dev/null; then
        cargo install cargo-audit --locked
    fi
"
if ! sudo -u "${SERVICE_USER}" bash -c "source \"\$HOME/.cargo/env\" && cd '${APP_DIR}' && cargo audit"; then
    die "cargo audit found a vulnerability advisory. Review it before deploying -- not auto-bypassed."
fi

log_info "Building release binary..."
sudo -u "${SERVICE_USER}" bash -c "
    source \"\$HOME/.cargo/env\"
    cd '${APP_DIR}' && cargo build --release
"

log_info "Restarting service (migrations run automatically on the bot's own startup)..."
systemctl restart "${SERVICE_NAME}"
sleep 3
systemctl status "${SERVICE_NAME}" --no-pager || true

log_info "Recent log output:"
journalctl -u "${SERVICE_NAME}" -n 20 --no-pager
