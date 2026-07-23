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
# Deliberate, scoped exception -- NOT a blanket bypass. These 4 advisories
# all trace to rustls-webpki 0.102.8, pulled in transitively via
# serenity 0.12.5 -> tokio-tungstenite 0.21.0 -> rustls 0.22.4 (the Discord
# Gateway WebSocket TLS layer). Confirmed not fixable by `cargo update`:
# serenity 0.12.5 is the latest release on crates.io, and the advisories'
# own fix (rustls-webpki >=0.103.13) is API-incompatible with rustls 0.22.x
# (a real breaking change upstream, not a version-string technicality) --
# tokio-tungstenite/tungstenite 0.21.0 both pin rustls = "0.22" directly, so
# there is no clean way to force the fixed webpki without forking/vendoring
# tokio-tungstenite itself. This is a real, accepted, TEMPORARY exception,
# not an indefinite one -- track it against replacing/upgrading this
# dependency chain (newer Rust toolchain + updated TLS/crypto deps) in a
# future session, and remove this ignore list the moment that lands.
# Any advisory OTHER than these four still hard-blocks deploy, unchanged.
CARGO_AUDIT_IGNORE=(
    --ignore RUSTSEC-2026-0104
    --ignore RUSTSEC-2026-0049
    --ignore RUSTSEC-2026-0098
    --ignore RUSTSEC-2026-0099
)
if ! sudo -u "${SERVICE_USER}" bash -c "source \"\$HOME/.cargo/env\" && cd '${APP_DIR}' && cargo audit ${CARGO_AUDIT_IGNORE[*]}"; then
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
