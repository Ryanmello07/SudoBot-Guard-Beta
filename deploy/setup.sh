#!/usr/bin/env bash
# One-time provisioning for SudoBot Guard on a fresh Ubuntu 26.04 LTS box.
# Run as root: sudo ./setup.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

stage_preflight() {
    require_root
    if [[ ! -f /etc/os-release ]] || ! grep -qi 'ubuntu\|debian' /etc/os-release; then
        die "This script targets Ubuntu/Debian. /etc/os-release doesn't look like either."
    fi
    if systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE_NAME}"; then
        log_warn "${SERVICE_NAME} already exists on this box."
        read -rp "Continue and reprovision anyway? [y/N] " confirm
        [[ "${confirm}" =~ ^[Yy]$ ]] || die "Aborted by user."
    fi
    log_info "Preflight checks passed."
}

stage_os_baseline() {
    log_info "Updating package lists and installing baseline packages..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get upgrade -y
    apt-get install -y \
        unattended-upgrades fail2ban \
        build-essential pkg-config libssl-dev \
        git curl ufw postgresql

    log_info "Enabling unattended security upgrades..."
    cat > /etc/apt/apt.conf.d/51sudobot-unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
EOF
    systemctl enable --now unattended-upgrades

    log_info "Enabling fail2ban's SSH jail..."
    cat > /etc/fail2ban/jail.d/sudobot-sshd.local <<'EOF'
[sshd]
enabled = true
backend = systemd
EOF
    systemctl enable --now fail2ban
    log_info "OS baseline complete."
}

stage_ssh_hardening() {
    log_info "Hardening SSH..."
    local target_user="${SUDO_USER:-root}"
    local key_file="/root/.ssh/authorized_keys"
    if [[ "${target_user}" != "root" ]]; then
        key_file="/home/${target_user}/.ssh/authorized_keys"
    fi
    if [[ ! -s "${key_file}" ]]; then
        die "No authorized_keys found at ${key_file} for user '${target_user}'. Refusing to disable password auth without a working key login already in place — you would lock yourself out."
    fi

    local sshd_config="/etc/ssh/sshd_config"
    sed -i \
        -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' \
        -e 's/^#\?PermitRootLogin.*/PermitRootLogin no/' \
        "${sshd_config}"
    if ! grep -q '^PasswordAuthentication no' "${sshd_config}"; then
        echo "PasswordAuthentication no" >> "${sshd_config}"
    fi
    if ! grep -q '^PermitRootLogin no' "${sshd_config}"; then
        echo "PermitRootLogin no" >> "${sshd_config}"
    fi
    systemctl restart ssh
    log_info "SSH hardened: key-only auth, root login disabled."
}

stage_firewall() {
    log_info "Configuring ufw (default-deny inbound, SSH only)..."
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow OpenSSH
    ufw --force enable
    log_info "Firewall enabled: $(ufw status | head -1)"
}

main() {
    stage_preflight
    stage_os_baseline
    stage_ssh_hardening
    stage_firewall
    log_info "Stages 1-4 complete. (More stages appended by later tasks.)"
}

main "$@"
