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

    # Root-only setups (connected directly as root, no SUDO_USER) must keep
    # key-based root login alive, or the very next connection locks the
    # operator out entirely. Only when there's a separate sudo user with
    # their own working key is it safe to disable root login outright.
    local permit_root_login="no"
    if [[ -z "${SUDO_USER:-}" ]]; then
        permit_root_login="prohibit-password"
        log_warn "No SUDO_USER detected (connected directly as root). Setting PermitRootLogin to 'prohibit-password' instead of 'no' to avoid locking out the only admin account."
    fi

    # Write hardening as a drop-in rather than sed-editing sshd_config
    # directly: modern Ubuntu/Debian cloud images include
    # /etc/ssh/sshd_config.d/*.conf near the top of the main config, and
    # sshd uses the FIRST value seen for each keyword. A cloud-init drop-in
    # (e.g. 50-cloud-init.conf) can silently win over anything written into
    # the main file. The "00-" prefix sorts this file first among drop-ins
    # so its values take precedence.
    local dropin_dir="/etc/ssh/sshd_config.d"
    local dropin_file="${dropin_dir}/00-sudobot-hardening.conf"
    mkdir -p "${dropin_dir}"
    cat > "${dropin_file}" <<EOF
# Managed by SudoBot Guard deploy/setup.sh (stage_ssh_hardening). Do not edit by hand.
PasswordAuthentication no
PermitRootLogin ${permit_root_login}
EOF

    systemctl restart ssh

    # Don't trust the file write alone: verify the config sshd will
    # actually use (after resolving Include order/overrides) matches intent.
    local effective
    effective="$(sshd -T | grep -iE '^(passwordauthentication|permitrootlogin)')"
    if ! grep -qi "^passwordauthentication no$" <<<"${effective}"; then
        die "SSH hardening did not take effect: expected 'PasswordAuthentication no' in effective sshd config, but got:\n${effective}\nA competing sshd_config.d drop-in may be overriding ${dropin_file}."
    fi
    if ! grep -qi "^permitrootlogin ${permit_root_login}$" <<<"${effective}"; then
        die "SSH hardening did not take effect: expected 'PermitRootLogin ${permit_root_login}' in effective sshd config, but got:\n${effective}\nA competing sshd_config.d drop-in may be overriding ${dropin_file}."
    fi

    log_info "SSH hardened: key-only auth, PermitRootLogin=${permit_root_login} (verified via sshd -T)."
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
