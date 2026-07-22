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

stage_service_user() {
    log_info "Creating service user '${SERVICE_USER}'..."
    if id "${SERVICE_USER}" &>/dev/null; then
        log_warn "User ${SERVICE_USER} already exists, skipping creation."
    else
        useradd --create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
    fi
    log_info "Service user ready."
}

stage_postgres() {
    log_info "Configuring PostgreSQL (local-only, least-privilege roles)..."
    local pg_conf
    pg_conf="$(find /etc/postgresql -maxdepth 2 -name postgresql.conf | head -1)"
    if [[ -z "${pg_conf}" ]]; then
        die "Could not locate postgresql.conf"
    fi
    sed -i "s/^#\?listen_addresses.*/listen_addresses = 'localhost'/" "${pg_conf}"
    systemctl restart postgresql

    local db_password backup_password
    db_password="$(openssl rand -hex 24)"
    backup_password="$(openssl rand -hex 24)"

    sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${DB_APP_ROLE}') THEN
        CREATE ROLE ${DB_APP_ROLE} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '${db_password}';
    ELSE
        ALTER ROLE ${DB_APP_ROLE} WITH PASSWORD '${db_password}';
    END IF;
END
\$\$;
SELECT 'CREATE DATABASE ${DB_NAME} OWNER ${DB_APP_ROLE}'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DB_NAME}')\gexec
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${DB_BACKUP_ROLE}') THEN
        CREATE ROLE ${DB_BACKUP_ROLE} WITH LOGIN REPLICATION PASSWORD '${backup_password}';
    ELSE
        ALTER ROLE ${DB_BACKUP_ROLE} WITH PASSWORD '${backup_password}';
    END IF;
END
\$\$;
SQL

    # Root-only temp files; Task 5 reads the app password to assemble
    # DATABASE_URL and Task 6 reads the backup password to write
    # BACKUP_SVC_USER's PGPASSFILE. Each is shredded once consumed --
    # never written into any world/group-readable location.
    umask 077
    echo "${db_password}" > /root/.sudobot_db_password
    echo "${backup_password}" > /root/.sudobot_backup_password
    log_info "PostgreSQL configured: DB '${DB_NAME}', app role '${DB_APP_ROLE}', backup role '${DB_BACKUP_ROLE}'."
}

main() {
    stage_preflight
    stage_os_baseline
    stage_ssh_hardening
    stage_firewall
    stage_service_user
    stage_postgres
    log_info "Stages 1-6 complete. (More stages appended by later tasks.)"
}

main "$@"
