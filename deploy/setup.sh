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

stage_swap() {
    local total_mem_kb
    total_mem_kb="$(grep MemTotal /proc/meminfo | awk '{print $2}')"
    if (( total_mem_kb > 3000000 )); then
        log_info "RAM is comfortably above 2GB, skipping swap setup."
        return
    fi
    if swapon --show | grep -q .; then
        log_warn "Swap already configured, skipping."
        return
    fi
    log_info "Low RAM detected (${total_mem_kb}KB) — cargo build --release needs headroom. Adding a 2GB swap file..."
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    log_info "Swap enabled."
}

stage_build() {
    log_info "Installing Rust toolchain for ${SERVICE_USER}..."
    sudo -u "${SERVICE_USER}" bash -c '
        set -euo pipefail
        if [[ ! -x "$HOME/.cargo/bin/cargo" ]]; then
            curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
        fi
    '

    log_info "Cloning/updating the repository..."
    if [[ -d "${APP_DIR}/.git" ]]; then
        sudo -u "${SERVICE_USER}" git -C "${APP_DIR}" pull
    else
        sudo -u "${SERVICE_USER}" git clone "${REPO_URL}" "${APP_DIR}"
    fi

    log_info "Building release binary (this can take a while on 1 vCPU)..."
    sudo -u "${SERVICE_USER}" bash -c "
        source \"\$HOME/.cargo/env\"
        cd '${APP_DIR}' && cargo build --release
    "
    if [[ ! -x "${RELEASE_BIN}" ]]; then
        die "Build did not produce ${RELEASE_BIN}"
    fi
    log_info "Build complete: ${RELEASE_BIN}"
}

stage_secrets() {
    if [[ ! -f /root/.sudobot_db_password ]]; then
        die "Expected /root/.sudobot_db_password from stage_postgres — run that stage first."
    fi
    local db_password
    db_password="$(cat /root/.sudobot_db_password)"

    if [[ -f "${ENV_FILE}" ]]; then
        log_warn "${ENV_FILE} already exists."
        read -rp "Overwrite it with freshly-prompted secrets? [y/N] " confirm
        if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
            log_info "Keeping existing .env, but updating DATABASE_URL to match the just-rotated database password."
            sed -i "s|^DATABASE_URL=.*|DATABASE_URL=postgres://${DB_APP_ROLE}:${db_password}@localhost/${DB_NAME}|" "${ENV_FILE}"
            shred -u /root/.sudobot_db_password
            return
        fi
    fi

    echo
    log_info "Enter the secrets this bot needs. Nothing you type here is logged."
    read -rp "DISCORD_TOKEN: " -s discord_token; echo
    [[ -n "${discord_token}" ]] || die "DISCORD_TOKEN cannot be empty."
    read -rp "YUBICO_CLIENT_ID: " yubico_client_id
    [[ -n "${yubico_client_id}" ]] || die "YUBICO_CLIENT_ID cannot be empty."
    read -rp "YUBICO_SECRET_KEY: " -s yubico_secret_key; echo
    [[ -n "${yubico_secret_key}" ]] || die "YUBICO_SECRET_KEY cannot be empty."
    read -rp "INITIAL_BOT_ADMIN_ID (Discord user ID, optional, press enter to skip): " initial_admin_id

    local encryption_key
    encryption_key="$(openssl rand -hex 32)"

    umask 077
    {
        echo "DISCORD_TOKEN=${discord_token}"
        echo "DATABASE_URL=postgres://${DB_APP_ROLE}:${db_password}@localhost/${DB_NAME}"
        echo "ENCRYPTION_KEY=${encryption_key}"
        echo "YUBICO_CLIENT_ID=${yubico_client_id}"
        echo "YUBICO_SECRET_KEY=${yubico_secret_key}"
        [[ -n "${initial_admin_id}" ]] && echo "INITIAL_BOT_ADMIN_ID=${initial_admin_id}"
    } > "${ENV_FILE}"
    chown "${SERVICE_USER}:${SERVICE_USER}" "${ENV_FILE}"
    chmod 600 "${ENV_FILE}"

    shred -u /root/.sudobot_db_password

    echo
    log_warn "=========================================================="
    log_warn "ENCRYPTION_KEY (save this somewhere OFF this box right now,"
    log_warn "e.g. a password manager -- it is never shown again, and if"
    log_warn "it's lost every enrolled staff member must re-enroll):"
    echo "${encryption_key}"
    log_warn "=========================================================="
    echo
}

stage_systemd() {
    log_info "Installing systemd service..."
    cp "${SCRIPT_DIR}/sudobot-guard.service.template" "/etc/systemd/system/${SERVICE_NAME}"
    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
    systemctl restart "${SERVICE_NAME}"
    sleep 3
    systemctl status "${SERVICE_NAME}" --no-pager || true
    log_info "Service installed and started."
}

stage_backups() {
    log_info "Setting up backups (WAL archiving + daily base backup)..."

    if ! id "${BACKUP_SVC_USER}" &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "${BACKUP_SVC_USER}"
    fi
    mkdir -p "${BACKUP_ROOT}/base" "${BACKUP_ROOT}/wal"
    # Non-recursive: on a re-run, archive_command has already written WAL
    # segments into wal/ owned by postgres:postgres. A recursive chown here
    # would silently re-own them to ${BACKUP_SVC_USER}, and since postgres
    # is only a group member (not owner) of those files, that would strip
    # its own read access to WAL it already archived -- breaking PITR for
    # anything archived before the re-run. Only the directories themselves
    # need ${BACKUP_SVC_USER} ownership; file contents keep whatever user
    # actually wrote them (pg_basebackup as ${BACKUP_SVC_USER}, or
    # archive_command as postgres).
    chown "${BACKUP_SVC_USER}:${BACKUP_SVC_USER}" "${BACKUP_ROOT}" "${BACKUP_ROOT}/base" "${BACKUP_ROOT}/wal"
    chmod 750 "${BACKUP_ROOT}"
    chmod 770 "${BACKUP_ROOT}/wal"
    chmod 700 "${BACKUP_ROOT}/base"

    # postgresql's server process (archive_command) and, later, its
    # recovery process (restore_command) both run as the OS user
    # `postgres`, not as ${BACKUP_SVC_USER}. Add `postgres` as a
    # supplementary group member so it can write/read ${BACKUP_ROOT}/wal
    # without loosening ownership or opening up ${BACKUP_ROOT}/base. This
    # must happen before the `systemctl restart postgresql` below, since a
    # running process only picks up new supplementary group membership on
    # its next start.
    usermod -aG "${BACKUP_SVC_USER}" postgres

    if [[ ! -f /root/.sudobot_backup_password ]]; then
        die "Expected /root/.sudobot_backup_password from stage_postgres — run that stage first."
    fi
    local backup_password
    backup_password="$(cat /root/.sudobot_backup_password)"
    mkdir -p /etc/sudobot-guard
    umask 077
    echo "127.0.0.1:5432:*:${DB_BACKUP_ROLE}:${backup_password}" > /etc/sudobot-guard/pgpass
    chown "${BACKUP_SVC_USER}:${BACKUP_SVC_USER}" /etc/sudobot-guard/pgpass
    chmod 600 /etc/sudobot-guard/pgpass
    shred -u /root/.sudobot_backup_password

    local pg_conf pg_hba
    pg_conf="$(find /etc/postgresql -maxdepth 2 -name postgresql.conf | head -1)"
    pg_hba="$(find /etc/postgresql -maxdepth 2 -name pg_hba.conf | head -1)"

    sed -i \
        -e "s|^#\?archive_mode.*|archive_mode = on|" \
        -e "s|^#\?archive_command.*|archive_command = 'test ! -f ${BACKUP_ROOT}/wal/%f \&\& cp %p ${BACKUP_ROOT}/wal/%f'|" \
        -e "s|^#\?wal_level.*|wal_level = replica|" \
        "${pg_conf}"

    if ! grep -q "${DB_BACKUP_ROLE}" "${pg_hba}"; then
        echo "host    replication     ${DB_BACKUP_ROLE}    127.0.0.1/32    md5" >> "${pg_hba}"
    fi
    systemctl restart postgresql

    cp "${SCRIPT_DIR}/backup-base.sh" "/usr/local/bin/sudobot-guard-backup-base.sh"
    chmod 755 "/usr/local/bin/sudobot-guard-backup-base.sh"
    cp "${SCRIPT_DIR}/common.sh" "/usr/local/bin/common.sh"

    cat > /etc/systemd/system/sudobot-guard-backup.service <<'EOF'
[Unit]
Description=SudoBot Guard nightly Postgres base backup

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sudobot-guard-backup-base.sh
EOF

    cat > /etc/systemd/system/sudobot-guard-backup.timer <<'EOF'
[Unit]
Description=Run SudoBot Guard base backup nightly

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now sudobot-guard-backup.timer
    log_info "Backup timer installed (nightly at 03:00)."
}

main() {
    stage_preflight
    stage_os_baseline
    stage_ssh_hardening
    stage_firewall
    stage_service_user
    stage_postgres
    stage_swap
    stage_build
    stage_secrets
    stage_systemd
    stage_backups
    log_info "Stages 1-11 complete. (Monitoring stage appended by a later task.)"
}

main "$@"
