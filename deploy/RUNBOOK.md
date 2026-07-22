# SudoBot Guard — Operations Runbook

## Secret rotation

| Secret | If leaked |
|---|---|
| `DISCORD_TOKEN` | Regenerate in the Discord Developer Portal (Bot tab → Reset Token). Update `DISCORD_TOKEN` in `/home/sudobot/app/.env`. `systemctl restart sudobot-guard`. |
| Postgres app password | `sudo -u postgres psql -c "ALTER ROLE sudobot_app PASSWORD 'NEW_PASSWORD';"`. Update `DATABASE_URL` in `.env` to match. `systemctl restart sudobot-guard`. |
| `YUBICO_CLIENT_ID` / `YUBICO_SECRET_KEY` | Regenerate at https://upgrade.yubico.com/getapikey/. Update `.env`. `systemctl restart sudobot-guard`. Lower urgency than the other two -- these only validate OTP codes, they aren't a bypass secret. |
| `ENCRYPTION_KEY` | The expensive one. Generate a new one (`openssl rand -hex 32`), update `.env`, restart. Every currently-stored TOTP secret becomes permanently undecryptable -- **every enrolled staff member must run `/enroll` again.** This is not a quiet operation; announce it before doing it. |

## Restoring from backup

See `deploy/restore.sh`. Usage: `sudo ./restore.sh "YYYY-MM-DD HH:MM:SS"` (server local time). It stops the bot and Postgres, preserves the current data directory as a sibling directory suffixed `.pre-restore-<unix-timestamp>` before overwriting anything (the actual data directory path is resolved live via `SHOW data_directory` -- typically `/var/lib/postgresql/<version>/main` on Ubuntu, not a fixed path), restores the nearest base backup, and replays WAL to the target time. Confirm via `journalctl -u postgresql` that recovery completed and promoted before starting the bot back up. Note: this script needs Postgres running to resolve its own data directory, so it's meant to be run against a fresh cluster (e.g. right after re-provisioning with `setup.sh`) or the still-live current cluster -- not as a way to recover a cluster that won't start at all.

## Incident response (box suspected compromised)

1. **Revoke the Discord token immediately** via the Developer Portal -- this kills the live gateway session regardless of what else an attacker can still do on the box.
2. **Treat the encryption key and the database as burned.** Don't trust anything currently on the box, including backups taken after the suspected compromise window.
3. **Rebuild the host** from a clean OS image using `deploy/setup.sh`.
4. **Restore Postgres** from the last known-good backup (`deploy/restore.sh`, targeting a timestamp before the suspected compromise).
5. **Rotate every secret** in the table above, including the encryption key.
6. **Accept the re-enrollment cost.** Rotating the encryption key means everyone re-enrolls TOTP -- that's the price of this scenario, not a bug in the recovery process.

## Routine operations

- **Redeploy code:** `sudo ./deploy.sh` (pulls, audits dependencies, rebuilds, restarts; migrations run automatically on the bot's own startup).
- **Check status:** `systemctl status sudobot-guard`
- **Tail logs:** `journalctl -u sudobot-guard -f`
- **Enable monitoring alerts:** edit `/etc/sudobot-guard/monitoring.env` and set `HEARTBEAT_URL` (a healthchecks.io-style ping URL) and/or `DISK_ALERT_EMAIL`. Both checks silently no-op until configured.
