# SudoBot Guard — Phase 1 Design (Core Elevation Loop)

**Status:** Approved for implementation planning
**Scope:** Phase 1 only, per the original plan's suggested build order (`staff2fabotplanv2_1.md`, §12). Phase 2 (guard/reverts/lockdown) and Phase 3 (panic/calm/watchdog/break-glass) are separate, later design cycles.

## 1. Purpose

Staff hold a powerless standard role day-to-day; real permissions (a linked "permission role") are granted temporarily by this bot, gated behind a second factor (TOTP or YubiKey) that a stolen Discord session token never has. Phase 1 delivers the elevation loop end-to-end: registry, enrollment (both factors), timed elevation, deauth, expiry, and logging. This alone defeats an at-rest session-token thief, per the source plan's threat model (§1).

Full threat model, trust anchors, and honest limits are documented in the source plan and are not repeated here — this doc is the Rust/Phase-1-specific technical design built on top of it.

## 2. Scope boundaries

**In scope (Phase 1):** role-pair registry, dual-factor enrollment (TOTP + YubiKey, either or both), admin-approved add/regenerate flow, `/auth` elevation with per-role timers, replay protection, brute-force lockout, `/deauth`, `/status`, expiry sweep, single log channel with severity tiers and sequence numbers, multi-guild support, a simplified single-admin bootstrap.

**Explicitly deferred:**
- The always-on guard (manual-grant reverts, permission-baseline reverts, reconciliation sweeps, quarantine) — Phase 2.
- Lockdown mode — Phase 2.
- Full bot-admin bootstrap (claim window, two-admin redundancy, break-glass countdown) — Phase 2, alongside lockdown (the thing that most justifies it).
- Panic/calm, majority vote, watchdog bot — Phase 3.
- Session-expiry warnings — explicitly skipped (replaced by a Discord timestamp embed shown at grant time instead, per user decision).
- Webhook/bot-join/channel-overwrite watchers — Phase 2 scope decision.
- Proxying mass-destructive actions through the bot — revisit after Phase 1 has run for a month.
- FIDO2/WebAuthn — possible future phase.
- Off-platform log mirror — deferred indefinitely per original plan.

## 3. Tech stack

- **serenity** (async, tokio) — gateway, slash commands, message components, modals. Used directly (no poise framework).
- **sqlx** + **Postgres** — async, compile-time-checked queries, `sqlx migrate` for schema.
- **totp-rs** — RFC 6238 TOTP generation/verification.
- **aes-gcm** — encrypts TOTP secrets at rest; key from an env var, never stored in the DB.
- **argon2** — hashes backup codes (write-only, never decrypted).
- **qrcode** — renders the TOTP enrollment QR as a PNG attachment.
- **reqwest** — async HTTP client for Yubico's OTP verification API.
- Secrets (bot token, DB URL, encryption key, Yubico API credentials) via env vars / `.env` locally; a real secret store on the eventual production host (hosting to be decided by the user, separate from this dev sandbox).

## 4. Data model (Postgres, all tables `guild_id`-scoped)

- **`bot_admins`** — `guild_id`, `user_id`, `added_at`. Phase 1 bootstrap is simplified: first admin comes from an env var (`INITIAL_BOT_ADMIN_ID`) or a one-time `/setup claim` per guild. No timed claim window or 2FA-signing of admin changes yet — that's Phase 2.
- **`role_pairs`** — `guild_id`, `standard_role_id`, `permission_role_id`, `session_minutes`, `alert_tier`, `created_by`, `created_at`.
- **`totp_enrollments`** — `guild_id`, `user_id`, `totp_secret_encrypted`, `verified` (bool), `enrolled_at`.
- **`yubikey_enrollments`** — `guild_id`, `user_id`, `yubikey_public_id`, `verified` (bool, effectively always true post-live-validation), `enrolled_at`.
- **`enrollment_requests`** — `guild_id`, `user_id`, `factor_type` (`totp`/`yubikey`), `action` (`add`/`regenerate`), `status` (`pending`/`approved`/`expired`/`fulfilled`), `requested_at`, `approved_by`, `approved_at`, `window_minutes`, `window_expires_at`.
- **`backup_codes`** — `guild_id`, `user_id`, `code_hash` (argon2), `used_at` (nullable). 10 issued at first-ever enrollment.
- **`totp_replay_ledger`** — `guild_id`, `user_id`, `time_step`, `used_at`. Purged periodically. Not used for YubiKey (single-use by construction via Yubico's counter).
- **`auth_attempts`** — `guild_id`, `user_id`, `success`, `attempted_at`. Drives the 5-failures/10-min lockout.
- **`sessions`** — `guild_id`, `user_id`, `role_pair_id`, `granted_at`, `expires_at`, `revoked_at` (nullable), `revoke_reason` (`expired`/`deauth`).
- **`log_channels`** — `guild_id`, `channel_id`.
- **`log_sequence`** — `guild_id`, `next_seq`.

Guilds are fully independent: a user staffing two guilds enrolls separately in each, with separate secrets/keys.

## 5. Enrollment flow

Multi-factor, admin-gated after the first factor:

1. **First-ever factor is self-service.** `/enroll` shows an embed with three buttons: **TOTP**, **YubiKey**, **Both**. If the user has zero enrolled factors, all three proceed immediately.
2. **TOTP button** → bot generates a secret, replies ephemerally with an embed (QR PNG attachment + base32 secret) plus a "✅ I've added it — verify" button. That button opens a **modal** asking for the 6-digit code (a component response can't show both an image and a modal at once, hence the two-step). Submit → validated → `totp_enrollments.verified = true` → success embed. No separate `/verify` command.
3. **YubiKey button** → opens a modal directly asking the user to touch their key and paste the OTP. Submit → validated live against Yubico → public ID extracted and bound → done in one step (self-verifying).
4. **Both button** → runs steps 2 and 3 back to back, with the embed tracking progress (e.g. "TOTP ⏳ · YubiKey ⏳" → ✅ as each completes).
5. **Adding a second factor later, or regenerating an existing one, requires admin approval.** `/enroll <factor>` when the user already has ≥1 factor creates a pending `enrollment_requests` row and notifies the admin instead of showing the QR/modal directly.
6. **Admin approves**: `/enroll approve <user> <factor> <window>` (e.g. `30m`, `1h`; capped at 24h, no enforced minimum). On approval:
   - If `action = regenerate`, the old secret/key row is **deleted immediately** — the user has zero coverage for that factor until they re-enroll.
   - `window_expires_at` is set; the user has that long to complete enrollment.
   - If the window lapses unused, `status = expired` and the admin must re-approve from scratch (no auto-extend).
7. User re-runs `/enroll <factor>` — this time it completes (shows the QR/modal), since ephemeral responses can only be delivered as a reply to that user's own interaction, not pushed by the bot unprompted.

Backup codes (10, argon2-hashed) are issued once, at first-ever enrollment, regardless of which factor(s) are chosen. Using one fires an alert-tier log entry.

## 6. Elevation flow (`/auth`)

1. Reject if: not enrolled in any factor, not holding a registered standard role, or currently locked out.
2. **Factor auto-detection by code shape**: 6 digits → TOTP path; 44-char string → YubiKey path. User doesn't specify which.
3. **TOTP path**: check `totp_replay_ledger` (reject if this time-step was already used by this user), validate within ±1 step, insert into the ledger on success.
4. **YubiKey path**: validate live against Yubico's API. Single-use is enforced server-side by Yubico (key counter), no local replay ledger needed.
5. On success: for each eligible role pair (all by default, or the one named via the optional `role` param), grant the permission role, insert a `sessions` row, log an Info-tier entry with a Discord timestamp embed (`<t:unix:R>`), and reply ephemerally with the same timestamp embed — shown both where the command was issued and mirrored into the log channel.
6. On failure: log to `auth_attempts`. 5 failures in 10 minutes → lock out for 30 minutes, fire an Alert-tier log entry.
7. `/deauth` ends the caller's own active session(s) early. `/status` (bot admin) lists all active sessions and expiries.

**Expiry**: a background tokio task polls `sessions` every ~30s for rows past `expires_at` with `revoked_at IS NULL`, strips the Discord role, sets `revoked_at`/`revoke_reason = expired`, and logs it with the same timestamp-embed pattern.

## 7. Error handling — fail closed

Any error during `/auth` or elevation (Yubico API unreachable, DB write failure, Discord API error on role grant) denies the request and logs an Alert-tier entry. The bot never silently grants power on an error path — consistent with the source plan's fail-closed philosophy for guard behavior (§5).

## 8. Logging

Single log channel per guild (`/setup channel`). Two severity tiers per the source plan (§8):
- **Info** (no ping): successful auths, grants, expiries, deauths.
- **Alert** (pings configured target — deferred to Phase 3 for the actual ping-target config; Phase 1 just posts visibly): lockouts, failed enrollment approval issues, backup-code use.

Every entry carries a per-guild sequence number (`log_sequence`) so deleted entries leave a visible gap.

## 9. UI/UX standing convention

Applies bot-wide, not just `/enroll`: consistent embed color coding (blue = info, red/orange = alert, green = success), a consistent footer, and buttons/select-menus wherever a command has multiple natural choices (`/protect list` → select menu to remove one; `/status` → paginated embed if the session list is long). Exact copy/wording is iterated on live during testing rather than fully specified here.

## 10. Testing approach

Unit tests alongside implementation for pure, security-critical logic: TOTP validation, replay-ledger checks, lockout counting, AES-GCM encrypt/decrypt round-trips, argon2 backup-code hashing/verification. Discord-integration behavior (commands, buttons, modals, role grants) is verified via live manual testing in a real Discord server as we build, since that's not meaningfully unit-testable.

## 11. Command surface (Phase 1)

| Command | Who | What |
|---|---|---|
| `/setup channel` | Bot admin | Set the log channel |
| `/setup claim` | First-run | Simplified admin bootstrap |
| `/protect add/remove/list` | Bot admin | Register/list role pairs |
| `/enroll` | Registered-role holder | Shows TOTP/YubiKey/Both buttons; self-service if zero factors enrolled, else creates an approval request |
| `/enroll approve <user> <factor> <window>` | Bot admin | Approves a pending add/regenerate request; deletes old secret immediately if regenerating |
| `/auth <code> [role]` | Enrolled staff | Elevates all eligible pairs or one; auto-detects TOTP vs YubiKey |
| `/deauth` | Elevated staff | Drops own session(s) early |
| `/status` | Bot admin | Active sessions and expiries |

## 12. Open items carried forward (not blocking Phase 1)

- Ops facts (member/staff counts, final production host) — still not gathered; not architecturally blocking for Phase 1 since multi-guild + Postgres scale fine regardless.
- Alert-tier ping target configuration — stubbed as "post visibly" in Phase 1, real configurable ping target lands with Phase 3's panic/calm work.
