use crate::auth;
use crate::crypto::{encryption, totp};
use crate::elevation::{self, CodeShape};
use crate::logging::{log, LogTier};
use crate::yubico::YubicoClient;
use serenity::all::{
    CommandDataOptionValue, CommandInteraction, CommandOptionType, Context, CreateCommand,
    CreateCommandOption, CreateEmbed, CreateInteractionResponse, CreateInteractionResponseMessage,
};
use sqlx::PgPool;

const LOCKOUT_WINDOW_MINUTES: i32 = 30;
const LOCKOUT_THRESHOLD: i64 = 5;

pub fn commands() -> Vec<CreateCommand> {
    vec![
        CreateCommand::new("auth")
            .description("Elevate to your permission role(s) with a 2FA code")
            .add_option(
                CreateCommandOption::new(CommandOptionType::String, "code", "Your TOTP or YubiKey code")
                    .required(true),
            )
            .add_option(CreateCommandOption::new(
                CommandOptionType::Role,
                "role",
                "Elevate only the pair this role belongs to",
            )),
        CreateCommand::new("deauth").description("End your active elevated session(s) early"),
        CreateCommand::new("status").description("List active elevated sessions in this server"),
    ]
}

pub async fn handle(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
    cmd: &CommandInteraction,
) {
    match cmd.data.name.as_str() {
        "auth" => handle_auth(ctx, pool, encryption_key, yubico, cmd).await,
        "deauth" => handle_deauth(ctx, pool, cmd).await,
        "status" => handle_status(ctx, pool, cmd).await,
        _ => {}
    }
}

async fn reply_ephemeral(ctx: &Context, cmd: &CommandInteraction, content: &str) {
    let msg = CreateInteractionResponseMessage::new()
        .content(content)
        .ephemeral(true);
    let _ = cmd
        .create_response(&ctx.http, CreateInteractionResponse::Message(msg))
        .await;
}

async fn record_attempt(pool: &PgPool, guild_id_i64: i64, user_id_i64: i64, success: bool) {
    let _ = sqlx::query!(
        "INSERT INTO auth_attempts (guild_id, user_id, success) VALUES ($1, $2, $3)",
        guild_id_i64,
        user_id_i64,
        success
    )
    .execute(pool)
    .await;
}

async fn handle_auth(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
    cmd: &CommandInteraction,
) {
    let Some(guild_id) = cmd.guild_id else {
        return reply_ephemeral(ctx, cmd, "This command only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = cmd.user.id.get() as i64;

    // --- Lockout check ---
    let failure_count = match sqlx::query!(
        "SELECT COUNT(*) AS count FROM auth_attempts
         WHERE guild_id = $1 AND user_id = $2 AND success = false
           AND attempted_at > now() - make_interval(mins => $3)",
        guild_id_i64,
        user_id_i64,
        LOCKOUT_WINDOW_MINUTES
    )
    .fetch_one(pool)
    .await
    {
        Ok(row) => row.count.unwrap_or(0),
        Err(e) => {
            tracing::error!(error = ?e, "failed to check auth lockout");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };
    if failure_count >= LOCKOUT_THRESHOLD {
        let embed = CreateEmbed::new()
            .title("Auth lockout")
            .description(format!(
                "<@{}> is locked out after {} failed attempts in the last {} minutes",
                cmd.user.id, failure_count, LOCKOUT_WINDOW_MINUTES
            ))
            .color(0xED4245);
        let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Alert, embed).await;
        return reply_ephemeral(ctx, cmd, "Too many failed attempts. Try again later.").await;
    }

    // --- Extract options ---
    let mut code = None;
    let mut role_filter_i64: Option<i64> = None;
    for opt in &cmd.data.options {
        match (opt.name.as_str(), &opt.value) {
            ("code", CommandDataOptionValue::String(s)) => code = Some(s.clone()),
            ("role", CommandDataOptionValue::Role(id)) => role_filter_i64 = Some(id.get() as i64),
            _ => {}
        }
    }
    let Some(code) = code else {
        return reply_ephemeral(ctx, cmd, "Missing required code.").await;
    };

    // --- Eligible pairs: every pair in the guild if bot admin, else only pairs
    // whose standard_role_id the member holds. Unified into one query via the
    // is_admin boolean so both cases share a single anonymous row type. ---
    let is_admin = match auth::is_bot_admin(pool, guild_id_i64, user_id_i64).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "failed to check bot admin status");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };
    let member_role_ids: Vec<i64> = cmd
        .member
        .as_ref()
        .map(|m| m.roles.iter().map(|r| r.get() as i64).collect())
        .unwrap_or_default();

    let pairs = match sqlx::query!(
        "SELECT id, standard_role_id, permission_role_id, session_minutes
         FROM role_pairs
         WHERE guild_id = $1 AND ($2 OR standard_role_id = ANY($3))",
        guild_id_i64,
        is_admin,
        &member_role_ids
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = ?e, "failed to load eligible role pairs");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };

    let pairs: Vec<_> = if let Some(role_filter_i64) = role_filter_i64 {
        pairs
            .into_iter()
            .filter(|p| p.standard_role_id == role_filter_i64 || p.permission_role_id == role_filter_i64)
            .collect()
    } else {
        pairs
    };

    if pairs.is_empty() {
        return reply_ephemeral(ctx, cmd, "You don't hold any registered role to elevate.").await;
    }

    // --- Verify the code ---
    let Some(shape) = elevation::detect_code_shape(&code) else {
        record_attempt(pool, guild_id_i64, user_id_i64, false).await;
        return reply_ephemeral(ctx, cmd, "That doesn't look like a valid code.").await;
    };

    let verified = match shape {
        CodeShape::Totp => verify_totp(pool, guild_id_i64, user_id_i64, &code, encryption_key).await,
        CodeShape::Yubikey => verify_yubikey(pool, guild_id_i64, user_id_i64, &code, yubico).await,
    };

    let verified = match verified {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "error while verifying auth code");
            record_attempt(pool, guild_id_i64, user_id_i64, false).await;
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };

    if !verified {
        record_attempt(pool, guild_id_i64, user_id_i64, false).await;
        return reply_ephemeral(ctx, cmd, "That code didn't verify.").await;
    }

    record_attempt(pool, guild_id_i64, user_id_i64, true).await;

    // --- Grant every eligible pair independently ---
    let Some(member) = cmd.member.as_ref() else {
        return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
    };
    let mut granted_lines = Vec::new();
    let mut failed_lines = Vec::new();

    for pair in &pairs {
        let permission_role_id = serenity::all::RoleId::new(pair.permission_role_id as u64);
        if let Err(e) = member.add_role(&ctx.http, permission_role_id).await {
            tracing::error!(error = ?e, pair_id = pair.id, "failed to grant permission role");
            failed_lines.push(format!("<@&{}> — failed to grant, try again", pair.permission_role_id));
            continue;
        }

        let expires_at_result = sqlx::query!(
            "INSERT INTO sessions (guild_id, user_id, role_pair_id, expires_at)
             VALUES ($1, $2, $3, now() + make_interval(mins => $4))
             RETURNING expires_at",
            guild_id_i64,
            user_id_i64,
            pair.id,
            pair.session_minutes
        )
        .fetch_one(pool)
        .await;

        match expires_at_result {
            Ok(row) => {
                let ts = row.expires_at.timestamp();
                granted_lines.push(format!("<@&{}> — expires <t:{}:R>", pair.permission_role_id, ts));

                let embed = CreateEmbed::new()
                    .title("Elevated")
                    .description(format!(
                        "<@{}> elevated <@&{}>, expires <t:{}:R>",
                        cmd.user.id, pair.permission_role_id, ts
                    ))
                    .color(0x57F287);
                let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Info, embed).await;
            }
            Err(e) => {
                tracing::error!(error = ?e, pair_id = pair.id, "failed to record session");
                failed_lines.push(format!("<@&{}> — role granted but session tracking failed", pair.permission_role_id));
            }
        }
    }

    let mut content = String::new();
    if !granted_lines.is_empty() {
        content.push_str("Elevated:\n");
        content.push_str(&granted_lines.join("\n"));
    }
    if !failed_lines.is_empty() {
        if !content.is_empty() {
            content.push_str("\n\n");
        }
        content.push_str("Failed:\n");
        content.push_str(&failed_lines.join("\n"));
    }
    reply_ephemeral(ctx, cmd, &content).await;
}

async fn verify_totp(
    pool: &PgPool,
    guild_id_i64: i64,
    user_id_i64: i64,
    code: &str,
    encryption_key: &[u8; 32],
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT totp_secret_encrypted FROM totp_enrollments WHERE guild_id = $1 AND user_id = $2 AND verified = true",
        guild_id_i64,
        user_id_i64
    )
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };

    let Ok(base32_secret) = encryption::decrypt(encryption_key, &row.totp_secret_encrypted) else {
        return Ok(false);
    };
    let Ok(secret_bytes) = totp_rs::Secret::Encoded(base32_secret).to_bytes() else {
        return Ok(false);
    };

    let now_unix = chrono::Utc::now().timestamp() as u64;
    let account_name = user_id_i64.to_string();
    let Some(time_step) = totp::verify_code(&secret_bytes, &account_name, code, now_unix) else {
        return Ok(false);
    };

    // Atomic replay check: insert the (guild, user, time_step) triple; if a
    // row already existed, ON CONFLICT DO NOTHING means 0 rows affected,
    // which is exactly the replay signal — no separate SELECT-then-INSERT
    // race window.
    let insert_result = sqlx::query!(
        "INSERT INTO totp_replay_ledger (guild_id, user_id, time_step) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        guild_id_i64,
        user_id_i64,
        time_step
    )
    .execute(pool)
    .await?;

    Ok(insert_result.rows_affected() > 0)
}

async fn verify_yubikey(
    pool: &PgPool,
    guild_id_i64: i64,
    user_id_i64: i64,
    code: &str,
    yubico: &YubicoClient,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT yubikey_public_id FROM yubikey_enrollments WHERE guild_id = $1 AND user_id = $2",
        guild_id_i64,
        user_id_i64
    )
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };

    // Fail closed on any Yubico API error — a network hiccup denies, it
    // never silently succeeds.
    match yubico.verify_otp(code).await {
        Ok(result) => Ok(result.valid && result.public_id == row.yubikey_public_id),
        Err(e) => {
            tracing::error!(error = ?e, "Yubico verification request failed");
            Ok(false)
        }
    }
}

async fn handle_deauth(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction) {
    let Some(guild_id) = cmd.guild_id else {
        return reply_ephemeral(ctx, cmd, "This command only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = cmd.user.id.get() as i64;

    let sessions = match sqlx::query!(
        "SELECT s.id, s.role_pair_id, r.permission_role_id
         FROM sessions s
         JOIN role_pairs r ON r.id = s.role_pair_id
         WHERE s.guild_id = $1 AND s.user_id = $2 AND s.revoked_at IS NULL AND s.expires_at > now()",
        guild_id_i64,
        user_id_i64
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = ?e, "failed to load active sessions for deauth");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };

    if sessions.is_empty() {
        return reply_ephemeral(ctx, cmd, "You have no active elevated sessions.").await;
    }

    let Some(member) = cmd.member.as_ref() else {
        return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
    };

    let mut dropped = Vec::new();
    for session in &sessions {
        let permission_role_id = serenity::all::RoleId::new(session.permission_role_id as u64);
        let _ = member.remove_role(&ctx.http, permission_role_id).await;

        if let Err(e) = sqlx::query!(
            "UPDATE sessions SET revoked_at = now(), revoke_reason = 'deauth' WHERE id = $1",
            session.id
        )
        .execute(pool)
        .await
        {
            tracing::error!(error = ?e, session_id = session.id, "failed to mark session revoked");
            continue;
        }
        dropped.push(format!("<@&{}>", session.permission_role_id));
    }

    reply_ephemeral(ctx, cmd, &format!("Dropped: {}", dropped.join(", "))).await;

    let embed = CreateEmbed::new()
        .title("Deauthenticated")
        .description(format!("<@{}> ended their own session(s): {}", cmd.user.id, dropped.join(", ")))
        .color(0x5865F2);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Info, embed).await;
}

async fn handle_status(_ctx: &Context, _pool: &PgPool, _cmd: &CommandInteraction) {
    todo!("implemented in Task 4")
}
