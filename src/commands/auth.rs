use crate::auth;
use crate::elevation;
use crate::logging::{log, role_ref, user_ref, LogTier};
use crate::yubico::YubicoClient;
use serenity::all::{
    CommandDataOptionValue, CommandInteraction, CommandOptionType, Context, CreateCommand,
    CreateCommandOption, CreateEmbed, CreateInteractionResponse, CreateInteractionResponseFollowup,
    CreateInteractionResponseMessage,
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

/// Like `reply_ephemeral`, but for use after the interaction has already been
/// deferred (e.g. in `handle_auth`, which defers immediately after the
/// lockout check to stay under Discord's 3-second ack window). Once deferred,
/// `create_response` can no longer be used for the reply — Discord already
/// has an initial response recorded — so every reply from that point on must
/// go through a followup message instead.
async fn reply_followup(ctx: &Context, cmd: &CommandInteraction, content: &str) {
    let msg = CreateInteractionResponseFollowup::new()
        .content(content)
        .ephemeral(true);
    let _ = cmd.create_followup(&ctx.http, msg).await;
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
            .title("Auth Lockout")
            .field("User", user_ref(cmd.user.id.get() as i64), true)
            .field(
                "Failed Attempts",
                format!("{failure_count} in the last {LOCKOUT_WINDOW_MINUTES} minutes"),
                true,
            )
            .color(0xED4245);
        let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Alert, embed).await;
        return reply_ephemeral(ctx, cmd, "Too many failed attempts. Try again later.").await;
    }

    // Eligibility checks, code verification (possible live Yubico HTTP call),
    // and the per-pair grant loop (role adds + session writes) below can
    // plausibly exceed Discord's 3-second interaction ack window. Defer now
    // so Discord shows "thinking..." instead of failing the interaction;
    // every reply from here on must go through `reply_followup` instead of
    // `reply_ephemeral`, since the initial response has now been sent.
    if let Err(e) = cmd.defer_ephemeral(&ctx.http).await {
        tracing::error!(error = ?e, "failed to defer auth interaction");
        return;
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
        return reply_followup(ctx, cmd, "Missing required code.").await;
    };

    // --- Eligible pairs: every pair in the guild if bot admin, else only pairs
    // whose standard_role_id the member holds. Unified into one query via the
    // is_admin boolean so both cases share a single anonymous row type. ---
    let is_admin = match auth::is_bot_admin(pool, guild_id_i64, user_id_i64).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "failed to check bot admin status");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
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
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
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
        return reply_followup(ctx, cmd, "You don't hold any registered role to elevate.").await;
    }

    // --- Verify the code ---
    if elevation::detect_code_shape(&code).is_none() {
        record_attempt(pool, guild_id_i64, user_id_i64, false).await;
        return reply_followup(ctx, cmd, "That doesn't look like a valid code.").await;
    }

    let verified = match elevation::verify_code(pool, guild_id_i64, user_id_i64, &code, encryption_key, yubico).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "error while verifying auth code");
            record_attempt(pool, guild_id_i64, user_id_i64, false).await;
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };

    if !verified {
        record_attempt(pool, guild_id_i64, user_id_i64, false).await;
        return reply_followup(ctx, cmd, "That code didn't verify.").await;
    }

    record_attempt(pool, guild_id_i64, user_id_i64, true).await;

    // --- Grant every eligible pair independently ---
    let Some(member) = cmd.member.as_ref() else {
        return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
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

        let existing = sqlx::query!(
            "SELECT id FROM sessions WHERE guild_id = $1 AND user_id = $2 AND role_pair_id = $3 AND revoked_at IS NULL AND expires_at > now()",
            guild_id_i64,
            user_id_i64,
            pair.id
        )
        .fetch_optional(pool)
        .await;

        // `sqlx::query!` generates a distinct anonymous record type per call
        // site, so even though both branches only select `expires_at`, their
        // `Record` types don't unify — map each down to the bare
        // `DateTime<Utc>` so the match arms agree.
        let expires_at_result: Result<chrono::DateTime<chrono::Utc>, sqlx::Error> = match existing {
            Ok(Some(existing_row)) => {
                sqlx::query!(
                    "UPDATE sessions SET expires_at = now() + make_interval(mins => $1) WHERE id = $2 RETURNING expires_at",
                    pair.session_minutes,
                    existing_row.id
                )
                .fetch_one(pool)
                .await
                .map(|row| row.expires_at)
            }
            Ok(None) => {
                sqlx::query!(
                    "INSERT INTO sessions (guild_id, user_id, role_pair_id, expires_at)
                     VALUES ($1, $2, $3, now() + make_interval(mins => $4))
                     RETURNING expires_at",
                    guild_id_i64,
                    user_id_i64,
                    pair.id,
                    pair.session_minutes
                )
                .fetch_one(pool)
                .await
                .map(|row| row.expires_at)
            }
            Err(e) => Err(e),
        };

        match expires_at_result {
            Ok(expires_at) => {
                let ts = expires_at.timestamp();
                granted_lines.push(format!("<@&{}> — expires <t:{}:R>", pair.permission_role_id, ts));

                let embed = CreateEmbed::new()
                    .title("Elevated")
                    .field("User", user_ref(cmd.user.id.get() as i64), true)
                    .field("Role", role_ref(pair.permission_role_id), true)
                    .field("Expires", format!("<t:{ts}:R>"), false)
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
    reply_followup(ctx, cmd, &content).await;
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
    let mut dropped_ids = Vec::new();
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
        dropped_ids.push(session.permission_role_id);
    }

    reply_ephemeral(ctx, cmd, &format!("Dropped: {}", dropped.join(", "))).await;

    // Guard against an empty field value (Discord rejects the embed with a
    // 400): dropped_ids is empty if every session's revoke UPDATE failed.
    let roles_field = if dropped_ids.is_empty() {
        "*None*".to_string()
    } else {
        dropped_ids
            .iter()
            .map(|id| role_ref(*id))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let embed = CreateEmbed::new()
        .title("Deauthenticated")
        .field("User", user_ref(cmd.user.id.get() as i64), true)
        .field("Sessions Ended", roles_field, false)
        .color(0x5865F2);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Info, embed).await;
}

async fn handle_status(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction) {
    let Some(guild_id) = cmd.guild_id else {
        return reply_ephemeral(ctx, cmd, "This command only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = cmd.user.id.get() as i64;

    match auth::is_bot_admin(pool, guild_id_i64, user_id_i64).await {
        Ok(true) => {}
        Ok(false) => {
            return reply_ephemeral(ctx, cmd, "You need to be a bot admin to use this command.")
                .await
        }
        Err(e) => {
            tracing::error!(error = ?e, "failed to check bot admin status");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    let sessions = match sqlx::query!(
        "SELECT s.user_id, s.expires_at, r.permission_role_id
         FROM sessions s
         JOIN role_pairs r ON r.id = s.role_pair_id
         WHERE s.guild_id = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
         ORDER BY s.expires_at",
        guild_id_i64
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = ?e, "failed to load active sessions for status");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };

    let description = if sessions.is_empty() {
        "No active elevated sessions.".to_string()
    } else {
        sessions
            .iter()
            .map(|s| {
                format!(
                    "<@{}> — <@&{}> — expires <t:{}:R>",
                    s.user_id,
                    s.permission_role_id,
                    s.expires_at.timestamp()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let embed = CreateEmbed::new()
        .title("Active elevated sessions")
        .description(description)
        .color(0x5865F2);
    let msg = CreateInteractionResponseMessage::new()
        .embed(embed)
        .ephemeral(true);
    let _ = cmd
        .create_response(&ctx.http, CreateInteractionResponse::Message(msg))
        .await;
}
