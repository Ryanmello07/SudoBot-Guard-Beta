use crate::auth;
use crate::elevation;
use crate::logging::user_ref;
use crate::panic;
use crate::yubico::YubicoClient;
use serenity::all::{
    CommandDataOptionValue, CommandInteraction, CommandOptionType, Context, CreateCommand,
    CreateCommandOption, CreateInteractionResponse, CreateInteractionResponseFollowup,
    CreateInteractionResponseMessage,
};
use sqlx::PgPool;

pub fn commands() -> Vec<CreateCommand> {
    vec![CreateCommand::new("panic")
        .description("Emergency: strip all elevated permissions and lock down immediately")
        .add_option(CreateCommandOption::new(
            CommandOptionType::String,
            "authcode",
            "Bot admin 2FA code to bypass an active post-panic cooldown",
        ))]
}

async fn reply_ephemeral(ctx: &Context, cmd: &CommandInteraction, content: &str) {
    let msg = CreateInteractionResponseMessage::new().content(content).ephemeral(true);
    let _ = cmd.create_response(&ctx.http, CreateInteractionResponse::Message(msg)).await;
}

async fn reply_followup(ctx: &Context, cmd: &CommandInteraction, content: &str) {
    let msg = CreateInteractionResponseFollowup::new().content(content).ephemeral(true);
    let _ = cmd.create_followup(&ctx.http, msg).await;
}

pub async fn handle(
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

    // --- Eligibility: anyone holding either half of any registered pair ---
    let member_role_ids: Vec<i64> = cmd
        .member
        .as_ref()
        .map(|m| m.roles.iter().map(|r| r.get() as i64).collect())
        .unwrap_or_default();
    let registered = match panic::registered_role_ids(pool, guild_id_i64).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "panic: failed to load registered role ids");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };
    if !panic::is_protected_staff(&member_role_ids, &registered) {
        return reply_ephemeral(ctx, cmd, "You need to hold a registered staff role to trigger panic mode.").await;
    }

    // --- Idempotency ---
    match panic::is_active(pool, guild_id_i64).await {
        Ok(true) => return reply_ephemeral(ctx, cmd, "Panic mode is already active.").await,
        Ok(false) => {}
        Err(e) => {
            tracing::error!(error = ?e, "panic: failed to check active state");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    // --- Cooldown, with bot-admin bypass via optional authcode ---
    let authcode = cmd.data.options.iter().find_map(|o| {
        if let CommandDataOptionValue::String(s) = &o.value {
            Some(s.clone())
        } else {
            None
        }
    });

    let cooldown = match panic::cooldown_remaining(pool, guild_id_i64).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "panic: failed to check cooldown");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };

    // Defer now, before any potentially-slow work below: the admin-bypass
    // 2FA check can make a live Yubico network call, and trigger() does
    // guild-wide session revocation. Matches auth.rs's established pattern
    // of deferring before anything that could exceed Discord's 3-second
    // interaction ack window — every reply from here on must go through
    // reply_followup instead of reply_ephemeral.
    if let Err(e) = cmd.defer_ephemeral(&ctx.http).await {
        tracing::error!(error = ?e, "failed to defer panic interaction");
        return;
    }

    if let Some(until) = cooldown {
        let is_admin = auth::is_bot_admin(pool, guild_id_i64, user_id_i64).await.unwrap_or(false);
        let bypassed = if is_admin {
            match authcode {
                Some(code) => elevation::verify_code(pool, guild_id_i64, user_id_i64, &code, encryption_key, yubico)
                    .await
                    .unwrap_or(false),
                None => false,
            }
        } else {
            false
        };
        if !bypassed {
            let ts = until.timestamp();
            return reply_followup(
                ctx,
                cmd,
                &format!("Panic mode is on cooldown until <t:{ts}:R>. A bot admin can bypass this with `/panic authcode:<code>`."),
            )
            .await;
        }
    }

    // --- Trigger (mass revoke + lockdown + panic_active), then reply ---
    let revoked_count = panic::trigger(ctx, pool, guild_id, user_id_i64).await;
    if let Err(e) = panic::post_vote_message(ctx, pool, guild_id_i64).await {
        tracing::error!(error = ?e, guild_id = guild_id_i64, "panic: failed to post vote message");
    }

    reply_followup(
        ctx,
        cmd,
        "Panic mode activated. Every elevated session has been revoked and lockdown is now enforced. New elevation is blocked until panic ends.",
    )
    .await;

    panic::log_event(
        pool,
        ctx,
        guild_id_i64,
        "Panic Mode Triggered",
        vec![
            ("Triggered By", user_ref(user_id_i64), true),
            ("Sessions Revoked", revoked_count.to_string(), true),
        ],
    )
    .await;
}
