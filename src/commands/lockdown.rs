use crate::auth;
use crate::guard;
use crate::logging::{log, user_ref, LogTier};
use crate::settings;
use serenity::all::{
    CommandInteraction, CommandOptionType, Context, CreateCommand, CreateCommandOption, CreateEmbed,
    CreateInteractionResponse, CreateInteractionResponseFollowup, CreateInteractionResponseMessage,
    GuildId,
};
use sqlx::PgPool;

pub fn commands() -> Vec<CreateCommand> {
    vec![CreateCommand::new("lockdown")
        .description("Toggle full guard enforcement")
        .add_option(CreateCommandOption::new(
            CommandOptionType::SubCommand,
            "on",
            "Re-enable full guarding and refresh every role's baseline to its current state",
        ))
        .add_option(CreateCommandOption::new(
            CommandOptionType::SubCommand,
            "off",
            "Relax guarding — only manual permission-role grant protection stays active",
        ))
        .add_option(CreateCommandOption::new(
            CommandOptionType::SubCommand,
            "status",
            "Show whether lockdown is currently on or off",
        ))]
}

async fn reply_ephemeral(ctx: &Context, cmd: &CommandInteraction, content: &str) {
    let msg = CreateInteractionResponseMessage::new().content(content).ephemeral(true);
    let _ = cmd.create_response(&ctx.http, CreateInteractionResponse::Message(msg)).await;
}

/// Like `reply_ephemeral`, but for use after the interaction has already been
/// deferred (e.g. in `handle_on`, which defers immediately on entry to stay
/// under Discord's 3-second ack window while `sync_role_baselines` runs).
/// Once deferred, `create_response` can no longer be used for the reply —
/// Discord already has an initial response recorded — so every reply from
/// that point on must go through a followup message instead.
async fn reply_followup(ctx: &Context, cmd: &CommandInteraction, content: &str) {
    let msg = CreateInteractionResponseFollowup::new().content(content).ephemeral(true);
    let _ = cmd.create_followup(&ctx.http, msg).await;
}

pub async fn handle(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction) {
    let Some(sub) = cmd.data.options.first() else { return };
    let Some(guild_id) = cmd.guild_id else {
        return reply_ephemeral(ctx, cmd, "This command only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = cmd.user.id.get() as i64;

    match auth::is_bot_admin(pool, guild_id_i64, user_id_i64).await {
        Ok(true) => {}
        Ok(false) => return reply_ephemeral(ctx, cmd, "You need to be a bot admin to use this command.").await,
        Err(e) => {
            tracing::error!(error = ?e, "failed to check bot admin status");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    match sub.name.as_str() {
        "on" => handle_on(ctx, pool, cmd, guild_id, guild_id_i64, user_id_i64).await,
        "off" => handle_off(ctx, pool, cmd, guild_id_i64, user_id_i64).await,
        "status" => handle_status(ctx, pool, cmd, guild_id_i64).await,
        _ => {}
    }
}

async fn handle_on(
    ctx: &Context,
    pool: &PgPool,
    cmd: &CommandInteraction,
    guild_id: GuildId,
    guild_id_i64: i64,
    user_id_i64: i64,
) {
    // `sync_role_baselines` does two sequential DB round-trips per role (up
    // to 250 roles in a guild), with no concurrency — that can easily exceed
    // Discord's 3-second interaction ack window. Defer immediately so
    // Discord shows "thinking..." instead of failing the interaction; every
    // reply from here on must go through `reply_followup` instead of
    // `reply_ephemeral`, since the initial response has now been sent.
    if let Err(e) = cmd.defer_ephemeral(&ctx.http).await {
        tracing::error!(error = ?e, "failed to defer lockdown on interaction");
        return;
    }

    // Snapshot baselines *before* flipping the flag on: if the flag flipped
    // first, a sweep or reactive event could land in the gap between "guard
    // is enforcing" and "baselines reflect the current state," reverting a
    // role to its stale old baseline instead of accepting what's live now.
    guard::backfill::sync_role_baselines(ctx, pool, guild_id, true, Some(user_id_i64)).await;

    if let Err(e) = settings::set_setting(pool, guild_id_i64, guard::LOCKDOWN_ENABLED_KEY, "true", user_id_i64).await {
        tracing::error!(error = ?e, "failed to enable lockdown");
        return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
    }

    reply_followup(ctx, cmd, "Lockdown enabled — full guarding is active, and every role's baseline has been refreshed to its current state.").await;

    let embed = CreateEmbed::new()
        .title("Lockdown Enabled")
        .field("Enabled By", user_ref(user_id_i64), true)
        .field(
            "Now Active",
            "Permission/name/position guarding is active again, and every role's baseline was refreshed to its current live state.",
            false,
        )
        .color(0xED4245);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Alert, embed).await;
}

async fn handle_off(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction, guild_id_i64: i64, user_id_i64: i64) {
    if let Err(e) = settings::set_setting(pool, guild_id_i64, guard::LOCKDOWN_ENABLED_KEY, "false", user_id_i64).await {
        tracing::error!(error = ?e, "failed to disable lockdown");
        return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
    }

    reply_ephemeral(ctx, cmd, "Lockdown disabled — only manual permission-role grant protection remains active.").await;

    let embed = CreateEmbed::new()
        .title("Lockdown Disabled")
        .field("Disabled By", user_ref(user_id_i64), true)
        .field(
            "Now Active",
            "Permission/name/position guarding is paused. Manual permission-role grants are still reverted and quarantined.",
            false,
        )
        .color(0x5865F2);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Alert, embed).await;
}

async fn handle_status(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction, guild_id_i64: i64) {
    let enabled = guard::is_lockdown_enabled(pool, guild_id_i64).await.unwrap_or_else(|e| {
        tracing::error!(error = ?e, "failed to read lockdown state");
        true // fail closed for the status display too — never report "off" on a read error
    });
    let state = if enabled { "on" } else { "off" };
    reply_ephemeral(ctx, cmd, &format!("Lockdown is currently **{state}**.")).await;
}
