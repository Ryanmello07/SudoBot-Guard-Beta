use crate::auth;
use crate::elevation;
use crate::logging::{log, user_ref, LogTier};
use crate::yubico::YubicoClient;
use serenity::all::{
    CommandDataOption, CommandDataOptionValue, CommandInteraction, CommandOptionType, Context,
    CreateCommand, CreateCommandOption, CreateEmbed, CreateInteractionResponse,
    CreateInteractionResponseFollowup, CreateInteractionResponseMessage,
};
use sqlx::PgPool;

pub fn commands() -> Vec<CreateCommand> {
    vec![CreateCommand::new("setup")
        .description("Bot setup commands")
        .add_option(CreateCommandOption::new(
            CommandOptionType::SubCommand,
            "claim",
            "Claim bot admin for this guild (requires Manage Server, only while unclaimed)",
        ))
        .add_option(
            CreateCommandOption::new(
                CommandOptionType::SubCommand,
                "channel",
                "Set the log channel for this guild",
            )
            .add_sub_option(
                CreateCommandOption::new(
                    CommandOptionType::Channel,
                    "channel",
                    "The channel to post logs in",
                )
                .required(true),
            )
            .add_sub_option(
                CreateCommandOption::new(
                    CommandOptionType::String,
                    "authcode",
                    "Your TOTP or YubiKey code",
                )
                .required(true),
            ),
        )
        .add_option(
            CreateCommandOption::new(
                CommandOptionType::SubCommand,
                "panic-channel",
                "Set the channel where panic-mode vote messages are posted",
            )
            .add_sub_option(
                CreateCommandOption::new(
                    CommandOptionType::Channel,
                    "channel",
                    "The channel to post panic votes in",
                )
                .required(true),
            )
            .add_sub_option(
                CreateCommandOption::new(
                    CommandOptionType::String,
                    "authcode",
                    "Your TOTP or YubiKey code",
                )
                .required(true),
            ),
        )
        .add_option(
            CreateCommandOption::new(
                CommandOptionType::SubCommand,
                "admin-add",
                "Add another bot admin to this guild",
            )
            .add_sub_option(
                CreateCommandOption::new(
                    CommandOptionType::User,
                    "user",
                    "Who to make a bot admin",
                )
                .required(true),
            )
            .add_sub_option(
                CreateCommandOption::new(
                    CommandOptionType::String,
                    "authcode",
                    "Your TOTP or YubiKey code",
                )
                .required(true),
            ),
        )
        .add_option(
            CreateCommandOption::new(
                CommandOptionType::SubCommand,
                "admin-remove",
                "Remove a bot admin from this guild",
            )
            .add_sub_option(
                CreateCommandOption::new(
                    CommandOptionType::User,
                    "user",
                    "Who to remove as a bot admin",
                )
                .required(true),
            )
            .add_sub_option(
                CreateCommandOption::new(
                    CommandOptionType::String,
                    "authcode",
                    "Your TOTP or YubiKey code",
                )
                .required(true),
            ),
        )]
}

pub async fn handle(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
    cmd: &CommandInteraction,
) {
    let Some(sub) = cmd.data.options.first() else {
        return;
    };
    match sub.name.as_str() {
        "claim" => handle_claim(ctx, pool, cmd).await,
        "channel" => handle_channel(ctx, pool, encryption_key, yubico, cmd, sub).await,
        "panic-channel" => handle_panic_channel(ctx, pool, encryption_key, yubico, cmd, sub).await,
        "admin-add" => handle_admin_add(ctx, pool, encryption_key, yubico, cmd, sub).await,
        "admin-remove" => handle_admin_remove(ctx, pool, encryption_key, yubico, cmd, sub).await,
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

/// Like `reply_ephemeral`, but for after the interaction has been deferred
/// (handle_channel/handle_panic_channel defer so verifying the authcode's
/// possible live Yubico network call stays under Discord's 3-second ack window).
async fn reply_followup(ctx: &Context, cmd: &CommandInteraction, content: &str) {
    let msg = CreateInteractionResponseFollowup::new()
        .content(content)
        .ephemeral(true);
    let _ = cmd.create_followup(&ctx.http, msg).await;
}

/// Verifies the required `authcode` sub-option for the 2FA-gated setup
/// subcommands. Returns true only when the code verifies; on a bad code or an
/// error it has already sent the appropriate followup reply and returns false.
async fn verify_setup_authcode(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
    cmd: &CommandInteraction,
    opts: &[CommandDataOption],
    guild_id_i64: i64,
    user_id_i64: i64,
) -> bool {
    let authcode = opts.iter().find_map(|o| {
        if o.name == "authcode" {
            if let CommandDataOptionValue::String(s) = &o.value {
                return Some(s.clone());
            }
        }
        None
    });
    let Some(authcode) = authcode else {
        reply_followup(ctx, cmd, "Missing required code.").await;
        return false;
    };
    match elevation::verify_code(pool, guild_id_i64, user_id_i64, &authcode, encryption_key, yubico, elevation::LockoutPolicy::Enforce).await {
        Ok(elevation::VerifyOutcome::Verified) => true,
        Ok(elevation::VerifyOutcome::Invalid) => {
            reply_followup(ctx, cmd, "That code didn't verify.").await;
            false
        }
        Ok(elevation::VerifyOutcome::LockedOut { failure_count }) => {
            crate::logging::log_auth_lockout(pool, &ctx.http, guild_id_i64, user_id_i64, failure_count).await;
            reply_followup(ctx, cmd, "Too many failed attempts. Try again later.").await;
            false
        }
        Err(e) => {
            tracing::error!(error = ?e, "setup: error verifying authcode");
            reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
            false
        }
    }
}

async fn handle_claim(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction) {
    let Some(guild_id) = cmd.guild_id else {
        return reply_ephemeral(ctx, cmd, "This command only works in a server.").await;
    };

    // NOT independently spiked before this plan was written — if `.permissions`
    // doesn't exist on `Member` or isn't populated here, investigate the real
    // serenity 0.12.5 API (it should be Some for interaction-sourced members)
    // and ask rather than guessing a workaround.
    let has_manage_guild = cmd
        .member
        .as_ref()
        .and_then(|m| m.permissions)
        .map(|p| p.manage_guild())
        .unwrap_or(false);
    if !has_manage_guild {
        return reply_ephemeral(
            ctx,
            cmd,
            "You need the Manage Server permission to claim bot admin.",
        )
        .await;
    }

    let guild_id_i64 = guild_id.get() as i64;
    let count = match auth::bot_admin_count(pool, guild_id_i64).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = ?e, "failed to check bot admin count");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };
    if count > 0 {
        return reply_ephemeral(ctx, cmd, "This guild already has a bot admin.").await;
    }

    let user_id_i64 = cmd.user.id.get() as i64;
    if let Err(e) = auth::add_bot_admin(pool, guild_id_i64, user_id_i64).await {
        tracing::error!(error = ?e, "failed to add bot admin");
        return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
    }

    reply_ephemeral(ctx, cmd, "You are now a bot admin for this server.").await;

    let embed = CreateEmbed::new()
        .title("Bot Admin Claimed")
        .field("Claimed By", user_ref(cmd.user.id.get() as i64), false)
        .color(0x5865F2);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Info, embed).await;
}

async fn handle_channel(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
    cmd: &CommandInteraction,
    sub: &CommandDataOption,
) {
    let Some(guild_id) = cmd.guild_id else {
        return reply_ephemeral(ctx, cmd, "This command only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = cmd.user.id.get() as i64;

    // Defer before verifying the authcode: verify_code can make a live Yubico
    // network call and risk Discord's 3-second ack window. Every reply from
    // here on must go through `reply_followup`.
    if let Err(e) = cmd.defer_ephemeral(&ctx.http).await {
        tracing::error!(error = ?e, "failed to defer setup channel interaction");
        return;
    }

    match auth::is_bot_admin(pool, guild_id_i64, user_id_i64).await {
        Ok(true) => {}
        Ok(false) => {
            return reply_followup(ctx, cmd, "You need to be a bot admin to use this command.")
                .await
        }
        Err(e) => {
            tracing::error!(error = ?e, "failed to check bot admin status");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    let CommandDataOptionValue::SubCommand(opts) = &sub.value else {
        return;
    };

    if !verify_setup_authcode(ctx, pool, encryption_key, yubico, cmd, opts, guild_id_i64, user_id_i64).await {
        return;
    }

    let channel_id = opts.iter().find_map(|o| {
        if let CommandDataOptionValue::Channel(id) = o.value {
            Some(id)
        } else {
            None
        }
    });
    let Some(channel_id) = channel_id else {
        return reply_followup(ctx, cmd, "No channel provided.").await;
    };

    if let Err(e) = sqlx::query!(
        "INSERT INTO log_channels (guild_id, channel_id) VALUES ($1, $2)
         ON CONFLICT (guild_id) DO UPDATE SET channel_id = EXCLUDED.channel_id",
        guild_id_i64,
        channel_id.get() as i64
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = ?e, "failed to set log channel");
        return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
    }

    reply_followup(ctx, cmd, &format!("Log channel set to <#{channel_id}>.")).await;

    let embed = CreateEmbed::new()
        .title("Log Channel Configured")
        .field("Channel", format!("<#{0}>\n`{0}`", channel_id.get() as i64), true)
        .field("Configured By", user_ref(cmd.user.id.get() as i64), true)
        .color(0x5865F2);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Info, embed).await;
}

async fn handle_panic_channel(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
    cmd: &CommandInteraction,
    sub: &CommandDataOption,
) {
    let Some(guild_id) = cmd.guild_id else {
        return reply_ephemeral(ctx, cmd, "This command only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = cmd.user.id.get() as i64;

    // Defer before verifying the authcode: verify_code can make a live Yubico
    // network call and risk Discord's 3-second ack window. Every reply from
    // here on must go through `reply_followup`.
    if let Err(e) = cmd.defer_ephemeral(&ctx.http).await {
        tracing::error!(error = ?e, "failed to defer setup panic-channel interaction");
        return;
    }

    match auth::is_bot_admin(pool, guild_id_i64, user_id_i64).await {
        Ok(true) => {}
        Ok(false) => {
            return reply_followup(ctx, cmd, "You need to be a bot admin to use this command.")
                .await
        }
        Err(e) => {
            tracing::error!(error = ?e, "failed to check bot admin status");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    let CommandDataOptionValue::SubCommand(opts) = &sub.value else {
        return;
    };

    if !verify_setup_authcode(ctx, pool, encryption_key, yubico, cmd, opts, guild_id_i64, user_id_i64).await {
        return;
    }

    let channel_id = opts.iter().find_map(|o| {
        if let CommandDataOptionValue::Channel(id) = o.value {
            Some(id)
        } else {
            None
        }
    });
    let Some(channel_id) = channel_id else {
        return reply_followup(ctx, cmd, "No channel provided.").await;
    };

    if let Err(e) = sqlx::query!(
        "INSERT INTO panic_channels (guild_id, channel_id) VALUES ($1, $2)
         ON CONFLICT (guild_id) DO UPDATE SET channel_id = EXCLUDED.channel_id",
        guild_id_i64,
        channel_id.get() as i64
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = ?e, "failed to set panic channel");
        return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
    }

    reply_followup(ctx, cmd, &format!("Panic vote channel set to <#{channel_id}>.")).await;

    let embed = CreateEmbed::new()
        .title("Panic Channel Configured")
        .field("Channel", format!("<#{0}>\n`{0}`", channel_id.get() as i64), true)
        .field("Configured By", user_ref(cmd.user.id.get() as i64), true)
        .color(0x5865F2);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Info, embed).await;
}

/// Pulls the required `user` sub-option (a `CommandOptionType::User`) out of the
/// subcommand options as a raw i64 user id. In serenity 0.12 a User option is a
/// single `CommandDataOptionValue::User(UserId)` (resolved member data lives in
/// `cmd.data.resolved`, which we don't need here — the id is enough).
fn target_user_id(opts: &[CommandDataOption]) -> Option<i64> {
    opts.iter().find_map(|o| {
        if o.name == "user" {
            if let CommandDataOptionValue::User(id) = o.value {
                return Some(id.get() as i64);
            }
        }
        None
    })
}

/// Decision for whether an `admin-remove` should proceed, given the target's
/// current admin status and the guild's total bot-admin count. Kept as pure
/// logic so the last-admin safety guard can be unit-tested directly, matching
/// this codebase's pattern of testing small logic pieces (see protect.rs).
///
/// The `<= 1` (rather than `== 1`) is defensive: callers only reach this after
/// confirming the target IS an admin, so the count is necessarily `>= 1`, but
/// treating any "one or fewer" count as last-admin can never wrongly delete the
/// final admin.
#[derive(Debug, PartialEq, Eq)]
enum RemovalDecision {
    /// Target isn't a bot admin — nothing to remove.
    NotAnAdmin,
    /// Target is the only remaining admin — removing them would lock the guild out.
    LastAdmin,
    /// Safe to remove: target is an admin and at least one other admin remains.
    Proceed,
}

fn evaluate_removal(target_is_admin: bool, admin_count: i64) -> RemovalDecision {
    if !target_is_admin {
        RemovalDecision::NotAnAdmin
    } else if admin_count <= 1 {
        RemovalDecision::LastAdmin
    } else {
        RemovalDecision::Proceed
    }
}

async fn handle_admin_add(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
    cmd: &CommandInteraction,
    sub: &CommandDataOption,
) {
    let Some(guild_id) = cmd.guild_id else {
        return reply_ephemeral(ctx, cmd, "This command only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = cmd.user.id.get() as i64;

    // Defer before verifying the authcode: verify_code can make a live Yubico
    // network call and risk Discord's 3-second ack window. Every reply from
    // here on must go through `reply_followup`.
    if let Err(e) = cmd.defer_ephemeral(&ctx.http).await {
        tracing::error!(error = ?e, "failed to defer setup admin-add interaction");
        return;
    }

    match auth::is_bot_admin(pool, guild_id_i64, user_id_i64).await {
        Ok(true) => {}
        Ok(false) => {
            return reply_followup(ctx, cmd, "You need to be a bot admin to use this command.")
                .await
        }
        Err(e) => {
            tracing::error!(error = ?e, "failed to check bot admin status");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    let CommandDataOptionValue::SubCommand(opts) = &sub.value else {
        return;
    };

    if !verify_setup_authcode(ctx, pool, encryption_key, yubico, cmd, opts, guild_id_i64, user_id_i64).await {
        return;
    }

    let Some(target_id) = target_user_id(opts) else {
        return reply_followup(ctx, cmd, "No user provided.").await;
    };

    // Honest reply for the harmless no-op case: add_bot_admin uses
    // ON CONFLICT DO NOTHING, so re-adding an existing admin would otherwise
    // report a misleading success.
    match auth::is_bot_admin(pool, guild_id_i64, target_id).await {
        Ok(true) => {
            return reply_followup(ctx, cmd, &format!("<@{target_id}> is already a bot admin.")).await;
        }
        Ok(false) => {}
        Err(e) => {
            tracing::error!(error = ?e, "failed to check target bot admin status");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    if let Err(e) = auth::add_bot_admin(pool, guild_id_i64, target_id).await {
        tracing::error!(error = ?e, "failed to add bot admin");
        return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
    }

    reply_followup(ctx, cmd, &format!("<@{target_id}> is now a bot admin for this server.")).await;

    let embed = CreateEmbed::new()
        .title("Bot Admin Added")
        .field("Admin Added", user_ref(target_id), true)
        .field("Added By", user_ref(user_id_i64), true)
        .color(0x5865F2);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Alert, embed).await;
}

async fn handle_admin_remove(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
    cmd: &CommandInteraction,
    sub: &CommandDataOption,
) {
    let Some(guild_id) = cmd.guild_id else {
        return reply_ephemeral(ctx, cmd, "This command only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = cmd.user.id.get() as i64;

    // Defer before verifying the authcode: verify_code can make a live Yubico
    // network call and risk Discord's 3-second ack window. Every reply from
    // here on must go through `reply_followup`.
    if let Err(e) = cmd.defer_ephemeral(&ctx.http).await {
        tracing::error!(error = ?e, "failed to defer setup admin-remove interaction");
        return;
    }

    match auth::is_bot_admin(pool, guild_id_i64, user_id_i64).await {
        Ok(true) => {}
        Ok(false) => {
            return reply_followup(ctx, cmd, "You need to be a bot admin to use this command.")
                .await
        }
        Err(e) => {
            tracing::error!(error = ?e, "failed to check bot admin status");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    let CommandDataOptionValue::SubCommand(opts) = &sub.value else {
        return;
    };

    if !verify_setup_authcode(ctx, pool, encryption_key, yubico, cmd, opts, guild_id_i64, user_id_i64).await {
        return;
    }

    let Some(target_id) = target_user_id(opts) else {
        return reply_followup(ctx, cmd, "No user provided.").await;
    };

    // Guard sequence (order is the safety property): first confirm the target IS
    // an admin, then check the total count. A count of 1 here necessarily means
    // the target is the last admin, so removing them would leave the guild with
    // zero admins — refuse. See `evaluate_removal` for the pure decision logic.
    let target_is_admin = match auth::is_bot_admin(pool, guild_id_i64, target_id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "failed to check target bot admin status");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };
    if !target_is_admin {
        return reply_followup(ctx, cmd, "That user isn't a bot admin.").await;
    }

    let count = match auth::bot_admin_count(pool, guild_id_i64).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = ?e, "failed to check bot admin count");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };

    match evaluate_removal(target_is_admin, count) {
        RemovalDecision::NotAnAdmin => {
            return reply_followup(ctx, cmd, "That user isn't a bot admin.").await;
        }
        RemovalDecision::LastAdmin => {
            return reply_followup(
                ctx,
                cmd,
                "Can't remove the last bot admin — this would lock everyone in this guild out of every admin command. Add another admin first.",
            )
            .await;
        }
        RemovalDecision::Proceed => {}
    }

    if let Err(e) = auth::remove_bot_admin(pool, guild_id_i64, target_id).await {
        tracing::error!(error = ?e, "failed to remove bot admin");
        return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
    }

    reply_followup(ctx, cmd, &format!("<@{target_id}> is no longer a bot admin for this server.")).await;

    let embed = CreateEmbed::new()
        .title("Bot Admin Removed")
        .field("Admin Removed", user_ref(target_id), true)
        .field("Removed By", user_ref(user_id_i64), true)
        .color(0x5865F2);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Alert, embed).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removal_rejected_when_target_not_admin() {
        assert_eq!(evaluate_removal(false, 5), RemovalDecision::NotAnAdmin);
        // Count is irrelevant when the target isn't an admin.
        assert_eq!(evaluate_removal(false, 1), RemovalDecision::NotAnAdmin);
        assert_eq!(evaluate_removal(false, 0), RemovalDecision::NotAnAdmin);
    }

    #[test]
    fn removal_rejected_when_target_is_last_admin() {
        assert_eq!(evaluate_removal(true, 1), RemovalDecision::LastAdmin);
    }

    #[test]
    fn removal_allowed_when_another_admin_remains() {
        assert_eq!(evaluate_removal(true, 2), RemovalDecision::Proceed);
        assert_eq!(evaluate_removal(true, 10), RemovalDecision::Proceed);
    }

    #[test]
    fn last_admin_guard_is_defensive_against_impossible_low_counts() {
        // Reaching this function with target_is_admin == true guarantees count >= 1,
        // but a 0 must never be treated as "safe to delete the last admin".
        assert_eq!(evaluate_removal(true, 0), RemovalDecision::LastAdmin);
    }
}
