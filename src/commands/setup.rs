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
    match elevation::verify_code(pool, guild_id_i64, user_id_i64, &authcode, encryption_key, yubico).await {
        Ok(true) => true,
        Ok(false) => {
            reply_followup(ctx, cmd, "That code didn't verify.").await;
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
