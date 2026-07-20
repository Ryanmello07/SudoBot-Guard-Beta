use crate::auth;
use crate::logging::{log, LogTier};
use crate::settings::{self, ADMIN_REGEN_COOLDOWN_MINUTES_KEY};
use serenity::all::{
    CommandDataOption, CommandDataOptionValue, CommandInteraction, CommandOptionType, Context,
    CreateCommand, CreateCommandOption, CreateEmbed, CreateInteractionResponse,
    CreateInteractionResponseMessage,
};
use sqlx::PgPool;

pub fn commands() -> Vec<CreateCommand> {
    vec![CreateCommand::new("settings")
        .description("Configure server-specific rules and cooldowns")
        .add_option(CreateCommandOption::new(
            CommandOptionType::SubCommand,
            "view",
            "Show current settings",
        ))
        .add_option(
            CreateCommandOption::new(CommandOptionType::SubCommand, "set", "Change a setting")
                .add_sub_option(
                    CreateCommandOption::new(
                        CommandOptionType::String,
                        "key",
                        "Which setting to change",
                    )
                    .required(true)
                    .add_string_choice(
                        "admin_regen_cooldown_minutes",
                        ADMIN_REGEN_COOLDOWN_MINUTES_KEY,
                    )
                    .add_string_choice(
                        "admin_regen_completion_window_minutes",
                        crate::settings::ADMIN_REGEN_COMPLETION_WINDOW_MINUTES_KEY,
                    ),
                )
                .add_sub_option(
                    CreateCommandOption::new(CommandOptionType::String, "value", "New value")
                        .required(true),
                ),
        )]
}

pub async fn handle(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction) {
    let Some(sub) = cmd.data.options.first() else {
        return;
    };
    match sub.name.as_str() {
        "view" => handle_view(ctx, pool, cmd).await,
        "set" => handle_set(ctx, pool, cmd, sub).await,
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

async fn require_bot_admin(pool: &PgPool, guild_id_i64: i64, user_id_i64: i64) -> Result<bool, sqlx::Error> {
    auth::is_bot_admin(pool, guild_id_i64, user_id_i64).await
}

async fn handle_view(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction) {
    let Some(guild_id) = cmd.guild_id else {
        return reply_ephemeral(ctx, cmd, "This command only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = cmd.user.id.get() as i64;

    match require_bot_admin(pool, guild_id_i64, user_id_i64).await {
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

    let mut embed = CreateEmbed::new()
        .title("Server settings")
        .description("Rules and cooldowns for this server. Change any of these with `/settings set`.")
        .color(0x5865F2);

    for def in settings::SETTINGS_REGISTRY {
        let value = match settings::get_int_setting(pool, guild_id_i64, def.key, def.default).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = ?e, key = def.key, "failed to read setting");
                return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
            }
        };
        embed = embed.field(
            def.key,
            format!("**{value} minutes** (default: {})\n{}", def.default, def.description),
            false,
        );
    }

    let msg = CreateInteractionResponseMessage::new()
        .embed(embed)
        .ephemeral(true);
    let _ = cmd
        .create_response(&ctx.http, CreateInteractionResponse::Message(msg))
        .await;
}

async fn handle_set(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction, sub: &CommandDataOption) {
    let Some(guild_id) = cmd.guild_id else {
        return reply_ephemeral(ctx, cmd, "This command only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = cmd.user.id.get() as i64;

    match require_bot_admin(pool, guild_id_i64, user_id_i64).await {
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

    let CommandDataOptionValue::SubCommand(opts) = &sub.value else {
        return;
    };
    let mut key = None;
    let mut value = None;
    for opt in opts {
        match (opt.name.as_str(), &opt.value) {
            ("key", CommandDataOptionValue::String(s)) => key = Some(s.clone()),
            ("value", CommandDataOptionValue::String(s)) => value = Some(s.clone()),
            _ => {}
        }
    }
    let (Some(key), Some(value)) = (key, value) else {
        return reply_ephemeral(ctx, cmd, "Missing required options.").await;
    };

    if let Err(msg) = settings::validate_setting(&key, &value) {
        return reply_ephemeral(ctx, cmd, &msg).await;
    }

    if let Err(e) = settings::set_setting(pool, guild_id_i64, &key, &value, user_id_i64).await {
        tracing::error!(error = ?e, "failed to set setting");
        return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
    }

    reply_ephemeral(ctx, cmd, &format!("Set {key} = {value}.")).await;

    let embed = CreateEmbed::new()
        .title("Setting changed")
        .description(format!("<@{}> set `{key}` = `{value}`", cmd.user.id))
        .color(0x5865F2);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Info, embed).await;
}
