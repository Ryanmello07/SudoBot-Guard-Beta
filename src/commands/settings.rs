use crate::auth;
use crate::logging::{log, user_ref, LogTier};
use crate::settings::{self, ADMIN_REGEN_COOLDOWN_MINUTES_KEY};
use serenity::all::{
    ActionRowComponent, CommandDataOption, CommandDataOptionValue, CommandInteraction,
    CommandOptionType, ComponentInteraction, ComponentInteractionDataKind, Context, CreateActionRow,
    CreateCommand, CreateCommandOption, CreateEmbed, CreateInputText, CreateInteractionResponse,
    CreateInteractionResponseMessage, CreateModal, CreateSelectMenu, CreateSelectMenuKind,
    CreateSelectMenuOption, InputTextStyle, ModalInteraction,
};
use sqlx::PgPool;

const SETTINGS_SELECT_ID: &str = "settings_select";
const SETTINGS_MODAL_PREFIX: &str = "settings_modal:";

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
                    )
                    .add_string_choice(
                        "quarantine_on_manual_grant",
                        crate::settings::QUARANTINE_ON_MANUAL_GRANT_KEY,
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

    let embed = match build_settings_embed(pool, guild_id_i64).await {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = ?e, "failed to read settings");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };

    let msg = CreateInteractionResponseMessage::new()
        .embed(embed)
        .components(vec![settings_select_row()])
        .ephemeral(true);
    let _ = cmd
        .create_response(&ctx.http, CreateInteractionResponse::Message(msg))
        .await;
}

/// Shared by `/settings view` and the modal's success path (which refreshes
/// the same view in place), so both always show identical, up-to-date data.
async fn build_settings_embed(pool: &PgPool, guild_id_i64: i64) -> Result<CreateEmbed, sqlx::Error> {
    let mut embed = CreateEmbed::new()
        .title("Server settings")
        .description("Rules and cooldowns for this server. Change any of these with `/settings set` or the dropdown below.")
        .color(0x5865F2);

    for def in settings::SETTINGS_REGISTRY {
        let value_text = match def.kind {
            settings::SettingKind::Minutes => {
                let value = settings::get_int_setting(pool, guild_id_i64, def.key, def.default).await?;
                format!("**{value} minutes** (default: {} minutes)", def.default)
            }
            settings::SettingKind::Bool => {
                let default_bool = def.default != 0;
                let value = settings::get_bool_setting(pool, guild_id_i64, def.key, default_bool).await?;
                format!("**{}** (default: {})", if value { "on" } else { "off" }, if default_bool { "on" } else { "off" })
            }
        };
        embed = embed.field(def.key, format!("{value_text}\n{}", def.description), false);
    }
    Ok(embed)
}

fn settings_select_row() -> CreateActionRow {
    CreateActionRow::SelectMenu(
        CreateSelectMenu::new(SETTINGS_SELECT_ID, settings_select_kind()).placeholder("Change a setting"),
    )
}

/// Builds the select menu's options from the registry so the dropdown stays
/// in sync with `/settings set`'s choices without separate upkeep.
fn settings_select_kind() -> CreateSelectMenuKind {
    let options: Vec<CreateSelectMenuOption> = settings::SETTINGS_REGISTRY
        .iter()
        .map(|def| {
            let description: String = def.description.chars().take(100).collect();
            CreateSelectMenuOption::new(def.key, def.key).description(description)
        })
        .collect();
    CreateSelectMenuKind::String { options }
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
        .title("Setting Changed")
        .field("Setting", format!("`{key}`"), true)
        .field("New Value", format!("`{value}`"), true)
        .field("Changed By", user_ref(cmd.user.id.get() as i64), false)
        .color(0x5865F2);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Info, embed).await;
}

async fn reply_component_ephemeral(ctx: &Context, comp: &ComponentInteraction, content: &str) {
    let msg = CreateInteractionResponseMessage::new()
        .content(content)
        .ephemeral(true);
    let _ = comp
        .create_response(&ctx.http, CreateInteractionResponse::Message(msg))
        .await;
}

/// Handles the `/settings view` dropdown: opens a modal pre-filled with the
/// chosen setting's current value. The modal submit (`handle_modal`) does
/// the actual validate-and-save, re-checking bot admin itself, so this step
/// only needs to check admin to avoid showing the modal to a non-admin at all.
pub async fn handle_component(ctx: &Context, pool: &PgPool, comp: &ComponentInteraction) {
    if comp.data.custom_id != SETTINGS_SELECT_ID {
        return;
    }
    let ComponentInteractionDataKind::StringSelect { values } = &comp.data.kind else {
        return;
    };
    let Some(key) = values.first().cloned() else {
        return;
    };
    let Some(guild_id) = comp.guild_id else {
        return reply_component_ephemeral(ctx, comp, "This only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = comp.user.id.get() as i64;

    match require_bot_admin(pool, guild_id_i64, user_id_i64).await {
        Ok(true) => {}
        Ok(false) => {
            return reply_component_ephemeral(ctx, comp, "You need to be a bot admin to use this.").await
        }
        Err(e) => {
            tracing::error!(error = ?e, "failed to check bot admin status");
            return reply_component_ephemeral(ctx, comp, "Something went wrong. Try again later.").await;
        }
    }

    let Some(def) = settings::SETTINGS_REGISTRY.iter().find(|d| d.key == key) else {
        return reply_component_ephemeral(ctx, comp, "Unknown setting.").await;
    };
    let current_text = match def.kind {
        settings::SettingKind::Minutes => {
            match settings::get_int_setting(pool, guild_id_i64, def.key, def.default).await {
                Ok(v) => v.to_string(),
                Err(e) => {
                    tracing::error!(error = ?e, key = def.key, "failed to read setting");
                    return reply_component_ephemeral(ctx, comp, "Something went wrong. Try again later.").await;
                }
            }
        }
        settings::SettingKind::Bool => {
            let default_bool = def.default != 0;
            match settings::get_bool_setting(pool, guild_id_i64, def.key, default_bool).await {
                Ok(v) => v.to_string(),
                Err(e) => {
                    tracing::error!(error = ?e, key = def.key, "failed to read setting");
                    return reply_component_ephemeral(ctx, comp, "Something went wrong. Try again later.").await;
                }
            }
        }
    };

    let title: String = format!("Set {key}").chars().take(45).collect();
    let modal = CreateModal::new(format!("{SETTINGS_MODAL_PREFIX}{key}"), title).components(vec![
        CreateActionRow::InputText(
            CreateInputText::new(InputTextStyle::Short, "New value", "value")
                .value(current_text)
                .required(true),
        ),
    ]);
    if let Err(e) = comp
        .create_response(&ctx.http, CreateInteractionResponse::Modal(modal))
        .await
    {
        tracing::error!(error = ?e, "failed to open settings modal");
    }
}

async fn reply_modal_ephemeral(ctx: &Context, modal: &ModalInteraction, content: &str) {
    let msg = CreateInteractionResponseMessage::new()
        .content(content)
        .ephemeral(true);
    let _ = modal
        .create_response(&ctx.http, CreateInteractionResponse::Message(msg))
        .await;
}

pub async fn handle_modal(ctx: &Context, pool: &PgPool, modal: &ModalInteraction) {
    let Some(key) = modal.data.custom_id.strip_prefix(SETTINGS_MODAL_PREFIX) else {
        return;
    };
    let key = key.to_string();

    let Some(guild_id) = modal.guild_id else {
        return reply_modal_ephemeral(ctx, modal, "This only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = modal.user.id.get() as i64;

    // Re-check admin here rather than trusting the check done before the
    // modal was opened — a demoted admin could otherwise still submit it.
    match require_bot_admin(pool, guild_id_i64, user_id_i64).await {
        Ok(true) => {}
        Ok(false) => {
            return reply_modal_ephemeral(ctx, modal, "You need to be a bot admin to use this.").await
        }
        Err(e) => {
            tracing::error!(error = ?e, "failed to check bot admin status");
            return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
        }
    }

    let mut value = None;
    for row in &modal.data.components {
        for c in &row.components {
            if let ActionRowComponent::InputText(input) = c {
                if input.custom_id == "value" {
                    value = input.value.clone();
                }
            }
        }
    }
    let Some(value) = value else {
        return reply_modal_ephemeral(ctx, modal, "Missing value.").await;
    };

    if let Err(msg) = settings::validate_setting(&key, &value) {
        return reply_modal_ephemeral(ctx, modal, &msg).await;
    }

    if let Err(e) = settings::set_setting(pool, guild_id_i64, &key, &value, user_id_i64).await {
        tracing::error!(error = ?e, "failed to set setting");
        return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
    }

    // Refresh the /settings view message the dropdown was opened from,
    // rather than sending a separate confirmation — the updated field value
    // is the confirmation. Falls back to a plain ephemeral reply if the
    // refresh itself fails to read back (rare: same pool, right after write).
    // Ack first, before the logging POST below — log() is a network call and
    // must stay out of the interaction's 3-second ack budget.
    match build_settings_embed(pool, guild_id_i64).await {
        Ok(embed) => {
            let msg = CreateInteractionResponseMessage::new()
                .content(format!("Updated `{key}`."))
                .embed(embed)
                .components(vec![settings_select_row()]);
            if let Err(e) = modal
                .create_response(&ctx.http, CreateInteractionResponse::UpdateMessage(msg))
                .await
            {
                tracing::error!(error = ?e, "failed to refresh settings view after update");
            }
        }
        Err(e) => {
            tracing::error!(error = ?e, "failed to refresh settings view after update");
            reply_modal_ephemeral(ctx, modal, &format!("Set {key} = {value}, but the view couldn't refresh — re-run /settings view.")).await;
        }
    }

    let log_embed = CreateEmbed::new()
        .title("Setting Changed")
        .field("Setting", format!("`{key}`"), true)
        .field("New Value", format!("`{value}`"), true)
        .field("Changed By", user_ref(modal.user.id.get() as i64), false)
        .color(0x5865F2);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Info, log_embed).await;
}
