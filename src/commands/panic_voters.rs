use crate::auth;
use crate::elevation;
use crate::logging::role_ref;
use crate::yubico::YubicoClient;
use serenity::all::{
    CommandDataOption, CommandDataOptionValue, CommandInteraction, CommandOptionType,
    ComponentInteraction, Context, CreateActionRow, CreateCommand, CreateCommandOption,
    CreateEmbed, CreateInteractionResponse, CreateInteractionResponseFollowup,
    CreateInteractionResponseMessage, CreateSelectMenu, CreateSelectMenuKind,
    CreateSelectMenuOption, RoleId,
};
use sqlx::PgPool;

pub fn commands() -> Vec<CreateCommand> {
    vec![CreateCommand::new("panic-voters")
        .description("Manage which roles can vote to end panic mode")
        .add_option(
            CreateCommandOption::new(CommandOptionType::SubCommand, "add", "Add a role as an eligible voter")
                .add_sub_option(
                    CreateCommandOption::new(CommandOptionType::Role, "role", "The role to add").required(true),
                )
                .add_sub_option(
                    CreateCommandOption::new(CommandOptionType::String, "authcode", "Your TOTP or YubiKey code").required(true),
                ),
        )
        // No role option here deliberately: a Discord `Role`-type option can
        // only resolve to a role that currently exists in the guild, so it
        // can never target a voter role whose underlying Discord role was
        // since deleted (Discord itself rejects the interaction with "A role
        // id specified is invalid" before the bot even sees it). Removal
        // instead lists what's actually stored in voter_roles and lets the
        // admin pick by select menu, mirroring /protect remove's pair menu.
        .add_option(
            CreateCommandOption::new(
                CommandOptionType::SubCommand,
                "remove",
                "Remove a role from eligible voters (choose from a list)",
            )
            .add_sub_option(
                CreateCommandOption::new(CommandOptionType::String, "authcode", "Your TOTP or YubiKey code").required(true),
            ),
        )
        .add_option(CreateCommandOption::new(
            CommandOptionType::SubCommand,
            "list",
            "List eligible voter roles",
        ))]
}

async fn reply_ephemeral(ctx: &Context, cmd: &CommandInteraction, content: &str) {
    let msg = CreateInteractionResponseMessage::new().content(content).ephemeral(true);
    let _ = cmd.create_response(&ctx.http, CreateInteractionResponse::Message(msg)).await;
}

/// Like `reply_ephemeral`, but for after the interaction has been deferred
/// (handle_add/handle_remove defer so verifying the authcode's possible live
/// Yubico network call stays under Discord's 3-second ack window).
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
        "add" => handle_add(ctx, pool, encryption_key, yubico, cmd, sub, guild_id_i64, user_id_i64).await,
        "remove" => handle_remove(ctx, pool, encryption_key, yubico, cmd, sub, guild_id_i64, user_id_i64).await,
        "list" => handle_list(ctx, pool, cmd, guild_id_i64).await,
        _ => {}
    }
}

fn extract_role(sub: &CommandDataOption) -> Option<i64> {
    let CommandDataOptionValue::SubCommand(opts) = &sub.value else { return None };
    opts.iter().find_map(|o| {
        if let CommandDataOptionValue::Role(id) = o.value {
            Some(id.get() as i64)
        } else {
            None
        }
    })
}

fn extract_authcode(sub: &CommandDataOption) -> Option<String> {
    let CommandDataOptionValue::SubCommand(opts) = &sub.value else { return None };
    opts.iter().find_map(|o| {
        if let CommandDataOptionValue::String(s) = &o.value {
            Some(s.clone())
        } else {
            None
        }
    })
}

async fn handle_add(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
    cmd: &CommandInteraction,
    sub: &CommandDataOption,
    guild_id_i64: i64,
    user_id_i64: i64,
) {
    // Defer before verifying the authcode: verify_code can make a live Yubico
    // network call and risk Discord's 3-second ack window. Every reply from
    // here on must go through `reply_followup`.
    if let Err(e) = cmd.defer_ephemeral(&ctx.http).await {
        tracing::error!(error = ?e, "failed to defer panic-voters add interaction");
        return;
    }

    let Some(role_id_i64) = extract_role(sub) else {
        return reply_followup(ctx, cmd, "No role provided.").await;
    };
    let Some(authcode) = extract_authcode(sub) else {
        return reply_followup(ctx, cmd, "Missing required code.").await;
    };
    match elevation::verify_code(pool, guild_id_i64, user_id_i64, &authcode, encryption_key, yubico).await {
        Ok(true) => {}
        Ok(false) => return reply_followup(ctx, cmd, "That code didn't verify.").await,
        Err(e) => {
            tracing::error!(error = ?e, "panic-voters: error verifying authcode");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    if let Err(e) = sqlx::query!(
        "INSERT INTO voter_roles (guild_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        guild_id_i64,
        role_id_i64
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = ?e, "failed to add voter role");
        return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
    }
    reply_followup(ctx, cmd, "Voter role added.").await;
}

async fn handle_remove(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
    cmd: &CommandInteraction,
    sub: &CommandDataOption,
    guild_id_i64: i64,
    user_id_i64: i64,
) {
    let Some(guild_id) = cmd.guild_id else {
        return reply_ephemeral(ctx, cmd, "This command only works in a server.").await;
    };

    // Defer before verifying the authcode: verify_code can make a live Yubico
    // network call and risk Discord's 3-second ack window. The 2FA code is
    // required and verified here, on the initial slash invocation, before the
    // ephemeral select menu is ever shown — the later component click that
    // performs the delete is a clarification of WHICH role, not a new privilege
    // decision, and its handler still independently re-checks is_bot_admin.
    // Every reply from here on must go through `reply_followup`.
    if let Err(e) = cmd.defer_ephemeral(&ctx.http).await {
        tracing::error!(error = ?e, "failed to defer panic-voters remove interaction");
        return;
    }

    let Some(authcode) = extract_authcode(sub) else {
        return reply_followup(ctx, cmd, "Missing required code.").await;
    };
    match elevation::verify_code(pool, guild_id_i64, user_id_i64, &authcode, encryption_key, yubico).await {
        Ok(true) => {}
        Ok(false) => return reply_followup(ctx, cmd, "That code didn't verify.").await,
        Err(e) => {
            tracing::error!(error = ?e, "panic-voters: error verifying authcode");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    let rows = match sqlx::query!("SELECT role_id FROM voter_roles WHERE guild_id = $1 ORDER BY role_id", guild_id_i64)
        .fetch_all(pool)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = ?e, "failed to list voter roles for removal");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };

    if rows.is_empty() {
        return reply_followup(ctx, cmd, "No voter roles are registered yet.").await;
    }

    // Select-menu option labels don't render mention syntax (unlike message
    // content), so resolve a real name from cache where possible — falling
    // back to a plainly-labeled "unknown role" entry (rather than raw
    // mention markup, which would just show as literal text) for a role
    // that's since been deleted, since that's exactly the case this menu
    // exists to handle.
    let guild = ctx.cache.guild(guild_id).map(|g| g.clone());
    let resolve_label = |role_id: i64| -> String {
        guild
            .as_ref()
            .and_then(|g| g.roles.get(&RoleId::new(role_id as u64)))
            .map(|r| r.name.clone())
            .unwrap_or_else(|| format!("Unknown role ({role_id})"))
    };

    let total = rows.len();
    let shown: Vec<_> = rows.iter().take(25).collect();
    let options: Vec<CreateSelectMenuOption> = shown
        .iter()
        .map(|row| {
            let label: String = resolve_label(row.role_id).chars().take(100).collect();
            CreateSelectMenuOption::new(label, row.role_id.to_string())
        })
        .collect();

    let content = if total > 25 {
        format!("Choose a voter role to remove (showing 25 of {total} — remove some to see the rest):")
    } else {
        "Choose a voter role to remove:".to_string()
    };

    let select = CreateActionRow::SelectMenu(
        CreateSelectMenu::new("panic_voters_remove_select", CreateSelectMenuKind::String { options })
            .placeholder("Choose a voter role to remove"),
    );

    let msg = CreateInteractionResponseFollowup::new()
        .content(content)
        .components(vec![select])
        .ephemeral(true);
    let _ = cmd.create_followup(&ctx.http, msg).await;
}

pub async fn handle_component(ctx: &Context, pool: &PgPool, comp: &ComponentInteraction) {
    if comp.data.custom_id != "panic_voters_remove_select" {
        return;
    }
    let serenity::all::ComponentInteractionDataKind::StringSelect { values } = &comp.data.kind else {
        return;
    };
    let Some(role_id_i64) = values.first().and_then(|v| v.parse::<i64>().ok()) else {
        return;
    };
    let Some(guild_id) = comp.guild_id else {
        return;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = comp.user.id.get() as i64;

    match auth::is_bot_admin(pool, guild_id_i64, user_id_i64).await {
        Ok(true) => {}
        Ok(false) => {
            let msg = CreateInteractionResponseMessage::new()
                .content("You need to be a bot admin to use this command.")
                .components(vec![])
                .ephemeral(true);
            let _ = comp.create_response(&ctx.http, CreateInteractionResponse::UpdateMessage(msg)).await;
            return;
        }
        Err(e) => {
            tracing::error!(error = ?e, "failed to check bot admin status");
            let msg = CreateInteractionResponseMessage::new()
                .content("Something went wrong. Try again later.")
                .components(vec![])
                .ephemeral(true);
            let _ = comp.create_response(&ctx.http, CreateInteractionResponse::UpdateMessage(msg)).await;
            return;
        }
    }

    let deleted = sqlx::query!(
        "DELETE FROM voter_roles WHERE guild_id = $1 AND role_id = $2",
        guild_id_i64,
        role_id_i64
    )
    .execute(pool)
    .await;

    let content = match deleted {
        Ok(result) if result.rows_affected() > 0 => "Voter role removed.",
        Ok(_) => "That voter role is already gone.",
        Err(e) => {
            tracing::error!(error = ?e, "failed to remove voter role via select menu");
            "Something went wrong. Try again later."
        }
    };

    let msg = CreateInteractionResponseMessage::new().content(content).components(vec![]).ephemeral(true);
    let _ = comp.create_response(&ctx.http, CreateInteractionResponse::UpdateMessage(msg)).await;
}

async fn handle_list(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction, guild_id_i64: i64) {
    let rows = match sqlx::query!("SELECT role_id FROM voter_roles WHERE guild_id = $1", guild_id_i64)
        .fetch_all(pool)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = ?e, "failed to list voter roles");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };

    let description = if rows.is_empty() {
        "No voter roles configured yet.".to_string()
    } else {
        rows.iter().map(|r| role_ref(r.role_id)).collect::<Vec<_>>().join("\n")
    };

    let embed = CreateEmbed::new().title("Panic Vote — Eligible Voter Roles").description(description).color(0x5865F2);
    let msg = CreateInteractionResponseMessage::new().embed(embed).ephemeral(true);
    let _ = cmd.create_response(&ctx.http, CreateInteractionResponse::Message(msg)).await;
}
