use crate::auth;
use crate::logging::{log, LogTier};
use serenity::all::{
    CommandDataOption, CommandDataOptionValue, CommandInteraction, CommandOptionType,
    ComponentInteraction, Context, CreateActionRow, CreateCommand, CreateCommandOption,
    CreateEmbed, CreateInteractionResponse, CreateInteractionResponseMessage, CreateSelectMenu,
    CreateSelectMenuKind, CreateSelectMenuOption, RoleId,
};
use sqlx::PgPool;

pub fn commands() -> Vec<CreateCommand> {
    vec![CreateCommand::new("protect")
        .description("Manage protected role pairs")
        .add_option(
            CreateCommandOption::new(CommandOptionType::SubCommand, "add", "Register a role pair")
                .add_sub_option(
                    CreateCommandOption::new(
                        CommandOptionType::Role,
                        "standard_role",
                        "The staffer's identity role (zero permissions)",
                    )
                    .required(true),
                )
                .add_sub_option(
                    CreateCommandOption::new(
                        CommandOptionType::Role,
                        "permission_role",
                        "The role with real permissions, only ever bot-granted",
                    )
                    .required(true),
                )
                .add_sub_option(
                    CreateCommandOption::new(
                        CommandOptionType::Integer,
                        "session_minutes",
                        "How long an elevation from this pair lasts",
                    )
                    .required(true)
                    .min_int_value(1)
                    .max_int_value(i32::MAX as u64),
                )
                .add_sub_option(
                    CreateCommandOption::new(
                        CommandOptionType::String,
                        "alert_tier",
                        "Log severity for this pair's events (default: info)",
                    )
                    .add_string_choice("info", "info")
                    .add_string_choice("alert", "alert"),
                ),
        )
        .add_option(CreateCommandOption::new(
            CommandOptionType::SubCommand,
            "remove",
            "Remove a registered role pair",
        ))
        .add_option(CreateCommandOption::new(
            CommandOptionType::SubCommand,
            "list",
            "List registered role pairs",
        ))]
}

pub async fn handle(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction) {
    let Some(sub) = cmd.data.options.first() else {
        return;
    };
    match sub.name.as_str() {
        "add" => handle_add(ctx, pool, cmd, sub).await,
        "remove" => handle_remove(ctx, pool, cmd).await,
        "list" => handle_list(ctx, pool, cmd).await,
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

/// Given the bot's own top role position and a list of (role label, position)
/// pairs being considered for registration, returns the labels of any role
/// that sits at or above the bot's own position (meaning the bot can't
/// manage it). Empty `Err` never occurs — a non-empty violations list is
/// always returned on failure.
pub fn validate_hierarchy(
    bot_top_position: u16,
    role_positions: &[(&str, u16)],
) -> Result<(), Vec<String>> {
    let violations: Vec<String> = role_positions
        .iter()
        .filter(|(_, pos)| *pos >= bot_top_position)
        .map(|(label, _)| label.to_string())
        .collect();
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

async fn handle_add(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction, sub: &CommandDataOption) {
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

    let CommandDataOptionValue::SubCommand(opts) = &sub.value else {
        return;
    };

    let mut standard_role = None;
    let mut permission_role = None;
    let mut session_minutes: Option<i64> = None;
    let mut alert_tier = "info".to_string();
    for opt in opts {
        match (opt.name.as_str(), &opt.value) {
            ("standard_role", CommandDataOptionValue::Role(id)) => standard_role = Some(*id),
            ("permission_role", CommandDataOptionValue::Role(id)) => permission_role = Some(*id),
            ("session_minutes", CommandDataOptionValue::Integer(n)) => session_minutes = Some(*n),
            ("alert_tier", CommandDataOptionValue::String(s)) => alert_tier = s.clone(),
            _ => {}
        }
    }
    let (Some(standard_role), Some(permission_role), Some(session_minutes)) =
        (standard_role, permission_role, session_minutes)
    else {
        return reply_ephemeral(ctx, cmd, "Missing required options.").await;
    };

    if standard_role == permission_role {
        return reply_ephemeral(
            ctx,
            cmd,
            "Standard role and permission role must be different.",
        )
        .await;
    }

    // NOT independently spiked before this plan was written — if
    // `ctx.cache.current_user()` doesn't exist under this name/path in
    // serenity 0.12.5, investigate the real API rather than guessing.
    let Some(guild) = ctx.cache.guild(guild_id).map(|g| g.clone()) else {
        return reply_ephemeral(
            ctx,
            cmd,
            "Couldn't read this server's roles right now, try again in a moment.",
        )
        .await;
    };
    let Some(bot_member) = guild.members.get(&ctx.cache.current_user().id) else {
        return reply_ephemeral(
            ctx,
            cmd,
            "Couldn't verify the bot's own role position, try again in a moment.",
        )
        .await;
    };
    let bot_top_position = bot_member
        .roles
        .iter()
        .filter_map(|r| guild.roles.get(r))
        .map(|r| r.position)
        .max()
        .unwrap_or(0);

    let role_positions: Vec<(&str, u16)> = vec![
        (
            "standard role",
            guild
                .roles
                .get(&standard_role)
                .map(|r| r.position)
                .unwrap_or(u16::MAX),
        ),
        (
            "permission role",
            guild
                .roles
                .get(&permission_role)
                .map(|r| r.position)
                .unwrap_or(u16::MAX),
        ),
    ];
    if let Err(violations) = validate_hierarchy(bot_top_position, &role_positions) {
        return reply_ephemeral(
            ctx,
            cmd,
            &format!(
                "These roles sit at or above the bot's own role, so it can't manage them: {}",
                violations.join(", ")
            ),
        )
        .await;
    }

    let Ok(session_minutes_i32) = i32::try_from(session_minutes) else {
        return reply_ephemeral(ctx, cmd, "Session length is out of range.").await;
    };

    if let Err(e) = sqlx::query!(
        "INSERT INTO role_pairs (guild_id, standard_role_id, permission_role_id, session_minutes, alert_tier, created_by)
         VALUES ($1, $2, $3, $4, $5, $6)",
        guild_id_i64,
        standard_role.get() as i64,
        permission_role.get() as i64,
        session_minutes_i32,
        alert_tier,
        user_id_i64
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = ?e, "failed to insert role pair");
        return reply_ephemeral(
            ctx,
            cmd,
            "Couldn't register that pair — it may already be registered, or something went wrong.",
        )
        .await;
    }

    for (role_id, role_name) in [
        (standard_role, guild.roles.get(&standard_role).map(|r| r.name.clone())),
        (permission_role, guild.roles.get(&permission_role).map(|r| r.name.clone())),
    ] {
        let role_id_i64 = role_id.get() as i64;

        // Only backfill if no baseline exists yet — never overwrite an
        // existing one. A baseline may already exist from the startup
        // backfill, or from a prior `/protect add` on this same role before
        // a `/protect remove` + re-add. Unconditionally upserting here would
        // silently replace the previously-trusted baseline with whatever the
        // role's live permissions happen to be at this exact instant, which
        // could bake in an in-flight tamper as the new "trusted" state.
        match crate::guard::baseline::get_baseline(pool, guild_id_i64, role_id_i64).await {
            Ok(Some(_)) => continue, // already has a baseline — don't touch it
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = ?e, %guild_id, role_id = role_id_i64, "guard: failed to check baseline before registration backfill");
                continue;
            }
        }

        let position = guild.roles.get(&role_id).map(|r| r.position as i32);
        let permissions = guild.roles.get(&role_id).map(|r| r.permissions.bits() as i64).unwrap_or(0);
        if let Err(e) = crate::guard::baseline::upsert_baseline(
            pool,
            guild_id_i64,
            role_id_i64,
            permissions,
            role_name.as_deref(),
            position,
            None,
        )
        .await
        {
            tracing::error!(error = ?e, %guild_id, role_id = role_id_i64, "guard: failed to backfill baseline on registration");
        }
    }

    reply_ephemeral(ctx, cmd, "Role pair registered.").await;

    let embed = CreateEmbed::new()
        .title("Role pair registered")
        .description(format!(
            "<@{}> registered <@&{}> \u{2192} <@&{}> ({} min, {} tier)",
            cmd.user.id, standard_role, permission_role, session_minutes, alert_tier
        ))
        .color(0x57F287);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Info, embed).await;
}

pub fn format_pair_label(standard_role_name: &str, permission_role_name: &str) -> String {
    format!("{standard_role_name} \u{2192} {permission_role_name}")
}

async fn handle_remove(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction) {
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

    let rows = match sqlx::query!(
        "SELECT id, standard_role_id, permission_role_id FROM role_pairs WHERE guild_id = $1 ORDER BY id",
        guild_id_i64
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = ?e, "failed to list role pairs");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };

    if rows.is_empty() {
        return reply_ephemeral(ctx, cmd, "No role pairs are registered yet.").await;
    }

    // Resolve role names from cache so labels are readable — select-menu
    // option labels don't render Discord mention syntax, unlike message
    // content. Fall back to the raw mention format per-role (or for every
    // row, if the guild isn't cached) rather than blocking removal.
    let guild = ctx.cache.guild(guild_id).map(|g| g.clone());
    let resolve_name = |role_id: i64| -> String {
        let fallback = || format!("<@&{role_id}>");
        guild
            .as_ref()
            .and_then(|g| g.roles.get(&RoleId::new(role_id as u64)))
            .map(|r| r.name.clone())
            .unwrap_or_else(fallback)
    };

    let total = rows.len();
    let shown: Vec<_> = rows.iter().take(25).collect();
    let options: Vec<CreateSelectMenuOption> = shown
        .iter()
        .map(|row| {
            let label = format_pair_label(
                &resolve_name(row.standard_role_id),
                &resolve_name(row.permission_role_id),
            );
            // Discord hard-caps select-menu option labels at 100 chars; role
            // names can be up to 100 chars each, so a combined label could
            // exceed that and cause the same silent-400 class this fix is
            // closing. Truncate defensively rather than risk it.
            let label: String = label.chars().take(100).collect();
            CreateSelectMenuOption::new(label, row.id.to_string())
        })
        .collect();

    let content = if total > 25 {
        format!("Choose a role pair to remove (showing 25 of {total} — remove some to see the rest):")
    } else {
        "Choose a role pair to remove:".to_string()
    };

    let select = CreateActionRow::SelectMenu(
        CreateSelectMenu::new(
            "protect_remove_select",
            CreateSelectMenuKind::String { options },
        )
        .placeholder("Choose a role pair to remove"),
    );

    let msg = CreateInteractionResponseMessage::new()
        .content(content)
        .components(vec![select])
        .ephemeral(true);
    let _ = cmd
        .create_response(&ctx.http, CreateInteractionResponse::Message(msg))
        .await;
}

async fn handle_list(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction) {
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

    let rows = match sqlx::query!(
        "SELECT standard_role_id, permission_role_id, session_minutes, alert_tier FROM role_pairs WHERE guild_id = $1 ORDER BY id",
        guild_id_i64
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = ?e, "failed to list role pairs");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };

    let description = if rows.is_empty() {
        "No role pairs are registered yet.".to_string()
    } else {
        rows.iter()
            .map(|row| {
                format!(
                    "<@&{}> \u{2192} <@&{}> — {} min, {} tier",
                    row.standard_role_id, row.permission_role_id, row.session_minutes, row.alert_tier
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let embed = CreateEmbed::new()
        .title("Registered role pairs")
        .description(description)
        .color(0x5865F2);
    let msg = CreateInteractionResponseMessage::new()
        .embed(embed)
        .ephemeral(true);
    let _ = cmd
        .create_response(&ctx.http, CreateInteractionResponse::Message(msg))
        .await;
}

pub async fn handle_component(ctx: &Context, pool: &PgPool, comp: &ComponentInteraction) {
    if comp.data.custom_id != "protect_remove_select" {
        return;
    }
    let serenity::all::ComponentInteractionDataKind::StringSelect { values } = &comp.data.kind
    else {
        return;
    };
    let Some(selected_id) = values.first().and_then(|v| v.parse::<i64>().ok()) else {
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
            let _ = comp
                .create_response(&ctx.http, CreateInteractionResponse::UpdateMessage(msg))
                .await;
            return;
        }
        Err(e) => {
            tracing::error!(error = ?e, "failed to check bot admin status");
            let msg = CreateInteractionResponseMessage::new()
                .content("Something went wrong. Try again later.")
                .components(vec![])
                .ephemeral(true);
            let _ = comp
                .create_response(&ctx.http, CreateInteractionResponse::UpdateMessage(msg))
                .await;
            return;
        }
    }

    let deleted = sqlx::query!(
        "DELETE FROM role_pairs WHERE id = $1 AND guild_id = $2 RETURNING standard_role_id, permission_role_id",
        selected_id,
        guild_id_i64
    )
    .fetch_optional(pool)
    .await;

    let msg = match deleted {
        Ok(Some(row)) => {
            let embed = CreateEmbed::new()
                .title("Role pair removed")
                .description(format!(
                    "<@{}> removed <@&{}> \u{2192} <@&{}>",
                    comp.user.id, row.standard_role_id, row.permission_role_id
                ))
                .color(0xED4245);
            let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Info, embed).await;
            CreateInteractionResponseMessage::new()
                .content("Role pair removed.")
                .components(vec![])
                .ephemeral(true)
        }
        Ok(None) => CreateInteractionResponseMessage::new()
            .content("That pair no longer exists.")
            .components(vec![])
            .ephemeral(true),
        Err(e) => {
            tracing::error!(error = ?e, "failed to delete role pair");
            CreateInteractionResponseMessage::new()
                .content("Something went wrong. Try again later.")
                .components(vec![])
                .ephemeral(true)
        }
    };

    let _ = comp
        .create_response(&ctx.http, CreateInteractionResponse::UpdateMessage(msg))
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_pair_label_with_arrow() {
        let label = format_pair_label("Moderator", "Moderator (Elevated)");
        assert_eq!(label, "Moderator \u{2192} Moderator (Elevated)");
    }

    #[test]
    fn accepts_roles_strictly_below_bot() {
        let result = validate_hierarchy(10, &[("standard role", 3), ("permission role", 5)]);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn rejects_role_equal_to_bot_position() {
        let result = validate_hierarchy(10, &[("standard role", 10)]);
        assert_eq!(result, Err(vec!["standard role".to_string()]));
    }

    #[test]
    fn rejects_role_above_bot_position() {
        let result = validate_hierarchy(10, &[("permission role", 15)]);
        assert_eq!(result, Err(vec!["permission role".to_string()]));
    }

    #[test]
    fn reports_all_violating_roles_not_just_the_first() {
        let result = validate_hierarchy(10, &[("standard role", 12), ("permission role", 20)]);
        assert_eq!(
            result,
            Err(vec!["standard role".to_string(), "permission role".to_string()])
        );
    }

    #[test]
    fn mixed_valid_and_invalid_only_reports_invalid() {
        let result = validate_hierarchy(10, &[("standard role", 3), ("permission role", 10)]);
        assert_eq!(result, Err(vec!["permission role".to_string()]));
    }
}
