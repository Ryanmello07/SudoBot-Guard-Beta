use crate::auth;
use crate::logging::role_ref;
use serenity::all::{
    CommandDataOption, CommandDataOptionValue, CommandInteraction, CommandOptionType, Context,
    CreateCommand, CreateCommandOption, CreateEmbed, CreateInteractionResponse,
    CreateInteractionResponseMessage,
};
use sqlx::PgPool;

pub fn commands() -> Vec<CreateCommand> {
    vec![CreateCommand::new("panic-voters")
        .description("Manage which roles can vote to end panic mode")
        .add_option(
            CreateCommandOption::new(CommandOptionType::SubCommand, "add", "Add a role as an eligible voter").add_sub_option(
                CreateCommandOption::new(CommandOptionType::Role, "role", "The role to add").required(true),
            ),
        )
        .add_option(
            CreateCommandOption::new(CommandOptionType::SubCommand, "remove", "Remove a role from eligible voters")
                .add_sub_option(
                    CreateCommandOption::new(CommandOptionType::Role, "role", "The role to remove").required(true),
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
        "add" => handle_add(ctx, pool, cmd, sub, guild_id_i64).await,
        "remove" => handle_remove(ctx, pool, cmd, sub, guild_id_i64).await,
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

async fn handle_add(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction, sub: &CommandDataOption, guild_id_i64: i64) {
    let Some(role_id_i64) = extract_role(sub) else {
        return reply_ephemeral(ctx, cmd, "No role provided.").await;
    };
    if let Err(e) = sqlx::query!(
        "INSERT INTO voter_roles (guild_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        guild_id_i64,
        role_id_i64
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = ?e, "failed to add voter role");
        return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
    }
    reply_ephemeral(ctx, cmd, "Voter role added.").await;
}

async fn handle_remove(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction, sub: &CommandDataOption, guild_id_i64: i64) {
    let Some(role_id_i64) = extract_role(sub) else {
        return reply_ephemeral(ctx, cmd, "No role provided.").await;
    };
    if let Err(e) = sqlx::query!(
        "DELETE FROM voter_roles WHERE guild_id = $1 AND role_id = $2",
        guild_id_i64,
        role_id_i64
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = ?e, "failed to remove voter role");
        return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
    }
    reply_ephemeral(ctx, cmd, "Voter role removed.").await;
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
