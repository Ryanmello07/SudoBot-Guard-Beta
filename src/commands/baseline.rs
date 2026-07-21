use crate::auth;
use crate::logging::{log, LogTier};
use serenity::all::{
    CommandDataOption, CommandDataOptionValue, CommandInteraction, CommandOptionType, Context,
    CreateCommand, CreateCommandOption, CreateEmbed, CreateInteractionResponse,
    CreateInteractionResponseMessage,
};
use sqlx::PgPool;

pub fn commands() -> Vec<CreateCommand> {
    vec![CreateCommand::new("baseline")
        .description("Manage guarded role permission baselines")
        .add_option(
            CreateCommandOption::new(CommandOptionType::SubCommand, "update", "Bless a role's current state as the new accepted baseline")
                .add_sub_option(
                    CreateCommandOption::new(CommandOptionType::Role, "role", "The role to update")
                        .required(true),
                ),
        )]
}

async fn reply_ephemeral(ctx: &Context, cmd: &CommandInteraction, content: &str) {
    let msg = CreateInteractionResponseMessage::new().content(content).ephemeral(true);
    let _ = cmd.create_response(&ctx.http, CreateInteractionResponse::Message(msg)).await;
}

pub async fn handle(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction) {
    let Some(sub) = cmd.data.options.first() else { return };
    if sub.name != "update" {
        return;
    }
    handle_update(ctx, pool, cmd, sub).await;
}

async fn handle_update(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction, sub: &CommandDataOption) {
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

    let CommandDataOptionValue::SubCommand(opts) = &sub.value else { return };
    let Some(role_id) = opts.iter().find_map(|o| match (&o.name[..], &o.value) {
        ("role", CommandDataOptionValue::Role(id)) => Some(*id),
        _ => None,
    }) else {
        return reply_ephemeral(ctx, cmd, "Missing required option.").await;
    };

    let Some(guild) = ctx.cache.guild(guild_id).map(|g| g.clone()) else {
        return reply_ephemeral(ctx, cmd, "Couldn't read this server's roles right now, try again in a moment.").await;
    };
    let Some(role) = guild.roles.get(&role_id) else {
        return reply_ephemeral(ctx, cmd, "That role couldn't be found.").await;
    };

    let role_id_i64 = role_id.get() as i64;
    let is_registered = crate::guard::baseline::is_registered_role(pool, guild_id_i64, role_id_i64)
        .await
        .unwrap_or(false);
    let name = is_registered.then(|| role.name.clone());
    let position = is_registered.then_some(role.position as i32);

    if let Err(e) = crate::guard::baseline::upsert_baseline(
        pool,
        guild_id_i64,
        role_id_i64,
        role.permissions.bits() as i64,
        name.as_deref(),
        position,
        Some(user_id_i64),
    )
    .await
    {
        tracing::error!(error = ?e, "failed to update baseline");
        return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
    }

    reply_ephemeral(ctx, cmd, &format!("Baseline updated for <@&{role_id_i64}>.")).await;

    let embed = CreateEmbed::new()
        .title("Baseline updated")
        .description(format!("<@{user_id_i64}> blessed <@&{role_id_i64}>'s current state as the new accepted baseline."))
        .color(0x5865F2);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Info, embed).await;
}
