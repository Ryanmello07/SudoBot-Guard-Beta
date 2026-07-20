use crate::auth;
use serenity::all::{
    ButtonStyle, CommandInteraction, Context, CreateActionRow, CreateButton, CreateCommand,
    CreateEmbed, CreateInteractionResponse, CreateInteractionResponseMessage,
};
use sqlx::PgPool;

pub fn commands() -> Vec<CreateCommand> {
    vec![CreateCommand::new("enroll")
        .description("Enroll a second factor")
        .add_option(serenity::all::CreateCommandOption::new(
            serenity::all::CommandOptionType::SubCommand,
            "start",
            "Begin enrollment",
        ))]
}

pub async fn handle(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction) {
    let Some(sub) = cmd.data.options.first() else {
        return;
    };
    if sub.name == "start" {
        handle_start(ctx, pool, cmd).await;
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

/// True if the user is a bot admin (always eligible, per Plan 2's carried
/// forward decision) or holds any role registered as a standard_role_id for
/// this guild.
pub async fn is_eligible_to_enroll(
    ctx: &Context,
    pool: &PgPool,
    guild_id_i64: i64,
    guild_id: serenity::all::GuildId,
    user_id_i64: i64,
    member_role_ids: &[serenity::all::RoleId],
) -> Result<bool, sqlx::Error> {
    if auth::is_bot_admin(pool, guild_id_i64, user_id_i64).await? {
        return Ok(true);
    }
    let _ = guild_id; // reserved for a future cache-based check if role IDs aren't passed in
    let role_ids_i64: Vec<i64> = member_role_ids.iter().map(|r| r.get() as i64).collect();
    let row = sqlx::query!(
        "SELECT 1 AS present FROM role_pairs WHERE guild_id = $1 AND standard_role_id = ANY($2)",
        guild_id_i64,
        &role_ids_i64
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

async fn handle_start(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction) {
    let Some(guild_id) = cmd.guild_id else {
        return reply_ephemeral(ctx, cmd, "This command only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = cmd.user.id.get() as i64;
    let member_role_ids: Vec<serenity::all::RoleId> = cmd
        .member
        .as_ref()
        .map(|m| m.roles.clone())
        .unwrap_or_default();

    match is_eligible_to_enroll(ctx, pool, guild_id_i64, guild_id, user_id_i64, &member_role_ids).await {
        Ok(true) => {}
        Ok(false) => {
            return reply_ephemeral(
                ctx,
                cmd,
                "You need to hold a registered staff role (or be a bot admin) to enroll.",
            )
            .await
        }
        Err(e) => {
            tracing::error!(error = ?e, "failed to check enrollment eligibility");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    let embed = CreateEmbed::new()
        .title("Choose how to secure your account")
        .description("Pick a factor to enroll. You can enroll both.")
        .color(0x5865F2);
    let buttons = CreateActionRow::Buttons(vec![
        CreateButton::new("enroll_totp")
            .label("TOTP")
            .style(ButtonStyle::Primary),
        CreateButton::new("enroll_yubikey")
            .label("YubiKey")
            .style(ButtonStyle::Secondary),
        CreateButton::new("enroll_both")
            .label("Both")
            .style(ButtonStyle::Success),
    ]);
    let msg = CreateInteractionResponseMessage::new()
        .embed(embed)
        .components(vec![buttons])
        .ephemeral(true);
    let _ = cmd
        .create_response(&ctx.http, CreateInteractionResponse::Message(msg))
        .await;
}
