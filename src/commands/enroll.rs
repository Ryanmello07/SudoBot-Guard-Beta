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
        ))
        .add_option(
            serenity::all::CreateCommandOption::new(
                serenity::all::CommandOptionType::SubCommand,
                "approve",
                "Approve a pending (or proactive) enrollment for a staffer",
            )
            .add_sub_option(
                serenity::all::CreateCommandOption::new(
                    serenity::all::CommandOptionType::User,
                    "user",
                    "Who to approve",
                )
                .required(true),
            )
            .add_sub_option(
                serenity::all::CreateCommandOption::new(
                    serenity::all::CommandOptionType::String,
                    "factor",
                    "Which factor",
                )
                .required(true)
                .add_string_choice("totp", "totp")
                .add_string_choice("yubikey", "yubikey"),
            )
            .add_sub_option(
                serenity::all::CreateCommandOption::new(
                    serenity::all::CommandOptionType::String,
                    "window",
                    "How long they have to complete it, e.g. '30m' or '1h' (max 24h)",
                )
                .required(true),
            ),
        )]
}

pub async fn handle(ctx: &Context, pool: &PgPool, cmd: &CommandInteraction) {
    let Some(sub) = cmd.data.options.first() else {
        return;
    };
    match sub.name.as_str() {
        "start" => handle_start(ctx, pool, cmd).await,
        "approve" => handle_approve(ctx, pool, cmd, sub).await,
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

async fn handle_approve(
    ctx: &Context,
    pool: &PgPool,
    cmd: &CommandInteraction,
    sub: &serenity::all::CommandDataOption,
) {
    let Some(guild_id) = cmd.guild_id else {
        return reply_ephemeral(ctx, cmd, "This command only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let approver_id_i64 = cmd.user.id.get() as i64;

    match auth::is_bot_admin(pool, guild_id_i64, approver_id_i64).await {
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

    let serenity::all::CommandDataOptionValue::SubCommand(opts) = &sub.value else {
        return;
    };
    let mut target_user = None;
    let mut factor = None;
    let mut window_str = None;
    for opt in opts {
        match (opt.name.as_str(), &opt.value) {
            ("user", serenity::all::CommandDataOptionValue::User(id)) => target_user = Some(*id),
            ("factor", serenity::all::CommandDataOptionValue::String(s)) => factor = Some(s.clone()),
            ("window", serenity::all::CommandDataOptionValue::String(s)) => window_str = Some(s.clone()),
            _ => {}
        }
    }
    let (Some(target_user), Some(factor), Some(window_str)) = (target_user, factor, window_str) else {
        return reply_ephemeral(ctx, cmd, "Missing required options.").await;
    };

    let window_minutes = match crate::enrollment::parse_window_minutes(&window_str) {
        Ok(m) => m,
        Err(msg) => return reply_ephemeral(ctx, cmd, &msg).await,
    };

    let target_user_i64 = target_user.get() as i64;
    let action = match determine_regenerate_or_add(pool, guild_id_i64, target_user_i64, &factor).await {
        Ok(action) => action,
        Err(e) => {
            tracing::error!(error = ?e, "failed to determine add-vs-regenerate for enrollment approval");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(error = ?e, "failed to start transaction for enrollment approval");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };

    let approved_at_result = sqlx::query!(
        "INSERT INTO enrollment_requests (guild_id, user_id, factor_type, action, status, approved_by, approved_at, window_minutes, window_expires_at)
         VALUES ($1, $2, $3, $4, 'approved', $5, now(), $6, now() + make_interval(mins => $6))",
        guild_id_i64,
        target_user_i64,
        factor,
        action,
        approver_id_i64,
        window_minutes,
    )
    .execute(&mut *tx)
    .await;

    if let Err(e) = approved_at_result {
        tracing::error!(error = ?e, "failed to record enrollment approval");
        return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
    }

    // Regenerate approvals delete the old factor immediately, per design.
    // Run in the same transaction as the INSERT above so a failure here rolls
    // back the whole approval instead of leaving an "approved" request row on
    // the books while the old factor secret is still live.
    if action == "regenerate" {
        let delete_result = match factor.as_str() {
            "totp" => sqlx::query!(
                "DELETE FROM totp_enrollments WHERE guild_id = $1 AND user_id = $2",
                guild_id_i64,
                target_user_i64
            )
            .execute(&mut *tx)
            .await,
            _ => sqlx::query!(
                "DELETE FROM yubikey_enrollments WHERE guild_id = $1 AND user_id = $2",
                guild_id_i64,
                target_user_i64
            )
            .execute(&mut *tx)
            .await,
        };
        if let Err(e) = delete_result {
            tracing::error!(error = ?e, "failed to delete old factor during regenerate approval");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    if let Err(e) = tx.commit().await {
        tracing::error!(error = ?e, "failed to commit enrollment approval transaction");
        return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
    }

    reply_ephemeral(
        ctx,
        cmd,
        &format!("Approved {factor} enrollment for <@{target_user}> — they have {window_minutes} minutes to complete it via /enroll start."),
    )
    .await;

    let embed = CreateEmbed::new()
        .title("Enrollment approved")
        .description(format!(
            "<@{}> approved a {factor} {action} for <@{target_user}>, window: {window_minutes} min",
            cmd.user.id
        ))
        .color(0x5865F2);
    let _ = crate::logging::log(pool, &ctx.http, guild_id_i64, crate::logging::LogTier::Info, embed).await;
}

async fn determine_regenerate_or_add(
    pool: &PgPool,
    guild_id_i64: i64,
    user_id_i64: i64,
    factor: &str,
) -> Result<String, sqlx::Error> {
    let has_verified = match factor {
        "totp" => sqlx::query!(
            "SELECT 1 AS present FROM totp_enrollments WHERE guild_id = $1 AND user_id = $2 AND verified = true",
            guild_id_i64,
            user_id_i64
        )
        .fetch_optional(pool)
        .await?
        .is_some(),
        _ => sqlx::query!(
            "SELECT 1 AS present FROM yubikey_enrollments WHERE guild_id = $1 AND user_id = $2 AND verified = true",
            guild_id_i64,
            user_id_i64
        )
        .fetch_optional(pool)
        .await?
        .is_some(),
    };
    Ok(if has_verified { "regenerate" } else { "add" }.to_string())
}
