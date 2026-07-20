use crate::auth;
use crate::crypto::{backup_codes, encryption, totp};
use crate::enrollment::{self, EnrollmentDecision};
use crate::settings;
use serenity::all::{
    ButtonStyle, CommandInteraction, ComponentInteraction, Context, CreateActionRow, CreateAttachment,
    CreateButton, CreateCommand, CreateEmbed, CreateInputText, CreateInteractionResponse,
    CreateInteractionResponseFollowup, CreateInteractionResponseMessage, CreateModal, InputTextStyle,
    ModalInteraction,
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

    // Bot admins self-serve entirely (Task 5/6 design): the admin regen
    // cooldown is the ONLY rate-limit on them regenerating an existing
    // factor, and that cooldown is only consulted by evaluate_gate's
    // SelfServiceRegenerate path. Approving a bot admin here would insert an
    // already-'approved' request and (for regenerate) delete their existing
    // verified factor outright, which then makes evaluate_gate see no
    // verified factor and return SelfServiceAdd — bypassing the cooldown
    // entirely. Block on the target (not just the caller) before any DB
    // writes so neither self-approval nor cross-admin-reset can happen.
    match auth::is_bot_admin(pool, guild_id_i64, target_user_i64).await {
        Ok(true) => {
            return reply_ephemeral(
                ctx,
                cmd,
                "Bot admins don't need approval — they can enroll directly via /enroll start.",
            )
            .await;
        }
        Ok(false) => {}
        Err(e) => {
            tracing::error!(error = ?e, "failed to check target's bot admin status");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

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

pub async fn handle_component(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    comp: &ComponentInteraction,
) {
    match comp.data.custom_id.as_str() {
        "enroll_totp" => handle_totp_button(ctx, pool, encryption_key, comp, false).await,
        "totp_verify_button" | "totp_verify_button_then_yubikey" => {
            handle_totp_verify_button(ctx, comp).await
        }
        "enroll_yubikey" => handle_yubikey_button(ctx, pool, comp).await,
        "enroll_both" => handle_totp_button(ctx, pool, encryption_key, comp, true).await,
        _ => {}
    }
}

async fn reply_component_ephemeral(ctx: &Context, comp: &ComponentInteraction, content: &str) {
    let msg = serenity::all::CreateInteractionResponseMessage::new()
        .content(content)
        .ephemeral(true);
    let _ = comp
        .create_response(&ctx.http, serenity::all::CreateInteractionResponse::Message(msg))
        .await;
}

/// Looks up everything `decide_enrollment_action` needs for one factor and
/// evaluates it. `factor` is "totp" or "yubikey".
async fn evaluate_gate(
    pool: &PgPool,
    guild_id_i64: i64,
    user_id_i64: i64,
    factor: &str,
) -> Result<EnrollmentDecision, sqlx::Error> {
    let is_admin = auth::is_bot_admin(pool, guild_id_i64, user_id_i64).await?;

    let (has_verified_factor, enrolled_at): (bool, Option<chrono::DateTime<chrono::Utc>>) = if factor == "totp" {
        let row = sqlx::query!(
            "SELECT enrolled_at FROM totp_enrollments WHERE guild_id = $1 AND user_id = $2 AND verified = true",
            guild_id_i64,
            user_id_i64
        )
        .fetch_optional(pool)
        .await?;
        (row.is_some(), row.map(|r| r.enrolled_at))
    } else {
        let row = sqlx::query!(
            "SELECT enrolled_at FROM yubikey_enrollments WHERE guild_id = $1 AND user_id = $2 AND verified = true",
            guild_id_i64,
            user_id_i64
        )
        .fetch_optional(pool)
        .await?;
        (row.is_some(), row.map(|r| r.enrolled_at))
    };

    let cooldown_ok = if let Some(enrolled_at) = enrolled_at {
        let cooldown_minutes = settings::get_int_setting(
            pool,
            guild_id_i64,
            settings::ADMIN_REGEN_COOLDOWN_MINUTES_KEY,
            settings::ADMIN_REGEN_COOLDOWN_MINUTES_DEFAULT,
        )
        .await?;
        enrollment::cooldown_elapsed(enrolled_at, chrono::Utc::now(), cooldown_minutes)
    } else {
        true
    };

    let has_approved_request = sqlx::query!(
        "SELECT 1 AS present FROM enrollment_requests
         WHERE guild_id = $1 AND user_id = $2 AND factor_type = $3
           AND status = 'approved' AND window_expires_at > now()",
        guild_id_i64,
        user_id_i64,
        factor
    )
    .fetch_optional(pool)
    .await?
    .is_some();

    Ok(enrollment::decide_enrollment_action(
        is_admin,
        has_verified_factor,
        cooldown_ok,
        has_approved_request,
    ))
}

async fn handle_totp_button(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    comp: &ComponentInteraction,
    then_yubikey: bool,
) {
    let Some(guild_id) = comp.guild_id else {
        return reply_component_ephemeral(ctx, comp, "This only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = comp.user.id.get() as i64;

    let decision = match evaluate_gate(pool, guild_id_i64, user_id_i64, "totp").await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = ?e, "failed to evaluate enrollment gate");
            return reply_component_ephemeral(ctx, comp, "Something went wrong. Try again later.").await;
        }
    };

    match decision {
        EnrollmentDecision::CooldownNotElapsed => {
            return reply_component_ephemeral(
                ctx,
                comp,
                "You've regenerated this factor too recently — try again later.",
            )
            .await;
        }
        EnrollmentDecision::NeedsApproval => {
            let _ = sqlx::query!(
                "INSERT INTO enrollment_requests (guild_id, user_id, factor_type, action)
                 VALUES ($1, $2, 'totp', 'add')",
                guild_id_i64,
                user_id_i64
            )
            .execute(pool)
            .await;
            return reply_component_ephemeral(
                ctx,
                comp,
                "A bot admin needs to approve this before you can enroll TOTP. Ask one to run /enroll approve for you.",
            )
            .await;
        }
        EnrollmentDecision::SelfServiceRegenerate | EnrollmentDecision::ApprovedRegenerate => {
            let _ = sqlx::query!(
                "DELETE FROM totp_enrollments WHERE guild_id = $1 AND user_id = $2",
                guild_id_i64,
                user_id_i64
            )
            .execute(pool)
            .await;
        }
        EnrollmentDecision::SelfServiceAdd | EnrollmentDecision::ApprovedAdd => {}
    }

    let secret_bytes = totp::generate_secret_bytes();
    let account_name = comp.user.id.to_string();
    let totp_instance = totp::build_totp(secret_bytes, account_name);
    let base32 = totp::base32_secret(&totp_instance);
    let png = match totp::provisioning_qr_png(&totp_instance) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(error = %e, "failed to generate QR PNG");
            return reply_component_ephemeral(ctx, comp, "Something went wrong. Try again later.").await;
        }
    };

    // Encrypt the base32 form, not the raw secret bytes: generate_secret_bytes()
    // returns random bytes with no guarantee of being valid UTF-8 (per its own
    // doc comment in Plan 1), so a lossy string conversion would silently
    // corrupt the secret and break verification forever. Base32 is always
    // plain ASCII, round-trips losslessly, and totp-rs already provides the
    // decoder via Secret::Encoded(..).to_bytes() (Task 4's Foundation spike
    // verified this exact Secret::Encoded constructor compiles and works).
    let encrypted = match encryption::encrypt(encryption_key, &base32) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(error = ?e, "failed to encrypt TOTP secret");
            return reply_component_ephemeral(ctx, comp, "Something went wrong. Try again later.").await;
        }
    };

    if let Err(e) = sqlx::query!(
        "INSERT INTO totp_enrollments (guild_id, user_id, totp_secret_encrypted, verified)
         VALUES ($1, $2, $3, false)
         ON CONFLICT (guild_id, user_id) DO UPDATE SET totp_secret_encrypted = EXCLUDED.totp_secret_encrypted, verified = false, enrolled_at = now()",
        guild_id_i64,
        user_id_i64,
        encrypted
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = ?e, "failed to store TOTP secret");
        return reply_component_ephemeral(ctx, comp, "Something went wrong. Try again later.").await;
    }

    let attachment = CreateAttachment::bytes(png, "totp-qr.png");
    let embed = serenity::all::CreateEmbed::new()
        .title("Scan this QR code")
        .description(format!("Or enter manually: `{base32}`"))
        .attachment("totp-qr.png")
        .color(0x5865F2);
    let verify_custom_id = if then_yubikey {
        "totp_verify_button_then_yubikey"
    } else {
        "totp_verify_button"
    };
    let button = CreateActionRow::Buttons(vec![serenity::all::CreateButton::new(verify_custom_id)
        .label("I've added it — verify")
        .style(serenity::all::ButtonStyle::Primary)]);
    let msg = serenity::all::CreateInteractionResponseMessage::new()
        .embed(embed)
        .add_file(attachment)
        .components(vec![button])
        .ephemeral(true);
    let _ = comp
        .create_response(&ctx.http, serenity::all::CreateInteractionResponse::Message(msg))
        .await;
}

async fn handle_totp_verify_button(ctx: &Context, comp: &ComponentInteraction) {
    let then_yubikey = comp.data.custom_id == "totp_verify_button_then_yubikey";
    let modal_id = if then_yubikey {
        "totp_verify_modal_then_yubikey"
    } else {
        "totp_verify_modal"
    };
    let modal = CreateModal::new(modal_id, "Verify TOTP").components(vec![CreateActionRow::InputText(
        CreateInputText::new(InputTextStyle::Short, "Code", "totp_code")
            .placeholder("6-digit code")
            .required(true),
    )]);
    if let Err(e) = comp
        .create_response(&ctx.http, serenity::all::CreateInteractionResponse::Modal(modal))
        .await
    {
        tracing::error!(error = ?e, "failed to open TOTP verify modal");
    }
}

async fn handle_yubikey_button(ctx: &Context, pool: &PgPool, comp: &ComponentInteraction) {
    let Some(guild_id) = comp.guild_id else {
        return reply_component_ephemeral(ctx, comp, "This only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = comp.user.id.get() as i64;

    let decision = match evaluate_gate(pool, guild_id_i64, user_id_i64, "yubikey").await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = ?e, "failed to evaluate enrollment gate");
            return reply_component_ephemeral(ctx, comp, "Something went wrong. Try again later.").await;
        }
    };

    match decision {
        EnrollmentDecision::CooldownNotElapsed => {
            return reply_component_ephemeral(
                ctx,
                comp,
                "You've regenerated this factor too recently — try again later.",
            )
            .await;
        }
        EnrollmentDecision::NeedsApproval => {
            let _ = sqlx::query!(
                "INSERT INTO enrollment_requests (guild_id, user_id, factor_type, action)
                 VALUES ($1, $2, 'yubikey', 'add')",
                guild_id_i64,
                user_id_i64
            )
            .execute(pool)
            .await;
            return reply_component_ephemeral(
                ctx,
                comp,
                "A bot admin needs to approve this before you can enroll a YubiKey. Ask one to run /enroll approve for you.",
            )
            .await;
        }
        EnrollmentDecision::SelfServiceRegenerate | EnrollmentDecision::ApprovedRegenerate => {
            let _ = sqlx::query!(
                "DELETE FROM yubikey_enrollments WHERE guild_id = $1 AND user_id = $2",
                guild_id_i64,
                user_id_i64
            )
            .execute(pool)
            .await;
        }
        EnrollmentDecision::SelfServiceAdd | EnrollmentDecision::ApprovedAdd => {}
    }

    let modal = CreateModal::new("yubikey_enroll_modal", "Enroll YubiKey").components(vec![
        CreateActionRow::InputText(
            CreateInputText::new(InputTextStyle::Short, "Touch your YubiKey and paste the OTP", "yubikey_otp")
                .placeholder("cccc...")
                .required(true),
        ),
    ]);
    if let Err(e) = comp
        .create_response(&ctx.http, serenity::all::CreateInteractionResponse::Modal(modal))
        .await
    {
        tracing::error!(error = ?e, "failed to open YubiKey enroll modal");
    }
}

pub async fn handle_modal(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &crate::yubico::YubicoClient,
    modal: &ModalInteraction,
) {
    if modal.data.custom_id == "totp_verify_modal" || modal.data.custom_id == "totp_verify_modal_then_yubikey" {
        handle_totp_verify_modal(ctx, pool, encryption_key, modal).await;
    }
    if modal.data.custom_id == "yubikey_enroll_modal" {
        handle_yubikey_modal(ctx, pool, yubico, modal).await;
    }
}

async fn reply_modal_ephemeral(ctx: &Context, modal: &ModalInteraction, content: &str) {
    let msg = serenity::all::CreateInteractionResponseMessage::new()
        .content(content)
        .ephemeral(true);
    let _ = modal
        .create_response(&ctx.http, serenity::all::CreateInteractionResponse::Message(msg))
        .await;
}

async fn handle_totp_verify_modal(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    modal: &ModalInteraction,
) {
    let Some(guild_id) = modal.guild_id else {
        return reply_modal_ephemeral(ctx, modal, "This only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = modal.user.id.get() as i64;

    let submitted_code = modal
        .data
        .components
        .iter()
        .flat_map(|row| row.components.iter())
        .find_map(|c| {
            if let serenity::all::ActionRowComponent::InputText(input) = c {
                input.value.clone()
            } else {
                None
            }
        })
        .unwrap_or_default();

    let row = match sqlx::query!(
        "SELECT totp_secret_encrypted FROM totp_enrollments WHERE guild_id = $1 AND user_id = $2",
        guild_id_i64,
        user_id_i64
    )
    .fetch_optional(pool)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return reply_modal_ephemeral(ctx, modal, "No pending TOTP enrollment found. Run /enroll start again.").await,
        Err(e) => {
            tracing::error!(error = ?e, "failed to load TOTP secret");
            return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
        }
    };

    let base32_secret = match encryption::decrypt(encryption_key, &row.totp_secret_encrypted) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = ?e, "failed to decrypt TOTP secret");
            return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
        }
    };
    // Reverse of the encrypt side: the stored value is the base32 form, so
    // decode it back to raw secret bytes via totp-rs's own Secret::Encoded
    // before calling verify_code (which expects raw bytes).
    let secret_bytes = match totp_rs::Secret::Encoded(base32_secret).to_bytes() {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = ?e, "failed to decode stored base32 TOTP secret");
            return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
        }
    };

    let now_unix = chrono::Utc::now().timestamp() as u64;
    let account_name = modal.user.id.to_string();
    let matched_step = totp::verify_code(&secret_bytes, &account_name, &submitted_code, now_unix);

    if matched_step.is_none() {
        return reply_modal_ephemeral(ctx, modal, "That code didn't match. Try again.").await;
    }

    if let Err(e) = sqlx::query!(
        "UPDATE totp_enrollments SET verified = true WHERE guild_id = $1 AND user_id = $2",
        guild_id_i64,
        user_id_i64
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = ?e, "failed to mark TOTP verified");
        return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
    }

    let _ = sqlx::query!(
        "UPDATE enrollment_requests SET status = 'fulfilled'
         WHERE guild_id = $1 AND user_id = $2 AND factor_type = 'totp' AND status = 'approved'",
        guild_id_i64,
        user_id_i64
    )
    .execute(pool)
    .await;

    let backup_codes_shown = issue_backup_codes_if_first_factor(pool, guild_id_i64, user_id_i64).await;

    let mut content = "TOTP verified and enrolled.".to_string();
    if let Some(codes) = backup_codes_shown {
        content.push_str("\n\nSave these one-time backup codes now — they won't be shown again:\n");
        content.push_str(&codes.join("\n"));
    }

    let then_yubikey = modal.data.custom_id == "totp_verify_modal_then_yubikey";
    if then_yubikey {
        content.push_str("\n\nNow enroll your YubiKey:");
        let button = CreateActionRow::Buttons(vec![serenity::all::CreateButton::new("enroll_yubikey")
            .label("Continue: Enroll YubiKey")
            .style(serenity::all::ButtonStyle::Primary)]);
        let msg = serenity::all::CreateInteractionResponseMessage::new()
            .content(content)
            .components(vec![button])
            .ephemeral(true);
        let _ = modal
            .create_response(&ctx.http, serenity::all::CreateInteractionResponse::Message(msg))
            .await;
    } else {
        reply_modal_ephemeral(ctx, modal, &content).await;
    }

    let embed = serenity::all::CreateEmbed::new()
        .title("TOTP enrolled")
        .description(format!("<@{}> enrolled/regenerated TOTP", modal.user.id))
        .color(0x57F287);
    let _ = crate::logging::log(pool, &ctx.http, guild_id_i64, crate::logging::LogTier::Info, embed).await;
}

async fn handle_yubikey_modal(
    ctx: &Context,
    pool: &PgPool,
    yubico: &crate::yubico::YubicoClient,
    modal: &ModalInteraction,
) {
    let Some(guild_id) = modal.guild_id else {
        return reply_modal_ephemeral(ctx, modal, "This only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = modal.user.id.get() as i64;

    let submitted_otp = modal
        .data
        .components
        .iter()
        .flat_map(|row| row.components.iter())
        .find_map(|c| {
            if let serenity::all::ActionRowComponent::InputText(input) = c {
                input.value.clone()
            } else {
                None
            }
        })
        .unwrap_or_default();

    let result = match yubico.verify_otp(&submitted_otp).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = ?e, "Yubico verification request failed");
            return reply_modal_ephemeral(ctx, modal, "Couldn't reach Yubico's verification service. Try again later.").await;
        }
    };

    if !result.valid {
        return reply_modal_ephemeral(ctx, modal, "That OTP didn't validate. Try again.").await;
    }

    if let Err(e) = sqlx::query!(
        "INSERT INTO yubikey_enrollments (guild_id, user_id, yubikey_public_id)
         VALUES ($1, $2, $3)
         ON CONFLICT (guild_id, user_id) DO UPDATE SET yubikey_public_id = EXCLUDED.yubikey_public_id, enrolled_at = now()",
        guild_id_i64,
        user_id_i64,
        result.public_id
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = ?e, "failed to store YubiKey enrollment");
        return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
    }

    let _ = sqlx::query!(
        "UPDATE enrollment_requests SET status = 'fulfilled'
         WHERE guild_id = $1 AND user_id = $2 AND factor_type = 'yubikey' AND status = 'approved'",
        guild_id_i64,
        user_id_i64
    )
    .execute(pool)
    .await;

    let backup_codes_shown = issue_backup_codes_if_first_factor(pool, guild_id_i64, user_id_i64).await;

    let mut content = "YubiKey verified and enrolled.".to_string();
    if let Some(codes) = backup_codes_shown {
        content.push_str("\n\nSave these one-time backup codes now — they won't be shown again:\n");
        content.push_str(&codes.join("\n"));
    }
    reply_modal_ephemeral(ctx, modal, &content).await;

    let embed = serenity::all::CreateEmbed::new()
        .title("YubiKey enrolled")
        .description(format!("<@{}> enrolled/regenerated a YubiKey", modal.user.id))
        .color(0x57F287);
    let _ = crate::logging::log(pool, &ctx.http, guild_id_i64, crate::logging::LogTier::Info, embed).await;
}

/// If this is the user's very first verified factor of any kind (checked
/// BEFORE this factor's own verification just landed), issues and returns
/// 10 backup codes. Returns None if they already had a verified factor.
async fn issue_backup_codes_if_first_factor(
    pool: &PgPool,
    guild_id_i64: i64,
    user_id_i64: i64,
) -> Option<Vec<String>> {
    let existing_backup_codes = sqlx::query!(
        "SELECT 1 AS present FROM backup_codes WHERE guild_id = $1 AND user_id = $2",
        guild_id_i64,
        user_id_i64
    )
    .fetch_optional(pool)
    .await
    .ok()?;
    if existing_backup_codes.is_some() {
        return None; // already issued once before
    }

    let codes = backup_codes::generate_codes(backup_codes::CODE_COUNT);
    for code in &codes {
        let hash = backup_codes::hash_code(code);
        let _ = sqlx::query!(
            "INSERT INTO backup_codes (guild_id, user_id, code_hash) VALUES ($1, $2, $3)",
            guild_id_i64,
            user_id_i64,
            hash
        )
        .execute(pool)
        .await;
    }
    Some(codes)
}
