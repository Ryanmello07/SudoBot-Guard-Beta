use crate::auth;
use crate::crypto::{backup_codes, encryption, totp};
use crate::elevation;
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
            )
            .add_sub_option(
                serenity::all::CreateCommandOption::new(
                    serenity::all::CommandOptionType::String,
                    "authcode",
                    "Your own TOTP or YubiKey code",
                )
                .required(true),
            ),
        )]
}

pub async fn handle(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &crate::yubico::YubicoClient,
    cmd: &CommandInteraction,
) {
    let Some(sub) = cmd.data.options.first() else {
        return;
    };
    match sub.name.as_str() {
        "start" => handle_start(ctx, pool, cmd).await,
        "approve" => handle_approve(ctx, pool, encryption_key, yubico, cmd, sub).await,
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
/// (handle_approve defers so verifying the approver's authcode — a possible
/// live Yubico network call — stays under Discord's 3-second ack window).
async fn reply_followup(ctx: &Context, cmd: &CommandInteraction, content: &str) {
    let msg = CreateInteractionResponseFollowup::new()
        .content(content)
        .ephemeral(true);
    let _ = cmd.create_followup(&ctx.http, msg).await;
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
    encryption_key: &[u8; 32],
    yubico: &crate::yubico::YubicoClient,
    cmd: &CommandInteraction,
    sub: &serenity::all::CommandDataOption,
) {
    let Some(guild_id) = cmd.guild_id else {
        return reply_ephemeral(ctx, cmd, "This command only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let approver_id_i64 = cmd.user.id.get() as i64;

    // Defer before verifying the approver's authcode: verify_code can make a
    // live Yubico network call and risk Discord's 3-second ack window. Every
    // reply from here on must go through `reply_followup`.
    if let Err(e) = cmd.defer_ephemeral(&ctx.http).await {
        tracing::error!(error = ?e, "failed to defer enroll approve interaction");
        return;
    }

    match auth::is_bot_admin(pool, guild_id_i64, approver_id_i64).await {
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

    let serenity::all::CommandDataOptionValue::SubCommand(opts) = &sub.value else {
        return;
    };
    let mut target_user = None;
    let mut factor = None;
    let mut window_str = None;
    let mut authcode = None;
    for opt in opts {
        match (opt.name.as_str(), &opt.value) {
            ("user", serenity::all::CommandDataOptionValue::User(id)) => target_user = Some(*id),
            ("factor", serenity::all::CommandDataOptionValue::String(s)) => factor = Some(s.clone()),
            ("window", serenity::all::CommandDataOptionValue::String(s)) => window_str = Some(s.clone()),
            ("authcode", serenity::all::CommandDataOptionValue::String(s)) => authcode = Some(s.clone()),
            _ => {}
        }
    }
    let (Some(target_user), Some(factor), Some(window_str), Some(authcode)) =
        (target_user, factor, window_str, authcode)
    else {
        return reply_followup(ctx, cmd, "Missing required options.").await;
    };

    // Verify the approving admin's OWN 2FA code before authorizing this action
    // over another staffer. Additive to the is_bot_admin check above.
    match elevation::verify_code(pool, guild_id_i64, approver_id_i64, &authcode, encryption_key, yubico).await {
        Ok(true) => {}
        Ok(false) => return reply_followup(ctx, cmd, "That code didn't verify.").await,
        Err(e) => {
            tracing::error!(error = ?e, "enroll: error verifying approver authcode");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    let window_minutes = match crate::enrollment::parse_window_minutes(&window_str) {
        Ok(m) => m,
        Err(msg) => return reply_followup(ctx, cmd, &msg).await,
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
            return reply_followup(
                ctx,
                cmd,
                "Bot admins don't need approval — they can enroll directly via /enroll start.",
            )
            .await;
        }
        Ok(false) => {}
        Err(e) => {
            tracing::error!(error = ?e, "failed to check target's bot admin status");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    let action = match determine_regenerate_or_add(pool, guild_id_i64, target_user_i64, &factor).await {
        Ok(action) => action,
        Err(e) => {
            tracing::error!(error = ?e, "failed to determine add-vs-regenerate for enrollment approval");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    };

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(error = ?e, "failed to start transaction for enrollment approval");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
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
        return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
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
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    if let Err(e) = tx.commit().await {
        tracing::error!(error = ?e, "failed to commit enrollment approval transaction");
        return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
    }

    reply_followup(
        ctx,
        cmd,
        &format!("Approved {factor} enrollment for <@{target_user}> — they have {window_minutes} minutes to complete it via /enroll start."),
    )
    .await;

    let embed = CreateEmbed::new()
        .title("Enrollment Approved")
        .field("Staffer", crate::logging::user_ref(target_user.get() as i64), true)
        .field("Approved By", crate::logging::user_ref(cmd.user.id.get() as i64), true)
        .field(
            "Details",
            format!("Factor: {factor}\nAction: {action}\nWindow: {window_minutes} min"),
            false,
        )
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
        // Post-regenerate continuation: the backup code was already verified and
        // consumed and the old YubiKey factor deleted, so open the enroll modal
        // directly rather than re-running the gate (which would now see no
        // verified factor and needlessly reprompt).
        "yubikey_enroll_after_regen" => {
            if let Err(e) = comp
                .create_response(&ctx.http, serenity::all::CreateInteractionResponse::Modal(yubikey_enroll_modal()))
                .await
            {
                tracing::error!(error = ?e, "failed to open YubiKey enroll modal after regen");
            }
        }
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

/// Shown when a self-service regenerate is refused because the submitted
/// backup code didn't match any unused code (wrong code, or none left). Mirrors
/// the `NeedsApproval` tone: the old factor is left fully intact (fail closed).
const REGEN_BACKUP_CODE_FAILED_MSG: &str =
    "That backup code didn't match, or you have no unused backup codes left. Your existing factor is unchanged — ask a bot admin to run /enroll approve for you instead.";

/// Pulls the single text value a user typed into a one-field modal.
fn first_modal_input(modal: &ModalInteraction) -> String {
    modal
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
        .unwrap_or_default()
}

/// Opens a modal prompting for a backup code. Used to gate a self-service
/// regenerate behind proof of possession before the existing factor is touched.
async fn open_backup_code_modal(ctx: &Context, comp: &ComponentInteraction, modal_id: &str, title: &str) {
    let modal = CreateModal::new(modal_id, title).components(vec![CreateActionRow::InputText(
        CreateInputText::new(InputTextStyle::Short, "Backup code", "backup_code")
            .placeholder("10-character backup code")
            .required(true),
    )]);
    if let Err(e) = comp
        .create_response(&ctx.http, serenity::all::CreateInteractionResponse::Modal(modal))
        .await
    {
        tracing::error!(error = ?e, "failed to open backup code modal");
    }
}

/// Finds the id of the user's first unused backup-code row whose hash the
/// submitted `code` verifies against, or `None` if none match. Does NOT consume
/// it — consumption happens later, guarded, inside the regenerate transaction.
async fn find_unused_matching_backup_code(
    pool: &PgPool,
    guild_id_i64: i64,
    user_id_i64: i64,
    code: &str,
) -> Result<Option<i64>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT id, code_hash FROM backup_codes WHERE guild_id = $1 AND user_id = $2 AND used_at IS NULL",
        guild_id_i64,
        user_id_i64
    )
    .fetch_all(pool)
    .await?;
    let hashes: Vec<String> = rows.iter().map(|r| r.code_hash.clone()).collect();
    Ok(backup_codes::find_matching_code_index(code, &hashes).map(|i| rows[i].id))
}

/// Generates a fresh TOTP secret and returns `(encrypted_secret, base32, qr_png)`.
/// Pure of any DB writes so callers can store it inside their own transaction.
fn generate_totp_material(
    encryption_key: &[u8; 32],
    account_user_id: serenity::all::UserId,
) -> Result<(Vec<u8>, String, Vec<u8>), ()> {
    let secret_bytes = totp::generate_secret_bytes();
    let account_name = account_user_id.to_string();
    let totp_instance = totp::build_totp(secret_bytes, account_name);
    let base32 = totp::base32_secret(&totp_instance);
    let png = match totp::provisioning_qr_png(&totp_instance) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(error = %e, "failed to generate QR PNG");
            return Err(());
        }
    };
    // Encrypt the base32 form, not the raw secret bytes: generate_secret_bytes()
    // returns random bytes with no guarantee of being valid UTF-8, so a lossy
    // string conversion would silently corrupt the secret. Base32 is always
    // plain ASCII and round-trips losslessly.
    let encrypted = match encryption::encrypt(encryption_key, &base32) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(error = ?e, "failed to encrypt TOTP secret");
            return Err(());
        }
    };
    Ok((encrypted, base32, png))
}

/// Builds the "scan this QR" response message (embed + QR attachment + verify
/// button). `then_yubikey` selects the verify button that chains into YubiKey.
fn build_totp_qr_response(base32: &str, png: Vec<u8>, then_yubikey: bool) -> CreateInteractionResponseMessage {
    let attachment = CreateAttachment::bytes(png, "totp-qr.png");
    let embed = CreateEmbed::new()
        .title("Scan this QR code")
        .description(format!("Or enter manually: `{base32}`"))
        .attachment("totp-qr.png")
        .color(0x5865F2);
    let verify_custom_id = if then_yubikey {
        "totp_verify_button_then_yubikey"
    } else {
        "totp_verify_button"
    };
    let button = CreateActionRow::Buttons(vec![CreateButton::new(verify_custom_id)
        .label("I've added it — verify")
        .style(ButtonStyle::Primary)]);
    CreateInteractionResponseMessage::new()
        .embed(embed)
        .add_file(attachment)
        .components(vec![button])
        .ephemeral(true)
}

/// The YubiKey enrollment modal (touch + paste OTP). Shared by the first-time
/// enroll path and the post-regenerate continuation button.
fn yubikey_enroll_modal() -> CreateModal {
    CreateModal::new("yubikey_enroll_modal", "Enroll YubiKey").components(vec![CreateActionRow::InputText(
        CreateInputText::new(InputTextStyle::Short, "Touch your YubiKey and paste the OTP", "yubikey_otp")
            .placeholder("cccc...")
            .required(true),
    )])
}

/// Logs the `LogTier::Alert` "factor regenerating" embed emitted when an
/// existing factor is deleted to begin regeneration.
async fn log_factor_regenerating(ctx: &Context, pool: &PgPool, guild_id_i64: i64, user_id: u64, factor_label: &str) {
    let embed = CreateEmbed::new()
        .title(format!("{factor_label} Factor Regenerating"))
        .field("User", crate::logging::user_ref(user_id as i64), true)
        .field(
            "Detail",
            format!("The existing {factor_label} factor was deleted to begin regeneration."),
            false,
        )
        .color(0x5865F2);
    let _ = crate::logging::log(pool, &ctx.http, guild_id_i64, crate::logging::LogTier::Alert, embed).await;
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

    let has_verified_factor: bool = if factor == "totp" {
        sqlx::query!(
            "SELECT 1 AS present FROM totp_enrollments WHERE guild_id = $1 AND user_id = $2 AND verified = true",
            guild_id_i64,
            user_id_i64
        )
        .fetch_optional(pool)
        .await?
        .is_some()
    } else {
        sqlx::query!(
            "SELECT 1 AS present FROM yubikey_enrollments WHERE guild_id = $1 AND user_id = $2 AND verified = true",
            guild_id_i64,
            user_id_i64
        )
        .fetch_optional(pool)
        .await?
        .is_some()
    };

    let cooldown_ok = if has_verified_factor && is_admin {
        let cooldown_minutes = settings::get_int_setting(
            pool,
            guild_id_i64,
            settings::ADMIN_REGEN_COOLDOWN_MINUTES_KEY,
            settings::ADMIN_REGEN_COOLDOWN_MINUTES_DEFAULT,
        )
        .await?;
        let completion_window_minutes = settings::get_int_setting(
            pool,
            guild_id_i64,
            settings::ADMIN_REGEN_COMPLETION_WINDOW_MINUTES_KEY,
            settings::ADMIN_REGEN_COMPLETION_WINDOW_MINUTES_DEFAULT,
        )
        .await?;

        // Anchor the admin's own regenerate cooldown to when they first
        // requested it, and only while the request is still within its
        // completion window (cooldown + completion_window from the request
        // time) -- once that window passes with no completion, the request
        // is treated as expired and a fresh click starts an entirely new
        // cooldown, so an approved-but-abandoned request doesn't stay valid
        // forever.
        let existing_request = sqlx::query!(
            "SELECT requested_at FROM enrollment_requests
             WHERE guild_id = $1 AND user_id = $2 AND factor_type = $3
               AND action = 'regenerate' AND status = 'approved'
               AND window_expires_at > now()
             ORDER BY requested_at DESC LIMIT 1",
            guild_id_i64,
            user_id_i64,
            factor
        )
        .fetch_optional(pool)
        .await?;

        match existing_request {
            Some(row) => enrollment::cooldown_elapsed(row.requested_at, chrono::Utc::now(), cooldown_minutes),
            None => {
                // Any earlier request for this (guild, user, factor,
                // regenerate) that's now past its own window is stale --
                // mark it explicitly expired rather than leaving it looking
                // like a live 'approved' row forever.
                sqlx::query!(
                    "UPDATE enrollment_requests SET status = 'expired'
                     WHERE guild_id = $1 AND user_id = $2 AND factor_type = $3
                       AND action = 'regenerate' AND status = 'approved'
                       AND window_expires_at <= now()",
                    guild_id_i64,
                    user_id_i64,
                    factor
                )
                .execute(pool)
                .await?;

                let total_minutes = cooldown_minutes + completion_window_minutes;
                sqlx::query!(
                    "INSERT INTO enrollment_requests
                        (guild_id, user_id, factor_type, action, status, approved_by, approved_at, window_minutes, window_expires_at)
                     VALUES ($1, $2, $3, 'regenerate', 'approved', $2, now(), $4, now() + make_interval(mins => $5))",
                    guild_id_i64,
                    user_id_i64,
                    factor,
                    completion_window_minutes as i32,
                    total_minutes as i32
                )
                .execute(pool)
                .await?;
                false
            }
        }
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

/// Builds the reply for `EnrollmentDecision::CooldownNotElapsed`: looks up
/// the admin's own auto-approved regenerate request (recorded the first time
/// they clicked) and tells them roughly when the cooldown will have elapsed.
async fn cooldown_wait_message(pool: &PgPool, guild_id_i64: i64, user_id_i64: i64, factor: &str) -> String {
    match sqlx::query!(
        "SELECT requested_at FROM enrollment_requests
         WHERE guild_id = $1 AND user_id = $2 AND factor_type = $3
           AND action = 'regenerate' AND status = 'approved'
           AND window_expires_at > now()
         ORDER BY requested_at DESC LIMIT 1",
        guild_id_i64,
        user_id_i64,
        factor
    )
    .fetch_optional(pool)
    .await
    {
        Ok(Some(row)) => {
            let cooldown_minutes = settings::get_int_setting(
                pool,
                guild_id_i64,
                settings::ADMIN_REGEN_COOLDOWN_MINUTES_KEY,
                settings::ADMIN_REGEN_COOLDOWN_MINUTES_DEFAULT,
            )
            .await
            .unwrap_or(settings::ADMIN_REGEN_COOLDOWN_MINUTES_DEFAULT);
            let available_at = row.requested_at + chrono::Duration::minutes(cooldown_minutes);
            format!(
                "You requested a regenerate for this factor — you can complete it <t:{}:R>.",
                available_at.timestamp()
            )
        }
        _ => "You've regenerated this factor too recently — try again later.".to_string(),
    }
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
                &cooldown_wait_message(pool, guild_id_i64, user_id_i64, "totp").await,
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
        EnrollmentDecision::SelfServiceRegenerate => {
            // Fail closed: an admin self-regenerate needs proof of possessing
            // the CURRENT factor. Prompt for a backup code via modal and do
            // NOT touch the existing factor here — the delete + regeneration
            // happens only after the code verifies, in
            // handle_totp_regen_backup_modal. (ApprovedRegenerate, below, is a
            // separate already-stronger path: an admin explicitly approved it.)
            let modal_id = if then_yubikey {
                "totp_regen_backup_modal_then_yubikey"
            } else {
                "totp_regen_backup_modal"
            };
            return open_backup_code_modal(ctx, comp, modal_id, "Regenerate TOTP").await;
        }
        EnrollmentDecision::ApprovedRegenerate => {
            let _ = sqlx::query!(
                "DELETE FROM totp_enrollments WHERE guild_id = $1 AND user_id = $2",
                guild_id_i64,
                user_id_i64
            )
            .execute(pool)
            .await;
            log_factor_regenerating(ctx, pool, guild_id_i64, comp.user.id.get(), "TOTP").await;
        }
        EnrollmentDecision::SelfServiceAdd | EnrollmentDecision::ApprovedAdd => {}
    }

    let (encrypted, base32, png) = match generate_totp_material(encryption_key, comp.user.id) {
        Ok(material) => material,
        Err(()) => return reply_component_ephemeral(ctx, comp, "Something went wrong. Try again later.").await,
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

    let msg = build_totp_qr_response(&base32, png, then_yubikey);
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
                &cooldown_wait_message(pool, guild_id_i64, user_id_i64, "yubikey").await,
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
        EnrollmentDecision::SelfServiceRegenerate => {
            // Fail closed: gate the admin self-regenerate behind a backup code.
            // Since a modal-submit cannot open another modal, the backup-code
            // modal can't chain straight into `yubikey_enroll_modal`; instead
            // handle_yubikey_regen_backup_modal verifies + consumes the code,
            // deletes the old factor, and replies with a button that opens the
            // enroll modal. (ApprovedRegenerate, below, stays as-is.)
            return open_backup_code_modal(ctx, comp, "yubikey_regen_backup_modal", "Regenerate YubiKey").await;
        }
        EnrollmentDecision::ApprovedRegenerate => {
            let _ = sqlx::query!(
                "DELETE FROM yubikey_enrollments WHERE guild_id = $1 AND user_id = $2",
                guild_id_i64,
                user_id_i64
            )
            .execute(pool)
            .await;
            log_factor_regenerating(ctx, pool, guild_id_i64, comp.user.id.get(), "YubiKey").await;
        }
        EnrollmentDecision::SelfServiceAdd | EnrollmentDecision::ApprovedAdd => {}
    }

    if let Err(e) = comp
        .create_response(&ctx.http, serenity::all::CreateInteractionResponse::Modal(yubikey_enroll_modal()))
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
    if modal.data.custom_id == "totp_regen_backup_modal" || modal.data.custom_id == "totp_regen_backup_modal_then_yubikey" {
        handle_totp_regen_backup_modal(ctx, pool, encryption_key, modal).await;
    }
    if modal.data.custom_id == "yubikey_regen_backup_modal" {
        handle_yubikey_regen_backup_modal(ctx, pool, modal).await;
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

    let submitted_code = first_modal_input(modal);

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
        .title("TOTP Enrolled")
        .field("User", crate::logging::user_ref(modal.user.id.get() as i64), true)
        .field("Factor", "TOTP enrolled/regenerated", true)
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

    let submitted_otp = first_modal_input(modal);

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
        .title("YubiKey Enrolled")
        .field("User", crate::logging::user_ref(modal.user.id.get() as i64), true)
        .field("Factor", "YubiKey enrolled/regenerated", true)
        .color(0x57F287);
    let _ = crate::logging::log(pool, &ctx.http, guild_id_i64, crate::logging::LogTier::Info, embed).await;
}

/// Self-service TOTP regenerate, gated on a backup code. Called only from the
/// `totp_regen_backup_modal[_then_yubikey]` submit. Order (requirement #5):
/// verify the code, then consume it, then delete the old factor — a wrong code
/// never touches the existing factor.
async fn handle_totp_regen_backup_modal(
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
    let then_yubikey = modal.data.custom_id == "totp_regen_backup_modal_then_yubikey";
    let submitted = first_modal_input(modal);

    // Verify possession BEFORE anything is deleted. Fail closed on a wrong code
    // or no unused codes left — the existing factor stays fully intact.
    let matched_id = match find_unused_matching_backup_code(pool, guild_id_i64, user_id_i64, &submitted).await {
        Ok(Some(id)) => id,
        Ok(None) => return reply_modal_ephemeral(ctx, modal, REGEN_BACKUP_CODE_FAILED_MSG).await,
        Err(e) => {
            tracing::error!(error = ?e, "failed to look up backup codes for totp regenerate");
            return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
        }
    };

    // Build the new secret up front (pure, no DB) so the transaction below only
    // spans DB writes.
    let (encrypted, base32, png) = match generate_totp_material(encryption_key, modal.user.id) {
        Ok(material) => material,
        Err(()) => return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await,
    };

    // consume → delete old → store new, all in one transaction (matching
    // handle_approve): a failure partway can't consume a code without
    // regenerating, or delete a factor without recording the consumption.
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(error = ?e, "failed to start transaction for totp self-regenerate");
            return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
        }
    };

    // Guarded by `used_at IS NULL` so a concurrent submit can't double-spend the
    // same code; 0 rows affected means it was already used — fail closed.
    match sqlx::query!(
        "UPDATE backup_codes SET used_at = now() WHERE id = $1 AND used_at IS NULL",
        matched_id
    )
    .execute(&mut *tx)
    .await
    {
        Ok(r) if r.rows_affected() == 1 => {}
        Ok(_) => {
            let _ = tx.rollback().await;
            return reply_modal_ephemeral(ctx, modal, REGEN_BACKUP_CODE_FAILED_MSG).await;
        }
        Err(e) => {
            tracing::error!(error = ?e, "failed to consume backup code for totp regenerate");
            let _ = tx.rollback().await;
            return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
        }
    }

    if let Err(e) = sqlx::query!(
        "DELETE FROM totp_enrollments WHERE guild_id = $1 AND user_id = $2",
        guild_id_i64,
        user_id_i64
    )
    .execute(&mut *tx)
    .await
    {
        tracing::error!(error = ?e, "failed to delete old totp factor during self-regenerate");
        let _ = tx.rollback().await;
        return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
    }

    if let Err(e) = sqlx::query!(
        "INSERT INTO totp_enrollments (guild_id, user_id, totp_secret_encrypted, verified)
         VALUES ($1, $2, $3, false)
         ON CONFLICT (guild_id, user_id) DO UPDATE SET totp_secret_encrypted = EXCLUDED.totp_secret_encrypted, verified = false, enrolled_at = now()",
        guild_id_i64,
        user_id_i64,
        encrypted
    )
    .execute(&mut *tx)
    .await
    {
        tracing::error!(error = ?e, "failed to store new totp secret during self-regenerate");
        let _ = tx.rollback().await;
        return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
    }

    if let Err(e) = tx.commit().await {
        tracing::error!(error = ?e, "failed to commit totp self-regenerate transaction");
        return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
    }

    log_factor_regenerating(ctx, pool, guild_id_i64, modal.user.id.get(), "TOTP").await;

    // TOTP's next step is a QR message, which is a legal response to a modal
    // submit, so it chains directly here.
    let msg = build_totp_qr_response(&base32, png, then_yubikey);
    let _ = modal
        .create_response(&ctx.http, serenity::all::CreateInteractionResponse::Message(msg))
        .await;
}

/// Self-service YubiKey regenerate, gated on a backup code. Called only from the
/// `yubikey_regen_backup_modal` submit. Same verify→consume→delete order as the
/// TOTP path. Because a modal submit cannot open another modal, this replies
/// with a button that opens `yubikey_enroll_modal` rather than chaining into it.
async fn handle_yubikey_regen_backup_modal(ctx: &Context, pool: &PgPool, modal: &ModalInteraction) {
    let Some(guild_id) = modal.guild_id else {
        return reply_modal_ephemeral(ctx, modal, "This only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = modal.user.id.get() as i64;
    let submitted = first_modal_input(modal);

    let matched_id = match find_unused_matching_backup_code(pool, guild_id_i64, user_id_i64, &submitted).await {
        Ok(Some(id)) => id,
        Ok(None) => return reply_modal_ephemeral(ctx, modal, REGEN_BACKUP_CODE_FAILED_MSG).await,
        Err(e) => {
            tracing::error!(error = ?e, "failed to look up backup codes for yubikey regenerate");
            return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
        }
    };

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(error = ?e, "failed to start transaction for yubikey self-regenerate");
            return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
        }
    };

    match sqlx::query!(
        "UPDATE backup_codes SET used_at = now() WHERE id = $1 AND used_at IS NULL",
        matched_id
    )
    .execute(&mut *tx)
    .await
    {
        Ok(r) if r.rows_affected() == 1 => {}
        Ok(_) => {
            let _ = tx.rollback().await;
            return reply_modal_ephemeral(ctx, modal, REGEN_BACKUP_CODE_FAILED_MSG).await;
        }
        Err(e) => {
            tracing::error!(error = ?e, "failed to consume backup code for yubikey regenerate");
            let _ = tx.rollback().await;
            return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
        }
    }

    if let Err(e) = sqlx::query!(
        "DELETE FROM yubikey_enrollments WHERE guild_id = $1 AND user_id = $2",
        guild_id_i64,
        user_id_i64
    )
    .execute(&mut *tx)
    .await
    {
        tracing::error!(error = ?e, "failed to delete old yubikey factor during self-regenerate");
        let _ = tx.rollback().await;
        return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
    }

    if let Err(e) = tx.commit().await {
        tracing::error!(error = ?e, "failed to commit yubikey self-regenerate transaction");
        return reply_modal_ephemeral(ctx, modal, "Something went wrong. Try again later.").await;
    }

    log_factor_regenerating(ctx, pool, guild_id_i64, modal.user.id.get(), "YubiKey").await;

    let button = CreateActionRow::Buttons(vec![CreateButton::new("yubikey_enroll_after_regen")
        .label("Continue: Enroll YubiKey")
        .style(ButtonStyle::Primary)]);
    let msg = CreateInteractionResponseMessage::new()
        .content("Backup code accepted — your old YubiKey factor was removed. Now enroll your new YubiKey:")
        .components(vec![button])
        .ephemeral(true);
    let _ = modal
        .create_response(&ctx.http, serenity::all::CreateInteractionResponse::Message(msg))
        .await;
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
