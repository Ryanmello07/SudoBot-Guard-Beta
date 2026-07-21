use crate::auth;
use crate::elevation;
use crate::logging::user_ref;
use crate::panic;
use crate::yubico::YubicoClient;
use serenity::all::{
    CommandDataOptionValue, CommandInteraction, CommandOptionType, ComponentInteraction, Context,
    CreateActionRow, CreateCommand, CreateCommandOption, CreateInputText, CreateInteractionResponse,
    CreateInteractionResponseFollowup, CreateInteractionResponseMessage, CreateModal, InputTextStyle,
};
use sqlx::PgPool;

pub fn commands() -> Vec<CreateCommand> {
    vec![CreateCommand::new("calm")
        .description("Vote to end panic mode, or manage your vote")
        .add_option(
            CreateCommandOption::new(CommandOptionType::SubCommand, "vote", "Cast a 2FA-verified vote to end panic")
                .add_sub_option(
                    CreateCommandOption::new(CommandOptionType::String, "authcode", "Your TOTP or YubiKey code").required(true),
                ),
        )
        .add_option(
            CreateCommandOption::new(CommandOptionType::SubCommand, "cancel", "Retract your vote").add_sub_option(
                CreateCommandOption::new(CommandOptionType::String, "authcode", "Your TOTP or YubiKey code").required(true),
            ),
        )
        .add_option(
            CreateCommandOption::new(CommandOptionType::SubCommand, "override", "Bot-admin-only: end panic immediately")
                .add_sub_option(
                    CreateCommandOption::new(CommandOptionType::String, "authcode", "Your own TOTP or YubiKey code").required(true),
                ),
        )]
}

async fn reply_ephemeral(ctx: &Context, cmd: &CommandInteraction, content: &str) {
    let msg = CreateInteractionResponseMessage::new().content(content).ephemeral(true);
    let _ = cmd.create_response(&ctx.http, CreateInteractionResponse::Message(msg)).await;
}

async fn reply_followup(ctx: &Context, cmd: &CommandInteraction, content: &str) {
    let msg = CreateInteractionResponseFollowup::new().content(content).ephemeral(true);
    let _ = cmd.create_followup(&ctx.http, msg).await;
}

fn extract_authcode(sub: &serenity::all::CommandDataOption) -> Option<String> {
    let CommandDataOptionValue::SubCommand(opts) = &sub.value else { return None };
    opts.iter().find_map(|o| {
        if let CommandDataOptionValue::String(s) = &o.value {
            Some(s.clone())
        } else {
            None
        }
    })
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

    match panic::is_active(pool, guild_id_i64).await {
        Ok(true) => {}
        Ok(false) => return reply_ephemeral(ctx, cmd, "Panic mode isn't currently active.").await,
        Err(e) => {
            tracing::error!(error = ?e, "calm: failed to check panic active state");
            return reply_ephemeral(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    // Defer now, before any potentially-slow work below: every subcommand
    // calls elevation::verify_code, which can make a live Yubico network
    // call and risk Discord's 3-second interaction ack window. Matches the
    // established pattern (auth.rs, panic.rs) of deferring once before
    // anything slow — every reply from here on must go through
    // reply_followup instead of reply_ephemeral.
    if let Err(e) = cmd.defer_ephemeral(&ctx.http).await {
        tracing::error!(error = ?e, "failed to defer calm interaction");
        return;
    }

    let Some(authcode) = extract_authcode(sub) else {
        return reply_followup(ctx, cmd, "Missing required code.").await;
    };

    match sub.name.as_str() {
        "vote" => handle_vote(ctx, pool, encryption_key, yubico, cmd, guild_id, guild_id_i64, user_id_i64, &authcode).await,
        "cancel" => handle_cancel(ctx, pool, encryption_key, yubico, cmd, guild_id, guild_id_i64, user_id_i64, &authcode).await,
        "override" => handle_override(ctx, pool, encryption_key, yubico, cmd, guild_id, guild_id_i64, user_id_i64, &authcode).await,
        _ => {}
    }
}

async fn handle_vote(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
    cmd: &CommandInteraction,
    guild_id: serenity::all::GuildId,
    guild_id_i64: i64,
    user_id_i64: i64,
    authcode: &str,
) {
    match elevation::verify_code(pool, guild_id_i64, user_id_i64, authcode, encryption_key, yubico).await {
        Ok(true) => {}
        Ok(false) => return reply_followup(ctx, cmd, "That code didn't verify.").await,
        Err(e) => {
            tracing::error!(error = ?e, "calm: error verifying vote code");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    if let Err(e) = panic::cast_vote(pool, guild_id_i64, user_id_i64).await {
        tracing::error!(error = ?e, "calm: failed to record vote");
        return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
    }
    reply_followup(ctx, cmd, "Your vote to end panic mode has been recorded.").await;
    resolve_after_vote_change(ctx, pool, guild_id, guild_id_i64, user_id_i64, "voted to end panic").await;
}

async fn handle_cancel(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
    cmd: &CommandInteraction,
    guild_id: serenity::all::GuildId,
    guild_id_i64: i64,
    user_id_i64: i64,
    authcode: &str,
) {
    match elevation::verify_code(pool, guild_id_i64, user_id_i64, authcode, encryption_key, yubico).await {
        Ok(true) => {}
        Ok(false) => return reply_followup(ctx, cmd, "That code didn't verify.").await,
        Err(e) => {
            tracing::error!(error = ?e, "calm: error verifying cancel code");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    if let Err(e) = panic::cancel_vote(pool, guild_id_i64, user_id_i64).await {
        tracing::error!(error = ?e, "calm: failed to cancel vote");
        return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
    }
    reply_followup(ctx, cmd, "Your vote has been retracted.").await;
    let _ = panic::update_vote_message(ctx, pool, guild_id_i64, false).await;
    panic::log_event(
        pool,
        ctx,
        guild_id_i64,
        "Panic Vote Cancelled",
        vec![("Cancelled By", user_ref(user_id_i64), true)],
    )
    .await;
}

async fn handle_override(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
    cmd: &CommandInteraction,
    _guild_id: serenity::all::GuildId,
    guild_id_i64: i64,
    user_id_i64: i64,
    authcode: &str,
) {
    match auth::is_bot_admin(pool, guild_id_i64, user_id_i64).await {
        Ok(true) => {}
        Ok(false) => return reply_followup(ctx, cmd, "You need to be a bot admin to override panic mode.").await,
        Err(e) => {
            tracing::error!(error = ?e, "calm: failed to check bot admin status");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }
    match elevation::verify_code(pool, guild_id_i64, user_id_i64, authcode, encryption_key, yubico).await {
        Ok(true) => {}
        Ok(false) => return reply_followup(ctx, cmd, "That code didn't verify.").await,
        Err(e) => {
            tracing::error!(error = ?e, "calm: error verifying override code");
            return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
        }
    }

    if let Err(e) = panic::end_panic(pool, guild_id_i64).await {
        tracing::error!(error = ?e, "calm: failed to end panic via override");
        return reply_followup(ctx, cmd, "Something went wrong. Try again later.").await;
    }
    reply_followup(ctx, cmd, "Panic mode ended by admin override.").await;
    let _ = panic::update_vote_message(ctx, pool, guild_id_i64, true).await;
    panic::log_event(
        pool,
        ctx,
        guild_id_i64,
        "Panic Mode Ended (Admin Override)",
        vec![("Ended By", user_ref(user_id_i64), true)],
    )
    .await;
}

/// After a vote is cast, checks whether it just crossed the majority
/// threshold; if so, ends panic and logs resolution, otherwise just
/// refreshes the vote message with the new tally.
async fn resolve_after_vote_change(
    ctx: &Context,
    pool: &PgPool,
    guild_id: serenity::all::GuildId,
    guild_id_i64: i64,
    voter_id_i64: i64,
    action_description: &str,
) {
    let (yes, total) = panic::tally(ctx, pool, guild_id).await.unwrap_or((0, 0));
    if panic::majority_reached(yes, total) {
        if let Err(e) = panic::end_panic(pool, guild_id_i64).await {
            tracing::error!(error = ?e, "calm: failed to end panic after majority reached");
            return;
        }
        let _ = panic::update_vote_message(ctx, pool, guild_id_i64, true).await;
        panic::log_event(
            pool,
            ctx,
            guild_id_i64,
            "Panic Mode Ended (Majority Vote)",
            vec![("Final Tally", format!("{yes} of {total}"), true)],
        )
        .await;
    } else {
        let _ = panic::update_vote_message(ctx, pool, guild_id_i64, false).await;
        panic::log_event(
            pool,
            ctx,
            guild_id_i64,
            "Panic Vote Cast",
            vec![
                ("Voter", user_ref(voter_id_i64), true),
                ("Tally", format!("{yes} of {total} ({action_description})"), true),
            ],
        )
        .await;
    }
}

pub async fn handle_component(ctx: &Context, comp: &ComponentInteraction) {
    let modal_id = match comp.data.custom_id.as_str() {
        "panic_vote_button" => "panic_vote_modal",
        "panic_cancel_button" => "panic_cancel_modal",
        _ => return,
    };
    let modal = CreateModal::new(modal_id, "Authentication Code").components(vec![CreateActionRow::InputText(
        CreateInputText::new(InputTextStyle::Short, "Authentication Code", "panic_authcode")
            .placeholder("TOTP or YubiKey code")
            .required(true),
    )]);
    if let Err(e) = comp.create_response(&ctx.http, CreateInteractionResponse::Modal(modal)).await {
        tracing::error!(error = ?e, "failed to open panic vote/cancel modal");
    }
}

pub async fn handle_modal(
    ctx: &Context,
    pool: &PgPool,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
    modal: &serenity::all::ModalInteraction,
) {
    if modal.data.custom_id != "panic_vote_modal" && modal.data.custom_id != "panic_cancel_modal" {
        return;
    }
    let Some(guild_id) = modal.guild_id else {
        return reply_modal_ephemeral(ctx, modal, "This only works in a server.").await;
    };
    let guild_id_i64 = guild_id.get() as i64;
    let user_id_i64 = modal.user.id.get() as i64;

    if let Err(e) = modal.defer_ephemeral(&ctx.http).await {
        tracing::error!(error = ?e, "failed to defer calm vote/cancel modal interaction");
        return;
    }

    let code = modal
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

    match elevation::verify_code(pool, guild_id_i64, user_id_i64, &code, encryption_key, yubico).await {
        Ok(true) => {}
        Ok(false) => return reply_modal_followup(ctx, modal, "That code didn't verify.").await,
        Err(e) => {
            tracing::error!(error = ?e, "calm: error verifying vote/cancel modal code");
            return reply_modal_followup(ctx, modal, "Something went wrong. Try again later.").await;
        }
    }

    if modal.data.custom_id == "panic_vote_modal" {
        if let Err(e) = panic::cast_vote(pool, guild_id_i64, user_id_i64).await {
            tracing::error!(error = ?e, "calm: failed to record vote via modal");
            return reply_modal_followup(ctx, modal, "Something went wrong. Try again later.").await;
        }
        reply_modal_followup(ctx, modal, "Your vote to end panic mode has been recorded.").await;
        resolve_after_vote_change(ctx, pool, guild_id, guild_id_i64, user_id_i64, "voted via button").await;
    } else {
        if let Err(e) = panic::cancel_vote(pool, guild_id_i64, user_id_i64).await {
            tracing::error!(error = ?e, "calm: failed to cancel vote via modal");
            return reply_modal_followup(ctx, modal, "Something went wrong. Try again later.").await;
        }
        reply_modal_followup(ctx, modal, "Your vote has been retracted.").await;
        let _ = panic::update_vote_message(ctx, pool, guild_id_i64, false).await;
        panic::log_event(
            pool,
            ctx,
            guild_id_i64,
            "Panic Vote Cancelled",
            vec![("Cancelled By", crate::logging::user_ref(user_id_i64), true)],
        )
        .await;
    }
}

async fn reply_modal_ephemeral(ctx: &Context, modal: &serenity::all::ModalInteraction, content: &str) {
    let msg = CreateInteractionResponseMessage::new().content(content).ephemeral(true);
    let _ = modal.create_response(&ctx.http, CreateInteractionResponse::Message(msg)).await;
}

async fn reply_modal_followup(ctx: &Context, modal: &serenity::all::ModalInteraction, content: &str) {
    let msg = serenity::all::CreateInteractionResponseFollowup::new().content(content).ephemeral(true);
    let _ = modal.create_followup(&ctx.http, msg).await;
}
