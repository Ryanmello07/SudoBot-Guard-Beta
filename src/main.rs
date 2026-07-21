mod auth;
mod commands;
mod config;
mod crypto;
mod db;
mod elevation;
mod enrollment;
mod guard;
mod logging;
mod settings;
mod yubico;

use config::Config;
use serenity::all::{Guild, GuildId, Interaction};
use serenity::all::Http;
use serenity::async_trait;
use serenity::model::gateway::Ready;
use serenity::prelude::*;
use sqlx::PgPool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct Handler {
    pool: PgPool,
    initial_bot_admin_id: Option<u64>,
    encryption_key: [u8; 32],
    yubico: yubico::YubicoClient,
    bot_user_id: AtomicU64,
    guard_sweep_started: std::sync::atomic::AtomicBool,
}

impl Handler {
    /// Registers this guild's commands and bootstraps its admin if needed.
    /// Called both from `ready` (for guilds the bot is already in — the
    /// gateway does not reliably deliver a `guild_create` event for these
    /// on every connection, so `ready.guilds` is the dependable source) and
    /// from `guild_create` (for guilds joined while already connected).
    async fn setup_guild(&self, ctx: &Context, guild_id: GuildId) {
        if let Err(e) = commands::register_all(ctx, guild_id).await {
            tracing::error!(error = ?e, %guild_id, "failed to register commands");
            return;
        }
        tracing::info!(%guild_id, "registered commands");

        let initial_admin_id_i64 = self.initial_bot_admin_id.map(|id| id as i64);
        if let Err(e) =
            auth::bootstrap_admin_if_needed(&self.pool, guild_id.get() as i64, initial_admin_id_i64)
                .await
        {
            tracing::error!(error = ?e, %guild_id, "failed to bootstrap admin");
        }

        self.backfill_role_baselines(ctx, guild_id).await;
    }

    /// Captures a permissions baseline for any role that doesn't have one
    /// yet — runs at every startup (and every guild join) so a bot restart
    /// can never leave a role unguarded. Registered roles also get their
    /// name and position captured. Delegates to the shared sync function
    /// used by `/lockdown on` for its force-refresh variant.
    async fn backfill_role_baselines(&self, ctx: &Context, guild_id: GuildId) {
        guard::backfill::sync_role_baselines(ctx, &self.pool, guild_id, false, None).await;
    }
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        tracing::info!(bot_name = %ready.user.name, "connected and ready");
        self.bot_user_id.store(ready.user.id.get(), Ordering::Relaxed);

        if !self.guard_sweep_started.swap(true, Ordering::Relaxed) {
            let sweep_ctx = ctx.clone();
            let sweep_pool = self.pool.clone();
            tokio::spawn(async move {
                // tokio::time::interval fires immediately on its first
                // tick(), so this loop's first iteration is the startup
                // sweep — no separate call needed before the loop.
                let mut interval = tokio::time::interval(Duration::from_secs(300));
                loop {
                    interval.tick().await;
                    for guild_id in sweep_ctx.cache.guilds() {
                        guard::sweep::run_once(&sweep_ctx, &sweep_pool, guild_id).await;
                    }
                }
            });
        }

        for guild in &ready.guilds {
            self.setup_guild(&ctx, guild.id).await;
        }
    }

    async fn guild_create(&self, ctx: Context, guild: Guild, is_new: Option<bool>) {
        if is_new != Some(true) {
            // Already covered by the ready handler's ready.guilds loop.
            return;
        }
        self.setup_guild(&ctx, guild.id).await;
    }

    /// Captures a baseline for a role the instant it's created, so it's
    /// guarded from the moment it exists rather than only after the next
    /// bot restart (or the next sweep tick, which never creates baselines —
    /// it only compares against ones that already exist). A brand-new role
    /// is essentially never already registered, but the registration check
    /// is kept for consistency with how baselines are captured everywhere
    /// else (startup backfill, `/protect add`, `/lockdown on`).
    async fn guild_role_create(&self, _ctx: Context, new: serenity::model::guild::Role) {
        let guild_id_i64 = new.guild_id.get() as i64;
        let role_id_i64 = new.id.get() as i64;
        let is_registered = guard::baseline::is_registered_role(&self.pool, guild_id_i64, role_id_i64)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = ?e, guild_id = guild_id_i64, role_id = role_id_i64, "guard: failed to check role registration for new role");
                false
            });
        let name = is_registered.then(|| new.name.clone());
        // Position is captured for every role, not just registered ones —
        // it's tied to Discord's role hierarchy, not just cosmetic identity.
        let position = Some(new.position as i32);
        if let Err(e) = guard::baseline::upsert_baseline(
            &self.pool,
            guild_id_i64,
            role_id_i64,
            new.permissions.bits() as i64,
            name.as_deref(),
            position,
            None,
        )
        .await
        {
            tracing::error!(error = ?e, guild_id = guild_id_i64, role_id = role_id_i64, "guard: failed to capture baseline for newly created role");
        }
    }

    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        match interaction {
            Interaction::Command(cmd) => match cmd.data.name.as_str() {
                "setup" => commands::setup::handle(&ctx, &self.pool, &cmd).await,
                "protect" => commands::protect::handle(&ctx, &self.pool, &cmd).await,
                "settings" => commands::settings::handle(&ctx, &self.pool, &cmd).await,
                "enroll" => commands::enroll::handle(&ctx, &self.pool, &cmd).await,
                "lockdown" => commands::lockdown::handle(&ctx, &self.pool, &cmd).await,
                "auth" | "deauth" | "status" => {
                    commands::auth::handle(&ctx, &self.pool, &self.encryption_key, &self.yubico, &cmd).await
                }
                _ => {}
            },
            Interaction::Component(comp) => {
                if comp.data.custom_id == "protect_remove_select" {
                    commands::protect::handle_component(&ctx, &self.pool, &comp).await;
                } else if comp.data.custom_id == "settings_select" {
                    commands::settings::handle_component(&ctx, &self.pool, &comp).await;
                } else {
                    commands::enroll::handle_component(&ctx, &self.pool, &self.encryption_key, &comp).await;
                }
            }
            Interaction::Modal(modal) => {
                if modal.data.custom_id.starts_with("settings_modal:") {
                    commands::settings::handle_modal(&ctx, &self.pool, &modal).await;
                } else {
                    commands::enroll::handle_modal(&ctx, &self.pool, &self.encryption_key, &self.yubico, &modal).await
                }
            }
            _ => {}
        }
    }

    async fn guild_audit_log_entry_create(
        &self,
        ctx: Context,
        entry: serenity::model::guild::audit_log::AuditLogEntry,
        guild_id: GuildId,
    ) {
        guard::audit_handler::handle_entry(
            &ctx,
            &self.pool,
            guild_id.get() as i64,
            &entry,
            self.bot_user_id.load(Ordering::Relaxed),
        )
        .await;
    }
}

/// Runs forever, checking for expired sessions every 30 seconds and
/// stripping the Discord role for each one found. Independent of the
/// gateway event-handler model — this is the bot's own background clock,
/// not triggered by anything Discord sends.
async fn sweep_expired_sessions(http: Arc<Http>, pool: sqlx::PgPool) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;

        let expired = match sqlx::query!(
            "SELECT s.id, s.guild_id, s.user_id, r.permission_role_id
             FROM sessions s
             JOIN role_pairs r ON r.id = s.role_pair_id
             WHERE s.revoked_at IS NULL AND s.expires_at <= now()"
        )
        .fetch_all(&pool)
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(error = ?e, "expiry sweep: failed to query expired sessions");
                continue;
            }
        };

        for session in expired {
            let guild_id = serenity::all::GuildId::new(session.guild_id as u64);
            let user_id = serenity::all::UserId::new(session.user_id as u64);
            let permission_role_id = serenity::all::RoleId::new(session.permission_role_id as u64);

            match guild_id.member(&http, user_id).await {
                Ok(member) => {
                    match member.remove_role(&http, permission_role_id).await {
                        Ok(()) => {
                            // fall through to mark revoked below
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, session_id = session.id, "expiry sweep: failed to remove role, will retry next tick");
                            continue; // leave revoked_at NULL, retry next tick
                        }
                    }
                }
                Err(e) => {
                    let member_not_found = matches!(
                        &e,
                        serenity::Error::Http(http_err) if http_err.status_code() == Some(reqwest::StatusCode::NOT_FOUND)
                    );
                    if member_not_found {
                        tracing::error!(error = ?e, session_id = session.id, "expiry sweep: member left the guild — marking revoked, no role to remove");
                        // fall through to mark revoked below — member is genuinely gone
                    } else {
                        tracing::error!(error = ?e, session_id = session.id, "expiry sweep: failed to fetch member (transient error), will retry next tick");
                        continue; // leave revoked_at NULL, retry next tick
                    }
                }
            }

            // Only reached if role removal succeeded, or the member has left the guild.
            if let Err(e) = sqlx::query!(
                "UPDATE sessions SET revoked_at = now(), revoke_reason = 'expired' WHERE id = $1",
                session.id
            )
            .execute(&pool)
            .await
            {
                tracing::error!(error = ?e, session_id = session.id, "expiry sweep: failed to mark session revoked");
                continue;
            }

            let embed = serenity::all::CreateEmbed::new()
                .title("Session expired")
                .description(format!("<@{}>'s <@&{}> expired", session.user_id, session.permission_role_id))
                .color(0x5865F2);
            let _ = logging::log(&pool, &http, session.guild_id, logging::LogTier::Info, embed).await;
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    dotenvy::dotenv().ok();

    let config =
        Config::from_env().expect("invalid configuration — check .env against .env.example");

    let pool = db::init_pool(&config.database_url)
        .await
        .expect("failed to connect to Postgres");
    db::run_migrations(&pool)
        .await
        .expect("failed to run database migrations");
    tracing::info!("database connected and migrated");

    let yubico = yubico::YubicoClient::new(config.yubico_client_id.clone(), &config.yubico_secret_key);

    let intents = GatewayIntents::GUILDS | GatewayIntents::GUILD_MEMBERS | GatewayIntents::GUILD_MODERATION;
    let mut client = Client::builder(&config.discord_token, intents)
        .event_handler(Handler {
            pool: pool.clone(),
            initial_bot_admin_id: config.initial_bot_admin_id,
            encryption_key: config.encryption_key,
            yubico,
            bot_user_id: AtomicU64::new(0),
            guard_sweep_started: std::sync::atomic::AtomicBool::new(false),
        })
        .await
        .expect("failed to create Discord client — check DISCORD_TOKEN");

    tokio::spawn(sweep_expired_sessions(client.http.clone(), pool));

    if let Err(why) = client.start().await {
        tracing::error!(error = ?why, "client error");
    }
}
