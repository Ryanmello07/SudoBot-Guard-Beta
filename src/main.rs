mod auth;
mod commands;
mod config;
mod crypto;
mod db;
mod logging;
mod settings;
mod yubico;

use config::Config;
use serenity::all::{Guild, GuildId, Interaction};
use serenity::async_trait;
use serenity::model::gateway::Ready;
use serenity::prelude::*;
use sqlx::PgPool;

struct Handler {
    pool: PgPool,
    initial_bot_admin_id: Option<u64>,
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
    }
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        tracing::info!(bot_name = %ready.user.name, "connected and ready");
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

    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        match interaction {
            Interaction::Command(cmd) => match cmd.data.name.as_str() {
                "setup" => commands::setup::handle(&ctx, &self.pool, &cmd).await,
                "protect" => commands::protect::handle(&ctx, &self.pool, &cmd).await,
                "settings" => commands::settings::handle(&ctx, &self.pool, &cmd).await,
                _ => {}
            },
            Interaction::Component(comp) => {
                commands::protect::handle_component(&ctx, &self.pool, &comp).await
            }
            _ => {}
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

    let intents = GatewayIntents::GUILDS | GatewayIntents::GUILD_MEMBERS;
    let mut client = Client::builder(&config.discord_token, intents)
        .event_handler(Handler {
            pool,
            initial_bot_admin_id: config.initial_bot_admin_id,
        })
        .await
        .expect("failed to create Discord client — check DISCORD_TOKEN");

    if let Err(why) = client.start().await {
        tracing::error!(error = ?why, "client error");
    }
}
