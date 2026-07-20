mod auth;
mod config;
mod crypto;
mod db;
mod logging;
mod yubico;

use config::Config;
use serenity::async_trait;
use serenity::model::gateway::Ready;
use serenity::prelude::*;

struct Handler;

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, _ctx: Context, ready: Ready) {
        tracing::info!(bot_name = %ready.user.name, "connected and ready");
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

    let config = Config::from_env().expect("invalid configuration — check .env against .env.example");

    let pool = db::init_pool(&config.database_url)
        .await
        .expect("failed to connect to Postgres");
    db::run_migrations(&pool)
        .await
        .expect("failed to run database migrations");
    tracing::info!("database connected and migrated");

    let intents = GatewayIntents::GUILDS | GatewayIntents::GUILD_MEMBERS;
    let mut client = Client::builder(&config.discord_token, intents)
        .event_handler(Handler)
        .await
        .expect("failed to create Discord client — check DISCORD_TOKEN");

    if let Err(why) = client.start().await {
        tracing::error!(error = ?why, "client error");
    }
}
