use serenity::all::{ChannelId, CreateEmbed, CreateEmbedFooter, CreateMessage, Http};
use sqlx::PgPool;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LogError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("failed to send log message: {0}")]
    Discord(#[from] serenity::Error),
}

#[derive(Debug)]
pub enum LogTier {
    Info,
    Alert,
}

pub async fn log(
    pool: &PgPool,
    http: &Http,
    guild_id: i64,
    tier: LogTier,
    embed: CreateEmbed,
) -> Result<(), LogError> {
    tracing::debug!(guild_id, ?tier, "posting log entry");

    let channel_row = sqlx::query!(
        "SELECT channel_id FROM log_channels WHERE guild_id = $1",
        guild_id
    )
    .fetch_optional(pool)
    .await?;

    let Some(row) = channel_row else {
        tracing::warn!(guild_id, "log() called but no log channel configured for this guild");
        return Ok(());
    };

    let seq = next_log_sequence(pool, guild_id).await?;
    let embed = embed.footer(CreateEmbedFooter::new(format!("#{seq}")));

    let channel_id = ChannelId::new(row.channel_id as u64);
    channel_id
        .send_message(http, CreateMessage::new().embed(embed))
        .await?;
    Ok(())
}

/// Atomically claims the next sequence number for a guild and advances the
/// counter, in a single round trip. First call for a guild claims 1 and
/// leaves the stored counter at 2; each subsequent call claims the stored
/// value and advances it by 1.
async fn next_log_sequence(pool: &PgPool, guild_id: i64) -> Result<i64, sqlx::Error> {
    let row = sqlx::query!(
        "INSERT INTO log_sequence (guild_id, next_seq) VALUES ($1, 2)
         ON CONFLICT (guild_id) DO UPDATE SET next_seq = log_sequence.next_seq + 1
         RETURNING next_seq - 1 AS seq",
        guild_id
    )
    .fetch_one(pool)
    .await?;
    Ok(row
        .seq
        .expect("next_seq - 1 is never null since next_seq is NOT NULL"))
}
