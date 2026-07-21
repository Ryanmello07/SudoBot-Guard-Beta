use serenity::all::{ChannelId, CreateEmbed, CreateEmbedFooter, CreateMessage, Http, Timestamp};
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

/// Renders a role as a clickable mention with its raw ID beneath in a
/// copyable code block — mirrors how the bot's own reference (SudoBot)
/// shows entities in its logs, giving both a quick jump and a value that's
/// easy to select and paste elsewhere (an API call, another bot's command).
/// Use `role_ref_deleted` instead once the role no longer exists — Discord
/// can't resolve a mention for a deleted role and renders a confusing
/// generic fallback instead of the role's name.
pub fn role_ref(role_id: i64) -> String {
    format!("<@&{role_id}>\n`{role_id}`")
}

/// For a role that has already been deleted (recreation's old role, a
/// reverted lockdown-violation creation): a working mention isn't possible,
/// so just the ID, still copyable.
pub fn role_ref_deleted(role_id: i64) -> String {
    format!("`{role_id}`")
}

/// Renders a user the same way as `role_ref` — mention plus copyable ID.
pub fn user_ref(user_id: i64) -> String {
    format!("<@{user_id}>\n`{user_id}`")
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
    let embed = embed
        .footer(CreateEmbedFooter::new(format!("#{seq}")))
        .timestamp(Timestamp::now());

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
