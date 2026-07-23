use sqlx::PgPool;

pub async fn is_bot_admin(pool: &PgPool, guild_id: i64, user_id: i64) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT 1 AS present FROM bot_admins WHERE guild_id = $1 AND user_id = $2",
        guild_id,
        user_id
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

pub async fn bot_admin_count(pool: &PgPool, guild_id: i64) -> Result<i64, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS count FROM bot_admins WHERE guild_id = $1",
        guild_id
    )
    .fetch_one(pool)
    .await?;
    Ok(row.count.unwrap_or(0))
}

pub async fn add_bot_admin(pool: &PgPool, guild_id: i64, user_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO bot_admins (guild_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        guild_id,
        user_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove_bot_admin(pool: &PgPool, guild_id: i64, user_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM bot_admins WHERE guild_id = $1 AND user_id = $2",
        guild_id,
        user_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn bootstrap_admin_if_needed(
    pool: &PgPool,
    guild_id: i64,
    initial_admin_id: Option<i64>,
) -> Result<(), sqlx::Error> {
    let Some(admin_id) = initial_admin_id else {
        return Ok(());
    };
    if bot_admin_count(pool, guild_id).await? == 0 {
        add_bot_admin(pool, guild_id, admin_id).await?;
        tracing::info!(guild_id, admin_id, "auto-bootstrapped initial bot admin");
    }
    Ok(())
}
