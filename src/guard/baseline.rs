use sqlx::PgPool;

pub struct RoleBaseline {
    pub permissions: i64,
    pub name: Option<String>,
    pub position: Option<i32>,
}

pub async fn get_baseline(
    pool: &PgPool,
    guild_id: i64,
    role_id: i64,
) -> Result<Option<RoleBaseline>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT permissions, name, position FROM role_baselines WHERE guild_id = $1 AND role_id = $2",
        guild_id,
        role_id
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| RoleBaseline {
        permissions: r.permissions,
        name: r.name,
        position: r.position,
    }))
}

pub async fn upsert_baseline(
    pool: &PgPool,
    guild_id: i64,
    role_id: i64,
    permissions: i64,
    name: Option<&str>,
    position: Option<i32>,
    updated_by: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO role_baselines (guild_id, role_id, permissions, name, position, updated_by)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (guild_id, role_id) DO UPDATE
         SET permissions = EXCLUDED.permissions,
             name = EXCLUDED.name,
             position = EXCLUDED.position,
             updated_by = EXCLUDED.updated_by,
             updated_at = now()",
        guild_id,
        role_id,
        permissions,
        name,
        position,
        updated_by
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Updates only `name` and `position` on an existing baseline row, leaving
/// `permissions` untouched. Used when a role that already has a
/// permissions-only baseline (captured at some prior startup, before it was
/// ever registered) gets registered via `/protect add` — at that moment its
/// name/position need to be captured for the first time, but its
/// `permissions` value is already trusted and must not be reset to whatever
/// the role's live permissions happen to be at this instant.
pub async fn update_registration_metadata(
    pool: &PgPool,
    guild_id: i64,
    role_id: i64,
    name: Option<&str>,
    position: Option<i32>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE role_baselines SET name = $3, position = $4, updated_at = now() WHERE guild_id = $1 AND role_id = $2",
        guild_id,
        role_id,
        name,
        position
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn is_registered_role(
    pool: &PgPool,
    guild_id: i64,
    role_id: i64,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT 1 AS present FROM role_pairs
         WHERE guild_id = $1 AND (standard_role_id = $2 OR permission_role_id = $2)",
        guild_id,
        role_id
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

pub async fn registered_permission_role_ids(
    pool: &PgPool,
    guild_id: i64,
) -> Result<Vec<i64>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT permission_role_id FROM role_pairs WHERE guild_id = $1",
        guild_id
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.permission_role_id).collect())
}
