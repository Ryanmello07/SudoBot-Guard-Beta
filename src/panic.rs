use sqlx::PgPool;

/// True if the member (given their current role IDs) holds either half of
/// any registered role pair — the standard identity role or the permission
/// role. Broader than "currently elevated": matches anyone staff-registered
/// with the bot at all, elevated or not.
pub fn is_protected_staff(member_role_ids: &[i64], registered_role_ids: &[i64]) -> bool {
    member_role_ids.iter().any(|r| registered_role_ids.contains(r))
}

/// True once yes_votes forms a strict majority of total_eligible. Zero
/// eligible voters can never reach majority (avoids a 0-votes-needed
/// edge case if voter_roles is misconfigured to nobody).
pub fn majority_reached(yes_votes: i64, total_eligible: i64) -> bool {
    total_eligible > 0 && yes_votes * 2 > total_eligible
}

/// Every role ID that's either half of a registered role pair in this
/// guild — the standard identity role or the permission role.
pub async fn registered_role_ids(pool: &PgPool, guild_id_i64: i64) -> Result<Vec<i64>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"SELECT standard_role_id AS "role_id!" FROM role_pairs WHERE guild_id = $1
           UNION
           SELECT permission_role_id AS "role_id!" FROM role_pairs WHERE guild_id = $1"#,
        guild_id_i64
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.role_id).collect())
}

pub async fn voter_role_ids(pool: &PgPool, guild_id_i64: i64) -> Result<Vec<i64>, sqlx::Error> {
    let rows = sqlx::query!("SELECT role_id FROM voter_roles WHERE guild_id = $1", guild_id_i64)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|r| r.role_id).collect())
}

pub async fn is_active(pool: &PgPool, guild_id_i64: i64) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!("SELECT active FROM panic_state WHERE guild_id = $1", guild_id_i64)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.active).unwrap_or(false))
}

/// `Some(until)` if a post-panic cooldown is still in effect (checked
/// against the database's own clock via `now()`, not the app server's).
pub async fn cooldown_remaining(pool: &PgPool, guild_id_i64: i64) -> Result<Option<chrono::DateTime<chrono::Utc>>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT cooldown_until FROM panic_state WHERE guild_id = $1 AND cooldown_until IS NOT NULL AND cooldown_until > now()",
        guild_id_i64
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.cooldown_until))
}

pub async fn panic_channel(pool: &PgPool, guild_id_i64: i64) -> Result<Option<i64>, sqlx::Error> {
    let row = sqlx::query!("SELECT channel_id FROM panic_channels WHERE guild_id = $1", guild_id_i64)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.channel_id))
}

/// `Some((channel_id, message_id))` of the currently-posted vote message,
/// if one has been recorded for this guild's panic episode.
pub async fn vote_message_location(pool: &PgPool, guild_id_i64: i64) -> Result<Option<(i64, i64)>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT vote_channel_id, vote_message_id FROM panic_state WHERE guild_id = $1",
        guild_id_i64
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| match (r.vote_channel_id, r.vote_message_id) {
        (Some(c), Some(m)) => Some((c, m)),
        _ => None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_staff_detected_via_standard_role() {
        assert!(is_protected_staff(&[10], &[10, 20]));
    }

    #[test]
    fn protected_staff_detected_via_permission_role() {
        assert!(is_protected_staff(&[20], &[10, 20]));
    }

    #[test]
    fn protected_staff_not_detected_for_unrelated_role() {
        assert!(!is_protected_staff(&[99], &[10, 20]));
    }

    #[test]
    fn protected_staff_not_detected_for_empty_registry() {
        assert!(!is_protected_staff(&[10], &[]));
    }

    #[test]
    fn majority_reached_with_more_than_half() {
        assert!(majority_reached(4, 7));
    }

    #[test]
    fn majority_not_reached_at_exactly_half() {
        assert!(!majority_reached(3, 6));
    }

    #[test]
    fn majority_not_reached_below_half() {
        assert!(!majority_reached(2, 7));
    }

    #[test]
    fn majority_never_reached_with_zero_eligible() {
        assert!(!majority_reached(0, 0));
    }
}
