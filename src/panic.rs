use serenity::all::{Context, GuildId, RoleId, UserId};
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

/// Guild-wide session revocation: every currently-active session is
/// revoked and its permission role stripped from the holder. Returns the
/// number of sessions revoked, for logging. The guild-wide version of what
/// `/deauth` already does for a single caller.
pub async fn revoke_all_sessions(ctx: &Context, pool: &PgPool, guild_id_i64: i64) -> i64 {
    let sessions = match sqlx::query!(
        "SELECT s.id, s.user_id, r.permission_role_id
         FROM sessions s
         JOIN role_pairs r ON r.id = s.role_pair_id
         WHERE s.guild_id = $1 AND s.revoked_at IS NULL AND s.expires_at > now()",
        guild_id_i64
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = ?e, guild_id = guild_id_i64, "panic: failed to load active sessions for guild-wide revocation");
            return 0;
        }
    };

    let guild_id = GuildId::new(guild_id_i64 as u64);
    let mut revoked_count = 0;
    for session in &sessions {
        let permission_role_id = RoleId::new(session.permission_role_id as u64);
        if let Ok(member) = guild_id.member(&ctx.http, UserId::new(session.user_id as u64)).await {
            if let Err(e) = member.remove_role(&ctx.http, permission_role_id).await {
                tracing::error!(error = ?e, guild_id = guild_id_i64, session_id = session.id, "panic: failed to remove permission role during guild-wide revocation");
            }
        }
        if sqlx::query!(
            "UPDATE sessions SET revoked_at = now(), revoke_reason = 'panic' WHERE id = $1",
            session.id
        )
        .execute(pool)
        .await
        .is_ok()
        {
            revoked_count += 1;
        }
    }
    revoked_count
}

/// Executes a panic trigger: mass session revocation, force-lockdown-on
/// (the same mechanism `/lockdown on` uses), and setting `panic_active`.
/// Returns the number of sessions revoked. Does NOT check eligibility,
/// idempotency, or cooldown — the caller (`/panic`'s handler) must have
/// already confirmed those before calling this.
pub async fn trigger(ctx: &Context, pool: &PgPool, guild_id: GuildId, triggered_by_i64: i64) -> i64 {
    let guild_id_i64 = guild_id.get() as i64;
    let revoked_count = revoke_all_sessions(ctx, pool, guild_id_i64).await;

    crate::guard::backfill::sync_role_baselines(ctx, pool, guild_id, true, Some(triggered_by_i64)).await;
    if let Err(e) = crate::settings::set_setting(pool, guild_id_i64, crate::guard::LOCKDOWN_ENABLED_KEY, "true", triggered_by_i64).await {
        tracing::error!(error = ?e, guild_id = guild_id_i64, "panic: failed to force lockdown on during trigger");
    }

    if let Err(e) = sqlx::query!(
        "INSERT INTO panic_state (guild_id, active, triggered_by, triggered_at, cooldown_until)
         VALUES ($1, true, $2, now(), NULL)
         ON CONFLICT (guild_id) DO UPDATE
         SET active = true, triggered_by = EXCLUDED.triggered_by, triggered_at = now(), cooldown_until = NULL",
        guild_id_i64,
        triggered_by_i64
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = ?e, guild_id = guild_id_i64, "panic: failed to set panic_active during trigger");
    }

    revoked_count
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
