use crate::logging::{log, LogTier};
use serenity::all::{
    ButtonStyle, ChannelId, Context, CreateActionRow, CreateButton, CreateEmbed, CreateMessage,
    EditMessage, GuildId, RoleId, UserId,
};
use serenity::futures::StreamExt;
use sqlx::PgPool;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TallyError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("failed to list guild members: {0}")]
    Discord(#[from] serenity::Error),
}

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

    // Set panic_active FIRST — before the (potentially minutes-long)
    // revocation sweep and the lockdown-forcing calls below. `/auth`'s only
    // gate against new elevation is checking `is_active` at the top of
    // `handle_auth`, so until this upsert commits that gate reads `false`
    // and someone can elevate a brand-new session that the revocation loop
    // has already passed by. Committing this first shrinks that window from
    // the whole sweep down to a single INSERT, and fails safe: if anything
    // later in trigger() errors out partway, panic_active is already true so
    // new elevation stays blocked rather than silently allowed.
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

    // Guarantee a clean vote slate for the new episode. `end_panic` already
    // clears votes when an episode ends, but this belt-and-suspenders delete
    // closes the case where a stale vote row survived (e.g. a vote that raced
    // a prior episode's end) and would otherwise count toward this fresh
    // episode's tally from the moment it opens.
    if let Err(e) = sqlx::query!("DELETE FROM panic_votes WHERE guild_id = $1", guild_id_i64)
        .execute(pool)
        .await
    {
        tracing::error!(error = ?e, guild_id = guild_id_i64, "panic: failed to clear stale votes during trigger");
    }

    let revoked_count = revoke_all_sessions(ctx, pool, guild_id_i64).await;

    crate::guard::backfill::sync_role_baselines(ctx, pool, guild_id, true, Some(triggered_by_i64)).await;
    if let Err(e) = crate::settings::set_setting(pool, guild_id_i64, crate::guard::LOCKDOWN_ENABLED_KEY, "true", triggered_by_i64).await {
        tracing::error!(error = ?e, guild_id = guild_id_i64, "panic: failed to force lockdown on during trigger");
    }

    revoked_count
}

pub async fn cast_vote(pool: &PgPool, guild_id_i64: i64, voter_id_i64: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO panic_votes (guild_id, voter_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        guild_id_i64,
        voter_id_i64
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn cancel_vote(pool: &PgPool, guild_id_i64: i64, voter_id_i64: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM panic_votes WHERE guild_id = $1 AND voter_id = $2",
        guild_id_i64,
        voter_id_i64
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Every member ID currently holding any `voter_roles` role, fetched via a
/// live REST member listing rather than the gateway's member cache. The
/// cache only reflects whichever members Discord happened to have sent
/// (online members, or ones the bot has otherwise observed) unless the bot
/// explicitly requested a full member-list chunk — for a rare, human-paced,
/// security-critical operation like this, a real API call per vote is the
/// right trade: a live incident showed the cache silently under-counting
/// eligible voters (two members with the same voter role, only one of them
/// counted), which directly corrupts the majority threshold this whole
/// feature depends on.
async fn eligible_voter_ids(ctx: &Context, pool: &PgPool, guild_id: GuildId) -> Result<Vec<i64>, TallyError> {
    let guild_id_i64 = guild_id.get() as i64;
    let voter_roles = voter_role_ids(pool, guild_id_i64).await?;
    if voter_roles.is_empty() {
        return Ok(Vec::new());
    }

    let mut eligible_ids = Vec::new();
    let mut members = guild_id.members_iter(&ctx.http).boxed();
    while let Some(member_result) = members.next().await {
        match member_result {
            Ok(member) => {
                if member.roles.iter().any(|r| voter_roles.contains(&(r.get() as i64))) {
                    eligible_ids.push(member.user.id.get() as i64);
                }
            }
            Err(e) => {
                // Fail closed: a partial member list understates total_eligible,
                // which makes majority_reached easier to satisfy — the same
                // undercounting failure this function exists to fix, reintroduced
                // through a different door. Propagate instead of continuing.
                tracing::error!(error = ?e, %guild_id, "panic: failed to fetch a page of guild members while computing eligible voters");
                return Err(TallyError::Discord(e));
            }
        }
    }
    Ok(eligible_ids)
}

/// True if `user_id_i64` is currently in the guild and holds any
/// `voter_roles` role — checked live via REST, matching `tally`'s ground
/// truth exactly, so a "you're not eligible" reply is never based on stale
/// cache data.
pub async fn is_eligible_voter(ctx: &Context, pool: &PgPool, guild_id: GuildId, user_id_i64: i64) -> bool {
    let guild_id_i64 = guild_id.get() as i64;
    let Ok(voter_roles) = voter_role_ids(pool, guild_id_i64).await else {
        return false;
    };
    if voter_roles.is_empty() {
        return false;
    }
    let Ok(member) = guild_id.member(&ctx.http, UserId::new(user_id_i64 as u64)).await else {
        return false;
    };
    member.roles.iter().any(|r| voter_roles.contains(&(r.get() as i64)))
}

/// (yes_votes, total_eligible) computed live: total_eligible is every
/// member CURRENTLY holding any `voter_roles` role (via a real member
/// listing, not the gateway cache — see `eligible_voter_ids`); yes_votes is
/// how many of THOSE members have also cast a vote. A stored vote from
/// someone who no longer holds a voter role doesn't count — eligibility is
/// always "currently," never "at the time they voted."
pub async fn tally(ctx: &Context, pool: &PgPool, guild_id: GuildId) -> Result<(i64, i64), TallyError> {
    let guild_id_i64 = guild_id.get() as i64;
    let eligible_ids = eligible_voter_ids(ctx, pool, guild_id).await?;

    if eligible_ids.is_empty() {
        return Ok((0, 0));
    }

    let yes_votes = sqlx::query!(
        "SELECT COUNT(*) AS count FROM panic_votes WHERE guild_id = $1 AND voter_id = ANY($2)",
        guild_id_i64,
        &eligible_ids
    )
    .fetch_one(pool)
    .await?
    .count
    .unwrap_or(0);

    Ok((yes_votes, eligible_ids.len() as i64))
}

/// Ends the current panic episode: clears `active`, starts the 1-hour
/// cooldown, and wipes any votes so they never carry into a future episode.
pub async fn end_panic(pool: &PgPool, guild_id_i64: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE panic_state SET active = false, cooldown_until = now() + interval '1 hour' WHERE guild_id = $1",
        guild_id_i64
    )
    .execute(pool)
    .await?;
    sqlx::query!("DELETE FROM panic_votes WHERE guild_id = $1", guild_id_i64)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn record_vote_message(pool: &PgPool, guild_id_i64: i64, channel_id_i64: i64, message_id_i64: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE panic_state SET vote_channel_id = $2, vote_message_id = $3 WHERE guild_id = $1",
        guild_id_i64,
        channel_id_i64,
        message_id_i64
    )
    .execute(pool)
    .await?;
    Ok(())
}

fn vote_embed(yes_votes: i64, total_eligible: i64, resolved: bool) -> CreateEmbed {
    let title = if resolved { "Panic Mode — Resolved" } else { "Panic Mode — Vote to Calm" };
    let color = if resolved { 0x57F287 } else { 0xED4245 };
    CreateEmbed::new()
        .title(title)
        .field(
            "Tally",
            format!("{yes_votes} of {total_eligible} eligible voter(s) have voted to end panic — a majority is required."),
            false,
        )
        .field(
            "How to vote",
            "Click **Vote** or **Cancel Vote** below (a 2FA code is required), or run `/calm vote <authcode>` / `/calm cancel <authcode>` directly.",
            false,
        )
        .color(color)
}

fn vote_buttons() -> CreateActionRow {
    CreateActionRow::Buttons(vec![
        CreateButton::new("panic_vote_button").label("Vote").style(ButtonStyle::Danger),
        CreateButton::new("panic_cancel_button").label("Cancel Vote").style(ButtonStyle::Secondary),
    ])
}

/// Posts the initial vote message for a freshly-triggered panic episode
/// into the guild's configured panic channel, recording its location so
/// later votes/cancellations know which message to edit.
pub async fn post_vote_message(ctx: &Context, pool: &PgPool, guild_id_i64: i64) -> Result<(), serenity::Error> {
    let Ok(Some(channel_id_i64)) = panic_channel(pool, guild_id_i64).await else {
        tracing::error!(guild_id = guild_id_i64, "panic: no panic channel configured, vote message not posted");
        return Ok(());
    };
    let channel_id = ChannelId::new(channel_id_i64 as u64);

    let (yes, total) = tally(ctx, pool, GuildId::new(guild_id_i64 as u64)).await.unwrap_or((0, 0));
    let msg = channel_id
        .send_message(
            &ctx.http,
            CreateMessage::new().embed(vote_embed(yes, total, false)).components(vec![vote_buttons()]),
        )
        .await?;

    if let Err(e) = record_vote_message(pool, guild_id_i64, channel_id_i64, msg.id.get() as i64).await {
        tracing::error!(error = ?e, guild_id = guild_id_i64, "panic: failed to record vote message location");
    }
    Ok(())
}

/// Re-fetches the current tally and edits the existing vote message in
/// place — called after every vote/cancel so the message never falls out
/// of sync, and once more with `resolved = true` when panic actually ends.
pub async fn update_vote_message(ctx: &Context, pool: &PgPool, guild_id_i64: i64, resolved: bool) -> Result<(), serenity::Error> {
    let Ok(Some((channel_id_i64, message_id_i64))) = vote_message_location(pool, guild_id_i64).await else {
        return Ok(());
    };
    let channel_id = ChannelId::new(channel_id_i64 as u64);
    let message_id = serenity::all::MessageId::new(message_id_i64 as u64);

    let (yes, total) = tally(ctx, pool, GuildId::new(guild_id_i64 as u64)).await.unwrap_or((0, 0));
    let edit = if resolved {
        EditMessage::new().embed(vote_embed(yes, total, true)).components(vec![])
    } else {
        EditMessage::new().embed(vote_embed(yes, total, false)).components(vec![vote_buttons()])
    };
    channel_id.edit_message(&ctx.http, message_id, edit).await?;
    Ok(())
}

/// Logs a panic-related state transition consistently — used by the
/// command layer for trigger/vote/cancel/end events.
pub async fn log_event(pool: &PgPool, ctx: &Context, guild_id_i64: i64, title: &str, fields: Vec<(&str, String, bool)>) {
    let mut embed = CreateEmbed::new().title(title).color(0xED4245);
    for (name, value, inline) in fields {
        embed = embed.field(name, value, inline);
    }
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Alert, embed).await;
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
