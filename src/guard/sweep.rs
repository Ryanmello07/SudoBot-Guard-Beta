use crate::guard::{baseline, name_drifted, permission_drifted, position_drifted, reaction};
use serenity::all::{Context, GuildId};
use sqlx::PgPool;

/// One full pass over a guild's roles and members, comparing live state
/// against the guarded baseline/registry. Independent of the reactive
/// audit-log path — this is the safety net for anything that path could
/// ever miss (a dropped gateway event, the bot being offline when a change
/// happened).
pub async fn run_once(ctx: &Context, pool: &PgPool, guild_id: GuildId) {
    let guild_id_i64 = guild_id.get() as i64;
    let Some(guild) = ctx.cache.guild(guild_id).map(|g| g.clone()) else {
        tracing::warn!(%guild_id, "guard sweep: guild not in cache, skipping");
        return;
    };

    let lockdown_enabled = crate::guard::is_lockdown_enabled(pool, guild_id_i64).await.unwrap_or(true);

    // 1. Every role's permission bitmask vs baseline; registered roles'
    //    name/position vs baseline too. Skipped entirely when lockdown is
    //    off — only manual-grant reversion and role recreation (steps 2-3
    //    below) stay active regardless of lockdown state.
    if lockdown_enabled {
        for role in guild.roles.values() {
            let role_id_i64 = role.id.get() as i64;
            let Ok(Some(base)) = baseline::get_baseline(pool, guild_id_i64, role_id_i64).await else {
                continue; // no baseline yet — Task 6's backfill runs at startup, this is belt-and-suspenders
            };
            let is_registered = baseline::is_registered_role(pool, guild_id_i64, role_id_i64)
                .await
                .unwrap_or(false);

            let actual_bits = role.permissions.bits() as i64;
            if permission_drifted(base.permissions, actual_bits) {
                let _ = reaction::revert_permissions(ctx, pool, guild_id_i64, role_id_i64, base.permissions).await;
            }
            if let Some(baseline_name) = &base.name {
                if name_drifted(baseline_name, &role.name, is_registered) {
                    let _ = reaction::revert_name(ctx, pool, guild_id_i64, role_id_i64, baseline_name).await;
                }
            }
            if let Some(baseline_position) = base.position {
                if position_drifted(baseline_position, role.position as i32) {
                    let _ = reaction::revert_position(ctx, pool, guild_id_i64, role_id_i64, baseline_position).await;
                }
            }
        }
    }

    // 2. Registered roles that no longer exist among the guild's live roles.
    //
    // Known edge case (not architecturally fixed here): if a registered role
    // is deleted and the reactive handler (`audit_handler::handle_role_delete`
    // -> `reaction::recreate_role`) recreates it right as a sweep tick reads
    // `role_pairs`/`role_baselines` below, there's a narrow race where this
    // sweep could still see the not-yet-repointed old role ID, find it
    // missing from the live guild, and attempt a second recreation. Low
    // probability given the 5-minute sweep cadence versus the sub-second
    // window the race requires.
    if let Ok(rows) = sqlx::query!(
        "SELECT DISTINCT role_id FROM role_baselines
         WHERE guild_id = $1 AND role_id IN (
             SELECT standard_role_id FROM role_pairs WHERE guild_id = $1
             UNION
             SELECT permission_role_id FROM role_pairs WHERE guild_id = $1
         )",
        guild_id_i64
    )
    .fetch_all(pool)
    .await
    {
        for row in rows {
            let role_id = serenity::all::RoleId::new(row.role_id as u64);
            if !guild.roles.contains_key(&role_id) {
                if let Ok(Some(base)) = baseline::get_baseline(pool, guild_id_i64, row.role_id).await {
                    let _ = reaction::recreate_role(ctx, pool, guild_id_i64, row.role_id, &base).await;
                }
            }
        }
    }

    // 3. Every member holding a registered permission role without an
    //    active session backing it — an orphaned grant the reactive path
    //    never saw (e.g. it happened while the bot was offline).
    let Ok(registered) = baseline::registered_permission_role_ids(pool, guild_id_i64).await else {
        return;
    };
    for permission_role_id_i64 in registered {
        let role_id = serenity::all::RoleId::new(permission_role_id_i64 as u64);
        // `guild.members` is the gateway's member cache, not a REST fetch of
        // every member — above Discord's large-guild threshold (~250
        // members without full member-list chunking enabled), some members
        // may not be cached. This is a known scope limitation, deliberate
        // per the original design to keep the sweep cheap, not a bug: it
        // means this orphaned-grant safety net could miss a manually-granted
        // role held by an uncached member.
        for member in guild.members.values() {
            if !member.roles.contains(&role_id) {
                continue;
            }
            let member_id_i64 = member.user.id.get() as i64;
            let has_active_session = sqlx::query!(
                "SELECT 1 AS present FROM sessions s
                 JOIN role_pairs r ON r.id = s.role_pair_id
                 WHERE s.guild_id = $1 AND s.user_id = $2 AND r.permission_role_id = $3 AND s.revoked_at IS NULL",
                guild_id_i64,
                member_id_i64,
                permission_role_id_i64
            )
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
            .is_some();

            if !has_active_session {
                // No audit-log entry drives this path, so there's no known
                // granter to quarantine — per the design spec (§6), only the
                // revert and log entry apply here. `member_id_i64` is the
                // person *holding* the orphaned role, not who granted it;
                // conflating the two would quarantine an innocent holder.
                let _ = reaction::strip_manual_grant(ctx, guild_id_i64, permission_role_id_i64, member_id_i64).await;

                let embed = serenity::all::CreateEmbed::new()
                    .title("Orphaned permission-role grant reverted (found by sweep)")
                    .description(format!("<@{member_id_i64}> held <@&{permission_role_id_i64}> with no active session backing it — reverted. No audit-log entry was available to identify who granted it, so no quarantine was applied."))
                    .color(0xED4245);
                let _ = crate::logging::log(pool, &ctx.http, guild_id_i64, crate::logging::LogTier::Alert, embed).await;
            }
        }
    }
}
