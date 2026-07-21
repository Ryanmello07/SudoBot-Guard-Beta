use crate::guard::baseline;
use serenity::all::{Context, GuildId};
use sqlx::PgPool;

/// Walks every role in the guild and writes its baseline.
///
/// `force = false` (the routine startup path): skip any role that already
/// has a baseline row, so a restart never resets a role's guarded state to
/// whatever it happens to be at that moment.
///
/// `force = true` (`/lockdown on`'s path): unconditionally overwrite every
/// role's baseline with its current live state — this is the point of
/// turning lockdown on: trust whatever is live right now.
pub async fn sync_role_baselines(
    ctx: &Context,
    pool: &PgPool,
    guild_id: GuildId,
    force: bool,
    updated_by: Option<i64>,
) {
    let Some(guild) = ctx.cache.guild(guild_id).map(|g| g.clone()) else {
        tracing::warn!(%guild_id, "guard: guild not in cache, skipping baseline sync");
        return;
    };
    let guild_id_i64 = guild_id.get() as i64;

    for role in guild.roles.values() {
        let role_id_i64 = role.id.get() as i64;

        if !force {
            match baseline::get_baseline(pool, guild_id_i64, role_id_i64).await {
                Ok(Some(_)) => continue,
                Ok(None) => {}
                Err(e) => {
                    tracing::error!(error = ?e, %guild_id, role_id = role_id_i64, "guard: failed to check baseline during sync");
                    continue;
                }
            }
        }

        // Name and position are captured for every role, not just
        // registered ones — the whole role list is kept a carbon copy of
        // its baseline state, matching how permissions are always guarded.
        if let Err(e) = baseline::upsert_baseline(
            pool,
            guild_id_i64,
            role_id_i64,
            role.permissions.bits() as i64,
            Some(&role.name),
            Some(role.position as i32),
            updated_by,
        )
        .await
        {
            tracing::error!(error = ?e, %guild_id, role_id = role_id_i64, "guard: failed to sync baseline");
        }
    }

    // `force = true` also reconciles: baseline rows for roles that no
    // longer exist live (leftovers from a deleted role whose recreation
    // path failed, or from before `recreate_role` started cleaning up its
    // own old row) get deleted. Without this, `/lockdown on` would snapshot
    // "current roles plus every stale baseline ever left behind" instead of
    // "current roles" — and the sweep's lockdown-wide missing-role check
    // would then treat every stale row as a role to recreate, forever.
    // Never run on the `force = false` startup path: a registered role that
    // was deleted while the bot was offline needs its baseline intact so
    // the very next sweep tick can recreate it — pruning here would lose it
    // permanently.
    if force {
        let live_role_ids: Vec<i64> = guild.roles.keys().map(|id| id.get() as i64).collect();
        if live_role_ids.is_empty() {
            tracing::warn!(%guild_id, "guard: live role set was empty during force resync, skipping stale-baseline prune");
        } else if let Err(e) = sqlx::query!(
            "DELETE FROM role_baselines WHERE guild_id = $1 AND role_id <> ALL($2)",
            guild_id_i64,
            &live_role_ids
        )
        .execute(pool)
        .await
        {
            tracing::error!(error = ?e, %guild_id, "guard: failed to prune stale baselines during force resync");
        }
    }
}
