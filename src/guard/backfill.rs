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

        let is_registered = baseline::is_registered_role(pool, guild_id_i64, role_id_i64)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = ?e, %guild_id, role_id = role_id_i64, "guard: failed to check role registration during baseline sync");
                false
            });
        let name = is_registered.then(|| role.name.clone());
        // Position is captured for every role, not just registered ones —
        // it's tied to Discord's role hierarchy, not just cosmetic identity.
        let position = Some(role.position as i32);

        if let Err(e) = baseline::upsert_baseline(
            pool,
            guild_id_i64,
            role_id_i64,
            role.permissions.bits() as i64,
            name.as_deref(),
            position,
            updated_by,
        )
        .await
        {
            tracing::error!(error = ?e, %guild_id, role_id = role_id_i64, "guard: failed to sync baseline");
        }
    }
}
