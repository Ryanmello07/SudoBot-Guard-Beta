use serenity::all::{Context, GuildId, RoleId, UserId};
use serenity::futures::StreamExt;
use sqlx::PgPool;

/// Records that `user_id` currently holds each of `role_ids`, if not already
/// recorded. Deliberately insert-only: a member update that shows a role
/// having been REMOVED is never used to delete a row here. Discord fires
/// GUILD_MEMBER_UPDATE for a member the instant a role they held gets
/// deleted -- and it lands before the audit-log-driven role-recreation
/// handler that needs to know who held it (confirmed live: the member
/// update arrived ~33ms ahead of `handle_role_delete`). A delete-on-removal
/// reactive handler would erase the very data that handler exists to read.
/// Rows only ever get pruned by the periodic full resync (`sync_from_rest`),
/// which tolerates being up to one sweep interval stale; that staleness is
/// what lets a role's prior holders survive its own deletion.
pub async fn record_roles(pool: &PgPool, guild_id_i64: i64, user_id_i64: i64, role_ids: &[RoleId]) {
    for role_id in role_ids {
        if let Err(e) = sqlx::query!(
            "INSERT INTO role_members (guild_id, role_id, user_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            guild_id_i64,
            role_id.get() as i64,
            user_id_i64
        )
        .execute(pool)
        .await
        {
            tracing::error!(error = ?e, guild_id = guild_id_i64, user_id = user_id_i64, role_id = role_id.get() as i64, "guard: failed to record role membership");
        }
    }
}

/// Removes every row for a member who has left the guild -- the one case
/// where deleting eagerly is correct, since there's no future reassignment
/// scenario for someone no longer in the guild.
pub async fn forget_member(pool: &PgPool, guild_id_i64: i64, user_id_i64: i64) {
    if let Err(e) = sqlx::query!(
        "DELETE FROM role_members WHERE guild_id = $1 AND user_id = $2",
        guild_id_i64,
        user_id_i64
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = ?e, guild_id = guild_id_i64, user_id = user_id_i64, "guard: failed to clear role membership for departed member");
    }
}

/// Full reconciliation against a live REST member listing -- corrects any
/// drift the insert-only reactive path can't (a role removed without ever
/// costing a reassignment, a missed event during a disconnect). Run at
/// startup/guild join and on every periodic sweep tick. Aborts without
/// writing anything if the member listing can't be fully read, rather than
/// replacing good data with a partial roster.
pub async fn sync_from_rest(ctx: &Context, pool: &PgPool, guild_id: GuildId) {
    let guild_id_i64 = guild_id.get() as i64;
    let mut members = guild_id.members_iter(&ctx.http).boxed();
    let mut role_ids: Vec<i64> = Vec::new();
    let mut user_ids: Vec<i64> = Vec::new();
    while let Some(member_result) = members.next().await {
        match member_result {
            Ok(member) => {
                let user_id_i64 = member.user.id.get() as i64;
                for role in &member.roles {
                    role_ids.push(role.get() as i64);
                    user_ids.push(user_id_i64);
                }
            }
            Err(e) => {
                tracing::error!(error = ?e, %guild_id, "guard: failed to fetch a page of guild members during role_members resync -- aborting this sync rather than reconciling from a partial roster");
                return;
            }
        }
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(error = ?e, %guild_id, "guard: failed to start transaction for role_members resync");
            return;
        }
    };
    if let Err(e) = sqlx::query!("DELETE FROM role_members WHERE guild_id = $1", guild_id_i64).execute(&mut *tx).await {
        tracing::error!(error = ?e, %guild_id, "guard: failed to clear role_members before resync");
        return;
    }
    if let Err(e) = sqlx::query!(
        "INSERT INTO role_members (guild_id, role_id, user_id) SELECT $1, r, u FROM UNNEST($2::BIGINT[], $3::BIGINT[]) AS t(r, u)",
        guild_id_i64,
        &role_ids,
        &user_ids
    )
    .execute(&mut *tx)
    .await
    {
        tracing::error!(error = ?e, %guild_id, "guard: failed to insert resynced role_members rows");
        return;
    }
    if let Err(e) = tx.commit().await {
        tracing::error!(error = ?e, %guild_id, "guard: failed to commit role_members resync");
    }
}

/// Every member recorded as holding `role_id` -- read by
/// `reaction::recreate_role` to determine who to reassign a recreated role
/// to. May be up to one sweep interval stale by design (see `record_roles`).
pub async fn holders(pool: &PgPool, guild_id_i64: i64, role_id_i64: i64) -> Vec<UserId> {
    match sqlx::query_scalar!(
        "SELECT user_id FROM role_members WHERE guild_id = $1 AND role_id = $2",
        guild_id_i64,
        role_id_i64
    )
    .fetch_all(pool)
    .await
    {
        Ok(ids) => ids.into_iter().map(|id| UserId::new(id as u64)).collect(),
        Err(e) => {
            tracing::error!(error = ?e, guild_id = guild_id_i64, role_id = role_id_i64, "guard: failed to read role_members holders");
            Vec::new()
        }
    }
}

/// Drops every row for a role that's gone for good -- called after
/// `recreate_role` has already read `holders` for it. Not required for
/// correctness (the periodic resync would eventually reconcile these away
/// too, since no member will ever show this role_id again), just hygiene
/// against unbounded growth from a guild that deletes roles often.
pub async fn forget_role(pool: &PgPool, guild_id_i64: i64, role_id_i64: i64) {
    if let Err(e) = sqlx::query!(
        "DELETE FROM role_members WHERE guild_id = $1 AND role_id = $2",
        guild_id_i64,
        role_id_i64
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = ?e, guild_id = guild_id_i64, role_id = role_id_i64, "guard: failed to forget defunct role from role_members");
    }
}
