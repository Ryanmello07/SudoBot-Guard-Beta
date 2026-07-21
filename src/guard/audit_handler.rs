use crate::guard::{baseline, is_manual_grant, name_drifted, permission_drifted, position_drifted, reaction};
use serenity::all::Context;
use serenity::model::guild::audit_log::{Action, AuditLogEntry, Change, MemberAction, RoleAction};
use sqlx::PgPool;

pub async fn handle_entry(
    ctx: &Context,
    pool: &PgPool,
    guild_id_i64: i64,
    entry: &AuditLogEntry,
    bot_user_id: u64,
) {
    if entry.user_id.get() == bot_user_id {
        return; // the bot's own action (a revert, a grant, a baseline update) — never re-process it
    }

    match entry.action {
        Action::Role(RoleAction::Update) => handle_role_update(ctx, pool, guild_id_i64, entry).await,
        Action::Role(RoleAction::Delete) => handle_role_delete(ctx, pool, guild_id_i64, entry).await,
        Action::Member(MemberAction::RoleUpdate) => {
            handle_member_role_update(ctx, pool, guild_id_i64, entry).await
        }
        _ => {}
    }
}

async fn handle_role_update(ctx: &Context, pool: &PgPool, guild_id_i64: i64, entry: &AuditLogEntry) {
    let lockdown_enabled = crate::guard::is_lockdown_enabled(pool, guild_id_i64).await.unwrap_or(true);
    if !lockdown_enabled {
        return;
    }

    let Some(target_id) = entry.target_id else { return };
    let role_id_i64 = target_id.get() as i64;

    let is_registered = match baseline::is_registered_role(pool, guild_id_i64, role_id_i64).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "guard: failed to check role registration");
            return;
        }
    };
    let Ok(Some(base)) = baseline::get_baseline(pool, guild_id_i64, role_id_i64).await else {
        // No baseline yet means this role predates both the startup backfill
        // and guild_role_create's on-creation capture ever running against
        // it (e.g. the bot hasn't restarted since the role was created, and
        // guild_role_create's handler wasn't wired up at role-creation time
        // for some reason). The reconciliation sweep does NOT backfill this —
        // it explicitly skips roles with no baseline — so this role stays
        // unguarded until the next startup backfill runs.
        return;
    };

    let Some(changes) = &entry.changes else { return };
    for change in changes {
        match change {
            Change::Permissions { new: Some(new_perms), .. } => {
                let new_bits = new_perms.bits() as i64;
                if permission_drifted(base.permissions, new_bits) {
                    let _ = reaction::revert_permissions(ctx, pool, guild_id_i64, role_id_i64, base.permissions).await;
                }
            }
            Change::Name { new: Some(new_name), .. } => {
                if let Some(baseline_name) = &base.name {
                    if name_drifted(baseline_name, new_name, is_registered) {
                        let _ = reaction::revert_name(ctx, pool, guild_id_i64, role_id_i64, baseline_name).await;
                    }
                }
            }
            Change::Position { new: Some(new_position), .. } => {
                if let Some(baseline_position) = base.position {
                    if position_drifted(baseline_position, *new_position as i32) {
                        let _ = reaction::revert_position(ctx, pool, guild_id_i64, role_id_i64, baseline_position).await;
                    }
                }
            }
            _ => {}
        }
    }
}

async fn handle_role_delete(ctx: &Context, pool: &PgPool, guild_id_i64: i64, entry: &AuditLogEntry) {
    let Some(target_id) = entry.target_id else { return };
    let role_id_i64 = target_id.get() as i64;

    let Ok(true) = baseline::is_registered_role(pool, guild_id_i64, role_id_i64).await else {
        return; // not a registered role — deletion is fine, guard doesn't care
    };
    let Ok(Some(base)) = baseline::get_baseline(pool, guild_id_i64, role_id_i64).await else {
        return;
    };
    let _ = reaction::recreate_role(ctx, pool, guild_id_i64, role_id_i64, &base).await;
}

async fn handle_member_role_update(ctx: &Context, pool: &PgPool, guild_id_i64: i64, entry: &AuditLogEntry) {
    let Some(target_id) = entry.target_id else { return };
    let member_id_i64 = target_id.get() as i64;

    let Ok(registered) = baseline::registered_permission_role_ids(pool, guild_id_i64).await else {
        return;
    };
    let Some(changes) = &entry.changes else { return };
    for change in changes {
        if let Change::RolesAdded { new: Some(added), .. } = change {
            for affected in added {
                let added_role_id_i64 = affected.id.get() as i64;
                if is_manual_grant(added_role_id_i64, &registered) {
                    let _ = reaction::strip_manual_grant(ctx, guild_id_i64, added_role_id_i64, member_id_i64).await;
                    let stripped = reaction::quarantine_actor(ctx, pool, guild_id_i64, entry.user_id.get() as i64)
                        .await
                        .unwrap_or_default();

                    let embed = serenity::all::CreateEmbed::new()
                        .title("Manual permission-role grant reverted")
                        .description(format!(
                            "<@{member_id_i64}> was manually granted <@&{added_role_id_i64}> by <@{}> — reverted.{}",
                            entry.user_id,
                            if stripped.is_empty() {
                                String::new()
                            } else {
                                format!(" <@{}>'s own active sessions were quarantined.", entry.user_id)
                            }
                        ))
                        .color(0xED4245);
                    let _ = crate::logging::log(pool, &ctx.http, guild_id_i64, crate::logging::LogTier::Alert, embed).await;
                }
            }
        }
    }
}
