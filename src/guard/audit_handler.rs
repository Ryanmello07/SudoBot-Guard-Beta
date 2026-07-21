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
        Action::Role(RoleAction::Create) => handle_role_create(ctx, pool, guild_id_i64, entry).await,
        Action::Role(RoleAction::Update) => handle_role_update(ctx, pool, guild_id_i64, entry).await,
        Action::Role(RoleAction::Delete) => handle_role_delete(ctx, pool, guild_id_i64, entry).await,
        Action::Member(MemberAction::RoleUpdate) => {
            handle_member_role_update(ctx, pool, guild_id_i64, entry).await
        }
        _ => {}
    }
}

/// Quarantines the actor behind a permission/name/position edit — nothing
/// else. The actual revert already happened, instantly, via the raw gateway
/// event in `main.rs`'s `guild_role_update` (which has no actor info to
/// quarantine with). This path exists purely to attribute the edit to
/// whoever made it (only the audit log carries that) and act on it; it must
/// never call any `revert_*` function itself — doing so reintroduces the
/// exact double-revert bug that got this path removed in the first place.
///
/// Detection compares the audit entry's own recorded `new` values against
/// the baseline, not the role's current live state — by the time this
/// (slower) audit-log entry arrives, the gateway/sweep paths have typically
/// already reverted it, so live state would show no drift even though a
/// violation genuinely occurred. Position uses the same baseline-equality
/// check as permission/name (see `position_drifted`), scoped to roles below
/// the bot's own top role — a role at or above it isn't guarded at all,
/// since the bot can't manage it regardless.
async fn handle_role_update(ctx: &Context, pool: &PgPool, guild_id_i64: i64, entry: &AuditLogEntry) {
    let lockdown_enabled = crate::guard::is_lockdown_enabled(pool, guild_id_i64).await.unwrap_or(true);
    if !lockdown_enabled {
        return; // matches guild_role_update's own gate: not enforced, not a violation
    }

    let Some(target_id) = entry.target_id else { return };
    let role_id_i64 = target_id.get() as i64;

    let Ok(Some(base)) = baseline::get_baseline(pool, guild_id_i64, role_id_i64).await else {
        return;
    };

    let Some(changes) = &entry.changes else { return };
    let mut violated = false;
    for change in changes {
        match change {
            Change::Permissions { new: Some(new_perms), .. } => {
                if permission_drifted(base.permissions, new_perms.bits() as i64) {
                    violated = true;
                }
            }
            Change::Name { new: Some(new_name), .. } => {
                if let Some(baseline_name) = &base.name {
                    if name_drifted(baseline_name, new_name) {
                        violated = true;
                    }
                }
            }
            Change::Position { new: Some(new_position), .. } => {
                if let Some(baseline_position) = base.position {
                    let guild_id = serenity::all::GuildId::new(guild_id_i64 as u64);
                    let below_bot = crate::guard::bot_top_position(ctx, guild_id)
                        .map(|bot_top| (*new_position as u16) < bot_top)
                        .unwrap_or(false);
                    if below_bot && position_drifted(baseline_position, *new_position as i32) {
                        violated = true;
                    }
                }
            }
            _ => {}
        }
    }
    if !violated {
        return;
    }

    let actor_id_i64 = entry.user_id.get() as i64;
    let stripped = reaction::quarantine_actor(ctx, pool, guild_id_i64, actor_id_i64).await.unwrap_or_default();
    if stripped.is_empty() {
        // Nothing to report — the revert was already logged separately by
        // guild_role_update. Don't add a second embed saying nothing happened.
        return;
    }

    let embed = serenity::all::CreateEmbed::new()
        .title("Actor Quarantined (Role Tampering)")
        .field("Role", crate::logging::role_ref(role_id_i64), true)
        .field("Actor", crate::logging::user_ref(actor_id_i64), true)
        .field("Quarantine", "The actor's own active session(s) were quarantined.", false)
        .color(0xED4245);
    let _ = crate::logging::log(pool, &ctx.http, guild_id_i64, crate::logging::LogTier::Alert, embed).await;
}

/// Reverts a role *creation* the same way other unauthorized changes get
/// reverted — by undoing the action outright, not by patching state after
/// the fact. Position-drift guarding could in principle "fix" every other
/// role's shifted position once a role is inserted, but Discord's positions
/// are a dense shared ordering: inserting a role changes the total count,
/// so there's no way to revert everyone else back to their old absolute
/// position without the count matching too — this caused the sweep to
/// re-detect and re-revert the same drift on every tick, indefinitely.
/// Deleting the new role removes the count mismatch at its source, and
/// every other role's position snaps back on its own. Self-filtered for
/// free: `handle_entry` already drops entries where `entry.user_id` is the
/// bot itself, so this never fires for `reaction::recreate_role`'s own
/// role-creation (which is logged as the bot's own action).
async fn handle_role_create(ctx: &Context, pool: &PgPool, guild_id_i64: i64, entry: &AuditLogEntry) {
    let lockdown_enabled = crate::guard::is_lockdown_enabled(pool, guild_id_i64).await.unwrap_or(true);
    if !lockdown_enabled {
        return; // outside lockdown, new roles are just onboarded (see guild_role_create)
    }

    let Some(target_id) = entry.target_id else { return };
    let role_id_i64 = target_id.get() as i64;
    let guild_id = serenity::all::GuildId::new(guild_id_i64 as u64);
    let role_id = serenity::all::RoleId::new(role_id_i64 as u64);

    if let Err(e) = guild_id.delete_role(&ctx.http, role_id).await {
        tracing::error!(error = ?e, guild_id = guild_id_i64, role_id = role_id_i64, "guard: failed to delete role created during lockdown");
        return;
    }
    if let Err(e) = baseline::delete_baseline(pool, guild_id_i64, role_id_i64).await {
        tracing::error!(error = ?e, guild_id = guild_id_i64, role_id = role_id_i64, "guard: failed to remove baseline for role deleted after lockdown creation");
    }

    let actor_id_i64 = entry.user_id.get() as i64;
    let stripped = reaction::quarantine_actor(ctx, pool, guild_id_i64, actor_id_i64).await.unwrap_or_default();
    let quarantine_note = if stripped.is_empty() {
        "No sessions quarantined (the creator had none active, or quarantine-on-violation is off)."
    } else {
        "The creator's own active session(s) were quarantined."
    };

    let embed = serenity::all::CreateEmbed::new()
        .title("Role Creation Reverted (Lockdown)")
        .field("Role", crate::logging::role_ref_deleted(role_id_i64), true)
        .field("Created By", crate::logging::user_ref(actor_id_i64), true)
        .field(
            "Reason",
            "The role was created while lockdown was active — deleted. Lockdown treats the role list as frozen.",
            false,
        )
        .field("Quarantine", quarantine_note, false)
        .color(0xED4245);
    let _ = crate::logging::log(pool, &ctx.http, guild_id_i64, crate::logging::LogTier::Alert, embed).await;
}

/// Registered roles are always recreated on deletion. Unregistered roles
/// are only recreated while lockdown is active — a full role-set freeze,
/// symmetric with `handle_role_create` reverting new roles under lockdown.
/// Outside lockdown, deleting an ordinary role is left alone.
async fn handle_role_delete(ctx: &Context, pool: &PgPool, guild_id_i64: i64, entry: &AuditLogEntry) {
    let Some(target_id) = entry.target_id else { return };
    let role_id_i64 = target_id.get() as i64;

    let is_registered = baseline::is_registered_role(pool, guild_id_i64, role_id_i64)
        .await
        .unwrap_or(false);
    if !is_registered {
        let lockdown_enabled = crate::guard::is_lockdown_enabled(pool, guild_id_i64).await.unwrap_or(true);
        if !lockdown_enabled {
            return; // not registered, and lockdown isn't active — deletion is fine, guard doesn't care
        }
    }

    if !crate::guard::recreation_guard::try_claim(guild_id_i64, role_id_i64) {
        return; // already being recreated (a duplicate delivery of this same delete, or the sweep)
    }

    let Ok(Some(base)) = baseline::get_baseline(pool, guild_id_i64, role_id_i64).await else {
        crate::guard::recreation_guard::release(guild_id_i64, role_id_i64);
        return;
    };
    let _ = reaction::recreate_role(
        ctx,
        pool,
        guild_id_i64,
        role_id_i64,
        &base,
        is_registered,
        Some(entry.user_id.get() as i64),
    )
    .await;
    crate::guard::recreation_guard::release(guild_id_i64, role_id_i64);
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

                    let quarantine_note = if stripped.is_empty() {
                        // An empty result can't distinguish "granter had no
                        // active sessions" from "quarantine-on-violation is
                        // off" without a new query, which is out of scope —
                        // so state both possibilities honestly rather than
                        // assert one we can't verify.
                        "No sessions quarantined (the granter had none active, or quarantine-on-violation is off).".to_string()
                    } else {
                        "The granter's own active session(s) were quarantined.".to_string()
                    };
                    let embed = serenity::all::CreateEmbed::new()
                        .title("Manual Permission-Role Grant Reverted")
                        .field("Member", crate::logging::user_ref(member_id_i64), true)
                        .field("Role", crate::logging::role_ref(added_role_id_i64), true)
                        .field("Granted By", crate::logging::user_ref(entry.user_id.get() as i64), true)
                        .field("Quarantine", quarantine_note, false)
                        .color(0xED4245);
                    let _ = crate::logging::log(pool, &ctx.http, guild_id_i64, crate::logging::LogTier::Alert, embed).await;
                }
            }
        }
    }
}
