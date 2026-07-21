use crate::logging::{log, role_ref, role_ref_deleted, LogTier};
use crate::settings;
use serenity::all::{Context, EditRole, GuildId, LightMethod, Permissions, Request, RoleId, Route, UserId};
use sqlx::PgPool;

/// Renders what an unauthorized edit actually *changed* about a role's
/// permissions, as a Discord ```diff code block: `-` lines for permissions
/// the edit stripped away from the guarded baseline, `+` lines for ones it
/// granted. Permissions are boolean flags, so a diff is the natural shape,
/// and Discord renders `+`/`-` lines in green/red. Shows only the delta —
/// never the full restored baseline, which is uninformative (and often just
/// "None") when the point is which specific bits an attacker toggled.
fn permission_diff(baseline_bits: i64, actual_bits: i64) -> String {
    let baseline = Permissions::from_bits_truncate(baseline_bits as u64);
    let actual = Permissions::from_bits_truncate(actual_bits as u64);
    let added = actual & !baseline;
    let removed = baseline & !actual;

    let mut lines = Vec::new();
    for name in removed.get_permission_names() {
        lines.push(format!("- {name}"));
    }
    for name in added.get_permission_names() {
        lines.push(format!("+ {name}"));
    }
    if lines.is_empty() {
        // Drift was detected, so this shouldn't normally happen — be
        // defensive rather than emit an empty diff block.
        return "*No permission bits changed*".to_string();
    }
    format!("```diff\n{}\n```", lines.join("\n"))
}

pub async fn revert_permissions(
    ctx: &Context,
    pool: &PgPool,
    guild_id_i64: i64,
    role_id_i64: i64,
    target_bits: i64,
    actual_bits: i64,
) -> Result<(), serenity::Error> {
    let guild_id = GuildId::new(guild_id_i64 as u64);
    let role_id = RoleId::new(role_id_i64 as u64);
    tracing::warn!(guild_id = guild_id_i64, role_id = role_id_i64, target_bits, actual_bits, "guard action: reverting unauthorized role permission edit");
    guild_id
        .edit_role(&ctx.http, role_id, EditRole::new().permissions(Permissions::from_bits_truncate(target_bits as u64)))
        .await?;

    let embed = serenity::all::CreateEmbed::new()
        .title("Permission Edit Reverted")
        .field("Role", role_ref(role_id_i64), true)
        .field("Permission Changes (reverted)", permission_diff(target_bits, actual_bits), false)
        .color(0xED4245);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Alert, embed).await;
    Ok(())
}

pub async fn revert_name(
    ctx: &Context,
    pool: &PgPool,
    guild_id_i64: i64,
    role_id_i64: i64,
    target_name: &str,
    actual_name: &str,
) -> Result<(), serenity::Error> {
    let guild_id = GuildId::new(guild_id_i64 as u64);
    let role_id = RoleId::new(role_id_i64 as u64);
    tracing::warn!(guild_id = guild_id_i64, role_id = role_id_i64, target_name, actual_name, "guard action: reverting unauthorized role rename");
    guild_id.edit_role(&ctx.http, role_id, EditRole::new().name(target_name)).await?;

    let embed = serenity::all::CreateEmbed::new()
        .title("Role Rename Reverted")
        .field("Role", role_ref(role_id_i64), false)
        .field("Unauthorized Name", actual_name, true)
        .field("Restored Name", target_name, true)
        .color(0xED4245);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Alert, embed).await;
    Ok(())
}

/// Sets multiple roles' positions in ONE Discord API call — the whole point
/// being that Discord applies the entire list as a single transaction, with
/// no intermediate "some roles moved, others haven't yet" state for the
/// bot's own event handlers to misread as a fresh violation. Serenity's
/// `GuildId::edit_role_position` only ever sends a one-role list; this
/// builds the same request (`PATCH /guilds/{id}/roles`, which Discord's API
/// accepts a full list for) with every target included, bypassing that
/// convenience wrapper deliberately.
async fn bulk_reposition(
    ctx: &Context,
    guild_id_i64: i64,
    targets: &[(i64, u16)],
) -> Result<Vec<serenity::model::guild::Role>, serenity::Error> {
    let guild_id = GuildId::new(guild_id_i64 as u64);
    let body = format!(
        "[{}]",
        targets
            .iter()
            .map(|(role_id, position)| format!(r#"{{"id":"{role_id}","position":{position}}}"#))
            .collect::<Vec<_>>()
            .join(",")
    );
    let result = ctx
        .http
        .fire::<Vec<serenity::model::guild::Role>>(
            Request::new(Route::GuildRoles { guild_id }, LightMethod::Patch).body(Some(body.into_bytes())),
        )
        .await?;
    Ok(result)
}

/// Compares every guarded role's live position against its baseline and, if
/// ANY differ, corrects ALL of them in one atomic bulk call (see
/// `bulk_reposition`) rather than reverting role-by-role. Only roles below
/// the bot's own top role are guarded — the bot can never manage a role at
/// or above its own position via the Discord API regardless, so there's
/// nothing to enforce there. See the design note on
/// `crate::guard::position_drifted` for why bulk correction is what makes
/// absolute position guarding actually converge instead of oscillating.
///
/// Callers are responsible for the lockdown gate and for serializing
/// concurrent calls per guild (`position_reconcile_guard`) — this function
/// always does a fresh full scan and correction when called.
pub async fn reconcile_positions(ctx: &Context, pool: &PgPool, guild_id_i64: i64) -> Result<(), serenity::Error> {
    let guild_id = GuildId::new(guild_id_i64 as u64);
    let Some(bot_top) = crate::guard::bot_top_position(ctx, guild_id) else {
        return Ok(()); // can't locate the boundary this tick — skip rather than guess
    };
    let Some(guild) = ctx.cache.guild(guild_id).map(|g| g.clone()) else {
        return Ok(());
    };

    let mut targets = Vec::new();
    let mut any_drift = false;
    for role in guild.roles.values() {
        if role.id == guild_id.everyone_role() {
            continue; // @everyone's position is fixed by Discord, never a target
        }
        if role.position >= bot_top {
            continue; // above (or at) the bot — unmanageable, unguarded
        }
        let role_id_i64 = role.id.get() as i64;
        let Ok(Some(base)) = crate::guard::baseline::get_baseline(pool, guild_id_i64, role_id_i64).await else {
            continue; // no baseline yet, nothing to enforce
        };
        let Some(baseline_position) = base.position else { continue };
        let Ok(baseline_position_u16) = u16::try_from(baseline_position) else { continue };
        if crate::guard::position_drifted(baseline_position, role.position as i32) {
            any_drift = true;
        }
        targets.push((role_id_i64, baseline_position_u16));
    }

    if !any_drift {
        return Ok(());
    }

    tracing::warn!(guild_id = guild_id_i64, role_count = targets.len(), "guard action: reconciling all guarded role positions to baseline (bulk)");
    let returned = bulk_reposition(ctx, guild_id_i64, &targets).await?;

    // Empirical convergence check: Discord returns the authoritative
    // post-change position for every role in the guild. If it echoes back
    // exactly the integers we sent, this correction is final and the next
    // event should find no drift. If Discord silently normalized any of
    // them to a different value, comparing against the same absolute
    // integers will never converge — this is the one thing that decides
    // whether bulk correction actually fixes absolute position guarding or
    // just turns per-role oscillation into a slower per-correction one, so
    // it's logged loudly on every correction rather than assumed.
    let mut mismatches = Vec::new();
    for (role_id_i64, sent_position) in &targets {
        if let Some(returned_role) = returned.iter().find(|r| r.id.get() as i64 == *role_id_i64) {
            if returned_role.position != *sent_position {
                mismatches.push((*role_id_i64, *sent_position, returned_role.position));
            }
        }
    }
    if mismatches.is_empty() {
        tracing::info!(guild_id = guild_id_i64, "guard: bulk position correction confirmed — Discord echoed back exactly the positions sent");
    } else {
        tracing::error!(guild_id = guild_id_i64, ?mismatches, "guard: Discord returned DIFFERENT positions than sent — absolute position guarding cannot converge, this will keep re-triggering");
    }

    let embed = serenity::all::CreateEmbed::new()
        .title("Role Positions Reconciled")
        .field(
            "Detail",
            format!("An unauthorized role reorder was detected — {} guarded role(s) (below the bot's own role) were reset to their baseline positions in one bulk correction.", targets.len()),
            false,
        )
        .color(0xED4245);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Alert, embed).await;
    Ok(())
}

pub async fn strip_manual_grant(
    ctx: &Context,
    guild_id_i64: i64,
    role_id_i64: i64,
    member_id_i64: i64,
) -> Result<(), serenity::Error> {
    let guild_id = GuildId::new(guild_id_i64 as u64);
    let role_id = RoleId::new(role_id_i64 as u64);
    tracing::warn!(guild_id = guild_id_i64, role_id = role_id_i64, member_id = member_id_i64, "guard action: stripping manually-granted permission role from member");
    let member = guild_id.member(&ctx.http, UserId::new(member_id_i64 as u64)).await?;
    member.remove_role(&ctx.http, role_id).await?;
    Ok(())
}

pub async fn quarantine_actor(
    ctx: &Context,
    pool: &PgPool,
    guild_id_i64: i64,
    actor_id_i64: i64,
) -> Result<Vec<i64>, sqlx::Error> {
    let enabled = settings::get_bool_setting(
        pool,
        guild_id_i64,
        settings::QUARANTINE_ON_VIOLATION_KEY,
        settings::QUARANTINE_ON_VIOLATION_DEFAULT,
    )
    .await?;
    if !enabled {
        return Ok(Vec::new());
    }
    tracing::warn!(guild_id = guild_id_i64, actor_id = actor_id_i64, "guard action: quarantining actor's active sessions after a guard violation");

    let sessions = sqlx::query!(
        "SELECT s.id, r.permission_role_id
         FROM sessions s
         JOIN role_pairs r ON r.id = s.role_pair_id
         WHERE s.guild_id = $1 AND s.user_id = $2 AND s.revoked_at IS NULL AND s.expires_at > now()",
        guild_id_i64,
        actor_id_i64
    )
    .fetch_all(pool)
    .await?;

    let guild_id = GuildId::new(guild_id_i64 as u64);
    let mut stripped = Vec::new();
    for session in &sessions {
        let role_id = RoleId::new(session.permission_role_id as u64);
        if let Ok(member) = guild_id.member(&ctx.http, UserId::new(actor_id_i64 as u64)).await {
            if let Err(e) = member.remove_role(&ctx.http, role_id).await {
                tracing::error!(error = ?e, guild_id = guild_id_i64, actor_id = actor_id_i64, session_id = session.id, role_id = session.permission_role_id, "quarantine: failed to remove role from member");
            }
        }
        if sqlx::query!(
            "UPDATE sessions SET revoked_at = now(), revoke_reason = 'quarantine' WHERE id = $1",
            session.id
        )
        .execute(pool)
        .await
        .is_ok()
        {
            stripped.push(session.permission_role_id);
        }
    }
    Ok(stripped)
}

/// `actor_id`: `Some(user_id)` when the deletion was attributed to someone
/// via the audit log (the reactive `handle_role_delete` path) — that actor's
/// own sessions get quarantined too, so they can't just keep deleting the
/// role back. `None` when there's no known actor (the periodic sweep's
/// recreation path, which isn't driven by any audit-log entry).
pub async fn recreate_role(
    ctx: &Context,
    pool: &PgPool,
    guild_id_i64: i64,
    old_role_id_i64: i64,
    baseline: &crate::guard::baseline::RoleBaseline,
    is_registered: bool,
    actor_id: Option<i64>,
) -> Result<serenity::model::guild::Role, serenity::Error> {
    let guild_id = GuildId::new(guild_id_i64 as u64);
    tracing::warn!(guild_id = guild_id_i64, old_role_id = old_role_id_i64, is_registered, actor_id = ?actor_id, "guard action: recreating deleted guarded role from baseline");
    let name = baseline.name.as_deref().unwrap_or("recreated-role");
    let mut builder = EditRole::new()
        .name(name)
        .permissions(Permissions::from_bits_truncate(baseline.permissions as u64));
    if let Some(position) = baseline.position {
        builder = builder.position(u16::try_from(position).unwrap_or(0));
    }
    let new_role = guild_id.create_role(&ctx.http, builder).await?;

    if let Err(e) = sqlx::query!(
        "UPDATE role_pairs SET standard_role_id = $1 WHERE guild_id = $2 AND standard_role_id = $3",
        new_role.id.get() as i64,
        guild_id_i64,
        old_role_id_i64
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = ?e, guild_id = guild_id_i64, old_role_id = old_role_id_i64, new_role_id = new_role.id.get() as i64, "guard: failed to repoint role_pairs.standard_role_id after role recreation");
    }
    if let Err(e) = sqlx::query!(
        "UPDATE role_pairs SET permission_role_id = $1 WHERE guild_id = $2 AND permission_role_id = $3",
        new_role.id.get() as i64,
        guild_id_i64,
        old_role_id_i64
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = ?e, guild_id = guild_id_i64, old_role_id = old_role_id_i64, new_role_id = new_role.id.get() as i64, "guard: failed to repoint role_pairs.permission_role_id after role recreation");
    }
    if let Err(e) = crate::guard::baseline::upsert_baseline(
        pool,
        guild_id_i64,
        new_role.id.get() as i64,
        baseline.permissions,
        baseline.name.as_deref(),
        baseline.position,
        None,
    )
    .await
    {
        tracing::error!(error = ?e, guild_id = guild_id_i64, old_role_id = old_role_id_i64, new_role_id = new_role.id.get() as i64, "guard: failed to upsert role_baselines after role recreation");
    }
    // The new role gets its own baseline row above, keyed by its own id —
    // the old row is never updated in place (different role_id), so it must
    // be deleted explicitly. Leaving it would make the sweep see it as a
    // still-missing baseline on every future tick and recreate the role
    // again, unboundedly, once the sweep no longer scopes strictly to
    // registered roles.
    if let Err(e) = crate::guard::baseline::delete_baseline(pool, guild_id_i64, old_role_id_i64).await {
        tracing::error!(error = ?e, guild_id = guild_id_i64, old_role_id = old_role_id_i64, new_role_id = new_role.id.get() as i64, "guard: failed to delete old baseline after role recreation");
    }

    let mut embed = serenity::all::CreateEmbed::new()
        .title(if is_registered { "Registered role recreated" } else { "Role recreated (lockdown)" })
        .field("Old Role", role_ref_deleted(old_role_id_i64), true)
        .field("New Role", role_ref(new_role.id.get() as i64), true)
        .field(
            "Note",
            "The role was deleted and has been recreated from its guarded baseline. Re-check any external references to the old role ID.",
            false,
        );
    if let Some(actor_id_i64) = actor_id {
        let stripped = quarantine_actor(ctx, pool, guild_id_i64, actor_id_i64).await.unwrap_or_default();
        let quarantine_note = if stripped.is_empty() {
            "No sessions quarantined (the deleter had none active, or quarantine-on-violation is off)."
        } else {
            "The deleter's own active session(s) were quarantined."
        };
        embed = embed
            .field("Deleted By", crate::logging::user_ref(actor_id_i64), true)
            .field("Quarantine", quarantine_note, false);
    }
    let embed = embed.color(0xED4245);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Alert, embed).await;
    Ok(new_role)
}
