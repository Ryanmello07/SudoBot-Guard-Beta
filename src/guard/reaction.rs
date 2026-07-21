use crate::logging::{log, LogTier};
use crate::settings;
use serenity::all::{Context, EditRole, GuildId, Permissions, RoleId, UserId};
use sqlx::PgPool;

pub async fn revert_permissions(
    ctx: &Context,
    pool: &PgPool,
    guild_id_i64: i64,
    role_id_i64: i64,
    target_bits: i64,
) -> Result<(), serenity::Error> {
    let guild_id = GuildId::new(guild_id_i64 as u64);
    let role_id = RoleId::new(role_id_i64 as u64);
    guild_id
        .edit_role(&ctx.http, role_id, EditRole::new().permissions(Permissions::from_bits_truncate(target_bits as u64)))
        .await?;

    let embed = serenity::all::CreateEmbed::new()
        .title("Permission edit reverted")
        .description(format!("<@&{role_id_i64}>'s permissions were reverted to the guarded baseline."))
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
) -> Result<(), serenity::Error> {
    let guild_id = GuildId::new(guild_id_i64 as u64);
    let role_id = RoleId::new(role_id_i64 as u64);
    guild_id.edit_role(&ctx.http, role_id, EditRole::new().name(target_name)).await?;

    let embed = serenity::all::CreateEmbed::new()
        .title("Role rename reverted")
        .description(format!("<@&{role_id_i64}>'s name was reverted to the guarded baseline."))
        .color(0xED4245);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Alert, embed).await;
    Ok(())
}

pub async fn revert_position(
    ctx: &Context,
    pool: &PgPool,
    guild_id_i64: i64,
    role_id_i64: i64,
    target_position: i32,
) -> Result<(), serenity::Error> {
    let guild_id = GuildId::new(guild_id_i64 as u64);
    let role_id = RoleId::new(role_id_i64 as u64);
    let position_u16 = u16::try_from(target_position).unwrap_or(0);
    guild_id.edit_role_position(&ctx.http, role_id, position_u16).await?;

    let embed = serenity::all::CreateEmbed::new()
        .title("Role position reverted")
        .description(format!("<@&{role_id_i64}>'s position was reverted to the guarded baseline."))
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
        settings::QUARANTINE_ON_MANUAL_GRANT_KEY,
        settings::QUARANTINE_ON_MANUAL_GRANT_DEFAULT,
    )
    .await?;
    if !enabled {
        return Ok(Vec::new());
    }

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

pub async fn recreate_role(
    ctx: &Context,
    pool: &PgPool,
    guild_id_i64: i64,
    old_role_id_i64: i64,
    baseline: &crate::guard::baseline::RoleBaseline,
) -> Result<serenity::model::guild::Role, serenity::Error> {
    let guild_id = GuildId::new(guild_id_i64 as u64);
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

    let embed = serenity::all::CreateEmbed::new()
        .title("Registered role recreated")
        .description(format!(
            "A registered role (previously <@&{old_role_id_i64}>) was deleted and has been recreated as <@&{}>, from its guarded baseline. Re-check any external references to the old role ID.",
            new_role.id
        ))
        .color(0xED4245);
    let _ = log(pool, &ctx.http, guild_id_i64, LogTier::Alert, embed).await;
    Ok(new_role)
}
