pub mod audit_handler;
pub mod backfill;
pub mod baseline;
pub mod position_reconcile_guard;
pub mod reaction;
pub mod recreation_guard;
pub mod role_members;
pub mod sweep;

pub const LOCKDOWN_ENABLED_KEY: &str = "lockdown_enabled";
pub const LOCKDOWN_ENABLED_DEFAULT: bool = false;

/// Reads the guild's current lockdown state. Callers that can't read this
/// (a DB error, not "never configured") should fail closed — treat the
/// error as if lockdown were on, never silently relax guarding.
pub async fn is_lockdown_enabled(pool: &sqlx::PgPool, guild_id: i64) -> Result<bool, sqlx::Error> {
    crate::settings::get_bool_setting(pool, guild_id, LOCKDOWN_ENABLED_KEY, LOCKDOWN_ENABLED_DEFAULT).await
}

/// Every role's permission bitmask is guarded, registered or not — a bare
/// equality check, but naming it documents the rule and gives it its own
/// test, matching how the rest of this codebase tests small gating rules.
pub fn permission_drifted(baseline_bits: i64, actual_bits: i64) -> bool {
    baseline_bits != actual_bits
}

/// Name is guarded for every role regardless of registration, matching
/// `permission_drifted` — the role list is kept a carbon copy of its
/// baseline state, full stop.
pub fn name_drifted(baseline_name: &str, actual_name: &str) -> bool {
    baseline_name != actual_name
}

/// Position is guarded for every role, absolute — a bare equality check
/// just like `permission_drifted`, scoped by callers to roles below the
/// bot's own top role (see `bot_top_position`; the bot can't manage a role
/// at or above its own position regardless).
///
/// DESIGN NOTE (the single source of truth for the position-guarding
/// rationale; other call sites reference this doc rather than restating
/// it): absolute per-role position guarding is the right model — a single
/// unauthorized reorder genuinely converges (revert it, done). It only
/// *looked* unstable in an earlier incident because the correction was
/// applied one role at a time: reverting role A's index necessarily shifts
/// some other role B as a side effect of Discord's shared ordering, that
/// shift got misread as a fresh violation on B, B got reverted, which
/// shifted A again — a tug-of-war, invisible at low speed (the 5-minute
/// sweep or the ~1-minute audit-log lag naturally rate-limited it) but a
/// real flood once reverts became instant (100+ in a minute, live). The
/// fix is not to narrow what's guarded — it's `reaction::reconcile_positions`
/// applying every guarded role's correction in ONE atomic bulk Discord API
/// call, so there is no intermediate "wrong" state for the bot to
/// misinterpret as a new violation. See that function for the mechanism.
pub fn position_drifted(baseline_position: i32, actual_position: i32) -> bool {
    baseline_position != actual_position
}

/// The bot's own current top role position, read from the cache — the
/// boundary that scopes which roles get position guarding at all (a role
/// at or above this position can't be managed by the bot via the Discord
/// API, so there's nothing to enforce there). `None` when the guild or the
/// bot's own member entry isn't cached (in which case callers must skip
/// position guarding, never fail open on the other checks). Mirrors the
/// `bot_top_position` computation in `crate::commands::protect`'s
/// `handle_add`, including its `unwrap_or(0)`.
pub fn bot_top_position(
    ctx: &serenity::all::Context,
    guild_id: serenity::all::GuildId,
) -> Option<u16> {
    let guild = ctx.cache.guild(guild_id)?.clone();
    let bot_member = guild.members.get(&ctx.cache.current_user().id)?;
    Some(
        bot_member
            .roles
            .iter()
            .filter_map(|r| guild.roles.get(r))
            .map(|r| r.position)
            .max()
            .unwrap_or(0),
    )
}

/// True if `added_role_id` is one of the guild's registered permission
/// roles — i.e. a manual grant of real power, not just a standard role
/// (those can be granted by hand in normal mode) or an unrelated role.
pub fn is_manual_grant(added_role_id: i64, registered_permission_role_ids: &[i64]) -> bool {
    registered_permission_role_ids.contains(&added_role_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_drift_detected() {
        assert!(permission_drifted(0, 8));
    }

    #[test]
    fn permission_drift_not_detected_when_unchanged() {
        assert!(!permission_drifted(8, 8));
    }

    #[test]
    fn name_drift_detected_regardless_of_registration() {
        assert!(name_drifted("Old Name", "New Name"));
    }

    #[test]
    fn name_drift_not_detected_when_unchanged() {
        assert!(!name_drifted("Same", "Same"));
    }

    #[test]
    fn position_drift_detected() {
        assert!(position_drifted(3, 7));
    }

    #[test]
    fn position_drift_not_detected_when_unchanged() {
        assert!(!position_drifted(3, 3));
    }

    #[test]
    fn manual_grant_detected_when_role_is_registered_permission_role() {
        assert!(is_manual_grant(42, &[42, 99]));
    }

    #[test]
    fn manual_grant_not_detected_for_unregistered_role() {
        assert!(!is_manual_grant(7, &[42, 99]));
    }

    #[test]
    fn manual_grant_not_detected_for_empty_registry() {
        assert!(!is_manual_grant(42, &[]));
    }
}
