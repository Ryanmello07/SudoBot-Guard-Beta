pub mod audit_handler;
pub mod backfill;
pub mod baseline;
pub mod reaction;
pub mod recreation_guard;
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

/// True if a REGISTERED role has climbed to be at or above the bot's own
/// top role — the point at which the bot can no longer manage it via the
/// Discord API. This is the only position invariant guarded now.
///
/// DESIGN NOTE (the single source of truth for the position-guarding
/// rationale; other call sites reference this doc rather than restating
/// it): absolute per-role position guarding was tried and caused a live,
/// self-sustaining oscillation, because Discord positions are one shared
/// ordering across the whole guild and restoring one role's exact index
/// necessarily perturbs its neighbors — the old equality check then
/// flagged each perturbed neighbor as a fresh violation and reverted it,
/// which perturbed the first role again, hammering Discord's API and
/// spamming the log channel (100+ reverts in ~a minute in the incident
/// that prompted this rewrite). A hierarchy-boundary crossing is immune to
/// that cascade: it's a one-directional inequality, not an equality
/// assertion against a value shared with other roles, so a renormalized
/// neighbor is invisible unless it *itself* crosses the boundary — which,
/// for a guild with only a couple of roles near the top, essentially never
/// cascades, and even then each correction monotonically resolves a real
/// boundary violation rather than fighting over a shared index. A plain
/// reorder among roles that never crosses the bot's boundary produces zero
/// reverts. Direction matches `crate::commands::protect::validate_hierarchy`
/// exactly (`role_position >= bot_top_position` is the violation there too;
/// in Discord's convention a larger position number sits higher).
pub fn escaped_hierarchy(role_position: u16, bot_top_position: u16) -> bool {
    role_position >= bot_top_position
}

/// The bot's own current top role position, read from the cache — the
/// boundary `escaped_hierarchy` compares registered roles against. `None`
/// when the guild or the bot's own member entry isn't cached (in which
/// case callers must skip position guarding, never fail open on the other
/// checks). Mirrors the `bot_top_position` computation in
/// `crate::commands::protect`'s `handle_add`, including its `unwrap_or(0)`.
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
    fn escaped_hierarchy_true_when_role_equals_bot_top() {
        // A role sitting at exactly the bot's top position can't be managed
        // by the bot — same boundary `validate_hierarchy` rejects at
        // registration time (`>=`).
        assert!(escaped_hierarchy(10, 10));
    }

    #[test]
    fn escaped_hierarchy_true_when_role_above_bot_top() {
        assert!(escaped_hierarchy(15, 10));
    }

    #[test]
    fn escaped_hierarchy_false_when_role_below_bot_top() {
        assert!(!escaped_hierarchy(3, 10));
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
