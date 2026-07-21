pub mod audit_handler;
pub mod backfill;
pub mod baseline;
pub mod reaction;
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

/// Name changes are only guarded for roles currently registered in
/// `role_pairs` — renaming an ordinary role isn't a security concern.
pub fn name_drifted(baseline_name: &str, actual_name: &str, is_registered: bool) -> bool {
    is_registered && baseline_name != actual_name
}

/// Unlike `name_drifted`, position is guarded for every role regardless of
/// registration — a role's position is tied to Discord's role hierarchy
/// (which roles can escape above which), not just cosmetic identity, so
/// this one gets the same "always guarded" treatment as `permission_drifted`.
pub fn position_drifted(baseline_position: i32, actual_position: i32) -> bool {
    baseline_position != actual_position
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
    fn name_drift_ignored_for_unregistered_role() {
        assert!(!name_drifted("Old Name", "New Name", false));
    }

    #[test]
    fn name_drift_detected_for_registered_role() {
        assert!(name_drifted("Old Name", "New Name", true));
    }

    #[test]
    fn name_drift_not_detected_when_unchanged() {
        assert!(!name_drifted("Same", "Same", true));
    }

    #[test]
    fn position_drift_detected_regardless_of_registration() {
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
