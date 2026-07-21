pub mod baseline;

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

/// Position changes are only guarded for registered roles, same reasoning
/// as `name_drifted`.
pub fn position_drifted(baseline_position: i32, actual_position: i32, is_registered: bool) -> bool {
    is_registered && baseline_position != actual_position
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
    fn position_drift_ignored_for_unregistered_role() {
        assert!(!position_drifted(3, 7, false));
    }

    #[test]
    fn position_drift_detected_for_registered_role() {
        assert!(position_drifted(3, 7, true));
    }

    #[test]
    fn position_drift_not_detected_when_unchanged() {
        assert!(!position_drifted(3, 3, true));
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
