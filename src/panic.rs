/// True if the member (given their current role IDs) holds either half of
/// any registered role pair — the standard identity role or the permission
/// role. Broader than "currently elevated": matches anyone staff-registered
/// with the bot at all, elevated or not.
pub fn is_protected_staff(member_role_ids: &[i64], registered_role_ids: &[i64]) -> bool {
    member_role_ids.iter().any(|r| registered_role_ids.contains(r))
}

/// True once yes_votes forms a strict majority of total_eligible. Zero
/// eligible voters can never reach majority (avoids a 0-votes-needed
/// edge case if voter_roles is misconfigured to nobody).
pub fn majority_reached(yes_votes: i64, total_eligible: i64) -> bool {
    total_eligible > 0 && yes_votes * 2 > total_eligible
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_staff_detected_via_standard_role() {
        assert!(is_protected_staff(&[10], &[10, 20]));
    }

    #[test]
    fn protected_staff_detected_via_permission_role() {
        assert!(is_protected_staff(&[20], &[10, 20]));
    }

    #[test]
    fn protected_staff_not_detected_for_unrelated_role() {
        assert!(!is_protected_staff(&[99], &[10, 20]));
    }

    #[test]
    fn protected_staff_not_detected_for_empty_registry() {
        assert!(!is_protected_staff(&[10], &[]));
    }

    #[test]
    fn majority_reached_with_more_than_half() {
        assert!(majority_reached(4, 7));
    }

    #[test]
    fn majority_not_reached_at_exactly_half() {
        assert!(!majority_reached(3, 6));
    }

    #[test]
    fn majority_not_reached_below_half() {
        assert!(!majority_reached(2, 7));
    }

    #[test]
    fn majority_never_reached_with_zero_eligible() {
        assert!(!majority_reached(0, 0));
    }
}
