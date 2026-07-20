use chrono::{DateTime, Utc};

#[derive(Debug, PartialEq, Eq)]
pub enum EnrollmentDecision {
    SelfServiceAdd,
    SelfServiceRegenerate,
    CooldownNotElapsed,
    ApprovedAdd,
    ApprovedRegenerate,
    NeedsApproval,
}

/// The single authorization decision point for every enrollment button click.
/// - Bot admins self-serve always, subject to a cooldown on regenerating an
///   existing factor.
/// - Everyone else needs a previously-approved, unexpired `enrollment_requests`
///   row, or gets told to request one.
pub fn decide_enrollment_action(
    is_admin: bool,
    has_verified_factor: bool,
    cooldown_elapsed: bool,
    has_approved_unexpired_request: bool,
) -> EnrollmentDecision {
    if is_admin {
        if !has_verified_factor {
            EnrollmentDecision::SelfServiceAdd
        } else if cooldown_elapsed {
            EnrollmentDecision::SelfServiceRegenerate
        } else {
            EnrollmentDecision::CooldownNotElapsed
        }
    } else if has_approved_unexpired_request {
        if has_verified_factor {
            EnrollmentDecision::ApprovedRegenerate
        } else {
            EnrollmentDecision::ApprovedAdd
        }
    } else {
        EnrollmentDecision::NeedsApproval
    }
}

pub fn cooldown_elapsed(enrolled_at: DateTime<Utc>, now: DateTime<Utc>, cooldown_minutes: i64) -> bool {
    (now - enrolled_at).num_minutes() >= cooldown_minutes
}

/// Parses a window string like "30m" or "1h" into minutes. Capped at 24h
/// (1440 minutes), no enforced minimum.
pub fn parse_window_minutes(input: &str) -> Result<i32, String> {
    let input = input.trim();
    let Some(last_char) = input.chars().last() else {
        return Err("window must look like '30m' or '1h'".to_string());
    };
    let split_at = input.len() - last_char.len_utf8();
    let (num_part, unit) = input.split_at(split_at);
    let multiplier: i32 = match unit {
        "m" => 1,
        "h" => 60,
        _ => return Err("window must end in 'm' or 'h', e.g. '30m' or '1h'".to_string()),
    };
    let num: i32 = num_part
        .parse()
        .map_err(|_| "invalid number in window".to_string())?;
    if num <= 0 {
        return Err("window must be positive".to_string());
    }
    let minutes = num
        .checked_mul(multiplier)
        .ok_or_else(|| "window value too large".to_string())?;
    if minutes > 24 * 60 {
        return Err("window can't exceed 24h".to_string());
    }
    Ok(minutes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // -- decide_enrollment_action --

    #[test]
    fn admin_with_no_verified_factor_self_services_add() {
        assert_eq!(
            decide_enrollment_action(true, false, true, false),
            EnrollmentDecision::SelfServiceAdd
        );
    }

    #[test]
    fn admin_with_no_verified_factor_self_services_add_even_within_cooldown() {
        // Cooldown only applies to regenerating an existing factor.
        assert_eq!(
            decide_enrollment_action(true, false, false, false),
            EnrollmentDecision::SelfServiceAdd
        );
    }

    #[test]
    fn admin_with_verified_factor_past_cooldown_self_services_regenerate() {
        assert_eq!(
            decide_enrollment_action(true, true, true, false),
            EnrollmentDecision::SelfServiceRegenerate
        );
    }

    #[test]
    fn admin_with_verified_factor_within_cooldown_is_blocked() {
        assert_eq!(
            decide_enrollment_action(true, true, false, false),
            EnrollmentDecision::CooldownNotElapsed
        );
    }

    #[test]
    fn non_admin_with_approved_request_and_no_verified_factor_gets_approved_add() {
        assert_eq!(
            decide_enrollment_action(false, false, true, true),
            EnrollmentDecision::ApprovedAdd
        );
    }

    #[test]
    fn non_admin_with_approved_request_and_verified_factor_gets_approved_regenerate() {
        assert_eq!(
            decide_enrollment_action(false, true, true, true),
            EnrollmentDecision::ApprovedRegenerate
        );
    }

    #[test]
    fn non_admin_without_approved_request_always_needs_approval() {
        assert_eq!(
            decide_enrollment_action(false, false, true, false),
            EnrollmentDecision::NeedsApproval
        );
        assert_eq!(
            decide_enrollment_action(false, true, true, false),
            EnrollmentDecision::NeedsApproval
        );
    }

    // -- cooldown_elapsed --

    #[test]
    fn cooldown_not_elapsed_when_now_is_before_window_ends() {
        let enrolled_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap(); // 12h later
        assert!(!cooldown_elapsed(enrolled_at, now, 1440)); // 24h cooldown
    }

    #[test]
    fn cooldown_elapsed_when_now_is_exactly_at_window_end() {
        let enrolled_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let now = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap(); // exactly 24h later
        assert!(cooldown_elapsed(enrolled_at, now, 1440));
    }

    #[test]
    fn cooldown_elapsed_when_now_is_well_after_window_end() {
        let enrolled_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let now = Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap();
        assert!(cooldown_elapsed(enrolled_at, now, 1440));
    }

    // -- parse_window_minutes --

    #[test]
    fn parses_minutes_suffix() {
        assert_eq!(parse_window_minutes("30m"), Ok(30));
    }

    #[test]
    fn parses_hours_suffix() {
        assert_eq!(parse_window_minutes("1h"), Ok(60));
    }

    #[test]
    fn accepts_exactly_24h_cap() {
        assert_eq!(parse_window_minutes("24h"), Ok(1440));
    }

    #[test]
    fn rejects_over_24h_cap() {
        assert!(parse_window_minutes("25h").is_err());
    }

    #[test]
    fn rejects_zero() {
        assert!(parse_window_minutes("0m").is_err());
    }

    #[test]
    fn rejects_negative() {
        assert!(parse_window_minutes("-5m").is_err());
    }

    #[test]
    fn rejects_bad_unit() {
        assert!(parse_window_minutes("30x").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_window_minutes("").is_err());
    }

    #[test]
    fn rejects_non_numeric() {
        assert!(parse_window_minutes("abcm").is_err());
    }

    #[test]
    fn rejects_non_ascii_trailing_char_without_panicking() {
        assert!(parse_window_minutes("1€").is_err());
    }

    #[test]
    fn rejects_single_non_ascii_char() {
        assert!(parse_window_minutes("€").is_err());
    }
}
