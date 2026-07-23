use crate::crypto::{encryption, totp};
use crate::yubico::YubicoClient;
use sqlx::PgPool;

/// Brute-force lockout window and threshold. Relocated here from
/// `commands::auth` so `verify_code` is the single source of truth for
/// lockout: a `(guild_id, user_id)` with `LOCKOUT_THRESHOLD` or more failed
/// attempts inside the last `LOCKOUT_WINDOW_MINUTES` minutes is locked out.
pub const LOCKOUT_WINDOW_MINUTES: i32 = 30;
pub const LOCKOUT_THRESHOLD: i64 = 5;

#[derive(Debug, PartialEq, Eq)]
pub enum CodeShape {
    Totp,
    Yubikey,
}

/// Whether a given `verify_code` call should enforce brute-force lockout.
///
/// Kept an explicit per-call opt-in (rather than an unconditional property of
/// `verify_code`) so the emergency de-escalation path — `/calm` votes/cancels/
/// overrides and `/panic`'s admin cooldown-bypass — can never lock an admin
/// out of ending an active panic just because they fumbled codes on some
/// unrelated admin command. Those callers pass `Exempt`; every ordinary admin
/// action passes `Enforce`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum LockoutPolicy {
    Enforce,
    Exempt,
}

/// Outcome of a `verify_code` call.
///
/// `LockedOut` is only ever returned when the call passed
/// `LockoutPolicy::Enforce`; `Exempt` calls never lock out and so only ever
/// return `Verified` or `Invalid`. `failure_count` carries the number of
/// recent failed attempts so the caller can render the "Auth Lockout" alert
/// embed's `"{failure_count} in the last {LOCKOUT_WINDOW_MINUTES} minutes"`
/// wording without re-querying.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    Verified,
    Invalid,
    LockedOut { failure_count: i64 },
}

/// Pure lockout predicate, isolated for direct unit testing (mirroring the
/// `detect_code_shape` test style). A user is locked out once their recent
/// failed-attempt count reaches the threshold.
pub fn is_locked_out(failure_count: i64) -> bool {
    failure_count >= LOCKOUT_THRESHOLD
}

/// TOTP codes are exactly 6 ASCII digits; YubiKey OTPs are exactly 44
/// alphanumeric (modhex) characters. Anything else isn't a recognizable code.
pub fn detect_code_shape(code: &str) -> Option<CodeShape> {
    if code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()) {
        Some(CodeShape::Totp)
    } else if code.len() == 44 && code.chars().all(|c| c.is_ascii_alphanumeric()) {
        Some(CodeShape::Yubikey)
    } else {
        None
    }
}

pub async fn verify_totp(
    pool: &PgPool,
    guild_id_i64: i64,
    user_id_i64: i64,
    code: &str,
    encryption_key: &[u8; 32],
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT totp_secret_encrypted FROM totp_enrollments WHERE guild_id = $1 AND user_id = $2 AND verified = true",
        guild_id_i64,
        user_id_i64
    )
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };

    let Ok(base32_secret) = encryption::decrypt(encryption_key, &row.totp_secret_encrypted) else {
        return Ok(false);
    };
    let Ok(secret_bytes) = totp_rs::Secret::Encoded(base32_secret).to_bytes() else {
        return Ok(false);
    };

    let now_unix = chrono::Utc::now().timestamp() as u64;
    let account_name = user_id_i64.to_string();
    let Some(time_step) = totp::verify_code(&secret_bytes, &account_name, code, now_unix) else {
        return Ok(false);
    };

    let insert_result = sqlx::query!(
        "INSERT INTO totp_replay_ledger (guild_id, user_id, time_step) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        guild_id_i64,
        user_id_i64,
        time_step
    )
    .execute(pool)
    .await?;

    Ok(insert_result.rows_affected() > 0)
}

pub async fn verify_yubikey(
    pool: &PgPool,
    guild_id_i64: i64,
    user_id_i64: i64,
    code: &str,
    yubico: &YubicoClient,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT yubikey_public_id FROM yubikey_enrollments WHERE guild_id = $1 AND user_id = $2",
        guild_id_i64,
        user_id_i64
    )
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };

    match yubico.verify_otp(code).await {
        Ok(result) => Ok(result.valid && result.public_id == row.yubikey_public_id),
        Err(e) => {
            tracing::error!(error = ?e, "Yubico verification request failed");
            Ok(false)
        }
    }
}

/// Records one authentication attempt against `auth_attempts`, which is what
/// the lockout window later counts. Best-effort: a failed insert is logged and
/// swallowed rather than propagated, matching the original `commands::auth`
/// behavior — audit-log breakage must not change a caller's verify outcome.
async fn record_attempt(pool: &PgPool, guild_id_i64: i64, user_id_i64: i64, success: bool) {
    if let Err(e) = sqlx::query!(
        "INSERT INTO auth_attempts (guild_id, user_id, success) VALUES ($1, $2, $3)",
        guild_id_i64,
        user_id_i64,
        success
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = ?e, "failed to record auth attempt");
    }
}

/// Counts failed attempts for this `(guild_id, user_id)` inside the lockout
/// window. Errors propagate so the caller surfaces "Something went wrong"
/// rather than silently treating a DB failure as "not locked out".
async fn recent_failure_count(
    pool: &PgPool,
    guild_id_i64: i64,
    user_id_i64: i64,
) -> Result<i64, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS count FROM auth_attempts
         WHERE guild_id = $1 AND user_id = $2 AND success = false
           AND attempted_at > now() - make_interval(mins => $3)",
        guild_id_i64,
        user_id_i64,
        LOCKOUT_WINDOW_MINUTES
    )
    .fetch_one(pool)
    .await?;
    Ok(row.count.unwrap_or(0))
}

/// The single entry point every 2FA-gated action calls, so verification,
/// audit-logging, and brute-force lockout never drift between call sites.
///
/// Order of operations (matching the original `/auth` implementation):
///
/// 1. If `lockout_policy` is `Enforce`, count recent failures first. If the
///    count is at or over the threshold, return `LockedOut` immediately —
///    before any shape detection, verification, or replay-ledger consumption,
///    and *without* recording a new attempt (so merely hitting the gate never
///    inflates the count further).
/// 2. Otherwise detect the code's shape; an unrecognized code records a failed
///    attempt and returns `Invalid`.
/// 3. Otherwise run the real TOTP/YubiKey check, then *unconditionally* record
///    the attempt (success = whether it verified) — recording happens
///    regardless of `lockout_policy`, since audit-trail completeness is a
///    separate concern from blocking — and return `Verified`/`Invalid`.
///
/// This module stays Discord-UI-agnostic: rendering the "Auth Lockout" alert
/// and replying to the user on `LockedOut` is each enforcing caller's job.
pub async fn verify_code(
    pool: &PgPool,
    guild_id_i64: i64,
    user_id_i64: i64,
    code: &str,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
    lockout_policy: LockoutPolicy,
) -> Result<VerifyOutcome, sqlx::Error> {
    if lockout_policy == LockoutPolicy::Enforce {
        let failure_count = recent_failure_count(pool, guild_id_i64, user_id_i64).await?;
        if is_locked_out(failure_count) {
            return Ok(VerifyOutcome::LockedOut { failure_count });
        }
    }

    let Some(shape) = detect_code_shape(code) else {
        record_attempt(pool, guild_id_i64, user_id_i64, false).await;
        return Ok(VerifyOutcome::Invalid);
    };

    let verified = match shape {
        CodeShape::Totp => verify_totp(pool, guild_id_i64, user_id_i64, code, encryption_key).await?,
        CodeShape::Yubikey => verify_yubikey(pool, guild_id_i64, user_id_i64, code, yubico).await?,
    };

    record_attempt(pool, guild_id_i64, user_id_i64, verified).await;

    Ok(if verified {
        VerifyOutcome::Verified
    } else {
        VerifyOutcome::Invalid
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_six_digit_totp_code() {
        assert_eq!(detect_code_shape("123456"), Some(CodeShape::Totp));
    }

    #[test]
    fn recognizes_forty_four_char_yubikey_otp() {
        let otp = "c".repeat(44);
        assert_eq!(detect_code_shape(&otp), Some(CodeShape::Yubikey));
    }

    #[test]
    fn rejects_five_digit_code() {
        assert_eq!(detect_code_shape("12345"), None);
    }

    #[test]
    fn rejects_seven_digit_code() {
        assert_eq!(detect_code_shape("1234567"), None);
    }

    #[test]
    fn rejects_six_chars_with_a_letter() {
        assert_eq!(detect_code_shape("12345a"), None);
    }

    #[test]
    fn rejects_forty_three_char_string() {
        let s = "c".repeat(43);
        assert_eq!(detect_code_shape(&s), None);
    }

    #[test]
    fn rejects_forty_five_char_string() {
        let s = "c".repeat(45);
        assert_eq!(detect_code_shape(&s), None);
    }

    #[test]
    fn rejects_forty_four_chars_with_a_symbol() {
        let s = format!("{}!", "c".repeat(43));
        assert_eq!(detect_code_shape(&s), None);
    }

    #[test]
    fn rejects_empty_string() {
        assert_eq!(detect_code_shape(""), None);
    }

    #[test]
    fn not_locked_out_below_threshold() {
        assert!(!is_locked_out(LOCKOUT_THRESHOLD - 1));
    }

    #[test]
    fn locked_out_exactly_at_threshold() {
        // The gate is `>=`, so the threshold value itself locks out — a user
        // is blocked on the attempt after their Nth failure, not the N+1th.
        assert!(is_locked_out(LOCKOUT_THRESHOLD));
    }

    #[test]
    fn locked_out_above_threshold() {
        assert!(is_locked_out(LOCKOUT_THRESHOLD + 1));
    }

    #[test]
    fn zero_failures_is_not_locked_out() {
        assert!(!is_locked_out(0));
    }

    #[test]
    fn exempt_policy_differs_from_enforce() {
        // Guards against the two lockout policies accidentally collapsing into
        // one value — the whole emergency-path exemption depends on them being
        // distinguishable at every call site.
        assert_ne!(LockoutPolicy::Enforce, LockoutPolicy::Exempt);
    }
}
