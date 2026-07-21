use crate::crypto::{encryption, totp};
use crate::yubico::YubicoClient;
use sqlx::PgPool;

#[derive(Debug, PartialEq, Eq)]
pub enum CodeShape {
    Totp,
    Yubikey,
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

/// Detects the code's shape and verifies it against whichever factor the
/// user has enrolled — the single entry point every 2FA-gated action
/// (auth elevation, panic vote/cancel/override) should call, so verification
/// behavior never drifts between call sites.
pub async fn verify_code(
    pool: &PgPool,
    guild_id_i64: i64,
    user_id_i64: i64,
    code: &str,
    encryption_key: &[u8; 32],
    yubico: &YubicoClient,
) -> Result<bool, sqlx::Error> {
    let Some(shape) = detect_code_shape(code) else {
        return Ok(false);
    };
    match shape {
        CodeShape::Totp => verify_totp(pool, guild_id_i64, user_id_i64, code, encryption_key).await,
        CodeShape::Yubikey => verify_yubikey(pool, guild_id_i64, user_id_i64, code, yubico).await,
    }
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
}
