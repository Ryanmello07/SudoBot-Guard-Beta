use totp_rs::{Algorithm, Secret, TOTP};

pub const STEP_SECONDS: i64 = 30;

pub fn generate_secret_bytes() -> Vec<u8> {
    Secret::generate_secret()
        .to_bytes()
        .expect("a freshly generated raw secret is always valid bytes")
}

pub fn build_totp(secret_bytes: Vec<u8>, account_name: String) -> TOTP {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        STEP_SECONDS as u64,
        secret_bytes,
        Some("SudoBot Guard".to_string()),
        account_name,
    )
    .expect("TOTP parameters are fixed and always valid for our algorithm/digits/step")
}

pub fn base32_secret(totp: &TOTP) -> String {
    totp.get_secret_base32()
}

pub fn provisioning_qr_png(totp: &TOTP) -> Result<Vec<u8>, String> {
    totp.get_qr_png()
}

/// Verifies `code` against `secret_bytes` within a +/-1 time-step window of `now_unix`.
/// Returns the matched time step on success so the caller can check/insert it into the
/// replay ledger (this function does not touch the database).
pub fn verify_code(secret_bytes: &[u8], account_name: &str, code: &str, now_unix: u64) -> Option<i64> {
    let totp = build_totp(secret_bytes.to_vec(), account_name.to_string());
    let current_step = now_unix as i64 / STEP_SECONDS;

    for delta in [0i64, -1, 1] {
        let candidate_step = current_step + delta;
        if candidate_step < 0 {
            continue;
        }
        let candidate_time = (candidate_step * STEP_SECONDS) as u64;
        let expected = totp.generate(candidate_time);
        if constant_time_eq(expected.as_bytes(), code.as_bytes()) {
            return Some(candidate_step);
        }
    }
    None
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_is_20_bytes() {
        let secret = generate_secret_bytes();
        assert_eq!(secret.len(), 20);
    }

    #[test]
    fn base32_secret_round_trips_through_totp() {
        let secret_bytes = generate_secret_bytes();
        let totp = build_totp(secret_bytes, "alice#1234".to_string());
        let base32 = base32_secret(&totp);
        assert!(!base32.is_empty());
    }

    #[test]
    fn qr_png_starts_with_png_magic_bytes() {
        let secret_bytes = generate_secret_bytes();
        let totp = build_totp(secret_bytes, "alice#1234".to_string());
        let png = provisioning_qr_png(&totp).unwrap();
        assert_eq!(&png[0..4], &[0x89, 0x50, 0x4E, 0x47]);
    }

    #[test]
    fn verify_code_accepts_a_freshly_generated_code() {
        let secret_bytes = generate_secret_bytes();
        let totp = build_totp(secret_bytes.clone(), "alice#1234".to_string());
        let now = 1_700_000_000u64;
        let code = totp.generate(now);
        let result = verify_code(&secret_bytes, "alice#1234", &code, now);
        assert!(result.is_some());
    }

    #[test]
    fn verify_code_accepts_previous_step_within_window() {
        let secret_bytes = generate_secret_bytes();
        let totp = build_totp(secret_bytes.clone(), "alice#1234".to_string());
        let now = 1_700_000_000u64;
        let previous_step_time = now - STEP_SECONDS as u64;
        let code = totp.generate(previous_step_time);
        let result = verify_code(&secret_bytes, "alice#1234", &code, now);
        assert!(result.is_some());
    }

    #[test]
    fn verify_code_rejects_code_two_steps_old() {
        let secret_bytes = generate_secret_bytes();
        let totp = build_totp(secret_bytes.clone(), "alice#1234".to_string());
        let now = 1_700_000_000u64;
        let two_steps_ago = now - (2 * STEP_SECONDS as u64);
        let code = totp.generate(two_steps_ago);
        let result = verify_code(&secret_bytes, "alice#1234", &code, now);
        assert!(result.is_none());
    }

    #[test]
    fn verify_code_rejects_wrong_code() {
        let secret_bytes = generate_secret_bytes();
        let now = 1_700_000_000u64;
        let result = verify_code(&secret_bytes, "alice#1234", "000000", now);
        assert!(result.is_none());
    }
}
