use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::RngExt;

pub const CODE_COUNT: usize = 10;
const CODE_LEN: usize = 10;
// No 0/O/1/I, to avoid ambiguous characters when a human reads a printed code aloud.
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub fn generate_codes(count: usize) -> Vec<String> {
    (0..count).map(|_| generate_one_code()).collect()
}

fn generate_one_code() -> String {
    let mut rng = rand::rng();
    (0..CODE_LEN)
        .map(|_| CODE_ALPHABET[rng.random_range(0..CODE_ALPHABET.len())] as char)
        .collect()
}

pub fn hash_code(code: &str) -> String {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    argon2
        .hash_password(code.as_bytes(), &salt)
        .expect("hashing with a freshly generated salt does not fail")
        .to_string()
}

pub fn verify_code(code: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(code.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_requested_number_of_codes() {
        let codes = generate_codes(CODE_COUNT);
        assert_eq!(codes.len(), CODE_COUNT);
    }

    #[test]
    fn generated_codes_use_expected_length_and_alphabet() {
        let codes = generate_codes(5);
        for code in &codes {
            assert_eq!(code.len(), CODE_LEN);
            assert!(code.bytes().all(|b| CODE_ALPHABET.contains(&b)));
        }
    }

    #[test]
    fn generated_codes_are_not_all_identical() {
        let codes = generate_codes(5);
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert!(unique.len() > 1, "codes should be randomized, not constant");
    }

    #[test]
    fn hash_then_verify_round_trips() {
        let code = "ABCDE23456";
        let hash = hash_code(code);
        assert!(verify_code(code, &hash));
    }

    #[test]
    fn verify_rejects_wrong_code() {
        let hash = hash_code("ABCDE23456");
        assert!(!verify_code("WRONGCODE1", &hash));
    }

    #[test]
    fn verify_rejects_malformed_hash() {
        assert!(!verify_code("ABCDE23456", "not-a-real-argon2-hash"));
    }
}
