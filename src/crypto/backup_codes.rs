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

/// Returns the index of the first hash in `hashes` that `code` verifies
/// against, or `None` if it matches none of them.
///
/// Each backup code is independently salted and argon2-hashed, so a submitted
/// code can't be looked up by value — callers pass the candidate rows' hashes
/// and use the returned index to identify which specific stored row to consume.
pub fn find_matching_code_index(code: &str, hashes: &[String]) -> Option<usize> {
    hashes.iter().position(|hash| verify_code(code, hash))
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

    #[test]
    fn find_matching_index_returns_position_of_matching_hash() {
        let hashes = vec![hash_code("AAAAA11111"), hash_code("BBBBB22222"), hash_code("CCCCC33333")];
        assert_eq!(find_matching_code_index("BBBBB22222", &hashes), Some(1));
    }

    #[test]
    fn find_matching_index_returns_first_match_when_duplicates_present() {
        // Same code hashed twice (different salts) — should return the earliest.
        let hashes = vec![hash_code("AAAAA11111"), hash_code("DUPDUP7777"), hash_code("DUPDUP7777")];
        assert_eq!(find_matching_code_index("DUPDUP7777", &hashes), Some(1));
    }

    #[test]
    fn find_matching_index_returns_none_when_no_hash_matches() {
        let hashes = vec![hash_code("AAAAA11111"), hash_code("BBBBB22222")];
        assert_eq!(find_matching_code_index("ZZZZZ99999", &hashes), None);
    }

    #[test]
    fn find_matching_index_returns_none_for_empty_hash_list() {
        assert_eq!(find_matching_code_index("AAAAA11111", &[]), None);
    }

    #[test]
    fn find_matching_index_skips_malformed_hashes_and_finds_valid_match() {
        let hashes = vec!["not-a-hash".to_string(), hash_code("AAAAA11111")];
        assert_eq!(find_matching_code_index("AAAAA11111", &hashes), Some(1));
    }
}
