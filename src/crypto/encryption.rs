use aes_gcm::aead::{Aead, KeyInit, Nonce};
use aes_gcm::{Aes256Gcm, Key};
use rand::RngExt;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncryptionError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error("ciphertext too short to contain a nonce")]
    Truncated,
    #[error("decrypted bytes were not valid UTF-8")]
    InvalidUtf8,
}

const NONCE_LEN: usize = 12;

pub fn encrypt(key_bytes: &[u8; 32], plaintext: &str) -> Result<Vec<u8>, EncryptionError> {
    let key: Key<Aes256Gcm> = (*key_bytes).into();
    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill(&mut nonce_bytes);
    let nonce: Nonce<Aes256Gcm> = nonce_bytes.into();

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| EncryptionError::Encrypt)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt(key_bytes: &[u8; 32], data: &[u8]) -> Result<String, EncryptionError> {
    if data.len() < NONCE_LEN {
        return Err(EncryptionError::Truncated);
    }
    let key: Key<Aes256Gcm> = (*key_bytes).into();
    let cipher = Aes256Gcm::new(&key);

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce_array: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .expect("slice length already checked above");
    let nonce: Nonce<Aes256Gcm> = nonce_array.into();

    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| EncryptionError::Decrypt)?;

    String::from_utf8(plaintext).map_err(|_| EncryptionError::InvalidUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [42u8; 32]
    }

    #[test]
    fn round_trips_plaintext() {
        let key = test_key();
        let ciphertext = encrypt(&key, "top secret totp seed").unwrap();
        let plaintext = decrypt(&key, &ciphertext).unwrap();
        assert_eq!(plaintext, "top secret totp seed");
    }

    #[test]
    fn produces_different_ciphertext_each_time() {
        let key = test_key();
        let a = encrypt(&key, "same input").unwrap();
        let b = encrypt(&key, "same input").unwrap();
        assert_ne!(a, b, "random nonce should randomize ciphertext");
    }

    #[test]
    fn fails_to_decrypt_with_wrong_key() {
        let ciphertext = encrypt(&test_key(), "secret").unwrap();
        let wrong_key = [7u8; 32];
        assert_eq!(decrypt(&wrong_key, &ciphertext), Err(EncryptionError::Decrypt));
    }

    #[test]
    fn fails_on_truncated_ciphertext() {
        let key = test_key();
        let short = vec![1, 2, 3];
        assert_eq!(decrypt(&key, &short), Err(EncryptionError::Truncated));
    }
}
