use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use reqwest::Client;
use sha1::Sha1;
use thiserror::Error;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Error)]
pub enum YubicoError {
    #[error("request to Yubico failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("unexpected response format from Yubico")]
    BadResponse,
    #[error("OTP is too short to contain a public ID")]
    OtpTooShort,
}

pub struct YubicoVerifyResult {
    pub public_id: String,
    pub valid: bool,
}

pub struct YubicoClient {
    client_id: String,
    secret_key: Vec<u8>,
    http: Client,
}

impl YubicoClient {
    pub fn new(client_id: String, secret_key_base64: &str) -> Self {
        let secret_key = STANDARD
            .decode(secret_key_base64)
            .expect("YUBICO_SECRET_KEY must be valid base64, as issued by Yubico");
        Self {
            client_id,
            secret_key,
            http: Client::new(),
        }
    }

    pub async fn verify_otp(&self, otp: &str) -> Result<YubicoVerifyResult, YubicoError> {
        let Some(public_id) = otp.get(..12).map(str::to_string) else {
            return Err(YubicoError::OtpTooShort);
        };
        let nonce = generate_nonce();

        let mut params = vec![
            ("id".to_string(), self.client_id.clone()),
            ("nonce".to_string(), nonce),
            ("otp".to_string(), otp.to_string()),
        ];
        params.sort_by(|a, b| a.0.cmp(&b.0));
        let signature = sign_params(&self.secret_key, &params);

        let mut query: Vec<(&str, &str)> = params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        query.push(("h", &signature));

        let body = self
            .http
            .get("https://api.yubico.com/wsapi/2.0/verify")
            .query(&query)
            .send()
            .await?
            .text()
            .await?;

        let status = parse_field(&body, "status").ok_or(YubicoError::BadResponse)?;
        Ok(YubicoVerifyResult {
            public_id,
            valid: status == "OK",
        })
    }
}

fn sign_params(secret_key: &[u8], sorted_params: &[(String, String)]) -> String {
    let query_string = sorted_params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let mut mac =
        HmacSha1::new_from_slice(secret_key).expect("HMAC accepts a key of any length");
    mac.update(query_string.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

fn generate_nonce() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..24)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
}

fn parse_field<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    body.lines()
        .find_map(|line| line.trim().strip_prefix(prefix.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_field_extracts_value() {
        let body = "h=abc123\nt=2024-01-01\nstatus=OK\notp=xyz\n";
        assert_eq!(parse_field(body, "status"), Some("OK"));
    }

    #[test]
    fn parse_field_returns_none_for_missing_key() {
        let body = "status=OK\n";
        assert_eq!(parse_field(body, "nonexistent"), None);
    }

    #[test]
    fn parse_field_trims_whitespace_around_lines() {
        let body = "  status=OK  \n";
        assert_eq!(parse_field(body, "status"), Some("OK"));
    }

    #[test]
    fn sign_params_is_deterministic_for_the_same_input() {
        let key = STANDARD.decode("MTIzNDU2Nzg5MGFiY2RlZg==").unwrap();
        let params = vec![
            ("id".to_string(), "1".to_string()),
            ("otp".to_string(), "cccccc".to_string()),
        ];
        let sig_a = sign_params(&key, &params);
        let sig_b = sign_params(&key, &params);
        assert_eq!(sig_a, sig_b);
    }

    #[test]
    fn sign_params_changes_with_different_keys() {
        let params = vec![("id".to_string(), "1".to_string())];
        let key_a = STANDARD.decode("MTIzNDU2Nzg5MGFiY2RlZg==").unwrap();
        let key_b = STANDARD.decode("ZmZmZmZmZmZmZmZmZmZmZg==").unwrap();
        assert_ne!(sign_params(&key_a, &params), sign_params(&key_b, &params));
    }

    #[test]
    fn generate_nonce_has_expected_length_and_alphabet() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 24);
        assert!(nonce
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }
}
