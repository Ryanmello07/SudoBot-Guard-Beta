use std::env;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required env var: {0}")]
    Missing(&'static str),
    #[error("ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes)")]
    InvalidEncryptionKey,
}

pub struct Config {
    pub discord_token: String,
    pub database_url: String,
    pub encryption_key: [u8; 32],
    pub yubico_client_id: String,
    pub yubico_secret_key: String,
    pub initial_bot_admin_id: Option<u64>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let discord_token = require_var("DISCORD_TOKEN")?;
        let database_url = require_var("DATABASE_URL")?;
        let encryption_key = parse_encryption_key(&require_var("ENCRYPTION_KEY")?)?;
        let yubico_client_id = require_var("YUBICO_CLIENT_ID")?;
        let yubico_secret_key = require_var("YUBICO_SECRET_KEY")?;
        let initial_bot_admin_id = env::var("INITIAL_BOT_ADMIN_ID")
            .ok()
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse::<u64>().ok());

        Ok(Config {
            discord_token,
            database_url,
            encryption_key,
            yubico_client_id,
            yubico_secret_key,
            initial_bot_admin_id,
        })
    }
}

fn require_var(name: &'static str) -> Result<String, ConfigError> {
    env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or(ConfigError::Missing(name))
}

fn parse_encryption_key(hex_str: &str) -> Result<[u8; 32], ConfigError> {
    let bytes = hex::decode(hex_str).map_err(|_| ConfigError::InvalidEncryptionKey)?;
    bytes
        .try_into()
        .map_err(|_| ConfigError::InvalidEncryptionKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_encryption_key() {
        let hex_str = "00".repeat(32);
        let key = parse_encryption_key(&hex_str).unwrap();
        assert_eq!(key, [0u8; 32]);
    }

    #[test]
    fn rejects_short_encryption_key() {
        let hex_str = "00".repeat(16);
        assert!(matches!(
            parse_encryption_key(&hex_str),
            Err(ConfigError::InvalidEncryptionKey)
        ));
    }

    #[test]
    fn rejects_non_hex_encryption_key() {
        assert!(matches!(
            parse_encryption_key("not-hex-at-all"),
            Err(ConfigError::InvalidEncryptionKey)
        ));
    }
}
