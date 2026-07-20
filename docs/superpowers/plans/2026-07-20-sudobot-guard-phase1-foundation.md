# SudoBot Guard — Phase 1 Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the foundational, Discord-independent layer of SudoBot Guard: project scaffolding, config loading, crypto primitives (AES-GCM encryption, TOTP, backup codes), a Yubico OTP verification client, and the Postgres schema/connection — culminating in a minimal bot process that connects to Postgres, runs migrations, and comes online in Discord.

**Architecture:** A single Rust binary crate. Pure, security-critical logic (encryption, TOTP, backup codes, Yubico request signing) lives in small modules with no Discord or network dependency, so it's fully unit-testable. Config, DB, and the Discord client are wired together only in `main.rs`. This plan does not implement any slash commands — that's Plan 2 (Admin & Registry) — Task 8 here only proves the bot can boot end-to-end.

**Tech Stack:** Rust (stable, 1.97.1 confirmed installed), serenity 0.12 (Discord), sqlx 0.9 + Postgres (storage), totp-rs 5.7 (TOTP + QR), aes-gcm 0.11 (encryption at rest), argon2 0.5 (backup code hashing), reqwest 0.13 (Yubico API), hmac/sha1/base64 (Yubico request signing), tokio (async runtime).

## Global Constraints

- All crate versions and feature flags below were verified by compiling against them directly in this environment — use the exact `cargo add` invocations given, not hand-written `Cargo.toml` entries, so the resolved versions match what was tested.
- Every module handling secrets (encryption keys, TOTP secrets, backup codes, Yubico secret key) must never log the secret value itself, only success/failure.
- No `unwrap()` on anything that can fail from untrusted input (Discord data, network responses, DB rows). `unwrap()`/`expect()` are only acceptable where the invariant is enforced by our own code one line above (e.g. "we just validated this is 32 bytes").
- The project root is `/tmp/discord_sandbox`, already a git repo with the Phase 1 design spec committed at `docs/superpowers/specs/2026-07-20-sudobot-guard-phase1-design.md`. A `.env` file with real secrets already exists there — Task 1's first step must add it to `.gitignore` before anything is ever staged.
- A dedicated Postgres role/database already exist for this project: role `sudobot`, database `sudobot_guard`, on `127.0.0.1:5432`. Do not use the `postgres` superuser role or any other database on this host — another unrelated project's containers/DB run on this same machine and must not be touched.
- Every task that adds a pure-logic module ends with `cargo test` passing for that module before moving on.

---

## Task 1: Project scaffolding

**Files:**
- Create: `Cargo.toml` (via `cargo init`, then `cargo add`)
- Create: `.gitignore`
- Create: `.env.example`
- Create: `src/main.rs` (placeholder, overwritten in Task 8)

**Interfaces:**
- Produces: a buildable Cargo binary crate named `sudobot_guard` with every dependency this plan's later tasks need already declared in `Cargo.toml`.

- [ ] **Step 1: Initialize the Cargo project in the existing repo root**

```bash
cd /tmp/discord_sandbox
cargo init --name sudobot_guard .
```

Expected: `Cargo.toml`, `src/main.rs`, and a `.gitignore` are created. Cargo will *not* re-init git since `.git` already exists.

- [ ] **Step 2: Extend `.gitignore` to protect the real `.env`**

Open `.gitignore` (created by `cargo init`, currently just `/target`) and replace its contents:

```
/target
.env
.env.*
!.env.example
```

- [ ] **Step 3: Create `.env.example`**

```
DISCORD_TOKEN=
DATABASE_URL=postgres://sudobot:password@127.0.0.1:5432/sudobot_guard
ENCRYPTION_KEY=
YUBICO_CLIENT_ID=
YUBICO_SECRET_KEY=
INITIAL_BOT_ADMIN_ID=
```

- [ ] **Step 4: Add all dependencies with the exact verified feature flags**

Run each of these from `/tmp/discord_sandbox`:

```bash
cargo add tokio --features full
cargo add serenity
cargo add sqlx --no-default-features --features postgres,macros,migrate,chrono,tls-rustls-ring-webpki,runtime-tokio
cargo add totp-rs --features gen_secret,qr
cargo add aes-gcm
cargo add argon2 --features std
cargo add rand
cargo add subtle
cargo add reqwest --features json
cargo add hmac
cargo add sha1
cargo add base64
cargo add hex
cargo add dotenvy
cargo add thiserror
cargo add tracing
cargo add tracing-subscriber --features env-filter
```

Expected: each command prints `Adding <crate> vX.Y.Z to dependencies` with no `error:` lines. If any command reports an unrecognized feature, stop and re-check the feature name against this plan rather than guessing — feature names on these crates have changed across versions before (this is exactly why they're spelled out exactly here).

- [ ] **Step 5: Verify the project builds**

```bash
cargo build 2>&1 | tail -20
```

Expected: `Finished` with no errors (warnings about unused code in the still-empty `main.rs` are fine).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock .gitignore .env.example src/main.rs
git status
```

Confirm `.env` does **not** appear in the status output before committing.

```bash
git commit -m "Scaffold sudobot_guard Rust project with pinned dependencies"
```

---

## Task 2: Config loading

**Files:**
- Create: `src/config.rs`
- Modify: `src/main.rs` (add `mod config;`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `pub struct Config { pub discord_token: String, pub database_url: String, pub encryption_key: [u8; 32], pub yubico_client_id: String, pub yubico_secret_key: String, pub initial_bot_admin_id: Option<u64> }`, `pub enum ConfigError`, `Config::from_env() -> Result<Config, ConfigError>`. Later tasks (`main.rs` in Task 8) call `Config::from_env()` once at startup.

- [ ] **Step 1: Write `src/config.rs` with stubs and failing tests**

```rust
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
        todo!()
    }
}

fn parse_encryption_key(_hex_str: &str) -> Result<[u8; 32], ConfigError> {
    todo!()
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
```

Add `mod config;` to the top of `src/main.rs`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test config::tests 2>&1 | tail -20
```

Expected: compiles, then panics with `not yet implemented` for each test (from the `todo!()`).

- [ ] **Step 3: Implement `parse_encryption_key` and `from_env`**

Replace the two `todo!()` bodies:

```rust
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
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test config::tests 2>&1 | tail -20
```

Expected: `test result: ok. 3 passed`.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs src/main.rs
git commit -m "Add env-based config loading with validated encryption key"
```

---

## Task 3: AES-GCM encryption module

**Files:**
- Create: `src/crypto/mod.rs`
- Create: `src/crypto/encryption.rs`
- Modify: `src/main.rs` (add `mod crypto;`)

**Interfaces:**
- Consumes: nothing.
- Produces: `pub fn encrypt(key_bytes: &[u8; 32], plaintext: &str) -> Result<Vec<u8>, EncryptionError>`, `pub fn decrypt(key_bytes: &[u8; 32], data: &[u8]) -> Result<String, EncryptionError>`. Used later (Plan 2/3) to encrypt/decrypt `totp_enrollments.totp_secret_encrypted` using `Config::encryption_key`.

- [ ] **Step 1: Create `src/crypto/mod.rs`**

```rust
pub mod encryption;
```

- [ ] **Step 2: Write `src/crypto/encryption.rs` with stubs and failing tests**

```rust
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

pub fn encrypt(_key_bytes: &[u8; 32], _plaintext: &str) -> Result<Vec<u8>, EncryptionError> {
    todo!()
}

pub fn decrypt(_key_bytes: &[u8; 32], _data: &[u8]) -> Result<String, EncryptionError> {
    todo!()
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
```

Add `mod crypto;` to `src/main.rs`.

- [ ] **Step 3: Run tests to verify they fail**

```bash
cargo test crypto::encryption::tests 2>&1 | tail -20
```

Expected: panics with `not yet implemented`.

- [ ] **Step 4: Implement `encrypt` and `decrypt`**

```rust
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
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cargo test crypto::encryption::tests 2>&1 | tail -20
```

Expected: `test result: ok. 4 passed`.

- [ ] **Step 6: Commit**

```bash
git add src/crypto/mod.rs src/crypto/encryption.rs src/main.rs
git commit -m "Add AES-256-GCM encrypt/decrypt for secrets at rest"
```

---

## Task 4: TOTP module

**Files:**
- Create: `src/crypto/totp.rs`
- Modify: `src/crypto/mod.rs` (add `pub mod totp;`)

**Interfaces:**
- Consumes: nothing (independent of `encryption.rs`).
- Produces: `pub const STEP_SECONDS: i64`, `pub fn generate_secret_bytes() -> Vec<u8>`, `pub fn build_totp(secret_bytes: Vec<u8>, account_name: String) -> totp_rs::TOTP`, `pub fn base32_secret(totp: &TOTP) -> String`, `pub fn provisioning_qr_png(totp: &TOTP) -> Result<Vec<u8>, String>`, `pub fn verify_code(secret_bytes: &[u8], account_name: &str, code: &str, now_unix: u64) -> Option<i64>` (returns the matched time-step, for the caller's replay-ledger check — Plan 2/3 will check/insert `totp_replay_ledger` around this). Used later by `/enroll` (QR + base32 display) and `/auth` (code verification).

- [ ] **Step 1: Write `src/crypto/totp.rs` with stubs and failing tests**

```rust
use totp_rs::{Algorithm, Secret, TOTP};

pub const STEP_SECONDS: i64 = 30;

pub fn generate_secret_bytes() -> Vec<u8> {
    todo!()
}

pub fn build_totp(_secret_bytes: Vec<u8>, _account_name: String) -> TOTP {
    todo!()
}

pub fn base32_secret(_totp: &TOTP) -> String {
    todo!()
}

pub fn provisioning_qr_png(_totp: &TOTP) -> Result<Vec<u8>, String> {
    todo!()
}

pub fn verify_code(_secret_bytes: &[u8], _account_name: &str, _code: &str, _now_unix: u64) -> Option<i64> {
    todo!()
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
```

Add `pub mod totp;` to `src/crypto/mod.rs`.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test crypto::totp::tests 2>&1 | tail -30
```

Expected: panics with `not yet implemented`.

- [ ] **Step 3: Implement all functions**

```rust
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test crypto::totp::tests 2>&1 | tail -30
```

Expected: `test result: ok. 7 passed`.

- [ ] **Step 5: Commit**

```bash
git add src/crypto/totp.rs src/crypto/mod.rs
git commit -m "Add TOTP generation, QR provisioning, and windowed code verification"
```

---

## Task 5: Backup codes module

**Files:**
- Create: `src/crypto/backup_codes.rs`
- Modify: `src/crypto/mod.rs` (add `pub mod backup_codes;`)

**Interfaces:**
- Consumes: nothing.
- Produces: `pub const CODE_COUNT: usize = 10`, `pub fn generate_codes(count: usize) -> Vec<String>`, `pub fn hash_code(code: &str) -> String`, `pub fn verify_code(code: &str, hash: &str) -> bool`. Used later by enrollment (issue+hash 10 codes) and a future `/auth` fallback path.

- [ ] **Step 1: Write `src/crypto/backup_codes.rs` with stubs and failing tests**

```rust
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::RngExt;

pub const CODE_COUNT: usize = 10;
const CODE_LEN: usize = 10;
// No 0/O/1/I, to avoid ambiguous characters when a human reads a printed code aloud.
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub fn generate_codes(_count: usize) -> Vec<String> {
    todo!()
}

pub fn hash_code(_code: &str) -> String {
    todo!()
}

pub fn verify_code(_code: &str, _hash: &str) -> bool {
    todo!()
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
```

Add `pub mod backup_codes;` to `src/crypto/mod.rs`.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test crypto::backup_codes::tests 2>&1 | tail -30
```

Expected: panics with `not yet implemented`.

- [ ] **Step 3: Implement all functions**

```rust
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test crypto::backup_codes::tests 2>&1 | tail -30
```

Expected: `test result: ok. 6 passed`.

- [ ] **Step 5: Commit**

```bash
git add src/crypto/backup_codes.rs src/crypto/mod.rs
git commit -m "Add backup code generation and argon2 hashing"
```

---

## Task 6: Yubico OTP verification client

**Files:**
- Create: `src/yubico.rs`
- Modify: `src/main.rs` (add `mod yubico;`)

**Interfaces:**
- Consumes: nothing (constructs its own `reqwest::Client`).
- Produces: `pub struct YubicoClient`, `pub struct YubicoVerifyResult { pub public_id: String, pub valid: bool }`, `pub enum YubicoError`, `YubicoClient::new(client_id: String, secret_key_base64: &str) -> Self`, `async fn YubicoClient::verify_otp(&self, otp: &str) -> Result<YubicoVerifyResult, YubicoError>`. Used later by `/enroll yubikey` and `/auth` for the YubiKey factor path.
- Note: `verify_otp` makes a real network call to `api.yubico.com` and is **not** unit tested here — only its pure helper functions (`parse_field`, `sign_params`, `generate_nonce`) are. `verify_otp` itself gets verified during Plan 3's live testing with a real YubiKey and your Yubico API credentials.

- [ ] **Step 1: Write `src/yubico.rs` with stubs and failing tests for the pure helpers**

```rust
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
        if otp.len() < 12 {
            return Err(YubicoError::OtpTooShort);
        }
        let public_id = otp[..12].to_string();
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

fn sign_params(_secret_key: &[u8], _sorted_params: &[(String, String)]) -> String {
    todo!()
}

fn generate_nonce() -> String {
    todo!()
}

fn parse_field<'a>(_body: &'a str, _key: &str) -> Option<&'a str> {
    todo!()
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
```

Add `mod yubico;` to `src/main.rs`.

- [ ] **Step 2: Run tests to verify the three implemented-with-`todo!()` ones fail**

```bash
cargo test yubico::tests 2>&1 | tail -30
```

Expected: `parse_field_*` and `sign_params_*` and `generate_nonce_*` tests panic with `not yet implemented`.

- [ ] **Step 3: Implement the three helper functions**

```rust
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test yubico::tests 2>&1 | tail -30
```

Expected: `test result: ok. 6 passed`.

- [ ] **Step 5: Commit**

```bash
git add src/yubico.rs src/main.rs
git commit -m "Add Yubico OTP verification client with signed requests"
```

---

## Task 7: Database schema and connection pool

**Files:**
- Create: `migrations/0001_init.sql`
- Create: `src/db.rs`
- Modify: `src/main.rs` (add `mod db;`)

**Interfaces:**
- Consumes: `database_url: &str` (from `Config::database_url`, Task 2).
- Produces: `pub async fn init_pool(database_url: &str) -> Result<sqlx::PgPool, sqlx::Error>`, `pub async fn run_migrations(pool: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError>`. Used by `main.rs` in Task 8, and by every future command task's data-access code (Plan 2+) which will query these tables directly via `sqlx::query!`.
- This task has no unit tests — connecting to and migrating a real Postgres database isn't pure logic. It's verified live against the real `sudobot_guard` database instead, consistent with this plan's testing approach (pure logic gets unit tests, everything that talks to an external system gets live verification).

- [ ] **Step 1: Write the full schema migration**

Create `migrations/0001_init.sql`:

```sql
CREATE TABLE bot_admins (
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, user_id)
);

CREATE TABLE role_pairs (
    id BIGSERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    standard_role_id BIGINT NOT NULL,
    permission_role_id BIGINT NOT NULL,
    session_minutes INTEGER NOT NULL,
    alert_tier TEXT NOT NULL DEFAULT 'info',
    created_by BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (guild_id, standard_role_id),
    UNIQUE (guild_id, permission_role_id)
);

CREATE TABLE totp_enrollments (
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    totp_secret_encrypted BYTEA NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT false,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, user_id)
);

CREATE TABLE yubikey_enrollments (
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    yubikey_public_id TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT true,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, user_id)
);

CREATE TABLE enrollment_requests (
    id BIGSERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    factor_type TEXT NOT NULL CHECK (factor_type IN ('totp', 'yubikey')),
    action TEXT NOT NULL CHECK (action IN ('add', 'regenerate')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'expired', 'fulfilled')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_by BIGINT,
    approved_at TIMESTAMPTZ,
    window_minutes INTEGER,
    window_expires_at TIMESTAMPTZ
);

CREATE TABLE backup_codes (
    id BIGSERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE TABLE totp_replay_ledger (
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    time_step BIGINT NOT NULL,
    used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, user_id, time_step)
);

CREATE TABLE auth_attempts (
    id BIGSERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    success BOOLEAN NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id BIGSERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    role_pair_id BIGINT NOT NULL REFERENCES role_pairs(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoke_reason TEXT
);

CREATE TABLE log_channels (
    guild_id BIGINT PRIMARY KEY,
    channel_id BIGINT NOT NULL
);

CREATE TABLE log_sequence (
    guild_id BIGINT PRIMARY KEY,
    next_seq BIGINT NOT NULL DEFAULT 1
);

CREATE INDEX idx_auth_attempts_guild_user_time ON auth_attempts (guild_id, user_id, attempted_at);
CREATE INDEX idx_sessions_expiry ON sessions (expires_at) WHERE revoked_at IS NULL;
```

- [ ] **Step 2: Write `src/db.rs`**

```rust
use sqlx::postgres::{PgPool, PgPoolOptions};

pub async fn init_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}
```

Add `mod db;` to `src/main.rs`.

- [ ] **Step 3: Verify the migration runs against the real database**

```bash
sqlx migrate run --database-url "$(grep DATABASE_URL .env | cut -d= -f2-)"
```

Expected: `Applied 1/migrate init (<time>)`.

- [ ] **Step 4: Verify the tables exist**

```bash
psql "$(grep DATABASE_URL .env | cut -d= -f2-)" -c "\dt"
```

Expected: lists all 11 tables (`bot_admins`, `role_pairs`, `totp_enrollments`, `yubikey_enrollments`, `enrollment_requests`, `backup_codes`, `totp_replay_ledger`, `auth_attempts`, `sessions`, `log_channels`, `log_sequence`) plus sqlx's own `_sqlx_migrations`.

- [ ] **Step 5: Commit**

```bash
git add migrations/0001_init.sql src/db.rs src/main.rs
git commit -m "Add Postgres schema migration and connection pool"
```

---

## Task 8: Wire up `main.rs` — first live boot

**Files:**
- Modify: `src/main.rs` (replace placeholder body entirely)

**Interfaces:**
- Consumes: `config::Config::from_env()` (Task 2), `db::init_pool`/`db::run_migrations` (Task 7). `crypto::*` and `yubico::YubicoClient` are not yet used here — they're wired into command handlers starting in Plan 2 — but their `mod` declarations must remain so `cargo build`/`cargo test` keep covering them.
- Produces: a running process. This is the plan's final deliverable: the bot connects to Postgres, migrates, connects to Discord, and logs on the `ready` event.

- [ ] **Step 1: Replace `src/main.rs`**

```rust
mod config;
mod crypto;
mod db;
mod yubico;

use config::Config;
use serenity::async_trait;
use serenity::model::gateway::Ready;
use serenity::prelude::*;

struct Handler;

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, _ctx: Context, ready: Ready) {
        tracing::info!(bot_name = %ready.user.name, "connected and ready");
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    dotenvy::dotenv().ok();

    let config = Config::from_env().expect("invalid configuration — check .env against .env.example");

    let pool = db::init_pool(&config.database_url)
        .await
        .expect("failed to connect to Postgres");
    db::run_migrations(&pool)
        .await
        .expect("failed to run database migrations");
    tracing::info!("database connected and migrated");

    let intents = GatewayIntents::GUILDS | GatewayIntents::GUILD_MEMBERS;
    let mut client = Client::builder(&config.discord_token, intents)
        .event_handler(Handler)
        .await
        .expect("failed to create Discord client — check DISCORD_TOKEN");

    if let Err(why) = client.start().await {
        tracing::error!(error = ?why, "client error");
    }
}
```

- [ ] **Step 2: Build**

```bash
cargo build 2>&1 | tail -20
```

Expected: `Finished` with no errors.

- [ ] **Step 3: Run the full test suite one more time before the live check**

```bash
cargo test 2>&1 | tail -40
```

Expected: all tests from Tasks 2–6 still pass (26 total: 3 config + 4 encryption + 7 totp + 6 backup_codes + 6 yubico), `test result: ok`.

- [ ] **Step 4: Live check — run the bot and confirm it comes online**

```bash
cargo run 2>&1 | tail -20
```

Expected log output: `database connected and migrated` followed by `connected and ready`. **Pause here and ask the user to confirm the bot shows as online in their Discord server** before stopping the process (Ctrl+C) and moving on — this is the live-test checkpoint referenced in the design spec.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "Wire up main.rs: config, DB migration, and Discord client boot"
```

---

## Plan-level self-review notes

- **Spec coverage**: this plan covers Phase 1 design spec §3 (tech stack), §4 (data model — all 11 tables), and the crypto/Yubico primitives needed by §5 (enrollment) and §6 (elevation). It deliberately does **not** cover any command (`/setup`, `/protect`, `/enroll`, `/auth`, etc.) or the expiry sweep — those are Plan 2 (Admin & Registry) and beyond, per the phased approach agreed during brainstorming.
- **Type consistency**: `Config.database_url: String` (Task 2) is the exact parameter type `db::init_pool(database_url: &str)` (Task 7) expects. `crypto::totp::verify_code` returns `Option<i64>` (the time step) rather than `bool`, matching the design spec's requirement that the caller checks/inserts into `totp_replay_ledger` — that table's `time_step` column is `BIGINT`, consistent with `i64`.
- **No placeholders remain** outside of the intentional `todo!()` stubs that each task's own steps immediately replace with real implementations.
