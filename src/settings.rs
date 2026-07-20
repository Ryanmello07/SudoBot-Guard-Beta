use sqlx::PgPool;

pub const ADMIN_REGEN_COOLDOWN_MINUTES_KEY: &str = "admin_regen_cooldown_minutes";
pub const ADMIN_REGEN_COOLDOWN_MINUTES_DEFAULT: i64 = 1440;

/// All keys `/settings set` will accept. Add new entries here as the bot
/// grows more configurable rules.
pub const KNOWN_KEYS: &[&str] = &[ADMIN_REGEN_COOLDOWN_MINUTES_KEY];

pub fn validate_setting(key: &str, value: &str) -> Result<(), String> {
    if !KNOWN_KEYS.contains(&key) {
        return Err(format!("unknown setting: {key}"));
    }
    match key {
        ADMIN_REGEN_COOLDOWN_MINUTES_KEY => {
            let n: i64 = value
                .parse()
                .map_err(|_| "must be a positive integer (minutes)".to_string())?;
            if n <= 0 {
                return Err("must be positive".to_string());
            }
            Ok(())
        }
        _ => unreachable!("KNOWN_KEYS check above already rejected unknown keys"),
    }
}

pub async fn get_int_setting(
    pool: &PgPool,
    guild_id: i64,
    key: &str,
    default: i64,
) -> Result<i64, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT value FROM guild_settings WHERE guild_id = $1 AND key = $2",
        guild_id,
        key
    )
    .fetch_optional(pool)
    .await?;
    Ok(row
        .and_then(|r| r.value.parse::<i64>().ok())
        .unwrap_or(default))
}

pub async fn set_setting(
    pool: &PgPool,
    guild_id: i64,
    key: &str,
    value: &str,
    updated_by: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO guild_settings (guild_id, key, value, updated_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (guild_id, key) DO UPDATE
         SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()",
        guild_id,
        key,
        value,
        updated_by
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_cooldown_value() {
        assert_eq!(
            validate_setting(ADMIN_REGEN_COOLDOWN_MINUTES_KEY, "1440"),
            Ok(())
        );
    }

    #[test]
    fn rejects_zero_cooldown() {
        assert!(validate_setting(ADMIN_REGEN_COOLDOWN_MINUTES_KEY, "0").is_err());
    }

    #[test]
    fn rejects_negative_cooldown() {
        assert!(validate_setting(ADMIN_REGEN_COOLDOWN_MINUTES_KEY, "-5").is_err());
    }

    #[test]
    fn rejects_non_numeric_cooldown() {
        assert!(validate_setting(ADMIN_REGEN_COOLDOWN_MINUTES_KEY, "soon").is_err());
    }

    #[test]
    fn rejects_unknown_key() {
        assert!(validate_setting("not_a_real_setting", "123").is_err());
    }
}
