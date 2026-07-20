use sqlx::PgPool;

pub const ADMIN_REGEN_COOLDOWN_MINUTES_KEY: &str = "admin_regen_cooldown_minutes";
pub const ADMIN_REGEN_COOLDOWN_MINUTES_DEFAULT: i64 = 1440;

pub const ADMIN_REGEN_COMPLETION_WINDOW_MINUTES_KEY: &str = "admin_regen_completion_window_minutes";
pub const ADMIN_REGEN_COMPLETION_WINDOW_MINUTES_DEFAULT: i64 = 1440;

/// Generous upper bound for any minutes-valued setting (~30 days). Chosen so
/// two such settings summed together (e.g. a cooldown plus a completion
/// window) stay far below i32::MAX when narrowed for interval arithmetic,
/// with no realistic legitimate use case anywhere close to this ceiling.
pub const MAX_SETTING_MINUTES: i64 = 43_200;

/// A single configurable, integer-valued (minutes) server setting: its
/// storage key, a human-readable description shown in `/settings view`, and
/// its default when unset. Add new entries here as the bot grows more
/// configurable rules — `/settings view`, `/settings set`'s choices, and
/// validation should all derive from this one list rather than duplicating
/// per-key logic elsewhere.
pub struct SettingDefinition {
    pub key: &'static str,
    pub description: &'static str,
    pub default: i64,
}

pub const SETTINGS_REGISTRY: &[SettingDefinition] = &[
    SettingDefinition {
        key: ADMIN_REGEN_COOLDOWN_MINUTES_KEY,
        description: "How long a bot admin must wait after requesting a factor regenerate before they're allowed to complete it.",
        default: ADMIN_REGEN_COOLDOWN_MINUTES_DEFAULT,
    },
    SettingDefinition {
        key: ADMIN_REGEN_COMPLETION_WINDOW_MINUTES_KEY,
        description: "Once the cooldown above has passed, how long the admin has to actually complete the regenerate before the request expires and they have to start over.",
        default: ADMIN_REGEN_COMPLETION_WINDOW_MINUTES_DEFAULT,
    },
];

/// All settings currently take a positive integer number of minutes, capped
/// well under i32::MAX so values can never overflow/wrap when narrowed to
/// i32 for interval arithmetic (Postgres `make_interval` and similar) — no
/// per-key match needed unless a future setting has different rules.
pub fn validate_setting(key: &str, value: &str) -> Result<(), String> {
    if !SETTINGS_REGISTRY.iter().any(|s| s.key == key) {
        return Err(format!("unknown setting: {key}"));
    }
    let n: i64 = value
        .parse()
        .map_err(|_| "must be a positive integer (minutes)".to_string())?;
    if n <= 0 {
        return Err("must be positive".to_string());
    }
    if n > MAX_SETTING_MINUTES {
        return Err(format!("must be at most {MAX_SETTING_MINUTES} minutes ({} days)", MAX_SETTING_MINUTES / 1440));
    }
    Ok(())
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

    #[test]
    fn accepts_valid_completion_window_value() {
        assert_eq!(
            validate_setting(ADMIN_REGEN_COMPLETION_WINDOW_MINUTES_KEY, "1440"),
            Ok(())
        );
    }

    #[test]
    fn rejects_zero_completion_window() {
        assert!(validate_setting(ADMIN_REGEN_COMPLETION_WINDOW_MINUTES_KEY, "0").is_err());
    }

    #[test]
    fn registry_contains_both_keys() {
        let keys: Vec<&str> = SETTINGS_REGISTRY.iter().map(|s| s.key).collect();
        assert!(keys.contains(&ADMIN_REGEN_COOLDOWN_MINUTES_KEY));
        assert!(keys.contains(&ADMIN_REGEN_COMPLETION_WINDOW_MINUTES_KEY));
    }

    #[test]
    fn accepts_value_at_the_max_bound() {
        assert_eq!(
            validate_setting(ADMIN_REGEN_COOLDOWN_MINUTES_KEY, &MAX_SETTING_MINUTES.to_string()),
            Ok(())
        );
    }

    #[test]
    fn rejects_value_over_the_max_bound() {
        assert!(validate_setting(
            ADMIN_REGEN_COOLDOWN_MINUTES_KEY,
            &(MAX_SETTING_MINUTES + 1).to_string()
        )
        .is_err());
    }
}
