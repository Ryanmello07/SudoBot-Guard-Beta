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

pub const QUARANTINE_ON_MANUAL_GRANT_KEY: &str = "quarantine_on_manual_grant";
pub const QUARANTINE_ON_MANUAL_GRANT_DEFAULT: bool = true;

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum SettingKind {
    Minutes,
    Bool,
}

/// A single configurable server setting: its storage key, a human-readable
/// description shown in `/settings view`, its kind (which determines how
/// `validate_setting` parses input and how the UI renders/prefills it), and
/// its default. For `Bool`-kind settings, `default` is 0 (false) or 1
/// (true) — kept as `i64` so the struct stays uniform across both kinds
/// rather than needing an enum-of-defaults.
pub struct SettingDefinition {
    pub key: &'static str,
    pub description: &'static str,
    pub kind: SettingKind,
    pub default: i64,
}

pub const SETTINGS_REGISTRY: &[SettingDefinition] = &[
    SettingDefinition {
        key: ADMIN_REGEN_COOLDOWN_MINUTES_KEY,
        description: "How long a bot admin must wait after requesting a factor regenerate before they're allowed to complete it.",
        kind: SettingKind::Minutes,
        default: ADMIN_REGEN_COOLDOWN_MINUTES_DEFAULT,
    },
    SettingDefinition {
        key: ADMIN_REGEN_COMPLETION_WINDOW_MINUTES_KEY,
        description: "Once the cooldown above has passed, how long the admin has to actually complete the regenerate before the request expires and they have to start over.",
        kind: SettingKind::Minutes,
        default: ADMIN_REGEN_COMPLETION_WINDOW_MINUTES_DEFAULT,
    },
    SettingDefinition {
        key: QUARANTINE_ON_MANUAL_GRANT_KEY,
        description: "When a registered permission role is granted manually (outside the bot), also strip the granter's own active sessions. Set to false to only revert the grant, without quarantining the granter.",
        kind: SettingKind::Bool,
        default: QUARANTINE_ON_MANUAL_GRANT_DEFAULT as i64,
    },
];

pub fn validate_setting(key: &str, value: &str) -> Result<(), String> {
    let def = SETTINGS_REGISTRY
        .iter()
        .find(|s| s.key == key)
        .ok_or_else(|| format!("unknown setting: {key}"))?;

    match def.kind {
        SettingKind::Minutes => {
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
        SettingKind::Bool => {
            if value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false") {
                Ok(())
            } else {
                Err("must be true or false".to_string())
            }
        }
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

pub async fn get_bool_setting(
    pool: &PgPool,
    guild_id: i64,
    key: &str,
    default: bool,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT value FROM guild_settings WHERE guild_id = $1 AND key = $2",
        guild_id,
        key
    )
    .fetch_optional(pool)
    .await?;
    Ok(row
        .and_then(|r| {
            if r.value.eq_ignore_ascii_case("true") {
                Some(true)
            } else if r.value.eq_ignore_ascii_case("false") {
                Some(false)
            } else {
                None
            }
        })
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

    #[test]
    fn accepts_true_for_bool_setting() {
        assert_eq!(validate_setting(QUARANTINE_ON_MANUAL_GRANT_KEY, "true"), Ok(()));
    }

    #[test]
    fn accepts_false_for_bool_setting() {
        assert_eq!(validate_setting(QUARANTINE_ON_MANUAL_GRANT_KEY, "false"), Ok(()));
    }

    #[test]
    fn accepts_mixed_case_bool_value() {
        assert_eq!(validate_setting(QUARANTINE_ON_MANUAL_GRANT_KEY, "True"), Ok(()));
    }

    #[test]
    fn rejects_non_bool_value_for_bool_setting() {
        assert!(validate_setting(QUARANTINE_ON_MANUAL_GRANT_KEY, "1440").is_err());
    }

    #[test]
    fn registry_contains_quarantine_key() {
        let keys: Vec<&str> = SETTINGS_REGISTRY.iter().map(|s| s.key).collect();
        assert!(keys.contains(&QUARANTINE_ON_MANUAL_GRANT_KEY));
    }
}
