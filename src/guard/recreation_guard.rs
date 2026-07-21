use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

static IN_PROGRESS: OnceLock<Mutex<HashSet<(i64, i64)>>> = OnceLock::new();

fn set() -> &'static Mutex<HashSet<(i64, i64)>> {
    IN_PROGRESS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Claims exclusive responsibility for recreating this role. Returns `true`
/// if the caller should proceed, `false` if another in-process task (the
/// reactive audit-log handler firing twice for the same deletion, or the
/// periodic sweep) is already recreating it.
///
/// Recreation spans a role-create network call followed by a DB repoint of
/// `role_pairs`; without this guard, two callers can both observe the role
/// as "registered but missing" before either repoint lands, and each create
/// a replacement — this happened live: the same deletion produced two new
/// roles 268ms apart.
pub fn try_claim(guild_id_i64: i64, role_id_i64: i64) -> bool {
    set().lock().unwrap().insert((guild_id_i64, role_id_i64))
}

/// Releases a claim taken by `try_claim`. Must be called on every exit path
/// after a successful claim, including early returns.
pub fn release(guild_id_i64: i64, role_id_i64: i64) {
    set().lock().unwrap().remove(&(guild_id_i64, role_id_i64));
}
