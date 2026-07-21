use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

static IN_PROGRESS: OnceLock<Mutex<HashSet<i64>>> = OnceLock::new();

fn set() -> &'static Mutex<HashSet<i64>> {
    IN_PROGRESS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Claims exclusive responsibility for reconciling this guild's role
/// positions. Returns `true` if the caller should proceed, `false` if
/// another in-process task is already reconciling it.
///
/// A single manual reorder can generate several `guild_role_update` events
/// in quick succession (every role Discord shifts as a side effect gets its
/// own event) — without this guard, each would independently recompute and
/// fire its own bulk correction. `reaction::reconcile_positions` is
/// idempotent (each call converges to the same target state), so an
/// overlap isn't unsafe, just wasteful; this keeps it to one call per burst.
pub fn try_claim(guild_id_i64: i64) -> bool {
    set().lock().unwrap().insert(guild_id_i64)
}

/// Releases a claim taken by `try_claim`. Must be called on every exit path
/// after a successful claim, including early returns.
pub fn release(guild_id_i64: i64) {
    set().lock().unwrap().remove(&guild_id_i64);
}

/// Releases a claim after a short delay instead of immediately. A bulk
/// position correction generates its own `guild_role_update` echo for every
/// role it moved, delivered asynchronously — releasing the claim right away
/// (before those echoes land) lets each one independently re-scan a
/// still-settling cache and fire its own redundant bulk correction. Holding
/// the claim a couple seconds longer absorbs that whole echo burst as one
/// correction instead of several; it's not required for correctness (each
/// redundant correction still converges to the same baseline-derived
/// target), just for not spamming the log channel with duplicate "Role
/// Positions Reconciled" entries for what was really one reorder.
pub fn release_after_delay(guild_id_i64: i64, delay: std::time::Duration) {
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        release(guild_id_i64);
    });
}
