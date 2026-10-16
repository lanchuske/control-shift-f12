use std::time::{Duration, UNIX_EPOCH};

use seamless_input::runtime_status::{RuntimeStatus, RuntimeStatusStore};

fn snapshot(updated_ms: u64, sessions: usize) -> RuntimeStatus {
    RuntimeStatus {
        process_id: 4242,
        updated_unix_ms: updated_ms,
        displays: 2,
        authenticated_sessions: sessions,
    }
}

#[test]
fn current_runtime_status_round_trips_without_inventing_sessions() {
    let root = tempfile::tempdir().unwrap();
    let store = RuntimeStatusStore::new(root.path().join("runtime-status.v1"));
    let now = UNIX_EPOCH + Duration::from_secs(100);

    store.publish(&snapshot(100_000, 3)).unwrap();
    let current = store.read_current(now).unwrap().unwrap();

    assert_eq!(current.displays, 2);
    assert_eq!(current.authenticated_sessions, 3);
    assert!(!root.path().join("runtime-status.v1.tmp").exists());
}

#[test]
fn stale_or_malformed_status_fails_closed_as_not_running() {
    let root = tempfile::tempdir().unwrap();
    let store = RuntimeStatusStore::new(root.path().join("runtime-status.v1"));

    store.publish(&snapshot(10_000, 7)).unwrap();
    assert!(
        store
            .read_current(UNIX_EPOCH + Duration::from_secs(20))
            .unwrap()
            .is_none(),
        "a stale heartbeat must never claim a live authenticated session"
    );

    std::fs::write(store.path(), "authenticated_sessions=999\n").unwrap();
    assert!(
        store
            .read_current(UNIX_EPOCH + Duration::from_secs(20))
            .is_err(),
        "a partial snapshot must not be accepted"
    );
}

#[test]
fn clearing_runtime_status_removes_the_live_claim() {
    let root = tempfile::tempdir().unwrap();
    let store = RuntimeStatusStore::new(root.path().join("runtime-status.v1"));
    store.publish(&snapshot(100_000, 1)).unwrap();
    store.clear().unwrap();
    assert!(
        store
            .read_current(UNIX_EPOCH + Duration::from_secs(100))
            .unwrap()
            .is_none()
    );
}
