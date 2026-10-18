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

#[test]
fn an_old_process_cannot_clear_a_new_process_status() {
    let root = tempfile::tempdir().unwrap();
    let old = RuntimeStatusStore::within(root.path(), 1001);
    let new = RuntimeStatusStore::within(root.path(), 2002);
    old.publish(&RuntimeStatus {
        process_id: 1001,
        ..snapshot(100_000, 1)
    })
    .unwrap();
    new.publish(&RuntimeStatus {
        process_id: 2002,
        ..snapshot(100_000, 2)
    })
    .unwrap();

    old.clear_owned(1001).unwrap();

    assert!(
        old.read_current(UNIX_EPOCH + Duration::from_secs(100))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        new.read_current(UNIX_EPOCH + Duration::from_secs(100))
            .unwrap()
            .unwrap()
            .authenticated_sessions,
        2
    );
}

#[test]
fn ownership_mismatch_cannot_clear_or_publish_a_status() {
    let root = tempfile::tempdir().unwrap();
    let store = RuntimeStatusStore::within(root.path(), 4242);
    assert!(
        store
            .publish(&RuntimeStatus {
                process_id: 7,
                ..snapshot(100_000, 1)
            })
            .is_err()
    );
    store.publish(&snapshot(100_000, 1)).unwrap();
    assert!(store.clear_owned(7).is_err());
    assert!(store.path().exists());

    let foreign =
        "version=1\nprocess_id=7\nupdated_unix_ms=100000\ndisplays=1\nauthenticated_sessions=9\n";
    std::fs::write(store.path(), foreign).unwrap();
    assert!(store.clear_owned(4242).is_err());
    assert!(
        store.path().exists(),
        "compare-and-clear must preserve a foreign owner"
    );
}

#[test]
fn failed_replace_does_not_destroy_the_last_good_heartbeat() {
    let root = tempfile::tempdir().unwrap();
    let store = RuntimeStatusStore::within(root.path(), 4242);
    store.publish(&snapshot(100_000, 1)).unwrap();
    let mut temp_name = store.path().as_os_str().to_owned();
    temp_name.push(".tmp");
    std::fs::create_dir(std::path::PathBuf::from(temp_name)).unwrap();

    assert!(store.publish(&snapshot(101_000, 9)).is_err());
    assert_eq!(
        store
            .read_current(UNIX_EPOCH + Duration::from_secs(100))
            .unwrap()
            .unwrap()
            .authenticated_sessions,
        1
    );
}
