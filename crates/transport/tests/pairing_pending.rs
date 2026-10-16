#![cfg(unix)]
use seamless_transport::{
    IdentityStore,
    pairing_pending::{PendingStore, StoreError},
};

#[test]
fn quarantined_candidate_never_appears_in_active_pins() {
    let home = tempfile::tempdir().unwrap();
    let identity = IdentityStore::open_or_create(home.path(), "local").unwrap();
    let store = PendingStore::open(home.path()).unwrap();
    let version = store.version().unwrap();
    store.prepare(version, [1; 32], [2; 32]).unwrap();
    assert!(store.pending([1; 32]).unwrap().is_some());
    assert_eq!(identity.peers().count(), 0);
    assert_eq!(
        IdentityStore::open_or_create(home.path(), "local")
            .unwrap()
            .peers()
            .count(),
        0
    );
    assert_eq!(
        store.promote([1; 32]).unwrap_err(),
        StoreError::VerificationUnavailable
    );
    assert!(home.path().join("pairing-pending").is_dir());
    assert!(home.path().join("pairing-tombstones").is_dir());
    assert!(!home.path().join("peers.json").exists());
}

#[test]
fn stale_writer_cannot_overwrite_a_durable_revoke_after_reopen() {
    let home = tempfile::tempdir().unwrap();
    let first = PendingStore::open(home.path()).unwrap();
    let stale = PendingStore::open(home.path()).unwrap();
    let version = stale.version().unwrap();
    first.prepare(version, [1; 32], [2; 32]).unwrap();
    first
        .revoke_candidate(first.version().unwrap(), [2; 32])
        .unwrap();
    assert_eq!(
        stale.prepare(version, [3; 32], [2; 32]).unwrap_err(),
        StoreError::Conflict
    );
    let reopened = PendingStore::open(home.path()).unwrap();
    assert!(reopened.pending([1; 32]).unwrap().is_none());
    assert_eq!(
        reopened
            .prepare(reopened.version().unwrap(), [1; 32], [2; 32])
            .unwrap_err(),
        StoreError::ConsumedAttempt
    );
    assert_eq!(reopened.revocation_generation([2; 32]).unwrap(), 1);
}

#[test]
fn cancelled_attempt_cannot_be_replayed_or_delete_a_newer_candidate() {
    let home = tempfile::tempdir().unwrap();
    let store = PendingStore::open(home.path()).unwrap();
    store
        .prepare(store.version().unwrap(), [1; 32], [2; 32])
        .unwrap();
    let before = store.version().unwrap();
    store.cancel(before, [1; 32]).unwrap();
    store
        .prepare(store.version().unwrap(), [3; 32], [2; 32])
        .unwrap();
    assert_eq!(
        store.cancel(before, [1; 32]).unwrap_err(),
        StoreError::Conflict
    );
    assert!(store.pending([3; 32]).unwrap().is_some());
    assert_eq!(
        store
            .prepare(store.version().unwrap(), [1; 32], [2; 32])
            .unwrap_err(),
        StoreError::ConsumedAttempt
    );
}

#[test]
fn identity_rotation_invalidates_all_pending_and_previous_versions() {
    let home = tempfile::tempdir().unwrap();
    let store = PendingStore::open(home.path()).unwrap();
    store
        .prepare(store.version().unwrap(), [1; 32], [2; 32])
        .unwrap();
    let old = store.version().unwrap();
    store.rotate_identity(old).unwrap();
    assert!(store.pending([1; 32]).unwrap().is_none());
    assert_eq!(
        store.version().unwrap().identity_generation,
        old.identity_generation + 1
    );
    assert_eq!(
        store.prepare(old, [3; 32], [2; 32]).unwrap_err(),
        StoreError::Conflict
    );
}

#[test]
fn corrupt_state_and_symlinked_directories_fail_closed() {
    use std::os::unix::fs::symlink;
    let home = tempfile::tempdir().unwrap();
    let store = PendingStore::open(home.path()).unwrap();
    std::fs::write(
        home.path().join("pairing-tombstones/ledger.json"),
        b"not-json",
    )
    .unwrap();
    assert!(store.version().is_err());
    assert!(PendingStore::open(home.path()).is_err());
    let another = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), another.path().join("pairing-pending")).unwrap();
    assert!(PendingStore::open(another.path()).is_err());
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[test]
fn parallel_cas_writers_have_exactly_one_winner() {
    let home = tempfile::tempdir().unwrap();
    let store = PendingStore::open(home.path()).unwrap();
    let version = store.version().unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = [1u8, 2]
        .into_iter()
        .map(|id| {
            let path = home.path().to_owned();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let store = PendingStore::open(path).unwrap();
                barrier.wait();
                store.prepare(version, [id; 32], [4; 32])
            })
        })
        .collect();
    let results: Vec<_> = workers.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(StoreError::Conflict)))
            .count(),
        1
    );
}

#[test]
fn missing_ledger_is_data_loss_not_a_fresh_epoch() {
    let home = tempfile::tempdir().unwrap();
    let store = PendingStore::open(home.path()).unwrap();
    store
        .revoke_candidate(store.version().unwrap(), [2; 32])
        .unwrap();
    std::fs::remove_file(home.path().join("pairing-tombstones/ledger.json")).unwrap();
    assert!(store.version().is_err());
    assert!(PendingStore::open(home.path()).is_err());
}

#[test]
fn corrupt_or_indirected_pending_file_is_never_returned_as_a_candidate() {
    use std::os::unix::fs::symlink;
    let home = tempfile::tempdir().unwrap();
    let store = PendingStore::open(home.path()).unwrap();
    store
        .prepare(store.version().unwrap(), [1; 32], [2; 32])
        .unwrap();
    let path = home
        .path()
        .join("pairing-pending")
        .join(format!("{}.json", "01".repeat(32)));
    let original = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"{}").unwrap();
    assert!(store.pending([1; 32]).is_err());
    std::fs::remove_file(&path).unwrap();
    let outside = home.path().join("untrusted.json");
    std::fs::write(&outside, &original).unwrap();
    symlink(&outside, &path).unwrap();
    assert!(store.pending([1; 32]).is_err());
    assert_eq!(std::fs::read(outside).unwrap(), original);
}

#[test]
fn denied_ledger_write_does_not_commit_an_orphan_candidate() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let store = PendingStore::open(home.path()).unwrap();
    let before = store.version().unwrap();
    let directory = home.path().join("pairing-tombstones");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = store.prepare(before, [1; 32], [2; 32]);
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());
    assert_eq!(store.version().unwrap(), before);
    assert!(store.pending([1; 32]).unwrap().is_none());
}

#[test]
fn pending_file_is_private_and_bound_to_the_ledger_version() {
    use std::os::unix::fs::MetadataExt;
    let home = tempfile::tempdir().unwrap();
    let store = PendingStore::open(home.path()).unwrap();
    let record = store
        .prepare(store.version().unwrap(), [1; 32], [2; 32])
        .unwrap();
    assert_eq!(record.version.revision, 1);
    assert_eq!(record.version.identity_generation, 0);
    assert_eq!(record.revocation_generation, 0);
    let path = home
        .path()
        .join("pairing-pending")
        .join(format!("{}.json", "01".repeat(32)));
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    let content: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        content["attempt_id"],
        serde_json::json!([
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1
        ])
    );
    assert_eq!(
        content.as_object().unwrap().len(),
        4,
        "quarantine stores only bounded public metadata"
    );
}
