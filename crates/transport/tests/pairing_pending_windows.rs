#![cfg(windows)]

use seamless_transport::pairing_pending::{PendingStore, StoreError};

fn record_path(root: &std::path::Path, byte: u8) -> std::path::PathBuf {
    root.join("pairing-pending")
        .join(format!("{}.json", format!("{byte:02x}").repeat(32)))
}

#[test]
fn windows_store_supports_cas_reopen_tombstones_and_separate_roots() {
    let root = tempfile::tempdir().unwrap();
    let store = PendingStore::open(root.path()).unwrap();
    let original = store.version().unwrap();
    let record = store.prepare(original, [1; 32], [2; 32]).unwrap();
    assert_eq!(record.version.revision, 1);
    assert!(root.path().join("pairing-pending").is_dir());
    assert!(root.path().join("pairing-tombstones").is_dir());
    drop(store);

    let reopened = PendingStore::open(root.path()).unwrap();
    assert_eq!(reopened.pending([1; 32]).unwrap(), Some(record));
    assert_eq!(
        reopened.prepare(original, [3; 32], [4; 32]).unwrap_err(),
        StoreError::Conflict
    );
    reopened
        .cancel(reopened.version().unwrap(), [1; 32])
        .unwrap();
    assert_eq!(
        reopened
            .prepare(reopened.version().unwrap(), [1; 32], [2; 32])
            .unwrap_err(),
        StoreError::ConsumedAttempt
    );
}

#[test]
fn windows_cross_process_cas_has_exactly_one_winner() {
    let root = tempfile::tempdir().unwrap();
    let store = PendingStore::open(root.path()).unwrap();
    let version = store.version().unwrap();
    drop(store);
    let mut children = vec![];
    for id in [7u8, 8] {
        children.push(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "windows_cas_child", "--nocapture"])
                .env("CSF12_WINDOWS_STORE_ROOT", root.path())
                .env("CSF12_WINDOWS_STORE_ID", id.to_string())
                .env("CSF12_WINDOWS_STORE_REV", version.revision.to_string())
                .env(
                    "CSF12_WINDOWS_STORE_GEN",
                    version.identity_generation.to_string(),
                )
                .spawn()
                .unwrap(),
        );
    }
    let mut codes: Vec<_> = children
        .iter_mut()
        .map(|child| child.wait().unwrap().code().unwrap())
        .collect();
    codes.sort();
    assert_eq!(codes, [0, 10]);
}

#[test]
fn windows_cas_child() {
    let Ok(root) = std::env::var("CSF12_WINDOWS_STORE_ROOT") else {
        return;
    };
    let id: u8 = std::env::var("CSF12_WINDOWS_STORE_ID")
        .unwrap()
        .parse()
        .unwrap();
    let expected = seamless_transport::pairing_pending::StoreVersion {
        revision: std::env::var("CSF12_WINDOWS_STORE_REV")
            .unwrap()
            .parse()
            .unwrap(),
        identity_generation: std::env::var("CSF12_WINDOWS_STORE_GEN")
            .unwrap()
            .parse()
            .unwrap(),
    };
    let store = PendingStore::open(root).unwrap();
    std::process::exit(match store.prepare(expected, [id; 32], [9; 32]) {
        Ok(_) => 0,
        Err(StoreError::Conflict) => 10,
        Err(other) => panic!("unexpected CAS result: {other:?}"),
    });
}

#[test]
fn windows_hardlinks_directories_and_oversized_records_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let store = PendingStore::open(root.path()).unwrap();
    store
        .prepare(store.version().unwrap(), [1; 32], [2; 32])
        .unwrap();
    let record = record_path(root.path(), 1);
    let outside = root.path().join("outside-link.json");
    std::fs::hard_link(&record, &outside).unwrap();
    assert!(
        store.version().is_err(),
        "hardlinked referenced record admitted"
    );
    drop(store);

    let root = tempfile::tempdir().unwrap();
    let store = PendingStore::open(root.path()).unwrap();
    store
        .prepare(store.version().unwrap(), [1; 32], [2; 32])
        .unwrap();
    let record = record_path(root.path(), 1);
    std::fs::remove_file(&record).unwrap();
    std::fs::create_dir(&record).unwrap();
    assert!(
        store.pending([1; 32]).is_err(),
        "directory admitted as record"
    );
    drop(store);

    let root = tempfile::tempdir().unwrap();
    let store = PendingStore::open(root.path()).unwrap();
    store
        .prepare(store.version().unwrap(), [1; 32], [2; 32])
        .unwrap();
    std::fs::write(record_path(root.path(), 1), vec![b'x'; 4097]).unwrap();
    assert!(store.version().is_err(), "oversized record admitted");

    let root = tempfile::tempdir().unwrap();
    let store = PendingStore::open(root.path()).unwrap();
    store
        .prepare(store.version().unwrap(), [1; 32], [2; 32])
        .unwrap();
    let record = record_path(root.path(), 1);
    let mut same_record_different_digest = std::fs::read(&record).unwrap();
    same_record_different_digest.push(b' ');
    std::fs::write(record, same_record_different_digest).unwrap();
    assert!(store.version().is_err(), "record digest was not exact");
}

#[test]
fn windows_junction_root_and_child_are_rejected_without_touching_target() {
    let parent = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let root_link = parent.path().join("root-link");
    let status = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&root_link)
        .arg(target.path())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(PendingStore::open(&root_link).is_err());
    assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 0);

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let child = root.path().join("pairing-pending");
    let status = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&child)
        .arg(outside.path())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(PendingStore::open(root.path()).is_err());
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[test]
fn windows_added_world_ace_invalidates_the_complete_store() {
    let root = tempfile::tempdir().unwrap();
    let store = PendingStore::open(root.path()).unwrap();
    store
        .prepare(store.version().unwrap(), [1; 32], [2; 32])
        .unwrap();
    let record = record_path(root.path(), 1);
    let output = std::process::Command::new("icacls")
        .arg(&record)
        .args(["/grant", "*S-1-1-0:(R)"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "icacls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        store.version().is_err(),
        "additional world ACE was admitted"
    );
    assert!(PendingStore::open(root.path()).is_err());
}

#[test]
fn windows_existing_store_directory_with_world_ace_is_not_silently_repaired() {
    let root = tempfile::tempdir().unwrap();
    let store = PendingStore::open(root.path()).unwrap();
    drop(store);
    let pending = root.path().join("pairing-pending");
    let output = std::process::Command::new("icacls")
        .arg(&pending)
        .args(["/grant", "*S-1-1-0:(OI)(CI)(F)"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "icacls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        PendingStore::open(root.path()).is_err(),
        "insecure existing directory was silently repaired"
    );
}

#[test]
fn missing_or_corrupt_ledger_never_creates_a_new_epoch() {
    for fault in ["missing", "corrupt"] {
        let root = tempfile::tempdir().unwrap();
        let store = PendingStore::open(root.path()).unwrap();
        store
            .revoke_candidate(store.version().unwrap(), [2; 32])
            .unwrap();
        let ledger = root.path().join("pairing-tombstones/ledger.json");
        if fault == "missing" {
            std::fs::remove_file(&ledger).unwrap();
        } else {
            std::fs::write(&ledger, b"not-json").unwrap();
        }
        assert!(store.version().is_err());
        assert!(PendingStore::open(root.path()).is_err());
    }
}

#[test]
fn windows_storage_source_retains_the_reviewed_durability_and_security_primitives() {
    let source = include_str!("../src/private_fs_windows.rs");
    for required in [
        "FILE_FLAG_OPEN_REPARSE_POINT",
        "info.nNumberOfLinks != 1",
        "size.AceCount != 1",
        "LockFileEx",
        "file.sync_all()",
        "if unsafe { FlushFileBuffers",
        "SetFileInformationByHandle",
        "FileRenameInfo",
        "FILE_FLAG_WRITE_THROUGH",
        "PROTECTED_DACL_SECURITY_INFORMATION",
    ] {
        assert!(source.contains(required), "missing contract: {required}");
    }
    assert_eq!(
        source.matches("file.sync_all()").count(),
        2,
        "replacement requires distinct pre-rename and post-rename file flushes"
    );
    for operation in [
        "flush_before_rename(&file, value)?",
        "publish_renamed_file(&file, &self.path.join(value), target_exists, value)?",
        "flush_after_rename(&file)?",
        "self.flush_for_replace(value)?",
    ] {
        assert!(
            source.contains(operation),
            "missing replacement operation: {operation}"
        );
    }
}
