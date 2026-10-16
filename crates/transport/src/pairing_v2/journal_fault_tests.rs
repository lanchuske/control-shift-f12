//! Real subprocess termination / injected I/O failure, never enabled in a library build.
use super::*;
use crate::pairing_v2::codec::{Value, decode};
use std::process::Command;

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/pairing-v2/e2e-v01-real-candidate-hello.json"
    ))
    .unwrap()
}
fn bytes(v: &serde_json::Value, key: &str) -> Vec<u8> {
    let s = v[key].as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&s[n..n + 2], 16).unwrap())
        .collect()
}
fn journal(store: &PendingStore, role: Role, complete: bool) -> PublicJournal {
    let v = fixture();
    let attempt = bytes(&v, "attempt_id_hex").try_into().unwrap();
    let pending = store.pending(attempt).unwrap().unwrap_or_else(|| {
        store
            .prepare(
                store.version().unwrap(),
                attempt,
                bytes(
                    &v,
                    if role == Role::A {
                        "role_b_full_fingerprint_hex"
                    } else {
                        "role_a_full_fingerprint_hex"
                    },
                )
                .try_into()
                .unwrap(),
            )
            .unwrap()
    });
    let certificates = ["hello_a_hex", "hello_b_hex"].map(|key| {
        let values = decode(
            "hello",
            &bytes(&v, key),
            &[1, 2, 2, 2, 2, 2, 2, 3, 2, 3, 3, 2, 3, 1],
        )
        .unwrap();
        let Value::Bytes(cert) = &values[8] else {
            panic!()
        };
        cert.clone()
    });
    PublicJournal {
        schema: 1,
        pending,
        local: role,
        certificates,
        transcript: bytes(&v, "transcript_hex").try_into().unwrap(),
        approvals: ["a", "b"].map(|s| SignedEvidence {
            body: bytes(&v, &format!("approve_{s}_body_hex")),
            signature: bytes(&v, &format!("approve_{s}_signature_hex")),
        }),
        messages: v["finalization"]
            .as_array()
            .unwrap()
            .iter()
            .take(if complete {
                5
            } else if role == Role::A {
                3
            } else {
                4
            })
            .map(|m| SignedEvidence {
                body: bytes(m, "body"),
                signature: bytes(m, "signature"),
            })
            .collect(),
        clock: JournalClock {
            boot: [1; 16],
            monotonic_ms: 6,
            utc_seconds: 1_893_456_000,
        },
    }
}

#[test]
fn journal_fault_child() {
    let Ok(root) = std::env::var("PAIRING_JOURNAL_CHILD_ROOT") else {
        return;
    };
    let role = if std::env::var("PAIRING_JOURNAL_CHILD_ROLE").unwrap() == "A" {
        Role::A
    } else {
        Role::B
    };
    let complete = std::env::var("PAIRING_JOURNAL_CHILD_COMPLETE").unwrap() == "true";
    let store = PendingStore::open(root).unwrap();
    let journal = journal(&store, role, complete);
    let version = store.version().unwrap();
    let operation =
        std::env::var("PAIRING_JOURNAL_CHILD_OPERATION").unwrap_or_else(|_| "journal".into());
    let recovery = if operation == "recovery" {
        let fields = crate::pairing_v2::RecoveryFields {
            attempt_id: journal.pending.attempt_id,
            fc_hash: journal.validate().unwrap().unwrap(),
            role: Role::B,
            challenger_nonce: vec![1; 32],
            responder_nonce: vec![2; 32],
            tls_exporter: vec![3; 32],
            identity_generation: 91,
            revocation_generation: 73,
        };
        let body = fields.encode().unwrap();
        let signer = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[4; 32]).unwrap();
        let fp = hash(&journal.certificates[1]);
        let id = validate_identity(
            &journal.certificates[1],
            fp[..16].try_into().unwrap(),
            journal.clock.utc_seconds,
        )
        .unwrap();
        Some(crate::pairing_v2::VerifiedRecoveryUse {
            local_version: version,
            pending: journal.pending.clone(),
            signer: *id.public_key(),
            signature: signer.sign(&body).as_ref().to_vec(),
            body,
            fc_hash: fields.fc_hash,
            peer_role: Role::B,
        })
    } else {
        None
    };
    // The test-only filesystem hook is armed AFTER fixture/setup reads/writes.
    crate::private_fs::faults::arm();
    let result = match operation.as_str() {
        "cancel" => store.cancel(version, journal.pending.attempt_id),
        "revoke" => store.revoke_candidate(version, journal.pending.peer_fingerprint),
        "rotate" => store.rotate_identity(version),
        "recovery" => store.consume_verified_recovery(recovery.unwrap()),
        _ => store.persist_pairing_journal(version, &journal),
    };
    std::process::exit(if result.is_err() { 92 } else { 0 });
}

#[test]
fn completed_journal_must_extend_exact_durable_prefix_including_original_clock() {
    for role in [Role::A, Role::B] {
        let temp = tempfile::tempdir().unwrap();
        let store = PendingStore::open(temp.path()).unwrap();
        let initial = journal(&store, role, false);
        store
            .persist_pairing_journal(store.version().unwrap(), &initial)
            .unwrap();
        let version = store.version().unwrap();
        let mut changed = journal(&store, role, true);
        changed.clock.utc_seconds += 1;
        assert!(
            changed.validate().is_ok(),
            "signatures alone do not bind local retention clock"
        );
        assert!(store.persist_pairing_journal(version, &changed).is_err());
        assert_eq!(store.version().unwrap(), version);
    }
}

#[test]
fn recovery_consumption_and_terminal_tombstones_are_atomic_at_every_manifest_boundary() {
    let stages = [
        "before_write",
        "after_write",
        "before_file_sync",
        "after_file_sync",
        "before_rename",
        "after_rename",
        "before_dir_sync",
        "after_dir_sync",
    ];
    for operation in ["cancel", "revoke", "rotate", "recovery"] {
        for stage in stages {
            for mode in ["crash", "error"] {
                let temp = tempfile::tempdir().unwrap();
                let store = PendingStore::open(temp.path()).unwrap();
                let initial = journal(&store, Role::A, false);
                store
                    .persist_pairing_journal(store.version().unwrap(), &initial)
                    .unwrap();
                let full = journal(&store, Role::A, true);
                store
                    .persist_pairing_journal(store.version().unwrap(), &full)
                    .unwrap();
                let version = store.version().unwrap();
                drop(store);
                let output = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "pairing_v2::journal::fault_tests::journal_fault_child",
                        "--nocapture",
                    ])
                    .env("PAIRING_JOURNAL_CHILD_ROOT", temp.path())
                    .env("PAIRING_JOURNAL_CHILD_ROLE", "A")
                    .env("PAIRING_JOURNAL_CHILD_COMPLETE", "true")
                    .env("PAIRING_JOURNAL_CHILD_OPERATION", operation)
                    .env("PAIRING_TEST_FS_FAULT", format!("ledger:{stage}:{mode}"))
                    .output()
                    .unwrap();
                assert_eq!(
                    output.status.code(),
                    Some(if mode == "crash" { 91 } else { 92 }),
                    "{operation}/{stage}/{mode}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let visible =
                    ["after_rename", "before_dir_sync", "after_dir_sync"].contains(&stage);
                let store = PendingStore::open(temp.path()).unwrap();
                assert_eq!(
                    store.version().unwrap().revision,
                    version.revision + u64::from(visible)
                );
                assert!(store.promote(full.pending.attempt_id).is_err());
                let manifest: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(temp.path().join("pairing-tombstones/ledger.json")).unwrap(),
                )
                .unwrap();
                if operation == "recovery" {
                    assert_eq!(
                        manifest["recoveries"].as_array().map_or(0, Vec::len),
                        usize::from(visible)
                    );
                    assert!(store.pending(full.pending.attempt_id).unwrap().is_some());
                } else {
                    assert_eq!(
                        store.pending(full.pending.attempt_id).unwrap().is_none(),
                        visible
                    );
                    if visible {
                        assert!(
                            store
                                .prepare(
                                    store.version().unwrap(),
                                    full.pending.attempt_id,
                                    full.pending.peer_fingerprint
                                )
                                .is_err()
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn every_journal_and_manifest_write_boundary_is_fail_closed_across_process_death_and_io_error() {
    let stages = [
        "before_write",
        "after_write",
        "before_file_sync",
        "after_file_sync",
        "before_rename",
        "after_rename",
        "before_dir_sync",
        "after_dir_sync",
    ];
    for role in [Role::A, Role::B] {
        for complete in [false, true] {
            for target in ["journal", "ledger"] {
                for stage in stages {
                    for mode in ["crash", "error"] {
                        let temp = tempfile::tempdir().unwrap();
                        let store = PendingStore::open(temp.path()).unwrap();
                        let initial = journal(&store, role, false);
                        if complete {
                            store
                                .persist_pairing_journal(store.version().unwrap(), &initial)
                                .unwrap();
                        }
                        let version = store.version().unwrap();
                        drop(store);
                        let output = Command::new(std::env::current_exe().unwrap())
                            .args([
                                "--exact",
                                "pairing_v2::journal::fault_tests::journal_fault_child",
                                "--nocapture",
                            ])
                            .env("PAIRING_JOURNAL_CHILD_ROOT", temp.path())
                            .env(
                                "PAIRING_JOURNAL_CHILD_ROLE",
                                if role == Role::A { "A" } else { "B" },
                            )
                            .env("PAIRING_JOURNAL_CHILD_COMPLETE", complete.to_string())
                            .env("PAIRING_TEST_FS_FAULT", format!("{target}:{stage}:{mode}"))
                            .output()
                            .unwrap();
                        assert_eq!(
                            output.status.code(),
                            Some(if mode == "crash" { 91 } else { 92 }),
                            "{role:?}/{complete}/{target}/{stage}/{mode}: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                        let store = PendingStore::open(temp.path()).unwrap();
                        let became_visible = target == "ledger"
                            && ["after_rename", "before_dir_sync", "after_dir_sync"]
                                .contains(&stage);
                        assert_eq!(
                            store.version().unwrap().revision,
                            version.revision + u64::from(became_visible)
                        );
                        assert!(store.promote(initial.pending.attempt_id).is_err());
                        match store
                            .reconcile_pairing(initial.pending.attempt_id, Some(initial.clock))
                            .unwrap()
                        {
                            ReconcileOutcome::Discarded => assert!(!complete && !became_visible),
                            ReconcileOutcome::RecoveryOnly(j) => {
                                assert!(complete || became_visible);
                                assert_eq!(
                                    j.durable_fc_hash().unwrap().is_some(),
                                    complete && became_visible
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
