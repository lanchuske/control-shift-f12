use crate::pairing_v2::{
    SUITE,
    codec::{Value, encode},
    operational_binding::BindingInput,
    operational_wire::{ALPN, CandidateRequest, FrameKind, TransportFrame, read_record},
    provisional_tls::{ProvisionalChannel, ProvisionalEndpoint, configs, process_owner},
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

fn identity(usage: bool) -> (Vec<u8>, rustls::pki_types::PrivateKeyDer<'static>) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut p = rcgen::CertificateParams::default();
    p.is_ca = rcgen::IsCa::ExplicitNoCa;
    p.subject_alt_names = vec![rcgen::SanType::URI(
        "urn:control-shift-f12:identity".try_into().unwrap(),
    )];
    if usage {
        p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    }
    (
        p.self_signed(&key).unwrap().der().to_vec(),
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
}

fn handshake_config(local: u8, remote: u8) -> super::HandshakeConfig {
    super::HandshakeConfig {
        device_name: format!("Peer {local}"),
        os: "macos".into(),
        local_rendezvous: [local; 16],
        selected_rendezvous: [remote; 16],
    }
}

#[tokio::test]
async fn one_local_sas_approval_never_commits_a_relationship() {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let before_a = sa.version().unwrap();
    let before_b = sb.version().unwrap();
    let (prompt_a_tx, prompt_a_rx) = tokio::sync::oneshot::channel();
    let (prompt_b_tx, prompt_b_rx) = tokio::sync::oneshot::channel();
    let (approve_a_tx, approve_a_rx) = tokio::sync::oneshot::channel();
    let (approve_b_tx, approve_b_rx) = tokio::sync::oneshot::channel();
    let attempt_a = a.handshake(handshake_config(1, 2), &sa, |prompt| async move {
        prompt_a_tx.send(prompt.clone()).unwrap();
        prompt.decision(approve_a_rx.await.unwrap())
    });
    let attempt_b = b.handshake(handshake_config(2, 1), &sb, |prompt| async move {
        prompt_b_tx.send(prompt.clone()).unwrap();
        prompt.decision(approve_b_rx.await.unwrap())
    });
    tokio::pin!(attempt_a, attempt_b);
    let decisions = async {
        let (prompt_a, prompt_b) = tokio::join!(prompt_a_rx, prompt_b_rx);
        let prompt_a = prompt_a.unwrap();
        let prompt_b = prompt_b.unwrap();
        assert_eq!(prompt_a.words, prompt_b.words);
        assert_eq!(prompt_a.attempt, prompt_b.attempt);
        assert_eq!(prompt_a.transcript, prompt_b.transcript);
        approve_a_tx.send(true).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        // The remote callback is deliberately still waiting on a separate
        // local gesture. No protocol finalizer may prepare durable evidence.
        assert_eq!(sa.version().unwrap(), before_a);
        assert_eq!(sb.version().unwrap(), before_b);
        assert!(sa.pending(prompt_a.attempt).unwrap().is_none());
        assert!(sb.pending(prompt_b.attempt).unwrap().is_none());
        let store =
            crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path())
                .unwrap();
        assert_eq!(
            store.reconcile(prompt_a.attempt).unwrap(),
            crate::pairing_v2::admission_authority::ReconcileAdmission::Absent
        );
        // Keep the independent remote decision alive through every assertion.
        drop(approve_b_tx);
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            biased;
            _ = &mut attempt_a => panic!("one-sided approval completed local handshake"),
            _ = &mut attempt_b => panic!("remote handshake completed without local gesture"),
            _ = decisions => {}
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn current_foundation_revokes_committed_metadata_on_listener_shutdown() {
    let (ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(
            handshake_config(1, 2),
            &sa,
            |p| async move { p.decision(true) }
        ),
        b.handshake(
            handshake_config(2, 1),
            &sb,
            |p| async move { p.decision(true) }
        )
    );
    let _b = b.unwrap();
    let store =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    let receipt = store
        .commit_sealed_foundation(store.version().unwrap(), a.unwrap())
        .await
        .unwrap();
    assert_eq!(
        store.reconcile(receipt.attempt()).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
    );
    drop(ea);
    // This is the current reviewed foundation boundary, not product success.
    // Task 3 requires an independently reviewed, crash-safe handoff of durable
    // ownership before normal listener cleanup can preserve a relationship.
    assert_eq!(
        store.reconcile(receipt.attempt()).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Revoked
    );
}
#[tokio::test]
async fn bilateral_rejects_substituted_tls_connection_before_candidate_io() {
    let (_ea, _eb, mut a, _b, _) = pair().await;
    let (_ec, _ed, foreign, _peer, _) = pair().await;
    let original = a.connection.clone();
    let mut original_exporter = [0; 32];
    let mut foreign_exporter = [0; 32];
    original
        .export_keying_material(
            &mut original_exporter,
            b"EXPORTER-ControlShiftF12-Handshake-v2",
            b"test-context",
        )
        .unwrap();
    foreign
        .connection
        .export_keying_material(
            &mut foreign_exporter,
            b"EXPORTER-ControlShiftF12-Handshake-v2",
            b"test-context",
        )
        .unwrap();
    assert_ne!(original_exporter, foreign_exporter);
    // Test-only access models a broken owner retaining old metadata with a second TLS.
    a.connection = foreign.connection.clone();
    let temp = tempfile::tempdir().unwrap();
    let store = crate::pairing_pending::PendingStore::open(temp.path()).unwrap();
    let before = store.version().unwrap();
    let result = tokio::time::timeout(
        Duration::from_millis(200),
        a.handshake(handshake_config(1, 2), &store, |_| async {
            panic!("substituted TLS reached SAS")
        }),
    )
    .await;
    assert!(
        matches!(result, Ok(Err(super::HandshakeError::Rejected))),
        "substituted TLS must reject before candidate I/O"
    );
    assert_eq!(store.version().unwrap(), before);
}
#[tokio::test]
async fn bilateral_completed_capability_is_invalidated_by_late_extra_stream() {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(
            handshake_config(1, 2),
            &sa,
            |p| async move { p.decision(true) }
        ),
        b.handshake(
            handshake_config(2, 1),
            &sb,
            |p| async move { p.decision(true) }
        )
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert!(a.is_protocol_valid());
    b.test_late_extra().await;
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while a.is_protocol_valid() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(!a.is_protocol_valid());
}
#[tokio::test]
async fn bilateral_completed_capability_rejects_late_candidate_data() {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(
            handshake_config(1, 2),
            &sa,
            |p| async move { p.decision(true) }
        ),
        b.handshake(
            handshake_config(2, 1),
            &sb,
            |p| async move { p.decision(true) }
        )
    );
    let a = a.unwrap();
    let mut b = b.unwrap();
    assert!(a.durable_fc_hash().is_some());
    b.test_late_candidate().await;
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while a.is_protocol_valid() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(!a.is_protocol_valid());
    assert!(a.durable_fc_hash().is_none());
}

#[tokio::test]
async fn bilateral_pending_authority_must_be_consumed_and_revalidated_when_sealed() {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(
            handshake_config(1, 2),
            &sa,
            |p| async move { p.decision(true) }
        ),
        b.handshake(
            handshake_config(2, 1),
            &sb,
            |p| async move { p.decision(true) }
        )
    );
    let a = a.unwrap();
    let b = b.unwrap();

    b.test_late_extra().await;
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while a.is_protocol_valid() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    assert!(a.seal_for_promotion().await.is_err());
}

#[tokio::test]
async fn bilateral_pending_authority_seals_into_live_move_only_evidence() {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(
            handshake_config(1, 2),
            &sa,
            |p| async move { p.decision(true) }
        ),
        b.handshake(
            handshake_config(2, 1),
            &sb,
            |p| async move { p.decision(true) }
        )
    );
    let sealed = a.unwrap().seal_for_promotion().await.unwrap();
    sealed.revalidate().unwrap();
    drop(b.unwrap());
}

#[tokio::test]
async fn bilateral_sealed_evidence_rejects_late_invalidation_before_commit() {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(
            handshake_config(1, 2),
            &sa,
            |p| async move { p.decision(true) }
        ),
        b.handshake(
            handshake_config(2, 1),
            &sb,
            |p| async move { p.decision(true) }
        )
    );
    let sealed = a.unwrap().seal_for_promotion().await.unwrap();
    let b = b.unwrap();
    b.test_late_extra().await;
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while sealed.revalidate().is_ok() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(sealed.revalidate().is_err());
}

#[tokio::test]
async fn bilateral_sealed_evidence_commits_only_durable_metadata_not_runtime_authority() {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(
            handshake_config(1, 2),
            &sa,
            |p| async move { p.decision(true) }
        ),
        b.handshake(
            handshake_config(2, 1),
            &sb,
            |p| async move { p.decision(true) }
        )
    );
    let store =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    let receipt = store
        .commit_sealed_foundation(store.version().unwrap(), a.unwrap())
        .await
        .unwrap();
    assert_eq!(
        store.reconcile(receipt.attempt()).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
    );
    let pending_files: Vec<_> = std::fs::read_dir(ta.path().join("pairing-pending"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        pending_files
            .iter()
            .all(|name| !name.starts_with("journal-")),
        "admission left an orphan journal: {pending_files:?}"
    );
    drop(b.unwrap());
}

#[cfg(unix)]
#[tokio::test]
async fn real_late_extra_between_validation_and_rename_cannot_publish_authority() {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(
            handshake_config(1, 2),
            &sa,
            |p| async move { p.decision(true) }
        ),
        b.handshake(
            handshake_config(2, 1),
            &sb,
            |p| async move { p.decision(true) }
        )
    );
    let a = a.unwrap();
    let b = b.unwrap();
    let attempt = a.test_attempt();
    let root = ta.path().to_owned();
    let pause = crate::private_fs::faults::pause_before_rename();
    let commit_pause = pause.clone();
    let commit = std::thread::spawn(move || {
        commit_pause.arm_on_current_thread();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let store =
                    crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(&root)
                        .unwrap();
                let expected = store.version().unwrap();
                store.commit_sealed_foundation(expected, a).await
            })
    });

    let waiter = pause.clone();
    tokio::task::spawn_blocking(move || waiter.wait_until_reached())
        .await
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while b.is_protocol_valid() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let accepted_after_freeze = b.test_try_late_extra().await;
    pause.release();
    let result = tokio::task::spawn_blocking(move || commit.join().unwrap())
        .await
        .unwrap();
    assert!(
        !accepted_after_freeze,
        "freeze won but pairing ingress still accepted a real stream"
    );
    assert!(result.is_ok(), "metadata publication lost after freeze won");
    let reopened =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    assert_eq!(
        reopened.reconcile(attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
    );
}

#[tokio::test]
async fn real_late_extra_that_wins_before_freeze_blocks_publication() {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(
            handshake_config(1, 2),
            &sa,
            |p| async move { p.decision(true) }
        ),
        b.handshake(
            handshake_config(2, 1),
            &sb,
            |p| async move { p.decision(true) }
        )
    );
    let a = a.unwrap();
    let b = b.unwrap();
    let attempt = a.test_attempt();
    assert!(b.test_try_late_extra().await);
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while a.is_protocol_valid() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let store =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    assert_eq!(
        store
            .commit_sealed_foundation(store.version().unwrap(), a)
            .await,
        Err(crate::pairing_pending::StoreError::Invalid)
    );
    assert_ne!(
        store.reconcile(attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
    );
}

#[tokio::test]
async fn concurrent_real_late_extra_and_freeze_has_one_safe_winner() {
    for iteration in 1..=4u8 {
        let (_ea, _eb, a, b, _) = pair().await;
        let ta = tempfile::tempdir().unwrap();
        let tb = tempfile::tempdir().unwrap();
        let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
        let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
        let (a, b) = tokio::join!(
            a.handshake(
                handshake_config(iteration, iteration + 10),
                &sa,
                |p| async move { p.decision(true) }
            ),
            b.handshake(
                handshake_config(iteration + 10, iteration),
                &sb,
                |p| async move { p.decision(true) }
            )
        );
        let a = a.unwrap();
        let b = b.unwrap();
        let attempt = a.test_attempt();
        let root = ta.path().to_owned();
        let commit = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let store =
                        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(
                            &root,
                        )
                        .unwrap();
                    store
                        .commit_sealed_foundation(store.version().unwrap(), a)
                        .await
                })
        });
        let _remote_write_observation = b.test_try_late_extra().await;
        let result = tokio::task::spawn_blocking(move || commit.join().unwrap())
            .await
            .unwrap();
        let reopened =
            crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path())
                .unwrap();
        match result {
            Err(crate::pairing_pending::StoreError::Invalid) => assert_ne!(
                reopened.reconcile(attempt).unwrap(),
                crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
            ),
            Ok(_) => assert_eq!(
                reopened.reconcile(attempt).unwrap(),
                crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
            ),
            other => panic!("unexpected race result: {other:?}"),
        }
    }
}

#[tokio::test]
async fn endpoint_drop_that_revokes_scope_before_freeze_blocks_publication() {
    let (mut ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(
            handshake_config(1, 2),
            &sa,
            |p| async move { p.decision(true) }
        ),
        b.handshake(
            handshake_config(2, 1),
            &sb,
            |p| async move { p.decision(true) }
        )
    );
    let a = a.unwrap();
    let _b = b.unwrap();
    let attempt = a.test_attempt();
    let drop_pause = ea.test_pause_drop_after_scope_revocation();
    let drop_thread = std::thread::spawn(move || drop(ea));
    let waiter = drop_pause.0.clone();
    tokio::task::spawn_blocking(move || waiter.reached.wait())
        .await
        .unwrap();

    let store =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    let result = store
        .commit_sealed_foundation(store.version().unwrap(), a)
        .await;
    drop_pause.release();
    drop_thread.join().unwrap();
    assert_eq!(result, Err(crate::pairing_pending::StoreError::Invalid));
    assert_ne!(
        store.reconcile(attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
    );
}

#[cfg(unix)]
#[tokio::test]
async fn freeze_before_endpoint_drop_is_durably_revoked_before_future_authority() {
    let (mut ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(
            handshake_config(1, 2),
            &sa,
            |p| async move { p.decision(true) }
        ),
        b.handshake(
            handshake_config(2, 1),
            &sb,
            |p| async move { p.decision(true) }
        )
    );
    let a = a.unwrap();
    let _b = b.unwrap();
    let attempt = a.test_attempt();
    let root = ta.path().to_owned();
    let save_pause = crate::private_fs::faults::pause_before_rename();
    let commit_pause = save_pause.clone();
    let commit = std::thread::spawn(move || {
        commit_pause.arm_on_current_thread();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let store =
                    crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(&root)
                        .unwrap();
                store
                    .commit_sealed_foundation(store.version().unwrap(), a)
                    .await
            })
    });
    let waiter = save_pause.clone();
    tokio::task::spawn_blocking(move || waiter.wait_until_reached())
        .await
        .unwrap();

    let drop_pause = ea.test_pause_drop_after_scope_revocation();
    let drop_thread = std::thread::spawn(move || drop(ea));
    let drop_waiter = drop_pause.0.clone();
    tokio::task::spawn_blocking(move || drop_waiter.reached.wait())
        .await
        .unwrap();
    save_pause.release();
    let result = tokio::task::spawn_blocking(move || commit.join().unwrap())
        .await
        .unwrap();
    let during_drop =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path())
            .unwrap()
            .reconcile(attempt);
    assert_eq!(
        during_drop,
        Err(crate::pairing_pending::StoreError::Unavailable),
        "a live endpoint owns durable revocation; concurrent reconciliation must fail closed"
    );
    drop_pause.release();
    drop_thread.join().unwrap();
    assert!(result.is_ok());
    let reopened =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    assert_eq!(
        reopened.reconcile(attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Revoked
    );
}

#[tokio::test]
async fn endpoint_drop_revocation_faults_remain_observable_and_retryable() {
    for (setting, first_reconcile) in [
        (
            "ledger:before_revoke_lock:error",
            Err(crate::pairing_pending::StoreError::Unavailable),
        ),
        (
            "ledger:before_revoke_load:error",
            Err(crate::pairing_pending::StoreError::Unavailable),
        ),
        (
            "ledger:before_write:error",
            Err(crate::pairing_pending::StoreError::Unavailable),
        ),
        (
            "pending:before_remove:error",
            Err(crate::pairing_pending::StoreError::Unavailable),
        ),
        (
            "pending:after_remove:error",
            Ok(crate::pairing_v2::admission_authority::ReconcileAdmission::Revoked),
        ),
    ] {
        let (ea, _eb, a, b, _) = pair().await;
        let ta = tempfile::tempdir().unwrap();
        let tb = tempfile::tempdir().unwrap();
        let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
        let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
        let (a, b) = tokio::join!(
            a.handshake(
                handshake_config(1, 2),
                &sa,
                |p| async move { p.decision(true) }
            ),
            b.handshake(
                handshake_config(2, 1),
                &sb,
                |p| async move { p.decision(true) }
            )
        );
        let a = a.unwrap();
        let _b = b.unwrap();
        let attempt = a.test_attempt();
        let store =
            crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path())
                .unwrap();
        store
            .commit_sealed_foundation(store.version().unwrap(), a)
            .await
            .unwrap();

        unsafe { std::env::set_var("PAIRING_TEST_FS_FAULT", setting) };
        crate::private_fs::faults::arm();
        drop(ea);
        assert_eq!(store.reconcile(attempt), first_reconcile, "{setting}");
        unsafe { std::env::remove_var("PAIRING_TEST_FS_FAULT") };
        assert_eq!(
            store.reconcile(attempt).unwrap(),
            crate::pairing_v2::admission_authority::ReconcileAdmission::Revoked,
            "retry after {setting}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn durable_guard_fails_closed_in_a_fresh_process() {
    use std::process::Command;

    let (ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(
            handshake_config(1, 2),
            &sa,
            |p| async move { p.decision(true) }
        ),
        b.handshake(
            handshake_config(2, 1),
            &sb,
            |p| async move { p.decision(true) }
        )
    );
    let a = a.unwrap();
    let _b = b.unwrap();
    let attempt = a.test_attempt();
    let store =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    store
        .commit_sealed_foundation(store.version().unwrap(), a)
        .await
        .unwrap();

    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "pairing_v2::provisional_tls::tests::admission_guard_restart_worker",
            "--ignored",
        ])
        .env("CSF12_ADMISSION_GUARD_ROOT", ta.path())
        .env(
            "CSF12_ADMISSION_GUARD_ATTEMPT",
            attempt
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        store.reconcile(attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Revoked
    );
    drop(ea);
}

#[cfg(unix)]
#[test]
#[ignore]
fn admission_guard_restart_worker() {
    let root = std::env::var_os("CSF12_ADMISSION_GUARD_ROOT").unwrap();
    let hex = std::env::var("CSF12_ADMISSION_GUARD_ATTEMPT").unwrap();
    assert_eq!(hex.len(), 64);
    let mut attempt = [0u8; 32];
    for (index, byte) in attempt.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    let store =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(root).unwrap();
    assert_eq!(
        store.reconcile(attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Revoked
    );
}
#[tokio::test]
async fn bilateral_rejection_issues_real_reset_and_stop_independently_of_connection_close() {
    let (_ea, _eb, a, b, _) = pair().await;
    let (mut tx, mut rx) = a.connection.open_bi().await.unwrap();
    tx.write_all(&[1]).await.unwrap();
    let (mut bs, br) = b.connection.accept_bi().await.unwrap();
    bs.write_all(&[2]).await.unwrap();
    let mut one = [0];
    rx.read_exact(&mut one).await.unwrap();
    super::handshake_io::reject_test_stream((bs, br));
    assert!(
        matches!(tokio::time::timeout(Duration::from_secs(2),rx.read(&mut one)).await.unwrap(),Err(quinn::ReadError::Reset(code)) if code==super::super::handshake_wire::APPLICATION_ERROR.into())
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), tx.stopped())
            .await
            .unwrap()
            .unwrap(),
        Some(super::super::handshake_wire::APPLICATION_ERROR.into())
    );
    assert!(a.connection.close_reason().is_none());
    assert!(b.connection.close_reason().is_none());
}

#[tokio::test]
async fn bilateral_control_fragmentation_and_adversarial_phase_matrix() {
    for mutation in 0..7 {
        for sequence in [0, 2, 4, 6, 8, 10, 12, 14, 15, 16] {
            let (_ea, _eb, mut a, mut b, _) = pair().await;
            let a_role = if super::hash(a.local_identity.cert[0].as_ref()) < super::hash(&a.leaf) {
                1
            } else {
                2
            };
            if super::super::handshake_wire::SCHEDULE[sequence].1 == a_role {
                a.fault = Some(super::handshake_io::WireFault { sequence, mutation });
            } else {
                b.fault = Some(super::handshake_io::WireFault { sequence, mutation });
            }
            let ta = tempfile::tempdir().unwrap();
            let tb = tempfile::tempdir().unwrap();
            let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
            let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
            let test = async {
                tokio::join!(
                    a.handshake(
                        handshake_config(1, 2),
                        &sa,
                        |p| async move { p.decision(true) }
                    ),
                    b.handshake(
                        handshake_config(2, 1),
                        &sb,
                        |p| async move { p.decision(true) }
                    )
                )
            };
            let (a, b) = tokio::time::timeout(Duration::from_secs(5), test)
                .await
                .expect("fault must not stall");
            if mutation == 0 {
                assert!(a.is_ok() && b.is_ok(), "fragment seq {sequence}");
            } else {
                assert!(
                    a.is_err() && b.is_err(),
                    "mutation {mutation} seq {sequence}"
                );
            }
        }
    }
}

#[tokio::test]
async fn bilateral_wrong_ui_binding_and_user_reject_never_create_pending_evidence() {
    for mode in 0..4 {
        let (_ea, _eb, a, b, _) = pair().await;
        let ta = tempfile::tempdir().unwrap();
        let tb = tempfile::tempdir().unwrap();
        let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
        let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
        let (a, b) = tokio::join!(
            a.handshake(handshake_config(1, 2), &sa, |p| async move {
                let mut d = p.decision(mode != 0);
                match mode {
                    1 => d.attempt[0] ^= 1,
                    2 => d.transcript[0] ^= 1,
                    3 => d.ui_generation += 1,
                    _ => {}
                }
                d
            }),
            b.handshake(
                handshake_config(2, 1),
                &sb,
                |p| async move { p.decision(true) }
            )
        );
        assert!(a.is_err() && b.is_err());
        assert_eq!(sa.version().unwrap().revision, 0);
        assert_eq!(sb.version().unwrap().revision, 0);
    }
}

#[tokio::test]
async fn bilateral_candidate_raw_trailing_duplicate_downgrade_oversize_early_close_fail_closed() {
    for mode in 0..6 {
        let (_ea, _eb, x, y, _) = pair().await;
        let (attacker, honest) =
            if super::hash(x.local_identity.cert[0].as_ref()) < super::hash(&x.leaf) {
                (x, y)
            } else {
                (y, x)
            };
        let tmp = tempfile::tempdir().unwrap();
        let store = crate::pairing_pending::PendingStore::open(tmp.path()).unwrap();
        let exercise = async {
            let (mut send, mut recv) = attacker.connection.open_bi().await.unwrap();
            let mut raw = TransportFrame {
                kind: FrameKind::CandidateRequest,
                payload: CandidateRequest::new([1; 16], [2; 16], [3; 16])
                    .encode()
                    .unwrap(),
            }
            .encode()
            .unwrap();
            match mode {
                0 => raw.push(1),
                1 => raw.extend(raw.clone()),
                2 => raw[9] = 1,
                3 => raw[11..15].copy_from_slice(&1025u32.to_be_bytes()),
                4 => raw.truncate(8),
                _ => {
                    raw[10] = 2;
                }
            }
            let _ = send.write_all(&raw).await;
            if mode == 4 {
                send.finish().unwrap();
            }
            let error = tokio::time::timeout(Duration::from_secs(5), attacker.connection.closed())
                .await
                .unwrap();
            assert!(
                matches!(error,quinn::ConnectionError::ApplicationClosed(ref closed) if closed.error_code==super::super::handshake_wire::APPLICATION_ERROR.into()),
                "mode {mode}: {error:?}"
            );
            let _ = recv.stop(0u32.into());
        };
        let (result, ()) = tokio::join!(
            honest.handshake(handshake_config(2, 1), &store, |_| async {
                panic!("invalid candidate reached SAS")
            }),
            exercise
        );
        assert!(
            matches!(result, Err(super::HandshakeError::Rejected)),
            "mode {mode}"
        );
        assert_eq!(store.version().unwrap().revision, 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bilateral_two_process_real_tls_sas_and_durable_fc_pending_only() {
    let (der, key) = identity(true);
    let endpoint = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), der, key).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "pairing_v2::provisional_tls::tests::bilateral_process_worker",
            "--nocapture",
        ])
        .env(
            "CSF12_BILATERAL_TEST_PEER",
            endpoint.local_addr().unwrap().to_string(),
        )
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = ProcessGuard(Some(child));
    let temp = tempfile::tempdir().unwrap();
    let store = crate::pairing_pending::PendingStore::open(temp.path()).unwrap();
    let channel = endpoint.accept().await.unwrap();
    let done = channel
        .handshake(handshake_config(2, 1), &store, |p| async move {
            p.decision(true)
        })
        .await
        .unwrap();
    std::io::Write::write_all(child.0.as_mut().unwrap().stdin.as_mut().unwrap(), b"done\n")
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
        assert!(std::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let output = child.0.take().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected = done
        .durable_fc_hash
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(&format!("BILATERAL_PENDING:{expected}"))
    );
    assert_eq!(store.version().unwrap().revision, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bilateral_process_death_before_and_after_real_finalization_emit_keeps_quarantine() {
    for point in ["before", "after"] {
        let (der, key) = identity(true);
        let endpoint = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), der, key).unwrap();
        let child_root = tempfile::tempdir().unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "pairing_v2::provisional_tls::tests::bilateral_process_worker",
                "--nocapture",
            ])
            .env(
                "CSF12_BILATERAL_TEST_PEER",
                endpoint.local_addr().unwrap().to_string(),
            )
            .env("CSF12_BILATERAL_WORKER_STORE", child_root.path())
            .env("CSF12_BILATERAL_EMIT_CRASH", point)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut child = ProcessGuard(Some(child));
        let temp = tempfile::tempdir().unwrap();
        let store = crate::pairing_pending::PendingStore::open(temp.path()).unwrap();
        let channel = endpoint.accept().await.unwrap();
        let result = channel
            .handshake(handshake_config(2, 1), &store, |p| async move {
                p.decision(true)
            })
            .await;
        assert!(result.is_err(), "point {point}");
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(91),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reopened = crate::pairing_pending::PendingStore::open(child_root.path()).unwrap();
        assert_eq!(
            reopened.version().unwrap().revision,
            2,
            "prepare and local decision durable before either crash"
        );
        assert!(reopened.promote([1; 32]).is_err());
    }
}
#[test]
#[ignore = "subprocess helper"]
fn bilateral_process_worker() {
    let peer = std::env::var("CSF12_BILATERAL_TEST_PEER")
        .unwrap()
        .parse()
        .unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (der, key) = identity(true);
            let endpoint =
                ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), der, key).unwrap();
            let tmp = tempfile::tempdir().unwrap();
            let worker_root = std::env::var_os("CSF12_BILATERAL_WORKER_STORE")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| tmp.path().to_owned());
            let store = crate::pairing_pending::PendingStore::open(worker_root).unwrap();
            let channel = endpoint.connect(peer).await.unwrap();
            let done = channel
                .handshake(handshake_config(1, 2), &store, |p| async move {
                    p.decision(true)
                })
                .await
                .unwrap();
            assert_eq!(store.version().unwrap().revision, 3);
            let hash = done
                .durable_fc_hash
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            println!("BILATERAL_PENDING:{hash}");
            // Out-of-band harness lifetime acknowledgement, not pairing wire.
            tokio::task::spawn_blocking(|| {
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).unwrap();
                assert_eq!(line, "done\n");
            })
            .await
            .unwrap();
        });
}
#[tokio::test]
async fn bilateral_real_quic_one_connection_two_requester_streams_and_durable_fc() {
    let (_a, _b, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let prompts = std::sync::Mutex::new(Vec::new());
    let confirm = |p: super::VerificationPrompt| {
        prompts.lock().unwrap().push(p.clone());
        async move { p.decision(true) }
    };
    let (a, b) = tokio::join!(
        a.handshake(handshake_config(1, 2), &sa, confirm),
        b.handshake(handshake_config(2, 1), &sb, confirm)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_ne!(a.role, b.role);
    assert_eq!(a.durable_fc_hash, b.durable_fc_hash);
    assert_ne!(a.test_local_binding(), b.test_local_binding());
    let prompts = prompts.into_inner().unwrap();
    assert_eq!(prompts.len(), 2);
    assert_eq!(prompts[0].attempt, prompts[1].attempt);
    assert_eq!(prompts[0].transcript, prompts[1].transcript);
    assert_eq!(prompts[0].words, prompts[1].words);
    assert_eq!(sa.version().unwrap().revision, 3);
    assert_eq!(sb.version().unwrap().revision, 3);
}
fn hello(der: &[u8]) -> Vec<u8> {
    let mut suites = vec![0, 1, 0, SUITE.len() as u8];
    suites.extend(SUITE.as_bytes());
    encode(
        "candidate-hello",
        &[
            Value::Bytes(vec![2; 16]),
            Value::Bytes(vec![3; 16]),
            Value::Bytes(vec![4; 16]),
            Value::Text("Loopback peer".into()),
            Value::Text("macos".into()),
            Value::Bytes(suites),
            Value::Bytes(Sha256::digest(der).to_vec()),
            Value::Number(30_000),
        ],
    )
    .unwrap()
}
async fn pair() -> (
    ProvisionalEndpoint,
    ProvisionalEndpoint,
    ProvisionalChannel,
    ProvisionalChannel,
    Vec<u8>,
) {
    let (a, ak) = identity(true);
    let (b, bk) = identity(true);
    let server = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b.clone(), bk).unwrap();
    let client = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a.clone(), ak).unwrap();
    let (outgoing, incoming) = tokio::join!(
        client.connect(server.local_addr().unwrap()),
        server.accept()
    );
    let incoming = incoming.unwrap();
    assert_eq!(incoming.leaf, a);
    (client, server, outgoing.unwrap(), incoming, b)
}
#[tokio::test]
async fn actual_quic_leaf_and_real_exporter_bind_once_without_peer_admission() {
    let (_a, _b, mut channel, peer, der) = pair().await;
    let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    let hello = hello(&der);
    let context = BindingInput::new(
        &request,
        &hello,
        &der,
        channel.connection_id(),
        channel.generation,
        ALPN,
    )
    .unwrap();
    let mut exporter = Zeroizing::new([0u8; 32]);
    channel
        .connection
        .export_keying_material(
            exporter.as_mut(),
            b"EXPORTER-ControlShiftF12-Pairing-v2",
            context.exporter_context(),
        )
        .unwrap();
    let mut other = Zeroizing::new([0u8; 32]);
    peer.connection
        .export_keying_material(
            other.as_mut(),
            b"EXPORTER-ControlShiftF12-Pairing-v2",
            context.exporter_context(),
        )
        .unwrap();
    assert_eq!(
        *exporter, *other,
        "same explicit TLS exporter context on the selected connection"
    );
    let expected = context.finish(exporter).unwrap();
    let actual = channel.bind(&request, &hello).unwrap();
    assert_eq!(actual.digest(), expected.digest());
    assert_eq!(actual.replay_token(), expected.replay_token());
    assert!(process_owner().replay.consume(&actual).is_err());
    assert!(channel.bind(&request, &hello).is_err());
}
#[tokio::test]
async fn actual_leaf_claim_substitution_and_closed_connection_fail_before_binding() {
    let (_a, _b, mut channel, _peer, der) = pair().await;
    let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    let (other, _) = identity(true);
    assert!(channel.bind(&request, &hello(&other)).is_err());
    assert!(channel.bind(&request, &hello(&der)).is_err());
    assert!(channel.connection.close_reason().is_some());
}
#[tokio::test]
async fn process_owner_persists_replay_across_endpoint_lifetimes() {
    let (a, b, mut channel, _peer, der) = pair().await;
    let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    let binding = channel.bind(&request, &hello(&der)).unwrap();
    drop(a);
    drop(b);
    let (leaf, key) = identity(true);
    let new_endpoint =
        ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), leaf, key).unwrap();
    assert!(
        new_endpoint.owner.replay.consume(&binding).is_err(),
        "new endpoint reset process replay"
    );
}
#[tokio::test]
async fn server_without_client_auth_cannot_produce_provisional_channel() {
    let (leaf, key) = identity(true);
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.into()], key)
        .unwrap();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
        )),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    // The original external-connection attack still completes unilateral TLS,
    // but there is now no public way to adopt that connection (compile-fail).
    let (leaf, key) = identity(true);
    let (_, strict) = configs(leaf, key).unwrap();
    let (config, _) = strict.fresh().unwrap();
    let mut external = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    external.set_default_client_config(config);
    let (outgoing, incoming) = tokio::join!(
        external
            .connect(server.local_addr().unwrap(), "pairing.local")
            .unwrap(),
        async { server.accept().await.unwrap().await }
    );
    let outside = outgoing.unwrap();
    let incoming = incoming.unwrap();
    assert!(
        incoming.peer_identity().is_none(),
        "attack precondition: no client cert"
    );
    outside.close(0u32.into(), b"external precondition complete");
    let (leaf, key) = identity(true);
    let client = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), leaf, key).unwrap();
    // Prime the same endpoint with successful mutual TLS: authentication evidence
    // must be per connection, never inherited from this previous connection.
    let (leaf, key) = identity(true);
    let legitimate = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), leaf, key).unwrap();
    let (first, other) = tokio::join!(
        client.connect(legitimate.local_addr().unwrap()),
        legitimate.accept()
    );
    drop(first.unwrap());
    drop(other.unwrap());
    let (outgoing, _incoming) = tokio::join!(client.connect(server.local_addr().unwrap()), async {
        server.accept().await.unwrap().await
    });
    assert!(outgoing.is_err(), "unilateral TLS minted a sealed channel");
}
#[tokio::test]
async fn owner_generations_are_distinct_and_endpoint_drop_revokes_channels() {
    let (client, _server, mut channel, peer, der) = pair().await;
    assert_ne!(channel.generation, peer.generation);
    drop(client);
    assert_eq!(
        channel.scope.0.lock().unwrap().phase,
        super::ConsentPhase::Revoked,
        "scope revoked synchronously"
    );
    let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    assert!(channel.bind(&request, &hello(&der)).is_err());
}
#[tokio::test]
async fn revoked_scope_rejects_before_any_network_close_notification() {
    let (_client, _server, mut channel, _peer, der) = pair().await;
    // Inject the local revocation boundary without delivering a network close.
    channel.scope.revoke();
    assert!(channel.connection.close_reason().is_none());
    let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    assert!(channel.bind(&request, &hello(&der)).is_err());
}
#[tokio::test]
async fn poisoned_scope_is_fail_closed() {
    let (_client, _server, mut channel, _peer, der) = pair().await;
    let scope = channel.scope.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = scope.0.lock().unwrap();
            panic!("injected scope poison");
        })
        .join()
        .is_err()
    );
    let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    assert!(channel.bind(&request, &hello(&der)).is_err());
}
#[test]
fn generation_exhaustion_fails_closed_without_wrapping() {
    let owner = super::ProcessOwner {
        replay: Default::default(),
        generation: std::sync::atomic::AtomicU64::new(u64::MAX),
    };
    assert!(owner.generation().is_err());
    assert!(owner.generation().is_err());
}
#[tokio::test]
async fn fragmented_quic_record_and_trailing_or_dropped_record_obey_complete_boundary() {
    let (_a, _b, c, peer, _) = pair().await;
    let payload = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    let frame = TransportFrame {
        kind: FrameKind::CandidateRequest,
        payload,
    }
    .encode()
    .unwrap();
    for mode in 0..4 {
        let mut data = frame.clone();
        if mode == 3 {
            data.truncate(15);
            data[11..15].copy_from_slice(&u32::MAX.to_be_bytes());
        }
        let sender = c.connection.clone();
        let write = tokio::spawn(async move {
            let mut s = sender.open_uni().await.unwrap();
            for chunk in data.chunks(3) {
                s.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
            if mode == 1 {
                s.write_all(&[0]).await.unwrap();
            }
            if mode == 2 {
                s.reset(1u32.into()).unwrap();
            } else {
                s.finish().unwrap();
            }
        });
        let mut receive = peer.connection.accept_uni().await.unwrap();
        let result = read_record(
            &mut receive,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await;
        assert_eq!(result.is_ok(), mode == 0);
        write.await.unwrap();
    }
}

struct ProcessGuard(Option<std::process::Child>);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_process_loopback_observes_real_leaf_exporter_and_only_pending_evidence() {
    let (leaf, key) = identity(true);
    let endpoint =
        ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), leaf.clone(), key).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "pairing_v2::provisional_tls::tests::provisional_process_worker",
            "--nocapture",
        ])
        .env(
            "CSF12_PROVISIONAL_TEST_PEER",
            endpoint.local_addr().unwrap().to_string(),
        )
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = ProcessGuard(Some(child));
    let connection = tokio::time::timeout(Duration::from_secs(5), async {
        endpoint.accept().await.unwrap()
    })
    .await
    .unwrap();
    let (mut send, mut receive) =
        tokio::time::timeout(Duration::from_secs(5), connection.connection.accept_bi())
            .await
            .unwrap()
            .unwrap();
    let request = read_record(
        &mut receive,
        tokio::time::Instant::now() + Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(request.kind, FrameKind::CandidateRequest);
    CandidateRequest::decode(&request.payload).unwrap();
    let frame = TransportFrame {
        kind: FrameKind::CandidateHello,
        payload: hello(&leaf),
    }
    .encode()
    .unwrap();
    for chunk in frame.chunks(7) {
        send.write_all(chunk).await.unwrap();
    }
    send.finish().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
        assert!(std::time::Instant::now() < deadline, "worker deadline");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let output = child.0.take().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("TRANSPORT_BOUND_PENDING"));
}
#[test]
#[ignore = "subprocess helper"]
fn provisional_process_worker() {
    let peer = std::env::var("CSF12_PROVISIONAL_TEST_PEER")
        .unwrap()
        .parse()
        .unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (leaf, key) = identity(true);
            let endpoint =
                ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), leaf, key).unwrap();
            let mut channel = tokio::time::timeout(Duration::from_secs(5), endpoint.connect(peer))
                .await
                .unwrap()
                .unwrap();
            let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
                .encode()
                .unwrap();
            let (mut send, mut receive) = channel.connection.open_bi().await.unwrap();
            let frame = TransportFrame {
                kind: FrameKind::CandidateRequest,
                payload: request.clone(),
            }
            .encode()
            .unwrap();
            for chunk in frame.chunks(2) {
                send.write_all(chunk).await.unwrap();
            }
            send.finish().unwrap();
            let response = read_record(
                &mut receive,
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();
            assert_eq!(response.kind, FrameKind::CandidateHello);
            channel.bind(&request, &response.payload).unwrap();
            println!("TRANSPORT_BOUND_PENDING");
        });
}
#[test]
fn local_profile_and_certificate_key_mismatch_are_rejected() {
    let (bad, key) = identity(false);
    assert!(configs(bad, key).is_err());
    let (a, _) = identity(true);
    let (_, wrong) = identity(true);
    assert!(configs(a, wrong).is_err());
}

#[derive(Debug)]
struct ForgedSigner;
impl rustls::sign::SigningKey for ForgedSigner {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        offered
            .contains(&rustls::SignatureScheme::ED25519)
            .then(|| Box::new(Self) as Box<dyn rustls::sign::Signer>)
    }
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
}
impl rustls::sign::Signer for ForgedSigner {
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(vec![0; 64])
    }
    fn scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ED25519
    }
}
#[tokio::test]
async fn real_tls_rejects_forged_certificate_verify_even_with_valid_leaf_profile() {
    let (leaf, _key) = identity(true);
    let key = rustls::sign::CertifiedKey::new(vec![leaf.into()], Arc::new(ForgedSigner));
    let mut crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(super::ProfileVerifier(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))))
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(key)));
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
        )),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let (leaf, key) = identity(true);
    let client = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), leaf, key).unwrap();
    let outgoing = client.connect(server.local_addr().unwrap());
    let (result, _) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), outgoing),
        async {
            let c = server.accept().await.unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(2), c).await;
        }
    );
    assert!(
        result.unwrap().is_err(),
        "valid public certificate cannot replace private-key possession"
    );
}
#[tokio::test]
async fn actual_remote_bad_profile_and_alpn_downgrade_fail_tls() {
    for bad_profile in [false, true] {
        let (leaf, key) = identity(!bad_profile);
        let mut crypto = rustls::ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(super::ProfileVerifier(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))))
            .with_single_cert(vec![leaf.into()], key)
            .unwrap();
        crypto.alpn_protocols = vec![if bad_profile {
            ALPN.to_vec()
        } else {
            b"csf12-pair/1".to_vec()
        }];
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
            )),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let (leaf, key) = identity(true);
        let client = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), leaf, key).unwrap();
        let outgoing = client.connect(server.local_addr().unwrap());
        let (result, _) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(2), outgoing),
            async {
                if let Some(c) = server.accept().await {
                    let _ = tokio::time::timeout(Duration::from_secs(2), c).await;
                }
            }
        );
        assert!(
            result.unwrap().is_err(),
            "remote bad profile or ALPN accepted"
        );
    }
}
