use super::handshake_io::FinalizationTestFault;
use crate::pairing_pending::{BilateralTransactionFields, derive_bilateral_transaction_id};
use crate::pairing_v2::{
    Role, SUITE,
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

#[test]
fn recovery_tls_profile_requires_the_durable_peer_fingerprint() {
    let (peer, _) = identity(true);
    let (other, _) = identity(true);
    let now = 1_893_456_000;
    let peer_fingerprint: [u8; 32] = Sha256::digest(&peer).into();
    assert!(super::profile_for_pinned_peer(&peer, peer_fingerprint, now).is_ok());
    assert!(super::profile_for_pinned_peer(&other, peer_fingerprint, now).is_err());
    assert!(
        super::strict_pinned_configs(
            peer,
            identity(true).1,
            [0; 32],
            b"control-shift-f12-recovery/1",
            1,
            0,
        )
        .is_err()
    );
}

#[tokio::test]
async fn recovery_tls_rejects_an_unpinned_peer_before_any_recovery_record() {
    let (a_certificate, a_key) = identity(true);
    let (b_certificate, b_key) = identity(true);
    let (outsider_certificate, outsider_key) = identity(true);
    let a_fingerprint: [u8; 32] = Sha256::digest(&a_certificate).into();
    let b_fingerprint: [u8; 32] = Sha256::digest(&b_certificate).into();
    let alpn = b"control-shift-f12-recovery/1";

    let (server_config, _) =
        super::strict_pinned_configs(b_certificate.clone(), b_key, a_fingerprint, alpn, 1, 0)
            .unwrap();
    let server = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();

    let (_, a_client) =
        super::strict_pinned_configs(a_certificate, a_key, b_fingerprint, alpn, 1, 0).unwrap();
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let (config, evidence) = a_client.fresh().unwrap();
    client.set_default_client_config(config);
    let connecting = client
        .connect(server.local_addr().unwrap(), "pairing.local")
        .unwrap();
    let (connected, accepted) = tokio::join!(connecting, async {
        let incoming = server.accept().await.unwrap();
        incoming.await
    });
    assert!(connected.is_ok());
    assert!(accepted.is_ok());
    assert!(evidence.was_requested());
    drop(client);

    let (_, outsider_client) = super::strict_pinned_configs(
        outsider_certificate,
        outsider_key,
        b_fingerprint,
        alpn,
        1,
        0,
    )
    .unwrap();
    let mut outsider = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let (config, _) = outsider_client.fresh().unwrap();
    outsider.set_default_client_config(config);
    let connecting = outsider
        .connect(server.local_addr().unwrap(), "pairing.local")
        .unwrap();
    let (_, server_rejected) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), connecting),
        async {
            let incoming = tokio::time::timeout(Duration::from_secs(2), server.accept())
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), incoming)
                .await
                .unwrap()
        }
    );
    assert!(server_rejected.is_err());
}

async fn pinned_recovery_connection() -> (
    quinn::Endpoint,
    quinn::Endpoint,
    quinn::Connection,
    quinn::Connection,
) {
    let (a_certificate, a_key) = identity(true);
    let (b_certificate, b_key) = identity(true);
    pinned_recovery_connection_for_identities(a_certificate, a_key, b_certificate, b_key).await
}

async fn pinned_recovery_connection_for_identities(
    a_certificate: Vec<u8>,
    a_key: rustls::pki_types::PrivateKeyDer<'static>,
    b_certificate: Vec<u8>,
    b_key: rustls::pki_types::PrivateKeyDer<'static>,
) -> (
    quinn::Endpoint,
    quinn::Endpoint,
    quinn::Connection,
    quinn::Connection,
) {
    let a_fingerprint: [u8; 32] = Sha256::digest(&a_certificate).into();
    let b_fingerprint: [u8; 32] = Sha256::digest(&b_certificate).into();
    let alpn = b"control-shift-f12-recovery/1";
    let (server_config, _) =
        super::strict_pinned_configs(b_certificate, b_key, a_fingerprint, alpn, 1, 0).unwrap();
    let server = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let (_, a_client) =
        super::strict_pinned_configs(a_certificate, a_key, b_fingerprint, alpn, 1, 0).unwrap();
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let (config, _) = a_client.fresh().unwrap();
    client.set_default_client_config(config);
    let connecting = client
        .connect(server.local_addr().unwrap(), "pairing.local")
        .unwrap();
    let (left_connection, right_connection) = tokio::join!(connecting, async {
        server.accept().await.unwrap().await.unwrap()
    });
    (server, client, left_connection.unwrap(), right_connection)
}

#[tokio::test]
async fn exact_peer_recovery_exchanges_one_complementary_record_over_pinned_tls() {
    let (_server, _client, left_connection, right_connection) = pinned_recovery_connection().await;
    let left = crate::pairing_v2::recovery::ExactPeerRecovery::new(
        [1; 32],
        [2; 32],
        Some([3; 32]),
        7,
        11,
        0,
    )
    .unwrap();
    let right = crate::pairing_v2::recovery::ExactPeerRecovery::new(
        [1; 32],
        [3; 32],
        Some([2; 32]),
        7,
        11,
        0,
    )
    .unwrap();
    let (left_peer, right_peer) = tokio::join!(
        crate::pairing_v2::recovery::exchange_exact_pair(&left_connection, true, left.clone(),),
        crate::pairing_v2::recovery::exchange_exact_pair(&right_connection, false, right.clone()),
    );
    assert_eq!(left_peer.unwrap().evidence(), &right);
    assert_eq!(right_peer.unwrap().evidence(), &left);
}

#[tokio::test]
async fn exact_peer_recovery_rejects_a_changed_binding_over_pinned_tls() {
    let (_server, _client, left_connection, right_connection) = pinned_recovery_connection().await;
    let left = crate::pairing_v2::recovery::ExactPeerRecovery::new(
        [1; 32],
        [2; 32],
        Some([3; 32]),
        7,
        11,
        0,
    )
    .unwrap();
    let changed = crate::pairing_v2::recovery::ExactPeerRecovery::new(
        [1; 32],
        [3; 32],
        Some([2; 32]),
        7,
        12,
        0,
    )
    .unwrap();
    let (left_result, right_result) = tokio::join!(
        crate::pairing_v2::recovery::exchange_exact_pair(&left_connection, true, left),
        crate::pairing_v2::recovery::exchange_exact_pair(&right_connection, false, changed),
    );
    assert!(left_result.is_err());
    assert!(right_result.is_err());
}

fn seed_recovery_receipt(
    root: &std::path::Path,
    local: [u8; 32],
    peer: [u8; 32],
    attempt: [u8; 32],
    peer_attempt: [u8; 32],
) -> crate::pairing_pending::AdmissionReceiptRecord {
    use crate::pairing_pending::{
        AdmissionOwnership, AdmissionReceiptRecord, BilateralAdmissionRecord, PendingStore,
        bind_prepared_bilateral_receipt_hash,
    };
    let store = PendingStore::open(root).unwrap();
    let record = store
        .prepare(store.version().unwrap(), attempt, peer)
        .unwrap();
    let version = store.version().unwrap();
    let fields = BilateralTransactionFields {
        local_identity: local,
        peer_identity: peer,
        local_attempt: attempt,
        peer_attempt,
        peer_pin: peer,
        transcript: [175; 32],
        suite: SUITE.to_owned(),
        policy_revision: 0,
    };
    let mut receipt = AdmissionReceiptRecord {
        attempt,
        peer,
        peer_pin: peer,
        durable_fc_hash: [176; 32],
        role: 0,
        suite: SUITE.to_owned(),
        protocol_version: 2,
        transcript: fields.transcript,
        binding: [177; 32],
        revision: version.revision + 1,
        identity_generation: version.identity_generation,
        revocation_generation: record.revocation_generation,
        policy_revision: 0,
        ownership: AdmissionOwnership::StoreOwned {
            guard_token: attempt,
            staged_revision: version.revision,
            handoff_revision: version.revision + 1,
        },
        bilateral: BilateralAdmissionRecord::prepared(
            &fields,
            attempt,
            version.identity_generation,
            record.revocation_generation,
            0,
        ),
    };
    bind_prepared_bilateral_receipt_hash(&mut receipt);
    store
        .publish_local_bilateral_receipt(version, &record, receipt)
        .unwrap()
}

#[tokio::test]
async fn exact_peer_recovery_coordinator_confirms_both_durable_receipts_without_authority() {
    use crate::pairing_pending::{BilateralAdmissionState, PendingStore};
    use crate::pairing_v2::admission_authority::{
        AdmissionAuthorityStore, recover_bilateral_foundation,
    };
    // Cover reciprocal unconfirmed records and the one-sided confirmed crash.
    for left_was_confirmed in [false, true] {
        let (a, ak) = identity(true);
        let (b, bk) = identity(true);
        let a_hash = Sha256::digest(&a).into();
        let b_hash = Sha256::digest(&b).into();
        let left_root = tempfile::tempdir().unwrap();
        let right_root = tempfile::tempdir().unwrap();
        let left_receipt =
            seed_recovery_receipt(left_root.path(), a_hash, b_hash, [171; 32], [172; 32]);
        let right_receipt =
            seed_recovery_receipt(right_root.path(), b_hash, a_hash, [172; 32], [171; 32]);
        if left_was_confirmed {
            let store = PendingStore::open(left_root.path()).unwrap();
            store
                .confirm_bilateral_receipt(
                    store.version().unwrap(),
                    [171; 32],
                    left_receipt.bilateral.transaction_id,
                    left_receipt.bilateral.local_receipt_hash,
                    right_receipt.bilateral.local_receipt_hash,
                )
                .unwrap();
        }
        let left = AdmissionAuthorityStore::open(left_root.path()).unwrap();
        let right = AdmissionAuthorityStore::open(right_root.path()).unwrap();
        let (_server, _client, lc, rc) =
            pinned_recovery_connection_for_identities(a, ak, b, bk).await;
        recover_bilateral_foundation(&left, [171; 32], &right, [172; 32], Some((&lc, &rc)))
            .await
            .unwrap();
        for (store, attempt, peer_hash) in [
            (&left, [171; 32], right_receipt.bilateral.local_receipt_hash),
            (&right, [172; 32], left_receipt.bilateral.local_receipt_hash),
        ] {
            let receipt = store.test_bilateral_receipt(attempt).unwrap().unwrap();
            assert_eq!(
                receipt.bilateral.state,
                BilateralAdmissionState::BilateralConfirmed
            );
            assert_eq!(receipt.bilateral.peer_receipt_hash, Some(peer_hash));
            assert!(store.operational_admission_snapshot(attempt).is_err());
        }
    }
}

#[tokio::test]
async fn exact_peer_recovery_coordinator_mismatch_aborts_both_before_same_peer_retry() {
    use crate::pairing_v2::admission_authority::{
        AdmissionAuthorityStore, ReconcileAdmission, recover_bilateral_foundation,
    };
    let (a, ak) = identity(true);
    let (b, bk) = identity(true);
    let a_hash = Sha256::digest(&a).into();
    let b_hash = Sha256::digest(&b).into();
    let left_root = tempfile::tempdir().unwrap();
    let right_root = tempfile::tempdir().unwrap();
    seed_recovery_receipt(left_root.path(), a_hash, b_hash, [181; 32], [182; 32]);
    // The authenticated peer has a different transaction, not authority to
    // complete the receiver's immutable receipt.
    seed_recovery_receipt(right_root.path(), b_hash, a_hash, [182; 32], [183; 32]);
    let left = AdmissionAuthorityStore::open(left_root.path()).unwrap();
    let right = AdmissionAuthorityStore::open(right_root.path()).unwrap();
    let (_server, _client, lc, rc) = pinned_recovery_connection_for_identities(a, ak, b, bk).await;
    assert!(
        recover_bilateral_foundation(&left, [181; 32], &right, [182; 32], Some((&lc, &rc)))
            .await
            .is_err()
    );
    for (store, attempt, peer, retry) in [
        (&left, [181; 32], b_hash, [184; 32]),
        (&right, [182; 32], a_hash, [185; 32]),
    ] {
        assert_eq!(
            store.reconcile(attempt).unwrap(),
            ReconcileAdmission::Absent
        );
        assert!(store.operational_admission_snapshot(attempt).is_err());
        store
            .prepare(store.version().unwrap(), retry, peer)
            .unwrap();
    }
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
async fn current_foundation_preserves_store_owned_metadata_on_listener_shutdown() {
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
    // This remains durable metadata only.  The handoff has transferred just
    // the revocation guard, so listener cleanup must not revoke it.
    assert_eq!(
        store.reconcile(receipt.attempt()).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
    );
}

#[tokio::test]
async fn real_handshake_inverted_perspectives_derive_one_bilateral_transaction_id() {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(handshake_config(1, 2), &sa, |prompt| async move {
            prompt.decision(true)
        }),
        b.handshake(handshake_config(2, 1), &sb, |prompt| async move {
            prompt.decision(true)
        })
    );
    let (a, b) = tokio::join!(
        a.unwrap().seal_for_promotion(),
        b.unwrap().seal_for_promotion()
    );
    let a = a.unwrap();
    let b = b.unwrap();
    let fields_a = a.fields();
    let fields_b = b.fields();
    assert_eq!(fields_a.transcript, fields_b.transcript);
    assert_eq!(fields_a.record.attempt_id, fields_b.record.attempt_id);
    assert_eq!(
        fields_a.record.peer_fingerprint,
        fields_a.certificate_fingerprints[1 - fields_a.role.index()]
    );
    assert_eq!(
        fields_b.record.peer_fingerprint,
        fields_b.certificate_fingerprints[1 - fields_b.role.index()]
    );

    let descriptor_a = BilateralTransactionFields {
        local_identity: fields_a.certificate_fingerprints[fields_a.role.index()],
        peer_identity: fields_a.record.peer_fingerprint,
        local_attempt: fields_a.record.attempt_id,
        peer_attempt: fields_b.record.attempt_id,
        peer_pin: fields_a.certificate_fingerprints[1 - fields_a.role.index()],
        transcript: fields_a.transcript,
        suite: SUITE.to_owned(),
        policy_revision: 0,
    };
    let descriptor_b = BilateralTransactionFields {
        local_identity: fields_b.certificate_fingerprints[fields_b.role.index()],
        peer_identity: fields_b.record.peer_fingerprint,
        local_attempt: fields_b.record.attempt_id,
        peer_attempt: fields_a.record.attempt_id,
        peer_pin: fields_b.certificate_fingerprints[1 - fields_b.role.index()],
        transcript: fields_b.transcript,
        suite: SUITE.to_owned(),
        policy_revision: 0,
    };
    assert_eq!(
        derive_bilateral_transaction_id(&descriptor_a),
        derive_bilateral_transaction_id(&descriptor_b)
    );
}

#[tokio::test]
async fn finalization_exchanges_authenticated_peer_proofs_on_real_endpoints() {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(handshake_config(1, 2), &sa, |prompt| async move {
            prompt.decision(true)
        }),
        b.handshake(handshake_config(2, 1), &sb, |prompt| async move {
            prompt.decision(true)
        })
    );
    let mut a = a.unwrap();
    let mut b = b.unwrap();
    let a_receipt = a
        .local_finalization_receipt(b.test_attempt(), [71; 32])
        .unwrap();
    let b_receipt = b
        .local_finalization_receipt(a.test_attempt(), [72; 32])
        .unwrap();
    assert_eq!(
        a_receipt.test_transaction_id(),
        b_receipt.test_transaction_id()
    );
    let (a_proof, b_proof) = tokio::join!(
        a.exchange_local_receipt(a_receipt),
        b.exchange_local_receipt(b_receipt)
    );
    assert!(a_proof.is_ok(), "A finalization result: {a_proof:?}");
    assert!(b_proof.is_ok(), "B finalization result: {b_proof:?}");
    let a_proof = a_proof.unwrap();
    let b_proof = b_proof.unwrap();
    assert_eq!(a_proof.transaction_id(), b_proof.transaction_id());
    assert_eq!(a_proof.peer_receipt_hash(), [72; 32]);
    assert_eq!(b_proof.peer_receipt_hash(), [71; 32]);
    assert_eq!(
        a_proof.transcript(),
        b_proof.transcript(),
        "the proof must remain bound to the frozen bilateral transcript"
    );
}

#[tokio::test]
async fn bilateral_commit_requires_both_stores_confirmed_before_any_snapshot() {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(handshake_config(31, 32), &sa, |prompt| async move {
            prompt.decision(true)
        }),
        b.handshake(handshake_config(32, 31), &sb, |prompt| async move {
            prompt.decision(true)
        })
    );
    let a = a.unwrap();
    let b = b.unwrap();
    let a_attempt = a.test_attempt();
    let b_attempt = b.test_attempt();
    let left =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    let right =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(tb.path()).unwrap();
    let hook = crate::pairing_v2::admission_authority::BilateralCommitTestHook::recording();

    crate::pairing_v2::admission_authority::commit_bilateral_foundation_with_test_hook(
        &left, a, &right, b, &hook,
    )
    .await
    .expect("both exact local receipts must confirm after authenticated peer proofs");

    use crate::pairing_v2::admission_authority::BilateralCommitCheckpoint as Checkpoint;
    assert_eq!(
        hook.checkpoints(),
        vec![
            Checkpoint::PreflightComplete,
            Checkpoint::LeftStaged,
            Checkpoint::RightStaged,
            Checkpoint::Task3ProofsAttempted,
            Checkpoint::Task3ProofsVerified,
            Checkpoint::LeftFrozen,
            Checkpoint::RightFrozen,
            Checkpoint::LeftFinalized,
            Checkpoint::RightFinalized,
            Checkpoint::LeftConfirmed,
            Checkpoint::RightConfirmed,
        ],
        "the trace is append-only evidence of actual transitions: Task 3 must finish while both endpoints remain live, before either freeze"
    );
    let left_receipt = left
        .test_bilateral_receipt(a_attempt)
        .unwrap()
        .expect("left confirmed receipt");
    let right_receipt = right
        .test_bilateral_receipt(b_attempt)
        .unwrap()
        .expect("right confirmed receipt");
    assert_eq!(
        left_receipt.bilateral.state,
        crate::pairing_pending::BilateralAdmissionState::BilateralConfirmed
    );
    assert_eq!(
        right_receipt.bilateral.state,
        crate::pairing_pending::BilateralAdmissionState::BilateralConfirmed
    );
    assert_eq!(
        left_receipt.bilateral.transaction_id,
        right_receipt.bilateral.transaction_id
    );
    assert_eq!(
        left_receipt.bilateral.local_receipt_hash,
        right_receipt.bilateral.peer_receipt_hash.unwrap()
    );
    assert_eq!(
        right_receipt.bilateral.local_receipt_hash,
        left_receipt.bilateral.peer_receipt_hash.unwrap()
    );
    assert!(left.operational_admission_snapshot(a_attempt).is_err());
    assert!(right.operational_admission_snapshot(b_attempt).is_err());
}

async fn bilateral_commit_failure_aborts_exact_transactions_on_both_stores(
    make_hook: impl FnOnce(
        ProvisionalEndpoint,
    ) -> crate::pairing_v2::admission_authority::BilateralCommitTestHook,
    expected_checkpoints: &[crate::pairing_v2::admission_authority::BilateralCommitCheckpoint],
) {
    let (ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(handshake_config(33, 34), &sa, |prompt| async move {
            prompt.decision(true)
        }),
        b.handshake(handshake_config(34, 33), &sb, |prompt| async move {
            prompt.decision(true)
        })
    );
    let a = a.unwrap();
    let b = b.unwrap();
    let a_attempt = a.test_attempt();
    let b_attempt = b.test_attempt();
    let left =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    let right =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(tb.path()).unwrap();

    let a_peer = sa.pending(a_attempt).unwrap().unwrap().peer_fingerprint;
    let b_peer = sb.pending(b_attempt).unwrap().unwrap().peer_fingerprint;
    // The hook keeps the real client endpoint alive unless this exact test
    // chooses to drop it at a named transition. This rules out a fake
    // store-only endpoint failure seam.
    let hook = make_hook(ea);
    let result =
        crate::pairing_v2::admission_authority::commit_bilateral_foundation_with_test_hook(
            &left, a, &right, b, &hook,
        )
        .await;
    assert!(result.is_err());
    assert!(left.operational_admission_snapshot(a_attempt).is_err());
    assert!(right.operational_admission_snapshot(b_attempt).is_err());
    assert_eq!(
        left.reconcile(a_attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Absent
    );
    assert_eq!(
        right.reconcile(b_attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Absent
    );
    assert!(
        !left.test_has_admission_guard(a_attempt).unwrap(),
        "exact abort must consume the left guard sidecar"
    );
    assert!(
        !right.test_has_admission_guard(b_attempt).unwrap(),
        "exact abort must consume the right guard sidecar"
    );
    // Reopen from disk after every terminal path.  A process that did not
    // observe the in-memory abort must neither retain an active sidecar nor
    // reconstruct an operational admission from the unfinished receipt.
    let reopened_left =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    let reopened_right =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(tb.path()).unwrap();
    assert_eq!(
        reopened_left.reconcile(a_attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Absent
    );
    assert_eq!(
        reopened_right.reconcile(b_attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Absent
    );
    assert!(!reopened_left.test_has_admission_guard(a_attempt).unwrap());
    assert!(!reopened_right.test_has_admission_guard(b_attempt).unwrap());
    // Exact compensation must release only the failed transaction.  A fresh
    // same-peer attempt proves no stale reservation, pin, or guard survived.
    reopened_left
        .prepare(reopened_left.version().unwrap(), [91; 32], a_peer)
        .expect("left exact abort must not block a later same-peer attempt");
    reopened_right
        .prepare(reopened_right.version().unwrap(), [92; 32], b_peer)
        .expect("right exact abort must not block a later same-peer attempt");
    assert_eq!(
        hook.checkpoints(),
        expected_checkpoints,
        "the test hook must report immutable checkpoints after real transitions"
    );
}

#[tokio::test]
async fn every_durable_bilateral_commit_checkpoint_aborts_exactly() {
    use crate::pairing_v2::admission_authority::{
        BilateralCommitCheckpoint as Checkpoint, BilateralCommitTestHook as Hook,
    };

    macro_rules! assert_exact_abort {
        ($make_hook:expr, $expected:expr) => {
            bilateral_commit_failure_aborts_exact_transactions_on_both_stores(
                $make_hook, &$expected,
            )
            .await
        };
    }

    assert_exact_abort!(
        |endpoint| Hook::with_live_left_endpoint(endpoint).fail_after(Checkpoint::LeftStaged),
        vec![
            Checkpoint::PreflightComplete,
            Checkpoint::LeftStaged,
            Checkpoint::RightAborted,
            Checkpoint::LeftAborted,
        ]
    );
    assert_exact_abort!(
        |endpoint| Hook::with_live_left_endpoint(endpoint).fail_after(Checkpoint::RightStaged),
        vec![
            Checkpoint::PreflightComplete,
            Checkpoint::LeftStaged,
            Checkpoint::RightStaged,
            Checkpoint::RightAborted,
            Checkpoint::LeftAborted,
        ]
    );
    assert_exact_abort!(
        |endpoint| Hook::with_live_left_endpoint(endpoint).fail_after(Checkpoint::LeftFinalized),
        vec![
            Checkpoint::PreflightComplete,
            Checkpoint::LeftStaged,
            Checkpoint::RightStaged,
            Checkpoint::Task3ProofsAttempted,
            Checkpoint::Task3ProofsVerified,
            Checkpoint::LeftFrozen,
            Checkpoint::RightFrozen,
            Checkpoint::LeftFinalized,
            Checkpoint::RightAborted,
            Checkpoint::LeftAborted,
        ]
    );
    assert_exact_abort!(
        |endpoint| Hook::with_live_left_endpoint(endpoint).fail_after(Checkpoint::RightFinalized),
        vec![
            Checkpoint::PreflightComplete,
            Checkpoint::LeftStaged,
            Checkpoint::RightStaged,
            Checkpoint::Task3ProofsAttempted,
            Checkpoint::Task3ProofsVerified,
            Checkpoint::LeftFrozen,
            Checkpoint::RightFrozen,
            Checkpoint::LeftFinalized,
            Checkpoint::RightFinalized,
            Checkpoint::RightAborted,
            Checkpoint::LeftAborted,
        ]
    );
    assert_exact_abort!(
        |endpoint| Hook::with_live_left_endpoint(endpoint).fail_after(Checkpoint::LeftConfirmed),
        vec![
            Checkpoint::PreflightComplete,
            Checkpoint::LeftStaged,
            Checkpoint::RightStaged,
            Checkpoint::Task3ProofsAttempted,
            Checkpoint::Task3ProofsVerified,
            Checkpoint::LeftFrozen,
            Checkpoint::RightFrozen,
            Checkpoint::LeftFinalized,
            Checkpoint::RightFinalized,
            Checkpoint::LeftConfirmed,
            Checkpoint::RightAborted,
            Checkpoint::LeftAborted,
        ]
    );
    assert_exact_abort!(
        |endpoint| Hook::with_live_left_endpoint(endpoint).wrong_transaction_on_wire(),
        vec![
            Checkpoint::PreflightComplete,
            Checkpoint::LeftStaged,
            Checkpoint::RightStaged,
            Checkpoint::Task3ProofsAttempted,
            Checkpoint::RightAborted,
            Checkpoint::LeftAborted,
        ]
    );
}

#[tokio::test]
async fn endpoint_drop_before_or_after_staging_aborts_exactly() {
    use crate::pairing_v2::admission_authority::{
        BilateralCommitCheckpoint as Checkpoint, BilateralCommitTestHook as Hook,
    };

    // The hook owns the actual provisional endpoint; reaching the named
    // checkpoint drops it and its watcher rather than synthesizing a storage
    // state. The coordinator must observe the real transport close.
    bilateral_commit_failure_aborts_exact_transactions_on_both_stores(
        |endpoint| Hook::drop_real_left_endpoint_after(Checkpoint::PreflightComplete, endpoint),
        &[
            Checkpoint::PreflightComplete,
            Checkpoint::LeftEndpointDropped,
        ],
    )
    .await;
    bilateral_commit_failure_aborts_exact_transactions_on_both_stores(
        |endpoint| Hook::drop_real_left_endpoint_after(Checkpoint::LeftStaged, endpoint),
        &[
            Checkpoint::PreflightComplete,
            Checkpoint::LeftStaged,
            Checkpoint::LeftEndpointDropped,
            Checkpoint::RightAborted,
        ],
    )
    .await;
    // After both sides freeze their exact reservations, dropping the original
    // endpoint must abort only its frozen handoff.  It may not fall back to a
    // peer-wide revocation that could erase a later same-peer admission.
    bilateral_commit_failure_aborts_exact_transactions_on_both_stores(
        |endpoint| Hook::drop_real_left_endpoint_after(Checkpoint::LeftFrozen, endpoint),
        &[
            Checkpoint::PreflightComplete,
            Checkpoint::LeftStaged,
            Checkpoint::RightStaged,
            Checkpoint::Task3ProofsAttempted,
            Checkpoint::Task3ProofsVerified,
            Checkpoint::LeftFrozen,
            Checkpoint::LeftEndpointDropped,
            Checkpoint::RightAborted,
        ],
    )
    .await;
}

#[tokio::test]
async fn stale_failed_coordinator_abort_cannot_damage_fresh_same_peer_finalization() {
    use crate::pairing_v2::admission_authority::BilateralCommitTestHook as Hook;

    // A failed coordinator consumes its endpoints. Reopen fresh endpoints
    // with the same identities so this is a real same-peer retry rather than
    // an invalid reuse of a closed provisional consent scope.
    let (a_identity, a_key) = identity(true);
    let a_retry_key = a_key.clone_key();
    let (b_identity, b_key) = identity(true);
    let b_retry_key = b_key.clone_key();
    let ea = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_identity.clone(), a_key)
        .unwrap();
    let eb = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_identity.clone(), b_key)
        .unwrap();
    let (a, b) = tokio::join!(ea.connect(eb.local_addr().unwrap()), eb.accept());
    let a = a.unwrap();
    let b = b.unwrap();
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(handshake_config(41, 42), &sa, |prompt| async move {
            prompt.decision(true)
        }),
        b.handshake(handshake_config(42, 41), &sb, |prompt| async move {
            prompt.decision(true)
        })
    );
    let a = a.unwrap();
    let b = b.unwrap();
    let stale_a_attempt = a.test_attempt();
    let stale_b_attempt = b.test_attempt();
    let left =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    let right =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(tb.path()).unwrap();
    // This is a real Task 3 failure: both receipts are already staged and
    // one peer sends an HMAC-valid receipt bound to the wrong transaction.
    // The fresh retry below must still complete a full bilateral commit.
    let stale_hook = Hook::recording().wrong_transaction_on_wire();
    assert!(
        crate::pairing_v2::admission_authority::commit_bilateral_foundation_with_test_hook(
            &left,
            a,
            &right,
            b,
            &stale_hook,
        )
        .await
        .is_err()
    );

    let fresh_ea =
        ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_identity, a_retry_key).unwrap();
    let fresh_eb =
        ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_identity, b_retry_key).unwrap();
    let (fresh_a, fresh_b) = tokio::join!(
        fresh_ea.connect(fresh_eb.local_addr().unwrap()),
        fresh_eb.accept(),
    );
    let (fresh_a, fresh_b) = tokio::join!(
        fresh_a
            .unwrap()
            .handshake(handshake_config(43, 44), &sa, |prompt| async move {
                prompt.decision(true)
            }),
        fresh_b
            .unwrap()
            .handshake(handshake_config(44, 43), &sb, |prompt| async move {
                prompt.decision(true)
            })
    );
    let fresh_a = fresh_a.unwrap();
    let fresh_b = fresh_b.unwrap();
    let fresh_a_attempt = fresh_a.test_attempt();
    let fresh_b_attempt = fresh_b.test_attempt();
    let fresh_hook = Hook::recording();
    crate::pairing_v2::admission_authority::commit_bilateral_foundation_with_test_hook(
        &left,
        fresh_a,
        &right,
        fresh_b,
        &fresh_hook,
    )
    .await
    .expect("fresh same-peer finalization must survive stale exact abort cleanup");

    assert_eq!(
        left.reconcile(stale_a_attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Absent
    );
    assert_eq!(
        right.reconcile(stale_b_attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Absent
    );
    assert!(
        left.operational_admission_snapshot(fresh_a_attempt)
            .is_err()
    );
    assert!(
        right
            .operational_admission_snapshot(fresh_b_attempt)
            .is_err()
    );
    assert_eq!(
        left.test_bilateral_receipt(fresh_a_attempt)
            .unwrap()
            .unwrap()
            .bilateral
            .state,
        crate::pairing_pending::BilateralAdmissionState::BilateralConfirmed
    );
    assert_eq!(
        right
            .test_bilateral_receipt(fresh_b_attempt)
            .unwrap()
            .unwrap()
            .bilateral
            .state,
        crate::pairing_pending::BilateralAdmissionState::BilateralConfirmed
    );
}

#[tokio::test]
async fn cancelling_post_task3_coordinator_aborts_exactly_and_allows_full_same_peer_retry() {
    use crate::pairing_v2::admission_authority::{
        BilateralCommitCheckpoint as Checkpoint, BilateralCommitTestHook as Hook,
    };

    let (a_identity, a_key) = identity(true);
    let a_retry_key = a_key.clone_key();
    let (b_identity, b_key) = identity(true);
    let b_retry_key = b_key.clone_key();
    let ea = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_identity.clone(), a_key)
        .unwrap();
    let eb = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_identity.clone(), b_key)
        .unwrap();
    let (a, b) = tokio::join!(ea.connect(eb.local_addr().unwrap()), eb.accept());
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.unwrap()
            .handshake(handshake_config(51, 52), &sa, |prompt| async move {
                prompt.decision(true)
            }),
        b.unwrap()
            .handshake(handshake_config(52, 51), &sb, |prompt| async move {
                prompt.decision(true)
            })
    );
    let a = a.unwrap();
    let b = b.unwrap();
    let cancelled_a_attempt = a.test_attempt();
    let cancelled_b_attempt = b.test_attempt();
    let left_root = ta.path().to_owned();
    let right_root = tb.path().to_owned();
    let (hook, pause) = Hook::recording().pause_after(Checkpoint::Task3ProofsVerified);

    let cancelled = tokio::spawn(async move {
        let left =
            crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(&left_root)
                .unwrap();
        let right =
            crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(&right_root)
                .unwrap();
        crate::pairing_v2::admission_authority::commit_bilateral_foundation_with_test_hook(
            &left, a, &right, b, &hook,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), pause.wait_until_reached())
        .await
        .expect("Task 3 must complete before cancellation");
    cancelled.abort();
    assert!(
        cancelled.await.unwrap_err().is_cancelled(),
        "the coordinator task must be cancelled while both endpoints remain alive"
    );

    let left =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    let right =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(tb.path()).unwrap();
    for (store, attempt) in [(&left, cancelled_a_attempt), (&right, cancelled_b_attempt)] {
        assert_eq!(
            store.reconcile(attempt).unwrap(),
            crate::pairing_v2::admission_authority::ReconcileAdmission::Absent
        );
        assert!(!store.test_has_admission_guard(attempt).unwrap());
        assert!(store.operational_admission_snapshot(attempt).is_err());
    }

    let fresh_ea =
        ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_identity, a_retry_key).unwrap();
    let fresh_eb =
        ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_identity, b_retry_key).unwrap();
    let (fresh_a, fresh_b) = tokio::join!(
        fresh_ea.connect(fresh_eb.local_addr().unwrap()),
        fresh_eb.accept(),
    );
    let (fresh_a, fresh_b) = tokio::join!(
        fresh_a
            .unwrap()
            .handshake(handshake_config(53, 54), &sa, |prompt| async move {
                prompt.decision(true)
            }),
        fresh_b
            .unwrap()
            .handshake(handshake_config(54, 53), &sb, |prompt| async move {
                prompt.decision(true)
            })
    );
    let fresh_a = fresh_a.unwrap();
    let fresh_b = fresh_b.unwrap();
    let fresh_a_attempt = fresh_a.test_attempt();
    let fresh_b_attempt = fresh_b.test_attempt();
    crate::pairing_v2::admission_authority::commit_bilateral_foundation(
        &left, fresh_a, &right, fresh_b,
    )
    .await
    .expect("a cancelled exact transaction must not block a full same-peer retry");
    assert_eq!(
        left.test_bilateral_receipt(fresh_a_attempt)
            .unwrap()
            .unwrap()
            .bilateral
            .state,
        crate::pairing_pending::BilateralAdmissionState::BilateralConfirmed
    );
    assert_eq!(
        right
            .test_bilateral_receipt(fresh_b_attempt)
            .unwrap()
            .unwrap()
            .bilateral
            .state,
        crate::pairing_pending::BilateralAdmissionState::BilateralConfirmed
    );
    pause.resume();
    drop(ea);
    drop(eb);
}

#[test]
fn task4_prepared_subprocess_crash_reconciles_exactly_before_fresh_same_peer_retry() {
    fn parse_marker(stdout: &str, prefix: &str) -> [u8; 32] {
        let hex = stdout
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .expect("crash worker must report its durable identity before exit");
        assert_eq!(hex.len(), 64);
        let mut value = [0u8; 32];
        for (index, byte) in value.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        value
    }

    let left_root = tempfile::tempdir().unwrap();
    let right_root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "pairing_v2::provisional_tls::tests::task4_crash_matrix_worker",
            "--nocapture",
        ])
        .env("CSF12_TASK4_LEFT_ROOT", left_root.path())
        .env("CSF12_TASK4_RIGHT_ROOT", right_root.path())
        .env("CSF12_TASK4_BOUNDARY", "prepared")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(91));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let left_attempt = parse_marker(&stdout, "TASK4_LEFT_ATTEMPT:");
    let right_attempt = parse_marker(&stdout, "TASK4_RIGHT_ATTEMPT:");
    let left_peer = parse_marker(&stdout, "TASK4_LEFT_PEER:");
    let right_peer = parse_marker(&stdout, "TASK4_RIGHT_PEER:");

    let left =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(left_root.path())
            .unwrap();
    let right =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(right_root.path())
            .unwrap();
    for (store, attempt, peer, retry) in [
        (&left, left_attempt, left_peer, [201; 32]),
        (&right, right_attempt, right_peer, [202; 32]),
    ] {
        assert_eq!(
            store.reconcile(attempt).unwrap(),
            crate::pairing_v2::admission_authority::ReconcileAdmission::Absent,
            "a dead Prepared coordinator must not survive as a pending or revoked admission"
        );
        assert!(!store.test_has_admission_guard(attempt).unwrap());
        assert!(store.operational_admission_snapshot(attempt).is_err());
        store
            .prepare(store.version().unwrap(), retry, peer)
            .expect("stale prepared reservation must not block same-peer retry");
    }
}

#[test]
fn task4_staged_subprocess_crash_reconciles_exactly_before_fresh_same_peer_retry() {
    fn parse_marker(stdout: &str, prefix: &str) -> [u8; 32] {
        let hex = stdout
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .expect("crash worker must report its durable identity before exit");
        assert_eq!(hex.len(), 64);
        let mut value = [0u8; 32];
        for (index, byte) in value.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        value
    }

    let left_root = tempfile::tempdir().unwrap();
    let right_root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "pairing_v2::provisional_tls::tests::task4_crash_matrix_worker",
            "--nocapture",
        ])
        .env("CSF12_TASK4_LEFT_ROOT", left_root.path())
        .env("CSF12_TASK4_RIGHT_ROOT", right_root.path())
        .env("CSF12_TASK4_BOUNDARY", "staged")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(91));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let left_attempt = parse_marker(&stdout, "TASK4_LEFT_ATTEMPT:");
    let right_attempt = parse_marker(&stdout, "TASK4_RIGHT_ATTEMPT:");
    let left_peer = parse_marker(&stdout, "TASK4_LEFT_PEER:");
    let right_peer = parse_marker(&stdout, "TASK4_RIGHT_PEER:");

    let left =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(left_root.path())
            .unwrap();
    let right =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(right_root.path())
            .unwrap();
    for (store, attempt, peer, retry) in [
        (&left, left_attempt, left_peer, [203; 32]),
        (&right, right_attempt, right_peer, [204; 32]),
    ] {
        assert_eq!(
            store.reconcile(attempt).unwrap(),
            crate::pairing_v2::admission_authority::ReconcileAdmission::Absent,
            "a dead Staged coordinator must not survive as a pending or revoked admission"
        );
        assert!(!store.test_has_admission_guard(attempt).unwrap());
        assert!(store.operational_admission_snapshot(attempt).is_err());
        store
            .prepare(store.version().unwrap(), retry, peer)
            .expect("stale staged reservation must not block same-peer retry");
    }
}

#[test]
fn task4_proof_verified_subprocess_crash_reconciles_exactly_before_fresh_same_peer_retry() {
    fn parse_marker(stdout: &str, prefix: &str) -> [u8; 32] {
        let hex = stdout
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .expect("crash worker must report its durable identity before exit");
        assert_eq!(hex.len(), 64);
        let mut value = [0u8; 32];
        for (index, byte) in value.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        value
    }

    let left_root = tempfile::tempdir().unwrap();
    let right_root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "pairing_v2::provisional_tls::tests::task4_crash_matrix_worker",
            "--nocapture",
        ])
        .env("CSF12_TASK4_LEFT_ROOT", left_root.path())
        .env("CSF12_TASK4_RIGHT_ROOT", right_root.path())
        .env("CSF12_TASK4_BOUNDARY", "proof_verified")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(91));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let left_attempt = parse_marker(&stdout, "TASK4_LEFT_ATTEMPT:");
    let right_attempt = parse_marker(&stdout, "TASK4_RIGHT_ATTEMPT:");
    let left_peer = parse_marker(&stdout, "TASK4_LEFT_PEER:");
    let right_peer = parse_marker(&stdout, "TASK4_RIGHT_PEER:");

    let left =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(left_root.path())
            .unwrap();
    let right =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(right_root.path())
            .unwrap();
    for (store, attempt, peer, retry) in [
        (&left, left_attempt, left_peer, [206; 32]),
        (&right, right_attempt, right_peer, [207; 32]),
    ] {
        assert_eq!(
            store.reconcile(attempt).unwrap(),
            crate::pairing_v2::admission_authority::ReconcileAdmission::Absent,
            "a verified in-memory proof must not survive a process crash as durable authority"
        );
        assert!(!store.test_has_admission_guard(attempt).unwrap());
        assert!(store.operational_admission_snapshot(attempt).is_err());
        store
            .prepare(store.version().unwrap(), retry, peer)
            .expect("a stale verified-proof transaction must not block same-peer retry");
    }
}

#[test]
fn task4_frozen_subprocess_crash_reconciles_exactly_before_fresh_same_peer_retry() {
    fn parse_marker(stdout: &str, prefix: &str) -> [u8; 32] {
        let hex = stdout
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .expect("crash worker must report its durable identity before exit");
        assert_eq!(hex.len(), 64);
        let mut value = [0u8; 32];
        for (index, byte) in value.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        value
    }

    let left_root = tempfile::tempdir().unwrap();
    let right_root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "pairing_v2::provisional_tls::tests::task4_crash_matrix_worker",
            "--nocapture",
        ])
        .env("CSF12_TASK4_LEFT_ROOT", left_root.path())
        .env("CSF12_TASK4_RIGHT_ROOT", right_root.path())
        .env("CSF12_TASK4_BOUNDARY", "frozen")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(91));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let left_attempt = parse_marker(&stdout, "TASK4_LEFT_ATTEMPT:");
    let right_attempt = parse_marker(&stdout, "TASK4_RIGHT_ATTEMPT:");
    let left_peer = parse_marker(&stdout, "TASK4_LEFT_PEER:");
    let right_peer = parse_marker(&stdout, "TASK4_RIGHT_PEER:");

    let left =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(left_root.path())
            .unwrap();
    let right =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(right_root.path())
            .unwrap();
    for (store, attempt, peer, retry) in [
        (&left, left_attempt, left_peer, [208; 32]),
        (&right, right_attempt, right_peer, [209; 32]),
    ] {
        assert_eq!(
            store.reconcile(attempt).unwrap(),
            crate::pairing_v2::admission_authority::ReconcileAdmission::Absent,
            "frozen reservations must be removed exactly after a process crash"
        );
        assert!(!store.test_has_admission_guard(attempt).unwrap());
        assert!(store.operational_admission_snapshot(attempt).is_err());
        store
            .prepare(store.version().unwrap(), retry, peer)
            .expect("a frozen transaction from a dead coordinator must not block retry");
    }
}

#[test]
fn task4_ambiguous_staged_sidecar_uses_legacy_fail_closed_recovery() {
    fn parse_marker(stdout: &str, prefix: &str) -> [u8; 32] {
        let hex = stdout
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .expect("crash worker must report its durable identity before exit");
        assert_eq!(hex.len(), 64);
        let mut value = [0u8; 32];
        for (index, byte) in value.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        value
    }
    fn guard_path(root: &std::path::Path, attempt: [u8; 32]) -> std::path::PathBuf {
        let attempt = attempt
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        root.join("pairing-tombstones")
            .join(format!("admission-revocation-{attempt}.json"))
    }

    let left_root = tempfile::tempdir().unwrap();
    let right_root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "pairing_v2::provisional_tls::tests::task4_crash_matrix_worker",
            "--nocapture",
        ])
        .env("CSF12_TASK4_LEFT_ROOT", left_root.path())
        .env("CSF12_TASK4_RIGHT_ROOT", right_root.path())
        .env("CSF12_TASK4_BOUNDARY", "staged")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(91));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let attempt = parse_marker(&stdout, "TASK4_LEFT_ATTEMPT:");
    let peer = parse_marker(&stdout, "TASK4_LEFT_PEER:");

    // A sidecar whose token no longer agrees with the staged receipt is not
    // eligible for the narrow exact-abort path. It must use the conservative
    // legacy resolver and leave the staged receipt ineligible rather than
    // deleting durable state based on an untrusted token.
    let path = guard_path(left_root.path(), attempt);
    let mut guard: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    guard["token"] = serde_json::to_value([255u8; 32]).unwrap();
    std::fs::write(&path, serde_json::to_vec(&guard).unwrap()).unwrap();

    let left =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(left_root.path())
            .unwrap();
    assert_eq!(
        left.reconcile(attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Revoked,
        "ambiguous staged ownership must not be exact-aborted"
    );
    assert!(!left.test_has_admission_guard(attempt).unwrap());
    assert!(left.test_bilateral_receipt(attempt).unwrap().is_some());
    assert!(
        left.prepare(left.version().unwrap(), [205; 32], peer)
            .is_err()
    );
}

#[test]
#[ignore = "subprocess helper"]
fn task4_crash_matrix_worker() {
    let left_root = std::env::var_os("CSF12_TASK4_LEFT_ROOT").unwrap();
    let right_root = std::env::var_os("CSF12_TASK4_RIGHT_ROOT").unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            use crate::pairing_v2::admission_authority::{
                BilateralCommitCheckpoint as Checkpoint, BilateralCommitTestHook as Hook,
            };

            let (_ea, _eb, a, b, _) = pair().await;
            let left_pending = crate::pairing_pending::PendingStore::open(&left_root).unwrap();
            let right_pending = crate::pairing_pending::PendingStore::open(&right_root).unwrap();
            let (a, b) = tokio::join!(
                a.handshake(handshake_config(61, 62), &left_pending, |prompt| async move {
                    prompt.decision(true)
                }),
                b.handshake(handshake_config(62, 61), &right_pending, |prompt| async move {
                    prompt.decision(true)
                })
            );
            let a = a.unwrap();
            let b = b.unwrap();
            let a_attempt = a.test_attempt();
            let b_attempt = b.test_attempt();
            let a_peer = left_pending.pending(a_attempt).unwrap().unwrap().peer_fingerprint;
            let b_peer = right_pending.pending(b_attempt).unwrap().unwrap().peer_fingerprint;
            let checkpoint = match std::env::var("CSF12_TASK4_BOUNDARY")
                .as_deref()
                .unwrap_or("prepared")
            {
                "prepared" => Checkpoint::PreflightComplete,
                "staged" => Checkpoint::RightStaged,
                "proof_verified" => Checkpoint::Task3ProofsVerified,
                "frozen" => Checkpoint::RightFrozen,
                "store_owned_before_release" => Checkpoint::StoreOwnedBeforeRelease,
                "left_finalized" => Checkpoint::LeftFinalized,
                "left_confirmed" => Checkpoint::LeftConfirmed,
                other => panic!("unsupported Task4 crash boundary: {other}"),
            };
            let (hook, pause) = Hook::recording().pause_after(checkpoint);
            tokio::spawn(async move {
                let left = crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(&left_root)
                    .unwrap();
                let right = crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(&right_root)
                    .unwrap();
                let _ = crate::pairing_v2::admission_authority::commit_bilateral_foundation_with_test_hook(
                    &left, a, &right, b, &hook,
                )
                .await;
            });
            pause.wait_until_reached().await;
            let hex = |value: [u8; 32]| value.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
            println!("TASK4_LEFT_ATTEMPT:{}", hex(a_attempt));
            println!("TASK4_RIGHT_ATTEMPT:{}", hex(b_attempt));
            println!("TASK4_LEFT_PEER:{}", hex(a_peer));
            println!("TASK4_RIGHT_PEER:{}", hex(b_peer));
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            std::process::exit(91);
        });
}

fn task4_interrupted_publication_exact_abort(boundary: &str) {
    use crate::pairing_v2::admission_authority::{
        AdmissionAuthorityStore, ReconcileAdmission, recover_bilateral_foundation,
    };
    let left_root = tempfile::tempdir().unwrap();
    let right_root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "pairing_v2::provisional_tls::tests::task4_crash_matrix_worker",
            "--nocapture",
        ])
        .env("CSF12_TASK4_LEFT_ROOT", left_root.path())
        .env("CSF12_TASK4_RIGHT_ROOT", right_root.path())
        .env("CSF12_TASK4_BOUNDARY", boundary)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(91),
        "worker stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let marker = |prefix: &str| -> [u8; 32] {
        let hex = stdout
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap();
        assert_eq!(hex.len(), 64);
        std::array::from_fn(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
    };
    let left = AdmissionAuthorityStore::open(left_root.path()).unwrap();
    let right = AdmissionAuthorityStore::open(right_root.path()).unwrap();
    let left_attempt = marker("TASK4_LEFT_ATTEMPT:");
    let right_attempt = marker("TASK4_RIGHT_ATTEMPT:");
    assert!(left.operational_admission_snapshot(left_attempt).is_err());
    assert!(right.operational_admission_snapshot(right_attempt).is_err());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // The interrupted peer has no fresh authenticated recovery channel. Both
    // immutable transactions must be aborted, including the store-owned pin.
    assert!(
        runtime
            .block_on(recover_bilateral_foundation(
                &left,
                left_attempt,
                &right,
                right_attempt,
                None,
            ))
            .is_err()
    );
    for (store, attempt, peer, retry) in [
        (&left, left_attempt, marker("TASK4_LEFT_PEER:"), [211; 32]),
        (
            &right,
            right_attempt,
            marker("TASK4_RIGHT_PEER:"),
            [212; 32],
        ),
    ] {
        assert_eq!(
            store.reconcile(attempt).unwrap(),
            ReconcileAdmission::Absent
        );
        assert!(!store.test_has_admission_guard(attempt).unwrap());
        assert!(store.operational_admission_snapshot(attempt).is_err());
        store
            .prepare(store.version().unwrap(), retry, peer)
            .unwrap();
    }
}

#[test]
fn task4_store_owned_before_release_crash_exact_aborts_before_same_peer_retry() {
    task4_interrupted_publication_exact_abort("store_owned_before_release");
}

#[test]
fn task4_left_finalized_crash_exact_aborts_before_same_peer_retry() {
    task4_interrupted_publication_exact_abort("left_finalized");
}

#[test]
fn task4_left_confirmed_crash_exact_aborts_before_same_peer_retry() {
    task4_interrupted_publication_exact_abort("left_confirmed");
}

#[tokio::test]
async fn finalization_rejects_cross_transaction_receipt_on_real_endpoints() {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(handshake_config(3, 4), &sa, |prompt| async move {
            prompt.decision(true)
        }),
        b.handshake(handshake_config(4, 3), &sb, |prompt| async move {
            prompt.decision(true)
        })
    );
    let mut a = a.unwrap();
    let mut b = b.unwrap();
    let mut a_receipt = a
        .local_finalization_receipt(b.test_attempt(), [73; 32])
        .unwrap();
    a_receipt.test_replace_transaction_id([74; 32]);
    let b_receipt = b
        .local_finalization_receipt(a.test_attempt(), [75; 32])
        .unwrap();
    let (a_result, b_result) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            a.exchange_local_receipt(a_receipt),
            b.exchange_local_receipt(b_receipt)
        )
    })
    .await
    .expect("cross-transaction rejection must close the peer finalization watcher");
    assert!(a_result.is_err());
    assert!(b_result.is_err());
}

async fn finalization_with_a_fault_is_rejected(fault: FinalizationTestFault) {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(handshake_config(5, 6), &sa, |prompt| async move {
            prompt.decision(true)
        }),
        b.handshake(handshake_config(6, 5), &sb, |prompt| async move {
            prompt.decision(true)
        })
    );
    let mut a = a.unwrap();
    let mut b = b.unwrap();
    let mut a_receipt = a
        .local_finalization_receipt(b.test_attempt(), [76; 32])
        .unwrap();
    let mut b_receipt = b
        .local_finalization_receipt(a.test_attempt(), [77; 32])
        .unwrap();
    match fault {
        FinalizationTestFault::UnknownFrame | FinalizationTestFault::WrongTransactionOnWire => {
            if a.role() == Role::A {
                a_receipt.test_fault(fault);
            } else {
                b_receipt.test_fault(fault);
            }
        }
        FinalizationTestFault::ExtraBi | FinalizationTestFault::ExtraUni => {
            if a.role() == Role::B {
                a_receipt.test_fault(fault);
            } else {
                b_receipt.test_fault(fault);
            }
        }
        FinalizationTestFault::NoBidi
        | FinalizationTestFault::NoBody
        | FinalizationTestFault::StopAfterLocalPublished
        | FinalizationTestFault::StopBeforeFirstAck
        | FinalizationTestFault::StopBeforeAck => {
            unreachable!("stall faults use finalization_stall_is_rejected_at_one_deadline")
        }
    }
    let (a_result, b_result) = tokio::join!(
        a.exchange_local_receipt(a_receipt),
        b.exchange_local_receipt(b_receipt)
    );
    assert!(
        a_result.is_err(),
        "faulting side accepted a second grammar path: a={a_result:?}, b={b_result:?}"
    );
    assert!(
        b_result.is_err(),
        "peer accepted a forbidden finalization path: a={a_result:?}, b={b_result:?}"
    );
}

async fn finalization_stall_is_rejected_at_one_deadline(fault: FinalizationTestFault) {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(handshake_config(9, 10), &sa, |prompt| async move {
            prompt.decision(true)
        }),
        b.handshake(handshake_config(10, 9), &sb, |prompt| async move {
            prompt.decision(true)
        })
    );
    let mut a = a.unwrap();
    let mut b = b.unwrap();
    let mut a_receipt = a
        .local_finalization_receipt(b.test_attempt(), [81; 32])
        .unwrap();
    let mut b_receipt = b
        .local_finalization_receipt(a.test_attempt(), [82; 32])
        .unwrap();
    if matches!(fault, FinalizationTestFault::StopBeforeAck) {
        if a.role() == Role::B {
            a_receipt.test_fault(fault);
        } else {
            b_receipt.test_fault(fault);
        }
    } else if a.role() == Role::A {
        a_receipt.test_fault(fault);
    } else {
        b_receipt.test_fault(fault);
    }
    let (a_result, b_result) = tokio::time::timeout(Duration::from_secs(7), async {
        tokio::join!(
            a.exchange_local_receipt(a_receipt),
            b.exchange_local_receipt(b_receipt)
        )
    })
    .await
    .expect("both finalization endpoints must terminate at the shared deadline");
    assert!(
        a_result.is_err() && b_result.is_err(),
        "no peer proof may survive a stall"
    );
    assert!(!a.is_protocol_valid() && !b.is_protocol_valid());
}

#[tokio::test]
async fn finalization_deadline_rejects_when_b_never_receives_bidi() {
    finalization_stall_is_rejected_at_one_deadline(FinalizationTestFault::NoBidi).await;
}

#[tokio::test]
async fn finalization_deadline_rejects_expected_stream_without_body() {
    finalization_stall_is_rejected_at_one_deadline(FinalizationTestFault::NoBody).await;
}

#[tokio::test]
async fn finalization_deadline_rejects_stop_after_local_published() {
    finalization_stall_is_rejected_at_one_deadline(FinalizationTestFault::StopAfterLocalPublished)
        .await;
}

#[tokio::test]
async fn finalization_deadline_rejects_stop_before_peer_ack() {
    finalization_stall_is_rejected_at_one_deadline(FinalizationTestFault::StopBeforeAck).await;
}

#[tokio::test]
async fn finalization_deadline_rejects_stop_before_first_peer_ack() {
    finalization_stall_is_rejected_at_one_deadline(FinalizationTestFault::StopBeforeFirstAck).await;
}

#[tokio::test]
async fn finalization_rejects_authenticated_wrong_transaction_on_wire() {
    finalization_with_a_fault_is_rejected(FinalizationTestFault::WrongTransactionOnWire).await;
}

#[tokio::test]
async fn finalization_rejects_unknown_frame_after_transition() {
    finalization_with_a_fault_is_rejected(FinalizationTestFault::UnknownFrame).await;
}

#[tokio::test]
async fn finalization_rejects_extra_bidi_stream_after_transition() {
    finalization_with_a_fault_is_rejected(FinalizationTestFault::ExtraBi).await;
}

#[tokio::test]
async fn finalization_rejects_extra_unidirectional_stream_after_transition() {
    finalization_with_a_fault_is_rejected(FinalizationTestFault::ExtraUni).await;
}

#[tokio::test]
async fn finalization_rejects_duplicate_exchange_after_success() {
    let (_ea, _eb, a, b, _) = pair().await;
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(handshake_config(7, 8), &sa, |prompt| async move {
            prompt.decision(true)
        }),
        b.handshake(handshake_config(8, 7), &sb, |prompt| async move {
            prompt.decision(true)
        })
    );
    let mut a = a.unwrap();
    let mut b = b.unwrap();
    let a_receipt = a
        .local_finalization_receipt(b.test_attempt(), [78; 32])
        .unwrap();
    let b_receipt = b
        .local_finalization_receipt(a.test_attempt(), [79; 32])
        .unwrap();
    let (a_result, b_result) = tokio::join!(
        a.exchange_local_receipt(a_receipt),
        b.exchange_local_receipt(b_receipt)
    );
    assert!(a_result.is_ok() && b_result.is_ok());
    let replay = a
        .local_finalization_receipt(b.test_attempt(), [80; 32])
        .unwrap();
    assert!(a.exchange_local_receipt(replay).await.is_err());
}

#[tokio::test]
async fn duplicate_live_attempt_cannot_revoke_existing_promoted_peer() {
    let (a_identity, a_key) = identity(true);
    let a_retry_key = a_key.clone_key();
    let (b_identity, b_key) = identity(true);
    let b_retry_key = b_key.clone_key();
    let ea = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_identity.clone(), a_key)
        .unwrap();
    let eb = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_identity.clone(), b_key)
        .unwrap();
    let (first_a, first_b) = tokio::join!(ea.connect(eb.local_addr().unwrap()), eb.accept());
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (first_a, first_b) = tokio::join!(
        first_a.unwrap().handshake(
            handshake_config(1, 2),
            &sa,
            |p| async move { p.decision(true) }
        ),
        first_b.unwrap().handshake(
            handshake_config(2, 1),
            &sb,
            |p| async move { p.decision(true) }
        )
    );
    let _first_b = first_b.unwrap();
    let store =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    let receipt = store
        .commit_sealed_foundation(store.version().unwrap(), first_a.unwrap())
        .await
        .unwrap();
    assert_eq!(
        store.reconcile(receipt.attempt()).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
    );

    drop(ea);
    drop(eb);
    let retry_a =
        ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_identity, a_retry_key).unwrap();
    let retry_b =
        ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_identity, b_retry_key).unwrap();
    let (second_a, second_b) = tokio::join!(
        retry_a.connect(retry_b.local_addr().unwrap()),
        retry_b.accept()
    );
    let (second_a, second_b) = tokio::join!(
        second_a.unwrap().handshake(
            handshake_config(3, 4),
            &sa,
            |p| async move { p.decision(true) }
        ),
        second_b.unwrap().handshake(
            handshake_config(4, 3),
            &sb,
            |p| async move { p.decision(true) }
        )
    );
    assert!(
        second_a.is_err(),
        "duplicate attempt must be rejected before handoff"
    );
    assert!(
        second_b.is_err(),
        "duplicate attempt must be rejected before handoff"
    );
    drop(retry_a);
    drop(retry_b);

    assert_eq!(
        store.reconcile(receipt.attempt()).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted,
        "a duplicate live attempt must not revoke an already promoted peer"
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
async fn prepared_bilateral_commit_consumes_authority_and_rejects_double_stage() {
    let (_ea, _eb, a, b, _) = pair().await;
    let root = tempfile::tempdir().unwrap();
    let peer_root = tempfile::tempdir().unwrap();
    let pending = crate::pairing_pending::PendingStore::open(root.path()).unwrap();
    let peer_pending = crate::pairing_pending::PendingStore::open(peer_root.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(handshake_config(61, 62), &pending, |prompt| async move {
            prompt.decision(true)
        }),
        b.handshake(
            handshake_config(62, 61),
            &peer_pending,
            |prompt| async move { prompt.decision(true) }
        )
    );
    let peer_attempt = b.as_ref().unwrap().test_attempt();
    let a = a.unwrap();
    let attempt = a.test_attempt();
    let store =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(root.path()).unwrap();

    // `prepare` consumes the completed authority. There is no production
    // split API that leaves a raw authority available for a second reserve.
    let mut prepared =
        crate::pairing_v2::admission_authority::PreparedBilateralCommit::prepare(&store, a)
            .await
            .unwrap();
    prepared.stage_once(peer_attempt).unwrap();
    assert!(
        store
            .test_staged_receipt_uses_prepared_reservation(attempt, &prepared)
            .unwrap(),
        "the staged AwaitingHandoff receipt must be bound to this opaque live reservation"
    );
    assert!(
        prepared.stage_once(peer_attempt).is_err(),
        "the same move-only commit cannot publish a second staged receipt"
    );
    assert!(
        prepared.freeze_once().await.is_err(),
        "freeze is impossible from Staged without a stored authenticated Task 3 proof"
    );
    drop(b.unwrap());
}

#[tokio::test]
async fn endpoint_drop_between_stage_and_task3_exactly_removes_live_reservation_receipt() {
    let (endpoint, _peer_endpoint, a, b, _) = pair().await;
    let root = tempfile::tempdir().unwrap();
    let peer_root = tempfile::tempdir().unwrap();
    let pending = crate::pairing_pending::PendingStore::open(root.path()).unwrap();
    let peer_pending = crate::pairing_pending::PendingStore::open(peer_root.path()).unwrap();
    let (a, b) = tokio::join!(
        a.handshake(handshake_config(63, 64), &pending, |prompt| async move {
            prompt.decision(true)
        }),
        b.handshake(
            handshake_config(64, 63),
            &peer_pending,
            |prompt| async move { prompt.decision(true) }
        )
    );
    let a = a.unwrap();
    let peer_attempt = b.as_ref().unwrap().test_attempt();
    let attempt = a.test_attempt();
    let store =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(root.path()).unwrap();
    let mut prepared =
        crate::pairing_v2::admission_authority::PreparedBilateralCommit::prepare(&store, a)
            .await
            .unwrap();
    prepared.stage_once(peer_attempt).unwrap();

    drop(endpoint);
    assert_eq!(
        store.reconcile(attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Absent,
        "a real endpoint/watcher drop before Task 3 must exact-revoke only its staged receipt"
    );
    assert!(
        prepared.freeze_once().await.is_err(),
        "a dropped live reservation must not be convertible into a finalization handoff"
    );
    drop(b.unwrap());
}

#[tokio::test]
async fn stale_prepared_reservation_cannot_finalize_after_fresh_same_peer_retry() {
    let (client_certificate, client_key) = identity(true);
    let retry_client_key = client_key.clone_key();
    let (server_certificate, server_key) = identity(true);
    let retry_server_key = server_key.clone_key();
    let server = ProvisionalEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        server_certificate.clone(),
        server_key,
    )
    .unwrap();
    let client = ProvisionalEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        client_certificate.clone(),
        client_key,
    )
    .unwrap();
    let (first_client, first_server) = tokio::join!(
        client.connect(server.local_addr().unwrap()),
        server.accept(),
    );
    let root = tempfile::tempdir().unwrap();
    let peer_root = tempfile::tempdir().unwrap();
    let pending = crate::pairing_pending::PendingStore::open(root.path()).unwrap();
    let peer_pending = crate::pairing_pending::PendingStore::open(peer_root.path()).unwrap();
    let (first_client, first_server) = tokio::join!(
        first_client
            .unwrap()
            .handshake(handshake_config(65, 66), &pending, |prompt| async move {
                prompt.decision(true)
            }),
        first_server.unwrap().handshake(
            handshake_config(66, 65),
            &peer_pending,
            |prompt| async move { prompt.decision(true) }
        )
    );
    let first_client = first_client.unwrap();
    let first_peer_attempt = first_server.as_ref().unwrap().test_attempt();
    let stale_attempt = first_client.test_attempt();
    let store =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(root.path()).unwrap();
    let mut stale = crate::pairing_v2::admission_authority::PreparedBilateralCommit::prepare(
        &store,
        first_client,
    )
    .await
    .unwrap();
    stale.stage_once(first_peer_attempt).unwrap();

    drop(client);
    drop(server);
    drop(first_server.unwrap());
    assert_eq!(
        store.reconcile(stale_attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Absent
    );

    let retry_client = ProvisionalEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        client_certificate,
        retry_client_key,
    )
    .unwrap();
    let retry_server = ProvisionalEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        server_certificate,
        retry_server_key,
    )
    .unwrap();
    // This test owns only the client's prepared reservation.  The original
    // unprepared peer pending record is intentionally left to its own normal
    // recovery path, so use a clean peer store for the independent retry.
    let retry_peer_root = tempfile::tempdir().unwrap();
    let retry_peer_pending =
        crate::pairing_pending::PendingStore::open(retry_peer_root.path()).unwrap();
    let (retry_client_channel, retry_server_channel) = tokio::join!(
        retry_client.connect(retry_server.local_addr().unwrap()),
        retry_server.accept(),
    );
    let (retry_client_authority, retry_server_authority) = tokio::join!(
        retry_client_channel.unwrap().handshake(
            handshake_config(67, 68),
            &pending,
            |prompt| async move { prompt.decision(true) },
        ),
        retry_server_channel.unwrap().handshake(
            handshake_config(68, 67),
            &retry_peer_pending,
            |prompt| async move { prompt.decision(true) },
        )
    );
    let retry_client_authority = retry_client_authority.unwrap();
    let retry_peer_attempt = retry_server_authority.as_ref().unwrap().test_attempt();
    let fresh_attempt = retry_client_authority.test_attempt();
    let mut fresh = crate::pairing_v2::admission_authority::PreparedBilateralCommit::prepare(
        &store,
        retry_client_authority,
    )
    .await
    .unwrap();
    fresh.stage_once(retry_peer_attempt).unwrap();
    assert!(
        stale.freeze_once().await.is_err(),
        "a stale prepared reservation cannot reach finalization after the retry owns a fresh exact reservation"
    );
    assert!(
        store
            .test_staged_receipt_uses_prepared_reservation(fresh_attempt, &fresh)
            .unwrap(),
        "the fresh exact retry remains staged; only the real paired coordinator may later exchange proof, freeze, and finalize it"
    );
    drop(retry_server_authority.unwrap());
}

#[tokio::test]
async fn frozen_handoff_transfers_only_the_revocation_guard_not_transport_authority() {
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
    let frozen = a
        .unwrap()
        .seal_for_promotion()
        .await
        .unwrap()
        .freeze(&sa)
        .await
        .unwrap();
    let scope = ea.scope.clone();
    let revoker = frozen.test_claim_handoff().unwrap();
    assert_eq!(
        scope.0.lock().unwrap().phase,
        super::ConsentPhase::TransferredToStore
    );
    drop(ea);
    assert_eq!(
        scope.0.lock().unwrap().phase,
        super::ConsentPhase::TransferredToStore,
        "endpoint cleanup must not reclaim a claimed handoff guard"
    );
    drop(revoker);
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
    // Once the durable store owns the exact revocation guard, endpoint cleanup
    // must only close provisional transport.  Before that transfer, drop still
    // retains its existing cancellation/revocation behavior.
    drop(ea);
    assert_eq!(
        store.reconcile(receipt.attempt()).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
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

/// A cancelled admission can still have a frozen endpoint waiting to be
/// dropped. That endpoint must clean up only its own guard: a later admission
/// for the same peer is a different durable owner and must survive.
#[tokio::test]
async fn stale_endpoint_drop_after_cancel_keeps_replacement_promoted() {
    let (a_identity, a_key) = identity(true);
    let a_retry_key = a_key.clone_key();
    let (b_identity, b_key) = identity(true);
    let b_retry_key = b_key.clone_key();
    let ea = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_identity.clone(), a_key)
        .unwrap();
    let eb = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_identity.clone(), b_key)
        .unwrap();
    let (a, b) = tokio::join!(ea.connect(eb.local_addr().unwrap()), eb.accept());
    let ta = tempfile::tempdir().unwrap();
    let tb = tempfile::tempdir().unwrap();
    let sa = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let sb = crate::pairing_pending::PendingStore::open(tb.path()).unwrap();
    let (a, b) = tokio::join!(
        a.unwrap().handshake(
            handshake_config(1, 2),
            &sa,
            |p| async move { p.decision(true) }
        ),
        b.unwrap().handshake(
            handshake_config(2, 1),
            &sb,
            |p| async move { p.decision(true) }
        )
    );
    let a = a.unwrap();
    let b = b.unwrap();
    let attempt = a.test_attempt();
    let store =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    let cancelled = store.pending(attempt).unwrap().unwrap();
    store
        .cancel(store.version().unwrap(), cancelled.attempt_id)
        .unwrap();
    sb.cancel(sb.version().unwrap(), b.test_attempt()).unwrap();
    drop(b);

    // Freeze after cancellation so the real endpoint owns a stale guard. The
    // stage fails closed, but the endpoint's Drop still exercises the actual
    // consent-scope revocation path rather than calling a revoker directly.
    assert_eq!(
        store
            .commit_sealed_foundation(store.version().unwrap(), a)
            .await,
        Err(crate::pairing_pending::StoreError::Invalid)
    );

    // Re-establish B with fresh endpoints but the same two identities. This
    // creates a real bilateral record and consumes the live sealed authority
    // through the staged/final durable publication path.
    drop(eb);
    let replacement_a =
        ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_identity, a_retry_key).unwrap();
    let replacement_b = ProvisionalEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        b_identity.clone(),
        b_retry_key,
    )
    .unwrap();
    let (replacement_a_channel, replacement_b_channel) = tokio::join!(
        replacement_a.connect(replacement_b.local_addr().unwrap()),
        replacement_b.accept()
    );
    let (replacement_a_authority, replacement_b_authority) = tokio::join!(
        replacement_a_channel
            .unwrap()
            .handshake(
                handshake_config(3, 4),
                &sa,
                |p| async move { p.decision(true) }
            ),
        replacement_b_channel
            .unwrap()
            .handshake(
                handshake_config(4, 3),
                &sb,
                |p| async move { p.decision(true) }
            )
    );
    let replacement_a_authority = replacement_a_authority.unwrap();
    // Keep B's sealed authority alive until A's promotion has frozen ingress
    // and published its durable record. Dropping B first is an intentional
    // peer shutdown, which the fail-closed ingress watcher must reject rather
    // than race with the promotion this test is meant to exercise.
    let replacement_b_authority = replacement_b_authority.unwrap();
    let replacement_attempt = replacement_a_authority.test_attempt();
    let replacement = store
        .commit_sealed_foundation(store.version().unwrap(), replacement_a_authority)
        .await
        .unwrap();
    assert_eq!(replacement.attempt(), replacement_attempt);
    let (_, receipt, active) = sa.admission_state(replacement_attempt).unwrap();
    assert!(active);
    assert_eq!(
        receipt.unwrap().peer_pin,
        <[u8; 32]>::from(Sha256::digest(&b_identity))
    );

    // Only after the replacement has reached durable promotion may either
    // endpoint close. A's old endpoint must not revoke B's exact ownership.
    drop(replacement_b_authority);
    drop(ea);
    assert_eq!(
        store.reconcile(replacement_attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
    );
    let (_, receipt, active) = sa.admission_state(replacement_attempt).unwrap();
    assert!(active);
    assert_eq!(
        receipt.unwrap().peer_pin,
        <[u8; 32]>::from(Sha256::digest(&b_identity))
    );
    drop(replacement_a);
    drop(replacement_b);
}

/// Identity rotation invalidates a staged, live handoff. Endpoint destruction
/// afterwards must only clear its old guard; reopening must not keep either an
/// active admission or an orphaned peer reservation.
#[tokio::test]
async fn rotation_then_endpoint_drop_recovers_staged_guard_without_reservation() {
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
    let sealed = a.seal_for_promotion().await.unwrap();
    let frozen = sealed.freeze(&sa).await.unwrap();
    let (fields, handoff) = frozen.into_store_handoff();
    let record = fields.record.clone();
    let expected = sa.version().unwrap();
    let staged_revision = expected.revision.checked_add(1).unwrap();
    let ownership = handoff.awaiting_handoff_ownership(staged_revision);
    let mut receipt = crate::pairing_pending::AdmissionReceiptRecord {
        attempt: record.attempt_id,
        peer: record.peer_fingerprint,
        peer_pin: fields.certificate_fingerprints[1 - fields.role.index()],
        durable_fc_hash: fields.durable_fc_hash,
        role: fields.role.index() as u8,
        suite: SUITE.to_owned(),
        protocol_version: 2,
        transcript: fields.transcript,
        binding: fields.local_binding,
        revision: staged_revision,
        identity_generation: expected.identity_generation,
        revocation_generation: record.revocation_generation,
        policy_revision: 0,
        bilateral: crate::pairing_pending::BilateralAdmissionRecord::prepared(
            &crate::pairing_pending::BilateralTransactionFields {
                local_identity: fields.certificate_fingerprints[fields.role.index()],
                peer_identity: fields.certificate_fingerprints[1 - fields.role.index()],
                local_attempt: record.attempt_id,
                peer_attempt: record.attempt_id,
                peer_pin: fields.certificate_fingerprints[1 - fields.role.index()],
                transcript: fields.transcript,
                suite: SUITE.to_owned(),
                policy_revision: 0,
            },
            ownership.guard_token(),
            expected.identity_generation,
            record.revocation_generation,
            0,
        ),
        ownership,
    };
    crate::pairing_pending::bind_prepared_bilateral_receipt_hash(&mut receipt);
    sa.stage_sealed_admission(expected, &record, &receipt)
        .unwrap();
    let (pending, staged, active) = sa.admission_state(record.attempt_id).unwrap();
    assert!(!pending);
    assert!(matches!(
        staged.map(|receipt| receipt.ownership),
        Some(crate::pairing_pending::AdmissionOwnership::AwaitingHandoff { .. })
    ));
    assert!(!active);

    sa.rotate_identity(sa.version().unwrap()).unwrap();
    drop(handoff);
    drop(ea);

    let reopened =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    assert_eq!(
        reopened.reconcile(record.attempt_id).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Revoked
    );
    // A fresh attempt proves rotation cleared the staged reservation rather
    // than leaving the old peer blocked after restart/recovery.
    reopened
        .prepare(
            reopened.version().unwrap(),
            [99; 32],
            record.peer_fingerprint,
        )
        .unwrap();
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
    assert_eq!(result, Err(crate::pairing_pending::StoreError::Invalid));
    let reopened =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    assert_eq!(
        reopened.reconcile(attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Revoked
    );
}

#[tokio::test]
async fn endpoint_drop_after_store_handoff_does_not_run_revocation_cleanup() {
    for _ in 0..5 {
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

        drop(ea);
        assert_eq!(
            store.reconcile(attempt).unwrap(),
            crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
        );
    }
}

/// Once the handoff has been claimed, an error before the final manifest
/// rename is uncertain rather than successful. Recovery must revoke the
/// ineligible staged receipt and leave no operational snapshot.
#[tokio::test]
async fn final_manifest_error_after_claim_is_not_operationally_active() {
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
    let sealed = a.unwrap().seal_for_promotion().await.unwrap();
    let frozen = sealed.freeze(&sa).await.unwrap();
    let (fields, handoff) = frozen.into_store_handoff();
    let record = fields.record.clone();
    let expected = sa.version().unwrap();
    let staged_revision = expected.revision.checked_add(1).unwrap();
    let ownership = handoff.awaiting_handoff_ownership(staged_revision);
    let mut receipt = crate::pairing_pending::AdmissionReceiptRecord {
        attempt: record.attempt_id,
        peer: record.peer_fingerprint,
        peer_pin: fields.certificate_fingerprints[1 - fields.role.index()],
        durable_fc_hash: fields.durable_fc_hash,
        role: fields.role.index() as u8,
        suite: SUITE.to_owned(),
        protocol_version: 2,
        transcript: fields.transcript,
        binding: fields.local_binding,
        revision: staged_revision,
        identity_generation: expected.identity_generation,
        revocation_generation: record.revocation_generation,
        policy_revision: 0,
        bilateral: crate::pairing_pending::BilateralAdmissionRecord::prepared(
            &crate::pairing_pending::BilateralTransactionFields {
                local_identity: fields.certificate_fingerprints[fields.role.index()],
                peer_identity: fields.certificate_fingerprints[1 - fields.role.index()],
                local_attempt: record.attempt_id,
                peer_attempt: record.attempt_id,
                peer_pin: fields.certificate_fingerprints[1 - fields.role.index()],
                transcript: fields.transcript,
                suite: SUITE.to_owned(),
                policy_revision: 0,
            },
            ownership.guard_token(),
            expected.identity_generation,
            record.revocation_generation,
            0,
        ),
        ownership,
    };
    crate::pairing_pending::bind_prepared_bilateral_receipt_hash(&mut receipt);
    sa.stage_sealed_admission(expected, &record, &receipt)
        .unwrap();

    unsafe { std::env::set_var("PAIRING_TEST_FS_FAULT", "ledger:before_rename:error") };
    crate::private_fs::faults::arm();
    assert!(matches!(
        sa.finalize_staged_admission(sa.version().unwrap(), record.attempt_id, handoff,),
        Err(crate::pairing_pending::StoreError::Unavailable)
    ));
    unsafe { std::env::remove_var("PAIRING_TEST_FS_FAULT") };

    let store =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    assert_eq!(
        store.reconcile(record.attempt_id).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Revoked
    );
    assert!(
        store
            .operational_admission_snapshot(record.attempt_id)
            .is_err()
    );
    drop(ea);
    drop(b.unwrap());
}

/// Exercise the production wrapper rather than a direct store call. A
/// before-rename error may not be reported as success, and a fresh open must
/// not manufacture an operational admission from the unfinished publication.
#[tokio::test]
async fn commit_wrapper_before_rename_error_reopens_without_operational_snapshot() {
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
    let _b = b.unwrap();
    let attempt = a.test_attempt();
    let store =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();

    unsafe { std::env::set_var("PAIRING_TEST_FS_FAULT", "ledger:before_rename:error") };
    crate::private_fs::faults::arm();
    assert_eq!(
        store
            .commit_sealed_foundation(store.version().unwrap(), a)
            .await,
        Err(crate::pairing_pending::StoreError::Unavailable)
    );
    unsafe { std::env::remove_var("PAIRING_TEST_FS_FAULT") };

    let reopened =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();
    assert_ne!(
        reopened.reconcile(attempt).unwrap(),
        crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
    );
    assert!(reopened.operational_admission_snapshot(attempt).is_err());
}

#[test]
fn final_manifest_crash_after_claim_reconciles_durable_boundary() {
    use std::process::Command;

    for (stage, expected) in [
        (
            "before_rename",
            crate::pairing_v2::admission_authority::ReconcileAdmission::Revoked,
        ),
        (
            "after_rename",
            crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted,
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "pairing_v2::provisional_tls::tests::final_manifest_fault_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("CSF12_FINALIZATION_FAULT_ROOT", root.path())
            .env("PAIRING_TEST_FS_FAULT", format!("ledger:{stage}:crash"))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(91), "{stage}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let attempt_hex = stdout
            .lines()
            .find_map(|line| line.strip_prefix("FINALIZATION_ATTEMPT:"))
            .unwrap_or_else(|| panic!("missing attempt for {stage}: {stdout}"));
        assert_eq!(attempt_hex.len(), 64);
        let mut attempt = [0u8; 32];
        for (index, byte) in attempt.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&attempt_hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        let reopened =
            crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(root.path())
                .unwrap();
        assert_eq!(reopened.reconcile(attempt).unwrap(), expected, "{stage}");
        assert!(
            reopened.operational_admission_snapshot(attempt).is_err(),
            "{stage}"
        );
    }
}

#[cfg(unix)]
#[test]
#[ignore = "subprocess helper"]
fn final_manifest_fault_worker() {
    use std::io::Write;

    let root = std::env::var_os("CSF12_FINALIZATION_FAULT_ROOT").unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            let (ea, _eb, a, b, _) = pair().await;
            let other = tempfile::tempdir().unwrap();
            let sa = crate::pairing_pending::PendingStore::open(root).unwrap();
            let sb = crate::pairing_pending::PendingStore::open(other.path()).unwrap();
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
            let frozen = sealed.freeze(&sa).await.unwrap();
            let (fields, handoff) = frozen.into_store_handoff();
            let record = fields.record.clone();
            let expected = sa.version().unwrap();
            let staged_revision = expected.revision.checked_add(1).unwrap();
            let ownership = handoff.awaiting_handoff_ownership(staged_revision);
            let mut receipt = crate::pairing_pending::AdmissionReceiptRecord {
                attempt: record.attempt_id,
                peer: record.peer_fingerprint,
                peer_pin: fields.certificate_fingerprints[1 - fields.role.index()],
                durable_fc_hash: fields.durable_fc_hash,
                role: fields.role.index() as u8,
                suite: SUITE.to_owned(),
                protocol_version: 2,
                transcript: fields.transcript,
                binding: fields.local_binding,
                revision: staged_revision,
                identity_generation: expected.identity_generation,
                revocation_generation: record.revocation_generation,
                policy_revision: 0,
                bilateral: crate::pairing_pending::BilateralAdmissionRecord::prepared(
                    &crate::pairing_pending::BilateralTransactionFields {
                        local_identity: fields.certificate_fingerprints[fields.role.index()],
                        peer_identity: fields.certificate_fingerprints[1 - fields.role.index()],
                        local_attempt: record.attempt_id,
                        peer_attempt: record.attempt_id,
                        peer_pin: fields.certificate_fingerprints[1 - fields.role.index()],
                        transcript: fields.transcript,
                        suite: SUITE.to_owned(),
                        policy_revision: 0,
                    },
                    ownership.guard_token(),
                    expected.identity_generation,
                    record.revocation_generation,
                    0,
                ),
                ownership,
            };
            crate::pairing_pending::bind_prepared_bilateral_receipt_hash(&mut receipt);
            sa.stage_sealed_admission(expected, &record, &receipt)
                .unwrap();
            writeln!(
                std::io::stdout(),
                "FINALIZATION_ATTEMPT:{}",
                record
                    .attempt_id
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            )
            .unwrap();
            std::io::stdout().flush().unwrap();
            crate::private_fs::faults::arm();
            let result =
                sa.finalize_staged_admission(sa.version().unwrap(), record.attempt_id, handoff);
            assert!(result.is_err(), "fault worker unexpectedly finalized");
            drop(ea);
            drop(b.unwrap());
        });
}

#[tokio::test]
async fn guard_cleanup_failure_returns_no_success_and_reconciles_store_owned_metadata() {
    use std::process::Command;

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
    let _b = b.unwrap();
    let attempt = a.test_attempt();
    let store =
        crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(ta.path()).unwrap();

    unsafe { std::env::set_var("PAIRING_TEST_FS_FAULT", "guard:before_remove:error") };
    crate::private_fs::faults::arm();
    assert_eq!(
        store
            .commit_sealed_foundation(store.version().unwrap(), a)
            .await,
        Err(crate::pairing_pending::StoreError::Unavailable)
    );
    unsafe { std::env::remove_var("PAIRING_TEST_FS_FAULT") };
    // A process that did not witness the failed unlink must still recognize
    // StoreOwned and perform cleanup only, never re-run revocation.
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
        crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
    );
}

#[test]
fn mismatched_guard_sidecar_is_never_removed_by_store_cleanup() {
    let ta = tempfile::tempdir().unwrap();
    let store = crate::pairing_pending::PendingStore::open(ta.path()).unwrap();
    let attempt = [90; 32];
    let mut revoker = store.admission_revoker([89; 32], attempt).unwrap();
    revoker.arm();
    let filename = format!(
        "admission-revocation-{}.json",
        attempt
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let guard_path = ta.path().join("pairing-tombstones").join(filename);
    let mut guard: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&guard_path).unwrap()).unwrap();
    guard["token"] = serde_json::to_value([91u8; 32]).unwrap();
    std::fs::write(&guard_path, serde_json::to_vec(&guard).unwrap()).unwrap();

    assert_eq!(
        revoker.release_to_store(),
        Err(crate::pairing_pending::StoreError::Invalid)
    );
    assert!(guard_path.exists(), "mismatched guard must not be removed");
}

#[tokio::test]
async fn store_owned_guard_reconciles_as_cleanup_in_a_fresh_process() {
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
        crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
    );
    drop(ea);
}

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
        crate::pairing_v2::admission_authority::ReconcileAdmission::Promoted
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
        .with_client_cert_verifier(Arc::new(super::ProfileVerifier {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            expected_peer: None,
        }))
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
            .with_client_cert_verifier(Arc::new(super::ProfileVerifier {
                provider: Arc::new(rustls::crypto::ring::default_provider()),
                expected_peer: None,
            }))
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
