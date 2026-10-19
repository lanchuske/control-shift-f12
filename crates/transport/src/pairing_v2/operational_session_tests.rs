use super::admission_authority::AdmissionAuthorityStore;
use super::operational_session::{
    AttemptGuard, AuthorityView, ExtraStreamMonitor, OperationalEndpoint, OperationalRecord,
    RecordType, Role, derive_and_verify_confirmation_key, validate_confirmation,
    validate_v01_schedule,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Command, Stdio},
    time::Duration,
};

#[test]
fn local_operational_consent_rejects_each_bound_value_mutation() {
    let consent =
        super::operational_session::LocalOperationalConsent::test_only_approved([71; 32], [72; 32]);
    assert!(consent.matches([71; 32], [72; 32]));
    assert!(!consent.matches([70; 32], [72; 32]));
    assert!(!consent.matches([71; 32], [73; 32]));
}

#[test]
fn frozen_v01_records_round_trip_exactly_and_enforce_the_six_record_schedule() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/pairing-v2/operational-session-v01.json"
    ))
    .unwrap();
    let records = fixture["records_hex"].as_array().unwrap();
    assert_eq!(records.len(), 6);

    for (sequence, value) in records.iter().enumerate() {
        let raw = hex(value.as_str().unwrap());
        let record = OperationalRecord::decode(&raw).unwrap();
        assert_eq!(record.sequence(), sequence as u32);
        assert_eq!(record.encode().unwrap(), raw);
        assert_eq!(
            record.expected_type(),
            RecordType::for_sequence(sequence as u32).unwrap()
        );
        assert_eq!(
            record.expected_sender(),
            Role::for_sequence(sequence as u32).unwrap()
        );
    }
}

#[test]
fn record_parser_fails_closed_for_the_frozen_header_and_length_mutants() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/pairing-v2/operational-session-v01.json"
    ))
    .unwrap();
    let valid = hex(fixture["records_hex"][0].as_str().unwrap());
    let mutations = [
        (0, b'X'), // magic substitution
        (9, 2),    // version substitution
        (10, 6),   // unknown/reserved type
        (11, 2),   // direction substitution
        (15, 1),   // sequence substitution
        (19, 0),   // declared length mismatch
    ];
    for (offset, replacement) in mutations {
        let mut changed = valid.clone();
        changed[offset] = replacement;
        assert!(
            OperationalRecord::decode(&changed).is_err(),
            "offset {offset}"
        );
    }
    let mut oversize = valid.clone();
    oversize[16..20].copy_from_slice(&(4097u32).to_be_bytes());
    assert!(OperationalRecord::decode(&oversize).is_err());
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(OperationalRecord::decode(&trailing).is_err());
}

#[test]
fn authority_views_decode_exactly_and_preserve_each_revision_byte() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/pairing-v2/operational-session-v01.json"
    ))
    .unwrap();
    for key in [
        "authority_commitment_a_view_hex",
        "authority_commitment_b_view_hex",
    ] {
        let raw = hex(fixture[key].as_str().unwrap());
        let view = AuthorityView::decode(&raw).unwrap();
        assert_eq!(view.encode().unwrap(), raw);
        assert!(view.is_v01());
    }

    let mut revised = hex(fixture["authority_commitment_a_view_hex"].as_str().unwrap());
    // A changed policy revision is still a syntactically valid *remote* view,
    // but the exact bytes remain available for the later bilateral commitment.
    let position = revised
        .windows(8)
        .position(|window| window == 7u64.to_be_bytes())
        .unwrap();
    revised[position + 7] = 8;
    let view = AuthorityView::decode(&revised).unwrap();
    assert_ne!(view.encode().unwrap(), raw_a(&fixture));
}

#[test]
fn authority_view_keeps_pairing_receipt_v2_distinct_from_wire_v1() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/pairing-v2/operational-session-v01.json"
    ))
    .unwrap();
    let valid = raw_a(&fixture);
    assert!(AuthorityView::decode(&valid).unwrap().is_v01());

    // The V01 authority view's fourth field is pairing receipt protocol 2.
    // Altering it to either the framing version (1) or an unknown version (3)
    // must never be accepted as the V01 durable tuple.
    let marker = [0, 4, 1, 0, 0, 0, 8];
    let offset = valid
        .windows(marker.len())
        .position(|w| w == marker)
        .unwrap();
    for replacement in [1, 3] {
        let mut changed = valid.clone();
        changed[offset + marker.len() + 7] = replacement;
        let parsed = AuthorityView::decode(&changed).unwrap();
        assert!(!parsed.is_v01());
    }
}

#[test]
fn frozen_v01_payloads_form_one_bound_bilateral_schedule() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/pairing-v2/operational-session-v01.json"
    ))
    .unwrap();
    let records = fixture["records_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| OperationalRecord::decode(&hex(value.as_str().unwrap())).unwrap())
        .collect::<Vec<_>>();
    validate_v01_schedule(&records).unwrap();

    let mut replay = records.clone();
    replay[5] = replay[4].clone();
    assert!(validate_v01_schedule(&replay).is_err());

    let mut trailing = records.clone();
    trailing.push(records[5].clone());
    assert!(validate_v01_schedule(&trailing).is_err());
}

#[test]
fn fixture_exporter_derives_the_only_key_that_accepts_both_confirms() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/pairing-v2/operational-session-v01.json"
    ))
    .unwrap();
    let records = fixture["records_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| OperationalRecord::decode(&hex(value.as_str().unwrap())).unwrap())
        .collect::<Vec<_>>();
    let exporter: [u8; 32] = hex(fixture["expected_exporter_output_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let key = derive_and_verify_confirmation_key(&records, exporter).unwrap();
    assert_eq!(
        Sha256::digest(key).as_slice(),
        hex(
            fixture["bilateral_derivation"]["a_confirmation_key_sha256_hex"]
                .as_str()
                .unwrap()
        )
        .as_slice()
    );

    let mut changed_exporter = exporter;
    changed_exporter[0] ^= 1;
    assert!(derive_and_verify_confirmation_key(&records, changed_exporter).is_err());
}

#[test]
fn confirm_a_hmac_mutation_is_rejected_before_confirm_b_can_be_constructed() {
    let key = [17; 32];
    let attempt = [18; 32];
    let session = [19; 16];
    let prior = [20; 32];
    let authentic =
        super::operational_session::confirmation(&key, Role::A, attempt, session, prior).unwrap();
    assert!(validate_confirmation(&key, Role::A, attempt, session, prior, authentic).is_ok());

    let mut altered = authentic;
    altered[0] ^= 1;
    assert!(validate_confirmation(&key, Role::A, attempt, session, prior, altered).is_err());
}

#[tokio::test]
async fn absolute_attempt_deadline_rejects_work_without_a_per_operation_extension() {
    let guard = AttemptGuard::test_only_expired();
    let result = guard.within(async { Ok::<(), super::Invalid>(()) }).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn absolute_attempt_deadline_cancels_a_slow_consent_future() {
    let guard = AttemptGuard::test_only_with_timeout(Duration::from_millis(1));
    let result = guard
        .within(async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok::<(), super::Invalid>(())
        })
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn monitor_rejects_a_stream_opened_after_the_primary_window() {
    let (a_der, a_key) = identity();
    let (b_der, b_key) = identity();
    let a =
        OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_der.clone(), a_key).unwrap();
    let b =
        OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_der.clone(), b_key).unwrap();
    let (a_channel, b_channel) = tokio::join!(
        a.connect(b.local_addr().unwrap(), Sha256::digest(&b_der).into()),
        b.accept(Sha256::digest(&a_der).into())
    );
    let mut monitor = ExtraStreamMonitor::new(a_channel.unwrap().test_only_connection(), Role::A);
    let b_connection = b_channel.unwrap().test_only_connection();
    let (mut late, _late_recv) =
        tokio::time::timeout(Duration::from_secs(1), b_connection.open_bi())
            .await
            .expect("late stream must open")
            .unwrap();
    late.write_all(b"late").await.unwrap();
    late.finish().unwrap();
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    assert!(monitor.assert_clear().is_err());
    drop(late);
    drop(b_connection);
    drop(monitor);
}

#[tokio::test]
async fn raw_peer_hook_is_test_only_and_does_not_escape_the_sealed_runtime() {
    // The helper is compiled only by this crate's test build. Production code
    // cannot name it, and it exposes no runtime/session authority.
    let (a_der, a_key) = identity();
    let (b_der, b_key) = identity();
    let a =
        OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_der.clone(), a_key).unwrap();
    let b =
        OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_der.clone(), b_key).unwrap();
    let (a_channel, b_channel) = tokio::join!(
        a.connect(b.local_addr().unwrap(), Sha256::digest(&b_der).into()),
        b.accept(Sha256::digest(&a_der).into())
    );
    let peer =
        super::operational_session::TestRawPeer::from_authenticated_channel(&b_channel.unwrap());
    drop(a_channel);
    assert_ne!(peer.exporter(b"test", b"context").unwrap(), [0; 32]);
}

#[tokio::test]
async fn v01_uses_a_fresh_mutual_tls_connection_with_the_operational_alpn() {
    let (a_der, a_key) = identity();
    let (b_der, b_key) = identity();
    let a =
        OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_der.clone(), a_key).unwrap();
    let b =
        OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_der.clone(), b_key).unwrap();
    let expected_a: [u8; 32] = Sha256::digest(&a_der).into();
    let expected_b: [u8; 32] = Sha256::digest(&b_der).into();
    let (a_channel, b_channel) = tokio::join!(
        a.connect(b.local_addr().unwrap(), expected_b),
        b.accept(expected_a)
    );
    let a_channel = a_channel.unwrap();
    let b_channel = b_channel.unwrap();
    assert_eq!(
        a_channel.observed_peer_fingerprint(),
        Sha256::digest(&b_der).as_slice()
    );
    assert_eq!(
        b_channel.observed_peer_fingerprint(),
        Sha256::digest(&a_der).as_slice()
    );
    assert_eq!(a_channel.negotiated_alpn(), b"csf12-operational/1");
    assert_eq!(b_channel.negotiated_alpn(), b"csf12-operational/1");
}

#[tokio::test]
async fn v01_exchanges_exactly_six_records_on_one_bidirectional_stream() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/pairing-v2/operational-session-v01.json"
    ))
    .unwrap();
    let records = fixture["records_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| OperationalRecord::decode(&hex(record.as_str().unwrap())).unwrap())
        .collect::<Vec<_>>();
    let (a_der, a_key) = identity();
    let (b_der, b_key) = identity();
    let a =
        OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_der.clone(), a_key).unwrap();
    let b =
        OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_der.clone(), b_key).unwrap();
    let a_pin: [u8; 32] = Sha256::digest(&a_der).into();
    let b_pin: [u8; 32] = Sha256::digest(&b_der).into();
    let (a_channel, b_channel) =
        tokio::join!(a.connect(b.local_addr().unwrap(), b_pin), b.accept(a_pin));
    let a_channel = a_channel.unwrap();
    let b_channel = b_channel.unwrap();
    let (a_result, b_result) = tokio::join!(
        a_channel.exchange_frozen_schedule(Role::A, &records),
        b_channel.exchange_frozen_schedule(Role::B, &records)
    );
    assert!(a_result.is_ok(), "{a_result:?}");
    assert!(b_result.is_ok(), "{b_result:?}");
}

#[tokio::test]
#[ignore = "requires a future authenticated operational-finalization authority"]
async fn v01_dynamic_attempt_uses_live_tls_exporter_and_durable_snapshots() {
    let (a_der, a_key) = identity();
    let (b_der, b_key) = identity();
    let a_pin: [u8; 32] = Sha256::digest(&a_der).into();
    let b_pin: [u8; 32] = Sha256::digest(&b_der).into();
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let a_store = AdmissionAuthorityStore::open(a_root.path()).unwrap();
    let b_store = AdmissionAuthorityStore::open(b_root.path()).unwrap();
    let ar = a_store
        .prepare(a_store.version().unwrap(), [31; 32], [32; 32])
        .unwrap();
    let br = b_store
        .prepare(b_store.version().unwrap(), [33; 32], [34; 32])
        .unwrap();
    a_store.commit_operational_test_receipt(&ar, b_pin).unwrap();
    b_store.commit_operational_test_receipt(&br, a_pin).unwrap();
    let a = OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_der, a_key).unwrap();
    let b = OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_der, b_key).unwrap();
    let (aa, bb) = if a_pin < b_pin {
        tokio::join!(
            a.connect_admitted(b.local_addr().unwrap(), &a_store, ar.attempt_id),
            b.accept_admitted(&b_store, br.attempt_id)
        )
    } else {
        tokio::join!(
            b.connect_admitted(a.local_addr().unwrap(), &b_store, br.attempt_id),
            a.accept_admitted(&a_store, ar.attempt_id)
        )
    };
    assert!(aa.is_ok(), "initiator admission failed");
    assert!(bb.is_ok(), "acceptor admission failed");
    let (ra, rb) = tokio::join!(
        aa.unwrap().complete_with_local_consent(
            |preconfirm, commitment, _remaining_ms| async move {
                Ok(
                    super::operational_session::LocalOperationalConsent::test_only_approved(
                        preconfirm, commitment,
                    ),
                )
            }
        ),
        bb.unwrap().complete_with_local_consent(
            |preconfirm, commitment, _remaining_ms| async move {
                Ok(
                    super::operational_session::LocalOperationalConsent::test_only_approved(
                        preconfirm, commitment,
                    ),
                )
            }
        )
    );
    assert!(ra.is_ok() && rb.is_ok(), "a={ra:?}; b={rb:?}");
}

#[tokio::test]
async fn unconfirmed_bilateral_receipt_cannot_start_an_operational_attempt() {
    let (a_der, a_key) = identity();
    let (b_der, b_key) = identity();
    let a_pin: [u8; 32] = Sha256::digest(&a_der).into();
    let b_pin: [u8; 32] = Sha256::digest(&b_der).into();
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let a_store = AdmissionAuthorityStore::open(a_root.path()).unwrap();
    let b_store = AdmissionAuthorityStore::open(b_root.path()).unwrap();
    let ar = a_store
        .prepare(a_store.version().unwrap(), [41; 32], [42; 32])
        .unwrap();
    let br = b_store
        .prepare(b_store.version().unwrap(), [43; 32], [44; 32])
        .unwrap();
    // Durable bilateral metadata is recovery-only until a later authenticated
    // operational-finalization phase exists. It must fail before opening a
    // transport even when the stored peer pin is deliberately wrong.
    a_store
        .commit_operational_test_receipt(&ar, [99; 32])
        .unwrap();
    b_store.commit_operational_test_receipt(&br, a_pin).unwrap();
    let a = OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_der, a_key).unwrap();
    let b = OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_der, b_key).unwrap();
    let (client, server) = tokio::join!(
        a.connect_admitted(b.local_addr().unwrap(), &a_store, ar.attempt_id),
        b.accept_admitted(&b_store, br.attempt_id)
    );
    assert!(client.is_err());
    assert!(server.is_err());
    assert_ne!(b_pin, [99; 32]);
}

#[tokio::test]
#[ignore = "requires a future authenticated operational-finalization authority"]
async fn corrupted_confirm_a_gets_application_reset_and_never_receives_confirm_b() {
    let (a_der, a_key, a_pin, b_der, b_key, b_pin) = loop {
        let (a_der, a_key) = identity();
        let (b_der, b_key) = identity();
        let a_pin: [u8; 32] = Sha256::digest(&a_der).into();
        let b_pin: [u8; 32] = Sha256::digest(&b_der).into();
        if a_pin < b_pin {
            break (a_der, a_key, a_pin, b_der, b_key, b_pin);
        }
    };
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let a_store = AdmissionAuthorityStore::open(a_root.path()).unwrap();
    let b_store = AdmissionAuthorityStore::open(b_root.path()).unwrap();
    let ar = a_store
        .prepare(a_store.version().unwrap(), [91; 32], [92; 32])
        .unwrap();
    let br = b_store
        .prepare(b_store.version().unwrap(), [93; 32], [94; 32])
        .unwrap();
    a_store.commit_operational_test_receipt(&ar, b_pin).unwrap();
    b_store.commit_operational_test_receipt(&br, a_pin).unwrap();
    let a = OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_der, a_key).unwrap();
    let b = OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_der, b_key).unwrap();
    let (a_attempt, b_attempt) = tokio::join!(
        a.connect_admitted(b.local_addr().unwrap(), &a_store, ar.attempt_id),
        b.accept_admitted(&b_store, br.attempt_id)
    );
    let raw = super::operational_session::TestRawPeer::from_admitted_attempt(a_attempt.unwrap());
    let (raw_result, victim) = tokio::join!(
        raw.send_corrupt_confirm_a(),
        b_attempt.unwrap().complete_with_local_consent(
            |preconfirm, commitment, _remaining_ms| async move {
                Ok(
                    super::operational_session::LocalOperationalConsent::test_only_approved(
                        preconfirm, commitment,
                    ),
                )
            }
        )
    );
    assert!(
        raw_result.is_ok(),
        "raw peer did not observe application reset: {raw_result:?}"
    );
    assert!(victim.is_err());
}

#[tokio::test]
#[ignore = "requires a future authenticated operational-finalization authority"]
async fn bidi_open_after_confirm_fin_is_rejected_by_the_terminal_close_boundary() {
    let (a_der, a_key, a_pin, b_der, b_key, b_pin) = loop {
        let (a_der, a_key) = identity();
        let (b_der, b_key) = identity();
        let a_pin: [u8; 32] = Sha256::digest(&a_der).into();
        let b_pin: [u8; 32] = Sha256::digest(&b_der).into();
        if a_pin < b_pin {
            break (a_der, a_key, a_pin, b_der, b_key, b_pin);
        }
    };
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let a_store = AdmissionAuthorityStore::open(a_root.path()).unwrap();
    let b_store = AdmissionAuthorityStore::open(b_root.path()).unwrap();
    let ar = a_store
        .prepare(a_store.version().unwrap(), [101; 32], [102; 32])
        .unwrap();
    let br = b_store
        .prepare(b_store.version().unwrap(), [103; 32], [104; 32])
        .unwrap();
    a_store.commit_operational_test_receipt(&ar, b_pin).unwrap();
    b_store.commit_operational_test_receipt(&br, a_pin).unwrap();
    let a = OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_der, a_key).unwrap();
    let b = OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_der, b_key).unwrap();
    let (a_attempt, b_attempt) = tokio::join!(
        a.connect_admitted(b.local_addr().unwrap(), &a_store, ar.attempt_id),
        b.accept_admitted(&b_store, br.attempt_id)
    );
    let raw = super::operational_session::TestRawPeer::from_admitted_attempt(a_attempt.unwrap());
    let (raw_result, victim) = tokio::join!(
        raw.send_valid_confirm_a_then_open_late_stream(),
        b_attempt.unwrap().complete_with_local_consent(
            |preconfirm, commitment, _remaining_ms| async move {
                Ok(
                    super::operational_session::LocalOperationalConsent::test_only_approved(
                        preconfirm, commitment,
                    ),
                )
            }
        )
    );
    assert!(
        raw_result.is_ok(),
        "late peer acquired a usable post-FIN stream: {raw_result:?}"
    );
    // Unlike `monitor_rejects_a_stream_opened_after_the_primary_window`, this
    // peer opens after valid Confirm A plus FIN. The accepted attempt has
    // already crossed the explicit close boundary, so its six-record result
    // may be successful, but the attacker cannot create an operational
    // session or obtain a stream after that point.
    assert!(
        victim.is_ok(),
        "clean transcript failed before close boundary: {victim:?}"
    );
}

#[tokio::test]
#[ignore = "requires a future authenticated operational-finalization authority"]
async fn v01_dynamic_attempt_fails_closed_when_revocation_wins_before_promotion() {
    let (a_der, a_key) = identity();
    let (b_der, b_key) = identity();
    let a_pin: [u8; 32] = Sha256::digest(&a_der).into();
    let b_pin: [u8; 32] = Sha256::digest(&b_der).into();
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let a_store = AdmissionAuthorityStore::open(a_root.path()).unwrap();
    let b_store = AdmissionAuthorityStore::open(b_root.path()).unwrap();
    let ar = a_store
        .prepare(a_store.version().unwrap(), [51; 32], [52; 32])
        .unwrap();
    let br = b_store
        .prepare(b_store.version().unwrap(), [53; 32], [54; 32])
        .unwrap();
    a_store.commit_operational_test_receipt(&ar, b_pin).unwrap();
    b_store.commit_operational_test_receipt(&br, a_pin).unwrap();
    let a = OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_der, a_key).unwrap();
    let b = OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_der, b_key).unwrap();
    let (aa, bb) = if a_pin < b_pin {
        tokio::join!(
            a.connect_admitted(b.local_addr().unwrap(), &a_store, ar.attempt_id),
            b.accept_admitted(&b_store, br.attempt_id)
        )
    } else {
        tokio::join!(
            b.connect_admitted(a.local_addr().unwrap(), &b_store, br.attempt_id),
            a.accept_admitted(&a_store, ar.attempt_id)
        )
    };
    let aa = aa.unwrap();
    let bb = bb.unwrap();
    a_store
        .revoke_candidate(a_store.version().unwrap(), ar.peer_fingerprint)
        .unwrap();
    let (ra, rb) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(
            aa.complete_with_local_consent(|preconfirm, commitment, _remaining_ms| async move {
                Ok(
                    super::operational_session::LocalOperationalConsent::test_only_approved(
                        preconfirm, commitment,
                    ),
                )
            }),
            bb.complete_with_local_consent(|preconfirm, commitment, _remaining_ms| async move {
                Ok(
                    super::operational_session::LocalOperationalConsent::test_only_approved(
                        preconfirm, commitment,
                    ),
                )
            })
        )
    })
    .await
    .expect("revocation must close the live attempt without waiting for its deadline");
    assert!(ra.is_err() || rb.is_err());
}

#[tokio::test]
#[ignore = "requires a future authenticated operational-finalization authority"]
async fn v01_revocation_between_accept_and_confirm_emits_no_confirm() {
    let (a_der, a_key) = identity();
    let (b_der, b_key) = identity();
    let a_pin: [u8; 32] = Sha256::digest(&a_der).into();
    let b_pin: [u8; 32] = Sha256::digest(&b_der).into();
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let a_store = AdmissionAuthorityStore::open(a_root.path()).unwrap();
    let b_store = AdmissionAuthorityStore::open(b_root.path()).unwrap();
    let ar = a_store
        .prepare(a_store.version().unwrap(), [81; 32], [82; 32])
        .unwrap();
    let br = b_store
        .prepare(b_store.version().unwrap(), [83; 32], [84; 32])
        .unwrap();
    a_store.commit_operational_test_receipt(&ar, b_pin).unwrap();
    b_store.commit_operational_test_receipt(&br, a_pin).unwrap();
    let a = OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_der, a_key).unwrap();
    let b = OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_der, b_key).unwrap();
    let (aa, bb) = if a_pin < b_pin {
        tokio::join!(
            a.connect_admitted(b.local_addr().unwrap(), &a_store, ar.attempt_id),
            b.accept_admitted(&b_store, br.attempt_id)
        )
    } else {
        tokio::join!(
            b.connect_admitted(a.local_addr().unwrap(), &b_store, br.attempt_id),
            a.accept_admitted(&a_store, ar.attempt_id)
        )
    };
    let aa = aa.unwrap();
    let bb = bb.unwrap();
    let (first, second) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            aa.complete_with_local_consent(|preconfirm, commitment, _remaining_ms| async move {
                a_store
                    .revoke_candidate(a_store.version().unwrap(), ar.peer_fingerprint)
                    .unwrap();
                Ok(
                    super::operational_session::LocalOperationalConsent::test_only_approved(
                        preconfirm, commitment,
                    ),
                )
            }),
            bb.complete_with_local_consent(|preconfirm, commitment, _remaining_ms| async move {
                Ok(
                    super::operational_session::LocalOperationalConsent::test_only_approved(
                        preconfirm, commitment,
                    ),
                )
            })
        )
    })
    .await
    .unwrap();
    assert!(first.is_err() || second.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a future authenticated operational-finalization authority"]
async fn v01_dynamic_attempt_succeeds_between_two_os_processes() {
    let (a_der, a_key) = identity_raw();
    let a_pin: [u8; 32] = Sha256::digest(&a_der).into();
    let (b_der, b_key, b_pin) = loop {
        let (der, key) = identity_raw();
        let pin: [u8; 32] = Sha256::digest(&der).into();
        if a_pin < pin {
            break (der, key, pin);
        }
    };
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "pairing_v2::operational_session_tests::operational_dynamic_process_worker",
            "--nocapture",
        ])
        .env("CSF12_OPERATIONAL_WORKER", "1")
        .env("CSF12_OPERATIONAL_CERT", hex_encode(&b_der))
        .env("CSF12_OPERATIONAL_KEY", hex_encode(&b_key))
        .env("CSF12_OPERATIONAL_PEER_PIN", hex_encode(&a_pin))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let address = loop {
        let mut line = String::new();
        assert!(
            reader.read_line(&mut line).unwrap() != 0,
            "worker exited before ready"
        );
        if let Some(address) = line.trim().strip_prefix("OPERATIONAL_ADDR=") {
            break address.parse().unwrap();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "worker did not report an endpoint"
        );
    };

    let root = tempfile::tempdir().unwrap();
    let store = AdmissionAuthorityStore::open(root.path()).unwrap();
    let record = store
        .prepare(store.version().unwrap(), [61; 32], [62; 32])
        .unwrap();
    store
        .commit_operational_test_receipt(&record, b_pin)
        .unwrap();
    let parent = OperationalEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        a_der,
        PrivatePkcs8KeyDer::from(a_key).into(),
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        parent
            .connect_admitted(address, &store, record.attempt_id)
            .await?
            .complete_with_local_consent(|preconfirm, commitment, _remaining_ms| async move {
                Ok(
                    super::operational_session::LocalOperationalConsent::test_only_approved(
                        preconfirm, commitment,
                    ),
                )
            })
            .await
    })
    .await
    .expect("two-process operational attempt timed out")
    .unwrap();

    let status = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let mut remaining = String::new();
    reader.read_to_string(&mut remaining).unwrap();
    assert!(remaining.contains("OPERATIONAL_PASS"), "{remaining}");
}

#[test]
#[ignore = "subprocess helper"]
fn operational_dynamic_process_worker() {
    if std::env::var_os("CSF12_OPERATIONAL_WORKER").is_none() {
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let der = hex_decode(&std::env::var("CSF12_OPERATIONAL_CERT").unwrap());
            let key = hex_decode(&std::env::var("CSF12_OPERATIONAL_KEY").unwrap());
            let peer_pin: [u8; 32] =
                hex_decode(&std::env::var("CSF12_OPERATIONAL_PEER_PIN").unwrap())
                    .try_into()
                    .unwrap();
            let root = tempfile::tempdir().unwrap();
            let store = AdmissionAuthorityStore::open(root.path()).unwrap();
            let record = store
                .prepare(store.version().unwrap(), [63; 32], [64; 32])
                .unwrap();
            store
                .commit_operational_test_receipt(&record, peer_pin)
                .unwrap();
            let endpoint = OperationalEndpoint::bind(
                "127.0.0.1:0".parse().unwrap(),
                der,
                PrivatePkcs8KeyDer::from(key).into(),
            )
            .unwrap();
            println!("OPERATIONAL_ADDR={}", endpoint.local_addr().unwrap());
            std::io::stdout().flush().unwrap();
            endpoint
                .accept_admitted(&store, record.attempt_id)
                .await
                .unwrap()
                .complete_with_local_consent(|preconfirm, commitment, _remaining_ms| async move {
                    Ok(
                        super::operational_session::LocalOperationalConsent::test_only_approved(
                            preconfirm, commitment,
                        ),
                    )
                })
                .await
                .unwrap();
            println!("OPERATIONAL_PASS");
        });
}

#[tokio::test]
async fn v01_rejects_a_live_tls_peer_that_does_not_match_the_admitted_pin() {
    let (a_der, a_key) = identity();
    let (b_der, b_key) = identity();
    let a =
        OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_der.clone(), a_key).unwrap();
    let b = OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_der, b_key).unwrap();
    let (a_result, b_result) = tokio::join!(
        a.connect(b.local_addr().unwrap(), [9; 32]),
        b.accept(Sha256::digest(&a_der).into())
    );
    assert!(a_result.is_err());
    drop(b_result);
}

fn identity() -> (Vec<u8>, rustls::pki_types::PrivateKeyDer<'static>) {
    let (certificate, key) = identity_raw();
    (certificate, PrivatePkcs8KeyDer::from(key).into())
}

fn identity_raw() -> (Vec<u8>, Vec<u8>) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.subject_alt_names = vec![rcgen::SanType::URI(
        "urn:control-shift-f12:identity".try_into().unwrap(),
    )];
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    (
        params.self_signed(&key).unwrap().der().to_vec(),
        key.serialize_der(),
    )
}

fn hex_encode(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn raw_a(fixture: &serde_json::Value) -> Vec<u8> {
    hex(fixture["authority_commitment_a_view_hex"].as_str().unwrap())
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}
