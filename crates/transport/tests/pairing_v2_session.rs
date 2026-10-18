#![cfg(feature = "pairing-v2-experimental")]
use seamless_transport::pairing_v2::codec::{Value, decode, encode};
use seamless_transport::pairing_v2::{Role, SessionMessage, SignedEvidence};

#[test]
fn reviewed_e2e_both_roles_derive_sas_and_require_current_local_and_peer_approval() {
    let v = fixture();
    for local in [Role::A, Role::B] {
        let mut s = session(&v, local);
        through_proofs(&mut s, &v);
        let expected: Vec<_> = v["sas_words"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap().to_string())
            .collect();
        assert_eq!(s.verification_words(3).unwrap().as_slice(), expected);
        let remote = if local == Role::A { Role::B } else { Role::A };
        s.receive(approval(&v, remote), 4).unwrap();
        assert!(s.both_approved(4).is_none());
        s.confirm(
            bytes(&v, "attempt_id_hex").try_into().unwrap(),
            bytes(&v, "transcript_hex").try_into().unwrap(),
            7,
            true,
            4,
        )
        .unwrap();
        s.receive(approval(&v, local), 5).unwrap();
        assert_eq!(s.both_approved(5).unwrap().as_slice(), bytes(&v, "p_hex"));
    }
}

#[test]
fn reveal_before_both_commitments_and_stale_ui_abort_without_resumption() {
    let v = fixture();
    let mut s = session(&v, Role::A);
    s.receive(
        SessionMessage::Commit(Role::A, bytes(&v, "commit_a_hex")),
        1,
    )
    .unwrap();
    assert!(
        s.receive(
            SessionMessage::Reveal(Role::A, bytes(&v, "reveal_a_hex")),
            2
        )
        .is_err()
    );
    assert!(
        s.receive(
            SessionMessage::Commit(Role::B, bytes(&v, "commit_b_hex")),
            3
        )
        .is_err()
    );
    for invalid in 0..4 {
        let mut s = session(&v, Role::A);
        through_proofs(&mut s, &v);
        let mut attempt: [u8; 32] = bytes(&v, "attempt_id_hex").try_into().unwrap();
        let mut transcript: [u8; 32] = bytes(&v, "transcript_hex").try_into().unwrap();
        if invalid == 0 {
            attempt[0] ^= 1;
        }
        if invalid == 1 {
            transcript[0] ^= 1;
        }
        assert!(
            s.confirm(
                attempt,
                transcript,
                if invalid == 2 { 8 } else { 7 },
                invalid != 3,
                4
            )
            .is_err()
        );
        assert!(s.verification_words(3).is_none());
        assert!(s.receive(approval(&v, Role::A), 5).is_err());
    }
}

#[test]
fn one_sided_local_signed_record_is_not_a_local_ui_gesture() {
    let v = fixture();
    let mut s = session(&v, Role::A);
    through_proofs(&mut s, &v);
    assert!(s.receive(approval(&v, Role::A), 4).is_err());
    assert!(s.both_approved(5).is_none());
}

#[cfg(unix)]
#[test]
fn each_role_requires_own_durable_boundary_before_complete_and_remains_quarantined() {
    use seamless_transport::{
        pairing_pending::PendingStore,
        pairing_v2::{FinalizationAction, JournalClock},
    };
    let v = fixture();
    for local in [Role::A, Role::B] {
        let mut s = session(&v, local);
        through_proofs(&mut s, &v);
        s.confirm(
            bytes(&v, "attempt_id_hex").try_into().unwrap(),
            bytes(&v, "transcript_hex").try_into().unwrap(),
            7,
            true,
            4,
        )
        .unwrap();
        for role in [Role::A, Role::B] {
            s.receive(approval(&v, role), 5).unwrap();
        }
        let temp = tempfile::tempdir().unwrap();
        let store = PendingStore::open(temp.path()).unwrap();
        let attempt = bytes(&v, "attempt_id_hex").try_into().unwrap();
        let peer = bytes(
            &v,
            if local == Role::A {
                "role_b_full_fingerprint_hex"
            } else {
                "role_a_full_fingerprint_hex"
            },
        )
        .try_into()
        .unwrap();
        let pending = store
            .prepare(store.version().unwrap(), attempt, peer)
            .unwrap();
        let clock = JournalClock {
            boot: [1; 16],
            monotonic_ms: 6,
            utc_seconds: 1_893_456_000,
        };
        let mut finalizer = s.begin_finalization(pending, clock).unwrap();
        for message in v["finalization"].as_array().unwrap() {
            let role = if message["role"] == "A" {
                Role::A
            } else {
                Role::B
            };
            let phase = message["phase"].as_str().unwrap();
            let action = finalizer
                .receive(
                    phase,
                    role,
                    SignedEvidence {
                        body: bytes(message, "body"),
                        signature: bytes(message, "signature"),
                    },
                    &bytes(message, "tag"),
                    clock,
                )
                .unwrap();
            let must_persist = phase == "complete"
                || (phase == "commit" && local == Role::A)
                || (phase == "commit_ack" && local == Role::B);
            assert_eq!(action == FinalizationAction::NeedsDurability, must_persist);
            assert!(finalizer.durable_fc_hash().is_none());
            if must_persist {
                finalizer
                    .persist(&store, store.version().unwrap(), clock)
                    .unwrap();
            }
        }
        assert_eq!(
            finalizer.durable_fc_hash().unwrap().as_slice(),
            bytes(&v, "finalization_certificate_hash_hex")
        );
        assert!(store.promote(attempt).is_err());
        assert!(store.pending(attempt).unwrap().is_some());
    }
}

#[cfg(unix)]
#[test]
fn restart_discards_precommit_and_recovers_only_own_committed_role_with_bounded_retention() {
    use seamless_transport::{
        pairing_pending::PendingStore,
        pairing_v2::{JournalClock, ReconcileOutcome},
    };
    for local in [Role::A, Role::B] {
        for cut in 0..5 {
            let (temp, store, attempt) = stored_until(local, cut);
            drop(store);
            let store = PendingStore::open(temp.path()).unwrap();
            let outcome = store
                .reconcile_pairing(
                    attempt,
                    Some(JournalClock {
                        boot: [2; 16],
                        monotonic_ms: 0,
                        utc_seconds: 1_893_456_010,
                    }),
                )
                .unwrap();
            let committed = cut >= if local == Role::A { 2 } else { 3 };
            match outcome {
                ReconcileOutcome::Discarded => {
                    assert!(!committed);
                    assert!(store.pending(attempt).unwrap().is_none());
                }
                ReconcileOutcome::RecoveryOnly(recovery) => {
                    assert!(committed);
                    assert_eq!(recovery.local_role(), local);
                    assert_eq!(recovery.durable_fc_hash().unwrap().is_some(), cut == 4);
                }
            }
            assert!(store.promote(attempt).is_err());
        }
        for clock in [
            None,
            Some(JournalClock {
                boot: [2; 16],
                monotonic_ms: 0,
                utc_seconds: 1_893_456_000 + 86_400,
            }),
            Some(JournalClock {
                boot: [2; 16],
                monotonic_ms: 0,
                utc_seconds: 1_893_455_999,
            }),
            Some(JournalClock {
                boot: [1; 16],
                monotonic_ms: 5,
                utc_seconds: 1_893_456_001,
            }),
        ] {
            let (_temp, store, attempt) = stored_until(local, if local == Role::A { 2 } else { 3 });
            assert!(matches!(
                store.reconcile_pairing(attempt, clock).unwrap(),
                ReconcileOutcome::Discarded
            ));
            assert!(store.pending(attempt).unwrap().is_none());
            assert!(
                store
                    .prepare(store.version().unwrap(), attempt, [9; 32])
                    .is_err()
            );
        }
    }
}

#[test]
fn reviewed_e2e_candidates_bind_exact_hello_fields_and_reject_v01_placeholders() {
    let v = fixture();
    for role in ["a", "b"] {
        let hello = bytes(&v, &format!("hello_{role}_hex"));
        bound(&v, role, &hello).unwrap();
        let fields = decode("hello", &hello, &[1, 2, 2, 2, 2, 2, 2, 3, 2, 3, 3, 2, 3, 1]).unwrap();
        for index in [0, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] {
            let mut changed = fields.clone();
            match &mut changed[index] {
                Value::Number(n) => *n += 1,
                Value::Text(s) => s.push('!'),
                Value::Bytes(b) => b[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(
                bound(&v, role, &encode("hello", &changed).unwrap()).is_err(),
                "binding/{role}/{index}"
            );
        }
        let mut placeholder = fields.clone();
        placeholder[4] = Value::Bytes(vec![0x40; 32]);
        assert!(bound(&v, role, &encode("hello", &placeholder).unwrap()).is_err());
    }
}

#[path = "support/pairing_v2.rs"]
mod common;
use common::*;

#[cfg(unix)]
#[test]
fn restart_completes_only_exact_remaining_signed_role_evidence_without_recreating_approval() {
    use seamless_transport::pairing_v2::{JournalClock, ReconcileOutcome};
    let v = fixture();
    for local in [Role::A, Role::B] {
        let (_temp, store, attempt) = stored_until(local, if local == Role::A { 2 } else { 3 });
        let clock = JournalClock {
            boot: [2; 16],
            monotonic_ms: 1,
            utc_seconds: 1_893_456_001,
        };
        let ReconcileOutcome::RecoveryOnly(mut recovery) =
            store.reconcile_pairing(attempt, Some(clock)).unwrap()
        else {
            panic!()
        };
        let remaining: Vec<_> = v["finalization"]
            .as_array()
            .unwrap()
            .iter()
            .skip(if local == Role::A { 3 } else { 4 })
            .map(|m| SignedEvidence {
                body: bytes(m, "body"),
                signature: bytes(m, "signature"),
            })
            .collect();
        let hash = recovery
            .complete_signed(&store, store.version().unwrap(), remaining.clone(), clock)
            .unwrap();
        assert_eq!(
            hash.as_slice(),
            bytes(&v, "finalization_certificate_hash_hex")
        );
        assert!(
            recovery
                .complete_signed(&store, store.version().unwrap(), remaining, clock)
                .is_err()
        );
        assert!(store.promote(attempt).is_err());
    }
}

#[cfg(unix)]
#[test]
fn expiry_between_commit_verification_and_write_never_creates_durable_commit() {
    use seamless_transport::{pairing_pending::PendingStore, pairing_v2::JournalClock};
    let v = fixture();
    let mut s = session(&v, Role::A);
    through_proofs(&mut s, &v);
    let attempt = bytes(&v, "attempt_id_hex").try_into().unwrap();
    s.confirm(
        attempt,
        bytes(&v, "transcript_hex").try_into().unwrap(),
        7,
        true,
        4,
    )
    .unwrap();
    for role in [Role::A, Role::B] {
        s.receive(approval(&v, role), 5).unwrap();
    }
    let temp = tempfile::tempdir().unwrap();
    let store = PendingStore::open(temp.path()).unwrap();
    let pending = store
        .prepare(
            store.version().unwrap(),
            attempt,
            bytes(&v, "role_b_full_fingerprint_hex").try_into().unwrap(),
        )
        .unwrap();
    let clock = JournalClock {
        boot: [1; 16],
        monotonic_ms: 6,
        utc_seconds: 1_893_456_000,
    };
    let mut f = s.begin_finalization(pending, clock).unwrap();
    for message in v["finalization"].as_array().unwrap().iter().take(3) {
        let role = if message["role"] == "A" {
            Role::A
        } else {
            Role::B
        };
        f.receive(
            message["phase"].as_str().unwrap(),
            role,
            SignedEvidence {
                body: bytes(message, "body"),
                signature: bytes(message, "signature"),
            },
            &bytes(message, "tag"),
            clock,
        )
        .unwrap();
    }
    let before = store.version().unwrap();
    assert!(
        f.persist(
            &store,
            before,
            JournalClock {
                monotonic_ms: 300_000,
                utc_seconds: 1_893_456_300,
                ..clock
            }
        )
        .is_err()
    );
    assert_eq!(store.version().unwrap(), before);
    assert!(f.durable_fc_hash().is_none());
}
#[cfg(unix)]
#[test]
fn terminal_tombstones_remove_referenced_journals_only_after_manifest_commit() {
    for operation in 0..3 {
        let (temp, store, attempt) = stored_until(Role::A, 4);
        let record = store.pending(attempt).unwrap().unwrap();
        match operation {
            0 => store.cancel(store.version().unwrap(), attempt).unwrap(),
            1 => store
                .revoke_candidate(store.version().unwrap(), record.peer_fingerprint)
                .unwrap(),
            _ => store.rotate_identity(store.version().unwrap()).unwrap(),
        }
        assert!(store.pending(attempt).unwrap().is_none());
        assert!(
            store
                .prepare(store.version().unwrap(), attempt, record.peer_fingerprint)
                .is_err()
        );
        let names: Vec<_> = std::fs::read_dir(temp.path().join("pairing-pending"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !names.iter().any(|n| n.starts_with("journal-")),
            "{names:?}"
        );
    }
}
#[test]
fn cancellation_is_terminal_and_duplicates_cannot_extend_network_or_human_deadlines() {
    let v = fixture();
    let mut s = session(&v, Role::A);
    commitments(&mut s, &v);
    s.receive(
        SessionMessage::Commit(Role::A, bytes(&v, "commit_a_hex")),
        29_999,
    )
    .unwrap();
    assert!(
        s.receive(
            SessionMessage::Commit(Role::A, bytes(&v, "commit_a_hex")),
            30_001
        )
        .is_err()
    );
    assert!(s.verification_words(30_002).is_none());
    let mut s = session(&v, Role::A);
    through_proofs(&mut s, &v);
    assert!(s.verification_words(299_999).is_some());
    assert!(s.verification_words(300_000).is_none());
    let mut s = session(&v, Role::A);
    through_proofs(&mut s, &v);
    s.cancel();
    assert!(s.verification_words(4).is_none());
    assert!(s.receive(approval(&v, Role::B), 5).is_err());
}

#[test]
fn changed_commit_reveal_proof_or_approval_aborts_permanently() {
    let v = fixture();
    for failure in 0..6 {
        let mut s = session(&v, Role::A);
        let message = match failure {
            0 => {
                commitments(&mut s, &v);
                let mut b = bytes(&v, "commit_a_hex");
                *b.last_mut().unwrap() ^= 1;
                SessionMessage::Commit(Role::A, b)
            }
            1 => {
                commitments(&mut s, &v);
                let mut b = bytes(&v, "reveal_b_hex");
                *b.last_mut().unwrap() ^= 1;
                SessionMessage::Reveal(Role::B, b)
            }
            2 => {
                commitments(&mut s, &v);
                SessionMessage::KeyProof(
                    Role::A,
                    bytes(&v, "proof_signature_a_hex"),
                    bytes(&v, "proof_tag_a_hex"),
                )
            }
            3 => {
                through_proofs(&mut s, &v);
                let mut b = bytes(&v, "proof_tag_b_hex");
                b[0] ^= 1;
                SessionMessage::KeyProof(Role::B, bytes(&v, "proof_signature_b_hex"), b)
            }
            4 => {
                through_proofs(&mut s, &v);
                let mut b = bytes(&v, "approve_b_signature_hex");
                b[0] ^= 1;
                SessionMessage::Approval(
                    Role::B,
                    SignedEvidence {
                        body: bytes(&v, "approve_b_body_hex"),
                        signature: b,
                    },
                    bytes(&v, "approve_b_tag_hex"),
                )
            }
            _ => {
                through_proofs(&mut s, &v);
                SessionMessage::Approval(
                    Role::A,
                    SignedEvidence {
                        body: bytes(&v, "approve_b_body_hex"),
                        signature: bytes(&v, "approve_b_signature_hex"),
                    },
                    bytes(&v, "approve_b_tag_hex"),
                )
            }
        };
        assert!(s.receive(message, 4).is_err(), "failure/{failure}");
        assert!(s.verification_words(5).is_none());
        assert!(s.both_approved(5).is_none());
    }
}

#[test]
fn simultaneous_initiation_requires_lower_full_fingerprint_connection_and_distinct_identities() {
    use seamless_transport::pairing_v2::SasSession;
    let v = fixture();
    for failure in 0..3 {
        let a = bound(&v, "a", &bytes(&v, "hello_a_hex")).unwrap();
        let b = bound(
            &v,
            if failure == 0 { "a" } else { "b" },
            &bytes(
                &v,
                if failure == 0 {
                    "hello_a_hex"
                } else {
                    "hello_b_hex"
                },
            ),
        )
        .unwrap();
        let local = if failure == 2 {
            [0; 32]
        } else {
            *a.fingerprint()
        };
        let initiator = if failure == 1 {
            *b.fingerprint()
        } else {
            *a.fingerprint()
        };
        assert!(
            SasSession::new(
                [a, b],
                local,
                initiator,
                zeroize::Zeroizing::new([0x70; 32]),
                7,
                0
            )
            .is_err()
        );
    }
}

#[cfg(unix)]
#[test]
fn corrupt_journal_a_blocks_every_operation_on_unrelated_b_without_advancement_or_cleanup() {
    use seamless_transport::pairing_pending::PendingStore;
    for operation in 0..7 {
        let (temp, store, _) = stored_until(Role::A, 4);
        let b = store
            .prepare(store.version().unwrap(), [8; 32], [9; 32])
            .unwrap();
        let version = store.version().unwrap();
        let ledger = temp.path().join("pairing-tombstones/ledger.json");
        let before = std::fs::read(&ledger).unwrap();
        let file = std::fs::read_dir(temp.path().join("pairing-pending"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("journal-")
            })
            .unwrap();
        std::fs::write(&file, b"corrupt").unwrap();
        let rejected = match operation {
            0 => PendingStore::open(temp.path()).is_err(),
            1 => store.pending(b.attempt_id).is_err(),
            2 => store.prepare(version, [10; 32], [11; 32]).is_err(),
            3 => store.cancel(version, b.attempt_id).is_err(),
            4 => store.revoke_candidate(version, b.peer_fingerprint).is_err(),
            5 => store.rotate_identity(version).is_err(),
            _ => store.reconcile_pairing(b.attempt_id, None).is_err(),
        };
        assert!(rejected, "operation/{operation}");
        assert_eq!(std::fs::read(ledger).unwrap(), before);
        assert_eq!(std::fs::read(file).unwrap(), b"corrupt");
    }
}
#[test]
fn reviewed_e2e_recovery_both_roles_are_byte_exact_role_bound_and_one_use() {
    use seamless_transport::pairing_v2::{
        RecoveryFields, RecoveryReplayRegistry, RecoverySignatureVerifier, validate_identity,
    };
    let v = fixture();
    let registry = std::sync::Arc::new(RecoveryReplayRegistry::default());
    for (role, label, suffix) in [(Role::A, "A", "a"), (Role::B, "B", "b")] {
        let proof = &v["recovery_proofs"][label];
        let expected = RecoveryFields {
            attempt_id: bytes(proof, "attempt_id_hex").try_into().unwrap(),
            fc_hash: bytes(proof, "fc_hash_hex").try_into().unwrap(),
            role,
            challenger_nonce: bytes(proof, "challenger_nonce_hex"),
            responder_nonce: bytes(proof, "responder_nonce_hex"),
            tls_exporter: bytes(proof, "exporter_hex"),
            identity_generation: proof["identity_generation"].as_u64().unwrap(),
            revocation_generation: proof["revocation_generation"].as_u64().unwrap(),
        };
        let body = bytes(proof, "body_hex");
        assert_eq!(expected.encode().unwrap(), body);
        let fields = decode(
            "hello",
            &bytes(&v, &format!("hello_{suffix}_hex")),
            &[1, 2, 2, 2, 2, 2, 2, 3, 2, 3, 3, 2, 3, 1],
        )
        .unwrap();
        let Value::Bytes(cert) = &fields[8] else {
            panic!()
        };
        let fp = bytes(&v, &format!("role_{suffix}_full_fingerprint_hex"));
        let identity =
            validate_identity(cert, fp[..16].try_into().unwrap(), 1_893_456_000).unwrap();
        let sig = bytes(proof, "signature_hex");
        let mut wrong = expected.clone();
        wrong.role = if role == Role::A { Role::B } else { Role::A };
        assert!(
            RecoverySignatureVerifier::new(wrong, 30_000, registry.clone())
                .verify(identity.public_key(), &sig, 1, false)
                .is_err()
        );
        RecoverySignatureVerifier::new(expected.clone(), 30_000, registry.clone())
            .verify(identity.public_key(), &sig, 1, false)
            .unwrap();
        assert!(
            RecoverySignatureVerifier::new(expected, 30_000, registry.clone())
                .verify(identity.public_key(), &sig, 2, false)
                .is_err()
        );
    }
}
#[test]
fn coordinator_never_negotiates_multisuite_or_legacy_even_with_rebound_candidate_hash() {
    use seamless_transport::pairing_v2::{BoundHello, CandidateBinding, CandidateHello, SUITE};
    let v = fixture();
    for offer in [vec!["legacy-v1"], vec!["legacy-v1", SUITE]] {
        let mut fields = decode(
            "candidate-hello",
            &bytes(&v, "candidate_hello_a_hex"),
            &[2, 2, 2, 3, 3, 2, 2, 1],
        )
        .unwrap();
        let mut suites = (offer.len() as u16).to_be_bytes().to_vec();
        for suite in offer {
            suites.extend((suite.len() as u16).to_be_bytes());
            suites.extend(suite.as_bytes());
        }
        fields[5] = Value::Bytes(suites);
        let candidate =
            CandidateHello::decode(&encode("candidate-hello", &fields).unwrap()).unwrap();
        let binding = CandidateBinding::select(&candidate, "selected-connection", 5).unwrap();
        let mut hello = decode(
            "hello",
            &bytes(&v, "hello_a_hex"),
            &[1, 2, 2, 2, 2, 2, 2, 3, 2, 3, 3, 2, 3, 1],
        )
        .unwrap();
        hello[4] = Value::Bytes(binding.digest().to_vec());
        let fp: [u8; 32] = bytes(&v, "role_a_full_fingerprint_hex").try_into().unwrap();
        assert!(
            BoundHello::validate(
                &candidate,
                &binding,
                &encode("hello", &hello).unwrap(),
                fp,
                "selected-connection",
                5,
                fp[..16].try_into().unwrap(),
                1_893_456_000
            )
            .is_err()
        );
    }
}

#[cfg(unix)]
#[test]
fn finalization_reorders_duplicates_bad_mac_and_missing_durability_abort_without_advancement() {
    use seamless_transport::{pairing_pending::PendingStore, pairing_v2::JournalClock};
    let v = fixture();
    let clock = JournalClock {
        boot: [1; 16],
        monotonic_ms: 6,
        utc_seconds: 1_893_456_000,
    };
    for local in [Role::A, Role::B] {
        for failure in 0..6 {
            let mut s = session(&v, local);
            through_proofs(&mut s, &v);
            let attempt = bytes(&v, "attempt_id_hex").try_into().unwrap();
            s.confirm(
                attempt,
                bytes(&v, "transcript_hex").try_into().unwrap(),
                7,
                true,
                4,
            )
            .unwrap();
            for role in [Role::A, Role::B] {
                s.receive(approval(&v, role), 5).unwrap();
            }
            let temp = tempfile::tempdir().unwrap();
            let store = PendingStore::open(temp.path()).unwrap();
            let pending = store
                .prepare(
                    store.version().unwrap(),
                    attempt,
                    bytes(
                        &v,
                        if local == Role::A {
                            "role_b_full_fingerprint_hex"
                        } else {
                            "role_a_full_fingerprint_hex"
                        },
                    )
                    .try_into()
                    .unwrap(),
                )
                .unwrap();
            let mut f = s.begin_finalization(pending, clock).unwrap();
            let version = store.version().unwrap();
            let send = |f: &mut seamless_transport::pairing_v2::Finalizer,
                        index: usize,
                        wrong_tag: bool,
                        now: JournalClock| {
                let m = &v["finalization"][index];
                let mut tag = bytes(m, "tag");
                if wrong_tag {
                    tag[0] ^= 1;
                }
                f.receive(
                    m["phase"].as_str().unwrap(),
                    if m["role"] == "A" { Role::A } else { Role::B },
                    SignedEvidence {
                        body: bytes(m, "body"),
                        signature: bytes(m, "signature"),
                    },
                    &tag,
                    now,
                )
            };
            let rejected = match failure {
                0 => send(&mut f, 2, false, clock).is_err(),
                1 => {
                    send(&mut f, 0, false, clock).unwrap();
                    send(&mut f, 0, false, clock).is_err()
                }
                2 => send(&mut f, 0, true, clock).is_err(),
                3 => send(
                    &mut f,
                    0,
                    false,
                    JournalClock {
                        monotonic_ms: 30_006,
                        ..clock
                    },
                )
                .is_err(),
                4 => {
                    for i in 0..=if local == Role::A { 2 } else { 3 } {
                        send(&mut f, i, false, clock).unwrap();
                    }
                    send(&mut f, if local == Role::A { 3 } else { 4 }, false, clock).is_err()
                }
                _ => {
                    for i in 0..=if local == Role::A { 2 } else { 3 } {
                        send(&mut f, i, false, clock).unwrap();
                    }
                    let mut stale = version;
                    stale.revision += 1;
                    f.persist(&store, stale, clock).is_err()
                }
            };
            assert!(rejected, "{local:?}/{failure}");
            assert!(f.durable_fc_hash().is_none());
            assert!(f.persist(&store, version, clock).is_err());
            assert_eq!(store.version().unwrap(), version);
        }
    }
}
