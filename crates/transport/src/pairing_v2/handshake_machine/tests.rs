use super::*;
use crate::pairing_v2::{
    handshake_wire::{Envelope, SCHEDULE},
    operational_wire::TransportFrame,
};
use ring::signature::Ed25519KeyPair;
fn bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn v() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/pairing-v2/handshake-v01-49e7137.json"
    ))
    .unwrap()
}
fn records() -> Vec<Vec<u8>> {
    v()["handshake_envelopes_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| bytes(s.as_str().unwrap()))
        .collect()
}
fn clock() -> JournalClock {
    JournalClock {
        boot: [1; 16],
        monotonic_ms: 1,
        utc_seconds: 1_893_456_000,
    }
}
fn candidate() -> CandidateTranscript {
    let v = v();
    let f: Vec<_> = v["candidate_frames_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            TransportFrame::decode(&bytes(s.as_str().unwrap()))
                .unwrap()
                .payload
        })
        .collect();
    CandidateTranscript::new(
        [f[0].clone(), f[2].clone()],
        [f[3].clone(), f[1].clone()],
        [
            bytes(v["observed_leaf_a_der_hex"].as_str().unwrap()),
            bytes(v["observed_leaf_b_der_hex"].as_str().unwrap()),
        ],
        clock().utc_seconds,
    )
    .unwrap()
}
fn machine(role: Role, store: &PendingStore) -> Machine {
    Machine::new(
        candidate(),
        role,
        Envelope::decode(&records()[role.index()]).unwrap().payload,
        Zeroizing::new([if role == Role::A { 0x70 } else { 0x80 }; 32]),
        Zeroizing::new([if role == Role::A { 0x90 } else { 0xa0 }; 32]),
        1,
        store.version().unwrap(),
        clock(),
        "quic-test",
        1,
    )
    .unwrap()
}
#[test]
fn both_roles_emit_exact49e_bytes_only_after_local_gesture_and_durable_boundaries() {
    for role in [Role::A, Role::B] {
        let tmp = tempfile::tempdir().unwrap();
        let store = PendingStore::open(tmp.path()).unwrap();
        let mut m = machine(role, &store);
        let key = Ed25519KeyPair::from_seed_unchecked(&[if role == Role::A { 1 } else { 4 }; 32])
            .unwrap();
        for (i, raw) in records().iter().enumerate() {
            if i == 8 {
                m.confirm(true, clock()).unwrap();
            }
            if SCHEDULE[i].1 == role.index() as u8 + 1 {
                let outgoing = m
                    .next_local(&|b| Ok(key.sign(b).as_ref().to_vec()), &store, clock())
                    .unwrap();
                assert_eq!(*raw, outgoing, "role {role:?} phase {i}");
            } else {
                m.receive(raw, &store, clock()).unwrap();
            }
        }
        assert_eq!(m.status(), Status::FcVerified);
        assert!(m.durable_fc().is_some());
        assert!(m.half_close(Role::A));
        assert!(m.half_close(Role::B));
        assert_eq!(m.status(), Status::CompletePendingAuthority);
        assert_eq!(store.version().unwrap().revision, 3); // prepare + first durable decision + complete
    }
}
#[test]
fn malformed_crypto_at_every_phase_is_terminal_and_never_revivable() {
    for at in 0..17 {
        let tmp = tempfile::tempdir().unwrap();
        let store = PendingStore::open(tmp.path()).unwrap();
        let mut m = machine(Role::A, &store);
        let records = records();
        for (i, raw) in records[..at].iter().enumerate() {
            if i == 8 {
                m.confirm(true, clock()).unwrap();
            }
            m.receive(raw, &store, clock()).unwrap();
        }
        if at == 8 {
            m.confirm(true, clock()).unwrap();
        }
        let mut bad = Envelope::decode(&records[at]).unwrap();
        // An opaque commitment can only be authenticated on reveal. For its
        // ingress phase mutate canonical framing, not an unknowable hash bit.
        let offset = if at == 2 || at == 3 {
            0
        } else {
            bad.payload.len() - 1
        };
        bad.payload[offset] ^= 1;
        let before = store.version().unwrap();
        assert!(
            m.receive(&bad.encode().unwrap(), &store, clock()).is_err(),
            "phase {at}"
        );
        assert_eq!(m.status(), Status::Aborted);
        assert_eq!(store.version().unwrap(), before);
        assert!(m.receive(&records[at], &store, clock()).is_err());
        assert!(m.durable_fc().is_none());
    }
}
#[test]
fn durability_cas_failure_cannot_return_commit_or_fc_for_emission() {
    for (role, at) in [(Role::A, 12), (Role::B, 13), (Role::A, 14)] {
        let tmp = tempfile::tempdir().unwrap();
        let store = PendingStore::open(tmp.path()).unwrap();
        let mut m = machine(role, &store);
        for (i, raw) in records()[..at].iter().enumerate() {
            if i == 8 {
                m.confirm(true, clock()).unwrap();
            }
            m.receive(raw, &store, clock()).unwrap();
        }
        store.rotate_identity(store.version().unwrap()).unwrap();
        let key = Ed25519KeyPair::from_seed_unchecked(&[if role == Role::A { 1 } else { 4 }; 32])
            .unwrap();
        assert!(
            m.next_local(&|b| Ok(key.sign(b).as_ref().to_vec()), &store, clock())
                .is_err()
        );
        assert_eq!(m.status(), Status::Aborted);
        assert!(m.durable_fc().is_none());
    }
}

#[test]
fn bilateral_durable_emit_fault_worker() {
    let Ok(root) = std::env::var("CSF12_BILATERAL_FAULT_ROOT") else {
        return;
    };
    let role = if std::env::var("CSF12_BILATERAL_FAULT_ROLE").unwrap() == "A" {
        Role::A
    } else {
        Role::B
    };
    let at = std::env::var("CSF12_BILATERAL_FAULT_AT")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let store = PendingStore::open(root).unwrap();
    let mut m = machine(role, &store);
    for (i, raw) in records()[..at].iter().enumerate() {
        if i == 8 {
            m.confirm(true, clock()).unwrap();
        }
        m.receive(raw, &store, clock()).unwrap();
    }
    let key =
        Ed25519KeyPair::from_seed_unchecked(&[if role == Role::A { 1 } else { 4 }; 32]).unwrap();
    crate::private_fs::faults::arm();
    match m.next_local(&|b| Ok(key.sign(b).as_ref().to_vec()), &store, clock()) {
        Ok(_) => {
            println!("EMIT_RETURNED");
            std::process::exit(0)
        }
        Err(_) => {
            assert_eq!(m.status(), Status::Aborted);
            assert!(m.durable_fc().is_none());
            std::process::exit(92)
        }
    }
}

#[test]
fn abort_discards_only_safe_precommit_pending_and_never_durable_or_conflicted_state() {
    for at in [10, 13] {
        let tmp = tempfile::tempdir().unwrap();
        let store = PendingStore::open(tmp.path()).unwrap();
        let mut m = machine(Role::A, &store);
        for (i, raw) in records()[..at].iter().enumerate() {
            if i == 8 {
                m.confirm(true, clock()).unwrap();
            }
            m.receive(raw, &store, clock()).unwrap();
        }
        let before = store.version().unwrap();
        m.reject();
        m.dispose_pending(&store);
        assert_eq!(
            store.version().unwrap().revision,
            if at == 10 {
                before.revision + 1
            } else {
                before.revision
            }
        );
    }
}
#[test]
fn bilateral_no_emit_at_each_real_durable_write_flush_rename_boundary() {
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
    for (role, at) in [("A", 12), ("B", 13), ("A", 14)] {
        for target in ["journal", "ledger"] {
            for stage in stages {
                for mode in ["error", "crash"] {
                    let tmp = tempfile::tempdir().unwrap();
                    let output=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","pairing_v2::handshake_machine::tests::bilateral_durable_emit_fault_worker","--nocapture"]).env("CSF12_BILATERAL_FAULT_ROOT",tmp.path()).env("CSF12_BILATERAL_FAULT_ROLE",role).env("CSF12_BILATERAL_FAULT_AT",at.to_string()).env("PAIRING_TEST_FS_FAULT",format!("{target}:{stage}:{mode}")).output().unwrap();
                    assert_eq!(
                        output.status.code(),
                        Some(if mode == "crash" { 91 } else { 92 }),
                        "{role} {at} {target} {stage} {mode}: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    assert!(!String::from_utf8_lossy(&output.stdout).contains("EMIT_RETURNED"));
                    // Reopening validates the whole durable manifest; no successful reopen
                    // turns quarantined evidence into an active trust/admission capability.
                    if let Ok(store) = PendingStore::open(tmp.path()) {
                        let v = store.version().unwrap();
                        assert!(v.revision <= 3);
                    }
                }
            }
        }
    }
}
