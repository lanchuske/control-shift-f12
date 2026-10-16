#![cfg(all(any(unix, windows), feature = "pairing-v2-experimental"))]
use seamless_transport::{
    pairing_pending::PendingStore,
    pairing_v2::{
        Invalid, RecoveryAuthority, RecoveryContext, RecoveryFields, Role, VerifiedRecoveryUse,
        verify_authoritative_recovery,
    },
};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

// Test-only source of accepted remote generations; there is no production
// source until durable role-finalization has been implemented and reviewed.
struct Authority {
    store: PendingStore,
    context: Mutex<Option<RecoveryContext>>,
}
impl RecoveryAuthority for Authority {
    fn expected(&self, _: [u8; 32]) -> Result<Option<RecoveryContext>, Invalid> {
        Ok(self.context.lock().unwrap().clone())
    }
    fn consume_if_current(
        &self,
        _: [u8; 32],
        revision: u64,
        proof: VerifiedRecoveryUse,
    ) -> Result<(), Invalid> {
        let context = self.context.lock().unwrap();
        if context.as_ref().ok_or(Invalid)?.revision != revision {
            return Err(Invalid);
        }
        self.store
            .consume_verified_recovery(proof)
            .map_err(|_| Invalid)
    }
}
#[path = "support/pairing_v2.rs"]
mod common;
fn attempt() -> [u8; 32] {
    common::bytes(&common::fixture(), "attempt_id_hex")
        .try_into()
        .unwrap()
}
fn setup(root: &std::path::Path) -> (Authority, Vec<u8>, Vec<u8>) {
    let v = common::fixture();
    let fields = seamless_transport::pairing_v2::codec::decode(
        "hello",
        &common::bytes(&v, "hello_b_hex"),
        &[1, 2, 2, 2, 2, 2, 2, 3, 2, 3, 3, 2, 3, 1],
    )
    .unwrap();
    let seamless_transport::pairing_v2::codec::Value::Bytes(der) = &fields[8] else {
        panic!()
    };
    let fingerprint: [u8; 32] = Sha256::digest(der).into();
    let store = PendingStore::open(root).unwrap();
    if store.pending(attempt()).unwrap().is_none() {
        drop(store);
        common::populate(root, Role::A, 4);
    }
    let store = PendingStore::open(root).unwrap();
    let pending = store.pending(attempt()).unwrap().unwrap();
    let expected = RecoveryFields {
        attempt_id: attempt(),
        fc_hash: common::bytes(&v, "finalization_certificate_hash_hex")
            .try_into()
            .unwrap(),
        role: Role::B,
        challenger_nonce: vec![1; 32],
        responder_nonce: vec![2; 32],
        tls_exporter: vec![3; 32],
        identity_generation: 91,
        revocation_generation: 73,
    };
    let body = expected.encode().unwrap();
    let signer = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[4; 32]).unwrap();
    let sig = signer.sign(&body).as_ref().to_vec();
    let context = RecoveryContext {
        challenge_id: [1; 32],
        issued_ms: 0,
        revision: 1,
        local_version: store.version().unwrap(),
        pending,
        peer_node: fingerprint[..16].try_into().unwrap(),
        peer_certificate: der.clone(),
        expected,
        deadline_ms: 30_000,
    };
    (
        Authority {
            store,
            context: Mutex::new(Some(context)),
        },
        body,
        sig,
    )
}

#[test]
fn accepted_remote_generations_are_not_local_generations_and_replay_survives_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let (authority, body, sig) = setup(temp.path());
    let before = authority.store.version().unwrap();
    assert!(
        verify_authoritative_recovery(&authority, [1; 32], &body, &[0; 64], 1, 1_893_456_000)
            .is_err()
    );
    assert_eq!(authority.store.version().unwrap(), before);
    verify_authoritative_recovery(&authority, [1; 32], &body, &sig, 1, 1_893_456_000).unwrap();
    assert!(authority.store.promote(attempt()).is_err());
    let mut context = authority.context.into_inner().unwrap().unwrap();
    drop(authority.store);
    let store = PendingStore::open(temp.path()).unwrap();
    context.local_version = store.version().unwrap();
    context.revision += 1;
    let reopened = Authority {
        store,
        context: Mutex::new(Some(context)),
    };
    assert!(
        verify_authoritative_recovery(&reopened, [1; 32], &body, &sig, 2, 1_893_456_000).is_err()
    );
}

#[test]
fn absent_or_changed_authority_and_local_revocation_fail_without_consumption() {
    for failure in 0..5 {
        let temp = tempfile::tempdir().unwrap();
        let (authority, body, sig) = setup(temp.path());
        match failure {
            0 => *authority.context.lock().unwrap() = None,
            1 => {
                authority
                    .context
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .expected
                    .identity_generation += 1
            }
            2 => {
                authority
                    .context
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .expected
                    .revocation_generation += 1
            }
            3 => {
                authority
                    .store
                    .cancel(authority.store.version().unwrap(), attempt())
                    .unwrap();
            }
            4 => {
                authority
                    .store
                    .rotate_identity(authority.store.version().unwrap())
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let before = authority.store.version().unwrap();
        assert!(
            verify_authoritative_recovery(&authority, [1; 32], &body, &sig, 1, 1_893_456_000)
                .is_err(),
            "failure/{failure}"
        );
        assert_eq!(authority.store.version().unwrap(), before);
    }
}

#[test]
fn exact_recovery_context_clock_and_channel_bindings_are_required() {
    for failure in 0..10 {
        let temp = tempfile::tempdir().unwrap();
        let (authority, body, sig) = setup(temp.path());
        let mut now = 1;
        {
            let mut guard = authority.context.lock().unwrap();
            let context = guard.as_mut().unwrap();
            match failure {
                0 => context.expected.fc_hash[0] ^= 1,
                1 => context.expected.role = Role::A,
                2 => context.expected.challenger_nonce[0] ^= 1,
                3 => context.expected.responder_nonce[0] ^= 1,
                4 => context.expected.tls_exporter[0] ^= 1,
                5 => context.challenge_id[0] ^= 1,
                6 => context.pending.peer_fingerprint[0] ^= 1,
                7 => now = 30_000,
                8 => context.issued_ms = 2,
                9 => context.deadline_ms = 30_001,
                _ => unreachable!(),
            }
        }
        let before = authority.store.version().unwrap();
        assert!(
            verify_authoritative_recovery(&authority, [1; 32], &body, &sig, now, 1_893_456_000)
                .is_err(),
            "binding/{failure}"
        );
        assert_eq!(authority.store.version().unwrap(), before);
    }
}

#[test]
fn concurrent_processes_share_durable_consumption() {
    let temp = tempfile::tempdir().unwrap();
    let (authority, _, _) = setup(temp.path());
    drop(authority);
    let mut children = vec![];
    for _ in 0..2 {
        children.push(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "durable_recovery_process_child", "--nocapture"])
                .env("PAIRING_V2_TEST_ROOT", temp.path())
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    let mut statuses: Vec<_> = children
        .iter_mut()
        .map(|child| child.wait().unwrap().code().unwrap())
        .collect();
    statuses.sort();
    assert_eq!(
        statuses,
        [0, 10],
        "only one process may consume the same proof"
    );
}

#[test]
fn durable_recovery_process_child() {
    let Ok(path) = std::env::var("PAIRING_V2_TEST_ROOT") else {
        return;
    };
    let (authority, body, sig) = setup(std::path::Path::new(&path));
    std::process::exit(
        if verify_authoritative_recovery(&authority, [1; 32], &body, &sig, 1, 1_893_456_000).is_ok()
        {
            0
        } else {
            10
        },
    );
}

#[test]
fn corrupted_consumption_blocks_all_manifest_reads_and_writes() {
    let temp = tempfile::tempdir().unwrap();
    let (authority, body, sig) = setup(temp.path());
    verify_authoritative_recovery(&authority, [1; 32], &body, &sig, 1, 1_893_456_000).unwrap();
    let version = authority.store.version().unwrap();
    let path = temp.path().join("pairing-tombstones/ledger.json");
    let mut ledger: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    ledger["recoveries"][0]["signature"][0] = serde_json::json!(0);
    let broken = serde_json::to_vec(&ledger).unwrap();
    std::fs::write(&path, &broken).unwrap();
    assert!(authority.store.version().is_err());
    assert!(authority.store.pending(attempt()).is_err());
    assert!(authority.store.prepare(version, [9; 32], [9; 32]).is_err());
    assert!(authority.store.cancel(version, attempt()).is_err());
    assert!(authority.store.rotate_identity(version).is_err());
    assert!(PendingStore::open(temp.path()).is_err());
    assert_eq!(std::fs::read(path).unwrap(), broken);
}

#[test]
fn authoritative_claim_cannot_replace_missing_local_durable_fc() {
    let temp = tempfile::tempdir().unwrap();
    let (authority, body, sig) = setup(temp.path());
    let path = temp.path().join("pairing-tombstones/ledger.json");
    let mut ledger: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    ledger.as_object_mut().unwrap().remove("journals");
    let before = serde_json::to_vec(&ledger).unwrap();
    std::fs::write(&path, &before).unwrap();
    assert!(
        verify_authoritative_recovery(&authority, [1; 32], &body, &sig, 1, 1_893_456_000).is_err()
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
}

fn durable_snapshot(
    root: &std::path::Path,
) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    ["pairing-pending", "pairing-tombstones"]
        .into_iter()
        .flat_map(|directory| std::fs::read_dir(root.join(directory)).unwrap())
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.strip_prefix(root).unwrap().to_owned(),
                std::fs::read(path).unwrap(),
            )
        })
        .collect()
}

// Killing the field's 32-byte guard must admit a correctly signed length-1
// proof and make this matrix RED. Context and signed body change together, so
// an unrelated expected-body or signature mismatch cannot mask a missing guard.
fn rejects_operational_recovery_length_matrix(field: &str, index: usize) {
    use seamless_transport::pairing_v2::codec::{Value, decode, encode};
    for length in [0, 1, 31, 33, 256] {
        let temp = tempfile::tempdir().unwrap();
        let (authority, original_body, _) = setup(temp.path());
        let value = vec![0x5a; length];
        {
            let mut guard = authority.context.lock().unwrap();
            let context = guard.as_mut().unwrap();
            match field {
                "challenger_nonce" => context.expected.challenger_nonce = value.clone(),
                "responder_nonce" => context.expected.responder_nonce = value.clone(),
                "tls_exporter" => context.expected.tls_exporter = value.clone(),
                _ => panic!("unknown matrix field"),
            }
        }
        let mut fields = decode(
            "recovery-proof",
            &original_body,
            &[3, 2, 2, 3, 2, 2, 2, 1, 1, 3],
        )
        .unwrap();
        fields[index] = Value::Bytes(value);
        // Encode the zero-length case at the canonical codec boundary too:
        // RecoveryFields::encode itself rejects empty generic fields.
        let body = encode("recovery-proof", &fields).unwrap();
        let signer = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[4; 32]).unwrap();
        let signature = signer.sign(&body);
        let version = authority.store.version().unwrap();
        let pending = authority.store.pending(attempt()).unwrap();
        let before = durable_snapshot(temp.path());
        let ledger: serde_json::Value =
            serde_json::from_slice(&before[std::path::Path::new("pairing-tombstones/ledger.json")])
                .unwrap();
        assert!(
            ledger.get("recoveries").is_none(),
            "fresh fixture has no consumed proof"
        );

        assert_eq!(
            verify_authoritative_recovery(
                &authority,
                [1; 32],
                &body,
                signature.as_ref(),
                1,
                1_893_456_000
            ),
            Err(Invalid),
            "operational {field} length {length} must reject"
        );
        assert_eq!(
            authority.store.version().unwrap(),
            version,
            "{field}/{length}: CAS advanced"
        );
        assert_eq!(
            authority.store.pending(attempt()).unwrap(),
            pending,
            "{field}/{length}: pending changed"
        );
        assert_eq!(
            durable_snapshot(temp.path()),
            before,
            "{field}/{length}: journal/tombstone/consumption changed"
        );
    }
}

#[test]
fn operational_challenger_nonce_length_matrix_rejects_without_durable_mutation() {
    rejects_operational_recovery_length_matrix("challenger_nonce", 4);
}

#[test]
fn operational_responder_nonce_length_matrix_rejects_without_durable_mutation() {
    rejects_operational_recovery_length_matrix("responder_nonce", 5);
}

#[test]
fn operational_tls_exporter_length_matrix_rejects_without_durable_mutation() {
    rejects_operational_recovery_length_matrix("tls_exporter", 6);
}
