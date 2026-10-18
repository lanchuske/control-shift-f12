#![allow(dead_code)]
use seamless_transport::pairing_v2::{
    BoundHello, CandidateBinding, CandidateHello, Role, SasSession, SessionMessage, SignedEvidence,
};
pub fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../fixtures/pairing-v2/e2e-v01-real-candidate-hello.json"
    ))
    .unwrap()
}

pub fn bytes(v: &serde_json::Value, key: &str) -> Vec<u8> {
    let s = v[key].as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&s[n..n + 2], 16).unwrap())
        .collect()
}

pub fn bound(
    v: &serde_json::Value,
    role: &str,
    hello: &[u8],
) -> Result<BoundHello, seamless_transport::pairing_v2::Invalid> {
    let candidate =
        CandidateHello::decode(&bytes(v, &format!("candidate_hello_{role}_hex"))).unwrap();
    let binding = CandidateBinding::select(&candidate, "selected-connection", 5).unwrap();
    let fp: [u8; 32] = bytes(v, &format!("role_{role}_full_fingerprint_hex"))
        .try_into()
        .unwrap();
    BoundHello::validate(
        &candidate,
        &binding,
        hello,
        fp,
        "selected-connection",
        5,
        fp[..16].try_into().unwrap(),
        1_893_456_000,
    )
}

pub fn session(v: &serde_json::Value, local: Role) -> SasSession {
    let a = bound(v, "a", &bytes(v, "hello_a_hex")).unwrap();
    let b = bound(v, "b", &bytes(v, "hello_b_hex")).unwrap();
    let coordinator = *a.fingerprint();
    let local_fp = if local == Role::A {
        coordinator
    } else {
        *b.fingerprint()
    };
    SasSession::new(
        [b, a],
        local_fp,
        coordinator,
        zeroize::Zeroizing::new([if local == Role::A { 0x70 } else { 0x80 }; 32]),
        7,
        0,
    )
    .unwrap()
}

pub fn commitments(s: &mut SasSession, v: &serde_json::Value) {
    for (role, suffix) in [(Role::A, "a"), (Role::B, "b")] {
        s.receive(
            SessionMessage::Commit(role, bytes(v, &format!("commit_{suffix}_hex"))),
            1,
        )
        .unwrap();
    }
}

pub fn through_proofs(s: &mut SasSession, v: &serde_json::Value) {
    commitments(s, v);
    for (role, suffix) in [(Role::A, "a"), (Role::B, "b")] {
        s.receive(
            SessionMessage::Reveal(role, bytes(v, &format!("reveal_{suffix}_hex"))),
            2,
        )
        .unwrap();
    }
    assert!(s.verification_words(3).is_none());
    for (role, suffix) in [(Role::A, "a"), (Role::B, "b")] {
        s.receive(
            SessionMessage::KeyProof(
                role,
                bytes(v, &format!("proof_signature_{suffix}_hex")),
                bytes(v, &format!("proof_tag_{suffix}_hex")),
            ),
            3,
        )
        .unwrap();
    }
}

pub fn approval(v: &serde_json::Value, role: Role) -> SessionMessage {
    let suffix = if role == Role::A { "a" } else { "b" };
    SessionMessage::Approval(
        role,
        SignedEvidence {
            body: bytes(v, &format!("approve_{suffix}_body_hex")),
            signature: bytes(v, &format!("approve_{suffix}_signature_hex")),
        },
        bytes(v, &format!("approve_{suffix}_tag_hex")),
    )
}

#[cfg(any(unix, windows))]
pub fn stored_until(
    local: Role,
    last_index: usize,
) -> (
    tempfile::TempDir,
    seamless_transport::pairing_pending::PendingStore,
    [u8; 32],
) {
    let temp = tempfile::tempdir().unwrap();
    let (store, attempt) = populate(temp.path(), local, last_index);
    (temp, store, attempt)
}
#[cfg(any(unix, windows))]
pub fn populate(
    root: &std::path::Path,
    local: Role,
    last_index: usize,
) -> (seamless_transport::pairing_pending::PendingStore, [u8; 32]) {
    use seamless_transport::{
        pairing_pending::PendingStore,
        pairing_v2::{FinalizationAction, JournalClock},
    };
    let v = fixture();
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
    let store = PendingStore::open(root).unwrap();
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
    let mut f = s.begin_finalization(pending, clock).unwrap();
    for message in v["finalization"]
        .as_array()
        .unwrap()
        .iter()
        .take(last_index + 1)
    {
        let role = if message["role"] == "A" {
            Role::A
        } else {
            Role::B
        };
        if f.receive(
            message["phase"].as_str().unwrap(),
            role,
            SignedEvidence {
                body: bytes(message, "body"),
                signature: bytes(message, "signature"),
            },
            &bytes(message, "tag"),
            clock,
        )
        .unwrap()
            == FinalizationAction::NeedsDurability
        {
            f.persist(&store, store.version().unwrap(), clock).unwrap();
        }
    }
    (store, attempt)
}
