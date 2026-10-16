use super::*;
use crate::pairing_v2::{
    codec::{Value, decode},
    derive_keys,
    evidence::hash,
    handshake_wire::Envelope,
    validate_identity,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use zeroize::Zeroizing;
fn bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/pairing-v2/handshake-v01-49e7137.json"
    ))
    .unwrap()
}
fn envelope(i: usize) -> Envelope {
    Envelope::decode(&bytes(
        fixture()["handshake_envelopes_hex"][i].as_str().unwrap(),
    ))
    .unwrap()
}
fn live() -> (LiveEvidence, [Ed25519KeyPair; 2]) {
    let v = fixture();
    let ids = ["observed_leaf_a_der_hex", "observed_leaf_b_der_hex"].map(|k| {
        let der = bytes(v[k].as_str().unwrap());
        validate_identity(&der, hash(&der)[..16].try_into().unwrap(), 1_893_456_000).unwrap()
    });
    let mut signers = [1, 4].map(|seed| Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap());
    if signers[0].public_key().as_ref() != ids[0].public_key() {
        signers.swap(0, 1);
    }
    let h = [envelope(0), envelope(1)];
    let c = [envelope(2), envelope(3)];
    let r = [envelope(4), envelope(5)];
    let (_, attempt, t) = crate::pairing_v2::detached_transcript(
        &h[0].payload,
        &h[1].payload,
        [&c[0].payload, &c[1].payload],
        [&r[0].payload, &r[1].payload],
    )
    .unwrap();
    let f = decode("reveal", &r[1].payload, &[2, 3, 2, 2]).unwrap();
    let Value::Bytes(peer) = &f[2] else { panic!() };
    let keys = derive_keys(
        Zeroizing::new([0x70; 32]),
        peer.as_slice().try_into().unwrap(),
        t,
    )
    .unwrap();
    (
        LiveEvidence {
            context: EvidenceContext::new(ids, attempt, t).unwrap(),
            keys: Arc::new(keys),
        },
        signers,
    )
}
#[test]
fn all_live_signed_envelopes_match_independent_49e_bytes() {
    let (live, keys) = live();
    for (i, role) in [Role::A, Role::B].into_iter().enumerate() {
        let sign = |body: &[u8]| Ok(keys[i].sign(body).as_ref().to_vec());
        assert_eq!(
            live.key_proof(role, &sign).unwrap(),
            envelope(6 + i).payload
        );
        assert_eq!(live.approval(role, &sign).unwrap(), envelope(8 + i).payload);
    }
    for (j, (phase, role)) in [
        ("ready", Role::A),
        ("ready", Role::B),
        ("commit", Role::A),
        ("commit_ack", Role::B),
        ("complete", Role::A),
    ]
    .into_iter()
    .enumerate()
    {
        let f = decode(
            "wire-finalization-v1",
            &envelope(10 + j).payload,
            &[2, 2, 2],
        )
        .unwrap();
        let Value::Bytes(body) = &f[0] else { panic!() };
        let b = decode("finalization-body", body, &[3, 3, 2, 2, 2, 3]).unwrap();
        let Value::Bytes(p) = &b[4] else { panic!() };
        assert_eq!(
            live.finalization(phase, role, p.as_slice().try_into().unwrap(), &|body| Ok(
                keys[role.index()].sign(body).as_ref().to_vec()
            ))
            .unwrap(),
            envelope(10 + j).payload
        );
    }
}
#[test]
fn cancel_matches_oracle_and_rejects_each_bound_field_and_tag() {
    let (live, keys) = live();
    let e = Envelope::decode(&bytes(
        fixture()["cancel_contract"]["fixture_envelope_hex"]
            .as_str()
            .unwrap(),
    ))
    .unwrap();
    let role = if e.direction == 1 { Role::A } else { Role::B };
    assert_eq!(
        live.cancel(role, &|body| Ok(keys[role.index()]
            .sign(body)
            .as_ref()
            .to_vec()))
            .unwrap(),
        e.payload
    );
    assert!(live.verify_cancel(role, &e.payload).is_ok());
    for i in 0..e.payload.len() {
        let mut bad = e.payload.clone();
        bad[i] ^= 1;
        assert!(live.verify_cancel(role, &bad).is_err(), "byte {i}");
    }
    assert!(
        live.verify_cancel(if role == Role::A { Role::B } else { Role::A }, &e.payload)
            .is_err()
    );
}
#[test]
fn wrong_identity_signer_never_emits_a_record() {
    let (live, keys) = live();
    let wrong = |body: &[u8]| Ok(keys[1].sign(body).as_ref().to_vec());
    assert!(live.key_proof(Role::A, &wrong).is_err());
    assert!(live.approval(Role::A, &wrong).is_err());
    assert!(live.cancel(Role::A, &wrong).is_err());
    assert!(
        live.finalization("commit", Role::B, [0; 32], &wrong)
            .is_err()
    );
}
