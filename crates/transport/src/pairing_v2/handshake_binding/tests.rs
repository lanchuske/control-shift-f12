use super::*;
use crate::pairing_v2::{codec::decode, operational_wire::TransportFrame};
fn v() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/pairing-v2/handshake-v01-49e7137.json"
    ))
    .unwrap()
}
fn bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn transcript() -> CandidateTranscript {
    let v = v();
    let f = v["candidate_frames_hex"].as_array().unwrap();
    CandidateTranscript::new(
        [
            TransportFrame::decode(&bytes(f[0].as_str().unwrap()))
                .unwrap()
                .payload,
            TransportFrame::decode(&bytes(f[2].as_str().unwrap()))
                .unwrap()
                .payload,
        ],
        [
            TransportFrame::decode(&bytes(f[3].as_str().unwrap()))
                .unwrap()
                .payload,
            TransportFrame::decode(&bytes(f[1].as_str().unwrap()))
                .unwrap()
                .payload,
        ],
        [
            bytes(v["observed_leaf_a_der_hex"].as_str().unwrap()),
            bytes(v["observed_leaf_b_der_hex"].as_str().unwrap()),
        ],
        1_893_456_000,
    )
    .unwrap()
}
#[test]
fn independent_shared_context_and_distinct_local_bindings_match49e() {
    let v = v();
    let t = transcript();
    assert_eq!(
        t.exporter_context().unwrap(),
        bytes(v["shared_exporter_context_hex"].as_str().unwrap())
    );
    let output: [u8; 32] = bytes(v["shared_exporter_output_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    for (role, key) in [(Role::A, "local_binding_a"), (Role::B, "local_binding_b")] {
        let b = &v[key];
        assert_eq!(
            t.local_binding(
                role,
                b["connection_id"].as_str().unwrap(),
                b["connection_generation"].as_u64().unwrap(),
                &output
            )
            .unwrap()
            .as_slice(),
            bytes(b["binding_sha256_hex"].as_str().unwrap())
        );
    }
}
#[test]
fn observed_leaf_swap_nonce_rendezvous_and_singleton_suite_are_not_claim_comparisons() {
    let good = transcript();
    for mutation in 0..7 {
        let mut req = good.requests.clone();
        let mut cand = good.candidates.clone();
        let mut observed = good.observed.clone();
        match mutation {
            0 => observed.swap(0, 1),
            1 => observed[0][0] ^= 1,
            2 => {
                let mut f = decode("candidate-hello", &cand[0], &[2, 2, 2, 3, 3, 2, 2, 1]).unwrap();
                f[1] = b(&[0; 16]);
                cand[0] = encode("candidate-hello", &f).unwrap();
            }
            3 => {
                let mut f = decode("candidate-hello", &cand[1], &[2, 2, 2, 3, 3, 2, 2, 1]).unwrap();
                f[0] = b(&[0; 16]);
                cand[1] = encode("candidate-hello", &f).unwrap();
            }
            4 => {
                let mut f = decode("candidate-hello", &cand[0], &[2, 2, 2, 3, 3, 2, 2, 1]).unwrap();
                f[6] = b(&hash(&observed[1]));
                cand[0] = encode("candidate-hello", &f).unwrap();
            }
            5 => {
                let mut f = decode("candidate-hello", &cand[1], &[2, 2, 2, 3, 3, 2, 2, 1]).unwrap();
                f[5] = b(&[0, 1, 0, 1, b'x']);
                cand[1] = encode("candidate-hello", &f).unwrap();
            }
            _ => req.swap(0, 1),
        }
        assert!(
            CandidateTranscript::new(req, cand, observed, 1_893_456_000).is_err(),
            "mutation {mutation}"
        );
    }
}
#[test]
fn hello_keeps_exact_candidate_hash_and_observed_identity() {
    let v = v();
    let t = transcript();
    for (i, role) in [Role::A, Role::B].into_iter().enumerate() {
        let envelope = crate::pairing_v2::handshake_wire::Envelope::decode(&bytes(
            v["handshake_envelopes_hex"][i].as_str().unwrap(),
        ))
        .unwrap();
        assert!(
            t.bind_hello(role, &envelope.payload, "quic-local", 1, 1_893_456_000)
                .is_ok()
        );
        for field in [4, 8] {
            let mut f = decode(
                "hello",
                &envelope.payload,
                &[1, 2, 2, 2, 2, 2, 2, 3, 2, 3, 3, 2, 3, 1],
            )
            .unwrap();
            f[field] = if field == 4 {
                b(&[9; 32])
            } else {
                b(&t.observed[1 - i])
            };
            assert!(
                t.bind_hello(
                    role,
                    &encode("hello", &f).unwrap(),
                    "quic-local",
                    1,
                    1_893_456_000
                )
                .is_err()
            );
        }
    }
}
