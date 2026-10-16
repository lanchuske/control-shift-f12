#![cfg(feature = "pairing-v2-experimental")]
use seamless_transport::pairing_v2::{
    codec::{Value, decode, encode},
    operational_binding::*,
    operational_wire::ALPN,
};
use std::sync::Arc;
use zeroize::Zeroizing;
fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "fixtures/pairing-v2/transport-v01-approved-fields.json"
    ))
    .unwrap()
}
fn bytes(v: &serde_json::Value, key: &str) -> Vec<u8> {
    let s = v[key].as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn input(v: &serde_json::Value) -> BindingInput {
    BindingInput::new(
        &bytes(v, "candidate_request_hex"),
        &bytes(v, "candidate_hello_hex"),
        &bytes(v, "actual_tls_leaf_der_hex"),
        "quic-a-b-0001",
        7,
        ALPN,
    )
    .unwrap()
}
fn result(v: &serde_json::Value) -> LocalBinding {
    input(v)
        .finish(Zeroizing::new(
            bytes(v, "exporter_output_hex").try_into().unwrap(),
        ))
        .unwrap()
}
#[test]
fn independent_fixture_freezes_context_binding_and_every_replay_field() {
    let v = fixture();
    let i = input(&v);
    assert_eq!(i.exporter_context(), bytes(&v, "exporter_context_hex"));
    let b = result(&v);
    assert_eq!(
        b.digest().as_slice(),
        bytes(&v, "operational_binding_sha256_hex")
    );
    assert_eq!(b.replay_token().as_slice(), bytes(&v, "replay_token_hex"));
}
#[test]
fn claim_cannot_replace_observed_leaf_and_request_echo_rendezvous_suite_alpn_are_mandatory() {
    let v = fixture();
    let request = bytes(&v, "candidate_request_hex");
    let hello = bytes(&v, "candidate_hello_hex");
    let der = bytes(&v, "actual_tls_leaf_der_hex");
    for leaf in [vec![], vec![0], {
        let mut b = der.clone();
        b[0] ^= 1;
        b
    }] {
        assert!(BindingInput::new(&request, &hello, &leaf, "quic-a-b-0001", 7, ALPN).is_err());
    }
    let fields = decode("candidate-hello", &hello, &[2, 2, 2, 3, 3, 2, 2, 1]).unwrap();
    for (index, bad) in [
        (0, Value::Bytes(vec![9; 16])),
        (1, Value::Bytes(vec![9; 16])),
        (5, Value::Bytes(vec![0, 1, 0, 3, b'b', b'a', b'd'])),
        (6, Value::Bytes(vec![9; 32])),
    ] {
        let mut f = fields.clone();
        f[index] = bad;
        assert!(
            BindingInput::new(
                &request,
                &encode("candidate-hello", &f).unwrap(),
                &der,
                "quic-a-b-0001",
                7,
                ALPN
            )
            .is_err()
        );
    }
    for alpn in [b"".as_slice(), b"csf12-pair/1", b"CSF12-pair/2"] {
        assert!(BindingInput::new(&request, &hello, &der, "quic-a-b-0001", 7, alpn).is_err());
    }
    for id in ["", "has space", "é", "\nconn"] {
        assert!(BindingInput::new(&request, &hello, &der, id, 7, ALPN).is_err());
    }
}
#[test]
fn accepted_substitutions_change_binding_and_replay_identity() {
    let v = fixture();
    let original = result(&v);
    let request = bytes(&v, "candidate_request_hex");
    let hello = bytes(&v, "candidate_hello_hex");
    let der = bytes(&v, "actual_tls_leaf_der_hex");
    let exporter = bytes(&v, "exporter_output_hex").try_into().unwrap();
    for (connection, generation) in [("quic-a-b-0002", 7), ("quic-a-b-0001", 8)] {
        let b = BindingInput::new(&request, &hello, &der, connection, generation, ALPN)
            .unwrap()
            .finish(Zeroizing::new(exporter))
            .unwrap();
        assert_ne!(b.digest(), original.digest());
        assert_ne!(b.replay_token(), original.replay_token());
    }
    let mut r = decode("candidate-request", &request, &[1, 2, 2, 2, 3, 1]).unwrap();
    r[1] = Value::Bytes(vec![5; 16]);
    let b = BindingInput::new(
        &encode("candidate-request", &r).unwrap(),
        &hello,
        &der,
        "quic-a-b-0001",
        7,
        ALPN,
    )
    .unwrap()
    .finish(Zeroizing::new(exporter))
    .unwrap();
    assert_ne!(b.digest(), original.digest());
    assert_ne!(b.replay_token(), original.replay_token());
    let mut h = decode("candidate-hello", &hello, &[2, 2, 2, 3, 3, 2, 2, 1]).unwrap();
    h[2] = Value::Bytes(vec![5; 16]);
    let b = BindingInput::new(
        &request,
        &encode("candidate-hello", &h).unwrap(),
        &der,
        "quic-a-b-0001",
        7,
        ALPN,
    )
    .unwrap()
    .finish(Zeroizing::new(exporter))
    .unwrap();
    assert_ne!(b.digest(), original.digest());
    assert_ne!(b.replay_token(), original.replay_token());
    let b = input(&v).finish(Zeroizing::new([0; 32])).unwrap();
    assert_ne!(b.digest(), original.digest());
    assert_eq!(
        b.replay_token(),
        original.replay_token(),
        "exporter must not change the frozen replay token schema"
    );
}
#[test]
fn shared_replay_registry_consumes_atomically_with_one_winner() {
    let registry = Arc::new(TransportReplayRegistry::default());
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let registry = registry.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let binding = result(&fixture());
                barrier.wait();
                registry.consume(&binding).is_ok()
            })
        })
        .collect();
    assert_eq!(
        workers
            .into_iter()
            .map(|w| u32::from(w.join().unwrap()))
            .sum::<u32>(),
        1
    );
    assert!(registry.consume(&result(&fixture())).is_err());
}

#[test]
fn replay_registry_capacity_never_evicts_old_consumption() {
    let v = fixture();
    let registry = TransportReplayRegistry::default();
    let h = bytes(&v, "candidate_hello_hex");
    let der = bytes(&v, "actual_tls_leaf_der_hex");
    for n in 0..=1024u16 {
        let mut id = [0; 16];
        id[..2].copy_from_slice(&n.to_be_bytes());
        let req = seamless_transport::pairing_v2::operational_wire::CandidateRequest::new(
            id, [0x20; 16], [0x50; 16],
        )
        .encode()
        .unwrap();
        let binding = BindingInput::new(&req, &h, &der, "quic-a-b-0001", 7, ALPN)
            .unwrap()
            .finish(Zeroizing::new([7; 32]))
            .unwrap();
        assert_eq!(registry.consume(&binding).is_ok(), n < 1024);
    }
    let req = seamless_transport::pairing_v2::operational_wire::CandidateRequest::new(
        [0; 16], [0x20; 16], [0x50; 16],
    )
    .encode()
    .unwrap();
    let old = BindingInput::new(&req, &h, &der, "quic-a-b-0001", 7, ALPN)
        .unwrap()
        .finish(Zeroizing::new([7; 32]))
        .unwrap();
    assert!(registry.consume(&old).is_err());
}
