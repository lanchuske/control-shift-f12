use super::*;
use crate::pairing_v2::operational_wire::ALPN;
use std::sync::Arc;
use zeroize::Zeroizing;
fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/pairing-v2/transport-v01-approved-fields.json"
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
fn result(v: &serde_json::Value) -> LocalBinding {
    BindingInput::new(
        &bytes(v, "candidate_request_hex"),
        &bytes(v, "candidate_hello_hex"),
        &bytes(v, "actual_tls_leaf_der_hex"),
        "quic-a-b-0001",
        7,
        ALPN,
    )
    .unwrap()
    .finish(Zeroizing::new([7; 32]))
    .unwrap()
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
        let req =
            crate::pairing_v2::operational_wire::CandidateRequest::new(id, [0x20; 16], [0x50; 16])
                .encode()
                .unwrap();
        let binding = BindingInput::new(&req, &h, &der, "quic-a-b-0001", 7, ALPN)
            .unwrap()
            .finish(Zeroizing::new([7; 32]))
            .unwrap();
        assert_eq!(registry.consume(&binding).is_ok(), n < 1024);
    }
    let req =
        crate::pairing_v2::operational_wire::CandidateRequest::new([0; 16], [0x20; 16], [0x50; 16])
            .encode()
            .unwrap();
    let old = BindingInput::new(&req, &h, &der, "quic-a-b-0001", 7, ALPN)
        .unwrap()
        .finish(Zeroizing::new([7; 32]))
        .unwrap();
    assert!(registry.consume(&old).is_err());
}
