#![cfg(feature = "pairing-v2-experimental")]
use seamless_transport::pairing_v2::{
    codec::{Value, decode, encode},
    operational_wire::*,
};
use tokio::io::AsyncWriteExt;
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
#[test]
fn frozen_request_and_frames_have_exact_independent_bytes() {
    let v = fixture();
    let raw = bytes(&v, "candidate_request_hex");
    assert_eq!(
        CandidateRequest::new([0x12; 16], [0x20; 16], [0x50; 16])
            .encode()
            .unwrap(),
        raw
    );
    assert_eq!(
        CandidateRequest::decode(&raw).unwrap().encode().unwrap(),
        raw
    );
    for (key, kind) in [
        ("candidate_request_frame_hex", FrameKind::CandidateRequest),
        ("candidate_hello_frame_hex", FrameKind::CandidateHello),
    ] {
        let raw = bytes(&v, key);
        let parsed = TransportFrame::decode(&raw).unwrap();
        assert_eq!(parsed.kind, kind);
        assert_eq!(parsed.encode().unwrap(), raw);
    }
}
#[test]
fn request_fields_reject_wrong_type_size_version_alpn_or_limit() {
    let v = fixture();
    let fields = decode(
        "candidate-request",
        &bytes(&v, "candidate_request_hex"),
        &[1, 2, 2, 2, 3, 1],
    )
    .unwrap();
    for (index, bad) in [
        (0, Value::Bool(true)),
        (0, Value::Number(1)),
        (1, Value::Bytes(vec![0; 15])),
        (2, Value::Bytes(vec![0; 17])),
        (3, Value::Bytes(vec![0; 15])),
        (4, Value::Text("csf12-pair/1".into())),
        (4, Value::Text("CSF12-pair/2".into())),
        (5, Value::Bool(true)),
        (5, Value::Number(4097)),
    ] {
        let mut f = fields.clone();
        f[index] = bad;
        assert!(CandidateRequest::decode(&encode("candidate-request", &f).unwrap()).is_err());
    }
}
#[test]
fn frame_rejects_each_truncation_trailing_unknown_type_version_and_oversize_before_body() {
    let raw = bytes(&fixture(), "candidate_request_frame_hex");
    for cut in 0..raw.len() {
        assert!(TransportFrame::decode(&raw[..cut]).is_err());
    }
    for tail in [vec![0], raw.clone()] {
        let mut b = raw.clone();
        b.extend(tail);
        assert!(TransportFrame::decode(&b).is_err());
    }
    for (index, value) in [(0, b'X'), (9, 1), (10, 0), (10, 4)] {
        let mut b = raw.clone();
        b[index] = value;
        assert!(TransportFrame::decode(&b).is_err());
    }
    for (kind, limit) in [
        (FrameKind::CandidateRequest, 1024),
        (FrameKind::CandidateHello, 4096),
        (FrameKind::Handshake, 16384),
    ] {
        let f = TransportFrame {
            kind,
            payload: vec![0; limit],
        };
        assert_eq!(TransportFrame::decode(&f.encode().unwrap()).unwrap(), f);
        let mut oversized = f.encode().unwrap();
        oversized.push(0);
        oversized[11..15].copy_from_slice(&((limit + 1) as u32).to_be_bytes());
        assert!(TransportFrame::decode(&oversized).is_err());
        assert!(
            TransportFrame {
                kind,
                payload: vec![0; limit + 1]
            }
            .encode()
            .is_err()
        );
    }
    let mut b = raw[..15].to_vec();
    b[11..15].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(TransportFrame::decode(&b).is_err());
}
#[tokio::test]
async fn streaming_waits_for_complete_record_eof_and_one_absolute_deadline() {
    let raw = bytes(&fixture(), "candidate_request_frame_hex");
    for split in 0..=raw.len() {
        let (mut tx, mut rx) = tokio::io::duplex(8);
        let raw = raw.clone();
        let writer = tokio::spawn(async move {
            tx.write_all(&raw[..split]).await.unwrap();
            tokio::task::yield_now().await;
            tx.write_all(&raw[split..]).await.unwrap();
            tx.shutdown().await.unwrap();
        });
        let frame = read_record(
            &mut rx,
            tokio::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(frame.kind, FrameKind::CandidateRequest);
        writer.await.unwrap();
    }
    for suffix in [vec![1], raw.clone()] {
        let mut data = raw.clone();
        data.extend(suffix);
        assert!(
            read_record(
                &mut data.as_slice(),
                tokio::time::Instant::now() + std::time::Duration::from_secs(1)
            )
            .await
            .is_err()
        );
    }
    for cut in [0, 1, 14, 15, raw.len() - 1] {
        assert!(
            read_record(
                &mut &raw[..cut],
                tokio::time::Instant::now() + std::time::Duration::from_secs(1)
            )
            .await
            .is_err()
        );
    }
    let (_held, mut rx) = tokio::io::duplex(1);
    assert!(
        read_record(
            &mut rx,
            tokio::time::Instant::now() + std::time::Duration::from_millis(10)
        )
        .await
        .is_err()
    );
}
