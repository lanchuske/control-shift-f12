use super::*;
fn fixture() -> serde_json::Value {
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
fn envelopes() -> Vec<Vec<u8>> {
    fixture()["handshake_envelopes_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| bytes(v.as_str().unwrap()))
        .collect()
}
fn frames() -> Vec<Vec<u8>> {
    fixture()["candidate_frames_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| bytes(v.as_str().unwrap()))
        .collect()
}
#[test]
fn independent_python_oracle_decodes_and_reencodes_all_seventeen_headers() {
    let records = envelopes();
    for (sequence, raw) in records.iter().enumerate() {
        // Independent literal header extraction, not the production encoder.
        assert_eq!(&raw[..8], b"CSF12H2\0");
        assert_eq!(u16::from_be_bytes(raw[8..10].try_into().unwrap()), 2);
        assert_eq!(
            u32::from_be_bytes(raw[12..16].try_into().unwrap()) as usize,
            sequence
        );
        assert_eq!(
            u32::from_be_bytes(raw[16..20].try_into().unwrap()) as usize,
            raw.len() - 20
        );
        let e = Envelope::decode(raw).unwrap();
        assert_eq!(e.encode().unwrap(), *raw);
    }
}
#[test]
fn sequence_is_independently_checked_even_when_type_direction_and_payload_match() {
    let records = envelopes();
    for at in 0..17 {
        let mut g = WireGuard::new();
        for raw in &records[..at] {
            assert!(g.receive_bytes(raw, |_, _| true));
        }
        let mut bad = records[at].clone();
        bad[12..16].copy_from_slice(&((at + 1) as u32).to_be_bytes());
        assert!(!g.receive_bytes(&bad, |_, _| panic!("wrong sequence reached payload")));
        assert!(g.protocol_failed());
    }
}
#[test]
fn raw_ingress_latches_every_malformed_record_before_validation_or_advance() {
    let good = envelopes().remove(0);
    let mut bads: Vec<Vec<u8>> = (0..good.len()).map(|n| good[..n].to_vec()).collect();
    let mut trailing = good.clone();
    trailing.push(0);
    bads.push(trailing);
    for (offset, value) in [(0, 0), (9, 1), (10, 0), (10, 12), (11, 0), (11, 3)] {
        let mut b = good.clone();
        b[offset] = value;
        bads.push(b);
    }
    let mut big = good.clone();
    big[16..20].copy_from_slice(&16385u32.to_be_bytes());
    bads.push(big);
    let mut zero = good[..20].to_vec();
    zero[16..20].fill(0);
    bads.push(zero);
    for bad in bads {
        let mut g = WireGuard::new();
        assert!(!g.receive_bytes(&bad, |_, _| panic!("invalid framing reached crypto")));
        assert_eq!(g.status(), Status::Aborted);
        assert!(g.protocol_failed());
        assert_eq!(g.sequence(), 0);
        assert!(!g.receive_bytes(&good, |_, _| true));
    }
}
#[test]
fn schedule_replay_payload_failure_and_post_complete_events_fail_stop() {
    let records = envelopes();
    for at in 0..17 {
        let mut g = WireGuard::new();
        for raw in &records[..at] {
            assert!(g.receive_bytes(raw, |_, _| true));
        }
        let wrong = &records[(at + 1) % 17];
        assert!(!g.receive_bytes(wrong, |_, _| true));
        assert!(g.protocol_failed());
        assert!(!g.receive_bytes(&records[at], |_, _| true));
        let mut g = WireGuard::new();
        for raw in &records[..at] {
            assert!(g.receive_bytes(raw, |_, _| true));
        }
        assert!(!g.receive_bytes(&records[at], |_, _| false));
        assert_eq!(g.sequence(), at);
        assert!(g.protocol_failed());
    }
    let mut g = WireGuard::new();
    for raw in &records {
        assert!(g.receive_bytes(raw, |_, _| true));
    }
    assert_eq!(g.status(), Status::FcVerified);
    assert!(g.half_close(1));
    assert!(g.half_close(2));
    assert_eq!(g.status(), Status::CompletePendingAuthority);
    assert!(!g.receive_bytes(&records[0], |_, _| true));
    assert_eq!(g.status(), Status::Aborted);
    assert!(g.protocol_failed());
}
#[test]
fn early_or_duplicate_half_close_never_means_approval() {
    let records = envelopes();
    for at in 0..17 {
        let mut g = WireGuard::new();
        for raw in &records[..at] {
            assert!(g.receive_bytes(raw, |_, _| true));
        }
        assert!(!g.half_close(1));
        assert!(g.protocol_failed());
    }
    let mut g = WireGuard::new();
    for raw in &records {
        assert!(g.receive_bytes(raw, |_, _| true));
    }
    assert!(g.half_close(2));
    assert!(!g.half_close(2));
    assert!(g.protocol_failed());
}
#[test]
fn authenticated_cancel_is_separate_but_early_or_invalid_cancel_is_protocol_error() {
    let records = envelopes();
    let cancel = bytes(
        fixture()["cancel_contract"]["fixture_envelope_hex"]
            .as_str()
            .unwrap(),
    );
    let mut g = WireGuard::new();
    for raw in &records[..8] {
        assert!(g.receive_bytes(raw, |_, _| true));
    }
    assert!(g.receive_bytes(&cancel, |i, e| i == 8 && e.kind == 11));
    assert_eq!(g.status(), Status::Cancelled);
    assert!(!g.protocol_failed());
    assert!(!g.receive_bytes(&records[8], |_, _| true));
    assert!(!g.half_close(1));
    assert!(!g.protocol_failed());
    for prefix in [0, 7, 8] {
        let mut g = WireGuard::new();
        for raw in &records[..prefix] {
            assert!(g.receive_bytes(raw, |_, _| true));
        }
        assert!(!g.receive_bytes(&cancel, |_, _| false));
        assert!(g.protocol_failed());
    }
}
#[test]
fn candidate_schedule_requires_matching_responder_and_response_half_close() {
    let f = frames();
    let events = [
        (1, 1, 1),
        (2, 1, 2),
        (3, 1, 2),
        (1, 2, 2),
        (2, 2, 1),
        (3, 2, 1),
    ];
    for invalid_at in 0..6 {
        let mut g = CandidateGuard::new();
        let mut frame = 0;
        for (i, (kind, requester, responder)) in events.iter().copied().enumerate() {
            if i == invalid_at {
                assert!(!g.receive(
                    kind,
                    requester,
                    3 - responder,
                    if kind == 3 { &[] } else { &f[frame] },
                    |_, _| true
                ));
                assert!(g.protocol_failed());
                break;
            }
            assert!(g.receive(
                kind,
                requester,
                responder,
                if kind == 3 { &[] } else { &f[frame] },
                |_, _| true
            ));
            if kind != 3 {
                frame += 1;
            }
        }
    }
    for extra in events {
        let mut g = CandidateGuard::new();
        let mut frame = 0;
        for (kind, requester, responder) in events {
            assert!(g.receive(
                kind,
                requester,
                responder,
                if kind == 3 { &[] } else { &f[frame] },
                |_, _| true
            ));
            if kind != 3 {
                frame += 1;
            }
        }
        assert!(g.complete());
        assert!(!g.receive(extra.0, extra.1, extra.2, &f[0], |_, _| true));
        assert!(g.protocol_failed());
        assert!(!g.complete());
    }
}
#[test]
fn malformed_candidate_and_reordered_streams_abort_without_revival() {
    let f = frames();
    for raw in [vec![], f[0][..14].to_vec(), {
        let mut x = f[0].clone();
        x.push(0);
        x
    }] {
        let mut g = CandidateGuard::new();
        assert!(!g.receive(1, 1, 1, &raw, |_, _| panic!(
            "bad raw reached candidate binding"
        )));
        assert!(g.protocol_failed());
        assert!(!g.receive(1, 1, 1, &f[0], |_, _| true));
    }
    let mut g = CandidateGuard::new();
    assert!(!g.receive(1, 2, 2, &f[2], |_, _| true));
    assert!(g.protocol_failed());
    let mut g = CandidateGuard::new();
    assert!(g.receive(1, 1, 1, &f[0], |_, _| true));
    assert!(!g.receive(2, 1, 2, &f[1], |_, _| false));
    assert!(g.protocol_failed());
}
