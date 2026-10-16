use super::operational_session::{
    AuthorityView, OperationalEndpoint, OperationalRecord, RecordType, Role,
    derive_and_verify_confirmation_key, validate_v01_schedule,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest, Sha256};

#[test]
fn frozen_v01_records_round_trip_exactly_and_enforce_the_six_record_schedule() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/pairing-v2/operational-session-v01.json"
    ))
    .unwrap();
    let records = fixture["records_hex"].as_array().unwrap();
    assert_eq!(records.len(), 6);

    for (sequence, value) in records.iter().enumerate() {
        let raw = hex(&value.as_str().unwrap());
        let record = OperationalRecord::decode(&raw).unwrap();
        assert_eq!(record.sequence(), sequence as u32);
        assert_eq!(record.encode().unwrap(), raw);
        assert_eq!(
            record.expected_type(),
            RecordType::for_sequence(sequence as u32).unwrap()
        );
        assert_eq!(
            record.expected_sender(),
            Role::for_sequence(sequence as u32).unwrap()
        );
    }
}

#[test]
fn record_parser_fails_closed_for_the_frozen_header_and_length_mutants() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/pairing-v2/operational-session-v01.json"
    ))
    .unwrap();
    let valid = hex(fixture["records_hex"][0].as_str().unwrap());
    let mutations = [
        (0, b'X'), // magic substitution
        (9, 2),    // version substitution
        (10, 6),   // unknown/reserved type
        (11, 2),   // direction substitution
        (15, 1),   // sequence substitution
        (19, 0),   // declared length mismatch
    ];
    for (offset, replacement) in mutations {
        let mut changed = valid.clone();
        changed[offset] = replacement;
        assert!(
            OperationalRecord::decode(&changed).is_err(),
            "offset {offset}"
        );
    }
    let mut oversize = valid.clone();
    oversize[16..20].copy_from_slice(&(4097u32).to_be_bytes());
    assert!(OperationalRecord::decode(&oversize).is_err());
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(OperationalRecord::decode(&trailing).is_err());
}

#[test]
fn authority_views_decode_exactly_and_preserve_each_revision_byte() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/pairing-v2/operational-session-v01.json"
    ))
    .unwrap();
    for key in [
        "authority_commitment_a_view_hex",
        "authority_commitment_b_view_hex",
    ] {
        let raw = hex(fixture[key].as_str().unwrap());
        let view = AuthorityView::decode(&raw).unwrap();
        assert_eq!(view.encode().unwrap(), raw);
        assert!(view.is_v01());
    }

    let mut revised = hex(fixture["authority_commitment_a_view_hex"].as_str().unwrap());
    // A changed policy revision is still a syntactically valid *remote* view,
    // but the exact bytes remain available for the later bilateral commitment.
    let position = revised
        .windows(8)
        .position(|window| window == 7u64.to_be_bytes())
        .unwrap();
    revised[position + 7] = 8;
    let view = AuthorityView::decode(&revised).unwrap();
    assert_ne!(view.encode().unwrap(), raw_a(&fixture));
}

#[test]
fn frozen_v01_payloads_form_one_bound_bilateral_schedule() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/pairing-v2/operational-session-v01.json"
    ))
    .unwrap();
    let records = fixture["records_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| OperationalRecord::decode(&hex(value.as_str().unwrap())).unwrap())
        .collect::<Vec<_>>();
    validate_v01_schedule(&records).unwrap();

    let mut replay = records.clone();
    replay[5] = replay[4].clone();
    assert!(validate_v01_schedule(&replay).is_err());

    let mut trailing = records.clone();
    trailing.push(records[5].clone());
    assert!(validate_v01_schedule(&trailing).is_err());
}

#[test]
fn fixture_exporter_derives_the_only_key_that_accepts_both_confirms() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/pairing-v2/operational-session-v01.json"
    ))
    .unwrap();
    let records = fixture["records_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| OperationalRecord::decode(&hex(value.as_str().unwrap())).unwrap())
        .collect::<Vec<_>>();
    let exporter: [u8; 32] = hex(fixture["expected_exporter_output_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let key = derive_and_verify_confirmation_key(&records, exporter).unwrap();
    assert_eq!(
        Sha256::digest(key).as_slice(),
        hex(
            fixture["bilateral_derivation"]["a_confirmation_key_sha256_hex"]
                .as_str()
                .unwrap()
        )
        .as_slice()
    );

    let mut changed_exporter = exporter;
    changed_exporter[0] ^= 1;
    assert!(derive_and_verify_confirmation_key(&records, changed_exporter).is_err());
}

#[tokio::test]
async fn v01_uses_a_fresh_mutual_tls_connection_with_the_operational_alpn() {
    let (a_der, a_key) = identity();
    let (b_der, b_key) = identity();
    let a =
        OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_der.clone(), a_key).unwrap();
    let b =
        OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_der.clone(), b_key).unwrap();
    let expected_a: [u8; 32] = Sha256::digest(&a_der).into();
    let expected_b: [u8; 32] = Sha256::digest(&b_der).into();
    let (a_channel, b_channel) = tokio::join!(
        a.connect(b.local_addr().unwrap(), expected_b),
        b.accept(expected_a)
    );
    let a_channel = a_channel.unwrap();
    let b_channel = b_channel.unwrap();
    assert_eq!(
        a_channel.observed_peer_fingerprint(),
        Sha256::digest(&b_der).as_slice()
    );
    assert_eq!(
        b_channel.observed_peer_fingerprint(),
        Sha256::digest(&a_der).as_slice()
    );
    assert_eq!(a_channel.negotiated_alpn(), b"csf12-operational/1");
    assert_eq!(b_channel.negotiated_alpn(), b"csf12-operational/1");
}

#[tokio::test]
async fn v01_rejects_a_live_tls_peer_that_does_not_match_the_admitted_pin() {
    let (a_der, a_key) = identity();
    let (b_der, b_key) = identity();
    let a =
        OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a_der.clone(), a_key).unwrap();
    let b = OperationalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b_der, b_key).unwrap();
    let (a_result, b_result) = tokio::join!(
        a.connect(b.local_addr().unwrap(), [9; 32]),
        b.accept(Sha256::digest(&a_der).into())
    );
    assert!(a_result.is_err());
    drop(b_result);
}

fn identity() -> (Vec<u8>, rustls::pki_types::PrivateKeyDer<'static>) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.subject_alt_names = vec![rcgen::SanType::URI(
        "urn:control-shift-f12:identity".try_into().unwrap(),
    )];
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    (
        params.self_signed(&key).unwrap().der().to_vec(),
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
}

fn raw_a(fixture: &serde_json::Value) -> Vec<u8> {
    hex(fixture["authority_commitment_a_view_hex"].as_str().unwrap())
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}
