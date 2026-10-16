#![cfg(feature = "pairing-v2-experimental")]
use seamless_transport::pairing_v2::{
    codec::{Value, decode, encode},
    sas_words, validate_identity, validate_wordlist,
};

fn fixture(name: &str) -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/pairing-v2")
                .join(name),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn candidate_addendum_bytes_bind_every_field_connection_generation_and_tls_leaf() {
    use seamless_transport::pairing_v2::{CandidateBinding, CandidateHello};
    let v = fixture("interop-v01-candidate-recovery.json");
    let raw = bytes(&v["candidate_hello"], "canonical_hex");
    let hello = CandidateHello::decode(&raw).unwrap();
    assert_eq!(hello.encode().unwrap(), raw);
    let fp: [u8; 32] = bytes(&v["candidate_hello"], "claimed_certificate_sha256_hex")
        .try_into()
        .unwrap();
    let selected = CandidateBinding::select(&hello, "conn-1:local", 7).unwrap();
    assert_eq!(
        selected.digest().as_slice(),
        bytes(&v["candidate_hello"], "sha256_hex")
    );
    assert!(selected.verify(&hello, fp, "conn-1:local", 7));
    assert!(!selected.verify(&hello, [0; 32], "conn-1:local", 7));
    assert!(!selected.verify(&hello, fp, "conn-2:local", 7));
    assert!(!selected.verify(&hello, fp, "conn-1:local", 8));
    for bad in [
        "",
        " conn",
        "conn\n",
        "conn\t",
        "conn\u{1b}",
        "conn\u{202e}",
        "é",
    ] {
        assert!(CandidateBinding::select(&hello, bad, 7).is_err());
        assert!(!selected.verify(&hello, fp, bad, 7));
    }
    let fields = decode("candidate-hello", &raw, &[2, 2, 2, 3, 3, 2, 2, 1]).unwrap();
    for index in 0..fields.len() {
        let mut changed = fields.clone();
        altered(&mut changed[index]);
        let raw = encode("candidate-hello", &changed).unwrap();
        if let Ok(changed) = CandidateHello::decode(&raw) {
            assert!(
                !selected.verify(&changed, fp, "conn-1:local", 7),
                "candidate/{index}"
            );
        }
    }
    for name in [
        "e\u{301}",
        "bad\u{202e}",
        "bad\u{2066}",
        "bad\u{200b}",
        "bad\0",
        "",
    ] {
        let mut changed = fields.clone();
        changed[3] = Value::Text(name.into());
        assert!(CandidateHello::decode(&encode("candidate-hello", &changed).unwrap()).is_err());
    }
    for raw_suite in [
        vec![0, 0],
        vec![0, 1, 0, 3, b'a', b'\n', b'b'],
        vec![0, 2, 0, 1, b'b', 0, 1, b'a'],
        vec![0, 2, 0, 1, b'a', 0, 1, b'a'],
    ] {
        let mut changed = fields.clone();
        changed[5] = Value::Bytes(raw_suite);
        assert!(CandidateHello::decode(&encode("candidate-hello", &changed).unwrap()).is_err());
    }
    for (index, wrong) in [
        (0, Value::Bytes(vec![0; 15])),
        (6, Value::Bytes(vec![0; 31])),
        (7, Value::Bool(true)),
        (7, Value::Number(0)),
        (7, Value::Number(30_001)),
    ] {
        let mut changed = fields.clone();
        changed[index] = wrong;
        assert!(CandidateHello::decode(&encode("candidate-hello", &changed).unwrap()).is_err());
    }
    assert!(CandidateHello::decode(&vec![0; 4097]).is_err());
}

#[test]
fn digest_json_boundary_accepts_only_canonical_lowercase_hex32() {
    use seamless_transport::pairing_v2::decode_hex32;
    assert_eq!(decode_hex32(&"ab".repeat(32)).unwrap(), [0xab; 32]);
    for value in [
        "AB".repeat(32),
        "ab".repeat(31),
        "ab".repeat(33),
        format!(" {}", "ab".repeat(32)),
        "gg".repeat(32),
    ] {
        assert!(decode_hex32(&value).is_err());
    }
}
fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn bytes(v: &serde_json::Value, name: &str) -> Vec<u8> {
    hex(v[name].as_str().unwrap())
}

fn computed_node(der: &[u8]) -> [u8; 16] {
    use sha2::Digest;
    sha2::Sha256::digest(der)[..16].try_into().unwrap()
}
fn resign_v05(mut der: Vec<u8>) -> Vec<u8> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(&der).unwrap();
    let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[0x11; 32]).unwrap();
    let signature = key.sign(cert.tbs_certificate.as_ref());
    let offset = der.len() - 64;
    der[offset..].copy_from_slice(signature.as_ref());
    der
}

#[test]
fn certificate_profile_rejects_correctly_signed_wrong_algorithms_usage_san_and_noncanonical_der() {
    let v = fixture("v05-x509-profile.json");
    let original = bytes(&v, "valid_ed25519_der_hex");
    for (pattern, replacement, occurrence) in [
        ("06032b6570", "06032b656e", 1), // X25519 SPKI, but Ed25519 signature remains valid.
        ("06032b6570", "06032b6571", 2), // Outer signature algorithm differs from inner.
        ("03020780", "03020284", 0),     // digitalSignature + keyCertSign.
        ("6964656e74697479", "6964656e74697478", 0), // Product SAN identity -> identitx.
    ] {
        let mut der = original.clone();
        let from = hex(pattern);
        let to = hex(replacement);
        let positions: Vec<_> = der
            .windows(from.len())
            .enumerate()
            .filter(|(_, w)| *w == from)
            .map(|(n, _)| n)
            .collect();
        let pos = positions[occurrence];
        der[pos..pos + from.len()].copy_from_slice(&to);
        let der = resign_v05(der);
        assert!(
            validate_identity(&der, computed_node(&der), 1_893_456_000).is_err(),
            "{pattern}/{occurrence}"
        );
    }
    let mut invalid_signature = original.clone();
    *invalid_signature.last_mut().unwrap() ^= 1;
    assert!(
        validate_identity(
            &invalid_signature,
            computed_node(&invalid_signature),
            1_893_456_000
        )
        .is_err()
    );
    let mut noncanonical = original;
    noncanonical[1] = 0x83;
    noncanonical.insert(2, 0);
    assert!(validate_identity(&noncanonical, computed_node(&noncanonical), 1_893_456_000).is_err());
}

fn altered(value: &mut Value) {
    match value {
        Value::Text(s) => s.push('!'),
        Value::Bytes(b) => b[0] ^= 1,
        Value::Number(n) => *n += 1,
        Value::Bool(b) => *b = !*b,
    }
}
fn tag(key: &[u8], kind: &str, body: &[u8], signature: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut m = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    m.update(
        &encode(
            kind,
            &[
                Value::Bytes(body.to_vec()),
                Value::Bytes(signature.to_vec()),
            ],
        )
        .unwrap(),
    );
    m.finalize().into_bytes().to_vec()
}

#[test]
fn signed_and_maced_changed_approval_and_finalization_bindings_are_rejected() {
    use seamless_transport::pairing_v2::{Role, SignedEvidence};
    let v = fixture("v01-canonical-transcript.json");
    let ctx = context(&v);
    for (role, suffix, seed) in [(Role::A, "a", 1), (Role::B, "b", 4)] {
        let signing = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        let key = bytes(&v, &format!("k_confirm_{suffix}_hex"));
        let fields = decode(
            "human-decision",
            &bytes(&v, &format!("approve_{suffix}_body_hex")),
            &[3, 2, 2, 3, 3, 1],
        )
        .unwrap();
        for index in 0..fields.len() {
            let mut mutated = fields.clone();
            altered(&mut mutated[index]);
            let body = encode("human-decision", &mutated).unwrap();
            let signature = signing.sign(&body).as_ref().to_vec();
            let mac = tag(&key, "approve-tag", &body, &signature);
            assert!(
                ctx.verify_approval(
                    role,
                    &SignedEvidence { body, signature },
                    Some((&key, &mac))
                )
                .is_err(),
                "approval/{suffix}/{index}"
            );
        }
    }
    let p = bytes(&v, "both_approved_hex").try_into().unwrap();
    for message in v["finalization"].as_array().unwrap() {
        let (role, seed, suffix) = if message["role"] == "A" {
            (Role::A, 1, "a")
        } else {
            (Role::B, 4, "b")
        };
        let signing = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        let key = bytes(&v, &format!("k_confirm_{suffix}_hex"));
        let fields = decode(
            "finalization-body",
            &bytes(message, "body"),
            &[3, 3, 2, 2, 2, 3],
        )
        .unwrap();
        for index in 0..fields.len() {
            let mut mutated = fields.clone();
            altered(&mut mutated[index]);
            let body = encode("finalization-body", &mutated).unwrap();
            let signature = signing.sign(&body).as_ref().to_vec();
            let mac = tag(&key, "finalization-tag", &body, &signature);
            assert!(
                ctx.verify_finalization(
                    message["phase"].as_str().unwrap(),
                    role,
                    p,
                    &SignedEvidence { body, signature },
                    Some((&key, &mac))
                )
                .is_err(),
                "final/{suffix}/{index}"
            );
        }
        let record = SignedEvidence {
            body: bytes(message, "body"),
            signature: bytes(message, "signature"),
        };
        assert!(
            ctx.verify_finalization(
                message["phase"].as_str().unwrap(),
                role,
                p,
                &record,
                Some((&key, &[0; 32]))
            )
            .is_err()
        );
    }
}

#[test]
fn every_recovery_binding_and_wrong_signer_rejects_without_consuming_valid_challenge() {
    use ring::signature::KeyPair;
    use seamless_transport::pairing_v2::{RecoveryFields, RecoverySignatureVerifier, Role};
    let v = fixture("v11-recovery.json");
    let signing = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[b'k'; 32]).unwrap();
    let public = signing.public_key().as_ref().try_into().unwrap();
    let signature = bytes(&v, "signature_hex");
    let original = RecoveryFields {
        attempt_id: [0xaa; 32],
        fc_hash: [0xbb; 32],
        role: Role::A,
        challenger_nonce: b"nonce-1".to_vec(),
        responder_nonce: b"nonce-2".to_vec(),
        tls_exporter: b"exporter".to_vec(),
        identity_generation: 3,
        revocation_generation: 4,
    };
    let fields = decode(
        "recovery-proof",
        &original.encode().unwrap(),
        &[3, 2, 2, 3, 2, 2, 2, 1, 1, 3],
    )
    .unwrap();
    for index in 0..fields.len() {
        let mut changed = fields.clone();
        altered(&mut changed[index]);
        let sig = signing.sign(&encode("recovery-proof", &changed).unwrap());
        let mut verifier = RecoverySignatureVerifier::new(original.clone(), 30_000);
        assert!(
            verifier.verify(public, sig.as_ref(), 1, false).is_err(),
            "recovery/{index}"
        );
        verifier.verify(public, &signature, 2, false).unwrap();
    }
    let other = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[b'x'; 32]).unwrap();
    assert!(
        RecoverySignatureVerifier::new(original, 30_000)
            .verify(
                other.public_key().as_ref().try_into().unwrap(),
                &signature,
                1,
                false
            )
            .is_err()
    );
}

#[test]
fn detached_commitments_and_key_derivation_match_v01_without_candidate_admission() {
    use seamless_transport::pairing_v2::{Role, derive_keys, detached_transcript};
    let v = fixture("v01-canonical-transcript.json");
    let (c, a, t) = detached_transcript(
        &bytes(&v, "hello_a_hex"),
        &bytes(&v, "hello_b_hex"),
        [&bytes(&v, "commit_a_hex"), &bytes(&v, "commit_b_hex")],
        [&bytes(&v, "reveal_a_hex"), &bytes(&v, "reveal_b_hex")],
    )
    .unwrap();
    assert_eq!(c.as_slice(), bytes(&v, "context_hex"));
    assert_eq!(a.as_slice(), bytes(&v, "attempt_id_hex"));
    assert_eq!(t.as_slice(), bytes(&v, "transcript_hex"));
    let reveal = decode("reveal", &bytes(&v, "reveal_b_hex"), &[2, 3, 2, 2]).unwrap();
    let Value::Bytes(pk) = &reveal[2] else {
        panic!()
    };
    let keys = derive_keys(
        zeroize::Zeroizing::new([0x70; 32]),
        pk.as_slice().try_into().unwrap(),
        t,
    )
    .unwrap();
    assert_eq!(
        keys.sas_digest(a).unwrap().as_slice(),
        bytes(&v, "sas_digest_hex")
    );
    let ctx = context(&v);
    for (role, suffix) in [(Role::A, "a"), (Role::B, "b")] {
        ctx.verify_key_proof(
            role,
            &bytes(&v, &format!("proof_signature_{suffix}_hex")),
            &bytes(&v, &format!("proof_tag_{suffix}_hex")),
            &keys,
        )
        .unwrap();
        assert!(
            ctx.verify_key_proof(
                role,
                &bytes(&v, &format!("proof_signature_{suffix}_hex")),
                &[0; 32],
                &keys
            )
            .is_err()
        );
        let mut bad_signature = bytes(&v, &format!("proof_signature_{suffix}_hex"));
        bad_signature[32] ^= 1;
        use hmac::{Hmac, Mac};
        let mut m =
            Hmac::<sha2::Sha256>::new_from_slice(&bytes(&v, &format!("k_confirm_{suffix}_hex")))
                .unwrap();
        m.update(
            &encode(
                "key-proof-tag",
                &[
                    Value::Text("control-shift-f12 pairing v2".into()),
                    Value::Bytes(a.to_vec()),
                    Value::Bytes(t.to_vec()),
                    Value::Text(role.text().into()),
                    Value::Bytes(bad_signature.clone()),
                ],
            )
            .unwrap(),
        );
        assert!(
            ctx.verify_key_proof(role, &bad_signature, &m.finalize().into_bytes(), &keys)
                .is_err()
        );
    }
    assert!(derive_keys(zeroize::Zeroizing::new([0x70; 32]), [0; 32], t).is_err());
    let mut bad = bytes(&v, "reveal_b_hex");
    *bad.last_mut().unwrap() ^= 1;
    assert!(
        detached_transcript(
            &bytes(&v, "hello_a_hex"),
            &bytes(&v, "hello_b_hex"),
            [&bytes(&v, "commit_a_hex"), &bytes(&v, "commit_b_hex")],
            [&bytes(&v, "reveal_a_hex"), &bad]
        )
        .is_err()
    );
}
fn context(v: &serde_json::Value) -> seamless_transport::pairing_v2::EvidenceContext {
    let mut identities = vec![];
    for key in ["hello_a_hex", "hello_b_hex"] {
        let hello = decode(
            "hello",
            &bytes(v, key),
            &[1, 2, 2, 2, 2, 2, 2, 3, 2, 3, 3, 2, 3, 1],
        )
        .unwrap();
        let Value::Bytes(der) = &hello[8] else {
            panic!()
        };
        use sha2::Digest;
        let fp: [u8; 32] = sha2::Sha256::digest(der).into();
        identities
            .push(validate_identity(der, fp[..16].try_into().unwrap(), 1_893_456_000).unwrap());
    }
    seamless_transport::pairing_v2::EvidenceContext::new(
        identities.try_into().ok().unwrap(),
        bytes(v, "attempt_id_hex").try_into().unwrap(),
        bytes(v, "transcript_hex").try_into().unwrap(),
    )
    .unwrap()
}

#[test]
fn approvals_p_and_complete_certificate_match_external_v01() {
    use seamless_transport::pairing_v2::{Role, SignedEvidence};
    let v = fixture("v01-canonical-transcript.json");
    let ctx = context(&v);
    let a = SignedEvidence {
        body: bytes(&v, "approve_a_body_hex"),
        signature: bytes(&v, "approve_a_signature_hex"),
    };
    let b = SignedEvidence {
        body: bytes(&v, "approve_b_body_hex"),
        signature: bytes(&v, "approve_b_signature_hex"),
    };
    ctx.verify_approval(
        Role::A,
        &a,
        Some((
            &bytes(&v, "k_confirm_a_hex"),
            &bytes(&v, "approve_a_tag_hex"),
        )),
    )
    .unwrap();
    ctx.verify_approval(
        Role::B,
        &b,
        Some((
            &bytes(&v, "k_confirm_b_hex"),
            &bytes(&v, "approve_b_tag_hex"),
        )),
    )
    .unwrap();
    let p = ctx.both_approved(&a, &b).unwrap();
    assert_eq!(p.as_slice(), bytes(&v, "both_approved_hex"));
    for m in v["finalization"].as_array().unwrap() {
        let role = if m["role"] == "A" { Role::A } else { Role::B };
        let key = bytes(
            &v,
            if role == Role::A {
                "k_confirm_a_hex"
            } else {
                "k_confirm_b_hex"
            },
        );
        ctx.verify_finalization(
            m["phase"].as_str().unwrap(),
            role,
            p,
            &SignedEvidence {
                body: bytes(m, "body"),
                signature: bytes(m, "signature"),
            },
            Some((&key, &bytes(m, "tag"))),
        )
        .unwrap();
    }
    let fc = ctx
        .verify_fc(&bytes(&v, "finalization_certificate_hex"))
        .unwrap();
    assert_eq!(
        fc.hash().as_slice(),
        bytes(&v, "finalization_certificate_hash_hex")
    );
    assert!(ctx.verify_approval(Role::B, &a, None).is_err());
    assert!(ctx.verify_approval(Role::A, &b, None).is_err());
    assert!(
        ctx.verify_approval(
            Role::A,
            &a,
            Some((
                &bytes(&v, "k_confirm_b_hex"),
                &bytes(&v, "approve_a_tag_hex")
            ))
        )
        .is_err()
    );
}

#[test]
fn every_fc_binding_and_required_signed_record_is_enforced() {
    let v = fixture("v01-canonical-transcript.json");
    let ctx = context(&v);
    let types = [3, 3, 2, 2, 2, 3, 2, 2, 2, 2, 2, 2, 2, 2];
    let fields = decode(
        "finalization-certificate",
        &bytes(&v, "finalization_certificate_hex"),
        &types,
    )
    .unwrap();
    for index in 0..fields.len() {
        let mut changed = fields.clone();
        match &mut changed[index] {
            Value::Text(s) => s.push('!'),
            Value::Bytes(b) => b[0] ^= 1,
            _ => panic!(),
        }
        assert!(
            ctx.verify_fc(&encode("finalization-certificate", &changed).unwrap())
                .is_err(),
            "field {index}"
        );
    }
    for index in 7..14 {
        let mut missing = fields.clone();
        missing[index] = Value::Bytes(vec![]);
        assert!(
            ctx.verify_fc(&encode("finalization-certificate", &missing).unwrap())
                .is_err()
        );
    }
}

#[test]
fn valid_bodies_with_forged_signatures_or_tags_are_not_bilateral_consent() {
    use seamless_transport::pairing_v2::{Role, SignedEvidence};
    let v = fixture("v01-canonical-transcript.json");
    let ctx = context(&v);
    for (role, suffix) in [(Role::A, "a"), (Role::B, "b")] {
        let key = bytes(&v, &format!("k_confirm_{suffix}_hex"));
        let body = bytes(&v, &format!("approve_{suffix}_body_hex"));
        let mut signature = bytes(&v, &format!("approve_{suffix}_signature_hex"));
        let record = SignedEvidence {
            body: body.clone(),
            signature: signature.clone(),
        };
        assert!(
            ctx.verify_approval(role, &record, Some((&key, &[0; 32])))
                .is_err()
        );
        signature[32] ^= 1;
        let forged_tag = tag(&key, "approve-tag", &body, &signature);
        assert!(
            ctx.verify_approval(
                role,
                &SignedEvidence { body, signature },
                Some((&key, &forged_tag))
            )
            .is_err()
        );
    }
    let types = [3, 3, 2, 2, 2, 3, 2, 2, 2, 2, 2, 2, 2, 2];
    let fields = decode(
        "finalization-certificate",
        &bytes(&v, "finalization_certificate_hex"),
        &types,
    )
    .unwrap();
    for index in 7..14 {
        let mut changed = fields.clone();
        let Value::Bytes(raw) = &fields[index] else {
            panic!()
        };
        let mut record = SignedEvidence::decode(raw).unwrap();
        record.signature[32] ^= 1;
        changed[index] = Value::Bytes(record.encode().unwrap());
        assert!(
            ctx.verify_fc(&encode("finalization-certificate", &changed).unwrap())
                .is_err(),
            "signature/{index}"
        );
    }
}

#[test]
fn recovery_signature_matches_external_v11_and_is_one_use() {
    use ring::signature::KeyPair;
    use seamless_transport::pairing_v2::{RecoveryFields, RecoverySignatureVerifier};
    let v = fixture("v11-recovery.json");
    let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[b'k'; 32]).unwrap();
    let fields = RecoveryFields {
        attempt_id: seamless_transport::pairing_v2::decode_hex32(
            v["attempt_id_hex"].as_str().unwrap(),
        )
        .unwrap(),
        fc_hash: seamless_transport::pairing_v2::decode_hex32(v["fc_hash_hex"].as_str().unwrap())
            .unwrap(),
        role: seamless_transport::pairing_v2::Role::A,
        challenger_nonce: bytes(&v, "challenger_nonce_hex"),
        responder_nonce: bytes(&v, "responder_nonce_hex"),
        tls_exporter: bytes(&v, "exporter_hex"),
        identity_generation: 3,
        revocation_generation: 4,
    };
    let mut verifier = RecoverySignatureVerifier::new(fields.clone(), 30_000);
    let public = key.public_key().as_ref().try_into().unwrap();
    let sig = bytes(&v, "signature_hex");
    assert_eq!(key.sign(&fields.encode().unwrap()).as_ref(), sig);
    verifier.verify(public, &sig, 29_999, false).unwrap();
    assert!(verifier.verify(public, &sig, 29_999, false).is_err());
    assert!(
        RecoverySignatureVerifier::new(fields.clone(), 30_000)
            .verify(public, &sig, 30_000, false)
            .is_err()
    );
    assert!(
        RecoverySignatureVerifier::new(fields, 30_000)
            .verify(public, &sig, 1, true)
            .is_err()
    );
}

#[test]
fn canonical_codec_matches_external_v02_and_rejects_ambiguous_input() {
    let v = fixture("v02-serialization.json");
    let expected = hex(v["legal_hex"].as_str().unwrap());
    let values = vec![
        Value::Number(2),
        Value::Text("café".into()),
        Value::Bytes(vec![0, 1, 2, 3]),
    ];
    assert_eq!(encode("hello", &values).unwrap(), expected);
    assert_eq!(decode("hello", &expected, &[1, 3, 2]).unwrap(), values);
    assert!(
        decode(
            "hello",
            &hex(v["unknown_critical_hex"].as_str().unwrap()),
            &[1, 3, 2]
        )
        .is_err()
    );
    let mut trailing = expected.clone();
    trailing.push(0);
    assert!(decode("hello", &trailing, &[1, 3, 2]).is_err());
    for end in 0..expected.len() {
        assert!(decode("hello", &expected[..end], &[1, 3, 2]).is_err());
    }
    let mut wrong_type = expected.clone();
    wrong_type[18] = 3;
    assert!(decode("hello", &wrong_type, &[1, 3, 2]).is_err());
}

#[test]
fn four_words_match_external_v03_and_asset_digest_is_enforced() {
    for case in fixture("v03-sas-mapping.json")["cases"].as_array().unwrap() {
        let digest: [u8; 32] = hex(case["digest_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        assert_eq!(
            serde_json::to_value(sas_words(&digest).unwrap()).unwrap(),
            case["words"]
        );
    }
    let asset = include_bytes!("../src/pairing_v2/bip39-english.txt");
    validate_wordlist(asset).unwrap();
    let mut changed = asset.to_vec();
    changed[0] ^= 1;
    assert!(validate_wordlist(&changed).is_err());
    assert!(validate_wordlist(&asset[..asset.len() - 1]).is_err());
}

#[test]
fn identity_accepts_external_v05_and_rejects_wrong_id_clock_signature_or_trailing_der() {
    let v = fixture("v05-x509-profile.json");
    let der = hex(v["valid_ed25519_der_hex"].as_str().unwrap());
    let node: [u8; 16] = hex(v["node_id_prefix_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let identity = validate_identity(&der, node, 1_893_456_000).unwrap();
    assert_eq!(
        identity.fingerprint().as_slice(),
        hex(v["full_fingerprint_sha256"].as_str().unwrap())
    );
    assert!(validate_identity(&der, [0; 16], 1_893_456_000).is_err());
    assert!(validate_identity(&der, node, 0).is_err());
    assert!(validate_identity(&der, node, 2_000_000_000).is_err());
    let mut changed = der.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(validate_identity(&changed, node, 1_893_456_000).is_err());
    let mut trailing = der;
    trailing.push(0);
    assert!(validate_identity(&trailing, node, 1_893_456_000).is_err());
}
