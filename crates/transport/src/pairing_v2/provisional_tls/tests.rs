use crate::pairing_v2::{
    SUITE,
    codec::{Value, encode},
    operational_binding::BindingInput,
    operational_wire::{ALPN, CandidateRequest, FrameKind, TransportFrame, read_record},
    provisional_tls::{ProvisionalChannel, ProvisionalEndpoint, configs, process_owner},
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

fn identity(usage: bool) -> (Vec<u8>, rustls::pki_types::PrivateKeyDer<'static>) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut p = rcgen::CertificateParams::default();
    p.is_ca = rcgen::IsCa::ExplicitNoCa;
    p.subject_alt_names = vec![rcgen::SanType::URI(
        "urn:control-shift-f12:identity".try_into().unwrap(),
    )];
    if usage {
        p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    }
    (
        p.self_signed(&key).unwrap().der().to_vec(),
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
}
fn hello(der: &[u8]) -> Vec<u8> {
    let mut suites = vec![0, 1, 0, SUITE.len() as u8];
    suites.extend(SUITE.as_bytes());
    encode(
        "candidate-hello",
        &[
            Value::Bytes(vec![2; 16]),
            Value::Bytes(vec![3; 16]),
            Value::Bytes(vec![4; 16]),
            Value::Text("Loopback peer".into()),
            Value::Text("macos".into()),
            Value::Bytes(suites),
            Value::Bytes(Sha256::digest(der).to_vec()),
            Value::Number(30_000),
        ],
    )
    .unwrap()
}
async fn pair() -> (
    ProvisionalEndpoint,
    ProvisionalEndpoint,
    ProvisionalChannel,
    ProvisionalChannel,
    Vec<u8>,
) {
    let (a, ak) = identity(true);
    let (b, bk) = identity(true);
    let server = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), b.clone(), bk).unwrap();
    let client = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), a.clone(), ak).unwrap();
    let (outgoing, incoming) = tokio::join!(
        client.connect(server.local_addr().unwrap()),
        server.accept()
    );
    let incoming = incoming.unwrap();
    assert_eq!(incoming.leaf, a);
    (client, server, outgoing.unwrap(), incoming, b)
}
#[tokio::test]
async fn actual_quic_leaf_and_real_exporter_bind_once_without_peer_admission() {
    let (_a, _b, mut channel, peer, der) = pair().await;
    let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    let hello = hello(&der);
    let context = BindingInput::new(
        &request,
        &hello,
        &der,
        channel.connection_id(),
        channel.generation,
        ALPN,
    )
    .unwrap();
    let mut exporter = Zeroizing::new([0u8; 32]);
    channel
        .connection
        .export_keying_material(
            exporter.as_mut(),
            b"EXPORTER-ControlShiftF12-Pairing-v2",
            context.exporter_context(),
        )
        .unwrap();
    let mut other = Zeroizing::new([0u8; 32]);
    peer.connection
        .export_keying_material(
            other.as_mut(),
            b"EXPORTER-ControlShiftF12-Pairing-v2",
            context.exporter_context(),
        )
        .unwrap();
    assert_eq!(
        *exporter, *other,
        "same explicit TLS exporter context on the selected connection"
    );
    let expected = context.finish(exporter).unwrap();
    let actual = channel.bind(&request, &hello).unwrap();
    assert_eq!(actual.digest(), expected.digest());
    assert_eq!(actual.replay_token(), expected.replay_token());
    assert!(process_owner().replay.consume(&actual).is_err());
    assert!(channel.bind(&request, &hello).is_err());
}
#[tokio::test]
async fn actual_leaf_claim_substitution_and_closed_connection_fail_before_binding() {
    let (_a, _b, mut channel, _peer, der) = pair().await;
    let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    let (other, _) = identity(true);
    assert!(channel.bind(&request, &hello(&other)).is_err());
    assert!(channel.bind(&request, &hello(&der)).is_err());
    assert!(channel.connection.close_reason().is_some());
}
#[tokio::test]
async fn process_owner_persists_replay_across_endpoint_lifetimes() {
    let (a, b, mut channel, _peer, der) = pair().await;
    let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    let binding = channel.bind(&request, &hello(&der)).unwrap();
    drop(a);
    drop(b);
    let (leaf, key) = identity(true);
    let new_endpoint =
        ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), leaf, key).unwrap();
    assert!(
        new_endpoint.owner.replay.consume(&binding).is_err(),
        "new endpoint reset process replay"
    );
}
#[tokio::test]
async fn server_without_client_auth_cannot_produce_provisional_channel() {
    let (leaf, key) = identity(true);
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.into()], key)
        .unwrap();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
        )),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    // The original external-connection attack still completes unilateral TLS,
    // but there is now no public way to adopt that connection (compile-fail).
    let (leaf, key) = identity(true);
    let (_, strict) = configs(leaf, key).unwrap();
    let (config, _) = strict.fresh().unwrap();
    let mut external = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    external.set_default_client_config(config);
    let (outgoing, incoming) = tokio::join!(
        external
            .connect(server.local_addr().unwrap(), "pairing.local")
            .unwrap(),
        async { server.accept().await.unwrap().await }
    );
    let outside = outgoing.unwrap();
    let incoming = incoming.unwrap();
    assert!(
        incoming.peer_identity().is_none(),
        "attack precondition: no client cert"
    );
    outside.close(0u32.into(), b"external precondition complete");
    let (leaf, key) = identity(true);
    let client = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), leaf, key).unwrap();
    // Prime the same endpoint with successful mutual TLS: authentication evidence
    // must be per connection, never inherited from this previous connection.
    let (leaf, key) = identity(true);
    let legitimate = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), leaf, key).unwrap();
    let (first, other) = tokio::join!(
        client.connect(legitimate.local_addr().unwrap()),
        legitimate.accept()
    );
    drop(first.unwrap());
    drop(other.unwrap());
    let (outgoing, _incoming) = tokio::join!(client.connect(server.local_addr().unwrap()), async {
        server.accept().await.unwrap().await
    });
    assert!(outgoing.is_err(), "unilateral TLS minted a sealed channel");
}
#[tokio::test]
async fn owner_generations_are_distinct_and_endpoint_drop_revokes_channels() {
    let (client, _server, mut channel, peer, der) = pair().await;
    assert_ne!(channel.generation, peer.generation);
    drop(client);
    assert!(
        !*channel.scope.lock().unwrap(),
        "scope revoked synchronously"
    );
    let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    assert!(channel.bind(&request, &hello(&der)).is_err());
}
#[tokio::test]
async fn revoked_scope_rejects_before_any_network_close_notification() {
    let (_client, _server, mut channel, _peer, der) = pair().await;
    // Inject the local revocation boundary without delivering a network close.
    *channel.scope.lock().unwrap() = false;
    assert!(channel.connection.close_reason().is_none());
    let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    assert!(channel.bind(&request, &hello(&der)).is_err());
}
#[tokio::test]
async fn poisoned_scope_is_fail_closed() {
    let (_client, _server, mut channel, _peer, der) = pair().await;
    let scope = channel.scope.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = scope.lock().unwrap();
            panic!("injected scope poison");
        })
        .join()
        .is_err()
    );
    let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    assert!(channel.bind(&request, &hello(&der)).is_err());
}
#[test]
fn generation_exhaustion_fails_closed_without_wrapping() {
    let owner = super::ProcessOwner {
        replay: Default::default(),
        generation: std::sync::atomic::AtomicU64::new(u64::MAX),
    };
    assert!(owner.generation().is_err());
    assert!(owner.generation().is_err());
}
#[tokio::test]
async fn fragmented_quic_record_and_trailing_or_dropped_record_obey_complete_boundary() {
    let (_a, _b, c, peer, _) = pair().await;
    let payload = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    let frame = TransportFrame {
        kind: FrameKind::CandidateRequest,
        payload,
    }
    .encode()
    .unwrap();
    for mode in 0..4 {
        let mut data = frame.clone();
        if mode == 3 {
            data.truncate(15);
            data[11..15].copy_from_slice(&u32::MAX.to_be_bytes());
        }
        let sender = c.connection.clone();
        let write = tokio::spawn(async move {
            let mut s = sender.open_uni().await.unwrap();
            for chunk in data.chunks(3) {
                s.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
            if mode == 1 {
                s.write_all(&[0]).await.unwrap();
            }
            if mode == 2 {
                s.reset(1u32.into()).unwrap();
            } else {
                s.finish().unwrap();
            }
        });
        let mut receive = peer.connection.accept_uni().await.unwrap();
        let result = read_record(
            &mut receive,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await;
        assert_eq!(result.is_ok(), mode == 0);
        write.await.unwrap();
    }
}

struct ProcessGuard(Option<std::process::Child>);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_process_loopback_observes_real_leaf_exporter_and_only_pending_evidence() {
    let (leaf, key) = identity(true);
    let endpoint =
        ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), leaf.clone(), key).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "pairing_v2::provisional_tls::tests::provisional_process_worker",
            "--nocapture",
        ])
        .env(
            "CSF12_PROVISIONAL_TEST_PEER",
            endpoint.local_addr().unwrap().to_string(),
        )
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = ProcessGuard(Some(child));
    let connection = tokio::time::timeout(Duration::from_secs(5), async {
        endpoint.accept().await.unwrap()
    })
    .await
    .unwrap();
    let (mut send, mut receive) =
        tokio::time::timeout(Duration::from_secs(5), connection.connection.accept_bi())
            .await
            .unwrap()
            .unwrap();
    let request = read_record(
        &mut receive,
        tokio::time::Instant::now() + Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(request.kind, FrameKind::CandidateRequest);
    CandidateRequest::decode(&request.payload).unwrap();
    let frame = TransportFrame {
        kind: FrameKind::CandidateHello,
        payload: hello(&leaf),
    }
    .encode()
    .unwrap();
    for chunk in frame.chunks(7) {
        send.write_all(chunk).await.unwrap();
    }
    send.finish().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
        assert!(std::time::Instant::now() < deadline, "worker deadline");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let output = child.0.take().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("TRANSPORT_BOUND_PENDING"));
}
#[test]
#[ignore = "subprocess helper"]
fn provisional_process_worker() {
    let peer = std::env::var("CSF12_PROVISIONAL_TEST_PEER")
        .unwrap()
        .parse()
        .unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (leaf, key) = identity(true);
            let endpoint =
                ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), leaf, key).unwrap();
            let mut channel = tokio::time::timeout(Duration::from_secs(5), endpoint.connect(peer))
                .await
                .unwrap()
                .unwrap();
            let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
                .encode()
                .unwrap();
            let (mut send, mut receive) = channel.connection.open_bi().await.unwrap();
            let frame = TransportFrame {
                kind: FrameKind::CandidateRequest,
                payload: request.clone(),
            }
            .encode()
            .unwrap();
            for chunk in frame.chunks(2) {
                send.write_all(chunk).await.unwrap();
            }
            send.finish().unwrap();
            let response = read_record(
                &mut receive,
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();
            assert_eq!(response.kind, FrameKind::CandidateHello);
            channel.bind(&request, &response.payload).unwrap();
            println!("TRANSPORT_BOUND_PENDING");
        });
}
#[test]
fn local_profile_and_certificate_key_mismatch_are_rejected() {
    let (bad, key) = identity(false);
    assert!(configs(bad, key).is_err());
    let (a, _) = identity(true);
    let (_, wrong) = identity(true);
    assert!(configs(a, wrong).is_err());
}

#[derive(Debug)]
struct ForgedSigner;
impl rustls::sign::SigningKey for ForgedSigner {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        offered
            .contains(&rustls::SignatureScheme::ED25519)
            .then(|| Box::new(Self) as Box<dyn rustls::sign::Signer>)
    }
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
}
impl rustls::sign::Signer for ForgedSigner {
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(vec![0; 64])
    }
    fn scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ED25519
    }
}
#[tokio::test]
async fn real_tls_rejects_forged_certificate_verify_even_with_valid_leaf_profile() {
    let (leaf, _key) = identity(true);
    let key = rustls::sign::CertifiedKey::new(vec![leaf.into()], Arc::new(ForgedSigner));
    let mut crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(super::ProfileVerifier(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))))
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(key)));
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
        )),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let (leaf, key) = identity(true);
    let client = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), leaf, key).unwrap();
    let outgoing = client.connect(server.local_addr().unwrap());
    let (result, _) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), outgoing),
        async {
            let c = server.accept().await.unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(2), c).await;
        }
    );
    assert!(
        result.unwrap().is_err(),
        "valid public certificate cannot replace private-key possession"
    );
}
#[tokio::test]
async fn actual_remote_bad_profile_and_alpn_downgrade_fail_tls() {
    for bad_profile in [false, true] {
        let (leaf, key) = identity(!bad_profile);
        let mut crypto = rustls::ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(super::ProfileVerifier(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))))
            .with_single_cert(vec![leaf.into()], key)
            .unwrap();
        crypto.alpn_protocols = vec![if bad_profile {
            ALPN.to_vec()
        } else {
            b"csf12-pair/1".to_vec()
        }];
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
            )),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let (leaf, key) = identity(true);
        let client = ProvisionalEndpoint::bind("127.0.0.1:0".parse().unwrap(), leaf, key).unwrap();
        let outgoing = client.connect(server.local_addr().unwrap());
        let (result, _) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(2), outgoing),
            async {
                if let Some(c) = server.accept().await {
                    let _ = tokio::time::timeout(Duration::from_secs(2), c).await;
                }
            }
        );
        assert!(
            result.unwrap().is_err(),
            "remote bad profile or ALPN accepted"
        );
    }
}
