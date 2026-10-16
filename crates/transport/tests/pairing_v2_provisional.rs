#![cfg(feature = "pairing-v2-experimental")]
use rustls::pki_types::PrivatePkcs8KeyDer;
use seamless_transport::pairing_v2::{
    SUITE,
    codec::{Value, encode},
    operational_binding::{BindingInput, TransportReplayRegistry},
    operational_wire::{ALPN, CandidateRequest, FrameKind, TransportFrame, read_record},
    provisional_tls::{ProvisionalChannel, configs},
};
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
    quinn::Endpoint,
    quinn::Endpoint,
    quinn::Connection,
    quinn::Connection,
    Vec<u8>,
) {
    let (a, ak) = identity(true);
    let (b, bk) = identity(true);
    let (server, _) = configs(b.clone(), bk).unwrap();
    let (_, client) = configs(a.clone(), ak).unwrap();
    let server = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client);
    let outgoing = endpoint
        .connect(server.local_addr().unwrap(), "pairing.local")
        .unwrap();
    let (outgoing, bconn) = tokio::join!(outgoing, async { server.accept().await.unwrap().await });
    let bconn = bconn.unwrap();
    let observed = bconn
        .peer_identity()
        .unwrap()
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .unwrap();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].as_ref(), a);
    (endpoint, server, outgoing.unwrap(), bconn, b)
}
#[tokio::test]
async fn actual_quic_leaf_and_real_exporter_bind_once_without_peer_admission() {
    let (_a, _b, c, peer, der) = pair().await;
    let registry = Arc::new(TransportReplayRegistry::default());
    let mut channel = ProvisionalChannel::observe(&c, 7, registry.clone()).unwrap();
    let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    let hello = hello(&der);
    let context =
        BindingInput::new(&request, &hello, &der, channel.connection_id(), 7, ALPN).unwrap();
    let mut exporter = Zeroizing::new([0u8; 32]);
    c.export_keying_material(
        exporter.as_mut(),
        b"EXPORTER-ControlShiftF12-Pairing-v2",
        context.exporter_context(),
    )
    .unwrap();
    let mut other = Zeroizing::new([0u8; 32]);
    peer.export_keying_material(
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
    let mut duplicate = ProvisionalChannel::observe(&c, 7, registry).unwrap();
    assert!(duplicate.bind(&request, &hello).is_err());
    assert!(channel.bind(&request, &hello).is_err());
}
#[tokio::test]
async fn actual_leaf_claim_substitution_and_closed_connection_fail_before_binding() {
    let (_a, _b, c, _peer, der) = pair().await;
    let mut channel = ProvisionalChannel::observe(&c, 1, Arc::default()).unwrap();
    let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
        .encode()
        .unwrap();
    let (other, _) = identity(true);
    assert!(channel.bind(&request, &hello(&other)).is_err());
    assert!(channel.bind(&request, &hello(&der)).is_err());
    assert!(c.close_reason().is_some());
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
        let sender = c.clone();
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
        let mut receive = peer.accept_uni().await.unwrap();
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
    let (server, _) = configs(leaf.clone(), key).unwrap();
    let endpoint = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "provisional_process_worker",
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
        endpoint.accept().await.unwrap().await.unwrap()
    })
    .await
    .unwrap();
    let (mut send, mut receive) =
        tokio::time::timeout(Duration::from_secs(5), connection.accept_bi())
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
            let (_, client) = configs(leaf, key).unwrap();
            let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            endpoint.set_default_client_config(client);
            let connection = tokio::time::timeout(
                Duration::from_secs(5),
                endpoint.connect(peer, "pairing.local").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
            let mut channel = ProvisionalChannel::observe(&connection, 1, Arc::default()).unwrap();
            let request = CandidateRequest::new([1; 16], [2; 16], [3; 16])
                .encode()
                .unwrap();
            let (mut send, mut receive) = connection.open_bi().await.unwrap();
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
        .with_no_client_auth()
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
    let (_, config) = configs(leaf, key).unwrap();
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(config);
    let outgoing = client
        .connect(server.local_addr().unwrap(), "pairing.local")
        .unwrap();
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
            .with_no_client_auth()
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
        let (_, config) = configs(leaf, key).unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(config);
        let outgoing = client
            .connect(server.local_addr().unwrap(), "pairing.local")
            .unwrap();
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
