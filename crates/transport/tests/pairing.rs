use seamless_input_protocol::NodeId;
use seamless_transport::{IdentityStore, PairingCode, PairingError, PairingSession, PinnedPeer};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tempfile::TempDir;
mod support;

fn identity(name: &str) -> (TempDir, IdentityStore) {
    let dir = TempDir::new().unwrap();
    let store = IdentityStore::open_or_create(dir.path(), name).unwrap();
    (dir, store)
}

fn complete_pairing(offer: PairingSession, accept: PairingSession) -> (PinnedPeer, PinnedPeer) {
    let offer_message = offer.message().to_vec();
    let accept_message = accept.message().to_vec();
    let (offer_pending, offer_confirmation) = offer.finish(&accept_message).unwrap();
    let (accept_pending, accept_confirmation) = accept.finish(&offer_message).unwrap();
    let offer_peer = offer_pending.confirm(&accept_confirmation).unwrap();
    let accept_peer = accept_pending.confirm(&offer_confirmation).unwrap();
    (offer_peer, accept_peer)
}

#[test]
fn six_word_codes_have_at_least_sixty_four_bits_of_entropy() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    let code = PairingCode::generate(now).unwrap();
    assert_eq!(code.phrase().split_whitespace().count(), 6);
    assert!(PairingCode::entropy_bits() >= 64);
    assert!(!format!("{code:?}").contains(code.phrase()));
}

#[test]
fn code_expires_after_five_minutes() {
    let (_, alice) = identity("Alice");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    let mut code = PairingCode::generate(now).unwrap();
    assert!(matches!(
        PairingSession::offer(&alice, &mut code, now + Duration::from_secs(301)),
        Err(PairingError::Expired)
    ));
}

#[test]
fn code_is_consumed_once_even_if_first_exchange_is_abandoned() {
    let (_, alice) = identity("Alice");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    let mut code = PairingCode::generate(now).unwrap();
    let _first = PairingSession::offer(&alice, &mut code, now).unwrap();
    assert!(matches!(
        PairingSession::offer(&alice, &mut code, now),
        Err(PairingError::Consumed)
    ));
}

#[test]
fn matching_codes_create_reciprocal_pins() {
    let (_, alice) = identity("Alice");
    let (_, bob) = identity("Bob");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    let mut code = PairingCode::generate(now).unwrap();
    let phrase = code.phrase().to_owned();
    let offer = PairingSession::offer(&alice, &mut code, now).unwrap();
    let accept = PairingSession::accept(&bob, &phrase).unwrap();
    let (bob_seen_by_alice, alice_seen_by_bob) = complete_pairing(offer, accept);
    assert_eq!(bob_seen_by_alice.node_id, bob.node_id());
    assert_eq!(alice_seen_by_bob.node_id, alice.node_id());
    assert_eq!(bob_seen_by_alice.friendly_name, "Bob");
    assert_eq!(alice_seen_by_bob.friendly_name, "Alice");
}

#[test]
fn wrong_code_fails_key_confirmation() {
    let (_, alice) = identity("Alice");
    let (_, bob) = identity("Bob");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    let mut code = PairingCode::generate(now).unwrap();
    let offer = PairingSession::offer(&alice, &mut code, now).unwrap();
    let accept = PairingSession::accept(&bob, "abandon ability able about above absent").unwrap();
    let offer_message = offer.message().to_vec();
    let accept_message = accept.message().to_vec();
    let (pending, _) = offer.finish(&accept_message).unwrap();
    let (_, wrong_confirmation) = accept.finish(&offer_message).unwrap();
    assert!(matches!(
        pending.confirm(&wrong_confirmation),
        Err(PairingError::ConfirmationMismatch)
    ));
}

#[test]
fn confirmation_replay_is_rejected() {
    let (_, alice) = identity("Alice");
    let (_, bob) = identity("Bob");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    let mut code = PairingCode::generate(now).unwrap();
    let phrase = code.phrase().to_owned();
    let offer = PairingSession::offer(&alice, &mut code, now).unwrap();
    let accept = PairingSession::accept(&bob, &phrase).unwrap();
    let offer_message = offer.message().to_vec();
    let accept_message = accept.message().to_vec();
    let (pending, confirmation) = offer.finish(&accept_message).unwrap();
    let (_, peer_confirmation) = accept.finish(&offer_message).unwrap();
    let mut replay = peer_confirmation.clone();
    replay.session_id = confirmation.session_id;
    assert!(matches!(
        pending.confirm(&replay),
        Err(PairingError::ConfirmationMismatch)
    ));
}

#[test]
fn passive_transcript_does_not_contain_or_hash_the_code() {
    let (_, alice) = identity("Alice");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    let mut code = PairingCode::generate(now).unwrap();
    let phrase = code.phrase().to_owned();
    let direct_hash = Sha256::digest(phrase.as_bytes());
    let offer = PairingSession::offer(&alice, &mut code, now).unwrap();
    let transcript = offer.message();
    assert!(
        !transcript
            .windows(phrase.len())
            .any(|w| w == phrase.as_bytes())
    );
    assert!(!transcript.windows(32).any(|w| w == direct_hash.as_slice()));
}

#[test]
fn certificate_pin_mismatch_is_rejected() {
    let (_, alice) = identity("Alice");
    let (_, bob) = identity("Bob");
    let record = PinnedPeer {
        node_id: bob.node_id(),
        friendly_name: "Bob".into(),
        public_identity: bob.certificate_der().to_vec(),
        certificate_pin: [7; 32],
    };
    assert!(matches!(
        alice.validate_peer_certificate(&record, bob.certificate_der()),
        Err(PairingError::PinMismatch)
    ));
}

#[test]
fn unpair_removes_only_selected_peer() {
    let (dir, mut alice) = identity("Alice");
    let (_, bob) = identity("Bob");
    let (_, carol) = identity("Carol");
    alice.pin_peer(PinnedPeer::from_identity(&bob)).unwrap();
    alice.pin_peer(PinnedPeer::from_identity(&carol)).unwrap();
    alice.unpair(bob.node_id()).unwrap();
    let reopened = IdentityStore::open_or_create(dir.path(), "ignored").unwrap();
    assert!(reopened.peer(bob.node_id()).is_none());
    assert!(reopened.peer(carol.node_id()).is_some());
}

#[cfg(unix)]
#[test]
fn failed_pin_persistence_does_not_change_in_memory_or_on_disk() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, mut alice) = identity("Alice");
    let (_, bob) = identity("Bob");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = alice.pin_peer(PinnedPeer::from_identity(&bob));
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    assert!(matches!(result, Err(PairingError::Io(_))));
    assert!(alice.peer(bob.node_id()).is_none());
    let reopened = IdentityStore::open_or_create(dir.path(), "ignored").unwrap();
    assert!(reopened.peer(bob.node_id()).is_none());
}

#[cfg(unix)]
#[test]
fn failed_unpair_persistence_keeps_trust_in_memory_and_on_disk() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, mut alice) = identity("Alice");
    let (_, bob) = identity("Bob");
    alice.pin_peer(PinnedPeer::from_identity(&bob)).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = alice.unpair(bob.node_id());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    assert!(matches!(result, Err(PairingError::Io(_))));
    assert!(alice.peer(bob.node_id()).is_some());
    let reopened = IdentityStore::open_or_create(dir.path(), "ignored").unwrap();
    assert!(reopened.peer(bob.node_id()).is_some());
}

#[test]
fn peer_store_contains_only_public_pairing_material() {
    let (dir, mut alice) = identity("Alice");
    let (_, bob) = identity("Bob");
    alice.pin_peer(PinnedPeer::from_identity(&bob)).unwrap();
    let peers: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("peers.json")).unwrap()).unwrap();
    let entry = &peers.as_array().unwrap()[0];
    let keys: std::collections::BTreeSet<_> = entry
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "certificate_pin",
            "friendly_name",
            "node_id",
            "public_identity"
        ]
        .into_iter()
        .collect()
    );
    assert!(
        !std::fs::read_to_string(dir.path().join("peers.json"))
            .unwrap()
            .contains("private")
    );
}

#[cfg(unix)]
#[test]
fn identity_and_peer_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, mut alice) = identity("Alice");
    let (_, bob) = identity("Bob");
    alice.pin_peer(PinnedPeer::from_identity(&bob)).unwrap();
    let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
    let identity_mode = std::fs::metadata(dir.path().join("identity.json"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let peers_mode = std::fs::metadata(dir.path().join("peers.json"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
    assert_eq!(identity_mode, 0o600);
    assert_eq!(peers_mode, 0o600);
}

#[test]
fn public_node_id_is_derived_from_identity_not_friendly_name() {
    let (_, first) = identity("same");
    let (_, second) = identity("same");
    assert_ne!(first.node_id(), second.node_id());
    assert_ne!(first.node_id(), NodeId([0; 16]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_mutual_tls_accepts_the_paired_certificates() {
    let (_, alice) = identity("Alice");
    let (_, bob) = identity("Bob");
    let bob_record = PinnedPeer::from_identity(&bob);
    let alice_record = PinnedPeer::from_identity(&alice);
    let (alice_server, alice_client) = alice.quic_configs_for(&bob_record).unwrap();
    let (bob_server, bob_client) = bob.quic_configs_for(&alice_record).unwrap();
    let alice_endpoint =
        quinn::Endpoint::server(alice_server, "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut bob_endpoint =
        quinn::Endpoint::server(bob_server, "127.0.0.1:0".parse().unwrap()).unwrap();
    bob_endpoint.set_default_client_config(bob_client);
    let incoming = alice_endpoint.accept();
    let outgoing = bob_endpoint
        .connect(alice_endpoint.local_addr().unwrap(), "seamless-input.local")
        .unwrap();
    let (accepted, connected) =
        tokio::join!(async { incoming.await.unwrap().await.unwrap() }, outgoing);
    connected.unwrap();
    accepted.close(0u32.into(), b"done");
    drop(alice_client);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_mutual_tls_rejects_an_unpaired_certificate() {
    let (_, alice) = identity("Alice");
    let (_, bob) = identity("Bob");
    let (_, mallory) = identity("Mallory");
    let bob_record = PinnedPeer::from_identity(&bob);
    let alice_record = PinnedPeer::from_identity(&alice);
    let (alice_server, _) = alice.quic_configs_for(&bob_record).unwrap();
    let (_, mallory_client) = mallory.quic_configs_for(&alice_record).unwrap();
    let alice_endpoint =
        quinn::Endpoint::server(alice_server, "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut mallory_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    mallory_endpoint.set_default_client_config(mallory_client);
    let incoming = alice_endpoint.accept();
    let outgoing = mallory_endpoint
        .connect(alice_endpoint.local_addr().unwrap(), "seamless-input.local")
        .unwrap();
    let (accepted, connected) = tokio::join!(async { incoming.await.unwrap().await }, outgoing);
    assert!(accepted.is_err());
    if let Ok(connection) = connected {
        assert!(
            tokio::time::timeout(Duration::from_secs(1), connection.closed())
                .await
                .is_ok()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_endpoint_marks_mutually_pinned_session_authenticated() {
    use seamless_transport::{EndpointOptions, PeerEndpoint, SessionTrust};
    let (_alice_dir, mut alice) = identity("Alice");
    let (_bob_dir, mut bob) = identity("Bob");
    let alice_record = PinnedPeer::from_identity(&alice);
    let bob_record = PinnedPeer::from_identity(&bob);
    alice.pin_peer(bob_record.clone()).unwrap();
    bob.pin_peer(alice_record.clone()).unwrap();
    let (alice_server, alice_client) = alice.quic_configs_for(&bob_record).unwrap();
    let (bob_server, bob_client) = bob.quic_configs_for(&alice_record).unwrap();
    let alice_endpoint = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        alice.node_id(),
        alice_server,
        alice_client,
        EndpointOptions {
            verifier: Some(Arc::new(alice.verifier())),
            ..EndpointOptions::default()
        },
    )
    .unwrap();
    let bob_endpoint = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        bob.node_id(),
        bob_server,
        bob_client,
        EndpointOptions {
            verifier: Some(Arc::new(bob.verifier())),
            ..EndpointOptions::default()
        },
    )
    .unwrap();
    if alice.node_id() < bob.node_id() {
        alice_endpoint
            .dial(
                bob_endpoint.local_addr(),
                "seamless-input.local",
                Some(bob.node_id()),
            )
            .await
            .unwrap();
    } else {
        bob_endpoint
            .dial(
                alice_endpoint.local_addr(),
                "seamless-input.local",
                Some(alice.node_id()),
            )
            .await
            .unwrap();
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let sessions = [alice_endpoint.sessions(), bob_endpoint.sessions()];
        if sessions.iter().all(|items| items.len() == 1) {
            assert!(
                sessions
                    .iter()
                    .all(|items| items[0].trust() == SessionTrust::Authenticated)
            );
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    alice_endpoint.revoke(bob.node_id());
    assert!(alice_endpoint.sessions().is_empty());
    assert!(
        bob_endpoint
            .dial(
                alice_endpoint.local_addr(),
                "seamless-input.local",
                Some(alice.node_id()),
            )
            .await
            .is_err(),
        "a revoked peer must not be readmitted by a stale endpoint verifier"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn temporary_quic_stream_pairs_two_peers() {
    let (_alice_dir, mut alice) = identity("Alice");
    let (_bob_dir, mut bob) = identity("Bob");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    let mut code = PairingCode::generate(now).unwrap();
    let phrase = code.phrase().to_owned();
    let (server, client) = support::configs();
    let server_endpoint = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client);
    let incoming = server_endpoint.accept();
    let outgoing = client_endpoint
        .connect(server_endpoint.local_addr().unwrap(), "localhost")
        .unwrap();
    let (server_connection, client_connection) =
        tokio::join!(async { incoming.await.unwrap().await.unwrap() }, outgoing);
    let client_connection = client_connection.unwrap();
    let (seen_by_alice, seen_by_bob) = tokio::join!(
        seamless_transport::pair_offer_over_quic(&client_connection, &mut alice, &mut code, now),
        seamless_transport::pair_accept_over_quic(&server_connection, &mut bob, &phrase),
    );
    assert_eq!(seen_by_alice.unwrap().node_id, bob.node_id());
    assert_eq!(seen_by_bob.unwrap().node_id, alice.node_id());
    assert!(alice.peer(bob.node_id()).is_some());
    assert!(bob.peer(alice.node_id()).is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn temporary_quic_stream_rejects_wrong_code() {
    let (_alice_dir, mut alice) = identity("Alice");
    let (_bob_dir, mut bob) = identity("Bob");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    let mut code = PairingCode::generate(now).unwrap();
    let (server, client) = support::configs();
    let server_endpoint = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client);
    let incoming = server_endpoint.accept();
    let outgoing = client_endpoint
        .connect(server_endpoint.local_addr().unwrap(), "localhost")
        .unwrap();
    let (server_connection, client_connection) =
        tokio::join!(async { incoming.await.unwrap().await.unwrap() }, outgoing);
    let client_connection = client_connection.unwrap();
    let (offer_result, accept_result) = tokio::join!(
        seamless_transport::pair_offer_over_quic(&client_connection, &mut alice, &mut code, now),
        seamless_transport::pair_accept_over_quic(
            &server_connection,
            &mut bob,
            "abandon ability able about above absent"
        ),
    );
    assert!(matches!(
        offer_result,
        Err(PairingError::ConfirmationMismatch)
    ));
    assert!(matches!(
        accept_result,
        Err(PairingError::ConfirmationMismatch)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn temporary_pairing_is_bounded_when_the_peer_never_opens_a_stream() {
    let (_alice_dir, mut alice) = identity("Alice");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    let mut code = PairingCode::generate(now).unwrap();
    let (server, client) = support::configs();
    let server_endpoint = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client);
    let incoming = server_endpoint.accept();
    let outgoing = client_endpoint
        .connect(server_endpoint.local_addr().unwrap(), "localhost")
        .unwrap();
    let (_server_connection, client_connection) =
        tokio::join!(async { incoming.await.unwrap().await.unwrap() }, outgoing);
    let result = seamless_transport::pair_offer_over_quic_with_timeout(
        &client_connection.unwrap(),
        &mut alice,
        &mut code,
        now,
        Duration::from_millis(20),
    )
    .await;
    assert!(matches!(result, Err(PairingError::TimedOut)));
}
