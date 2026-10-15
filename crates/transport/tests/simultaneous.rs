use seamless_input_protocol::NodeId;
use seamless_transport::quic::*;
use std::time::Duration;
mod support;

// Models an application verifier that approves the claim. Transport must still
// reject a TLS connection with no peer certificate before invoking this seam.
struct ApproveClaim;
impl PeerIdentityVerifier for ApproveClaim {
    fn verify(
        &self,
        _connection: &quinn::Connection,
        _claimed: NodeId,
    ) -> Result<(), TransportError> {
        Ok(())
    }
}

#[tokio::test]
async fn verifier_cannot_authenticate_an_absent_tls_client_identity() {
    let (server, client) = support::configs();
    let options = EndpointOptions {
        verifier: Some(std::sync::Arc::new(ApproveClaim)),
        ..EndpointOptions::default()
    };
    let a = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([1; 16]),
        server.clone(),
        client.clone(),
        options.clone(),
    )
    .unwrap();
    let b = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([2; 16]),
        server,
        client,
        options,
    )
    .unwrap();
    assert!(a.dial(b.local_addr(), "localhost", None).await.is_err());
    assert!(a.sessions().is_empty());
    assert!(b.sessions().is_empty());
}

#[tokio::test]
async fn remote_identity_rejection_does_not_trigger_reconnect() {
    let (server, client) = support::configs();
    let a = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([1; 16]),
        server.clone(),
        client.clone(),
        EndpointOptions::default(),
    )
    .unwrap();
    let options = EndpointOptions {
        verifier: Some(std::sync::Arc::new(ApproveClaim)),
        ..EndpointOptions::default()
    };
    let b = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([2; 16]),
        server,
        client,
        options,
    )
    .unwrap();
    let policy = ReconnectPolicy {
        max_attempts: 2,
        initial_delay: Duration::from_millis(5),
        ..ReconnectPolicy::default()
    };
    assert!(matches!(
        a.reconnect(b.local_addr(), "localhost", None, &policy)
            .await,
        Err(TransportError::IdentityRejected)
    ));
}

#[tokio::test]
async fn untrusted_tls_server_cannot_install_or_reconnect_a_session() {
    let (server_a, client_a) = support::configs();
    let (server_b, client_b) = support::configs();
    let a = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([1; 16]),
        server_a,
        client_a,
        EndpointOptions::default(),
    )
    .unwrap();
    let b = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([2; 16]),
        server_b,
        client_b,
        EndpointOptions::default(),
    )
    .unwrap();
    let policy = ReconnectPolicy {
        max_attempts: 2,
        initial_delay: Duration::from_millis(5),
        ..ReconnectPolicy::default()
    };
    assert!(matches!(
        a.reconnect(b.local_addr(), "localhost", None, &policy)
            .await,
        Err(TransportError::IdentityRejected)
    ));
    assert!(a.sessions().is_empty());
    assert!(b.sessions().is_empty());
}

#[test]
fn simultaneous_dials_choose_the_same_lower_node_on_both_peers() {
    assert_eq!(
        std::any::TypeId::of::<seamless_transport::NodeId>(),
        std::any::TypeId::of::<NodeId>(),
        "transport must consume the shared protocol identity type"
    );
    let a = NodeId([1; 16]);
    let b = NodeId([2; 16]);
    assert_eq!(canonical_initiator(a, b), a);
    assert_eq!(canonical_initiator(b, a), a);
}

#[tokio::test]
async fn real_loopback_simultaneous_dials_retain_one_pending_session_each() {
    let (server, client) = support::configs();
    let a = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([1; 16]),
        server.clone(),
        client.clone(),
        EndpointOptions::default(),
    )
    .unwrap();
    let b = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([2; 16]),
        server,
        client,
        EndpointOptions::default(),
    )
    .unwrap();
    let _ = tokio::join!(
        a.dial(b.local_addr(), "localhost", Some(NodeId([2; 16]))),
        b.dial(a.local_addr(), "localhost", Some(NodeId([1; 16])))
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    for endpoint in [&a, &b] {
        let sessions = endpoint.sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].initiator(), NodeId([1; 16]));
        assert_eq!(sessions[0].trust(), SessionTrust::PendingIdentity);
        assert!(sessions[0].authenticated_connection().is_none());
        assert!(!sessions[0].is_closed());
    }
    assert_eq!(a.sessions()[0].dial_nonce(), b.sessions()[0].dial_nonce());
    assert_eq!(a.sessions()[0].peer(), NodeId([2; 16]));
    assert_eq!(b.sessions()[0].peer(), NodeId([1; 16]));
}

#[tokio::test]
async fn version_mismatch_cannot_install_a_session() {
    let (server, client) = support::configs();
    let a = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([1; 16]),
        server.clone(),
        client.clone(),
        EndpointOptions::default(),
    )
    .unwrap();
    let options = EndpointOptions {
        version: 2,
        ..EndpointOptions::default()
    };
    let b = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([2; 16]),
        server,
        client,
        options,
    )
    .unwrap();
    assert!(matches!(
        a.dial(b.local_addr(), "localhost", None).await,
        Err(TransportError::VersionMismatch)
    ));
    assert!(a.sessions().is_empty());
    assert!(b.sessions().is_empty());
}

#[tokio::test]
async fn expected_identity_mismatch_is_rejected_before_election() {
    let (server, client) = support::configs();
    let a = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([1; 16]),
        server.clone(),
        client.clone(),
        EndpointOptions::default(),
    )
    .unwrap();
    let b = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([2; 16]),
        server,
        client,
        EndpointOptions::default(),
    )
    .unwrap();
    assert!(matches!(
        a.dial(b.local_addr(), "localhost", Some(NodeId([3; 16])))
            .await,
        Err(TransportError::IdentityRejected)
    ));
    assert!(a.sessions().is_empty());
}

#[tokio::test]
async fn heartbeat_preserves_idle_loopback_session() {
    let (server, client) = support::configs();
    let options = EndpointOptions {
        heartbeat_interval: Duration::from_millis(30),
        idle_timeout: Duration::from_millis(120),
        ..EndpointOptions::default()
    };
    let a = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([1; 16]),
        server.clone(),
        client.clone(),
        options.clone(),
    )
    .unwrap();
    let b = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([2; 16]),
        server,
        client,
        options,
    )
    .unwrap();
    let session = a.dial(b.local_addr(), "localhost", None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert!(
        !session.is_closed(),
        "keepalive must span more than three idle windows"
    );
}

#[test]
fn reconnect_schedule_caps_exponential_delay_and_stops() {
    let policy = ReconnectPolicy {
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(25),
        max_attempts: 5,
    };
    assert_eq!(
        policy.delays().unwrap(),
        vec![
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(25),
            Duration::from_millis(25)
        ]
    );
    assert!(
        ReconnectPolicy {
            max_attempts: 0,
            ..policy.clone()
        }
        .delays()
        .is_err()
    );
    assert!(
        ReconnectPolicy {
            max_attempts: 1001,
            ..policy
        }
        .delays()
        .is_err()
    );
    assert!(
        ReconnectPolicy {
            initial_delay: Duration::ZERO,
            ..ReconnectPolicy::default()
        }
        .delays()
        .is_err()
    );
}

#[tokio::test]
async fn reconnect_does_not_retry_incompatible_version() {
    let (server, client) = support::configs();
    let a = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([1; 16]),
        server.clone(),
        client.clone(),
        EndpointOptions::default(),
    )
    .unwrap();
    let b = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([2; 16]),
        server,
        client,
        EndpointOptions {
            version: 2,
            ..EndpointOptions::default()
        },
    )
    .unwrap();
    assert!(matches!(
        a.reconnect(
            b.local_addr(),
            "localhost",
            None,
            &ReconnectPolicy::default()
        )
        .await,
        Err(TransportError::VersionMismatch)
    ));
}

#[tokio::test]
async fn reconnect_to_unavailable_peer_stops_after_bounded_attempts() {
    let unavailable = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = unavailable.local_addr().unwrap();
    let (server, client) = support::configs();
    let options = EndpointOptions {
        handshake_timeout: Duration::from_millis(40),
        ..EndpointOptions::default()
    };
    let endpoint = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([1; 16]),
        server,
        client,
        options,
    )
    .unwrap();
    let policy = ReconnectPolicy {
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(20),
        max_attempts: 3,
    };
    let started = std::time::Instant::now();
    let result = endpoint
        .reconnect(address, "localhost", None, &policy)
        .await;
    assert!(matches!(
        result,
        Err(TransportError::ReconnectExhausted { attempts: 3 })
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(endpoint.sessions().is_empty());
}
