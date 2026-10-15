use std::{sync::Arc, time::Duration};

use seamless_input::{
    peer::{Capabilities, PeerMessage, decode_peer_message, encode_peer_message},
    runtime::{Runtime, apply_receive},
};
use seamless_input_core::{
    Display, DisplayId, Point, Topology,
    platform::{AccessState, ClipboardContent, ClipboardOutcome, PlatformClipboard, PlatformInput},
};
use seamless_input_protocol::InputEvent;
use seamless_transport::{EndpointOptions, IdentityStore, PeerEndpoint, PinnedPeer, SessionTrust};

#[derive(Default)]
struct RecordedInput(Vec<InputEvent>);
impl PlatformInput for RecordedInput {
    type Error = ();
    fn access_state(&self) -> AccessState {
        AccessState::Granted
    }
    fn inject(&mut self, event: &InputEvent) -> Result<(), Self::Error> {
        self.0.push(event.clone());
        Ok(())
    }
    fn release_all(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Default)]
struct RecordedClipboard(Vec<ClipboardContent>);
impl PlatformClipboard for RecordedClipboard {
    type Error = ();
    fn access_state(&self) -> AccessState {
        AccessState::Granted
    }
    fn poll(&mut self, _: u64) -> Result<ClipboardOutcome, Self::Error> {
        Ok(ClipboardOutcome::Unchanged)
    }
    fn write_remote(&mut self, content: &ClipboardContent) -> Result<(), Self::Error> {
        self.0.push(content.clone());
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_quic_packet_reaches_runtime_lease_validation_and_native_contract() {
    let roots = tempfile::tempdir().unwrap();
    let mut a = IdentityStore::open_or_create(roots.path().join("a"), "a").unwrap();
    let mut b = IdentityStore::open_or_create(roots.path().join("b"), "b").unwrap();
    a.pin_peer(PinnedPeer::from_identity(&b)).unwrap();
    b.pin_peer(PinnedPeer::from_identity(&a)).unwrap();
    let peer_b = a.peer(b.node_id()).unwrap();
    let peer_a = b.peer(a.node_id()).unwrap();
    let (a_server, a_client) = a.quic_configs_for(peer_b).unwrap();
    let (b_server, b_client) = b.quic_configs_for(peer_a).unwrap();
    let endpoint_a = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        a.node_id(),
        a_server,
        a_client,
        EndpointOptions {
            verifier: Some(Arc::new(a.verifier())),
            ..EndpointOptions::default()
        },
    )
    .unwrap();
    let endpoint_b = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        b.node_id(),
        b_server,
        b_client,
        EndpointOptions {
            verifier: Some(Arc::new(b.verifier())),
            ..EndpointOptions::default()
        },
    )
    .unwrap();
    let session_a = endpoint_a
        .dial(
            endpoint_b.local_addr(),
            "seamless-input.local",
            Some(b.node_id()),
        )
        .await
        .unwrap();
    assert_eq!(session_a.trust(), SessionTrust::Authenticated);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let session_b = loop {
        if let Some(session) = endpoint_b.sessions().into_iter().next() {
            break session;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    };

    let display = Display {
        id: DisplayId {
            node: b.node_id(),
            index: 0,
        },
        origin: Point { x: 0.0, y: 0.0 },
        width: 100.0,
        height: 100.0,
        scale: 1.0,
    };
    let mut runtime = Runtime::new(
        b.node_id(),
        display.id,
        Topology::new(display).unwrap(),
        1_000,
    )
    .unwrap();
    runtime
        .connect_admitted(
            a.node_id(),
            Capabilities::all(),
            b.peer(a.node_id()),
            session_b.trust(),
        )
        .unwrap();

    let epoch = 77;
    for message in [
        PeerMessage::Capabilities {
            epoch,
            capabilities: Capabilities::all(),
        },
        PeerMessage::AcquireLease { epoch },
        PeerMessage::Input {
            epoch,
            sequence: 1,
            event: InputEvent::Key {
                code: 4,
                pressed: true,
            },
        },
    ] {
        session_a
            .send_packet(&encode_peer_message(&message).unwrap())
            .await
            .unwrap();
    }

    let mut input = RecordedInput::default();
    let mut clipboard = RecordedClipboard::default();
    for _ in 0..3 {
        let message = decode_peer_message(&session_b.read_packet().await.unwrap()).unwrap();
        let received = runtime.receive(a.node_id(), message, 1).unwrap();
        apply_receive(&mut input, &mut clipboard, received).unwrap();
    }
    assert_eq!(
        input.0,
        vec![InputEvent::Key {
            code: 4,
            pressed: true,
        }]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_application_stream_times_out_and_drops_only_that_peer() {
    let roots = tempfile::tempdir().unwrap();
    let mut a = IdentityStore::open_or_create(roots.path().join("a"), "a").unwrap();
    let mut b = IdentityStore::open_or_create(roots.path().join("b"), "b").unwrap();
    a.pin_peer(PinnedPeer::from_identity(&b)).unwrap();
    b.pin_peer(PinnedPeer::from_identity(&a)).unwrap();
    let (a_server, a_client) = a.quic_configs_for(a.peer(b.node_id()).unwrap()).unwrap();
    let (b_server, b_client) = b.quic_configs_for(b.peer(a.node_id()).unwrap()).unwrap();
    let options_a = EndpointOptions {
        verifier: Some(Arc::new(a.verifier())),
        packet_read_timeout: Duration::from_millis(50),
        ..EndpointOptions::default()
    };
    let options_b = EndpointOptions {
        verifier: Some(Arc::new(b.verifier())),
        packet_read_timeout: Duration::from_millis(50),
        ..EndpointOptions::default()
    };
    let endpoint_a = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        a.node_id(),
        a_server,
        a_client,
        options_a,
    )
    .unwrap();
    let endpoint_b = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        b.node_id(),
        b_server,
        b_client,
        options_b,
    )
    .unwrap();
    let session_a = endpoint_a
        .dial(
            endpoint_b.local_addr(),
            "seamless-input.local",
            Some(b.node_id()),
        )
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let session_b = loop {
        if let Some(session) = endpoint_b.sessions().into_iter().next() {
            break session;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    };

    let mut partial = session_a
        .authenticated_connection()
        .unwrap()
        .open_uni()
        .await
        .unwrap();
    partial.write_all(&32_u32.to_be_bytes()).await.unwrap();
    partial.write_all(&[0x91]).await.unwrap();

    let started = tokio::time::Instant::now();
    assert!(matches!(
        session_b.read_packet().await,
        Err(seamless_transport::TransportError::Timeout)
    ));
    assert!(started.elapsed() < Duration::from_millis(500));
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            session_b.authenticated_connection().unwrap().closed()
        )
        .await
        .is_ok()
    );
}
