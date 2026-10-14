use seamless_input::{
    peer::{Capabilities, LeaseError, PeerMessage, PeerRegistry},
    runtime::{Runtime, RuntimeEffect, RuntimeReceive},
};
use seamless_input_core::clipboard::{ClipboardDeduper, ClipboardPayload};
use seamless_input_core::platform::{
    AccessState, ClipboardContent, ClipboardOutcome, PlatformClipboard, PlatformInput,
};
use seamless_input_core::{Display, DisplayId, Edge, Point, Topology};
use seamless_input_protocol::{InputEvent, NodeId};
use seamless_transport::{PinnedPeer, SessionTrust};

fn node(n: u8) -> NodeId {
    NodeId([n; 16])
}
fn display(n: u8) -> Display {
    Display {
        id: DisplayId {
            node: node(n),
            index: 0,
        },
        origin: Point { x: 0.0, y: 0.0 },
        width: 100.0,
        height: 100.0,
        scale: 1.0,
    }
}
fn mesh3() -> Topology {
    let mut t = Topology::new(display(1)).unwrap();
    t.place(display(1).id, Edge::Right, display(2)).unwrap();
    t.place(display(2).id, Edge::Right, display(3)).unwrap();
    t
}
fn admit(runtime: &mut Runtime, n: u8, caps: Capabilities) -> u64 {
    let pin = PinnedPeer {
        node_id: node(n),
        friendly_name: "peer".into(),
        public_identity: vec![n],
        certificate_pin: [n; 32],
    };
    runtime
        .connect_admitted(node(n), caps, Some(&pin), SessionTrust::Authenticated)
        .unwrap()
}

#[test]
fn capability_negotiation_is_intersection() {
    let mut peers = PeerRegistry::new(node(1));
    peers.connected(
        node(2),
        Capabilities {
            input: true,
            text: true,
            png: false,
        },
    );
    assert_eq!(
        peers
            .negotiated(
                node(2),
                Capabilities {
                    input: true,
                    text: false,
                    png: true
                }
            )
            .unwrap(),
        Capabilities {
            input: true,
            text: false,
            png: false
        }
    );
}

#[test]
fn exclusive_lease_rejects_second_controller_and_stale_events() {
    let mut peers = PeerRegistry::new(node(3));
    let first = peers.connected(node(1), Capabilities::all());
    let second = peers.connected(node(2), Capabilities::all());
    assert!(
        peers
            .receive(node(1), PeerMessage::AcquireLease { epoch: first })
            .is_ok()
    );
    assert_eq!(
        peers.receive(node(2), PeerMessage::AcquireLease { epoch: second }),
        Err(LeaseError::Busy)
    );
    assert!(
        peers
            .receive(
                node(1),
                PeerMessage::Input {
                    epoch: first,
                    sequence: 2,
                    event: InputEvent::Pointer { x: 1.0, y: 1.0 }
                }
            )
            .is_ok()
    );
    assert_eq!(
        peers.receive(
            node(1),
            PeerMessage::Input {
                epoch: first,
                sequence: 1,
                event: InputEvent::Pointer { x: 2.0, y: 2.0 }
            }
        ),
        Err(LeaseError::Stale)
    );
}

#[test]
fn routes_across_three_peers_and_returns_local_on_disappearance() {
    let mut runtime = Runtime::new(node(1), display(1).id, mesh3(), 1000).unwrap();
    admit(&mut runtime, 2, Capabilities::all());
    admit(&mut runtime, 3, Capabilities::all());
    let effects = runtime
        .cross(Edge::Right, Point { x: 100.0, y: 50.0 }, 0)
        .unwrap();
    assert!(
        effects
            .iter()
            .any(|e| matches!(e,RuntimeEffect::Send{peer,..} if *peer==node(2)))
    );
    runtime
        .cross(Edge::Right, Point { x: 100.0, y: 50.0 }, 1)
        .unwrap();
    assert_eq!(runtime.active_peer(), node(3));
    let effects = runtime.disconnect(node(3));
    assert_eq!(runtime.active_peer(), node(1));
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, RuntimeEffect::ReleaseLocal))
    );
}

#[tokio::test(start_paused = true)]
async fn reconnect_replaces_session_without_reviving_old_epoch() {
    let mut peers = PeerRegistry::new(node(1));
    let first = peers.connected(node(2), Capabilities::all());
    peers.disconnected(node(2));
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    let second = peers.connected(node(2), Capabilities::all());
    assert!(second > first);
    assert_eq!(
        peers.receive(
            node(2),
            PeerMessage::Input {
                epoch: first,
                sequence: 1,
                event: InputEvent::Pointer { x: 0.0, y: 0.0 }
            }
        ),
        Err(LeaseError::WrongEpoch)
    );
}

#[test]
fn incoming_clipboard_is_capability_checked_and_deduped() {
    let mut runtime = Runtime::new(node(1), display(1).id, mesh3(), 1000).unwrap();
    let epoch = admit(
        &mut runtime,
        2,
        Capabilities {
            input: true,
            text: true,
            png: false,
        },
    );
    let mut source = ClipboardDeduper::new(8);
    let transfer = source
        .accept_local(ClipboardPayload::text("shared"))
        .unwrap()
        .unwrap();
    let message = PeerMessage::Clipboard {
        epoch,
        sequence: 1,
        transfer: transfer.clone(),
    };
    assert_eq!(
        runtime.receive(node(2), message.clone(), 0).unwrap(),
        RuntimeReceive::Clipboard(ClipboardPayload::text("shared"))
    );
    assert_eq!(
        runtime.receive(node(2), message, 0),
        Err(LeaseError::Stale.into())
    );
    let png = source
        .accept_local(ClipboardPayload::png(vec![
            137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1,
            8, 6, 0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 11, 73, 68, 65, 84, 120, 156, 99, 96, 0, 2,
            0, 0, 5, 0, 1, 122, 94, 171, 63, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
        ]))
        .unwrap()
        .unwrap();
    assert_eq!(
        runtime.receive(
            node(2),
            PeerMessage::Clipboard {
                epoch,
                sequence: 2,
                transfer: png
            },
            0,
        ),
        Err(LeaseError::CapabilityDenied.into())
    );
}

#[test]
fn incoming_heartbeat_refreshes_the_active_controller_deadline() {
    let mut runtime = Runtime::new(node(1), display(1).id, mesh3(), 1000).unwrap();
    let epoch = admit(&mut runtime, 2, Capabilities::all());
    runtime
        .cross(Edge::Right, Point { x: 100.0, y: 50.0 }, 0)
        .unwrap();

    assert_eq!(
        runtime
            .receive(node(2), PeerMessage::Heartbeat { epoch }, 900)
            .unwrap(),
        RuntimeReceive::None
    );
    assert!(runtime.tick(1_500).unwrap().is_empty());
    assert_eq!(runtime.active_peer(), node(2));
    assert!(!runtime.tick(1_900).unwrap().is_empty());
    assert_eq!(runtime.active_peer(), node(1));
}

#[test]
fn emergency_return_recovers_local_and_tells_remote_to_release_held_input() {
    let mut runtime = Runtime::new(node(1), display(1).id, mesh3(), 1000).unwrap();
    let epoch = admit(&mut runtime, 2, Capabilities::all());
    runtime
        .cross(Edge::Right, Point { x: 100.0, y: 50.0 }, 0)
        .unwrap();

    let effects = runtime.emergency_return();
    assert_eq!(runtime.active_peer(), node(1));
    assert!(effects.iter().any(|effect| matches!(
        effect,
        RuntimeEffect::Send {
            peer,
            message: PeerMessage::ReleaseLease { epoch: sent_epoch }
        } if peer == &node(2) && sent_epoch == &epoch
    )));
    assert!(
        effects
            .iter()
            .any(|effect| matches!(effect, RuntimeEffect::ReleaseLocal))
    );
    assert!(
        effects
            .iter()
            .any(|effect| matches!(effect, RuntimeEffect::WarpLocal { .. }))
    );
}

#[test]
fn incoming_release_lease_releases_injected_input_on_the_controlled_peer() {
    let mut runtime = Runtime::new(node(1), display(1).id, mesh3(), 1000).unwrap();
    let epoch = admit(&mut runtime, 2, Capabilities::all());
    runtime
        .receive(node(2), PeerMessage::AcquireLease { epoch }, 0)
        .unwrap();
    assert_eq!(
        runtime
            .receive(node(2), PeerMessage::ReleaseLease { epoch }, 1)
            .unwrap(),
        RuntimeReceive::ReleaseInput
    );

    let mut input = FakeInput::default();
    let mut clipboard = FakeClipboard::default();
    seamless_input::runtime::apply_receive(
        &mut input,
        &mut clipboard,
        RuntimeReceive::ReleaseInput,
    )
    .unwrap();
    assert_eq!(input.released, 1);
}

#[test]
fn unpaired_or_unauthenticated_sessions_never_connect() {
    let mut runtime = Runtime::new(node(1), display(1).id, mesh3(), 1000).unwrap();
    let pin = PinnedPeer {
        node_id: node(2),
        friendly_name: "peer".into(),
        public_identity: vec![1],
        certificate_pin: [2; 32],
    };
    assert!(
        runtime
            .connect_admitted(
                node(2),
                Capabilities::all(),
                None,
                SessionTrust::Authenticated
            )
            .is_err()
    );
    assert!(
        runtime
            .connect_admitted(
                node(2),
                Capabilities::all(),
                Some(&pin),
                SessionTrust::PendingIdentity
            )
            .is_err()
    );
    assert!(
        runtime
            .connect_admitted(
                node(2),
                Capabilities::all(),
                Some(&pin),
                SessionTrust::Authenticated
            )
            .is_ok()
    );
}

#[derive(Default)]
struct FakeInput {
    injected: Vec<InputEvent>,
    released: usize,
}
impl PlatformInput for FakeInput {
    type Error = ();
    fn access_state(&self) -> AccessState {
        AccessState::Granted
    }
    fn inject(&mut self, e: &InputEvent) -> Result<(), ()> {
        self.injected.push(e.clone());
        Ok(())
    }
    fn release_all(&mut self) -> Result<(), ()> {
        self.released += 1;
        Ok(())
    }
}
#[derive(Default)]
struct FakeClipboard {
    written: Vec<ClipboardContent>,
}
impl PlatformClipboard for FakeClipboard {
    type Error = ();
    fn access_state(&self) -> AccessState {
        AccessState::Granted
    }
    fn poll(&mut self, _: u64) -> Result<ClipboardOutcome, ()> {
        Ok(ClipboardOutcome::Unchanged)
    }
    fn write_remote(&mut self, c: &ClipboardContent) -> Result<(), ()> {
        self.written.push(c.clone());
        Ok(())
    }
}

#[test]
fn received_data_dispatches_through_shared_platform_traits() {
    let mut input = FakeInput::default();
    let mut clipboard = FakeClipboard::default();
    seamless_input::runtime::apply_receive(
        &mut input,
        &mut clipboard,
        RuntimeReceive::Input(InputEvent::Key {
            code: 4,
            pressed: true,
        }),
    )
    .unwrap();
    seamless_input::runtime::apply_receive(
        &mut input,
        &mut clipboard,
        RuntimeReceive::Clipboard(ClipboardPayload::text("hello")),
    )
    .unwrap();
    assert_eq!(input.injected.len(), 1);
    assert_eq!(
        clipboard.written,
        vec![ClipboardContent::Text("hello".into())]
    );
}
