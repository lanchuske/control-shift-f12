use crate::{
    config::{ConfigError, ConfigStore, ConfigV1, LiveConfig, PeerConfig},
    cursor::CursorContinuity,
    peer::{Capabilities, RemoteDisplay, decode_peer_message, encode_peer_message},
    runtime::{Runtime, RuntimeEffect, RuntimeError, apply_receive},
};
use rand::{RngCore, rngs::OsRng};
use seamless_discovery::Discovery;
#[cfg(not(test))]
use seamless_input_core::platform::PlatformDisplays;
use seamless_input_core::{
    Display, DisplayId, NodeId, Point, Topology,
    clipboard::ClipboardPayload,
    platform::{
        AccessState, ClipboardContent, ClipboardOutcome, LogicalDisplay, PlatformClipboard,
        PlatformInput,
    },
};
use seamless_input_protocol::VERSION;
use seamless_transport::{
    EndpointOptions, IdentityStore, PairingError, PeerEndpoint, PeerSession, ReconnectPolicy,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, task::JoinHandle};

pub const INPUT_SERVICE_INTERVAL: Duration = Duration::from_millis(5);
const CAPTURE_DRAIN_BUDGET: usize = 64;

#[derive(Clone, Debug)]
pub struct AppPaths {
    pub root: PathBuf,
    pub config: PathBuf,
    pub identity: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self, ConfigError> {
        let root = if let Some(root) = std::env::var_os("SEAMLESS_INPUT_HOME") {
            PathBuf::from(root)
        } else {
            ConfigStore::default_path()?
                .parent()
                .ok_or(ConfigError::UserConfigUnavailable)?
                .to_path_buf()
        };
        Ok(Self {
            config: root.join("config.toml"),
            identity: root.join("identity"),
            root,
        })
    }

    pub fn config_store(&self) -> Result<ConfigStore, ConfigError> {
        ConfigStore::new(self.config.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorStatus {
    pub discovered: usize,
    pub authenticated_sessions: usize,
    pub displays: usize,
    pub clipboard: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReport {
    pub config: &'static str,
    pub input: &'static str,
    pub clipboard: &'static str,
    pub displays: String,
    pub discovery: &'static str,
    pub udp_transport: &'static str,
    pub identity: &'static str,
}

impl CapabilityReport {
    pub fn measure(paths: &AppPaths) -> Self {
        let config = paths
            .config_store()
            .and_then(|store| store.load_or_default())
            .map(|_| "PASS")
            .unwrap_or("FAIL");
        let identity = if identity_root_has_material(&paths.identity) {
            "PASS (configured)"
        } else {
            "PASS (not configured)"
        };
        let discovery = Discovery::new(VERSION)
            .and_then(|mut value| value.browse(Duration::ZERO))
            .map(|_| "PASS")
            .unwrap_or("FAIL");
        let udp_transport = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .map(|_| "PASS")
            .unwrap_or("FAIL");
        let mut platform = NativePlatform::new();
        let input = access_label(platform.input_access());
        let clipboard = access_label(platform.clipboard_access());
        let displays = match platform.displays() {
            Ok(displays) if !displays.is_empty() => format!("PASS ({})", displays.len()),
            Ok(_) => "FAIL (none found)".into(),
            Err(_) => "FAIL".into(),
        };
        Self {
            config,
            input,
            clipboard,
            displays,
            discovery,
            udp_transport,
            identity,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("identity setup failed: {0}")]
    Identity(#[from] PairingError),
    #[error("discovery failed: {0}")]
    Discovery(String),
    #[error("no usable local display is available")]
    NoDisplay,
    #[error("runtime setup failed")]
    Runtime,
    #[error("platform probe failed: {0}")]
    Platform(String),
    #[error("peer data plane failed: {0}")]
    DataPlane(String),
    #[error(
        "native input capture could not start: {0}. Enable input access for Control Shift F12 and restart it"
    )]
    Capture(String),
}

struct PeerLink {
    peer: NodeId,
    endpoint: PeerEndpoint,
    instance: String,
}

struct InboundPacket {
    peer: NodeId,
    packet: Result<Vec<u8>, String>,
}

enum PeerPacketOutcome {
    Received(crate::runtime::RuntimeReceive),
    Isolated { recovery: Vec<RuntimeEffect> },
}

fn process_peer_packet(
    runtime: &mut Runtime,
    peer: NodeId,
    packet: Result<Vec<u8>, String>,
    now_ms: u64,
) -> PeerPacketOutcome {
    let received = packet
        .and_then(|bytes| decode_peer_message(&bytes))
        .and_then(|message| {
            runtime
                .receive(peer, message, now_ms)
                .map_err(|_| "peer packet violates runtime policy".into())
        });
    match received {
        Ok(received) => PeerPacketOutcome::Received(received),
        Err(_) => PeerPacketOutcome::Isolated {
            recovery: runtime.disconnect(peer),
        },
    }
}

pub struct NativeSupervisor {
    identity: IdentityStore,
    identity_root: PathBuf,
    discovery: Discovery,
    live_config: LiveConfig,
    links: Vec<PeerLink>,
    sessions: BTreeMap<NodeId, PeerSession>,
    readers: BTreeMap<NodeId, JoinHandle<()>>,
    inbound_tx: mpsc::UnboundedSender<InboundPacket>,
    inbound_rx: mpsc::UnboundedReceiver<InboundPacket>,
    runtime: Runtime,
    platform: NativePlatform,
    admitted: BTreeSet<NodeId>,
    started: Instant,
    last_heartbeat_ms: u64,
    local_displays: Vec<LogicalDisplay>,
    remote_displays: BTreeMap<NodeId, Vec<RemoteDisplay>>,
    cursor: CursorContinuity,
    capture: NativeCapture,
    #[cfg(test)]
    suppress_native_apply: bool,
    #[cfg(test)]
    observed_received: Vec<crate::runtime::RuntimeReceive>,
}

impl NativeSupervisor {
    pub fn bootstrap(paths: &AppPaths) -> Result<Self, SupervisorError> {
        let store = paths.config_store()?;
        if !store.path().exists() {
            store.save(&Default::default())?;
        }
        let identity = IdentityStore::open_or_create(&paths.identity, "SeamlessInput peer")?;
        let mut discovery = Discovery::new(VERSION).map_err(SupervisorError::Discovery)?;
        let mut platform = NativePlatform::new();
        let displays = platform.displays()?;
        let first = displays.first().ok_or(SupervisorError::NoDisplay)?;
        synchronize_known_displays(&store, &identity, &displays)?;
        let live_config = store.live_reload()?;
        let remote_displays = BTreeMap::new();
        let topology = topology_from_config(
            identity.node_id(),
            &displays,
            &remote_displays,
            live_config.current(),
        )
        .map_err(|_| SupervisorError::Runtime)?;
        let local_display = display(identity.node_id(), first);
        let cursor = CursorContinuity::new(local_display.id);
        let runtime = Runtime::new(
            identity.node_id(),
            DisplayId {
                node: identity.node_id(),
                index: first.index,
            },
            topology,
            8_000,
        )
        .map_err(|_| SupervisorError::Runtime)?;

        let mut links = Vec::new();
        for peer in identity.peers() {
            links.push(create_peer_link(&identity, &mut discovery, peer)?);
        }
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let capture = NativeCapture::install()
            .map_err(|error| SupervisorError::Capture(error.to_string()))?;

        Ok(Self {
            identity,
            identity_root: paths.identity.clone(),
            discovery,
            live_config,
            links,
            sessions: BTreeMap::new(),
            readers: BTreeMap::new(),
            inbound_tx,
            inbound_rx,
            runtime,
            platform,
            admitted: BTreeSet::new(),
            started: Instant::now(),
            last_heartbeat_ms: 0,
            local_displays: displays,
            remote_displays,
            cursor,
            capture,
            #[cfg(test)]
            suppress_native_apply: false,
            #[cfg(test)]
            observed_received: Vec::new(),
        })
    }

    pub async fn tick(&mut self) -> Result<SupervisorStatus, SupervisorError> {
        self.refresh_peer_membership().await?;
        if let Ok(Some(config)) = self.live_config.poll() {
            let displays = self.platform.displays()?;
            self.local_displays = displays.clone();
            if let Ok(topology) = topology_from_config(
                self.identity.node_id(),
                &displays,
                &self.remote_displays,
                &config,
            ) {
                let first = displays.first().ok_or(SupervisorError::NoDisplay)?;
                let effects = self
                    .runtime
                    .reconfigure(
                        DisplayId {
                            node: self.identity.node_id(),
                            index: first.index,
                        },
                        topology,
                        8_000,
                    )
                    .map_err(|_| SupervisorError::Runtime)?;
                self.execute_effects(effects).await?;
            }
        }
        let discovered_peers = self
            .discovery
            .browse(Duration::from_millis(25))
            .map_err(SupervisorError::Discovery)?;
        let discovered = discovered_peers.len();
        let local_displays = self.platform.displays()?;
        self.local_displays = local_displays.clone();
        let displays = local_displays.len();
        let now_ms = self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let clipboard = match self.platform.poll_clipboard(now_ms)? {
            ClipboardOutcome::Changed(content) => {
                let payload = match content {
                    ClipboardContent::Text(text) => ClipboardPayload::Text(text),
                    ClipboardContent::Png(bytes) => ClipboardPayload::Png(bytes),
                };
                let effects = self
                    .runtime
                    .offer_clipboard(payload)
                    .map_err(|_| SupervisorError::Runtime)?;
                self.execute_effects(effects).await?;
                "changed"
            }
            ClipboardOutcome::Disabled => "disabled",
            ClipboardOutcome::Pending => "pending",
            ClipboardOutcome::Unchanged => "unchanged",
        };
        let effects = self
            .runtime
            .tick(now_ms)
            .map_err(|_| SupervisorError::Runtime)?;
        self.execute_effects(effects).await?;

        if now_ms.saturating_sub(self.last_heartbeat_ms) >= 2_000 {
            self.last_heartbeat_ms = now_ms;
            self.execute_effects(self.runtime.heartbeat_effects())
                .await?;
        }

        self.dial_discovered(&discovered_peers).await;

        let available: Vec<_> = self
            .links
            .iter()
            .flat_map(|link| link.endpoint.sessions())
            .collect();
        let mut newly_admitted = Vec::new();
        for session in available {
            if self.admitted.contains(&session.peer()) {
                continue;
            }
            let Some(pin) = self.identity.peer(session.peer()) else {
                continue;
            };
            self.runtime
                .connect_admitted(
                    session.peer(),
                    Capabilities::all(),
                    Some(pin),
                    session.trust(),
                )
                .map_err(|error| match error {
                    RuntimeError::SessionNotTrusted => SupervisorError::Runtime,
                    _ => SupervisorError::Runtime,
                })?;
            self.admitted.insert(session.peer());
            self.sessions.insert(session.peer(), session.clone());
            newly_admitted.push(session.peer());
            self.spawn_reader(session);
        }
        for peer in newly_admitted {
            let epoch = self
                .runtime
                .peer_epoch(peer)
                .ok_or(SupervisorError::Runtime)?;
            self.execute_effects(vec![
                RuntimeEffect::Send {
                    peer,
                    message: crate::peer::PeerMessage::Capabilities {
                        epoch,
                        capabilities: Capabilities::all(),
                    },
                },
                RuntimeEffect::Send {
                    peer,
                    message: crate::peer::PeerMessage::Displays {
                        epoch,
                        displays: local_displays.iter().map(|display| display.index).collect(),
                    },
                },
                RuntimeEffect::Send {
                    peer,
                    message: crate::peer::PeerMessage::DisplayGeometry {
                        epoch,
                        displays: self.local_displays.iter().map(remote_display).collect(),
                    },
                },
            ])
            .await?;
        }

        self.drain_inbound(now_ms).await?;

        Ok(SupervisorStatus {
            discovered,
            authenticated_sessions: self.admitted.len(),
            displays,
            clipboard,
        })
    }

    pub fn input_access(&self) -> AccessState {
        self.platform.input_access()
    }

    pub async fn service_input(&mut self) -> Result<(), SupervisorError> {
        let now_ms = self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        self.drain_capture(now_ms, CAPTURE_DRAIN_BUDGET).await?;
        self.capture
            .set_remote(self.runtime.active_peer() != self.identity.node_id());
        Ok(())
    }

    async fn refresh_peer_membership(&mut self) -> Result<(), SupervisorError> {
        let fresh = IdentityStore::open_or_create(&self.identity_root, "SeamlessInput peer")?;
        // Links are the live resource inventory. Comparing the durable store
        // against them also retries a partially failed add on the next tick.
        let current: BTreeSet<_> = self.links.iter().map(|link| link.peer).collect();
        let retained: BTreeSet<_> = fresh.peers().map(|peer| peer.node_id).collect();
        let revoked: Vec<_> = current.difference(&retained).copied().collect();
        let added: Vec<_> = retained.difference(&current).copied().collect();
        for peer in revoked.iter().copied() {
            for link in &self.links {
                link.endpoint.revoke(peer);
            }
            self.sessions.remove(&peer);
            self.admitted.remove(&peer);
            if let Some(task) = self.readers.remove(&peer) {
                task.abort();
            }
            let effects = self.runtime.disconnect(peer);
            self.execute_effects(effects).await?;
        }
        for peer in &revoked {
            if let Some(index) = self.links.iter().position(|link| link.peer == *peer) {
                let link = self.links.remove(index);
                // Revocation and endpoint teardown already happened. A stale
                // mDNS advertisement must not keep a revoked peer admitted.
                let _ = self.discovery.unpublish(&link.instance);
            }
        }
        for peer in added.iter().copied() {
            let pinned = fresh.peer(peer).ok_or(SupervisorError::Runtime)?;
            self.links
                .push(create_peer_link(&fresh, &mut self.discovery, pinned)?);
        }
        self.identity = fresh;
        if !revoked.is_empty() || !added.is_empty() {
            let displays = self.platform.displays()?;
            synchronize_known_displays(&self.live_config.store(), &self.identity, &displays)?;
        }
        Ok(())
    }

    async fn dial_discovered(&mut self, discovered: &[seamless_discovery::DiscoveredPeer]) {
        let policy = ReconnectPolicy {
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_millis(50),
            max_attempts: 1,
        };
        for link in &self.links {
            if self
                .sessions
                .get(&link.peer)
                .is_some_and(|session| !session.is_closed())
            {
                continue;
            }
            'candidate: for peer in discovered
                .iter()
                .filter(|peer| peer.compatible && !peer.advertisement.pairable)
            {
                for address in &peer.advertisement.addresses {
                    let attempt = tokio::time::timeout(
                        Duration::from_millis(250),
                        link.endpoint.reconnect(
                            *address,
                            "seamless-input.local",
                            Some(link.peer),
                            &policy,
                        ),
                    )
                    .await;
                    if let Ok(Ok(_)) = attempt {
                        break 'candidate;
                    }
                }
            }
        }
    }

    fn spawn_reader(&mut self, session: PeerSession) {
        if self.readers.contains_key(&session.peer()) {
            return;
        }
        let peer = session.peer();
        let sender = self.inbound_tx.clone();
        let task = tokio::spawn(async move {
            loop {
                let packet = session
                    .read_packet()
                    .await
                    .map_err(|error| error.to_string());
                let closed = packet.is_err();
                if sender.send(InboundPacket { peer, packet }).is_err() || closed {
                    break;
                }
            }
        });
        self.readers.insert(peer, task);
    }

    async fn drain_inbound(&mut self, now_ms: u64) -> Result<(), SupervisorError> {
        while let Ok(inbound) = self.inbound_rx.try_recv() {
            match process_peer_packet(&mut self.runtime, inbound.peer, inbound.packet, now_ms) {
                PeerPacketOutcome::Received(received) => {
                    #[cfg(test)]
                    self.observed_received.push(received.clone());
                    match received {
                        crate::runtime::RuntimeReceive::Displays(displays) => {
                            record_remote_display_indices(
                                &self.live_config.store(),
                                inbound.peer,
                                &displays,
                            )?;
                        }
                        crate::runtime::RuntimeReceive::DisplayGeometry(displays) => {
                            record_remote_display_indices(
                                &self.live_config.store(),
                                inbound.peer,
                                &displays
                                    .iter()
                                    .map(|display| display.index)
                                    .collect::<Vec<_>>(),
                            )?;
                            self.remote_displays.insert(inbound.peer, displays);
                            let local = self.platform.displays()?;
                            self.local_displays = local.clone();
                            let first = local.first().ok_or(SupervisorError::NoDisplay)?;
                            let topology = topology_from_config(
                                self.identity.node_id(),
                                &local,
                                &self.remote_displays,
                                self.live_config.current(),
                            )?;
                            let effects = self
                                .runtime
                                .reconfigure(
                                    DisplayId {
                                        node: self.identity.node_id(),
                                        index: first.index,
                                    },
                                    topology,
                                    8_000,
                                )
                                .map_err(|_| SupervisorError::Runtime)?;
                            self.execute_effects(effects).await?;
                        }
                        received => {
                            #[cfg(test)]
                            if self.suppress_native_apply {
                                continue;
                            }
                            let received = self.platform.prepare_remote_receive(received)?;
                            apply_receive(
                                &mut self.platform.input,
                                &mut self.platform.clipboard,
                                received,
                            )
                            .map_err(|_| SupervisorError::Runtime)?;
                        }
                    }
                }
                PeerPacketOutcome::Isolated { recovery } => {
                    if let Some(session) = self.sessions.remove(&inbound.peer) {
                        session.close(b"peer packet rejected");
                    }
                    self.admitted.remove(&inbound.peer);
                    if let Some(task) = self.readers.remove(&inbound.peer) {
                        task.abort();
                    }
                    self.execute_effects(recovery).await?;
                }
            }
        }
        Ok(())
    }

    async fn drain_capture(&mut self, now_ms: u64, budget: usize) -> Result<(), SupervisorError> {
        let captured = self.capture.drain(budget);
        for captured in captured {
            let effects = if captured.emergency {
                self.runtime.emergency_return()
            } else if let Some(event) = captured.event {
                let mut effects = Vec::new();
                if let seamless_input_protocol::InputEvent::Pointer { x, y } = event {
                    let native = Point { x, y };
                    let logical = capture_point_to_logical(native, &self.local_displays)
                        .ok_or_else(|| {
                            SupervisorError::Platform(
                                "captured pointer is outside the measured local display geometry"
                                    .into(),
                            )
                        })?;
                    let active = self.runtime.active_geometry().clone();
                    let point = self.cursor.observe(logical, &active);
                    if let Some((edge, crossing)) =
                        crate::cursor::bounded_edge_crossing(&active, point)
                    {
                        effects = self
                            .runtime
                            .cross(edge, crossing, now_ms)
                            .map_err(|_| SupervisorError::Runtime)?;
                        if self.runtime.active_display() != active.id
                            && let Some(mapped) = effect_pointer(&effects)
                        {
                            self.cursor.warp(self.runtime.active_display(), mapped);
                        }
                    }
                    if effects.is_empty() {
                        effects.extend(
                            self.runtime
                                .route(seamless_input_protocol::InputEvent::Pointer {
                                    x: point.x,
                                    y: point.y,
                                })
                                .map_err(|_| SupervisorError::Runtime)?,
                        );
                    }
                    if self.runtime.active_peer() != self.identity.node_id() {
                        let first = self
                            .local_displays
                            .first()
                            .ok_or(SupervisorError::NoDisplay)?;
                        let anchor =
                            crate::cursor::display_center(&display(self.identity.node_id(), first));
                        self.platform
                            .warp_local(anchor)
                            .map_err(SupervisorError::Platform)?;
                        self.cursor.recenter_native(anchor);
                    } else if self.runtime.active_display() != active.id
                        && let Some(mapped) = effect_pointer(&effects)
                    {
                        // The local Warp effect is injected and therefore
                        // filtered by both native capture hooks. Record its
                        // destination explicitly as the next physical baseline.
                        self.cursor.recenter_native(mapped);
                    }
                } else {
                    effects.extend(
                        self.runtime
                            .route(event)
                            .map_err(|_| SupervisorError::Runtime)?,
                    );
                }
                effects
            } else {
                Vec::new()
            };
            self.execute_effects(effects).await?;
        }
        Ok(())
    }

    async fn execute_effects(
        &mut self,
        effects: Vec<RuntimeEffect>,
    ) -> Result<(), SupervisorError> {
        let mut first_error = None;
        let mut failed_peers = BTreeSet::new();
        for effect in effects {
            let result = match effect {
                // A captured local event is already being delivered by the OS;
                // executing this effect means deliberately leaving it alone.
                RuntimeEffect::Local(_) => Ok(()),
                RuntimeEffect::ReleaseLocal => self
                    .platform
                    .input
                    .release_all()
                    .map_err(|error| error.to_string()),
                RuntimeEffect::WarpLocal { point, .. } => self.platform.warp_local(point),
                RuntimeEffect::Send { peer, message } => {
                    let packet = encode_peer_message(&message);
                    let result = match (self.sessions.get(&peer), packet) {
                        (Some(session), Ok(packet)) => session
                            .send_packet(&packet)
                            .await
                            .map_err(|error| error.to_string()),
                        (None, _) => Err("peer session is unavailable".into()),
                        (_, Err(error)) => Err(error),
                    };
                    if result.is_err() {
                        failed_peers.insert(peer);
                    }
                    Ok(())
                }
            };
            if first_error.is_none() {
                first_error = result.err();
            }
        }
        if let Some(error) = first_error {
            return Err(SupervisorError::DataPlane(error));
        }
        for peer in failed_peers {
            self.sessions.remove(&peer);
            self.admitted.remove(&peer);
            if let Some(task) = self.readers.remove(&peer) {
                task.abort();
            }
            for recovery in self.runtime.disconnect(peer) {
                match recovery {
                    RuntimeEffect::ReleaseLocal => self
                        .platform
                        .input
                        .release_all()
                        .map_err(|error| SupervisorError::DataPlane(error.to_string()))?,
                    RuntimeEffect::WarpLocal { point, .. } => self
                        .platform
                        .warp_local(point)
                        .map_err(SupervisorError::DataPlane)?,
                    RuntimeEffect::Local(_) | RuntimeEffect::Send { .. } => {}
                }
            }
        }
        Ok(())
    }
}

fn create_peer_link(
    identity: &IdentityStore,
    discovery: &mut Discovery,
    peer: &seamless_transport::PinnedPeer,
) -> Result<PeerLink, SupervisorError> {
    let (server, client) = identity.quic_configs_for(peer)?;
    let endpoint = PeerEndpoint::bind(
        SocketAddr::new(local_lan_ip(), 0),
        identity.node_id(),
        server,
        client,
        EndpointOptions {
            verifier: Some(Arc::new(identity.verifier())),
            ..EndpointOptions::default()
        },
    )
    .map_err(|_| SupervisorError::Runtime)?;
    let instance = random_instance();
    discovery
        .publish(&instance, endpoint.local_addr(), false)
        .map_err(SupervisorError::Discovery)?;
    Ok(PeerLink {
        peer: peer.node_id,
        endpoint,
        instance,
    })
}

/// Build runtime routing from the exact topology persisted by the TUI. Local
/// display geometry is measured; remote displays are omitted until an
/// authenticated peer advertises its real geometry.
pub fn topology_from_config(
    local: NodeId,
    local_displays: &[LogicalDisplay],
    remote_displays: &BTreeMap<NodeId, Vec<RemoteDisplay>>,
    config: &ConfigV1,
) -> Result<Topology, ConfigError> {
    let first = local_displays
        .first()
        .ok_or_else(|| ConfigError::Invalid("no local display".into()))?;
    let root_id = DisplayId {
        node: local,
        index: first.index,
    };
    let mut known = BTreeMap::new();
    for value in local_displays {
        known.insert(
            DisplayId {
                node: local,
                index: value.index,
            },
            display(local, value),
        );
    }
    for (node, displays) in remote_displays {
        for value in displays {
            let candidate = Display {
                id: DisplayId {
                    node: *node,
                    index: value.index,
                },
                origin: Point {
                    x: value.origin_x,
                    y: value.origin_y,
                },
                width: value.width,
                height: value.height,
                scale: value.scale,
            };
            candidate
                .validate()
                .map_err(|error| ConfigError::Invalid(error.to_string()))?;
            known.insert(candidate.id, candidate);
        }
    }
    let mut positions = BTreeMap::new();
    positions.insert(root_id, (0, 0));
    for placement in &config.placements {
        let id = parse_display_key(&placement.display)?;
        if known.contains_key(&id) {
            positions.insert(id, (placement.x, placement.y));
        }
    }
    let root_position = positions.get(&root_id).copied().unwrap_or((0, 0));
    for position in positions.values_mut() {
        position.0 -= root_position.0;
        position.1 -= root_position.1;
    }
    let mut topology = Topology::new(known[&root_id].clone())
        .map_err(|error| ConfigError::Invalid(error.to_string()))?;
    let mut placed = BTreeSet::from([root_id]);
    while placed.len() < positions.len() {
        let next = positions.iter().find_map(|(id, position)| {
            if placed.contains(id) {
                return None;
            }
            placed.iter().find_map(|anchor| {
                edge_between(positions[anchor], *position).map(|edge| (*id, *anchor, edge))
            })
        });
        let Some((id, anchor, edge)) = next else {
            return Err(ConfigError::Invalid(
                "configured displays must form one cardinal topology".into(),
            ));
        };
        topology
            .place(anchor, edge, known[&id].clone())
            .map_err(|error| ConfigError::Invalid(error.to_string()))?;
        placed.insert(id);
    }
    Ok(topology)
}

fn synchronize_known_displays(
    store: &ConfigStore,
    identity: &IdentityStore,
    displays: &[LogicalDisplay],
) -> Result<(), ConfigError> {
    let mut config = store.load_or_default()?;
    let local_id = node_hex(identity.node_id());
    let mut peers = vec![PeerConfig {
        node_id: local_id.clone(),
        name: identity.friendly_name().into(),
        displays: displays
            .iter()
            .map(|display| display.index.to_string())
            .collect(),
    }];
    for peer in identity.peers() {
        let id = node_hex(peer.node_id);
        let configured = config
            .peers
            .iter()
            .find(|configured| configured.node_id == id);
        peers.push(PeerConfig {
            node_id: id,
            name: peer.friendly_name.clone(),
            displays: configured
                .map(|peer| peer.displays.clone())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| vec!["0".into()]),
        });
    }
    config.peers = peers;
    let local_key = format!(
        "{local_id}:{}",
        displays.first().map(|display| display.index).unwrap_or(0)
    );
    if !config
        .placements
        .iter()
        .any(|placement| placement.display == local_key)
    {
        config.placements.push(crate::config::Placement {
            display: local_key,
            x: 0,
            y: 0,
        });
    }
    store.save(&config)
}

pub fn record_remote_display_indices(
    store: &ConfigStore,
    peer: NodeId,
    indices: &[u32],
) -> Result<(), ConfigError> {
    let mut normalized: Vec<_> = indices.iter().copied().take(32).collect();
    normalized.sort_unstable();
    normalized.dedup();
    if normalized.is_empty() {
        return Ok(());
    }
    let mut config = store.load_or_default()?;
    let id = node_hex(peer);
    let Some(configured) = config.peers.iter_mut().find(|value| value.node_id == id) else {
        return Ok(());
    };
    let normalized: Vec<_> = normalized
        .into_iter()
        .map(|index| index.to_string())
        .collect();
    if configured.displays == normalized {
        return Ok(());
    }
    configured.displays = normalized;
    store.save(&config)
}

fn node_hex(node: NodeId) -> String {
    node.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_node(value: &str) -> Result<NodeId, ConfigError> {
    if value.len() != 32 {
        return Err(ConfigError::Invalid(
            "node id must be 32 hex characters".into(),
        ));
    }
    let mut bytes = [0_u8; 16];
    for (index, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let text = std::str::from_utf8(chunk)
            .map_err(|_| ConfigError::Invalid("node id is not hex".into()))?;
        bytes[index] = u8::from_str_radix(text, 16)
            .map_err(|_| ConfigError::Invalid("node id is not hex".into()))?;
    }
    Ok(NodeId(bytes))
}

fn parse_display_key(value: &str) -> Result<DisplayId, ConfigError> {
    let (node, index) = value
        .rsplit_once(':')
        .ok_or_else(|| ConfigError::Invalid("display key is invalid".into()))?;
    Ok(DisplayId {
        node: parse_node(node)?,
        index: index
            .parse()
            .map_err(|_| ConfigError::Invalid("display index is invalid".into()))?,
    })
}

fn edge_between(anchor: (i32, i32), candidate: (i32, i32)) -> Option<seamless_input_core::Edge> {
    use seamless_input_core::Edge;
    match (candidate.0 - anchor.0, candidate.1 - anchor.1) {
        (-1, 0) => Some(Edge::Left),
        (1, 0) => Some(Edge::Right),
        (0, -1) => Some(Edge::Top),
        (0, 1) => Some(Edge::Bottom),
        _ => None,
    }
}

fn effect_pointer(effects: &[RuntimeEffect]) -> Option<Point> {
    effects.iter().rev().find_map(|effect| match effect {
        RuntimeEffect::WarpLocal { point, .. } => Some(*point),
        RuntimeEffect::Send {
            message:
                crate::peer::PeerMessage::Input {
                    event: seamless_input_protocol::InputEvent::Pointer { x, y },
                    ..
                },
            ..
        } => Some(Point { x: *x, y: *y }),
        _ => None,
    })
}

#[cfg(target_os = "macos")]
fn capture_point_to_logical(point: Point, _displays: &[LogicalDisplay]) -> Option<Point> {
    (point.x.is_finite() && point.y.is_finite()).then_some(point)
}

#[cfg(target_os = "windows")]
fn capture_point_to_logical(point: Point, displays: &[LogicalDisplay]) -> Option<Point> {
    crate::cursor::physical_to_logical(point, displays)
}

#[derive(Clone, Debug, PartialEq)]
struct CapturedInput {
    event: Option<seamless_input_protocol::InputEvent>,
    emergency: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureEnqueueAction {
    Continue,
    RecoverLocal,
}

struct CaptureBufferState {
    emergency: bool,
    ordered: VecDeque<CapturedInput>,
}

#[derive(Clone)]
struct CaptureBuffer {
    capacity: usize,
    state: Arc<Mutex<CaptureBufferState>>,
}

impl CaptureBuffer {
    fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "capture capacity must be non-zero");
        Self {
            capacity,
            state: Arc::new(Mutex::new(CaptureBufferState {
                emergency: false,
                ordered: VecDeque::with_capacity(capacity),
            })),
        }
    }

    fn push(&self, captured: CapturedInput) -> CaptureEnqueueAction {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if captured.emergency {
            state.ordered.clear();
            state.emergency = true;
            return CaptureEnqueueAction::RecoverLocal;
        }
        let pointer = matches!(
            captured.event,
            Some(seamless_input_protocol::InputEvent::Pointer { .. })
        );
        if pointer
            && let Some(last) = state.ordered.back_mut()
            && matches!(
                last.event,
                Some(seamless_input_protocol::InputEvent::Pointer { .. })
            )
        {
            *last = captured;
            return CaptureEnqueueAction::Continue;
        }
        if state.ordered.len() == self.capacity {
            state.ordered.clear();
            state.emergency = true;
            return CaptureEnqueueAction::RecoverLocal;
        }
        state.ordered.push_back(captured);
        CaptureEnqueueAction::Continue
    }

    fn drain(&self, budget: usize) -> Vec<CapturedInput> {
        if budget == 0 {
            return Vec::new();
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut drained = Vec::with_capacity(budget.min(state.ordered.len() + 1));
        if std::mem::take(&mut state.emergency) {
            drained.push(CapturedInput {
                event: None,
                emergency: true,
            });
            return drained;
        }
        while drained.len() < budget {
            let Some(captured) = state.ordered.pop_front() else {
                break;
            };
            drained.push(captured);
        }
        drained
    }
}

#[cfg(test)]
mod capture_buffer_tests {
    use super::{
        CAPTURE_DRAIN_BUDGET, CaptureBuffer, CaptureEnqueueAction, CapturedInput,
        INPUT_SERVICE_INTERVAL,
    };
    use seamless_input_protocol::{Button, InputEvent, Modifier};

    fn captured(event: InputEvent) -> CapturedInput {
        CapturedInput {
            event: Some(event),
            emergency: false,
        }
    }

    #[test]
    fn pointer_motion_is_latest_wins_and_drain_respects_budget() {
        let queue = CaptureBuffer::new(4);
        for value in 0..10_000 {
            assert_eq!(
                queue.push(captured(InputEvent::Pointer {
                    x: value as f64,
                    y: value as f64,
                })),
                CaptureEnqueueAction::Continue
            );
        }

        let drained = queue.drain(1);
        assert_eq!(drained.len(), 1);
        assert_eq!(
            drained[0].event,
            Some(InputEvent::Pointer {
                x: 9_999.0,
                y: 9_999.0,
            })
        );
        assert!(queue.drain(1).is_empty());
    }

    #[test]
    fn critical_transition_is_a_barrier_after_pointer_motion() {
        let queue = CaptureBuffer::new(4);
        let pointer = InputEvent::Pointer { x: 10.0, y: 20.0 };
        let down = InputEvent::Button {
            button: Button::Left,
            pressed: true,
        };
        queue.push(captured(pointer.clone()));
        queue.push(captured(down.clone()));

        assert_eq!(
            queue
                .drain(4)
                .into_iter()
                .map(|captured| captured.event.unwrap())
                .collect::<Vec<_>>(),
            vec![pointer, down]
        );
    }

    #[test]
    fn pointers_coalesce_only_inside_segments_between_critical_transitions() {
        let queue = CaptureBuffer::new(8);
        let first = InputEvent::Pointer { x: 10.0, y: 20.0 };
        let down = InputEvent::Button {
            button: Button::Left,
            pressed: true,
        };
        let second = InputEvent::Pointer { x: 30.0, y: 40.0 };
        let up = InputEvent::Button {
            button: Button::Left,
            pressed: false,
        };
        for event in [first.clone(), down.clone(), second.clone(), up.clone()] {
            queue.push(captured(event));
        }

        assert_eq!(
            queue
                .drain(8)
                .into_iter()
                .map(|captured| captured.event.unwrap())
                .collect::<Vec<_>>(),
            vec![first, down, second, up]
        );
    }

    #[test]
    fn key_modifier_and_button_transitions_remain_fifo_across_budgeted_drains() {
        let queue = CaptureBuffer::new(4);
        let events = [
            InputEvent::Key {
                code: 4,
                pressed: true,
            },
            InputEvent::Modifier {
                modifier: Modifier::Shift,
                pressed: true,
            },
            InputEvent::Button {
                button: Button::Left,
                pressed: false,
            },
        ];
        for event in events.clone() {
            assert_eq!(queue.push(captured(event)), CaptureEnqueueAction::Continue);
        }

        assert_eq!(
            queue
                .drain(2)
                .into_iter()
                .map(|captured| captured.event.unwrap())
                .collect::<Vec<_>>(),
            events[..2]
        );
        assert_eq!(queue.drain(1)[0].event, Some(events[2].clone()));
    }

    #[test]
    fn emergency_is_out_of_band_and_discards_stale_bulk_input() {
        let queue = CaptureBuffer::new(4);
        queue.push(captured(InputEvent::Key {
            code: 4,
            pressed: true,
        }));
        queue.push(captured(InputEvent::Pointer { x: 1.0, y: 2.0 }));

        assert_eq!(
            queue.push(CapturedInput {
                event: None,
                emergency: true,
            }),
            CaptureEnqueueAction::RecoverLocal
        );
        assert_eq!(
            queue.drain(64),
            vec![CapturedInput {
                event: None,
                emergency: true,
            }]
        );
        assert!(queue.drain(64).is_empty());
    }

    #[test]
    fn critical_overflow_forces_recovery_instead_of_silently_losing_an_up() {
        let queue = CaptureBuffer::new(2);
        queue.push(captured(InputEvent::Key {
            code: 4,
            pressed: true,
        }));
        queue.push(captured(InputEvent::Button {
            button: Button::Left,
            pressed: true,
        }));

        assert_eq!(
            queue.push(captured(InputEvent::Button {
                button: Button::Left,
                pressed: false,
            })),
            CaptureEnqueueAction::RecoverLocal
        );
        assert_eq!(
            queue.drain(64),
            vec![CapturedInput {
                event: None,
                emergency: true,
            }]
        );
    }

    #[test]
    fn input_service_has_a_small_fixed_time_and_work_budget() {
        assert!(INPUT_SERVICE_INTERVAL < std::time::Duration::from_millis(250));
        assert!((1..=64).contains(&CAPTURE_DRAIN_BUDGET));
    }
}

#[cfg(all(target_os = "macos", not(test)))]
struct NativeCapture {
    tap: seamless_input_platform_macos::input::MacEventTap,
    buffer: CaptureBuffer,
}

#[cfg(all(target_os = "macos", not(test)))]
impl NativeCapture {
    fn install() -> Result<Self, seamless_input_platform_macos::input::InputError> {
        const CRITICAL_CAPTURE_CAPACITY: usize = 256;
        let buffer = CaptureBuffer::new(CRITICAL_CAPTURE_CAPACITY);
        let callback_buffer = buffer.clone();
        let tap = seamless_input_platform_macos::input::MacEventTap::install(
            seamless_input_core::platform::CaptureMode::Local,
            move |event| match callback_buffer.push(CapturedInput {
                event: event.event,
                emergency: event.emergency,
            }) {
                CaptureEnqueueAction::Continue => {
                    seamless_input_platform_macos::input::CaptureCallbackAction::Continue
                }
                CaptureEnqueueAction::RecoverLocal => {
                    seamless_input_platform_macos::input::CaptureCallbackAction::RecoverLocal
                }
            },
        )?;
        Ok(Self { tap, buffer })
    }
    fn drain(&self, budget: usize) -> Vec<CapturedInput> {
        self.buffer.drain(budget)
    }
    fn set_remote(&self, remote: bool) {
        self.tap.set_mode(if remote {
            seamless_input_core::platform::CaptureMode::Remote
        } else {
            seamless_input_core::platform::CaptureMode::Local
        });
    }
}

#[cfg(all(target_os = "windows", not(test)))]
struct NativeCapture {
    hooks: seamless_input_platform_windows::input::WindowsHooks,
    receiver: std::sync::mpsc::Receiver<seamless_input_platform_windows::input::CaptureOutcome>,
}

#[cfg(all(target_os = "windows", not(test)))]
impl NativeCapture {
    fn install() -> Result<Self, seamless_input_platform_windows::input::InputError> {
        let (hooks, receiver) = seamless_input_platform_windows::input::WindowsHooks::install()?;
        Ok(Self { hooks, receiver })
    }
    fn drain(&self, budget: usize) -> Vec<CapturedInput> {
        self.receiver
            .try_iter()
            .take(budget)
            .map(|outcome| CapturedInput {
                event: outcome.event,
                emergency: outcome.emergency,
            })
            .collect()
    }
    fn set_remote(&self, remote: bool) {
        self.hooks.set_remote_capture(remote);
    }
}

// Supervisor unit tests exercise orchestration, topology, and the peer data
// plane. Installing process-global OS input hooks in each parallel test both
// requires user permissions and makes the native hook lifecycle race across
// test threads, so tests use an inert capture boundary instead. Platform hook
// behavior remains covered by the platform crates and production builds still
// compile the native implementations above.
#[cfg(test)]
struct NativeCapture;

#[cfg(test)]
impl NativeCapture {
    fn install() -> Result<Self, std::convert::Infallible> {
        Ok(Self)
    }

    fn drain(&self, _budget: usize) -> Vec<CapturedInput> {
        Vec::new()
    }

    fn set_remote(&self, _remote: bool) {}
}

fn display(node: NodeId, value: &LogicalDisplay) -> Display {
    Display {
        id: DisplayId {
            node,
            index: value.index,
        },
        origin: Point {
            x: value.origin_x,
            y: value.origin_y,
        },
        width: value.width,
        height: value.height,
        scale: value.scale,
    }
}

fn remote_display(value: &LogicalDisplay) -> RemoteDisplay {
    RemoteDisplay {
        index: value.index,
        origin_x: value.origin_x,
        origin_y: value.origin_y,
        width: value.width,
        height: value.height,
        scale: value.scale,
    }
}

fn random_instance() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn local_lan_ip() -> IpAddr {
    let fallback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
        return fallback;
    };
    if socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).is_err() {
        return fallback;
    }
    socket
        .local_addr()
        .map(|address| address.ip())
        .unwrap_or(fallback)
}

#[cfg(all(target_os = "macos", not(test)))]
struct NativePlatform {
    input: seamless_input_platform_macos::MacInput,
    displays: seamless_input_platform_macos::MacDisplays,
    clipboard: seamless_input_platform_macos::MacClipboard,
}

#[cfg(all(target_os = "macos", not(test)))]
impl NativePlatform {
    fn new() -> Self {
        Self {
            input: Default::default(),
            displays: Default::default(),
            clipboard: Default::default(),
        }
    }
    fn input_access(&self) -> AccessState {
        self.input.access_state()
    }
    fn clipboard_access(&self) -> AccessState {
        self.clipboard.access_state()
    }
    fn displays(&mut self) -> Result<Vec<LogicalDisplay>, SupervisorError> {
        self.displays
            .displays()
            .map_err(|error| SupervisorError::Platform(error.to_string()))
    }
    fn poll_clipboard(&mut self, now_ms: u64) -> Result<ClipboardOutcome, SupervisorError> {
        self.clipboard
            .poll(now_ms)
            .map_err(|error| SupervisorError::Platform(error.to_string()))
    }
    fn prepare_remote_receive(
        &mut self,
        received: crate::runtime::RuntimeReceive,
    ) -> Result<crate::runtime::RuntimeReceive, SupervisorError> {
        Ok(received)
    }
    fn warp_local(&mut self, point: Point) -> Result<(), String> {
        self.input
            .inject(&seamless_input_protocol::InputEvent::Pointer {
                x: point.x,
                y: point.y,
            })
            .map_err(|error| error.to_string())
    }
}

#[cfg(all(target_os = "windows", not(test)))]
struct NativePlatform {
    input: seamless_input_platform_windows::WindowsInput,
    displays: seamless_input_platform_windows::WindowsDisplays,
    clipboard: seamless_input_platform_windows::WindowsClipboard,
}

#[cfg(all(target_os = "windows", not(test)))]
impl NativePlatform {
    fn new() -> Self {
        Self {
            input: Default::default(),
            displays: Default::default(),
            clipboard: Default::default(),
        }
    }
    fn input_access(&self) -> AccessState {
        self.input.access_state()
    }
    fn clipboard_access(&self) -> AccessState {
        self.clipboard.access_state()
    }
    fn displays(&mut self) -> Result<Vec<LogicalDisplay>, SupervisorError> {
        self.displays
            .displays()
            .map_err(|error| SupervisorError::Platform(error.to_string()))
    }
    fn poll_clipboard(&mut self, now_ms: u64) -> Result<ClipboardOutcome, SupervisorError> {
        self.clipboard
            .poll(now_ms)
            .map_err(|error| SupervisorError::Platform(error.to_string()))
    }
    fn prepare_remote_receive(
        &mut self,
        received: crate::runtime::RuntimeReceive,
    ) -> Result<crate::runtime::RuntimeReceive, SupervisorError> {
        if let crate::runtime::RuntimeReceive::Input(
            seamless_input_protocol::InputEvent::Pointer { x, y },
        ) = received
        {
            let displays = self.displays()?;
            let point =
                crate::cursor::logical_to_physical(Point { x, y }, &displays).ok_or_else(|| {
                    SupervisorError::Platform(
                        "remote pointer is outside the measured Windows display geometry".into(),
                    )
                })?;
            Ok(crate::runtime::RuntimeReceive::Input(
                seamless_input_protocol::InputEvent::Pointer {
                    x: point.x,
                    y: point.y,
                },
            ))
        } else {
            Ok(received)
        }
    }
    fn warp_local(&mut self, point: Point) -> Result<(), String> {
        let displays = self.displays().map_err(|error| error.to_string())?;
        let point = crate::cursor::logical_to_physical(point, &displays).ok_or_else(|| {
            "local warp is outside the measured Windows display geometry".to_string()
        })?;
        self.input
            .inject(&seamless_input_protocol::InputEvent::Pointer {
                x: point.x,
                y: point.y,
            })
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
#[derive(Default)]
struct TestInput;

#[cfg(test)]
impl PlatformInput for TestInput {
    type Error = std::convert::Infallible;

    fn access_state(&self) -> AccessState {
        AccessState::Granted
    }

    fn inject(&mut self, _event: &seamless_input_protocol::InputEvent) -> Result<(), Self::Error> {
        Ok(())
    }

    fn release_all(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
#[derive(Default)]
struct TestClipboard;

#[cfg(test)]
impl PlatformClipboard for TestClipboard {
    type Error = std::convert::Infallible;

    fn access_state(&self) -> AccessState {
        AccessState::Granted
    }

    fn poll(&mut self, _now_ms: u64) -> Result<ClipboardOutcome, Self::Error> {
        Ok(ClipboardOutcome::Unchanged)
    }

    fn write_remote(&mut self, _content: &ClipboardContent) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
struct NativePlatform {
    input: TestInput,
    clipboard: TestClipboard,
}

#[cfg(test)]
impl NativePlatform {
    fn new() -> Self {
        Self {
            input: TestInput,
            clipboard: TestClipboard,
        }
    }

    fn input_access(&self) -> AccessState {
        self.input.access_state()
    }

    fn clipboard_access(&self) -> AccessState {
        self.clipboard.access_state()
    }

    fn displays(&mut self) -> Result<Vec<LogicalDisplay>, SupervisorError> {
        Ok(vec![LogicalDisplay {
            index: 0,
            origin_x: 0.0,
            origin_y: 0.0,
            width: 1920.0,
            height: 1080.0,
            scale: 1.0,
        }])
    }

    fn poll_clipboard(&mut self, now_ms: u64) -> Result<ClipboardOutcome, SupervisorError> {
        Ok(self.clipboard.poll(now_ms).unwrap())
    }

    fn prepare_remote_receive(
        &mut self,
        received: crate::runtime::RuntimeReceive,
    ) -> Result<crate::runtime::RuntimeReceive, SupervisorError> {
        Ok(received)
    }

    fn warp_local(&mut self, point: Point) -> Result<(), String> {
        self.input
            .inject(&seamless_input_protocol::InputEvent::Pointer {
                x: point.x,
                y: point.y,
            })
            .unwrap();
        Ok(())
    }
}

pub fn identity_root_has_material(root: &Path) -> bool {
    root.join("identity.json").is_file()
}

fn access_label(state: AccessState) -> &'static str {
    match state {
        AccessState::Granted => "PASS",
        AccessState::Denied => "FAIL (user permission denied)",
        AccessState::NotDetermined => "FAIL (user permission not determined)",
    }
}

#[cfg(test)]
mod fault_isolation_tests {
    use super::*;
    use crate::peer::PeerMessage;
    use seamless_input_core::Edge;
    use seamless_input_protocol::InputEvent;
    use seamless_transport::{PinnedPeer, SessionTrust};

    fn node(value: u8) -> NodeId {
        NodeId([value; 16])
    }

    fn test_runtime(caps: Capabilities) -> (Runtime, NodeId, u64) {
        let local = node(1);
        let remote = node(2);
        let local_display = Display {
            id: DisplayId {
                node: local,
                index: 0,
            },
            origin: Point { x: 0.0, y: 0.0 },
            width: 100.0,
            height: 100.0,
            scale: 1.0,
        };
        let remote_display = Display {
            id: DisplayId {
                node: remote,
                index: 0,
            },
            origin: Point { x: 0.0, y: 0.0 },
            width: 100.0,
            height: 100.0,
            scale: 1.0,
        };
        let local_id = local_display.id;
        let mut topology = Topology::new(local_display).unwrap();
        topology
            .place(local_id, Edge::Right, remote_display)
            .unwrap();
        let mut runtime = Runtime::new(local, local_id, topology, 1_000).unwrap();
        let pin = PinnedPeer {
            node_id: remote,
            friendly_name: "peer".into(),
            public_identity: vec![2],
            certificate_pin: [2; 32],
        };
        let epoch = runtime
            .connect_admitted(remote, caps, Some(&pin), SessionTrust::Authenticated)
            .unwrap();
        runtime
            .receive(
                remote,
                PeerMessage::Capabilities {
                    epoch,
                    capabilities: caps,
                },
                0,
            )
            .unwrap();
        (runtime, remote, epoch)
    }

    #[test]
    fn malformed_packet_isolates_peer_and_recovers_local_control() {
        let (mut runtime, remote, _) = test_runtime(Capabilities::all());
        runtime
            .cross(Edge::Right, Point { x: 100.0, y: 50.0 }, 1)
            .unwrap();
        assert_eq!(runtime.active_peer(), remote);

        let outcome = process_peer_packet(&mut runtime, remote, Ok(vec![0xc1]), 2);
        let PeerPacketOutcome::Isolated { recovery } = outcome else {
            panic!("malformed packet must isolate its peer")
        };
        assert_eq!(runtime.active_peer(), node(1));
        assert!(
            recovery
                .iter()
                .any(|effect| matches!(effect, RuntimeEffect::ReleaseLocal))
        );

        let pin = PinnedPeer {
            node_id: remote,
            friendly_name: "peer".into(),
            public_identity: vec![2],
            certificate_pin: [2; 32],
        };
        assert!(
            runtime
                .connect_admitted(
                    remote,
                    Capabilities::all(),
                    Some(&pin),
                    SessionTrust::Authenticated
                )
                .is_ok()
        );
    }

    #[test]
    fn wrong_epoch_stale_and_capability_violations_are_peer_scoped() {
        let scenarios = [
            PeerMessage::Input {
                epoch: 999,
                sequence: 1,
                event: InputEvent::Key {
                    code: 4,
                    pressed: true,
                },
            },
            PeerMessage::Input {
                epoch: 1,
                sequence: 0,
                event: InputEvent::Key {
                    code: 4,
                    pressed: true,
                },
            },
        ];
        for message in scenarios {
            let (mut runtime, remote, epoch) = test_runtime(Capabilities::all());
            if matches!(message, PeerMessage::Input { sequence: 0, .. }) {
                runtime
                    .receive(remote, PeerMessage::AcquireLease { epoch }, 0)
                    .unwrap();
                runtime
                    .receive(
                        remote,
                        PeerMessage::Input {
                            epoch,
                            sequence: 1,
                            event: InputEvent::Key {
                                code: 4,
                                pressed: true,
                            },
                        },
                        0,
                    )
                    .unwrap();
            }
            assert!(matches!(
                process_peer_packet(
                    &mut runtime,
                    remote,
                    Ok(encode_peer_message(&message).unwrap()),
                    1,
                ),
                PeerPacketOutcome::Isolated { .. }
            ));
        }

        let denied = Capabilities {
            input: false,
            text: true,
            png: true,
        };
        let (mut runtime, remote, epoch) = test_runtime(denied);
        runtime
            .receive(remote, PeerMessage::AcquireLease { epoch }, 0)
            .unwrap();
        let packet = encode_peer_message(&PeerMessage::Input {
            epoch,
            sequence: 1,
            event: InputEvent::Key {
                code: 4,
                pressed: true,
            },
        })
        .unwrap();
        assert!(matches!(
            process_peer_packet(&mut runtime, remote, Ok(packet), 1),
            PeerPacketOutcome::Isolated { .. }
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seamless_transport::PinnedPeer;

    fn test_paths(root: &Path, name: &str) -> AppPaths {
        let root = root.join(name);
        AppPaths {
            config: root.join("config.toml"),
            identity: root.join("identity"),
            root,
        }
    }

    fn pin_each_other(a: &AppPaths, b: &AppPaths) -> (NodeId, NodeId) {
        let mut a_identity = IdentityStore::open_or_create(&a.identity, "a").unwrap();
        let mut b_identity = IdentityStore::open_or_create(&b.identity, "b").unwrap();
        let a_id = a_identity.node_id();
        let b_id = b_identity.node_id();
        a_identity
            .pin_peer(PinnedPeer::from_identity(&b_identity))
            .unwrap();
        b_identity
            .pin_peer(PinnedPeer::from_identity(&a_identity))
            .unwrap();
        (a_id, b_id)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn running_supervisor_adds_a_newly_paired_peer_and_synchronizes_config() {
        let root = tempfile::tempdir().unwrap();
        let a_paths = test_paths(root.path(), "a");
        let b_paths = test_paths(root.path(), "b");
        let mut a = NativeSupervisor::bootstrap(&a_paths).unwrap();
        assert!(a.links.is_empty());

        let (_, b_id) = pin_each_other(&a_paths, &b_paths);
        a.refresh_peer_membership().await.unwrap();

        assert_eq!(a.links.len(), 1);
        assert_eq!(a.links[0].peer, b_id);
        let config = a_paths.config_store().unwrap().load().unwrap();
        assert!(
            config
                .peers
                .iter()
                .any(|peer| peer.node_id == node_hex(b_id))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn running_supervisor_removes_link_reader_session_and_config_for_unpaired_peer() {
        let root = tempfile::tempdir().unwrap();
        let a_paths = test_paths(root.path(), "a");
        let b_paths = test_paths(root.path(), "b");
        let (_, b_id) = pin_each_other(&a_paths, &b_paths);
        let mut a = NativeSupervisor::bootstrap(&a_paths).unwrap();
        assert_eq!(a.links.len(), 1);

        a.admitted.insert(b_id);
        a.readers.insert(b_id, tokio::spawn(async {}));
        IdentityStore::open_or_create(&a_paths.identity, "a")
            .unwrap()
            .unpair(b_id)
            .unwrap();
        a.refresh_peer_membership().await.unwrap();

        assert!(a.links.is_empty());
        assert!(!a.admitted.contains(&b_id));
        assert!(!a.readers.contains_key(&b_id));
        let config = a_paths.config_store().unwrap().load().unwrap();
        assert!(
            !config
                .peers
                .iter()
                .any(|peer| peer.node_id == node_hex(b_id))
        );
    }

    fn place_remote(paths: &AppPaths, remote: NodeId, display: u32, x: i32) {
        let store = paths.config_store().unwrap();
        let mut config = store.load().unwrap();
        config
            .placements
            .retain(|placement| placement.display != format!("{}:{display}", node_hex(remote)));
        config.placements.push(crate::config::Placement {
            display: format!("{}:{display}", node_hex(remote)),
            x,
            y: 0,
        });
        store.save(&config).unwrap();
    }

    async fn connect_supervisors(a: &mut NativeSupervisor, b: &mut NativeSupervisor) {
        let b_id = b.identity.node_id();
        a.links[0]
            .endpoint
            .dial(
                b.links[0].endpoint.local_addr(),
                "seamless-input.local",
                Some(b_id),
            )
            .await
            .unwrap();
        for _ in 0..20 {
            a.tick().await.unwrap();
            b.tick().await.unwrap();
            if a.admitted.len() == 1 && b.admitted.len() == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("supervisors did not admit their authenticated sessions");
    }

    async fn assert_hostile_display_message_isolates_before_config_mutation<F>(build: F)
    where
        F: FnOnce(u64) -> crate::peer::PeerMessage,
    {
        let root = tempfile::tempdir().unwrap();
        let a_paths = test_paths(root.path(), "a");
        let b_paths = test_paths(root.path(), "b");
        let (_, b_id) = pin_each_other(&a_paths, &b_paths);
        let mut a = NativeSupervisor::bootstrap(&a_paths).unwrap();
        let pin = a.identity.peer(b_id).unwrap().clone();
        a.runtime
            .connect_admitted(
                b_id,
                Capabilities::all(),
                Some(&pin),
                seamless_transport::SessionTrust::Authenticated,
            )
            .unwrap();
        let remote_epoch = 41;
        a.runtime
            .receive(
                b_id,
                crate::peer::PeerMessage::Capabilities {
                    epoch: remote_epoch,
                    capabilities: Capabilities::all(),
                },
                0,
            )
            .unwrap();
        a.admitted.insert(b_id);
        let config_before = std::fs::read(&a_paths.config).unwrap();

        a.inbound_tx
            .send(InboundPacket {
                peer: b_id,
                packet: Ok(encode_peer_message(&build(remote_epoch)).unwrap()),
            })
            .unwrap();
        a.drain_inbound(1).await.unwrap();

        assert!(!a.admitted.contains(&b_id), "hostile peer must be dropped");
        assert_eq!(a.runtime.peer_epoch(b_id), None);
        assert!(!a.remote_displays.contains_key(&b_id));
        assert_eq!(std::fs::read(&a_paths.config).unwrap(), config_before);
        a.tick().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hostile_remote_geometry_is_peer_scoped_before_configuration_changes() {
        assert_hostile_display_message_isolates_before_config_mutation(|epoch| {
            crate::peer::PeerMessage::DisplayGeometry {
                epoch,
                displays: vec![RemoteDisplay {
                    index: 0,
                    origin_x: f64::MAX / 2.0,
                    origin_y: 0.0,
                    width: f64::MIN_POSITIVE,
                    height: 100.0,
                    scale: 1.0,
                }],
            }
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn oversized_duplicate_and_wrong_epoch_legacy_displays_are_peer_scoped() {
        assert_hostile_display_message_isolates_before_config_mutation(|epoch| {
            crate::peer::PeerMessage::Displays {
                epoch,
                displays: (0..33).collect(),
            }
        })
        .await;
        assert_hostile_display_message_isolates_before_config_mutation(|epoch| {
            crate::peer::PeerMessage::Displays {
                epoch,
                displays: vec![0, 0],
            }
        })
        .await;
        assert_hostile_display_message_isolates_before_config_mutation(|epoch| {
            crate::peer::PeerMessage::Displays {
                epoch: epoch + 1,
                displays: vec![0],
            }
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn two_running_supervisors_pair_route_input_and_clipboard_then_reconnect() {
        let root = tempfile::tempdir().unwrap();
        let a_paths = test_paths(root.path(), "a");
        let b_paths = test_paths(root.path(), "b");
        let mut a = NativeSupervisor::bootstrap(&a_paths).unwrap();
        let mut b = NativeSupervisor::bootstrap(&b_paths).unwrap();
        a.suppress_native_apply = true;
        b.suppress_native_apply = true;

        let (a_id, b_id) = pin_each_other(&a_paths, &b_paths);
        a.refresh_peer_membership().await.unwrap();
        b.refresh_peer_membership().await.unwrap();
        let a_display = a.platform.displays().unwrap()[0].index;
        let b_display = b.platform.displays().unwrap()[0].index;
        place_remote(&a_paths, b_id, b_display, 1);
        place_remote(&b_paths, a_id, a_display, -1);
        a.tick().await.unwrap();
        b.tick().await.unwrap();
        let a_store = a_paths.config_store().unwrap();
        let mut stale = a_store.load().unwrap();
        stale
            .peers
            .iter_mut()
            .find(|peer| peer.node_id == node_hex(b_id))
            .unwrap()
            .displays = vec!["99".into()];
        a_store.save(&stale).unwrap();
        connect_supervisors(&mut a, &mut b).await;

        for _ in 0..10 {
            a.tick().await.unwrap();
            b.tick().await.unwrap();
            let a_config = a_paths.config_store().unwrap().load().unwrap();
            let b_displays = a_config
                .peers
                .iter()
                .find(|peer| peer.node_id == node_hex(b_id))
                .map(|peer| peer.displays.clone())
                .unwrap_or_default();
            if b_displays != vec!["99"] {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let expected_b_displays: Vec<_> = b
            .platform
            .displays()
            .unwrap()
            .into_iter()
            .map(|display| display.index.to_string())
            .collect();
        let a_config = a_paths.config_store().unwrap().load().unwrap();
        assert_eq!(
            a_config
                .peers
                .iter()
                .find(|peer| peer.node_id == node_hex(b_id))
                .unwrap()
                .displays,
            expected_b_displays
        );
        a.tick().await.unwrap();

        let now_ms = a.started.elapsed().as_millis() as u64;
        let local_display = display(a.identity.node_id(), &a.local_displays[0]);
        let crossing = Point {
            x: local_display.origin.x + local_display.width,
            y: local_display.origin.y + local_display.height / 2.0,
        };
        let effects = a
            .runtime
            .cross(seamless_input_core::Edge::Right, crossing, now_ms)
            .unwrap();
        assert_eq!(
            a.runtime.active_peer(),
            b_id,
            "cross must activate the paired peer"
        );
        a.execute_effects(effects).await.unwrap();
        let effects = a
            .runtime
            .route(seamless_input_protocol::InputEvent::Key {
                code: 4,
                pressed: true,
            })
            .unwrap();
        a.execute_effects(effects).await.unwrap();
        let effects = a
            .runtime
            .offer_clipboard(ClipboardPayload::text("dynamic clipboard"))
            .unwrap();
        a.execute_effects(effects).await.unwrap();
        for _ in 0..10 {
            b.tick().await.unwrap();
            let has_input = b.observed_received.iter().any(|received| {
                matches!(
                    received,
                    crate::runtime::RuntimeReceive::Input(
                        seamless_input_protocol::InputEvent::Key {
                            code: 4,
                            pressed: true
                        }
                    )
                )
            });
            let has_clipboard = b.observed_received.iter().any(|received| {
                matches!(
                    received,
                    crate::runtime::RuntimeReceive::Clipboard(ClipboardPayload::Text(text))
                        if text == "dynamic clipboard"
                )
            });
            if has_input && has_clipboard {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            b.observed_received.iter().any(|received| matches!(
                received,
                crate::runtime::RuntimeReceive::Input(seamless_input_protocol::InputEvent::Key {
                    code: 4,
                    pressed: true
                })
            )),
            "received: {:?}",
            b.observed_received
        );
        assert!(b.observed_received.iter().any(|received| matches!(
            received,
            crate::runtime::RuntimeReceive::Clipboard(ClipboardPayload::Text(text))
                if text == "dynamic clipboard"
        )));

        IdentityStore::open_or_create(&a_paths.identity, "a")
            .unwrap()
            .unpair(b_id)
            .unwrap();
        IdentityStore::open_or_create(&b_paths.identity, "b")
            .unwrap()
            .unpair(a_id)
            .unwrap();
        a.refresh_peer_membership().await.unwrap();
        b.refresh_peer_membership().await.unwrap();
        assert!(a.admitted.is_empty() && b.admitted.is_empty());

        pin_each_other(&a_paths, &b_paths);
        a.refresh_peer_membership().await.unwrap();
        b.refresh_peer_membership().await.unwrap();
        connect_supervisors(&mut a, &mut b).await;
        assert_eq!(a.admitted, BTreeSet::from([b_id]));
        assert_eq!(b.admitted, BTreeSet::from([a_id]));
    }
}
