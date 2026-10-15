use crate::{
    config::{ConfigError, ConfigStore, LiveConfig},
    peer::{Capabilities, decode_peer_message, encode_peer_message},
    runtime::{Runtime, RuntimeEffect, RuntimeError, apply_receive},
};
use rand::{RngCore, rngs::OsRng};
use seamless_discovery::Discovery;
use seamless_input_core::{
    Display, DisplayId, NodeId, Point, Topology,
    clipboard::ClipboardPayload,
    platform::{
        AccessState, ClipboardContent, ClipboardOutcome, LogicalDisplay, PlatformClipboard,
        PlatformDisplays, PlatformInput,
    },
};
use seamless_input_protocol::VERSION;
use seamless_transport::{
    EndpointOptions, IdentityStore, PairingError, PeerEndpoint, PeerSession, ReconnectPolicy,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, task::JoinHandle};

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
}

struct PeerLink {
    peer: NodeId,
    endpoint: PeerEndpoint,
    _instance: String,
}

struct InboundPacket {
    peer: NodeId,
    packet: Result<Vec<u8>, String>,
}

pub struct NativeSupervisor {
    identity: IdentityStore,
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
    local_display: Display,
    capture: Option<NativeCapture>,
}

impl NativeSupervisor {
    pub fn bootstrap(paths: &AppPaths) -> Result<Self, SupervisorError> {
        let store = paths.config_store()?;
        if !store.path().exists() {
            store.save(&Default::default())?;
        }
        let live_config = store.live_reload()?;
        let identity = IdentityStore::open_or_create(&paths.identity, "SeamlessInput peer")?;
        let mut discovery = Discovery::new(VERSION).map_err(SupervisorError::Discovery)?;
        let mut platform = NativePlatform::new();
        let displays = platform.displays()?;
        let first = displays.first().ok_or(SupervisorError::NoDisplay)?;
        let local_display = display(identity.node_id(), first);
        let topology =
            Topology::new(local_display.clone()).map_err(|_| SupervisorError::Runtime)?;
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
            links.push(PeerLink {
                peer: peer.node_id,
                endpoint,
                _instance: instance,
            });
        }
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let capture = NativeCapture::install().ok();

        Ok(Self {
            identity,
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
            local_display,
            capture,
        })
    }

    pub async fn tick(&mut self) -> Result<SupervisorStatus, SupervisorError> {
        if self.live_config.poll().is_err() {
            // Atomic replacement may be briefly invisible; the last good config remains active.
        }
        let discovered_peers = self
            .discovery
            .browse(Duration::from_millis(25))
            .map_err(SupervisorError::Discovery)?;
        let discovered = discovered_peers.len();
        let displays = self.platform.displays()?.len();
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
            self.execute_effects(vec![RuntimeEffect::Send {
                peer,
                message: crate::peer::PeerMessage::Capabilities {
                    epoch: self
                        .runtime
                        .peer_epoch(peer)
                        .ok_or(SupervisorError::Runtime)?,
                    capabilities: Capabilities::all(),
                },
            }])
            .await?;
        }

        self.drain_inbound(now_ms).await?;
        self.drain_capture(now_ms).await?;
        if let Some(capture) = &self.capture {
            capture.set_remote(self.runtime.active_peer() != self.identity.node_id());
        }

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
            match inbound.packet {
                Ok(bytes) => {
                    let message =
                        decode_peer_message(&bytes).map_err(SupervisorError::DataPlane)?;
                    let received = self
                        .runtime
                        .receive(inbound.peer, message, now_ms)
                        .map_err(|_| SupervisorError::Runtime)?;
                    apply_receive(
                        &mut self.platform.input,
                        &mut self.platform.clipboard,
                        received,
                    )
                    .map_err(|_| SupervisorError::Runtime)?;
                }
                Err(_) => {
                    self.sessions.remove(&inbound.peer);
                    self.admitted.remove(&inbound.peer);
                    if let Some(task) = self.readers.remove(&inbound.peer) {
                        task.abort();
                    }
                    let effects = self.runtime.disconnect(inbound.peer);
                    self.execute_effects(effects).await?;
                }
            }
        }
        Ok(())
    }

    async fn drain_capture(&mut self, now_ms: u64) -> Result<(), SupervisorError> {
        let captured = self
            .capture
            .as_ref()
            .map(NativeCapture::drain)
            .unwrap_or_default();
        for captured in captured {
            let effects = if captured.emergency {
                self.runtime.emergency_return()
            } else if let Some(event) = captured.event {
                let mut effects = Vec::new();
                if let seamless_input_protocol::InputEvent::Pointer { x, y } = event {
                    if let Some(edge) = pointer_edge(&self.local_display, x, y) {
                        effects = self
                            .runtime
                            .cross(edge, Point { x, y }, now_ms)
                            .map_err(|_| SupervisorError::Runtime)?;
                    }
                    if effects.is_empty() {
                        effects.extend(
                            self.runtime
                                .route(seamless_input_protocol::InputEvent::Pointer { x, y })
                                .map_err(|_| SupervisorError::Runtime)?,
                        );
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
                RuntimeEffect::WarpLocal { point, .. } => self
                    .platform
                    .input
                    .inject(&seamless_input_protocol::InputEvent::Pointer {
                        x: point.x,
                        y: point.y,
                    })
                    .map_err(|error| error.to_string()),
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
                        .input
                        .inject(&seamless_input_protocol::InputEvent::Pointer {
                            x: point.x,
                            y: point.y,
                        })
                        .map_err(|error| SupervisorError::DataPlane(error.to_string()))?,
                    RuntimeEffect::Local(_) | RuntimeEffect::Send { .. } => {}
                }
            }
        }
        Ok(())
    }
}

fn pointer_edge(display: &Display, x: f64, y: f64) -> Option<seamless_input_core::Edge> {
    use seamless_input_core::Edge;
    if x <= display.origin.x {
        Some(Edge::Left)
    } else if x >= display.origin.x + display.width {
        Some(Edge::Right)
    } else if y <= display.origin.y {
        Some(Edge::Top)
    } else if y >= display.origin.y + display.height {
        Some(Edge::Bottom)
    } else {
        None
    }
}

struct CapturedInput {
    event: Option<seamless_input_protocol::InputEvent>,
    emergency: bool,
}

#[cfg(target_os = "macos")]
struct NativeCapture {
    tap: seamless_input_platform_macos::input::MacEventTap,
    receiver: std::sync::mpsc::Receiver<seamless_input_platform_macos::input::CaptureOutcome>,
}

#[cfg(target_os = "macos")]
impl NativeCapture {
    fn install() -> Result<Self, seamless_input_platform_macos::input::InputError> {
        let (sender, receiver) = std::sync::mpsc::channel();
        let tap = seamless_input_platform_macos::input::MacEventTap::install(
            seamless_input_core::platform::CaptureMode::Local,
            move |event| {
                let _ = sender.send(event);
            },
        )?;
        Ok(Self { tap, receiver })
    }
    fn drain(&self) -> Vec<CapturedInput> {
        self.tap.poll();
        self.receiver
            .try_iter()
            .map(|outcome| CapturedInput {
                event: outcome.event,
                emergency: outcome.emergency,
            })
            .collect()
    }
    fn set_remote(&self, remote: bool) {
        self.tap.set_mode(if remote {
            seamless_input_core::platform::CaptureMode::Remote
        } else {
            seamless_input_core::platform::CaptureMode::Local
        });
    }
}

#[cfg(target_os = "windows")]
struct NativeCapture {
    hooks: seamless_input_platform_windows::input::WindowsHooks,
    receiver: std::sync::mpsc::Receiver<seamless_input_platform_windows::input::CaptureOutcome>,
}

#[cfg(target_os = "windows")]
impl NativeCapture {
    fn install() -> Result<Self, seamless_input_platform_windows::input::InputError> {
        let (hooks, receiver) = seamless_input_platform_windows::input::WindowsHooks::install()?;
        Ok(Self { hooks, receiver })
    }
    fn drain(&self) -> Vec<CapturedInput> {
        self.receiver
            .try_iter()
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

#[cfg(target_os = "macos")]
struct NativePlatform {
    input: seamless_input_platform_macos::MacInput,
    displays: seamless_input_platform_macos::MacDisplays,
    clipboard: seamless_input_platform_macos::MacClipboard,
}

#[cfg(target_os = "macos")]
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
}

#[cfg(target_os = "windows")]
struct NativePlatform {
    input: seamless_input_platform_windows::WindowsInput,
    displays: seamless_input_platform_windows::WindowsDisplays,
    clipboard: seamless_input_platform_windows::WindowsClipboard,
}

#[cfg(target_os = "windows")]
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
