use crate::{
    config::{ConfigError, ConfigStore, ConfigV1, LiveConfig, PeerConfig},
    peer::Capabilities,
    runtime::{Runtime, RuntimeError},
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
use seamless_transport::{EndpointOptions, IdentityStore, PairingError, PeerEndpoint};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

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
}

pub struct NativeSupervisor {
    identity: IdentityStore,
    identity_root: PathBuf,
    discovery: Discovery,
    live_config: LiveConfig,
    endpoints: Vec<PeerEndpoint>,
    runtime: Runtime,
    platform: NativePlatform,
    admitted: BTreeSet<NodeId>,
    started: Instant,
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
        let topology = topology_from_config(identity.node_id(), &displays, live_config.current())
            .map_err(|_| SupervisorError::Runtime)?;
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

        let mut endpoints = Vec::new();
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
            discovery
                .publish(&random_instance(), endpoint.local_addr(), false)
                .map_err(SupervisorError::Discovery)?;
            endpoints.push(endpoint);
        }

        Ok(Self {
            identity,
            identity_root: paths.identity.clone(),
            discovery,
            live_config,
            endpoints,
            runtime,
            platform,
            admitted: BTreeSet::new(),
            started: Instant::now(),
        })
    }

    pub fn tick(&mut self) -> Result<SupervisorStatus, SupervisorError> {
        self.refresh_revocations()?;
        if let Ok(Some(config)) = self.live_config.poll() {
            let displays = self.platform.displays()?;
            if let Ok(topology) = topology_from_config(self.identity.node_id(), &displays, &config)
            {
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
                if effects
                    .iter()
                    .any(|effect| matches!(effect, crate::runtime::RuntimeEffect::ReleaseLocal))
                {
                    self.platform.release_all()?;
                }
            }
        }
        let discovered = self
            .discovery
            .browse(Duration::from_millis(25))
            .map_err(SupervisorError::Discovery)?
            .len();
        let displays = self.platform.displays()?.len();
        let now_ms = self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let clipboard = match self.platform.poll_clipboard(now_ms)? {
            ClipboardOutcome::Changed(content) => {
                let payload = match content {
                    ClipboardContent::Text(text) => ClipboardPayload::Text(text),
                    ClipboardContent::Png(bytes) => ClipboardPayload::Png(bytes),
                };
                let _effects = self
                    .runtime
                    .offer_clipboard(payload)
                    .map_err(|_| SupervisorError::Runtime)?;
                "changed"
            }
            ClipboardOutcome::Disabled => "disabled",
            ClipboardOutcome::Pending => "pending",
            ClipboardOutcome::Unchanged => "unchanged",
        };
        let _ = self
            .runtime
            .tick(now_ms)
            .map_err(|_| SupervisorError::Runtime)?;

        for session in self.endpoints.iter().flat_map(PeerEndpoint::sessions) {
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

    fn refresh_revocations(&mut self) -> Result<(), SupervisorError> {
        let fresh = IdentityStore::open_or_create(&self.identity_root, "SeamlessInput peer")?;
        let current: BTreeSet<_> = self.identity.peers().map(|peer| peer.node_id).collect();
        let retained: BTreeSet<_> = fresh.peers().map(|peer| peer.node_id).collect();
        let revoked: Vec<_> = current.difference(&retained).copied().collect();
        for peer in revoked.iter().copied() {
            for endpoint in &self.endpoints {
                endpoint.revoke(peer);
            }
            self.admitted.remove(&peer);
            let effects = self.runtime.disconnect(peer);
            if effects
                .iter()
                .any(|effect| matches!(effect, crate::runtime::RuntimeEffect::ReleaseLocal))
            {
                self.platform.release_all()?;
            }
        }
        self.identity = fresh;
        if !revoked.is_empty() {
            let displays = self.platform.displays()?;
            synchronize_known_displays(&self.live_config.store(), &self.identity, &displays)?;
        }
        Ok(())
    }
}

/// Build runtime routing from the exact topology persisted by the TUI. Local
/// display geometry is measured; remote geometry remains conservative until a
/// peer advertises its real display list.
pub fn topology_from_config(
    local: NodeId,
    local_displays: &[LogicalDisplay],
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
    for peer in &config.peers {
        let node = parse_node(&peer.node_id)?;
        for index in peer
            .displays
            .iter()
            .filter_map(|value| value.parse::<u32>().ok())
        {
            known.entry(DisplayId { node, index }).or_insert(Display {
                id: DisplayId { node, index },
                origin: Point { x: 0.0, y: 0.0 },
                width: 1.0,
                height: 1.0,
                scale: 1.0,
            });
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
    fn release_all(&mut self) -> Result<(), SupervisorError> {
        self.input
            .release_all()
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
    fn release_all(&mut self) -> Result<(), SupervisorError> {
        self.input
            .release_all()
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
