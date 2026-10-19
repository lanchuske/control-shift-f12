//! Bounded G4 coordinator boundary. This module deliberately has no runtime,
//! input, clipboard, topology, layout or operational-session imports.

use crate::{
    guided_setup::SetupError,
    ui_contract::{CandidateCompatibility, CandidateFreshness, CandidateHandle, CandidateView},
};
#[cfg(feature = "g4-test-helper")]
use seamless_discovery::Advertisement;
use seamless_discovery::guided::GuidedMdns;
use seamless_discovery::guided::{
    CandidateHandle as DiscoveryHandle, ConsentCatalog, LocatorEvent, SelectedLocator,
};
use seamless_transport::pairing_v2::{
    AdmissionAuthorityStore, DurableAdmissionState, ProductIdentity,
    handshake_selected_and_commit_distributed,
    provisional_tls::{
        HandshakeConfig, IncomingHandshakeConfig, PRE_ADMISSION_SELECTION_WINDOW,
        PreAdmissionCandidate, ProvisionalEndpoint,
    },
};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

const QUEUE_CAPACITY: usize = 16;

pub(crate) struct G4DiscoveryCatalog {
    catalog: ConsentCatalog,
    scope: [u8; 8],
    handles: BTreeMap<CandidateHandle, (DiscoveryHandle, [u8; 16])>,
    local_rendezvous: Option<[u8; 16]>,
}

impl G4DiscoveryCatalog {
    pub(crate) fn open(scope: [u8; 8], now_ms: u64) -> Result<Self, SetupError> {
        let mut catalog = ConsentCatalog::default();
        catalog.open(now_ms)?;
        Ok(Self {
            catalog,
            scope,
            handles: BTreeMap::new(),
            local_rendezvous: None,
        })
    }

    fn open_for_session(
        scope: [u8; 8],
        local_rendezvous: [u8; 16],
        now_ms: u64,
    ) -> Result<Self, SetupError> {
        let mut value = Self::open(scope, now_ms)?;
        value.local_rendezvous = Some(local_rendezvous);
        Ok(value)
    }

    pub(crate) fn apply(&mut self, event: LocatorEvent, now_ms: u64) -> Result<(), SetupError> {
        match event {
            LocatorEvent::Observed(advertisement) => {
                let rendezvous = decode_rendezvous(&advertisement.instance)?;
                if self.local_rendezvous == Some(rendezvous) {
                    return Ok(());
                }
                let handle = self.catalog.observe(advertisement, now_ms)?;
                let ui = self.encode(handle)?;
                self.handles.insert(ui, (handle, rendezvous));
            }
            LocatorEvent::Removed(instance) => self.catalog.remove(&instance, now_ms)?,
        }
        self.retain_current(now_ms)?;
        Ok(())
    }

    pub(crate) fn views(&mut self, now_ms: u64) -> Result<Vec<CandidateView>, SetupError> {
        let current = self.catalog.candidates(now_ms)?;
        self.handles
            .retain(|_, (handle, _)| current.iter().any(|view| view.handle == *handle));
        Ok(current
            .into_iter()
            .filter_map(|view| {
                self.handles.iter().find_map(|(ui, (handle, _))| {
                    (*handle == view.handle).then(|| CandidateView {
                        handle: ui.clone(),
                        compatibility: if view.version == 2 && view.pairable {
                            CandidateCompatibility::Compatible
                        } else {
                            CandidateCompatibility::Incompatible
                        },
                        freshness: CandidateFreshness::Current,
                    })
                })
            })
            .collect())
    }

    pub(crate) fn select_once(
        &mut self,
        handle: &CandidateHandle,
        now_ms: u64,
    ) -> Result<SelectedLocator, SetupError> {
        let discovery = self
            .handles
            .get(handle)
            .map(|value| value.0)
            .ok_or(SetupError::StaleCandidate)?;
        let selected = self.catalog.select_once(discovery, now_ms)?;
        self.handles.clear();
        Ok(selected)
    }

    fn retain_current(&mut self, now_ms: u64) -> Result<(), SetupError> {
        let current = self.catalog.candidates(now_ms)?;
        self.handles
            .retain(|_, (handle, _)| current.iter().any(|view| view.handle == *handle));
        Ok(())
    }

    fn current_rendezvous(&self) -> BTreeMap<[u8; 16], CandidateHandle> {
        self.handles
            .iter()
            .map(|(handle, (_, rendezvous))| (*rendezvous, handle.clone()))
            .collect()
    }

    fn encode(&self, handle: DiscoveryHandle) -> Result<CandidateHandle, SetupError> {
        let scope: String = self
            .scope
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("{scope}-{:x}-{:x}", handle.window, handle.sequence)
            .try_into()
            .map_err(|_| SetupError::Limit)
    }
}

fn decode_rendezvous(value: &str) -> Result<[u8; 16], SetupError> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SetupError::InvalidArguments);
    }
    let mut decoded = [0; 16];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| SetupError::InvalidArguments)?;
    }
    Ok(decoded)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingToken {
    attempt: [u8; 32],
    transcript: [u8; 32],
    generation: u64,
}

impl PairingToken {
    pub(crate) fn from_engine(attempt: [u8; 32], transcript: [u8; 32], generation: u64) -> Self {
        Self {
            attempt,
            transcript,
            generation,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionError {
    NoPrompt,
    Stale,
    AlreadyDecided,
}

/// Exact, single-use local consent gate. The token is engine-authored from the
/// live handshake and never reconstructed from UI-visible data.
#[derive(Default)]
pub(crate) struct SasDecisionGate {
    current: Option<PairingToken>,
    consumed: bool,
}

impl SasDecisionGate {
    pub(crate) fn install(&mut self, token: PairingToken) -> Result<(), DecisionError> {
        if self.current.is_some() {
            return Err(DecisionError::AlreadyDecided);
        }
        self.current = Some(token);
        self.consumed = false;
        Ok(())
    }

    pub(crate) fn decide(
        &mut self,
        token: PairingToken,
        matches: bool,
    ) -> Result<bool, DecisionError> {
        let current = self.current.ok_or(DecisionError::NoPrompt)?;
        if current != token {
            return Err(DecisionError::Stale);
        }
        if self.consumed {
            return Err(DecisionError::AlreadyDecided);
        }
        self.consumed = true;
        self.current = None;
        Ok(matches)
    }

    pub(crate) fn cancel(&mut self) {
        self.current = None;
        self.consumed = true;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum G4Command {
    Start {
        generation: u64,
    },
    Stop {
        generation: u64,
    },
    Select {
        generation: u64,
        handle: CandidateHandle,
    },
    Decide {
        token: PairingToken,
        matches: bool,
    },
    Cancel {
        generation: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum G4Event {
    Browsing {
        generation: u64,
    },
    Candidates {
        generation: u64,
        candidates: Vec<CandidateView>,
    },
    SasReady {
        generation: u64,
        token: PairingToken,
        candidate: CandidateHandle,
        words: [String; 4],
    },
    DurableSnapshot {
        generation: Option<u64>,
        entries: Vec<DurableView>,
    },
    Rejected {
        generation: u64,
    },
    Cancelled {
        generation: u64,
    },
    Expired {
        generation: u64,
    },
    RemoteOutcomeUnknown {
        generation: u64,
    },
}

impl G4Event {
    pub(crate) fn session_generation(&self) -> Option<u64> {
        match self {
            Self::Browsing { generation }
            | Self::Candidates { generation, .. }
            | Self::SasReady { generation, .. }
            | Self::Rejected { generation }
            | Self::Cancelled { generation }
            | Self::Expired { generation }
            | Self::RemoteOutcomeUnknown { generation } => Some(*generation),
            Self::DurableSnapshot { generation, .. } => *generation,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableView {
    pub handle: String,
    pub confirmed: bool,
}

struct LiveSession {
    generation: u64,
    catalog: G4DiscoveryCatalog,
    browser: Option<GuidedMdns>,
    allowlist: Arc<Mutex<BTreeMap<[u8; 16], CandidateHandle>>>,
    selected: tokio::sync::mpsc::Sender<(CandidateHandle, SelectedLocator)>,
    decisions: tokio::sync::mpsc::Sender<(PairingToken, bool)>,
    cancel: tokio::sync::watch::Sender<bool>,
    _advertisement: crate::product_pairing_adapter::EngineAdvertisement,
    decision_gate: SasDecisionGate,
    task: tokio::task::JoinHandle<()>,
    browsing: bool,
}

pub struct RealG4Backend {
    runtime: tokio::runtime::Runtime,
    session: Option<LiveSession>,
    events: tokio::sync::mpsc::Receiver<G4Event>,
    event_tx: tokio::sync::mpsc::Sender<G4Event>,
    now_ms: u64,
    store: Arc<AdmissionAuthorityStore>,
    identity: Arc<ProductIdentity>,
    origin: Instant,
}

impl RealG4Backend {
    fn join_task_bounded(&self, task: &mut tokio::task::JoinHandle<()>) -> Result<(), SetupError> {
        let first = self
            .runtime
            .block_on(async { tokio::time::timeout(Duration::from_secs(2), &mut *task).await });
        match first {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(SetupError::Unavailable),
            Err(_) => {
                task.abort();
                self.runtime
                    .block_on(async {
                        tokio::time::timeout(Duration::from_secs(2), &mut *task).await
                    })
                    .map(|_| ())
                    .map_err(|_| SetupError::Unavailable)
            }
        }
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self, SetupError> {
        Self::open_with_initial_snapshot(root, |store| durable_snapshot(store, None))
    }

    fn open_with_initial_snapshot(
        root: impl AsRef<Path>,
        initial_snapshot: impl FnOnce(&Arc<AdmissionAuthorityStore>) -> Result<G4Event, SetupError>,
    ) -> Result<Self, SetupError> {
        let root = root.as_ref().to_path_buf();
        let store = Arc::new(
            AdmissionAuthorityStore::open(root.join("g4-admission"))
                .map_err(|_| SetupError::Unavailable)?,
        );
        let identity = Arc::new(
            ProductIdentity::open_or_create(&root.join("g4-identity"))
                .map_err(|_| SetupError::Unavailable)?,
        );
        let initial_snapshot = initial_snapshot(&store)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .thread_name("g4-pairing-tokio")
            .build()
            .map_err(|_| SetupError::Unavailable)?;
        let (event_tx, events) = tokio::sync::mpsc::channel(16);
        let backend = Self {
            runtime,
            session: None,
            events,
            event_tx,
            now_ms: 0,
            store,
            identity,
            origin: Instant::now(),
        };
        let _ = backend.event_tx.try_send(initial_snapshot);
        Ok(backend)
    }

    fn start(&mut self, generation: u64) -> Result<Vec<G4Event>, SetupError> {
        if generation == 0 || self.session.is_some() {
            return Err(SetupError::InvalidState);
        }
        let mut local = [0; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut local);
        if local == [0; 16] {
            local[0] = 1;
        }
        #[cfg(feature = "g4-test-helper")]
        let injected = test_pairing_config()?;
        #[cfg(feature = "g4-test-helper")]
        if let Some(config) = &injected {
            local = config.local_rendezvous;
        }
        #[cfg(feature = "g4-test-helper")]
        let bind_address = injected
            .as_ref()
            .map_or_else(|| "0.0.0.0:0".parse().unwrap(), |value| value.bind_address);
        #[cfg(not(feature = "g4-test-helper"))]
        let bind_address = "0.0.0.0:0".parse().unwrap();
        let runtime_guard = self.runtime.enter();
        let endpoint = Arc::new(
            self.identity
                .bind_pairing(bind_address)
                .map_err(|_| SetupError::Unavailable)?,
        );
        drop(runtime_guard);
        let port = endpoint
            .local_addr()
            .map_err(|_| SetupError::Unavailable)?
            .port();
        let advertisement =
            crate::product_pairing_adapter::EngineAdvertisement::start_exact(local, port)?;
        #[cfg(feature = "g4-test-helper")]
        let browser = if injected.is_some() {
            None
        } else {
            Some(GuidedMdns::start()?)
        };
        #[cfg(not(feature = "g4-test-helper"))]
        let browser = Some(GuidedMdns::start()?);
        let mut scope = [0; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut scope);
        #[allow(unused_mut)] // Mutated only by the closed g4-test-helper seam.
        let mut catalog = G4DiscoveryCatalog::open_for_session(scope, local, self.now_ms)?;
        #[cfg(feature = "g4-test-helper")]
        if let Some(config) = injected {
            catalog.apply(
                LocatorEvent::Observed(Advertisement {
                    instance: config
                        .peer_rendezvous
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                    version: 2,
                    pairable: true,
                    addresses: vec![config.peer_address],
                    ttl: None,
                }),
                self.now_ms,
            )?;
        }
        let allowlist = Arc::new(Mutex::new(BTreeMap::new()));
        let (selected_tx, selected_rx) = tokio::sync::mpsc::channel(1);
        let (decision_tx, decision_rx) = tokio::sync::mpsc::channel(1);
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let task = self.runtime.spawn(run_live_attempt(
            generation,
            endpoint,
            local,
            allowlist.clone(),
            selected_rx,
            decision_rx,
            cancel_rx,
            self.store.clone(),
            self.event_tx.clone(),
        ));
        self.session = Some(LiveSession {
            generation,
            catalog,
            browser,
            allowlist,
            selected: selected_tx,
            decisions: decision_tx,
            cancel: cancel_tx,
            _advertisement: advertisement,
            decision_gate: SasDecisionGate::default(),
            task,
            browsing: true,
        });
        Ok(vec![G4Event::Browsing { generation }])
    }

    fn stop(&mut self, generation: u64, report_outcome: bool) -> Result<Vec<G4Event>, SetupError> {
        let session = self.session.as_ref().ok_or(SetupError::InvalidState)?;
        if session.generation != generation {
            return Err(SetupError::StaleCandidate);
        }
        let mut session = self.session.take().unwrap();
        let _ = session.cancel.send(true);
        let joined = self.join_task_bounded(&mut session.task);
        // Joining closes the generation: every event now present belongs to
        // this stopped attempt and is returned before a new Start is allowed.
        let mut terminal = Vec::new();
        while let Ok(event) = self.events.try_recv() {
            terminal.push(event);
        }
        if !report_outcome {
            return joined.map(|()| Vec::new());
        }
        if joined.is_err() {
            return Ok(vec![G4Event::RemoteOutcomeUnknown { generation }]);
        }
        let snapshot = durable_snapshot(&self.store, Some(generation));
        Ok(classify_stopped_attempt(generation, terminal, snapshot))
    }

    fn refresh(&mut self) -> Vec<G4Event> {
        self.now_ms = self.origin.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let mut emitted = Vec::new();
        if let Some(session) = self.session.as_mut()
            && session.browsing
        {
            let browser_events = match session.browser.as_mut() {
                Some(browser) => browser.poll(),
                None => Ok(Vec::new()),
            };
            match browser_events {
                Ok(events) => {
                    for event in events {
                        match session.catalog.apply(event, self.now_ms) {
                            Ok(()) | Err(SetupError::InvalidArguments) => {}
                            Err(SetupError::Limit) => {
                                let _ = session.cancel.send(true);
                                emitted.push(G4Event::Rejected {
                                    generation: session.generation,
                                });
                                break;
                            }
                            Err(_) => {
                                let _ = session.cancel.send(true);
                                emitted.push(G4Event::Rejected {
                                    generation: session.generation,
                                });
                                break;
                            }
                        }
                    }
                    if let Ok(mut allowlist) = session.allowlist.lock() {
                        *allowlist = session.catalog.current_rendezvous();
                    }
                    match session.catalog.views(self.now_ms) {
                        Ok(candidates) => emitted.push(G4Event::Candidates {
                            generation: session.generation,
                            candidates,
                        }),
                        Err(SetupError::Expired) => {
                            let _ = session.cancel.send(true);
                            emitted.push(G4Event::Expired {
                                generation: session.generation,
                            });
                        }
                        Err(_) => {
                            let _ = session.cancel.send(true);
                            emitted.push(G4Event::Rejected {
                                generation: session.generation,
                            });
                        }
                    }
                }
                Err(_) => {
                    let _ = session.cancel.send(true);
                }
            }
        }
        let mut terminal = false;
        while let Ok(event) = self.events.try_recv() {
            if let G4Event::SasReady { token, .. } = &event
                && let Some(session) = self.session.as_mut()
            {
                session.browsing = false;
                let _ = session.decision_gate.install(*token);
            }
            if matches!(
                event,
                G4Event::DurableSnapshot { .. }
                    | G4Event::Rejected { .. }
                    | G4Event::Cancelled { .. }
                    | G4Event::Expired { .. }
                    | G4Event::RemoteOutcomeUnknown { .. }
            ) {
                terminal = true;
            }
            emitted.push(event);
        }
        if terminal
            && let Some(mut session) = self.session.take()
            && self.join_task_bounded(&mut session.task).is_err()
        {
            emitted.push(G4Event::RemoteOutcomeUnknown {
                generation: session.generation,
            });
        }
        emitted
    }
}

fn classify_stopped_attempt(
    generation: u64,
    mut terminal: Vec<G4Event>,
    snapshot: Result<G4Event, SetupError>,
) -> Vec<G4Event> {
    match snapshot {
        Ok(snapshot) if matches!(&snapshot, G4Event::DurableSnapshot { entries, .. } if !entries.is_empty()) =>
        {
            vec![snapshot]
        }
        Err(_) => vec![G4Event::RemoteOutcomeUnknown { generation }],
        _ if terminal.is_empty() => vec![G4Event::Cancelled { generation }],
        _ => {
            // The task completed and the store is empty, so only a classified
            // precommit terminal can remain.
            terminal.retain(|event| {
                matches!(
                    event,
                    G4Event::Rejected { .. } | G4Event::Cancelled { .. } | G4Event::Expired { .. }
                )
            });
            if terminal.is_empty() {
                terminal.push(G4Event::Cancelled { generation });
            }
            terminal
        }
    }
}

#[cfg(feature = "g4-test-helper")]
struct TestPairingConfig {
    local_rendezvous: [u8; 16],
    peer_rendezvous: [u8; 16],
    bind_address: std::net::SocketAddr,
    peer_address: std::net::SocketAddr,
}

#[cfg(feature = "g4-test-helper")]
fn test_pairing_config() -> Result<Option<TestPairingConfig>, SetupError> {
    let Some(local) = std::env::var_os("CSF12_G4_TEST_LOCAL_RENDEZVOUS") else {
        return Ok(None);
    };
    let peer =
        std::env::var_os("CSF12_G4_TEST_PEER_RENDEZVOUS").ok_or(SetupError::InvalidArguments)?;
    let bind = std::env::var_os("CSF12_G4_TEST_BIND").ok_or(SetupError::InvalidArguments)?;
    let peer_address =
        std::env::var_os("CSF12_G4_TEST_PEER_ADDRESS").ok_or(SetupError::InvalidArguments)?;
    let local = decode_rendezvous(local.to_str().ok_or(SetupError::InvalidArguments)?)?;
    let peer_rendezvous = decode_rendezvous(peer.to_str().ok_or(SetupError::InvalidArguments)?)?;
    let bind_address: std::net::SocketAddr = bind
        .to_str()
        .ok_or(SetupError::InvalidArguments)?
        .parse()
        .map_err(|_| SetupError::InvalidArguments)?;
    let peer_address: std::net::SocketAddr = peer_address
        .to_str()
        .ok_or(SetupError::InvalidArguments)?
        .parse()
        .map_err(|_| SetupError::InvalidArguments)?;
    if local == peer_rendezvous
        || !bind_address.ip().is_loopback()
        || !peer_address.ip().is_loopback()
    {
        return Err(SetupError::InvalidArguments);
    }
    Ok(Some(TestPairingConfig {
        local_rendezvous: local,
        peer_rendezvous,
        bind_address,
        peer_address,
    }))
}

fn durable_snapshot(
    store: &AdmissionAuthorityStore,
    generation: Option<u64>,
) -> Result<G4Event, SetupError> {
    let relationships = store
        .durable_admissions()
        .map_err(|_| SetupError::Unavailable)?
        .into_iter()
        .map(|entry| DurableView {
            handle: entry
                .opaque_id()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            confirmed: entry.state() == DurableAdmissionState::Confirmed,
        })
        .collect();
    Ok(G4Event::DurableSnapshot {
        generation,
        entries: relationships,
    })
}

#[allow(clippy::too_many_arguments)] // Explicitly names each bounded ownership channel.
async fn run_live_attempt(
    generation: u64,
    endpoint: Arc<ProvisionalEndpoint>,
    local_rendezvous: [u8; 16],
    allowlist: Arc<Mutex<BTreeMap<[u8; 16], CandidateHandle>>>,
    mut selected: tokio::sync::mpsc::Receiver<(CandidateHandle, SelectedLocator)>,
    mut decisions: tokio::sync::mpsc::Receiver<(PairingToken, bool)>,
    mut cancel: tokio::sync::watch::Receiver<bool>,
    store: Arc<AdmissionAuthorityStore>,
    events: tokio::sync::mpsc::Sender<G4Event>,
) {
    let incoming_endpoint = endpoint.clone();
    let incoming_allowlist = allowlist.clone();
    let incoming = async move {
        let channel = incoming_endpoint.accept().await.map_err(|_error| {
            eprintln!("G4_PAIRING_REJECT_STAGE=incoming_accept");
        })?;
        let selected_handle = Arc::new(Mutex::new(None));
        let captured_handle = selected_handle.clone();
        let candidate = channel
            .prepare_incoming(
                IncomingHandshakeConfig {
                    device_name: "Control Shift F12".into(),
                    os: std::env::consts::OS.into(),
                    local_rendezvous,
                },
                move |remote| {
                    let handle = incoming_allowlist
                        .lock()
                        .ok()
                        .and_then(|set| set.get(&remote).cloned());
                    if let Some(handle) = handle {
                        if let Ok(mut selected) = captured_handle.lock() {
                            *selected = Some(handle);
                        }
                        true
                    } else {
                        false
                    }
                },
            )
            .await
            .map_err(|_error| {
                eprintln!("G4_PAIRING_REJECT_STAGE=incoming_prepare");
            })?;
        let handle = selected_handle.lock().map_err(|_| ())?.clone().ok_or(())?;
        Ok::<_, ()>((candidate, handle))
    };
    let outgoing_endpoint = endpoint.clone();
    let outgoing = async move {
        let (handle, locator) = selected.recv().await.ok_or(())?;
        let remote = decode_rendezvous(&locator.rendezvous).map_err(|_| ())?;
        // Prefer exactly one dialer when both users select concurrently, but
        // preserve unilateral selection: the larger rendezvous waits out the
        // duplicate window, then dials if no incoming candidate won first.
        if local_rendezvous >= remote {
            tokio::time::sleep(PRE_ADMISSION_SELECTION_WINDOW).await;
        }
        let address = *locator.addresses.first().ok_or(())?;
        let channel = outgoing_endpoint.connect(address).await.map_err(|_error| {
            eprintln!("G4_PAIRING_REJECT_STAGE=outgoing_connect");
        })?;
        let candidate = channel
            .prepare_pre_admission(HandshakeConfig {
                device_name: "Control Shift F12".into(),
                os: std::env::consts::OS.into(),
                local_rendezvous,
                selected_rendezvous: remote,
            })
            .await
            .map_err(|_error| {
                eprintln!("G4_PAIRING_REJECT_STAGE=outgoing_prepare");
            })?;
        Ok::<_, ()>((candidate, handle))
    };
    let selected = {
        tokio::pin!(incoming);
        tokio::pin!(outgoing);
        let ((first, candidate_handle), first_incoming): (
            (PreAdmissionCandidate, CandidateHandle),
            bool,
        ) = tokio::select! {
            _ = cancel.changed() => { let _ = events.try_send(G4Event::Cancelled { generation }); return; }
            result = &mut incoming => match result { Ok(value) => (value, true), Err(_) => { let _ = events.try_send(G4Event::Rejected { generation }); return; } },
            result = &mut outgoing => match result { Ok(value) => (value, false), Err(_) => { let _ = events.try_send(G4Event::Rejected { generation }); return; } },
        };
        let deadline = first.selection_deadline();
        let competitor = if first_incoming {
            tokio::time::timeout_at(deadline, &mut outgoing)
                .await
                .ok()
                .and_then(Result::ok)
        } else {
            tokio::time::timeout_at(deadline, &mut incoming)
                .await
                .ok()
                .and_then(Result::ok)
        };
        let winner = match competitor {
            Some((competitor, competing_handle)) if competing_handle == candidate_handle => {
                first.select(Some(competitor))
            }
            Some(_) => {
                Err(seamless_transport::pairing_v2::provisional_tls::HandshakeError::Rejected)
            }
            None => first.select_after_window().await,
        };
        winner.map(|winner| (winner, candidate_handle))
    };
    // The incoming/outgoing preparation futures are dropped by this point, so
    // neither a losing connection nor a pending dial survives into SAS.
    let (winner, candidate_handle) = match selected {
        Ok(value) => value,
        Err(_error) => {
            eprintln!("G4_PAIRING_REJECT_STAGE=selection_convergence");
            let _ = events.try_send(G4Event::Rejected { generation });
            return;
        }
    };
    let outcome = {
        let event_tx = events.clone();
        let handshake =
            handshake_selected_and_commit_distributed(&store, winner, move |prompt| async move {
                let token = PairingToken::from_engine(
                    prompt.attempt,
                    prompt.transcript,
                    prompt.ui_generation,
                );
                if event_tx
                    .send(G4Event::SasReady {
                        generation,
                        token,
                        candidate: candidate_handle,
                        words: prompt.words.clone(),
                    })
                    .await
                    .is_err()
                {
                    return prompt.decision(false);
                }
                while let Some((candidate, matches)) = decisions.recv().await {
                    if candidate == token {
                        return prompt.decision(matches);
                    }
                }
                prompt.decision(false)
            });
        tokio::pin!(handshake);
        tokio::select! {
            _ = cancel.changed() => None,
            result = &mut handshake => Some(result),
        }
    };
    match outcome {
        None => match durable_snapshot(&store, Some(generation)) {
            Ok(G4Event::DurableSnapshot { entries, .. })
                if entries.iter().any(|entry| !entry.confirmed) =>
            {
                let _ = events
                    .send(G4Event::DurableSnapshot {
                        generation: Some(generation),
                        entries,
                    })
                    .await;
            }
            Ok(_) => {
                let _ = events.send(G4Event::Cancelled { generation }).await;
            }
            Err(_) => {
                let _ = events
                    .send(G4Event::RemoteOutcomeUnknown { generation })
                    .await;
            }
        },
        Some(Ok(_)) => {
            if let Ok(snapshot) = durable_snapshot(&store, Some(generation)) {
                let _ = events.send(snapshot).await;
            }
        }
        Some(Err(seamless_transport::pairing_v2::DistributedPairingError::Cancelled)) => {
            let _ = events.send(G4Event::Cancelled { generation }).await;
        }
        Some(Err(seamless_transport::pairing_v2::DistributedPairingError::Rejected)) => {
            let _ = events.send(G4Event::Rejected { generation }).await;
        }
        Some(Err(seamless_transport::pairing_v2::DistributedPairingError::Storage)) => {
            let _ = events
                .send(G4Event::RemoteOutcomeUnknown { generation })
                .await;
        }
    }
}

impl G4WorkerBackend for RealG4Backend {
    fn command(&mut self, command: G4Command) -> Vec<G4Event> {
        let fallback_generation = match &command {
            G4Command::Start { generation }
            | G4Command::Stop { generation }
            | G4Command::Select { generation, .. }
            | G4Command::Cancel { generation } => *generation,
            G4Command::Decide { token, .. } => self
                .session
                .as_ref()
                .map(|session| session.generation)
                .unwrap_or_else(|| token.generation()),
        };
        let result = match command {
            G4Command::Start { generation } => {
                // A durable snapshot queued by open belongs to backend startup,
                // never to the pairing attempt that is about to be created.
                let mut startup = Vec::new();
                while let Ok(event) = self.events.try_recv() {
                    if matches!(
                        event,
                        G4Event::DurableSnapshot {
                            generation: None,
                            ..
                        }
                    ) {
                        startup.push(event);
                    }
                }
                self.start(generation).map(|mut events| {
                    startup.append(&mut events);
                    startup
                })
            }
            G4Command::Stop { generation } => self.stop(generation, false),
            G4Command::Select { generation, handle } => {
                let session = self.session.as_mut().ok_or(SetupError::InvalidState);
                session.and_then(|session| {
                    if session.generation != generation {
                        return Err(SetupError::StaleCandidate);
                    }
                    let selected = session.catalog.select_once(&handle, self.now_ms)?;
                    let selected_rendezvous = decode_rendezvous(&selected.rendezvous)?;
                    let mut allowlist = session
                        .allowlist
                        .lock()
                        .map_err(|_| SetupError::Unavailable)?;
                    allowlist.clear();
                    allowlist.insert(selected_rendezvous, handle.clone());
                    drop(allowlist);
                    session
                        .selected
                        .try_send((handle, selected))
                        .map_err(|_| SetupError::InvalidState)?;
                    session.browsing = false;
                    Ok(Vec::new())
                })
            }
            G4Command::Decide { token, matches } => {
                let session = self.session.as_mut().ok_or(SetupError::InvalidState);
                session.and_then(|session| {
                    let matches = session
                        .decision_gate
                        .decide(token, matches)
                        .map_err(|_| SetupError::StaleCandidate)?;
                    session
                        .decisions
                        .try_send((token, matches))
                        .map_err(|_| SetupError::InvalidState)?;
                    Ok(Vec::new())
                })
            }
            G4Command::Cancel { generation } => self.stop(generation, true),
        };
        result.unwrap_or_else(|_error| {
            #[cfg(feature = "g4-test-helper")]
            eprintln!("G4_TEST_BACKEND_REJECT={_error:?}");
            vec![G4Event::Rejected {
                generation: fallback_generation,
            }]
        })
    }

    fn poll(&mut self) -> Vec<G4Event> {
        self.refresh()
    }

    fn shutdown(&mut self) {
        if let Some(mut session) = self.session.take() {
            session.decision_gate.cancel();
            let _ = session.cancel.send(true);
            let _ = self.join_task_bounded(&mut session.task);
        }
    }
}

pub trait G4WorkerBackend: Send + 'static {
    fn command(&mut self, command: G4Command) -> Vec<G4Event>;
    fn poll(&mut self) -> Vec<G4Event>;
    fn shutdown(&mut self);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerError {
    Busy,
    Closed,
    ShutdownTimeout,
}

pub struct G4PairingWorker {
    commands: Option<SyncSender<G4Command>>,
    events: Option<Receiver<G4Event>>,
    stopping: Arc<AtomicBool>,
    stopped: Receiver<()>,
    thread: Option<JoinHandle<()>>,
}

impl G4PairingWorker {
    pub fn spawn(backend: impl G4WorkerBackend) -> Result<Self, WorkerError> {
        Self::spawn_factory(move || Ok(backend))
    }

    pub(crate) fn spawn_factory<B, F>(factory: F) -> Result<Self, WorkerError>
    where
        B: G4WorkerBackend,
        F: FnOnce() -> Result<B, WorkerError> + Send + 'static,
    {
        Self::spawn_factory_with(factory, |worker| {
            std::thread::Builder::new()
                .name("g4-pairing-worker".into())
                .spawn(worker)
        })
    }

    fn spawn_factory_with<B, F, S>(factory: F, spawn_thread: S) -> Result<Self, WorkerError>
    where
        B: G4WorkerBackend,
        F: FnOnce() -> Result<B, WorkerError> + Send + 'static,
        S: FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>>,
    {
        let (commands, command_rx) = mpsc::sync_channel(QUEUE_CAPACITY);
        let (events, event_rx) = mpsc::sync_channel(QUEUE_CAPACITY);
        let (stopped_tx, stopped) = mpsc::sync_channel(1);
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_stopping = stopping.clone();
        let worker = Box::new(move || {
            let mut backend = match factory() {
                Ok(backend) => backend,
                Err(error) => {
                    let _ = started_tx.send(Err(error));
                    return;
                }
            };
            if started_tx.send(Ok(())).is_err() {
                backend.shutdown();
                return;
            }
            'worker: while !worker_stopping.load(Ordering::Acquire) {
                match command_rx.recv_timeout(Duration::from_millis(10)) {
                    Ok(command) => {
                        for event in backend.command(command) {
                            if events.send(event).is_err() {
                                break 'worker;
                            }
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        for event in backend.poll() {
                            if events.send(event).is_err() {
                                break 'worker;
                            }
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            backend.shutdown();
            drop(backend);
            let _ = stopped_tx.send(());
        });
        let thread = spawn_thread(worker).map_err(|_| WorkerError::Closed)?;
        match started_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = thread.join();
                return Err(error);
            }
            Err(_) => {
                let _ = thread.join();
                return Err(WorkerError::Closed);
            }
        }
        Ok(Self {
            commands: Some(commands),
            events: Some(event_rx),
            stopping,
            stopped,
            thread: Some(thread),
        })
    }

    pub fn try_command(&self, command: G4Command) -> Result<(), WorkerError> {
        self.commands
            .as_ref()
            .ok_or(WorkerError::Closed)?
            .try_send(command)
            .map_err(|error| match error {
                TrySendError::Full(_) => WorkerError::Busy,
                TrySendError::Disconnected(_) => WorkerError::Closed,
            })
    }

    pub fn try_event(&self) -> Option<G4Event> {
        self.events.as_ref()?.try_recv().ok()
    }

    pub fn shutdown(&mut self, timeout: Duration) -> Result<(), WorkerError> {
        self.stopping.store(true, Ordering::Release);
        self.commands.take();
        self.events.take();
        let deadline = Instant::now() + timeout;
        self.stopped
            .recv_timeout(timeout)
            .map_err(|_| WorkerError::ShutdownTimeout)?;
        if Instant::now() > deadline {
            return Err(WorkerError::ShutdownTimeout);
        }
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| WorkerError::Closed)?;
        }
        Ok(())
    }
}

impl Drop for G4PairingWorker {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.commands.take();
        self.events.take();
        if self.stopped.recv_timeout(Duration::from_secs(2)).is_ok()
            && let Some(thread) = self.thread.take()
        {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seamless_discovery::{Advertisement, guided::LocatorEvent};
    use std::sync::atomic::AtomicBool;

    fn advertisement(n: u64) -> Advertisement {
        Advertisement {
            instance: format!("{n:032x}"),
            version: 2,
            pairable: true,
            addresses: vec!["127.0.0.1:57892".parse().unwrap()],
            ttl: None,
        }
    }

    #[test]
    fn g4_sas_decision_binds_exact_attempt_transcript_generation_once() {
        let current = PairingToken::from_engine([1; 32], [2; 32], 3);
        let stale_attempt = PairingToken::from_engine([9; 32], [2; 32], 3);
        let stale_transcript = PairingToken::from_engine([1; 32], [9; 32], 3);
        let stale_generation = PairingToken::from_engine([1; 32], [2; 32], 4);
        let mut gate = SasDecisionGate::default();
        gate.install(current).unwrap();
        assert_eq!(gate.decide(stale_attempt, true), Err(DecisionError::Stale));
        assert_eq!(
            gate.decide(stale_transcript, true),
            Err(DecisionError::Stale)
        );
        assert_eq!(
            gate.decide(stale_generation, true),
            Err(DecisionError::Stale)
        );
        assert_eq!(gate.decide(current, false), Ok(false));
        assert_eq!(gate.decide(current, true), Err(DecisionError::NoPrompt));
    }

    #[test]
    fn cancel_clears_the_exact_transient_prompt() {
        let token = PairingToken::from_engine([1; 32], [2; 32], 3);
        let mut gate = SasDecisionGate::default();
        gate.install(token).unwrap();
        gate.cancel();
        assert_eq!(gate.decide(token, true), Err(DecisionError::NoPrompt));
    }

    #[test]
    fn g4_catalog_projects_only_opaque_current_handles_and_consumes_selection() {
        let mut catalog = G4DiscoveryCatalog::open([3; 8], 10).unwrap();
        catalog
            .apply(LocatorEvent::Observed(advertisement(1)), 11)
            .unwrap();
        let views = catalog.views(11).unwrap();
        assert_eq!(views.len(), 1);
        assert!(!views[0].handle.as_str().contains("127.0.0.1"));
        assert!(!views[0].handle.as_str().contains(&format!("{:032x}", 1)));
        let selected = catalog.select_once(&views[0].handle, 12).unwrap();
        assert_eq!(selected.rendezvous, format!("{:032x}", 1));
        assert!(catalog.select_once(&views[0].handle, 13).is_err());
    }

    #[test]
    fn repeated_observation_preserves_the_ui_handle_until_selection() {
        let mut catalog = G4DiscoveryCatalog::open([3; 8], 10).unwrap();
        catalog
            .apply(LocatorEvent::Observed(advertisement(1)), 11)
            .unwrap();
        let original = catalog.views(11).unwrap()[0].handle.clone();

        catalog
            .apply(LocatorEvent::Observed(advertisement(1)), 12)
            .unwrap();

        assert_eq!(catalog.views(12).unwrap()[0].handle, original);
        assert!(catalog.select_once(&original, 13).is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn backend_store_error_does_not_drop_runtime_in_async_context() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("g4-admission"), b"not a directory").unwrap();

        assert!(RealG4Backend::open(root.path()).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn backend_snapshot_error_does_not_drop_runtime_in_async_context() {
        let root = tempfile::tempdir().unwrap();
        let snapshot_reached = AtomicBool::new(false);

        let result = RealG4Backend::open_with_initial_snapshot(root.path(), |_| {
            snapshot_reached.store(true, Ordering::Release);
            Err(SetupError::Unavailable)
        });

        assert!(snapshot_reached.load(Ordering::Acquire));
        assert!(matches!(result, Err(SetupError::Unavailable)));
    }

    #[test]
    fn backend_reopens_the_same_product_identity_for_pairing_and_v01() {
        let root = tempfile::tempdir().unwrap();
        let first = RealG4Backend::open(root.path())
            .unwrap()
            .identity
            .fingerprint();
        let second = RealG4Backend::open(root.path())
            .unwrap()
            .identity
            .fingerprint();

        assert_ne!(first, [0; 32]);
        assert_eq!(first, second);
    }

    struct NoopBackend;

    impl G4WorkerBackend for NoopBackend {
        fn command(&mut self, _command: G4Command) -> Vec<G4Event> {
            Vec::new()
        }

        fn poll(&mut self) -> Vec<G4Event> {
            Vec::new()
        }

        fn shutdown(&mut self) {}
    }

    #[tokio::test(flavor = "current_thread")]
    async fn worker_factory_initializes_backend_off_the_async_caller() {
        let mut worker = G4PairingWorker::spawn_factory(|| {
            assert!(tokio::runtime::Handle::try_current().is_err());
            Ok(NoopBackend)
        })
        .unwrap();

        worker.shutdown(Duration::from_secs(1)).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn worker_spawn_failure_does_not_invoke_the_backend_factory() {
        let invoked = Arc::new(AtomicBool::new(false));
        let invoked_by_factory = invoked.clone();

        let result = G4PairingWorker::spawn_factory_with(
            move || {
                invoked_by_factory.store(true, Ordering::Release);
                Ok(NoopBackend)
            },
            |_| Err(std::io::Error::other("injected thread creation failure")),
        );

        assert!(matches!(result, Err(WorkerError::Closed)));
        assert!(!invoked.load(Ordering::Acquire));
    }

    struct SlowDropBackend {
        dropped: Arc<AtomicBool>,
    }

    impl G4WorkerBackend for SlowDropBackend {
        fn command(&mut self, _command: G4Command) -> Vec<G4Event> {
            Vec::new()
        }

        fn poll(&mut self) -> Vec<G4Event> {
            Vec::new()
        }

        fn shutdown(&mut self) {}
    }

    impl Drop for SlowDropBackend {
        fn drop(&mut self) {
            std::thread::sleep(Duration::from_millis(200));
            self.dropped.store(true, Ordering::Release);
        }
    }

    #[test]
    fn worker_shutdown_timeout_is_observable_before_backend_drop_completes() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mut worker = G4PairingWorker::spawn(SlowDropBackend {
            dropped: dropped.clone(),
        })
        .unwrap();
        let started = Instant::now();

        assert_eq!(
            worker.shutdown(Duration::from_millis(25)),
            Err(WorkerError::ShutdownTimeout)
        );
        assert!(started.elapsed() < Duration::from_millis(150));
        assert!(!dropped.load(Ordering::Acquire));
    }

    #[test]
    fn stopped_postcommit_attempt_projects_store_quarantine_not_precommit_cancel() {
        let quarantine = G4Event::DurableSnapshot {
            generation: Some(7),
            entries: vec![DurableView {
                handle: "quarantine-1".into(),
                confirmed: false,
            }],
        };

        assert_eq!(
            classify_stopped_attempt(7, Vec::new(), Ok(quarantine.clone())),
            vec![quarantine]
        );
        assert_eq!(
            classify_stopped_attempt(7, Vec::new(), Err(SetupError::Unavailable)),
            vec![G4Event::RemoteOutcomeUnknown { generation: 7 }]
        );
    }
}
