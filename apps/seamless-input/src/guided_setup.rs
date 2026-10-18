//! Experimental local-gesture controller. Locators are never authenticated peers.
//! No transport emitter, admission writer, legacy fallback or input adapter.
use seamless_discovery::guided::{
    CandidateHandle, ConsentCatalog, DiscoveryError, GuidedMdns, LocatorEvent,
};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupError {
    InvalidState,
    UnsupportedPlatform,
    Unavailable,
    Expired,
    ClockRollback,
    Limit,
    StaleCandidate,
    Incompatible,
    InvalidArguments,
    HandshakeEnvelopePending,
}
impl From<DiscoveryError> for SetupError {
    fn from(value: DiscoveryError) -> Self {
        match value {
            DiscoveryError::Closed => Self::InvalidState,
            DiscoveryError::Expired => Self::Expired,
            DiscoveryError::ClockRollback => Self::ClockRollback,
            DiscoveryError::Invalid => Self::InvalidArguments,
            DiscoveryError::Limit => Self::Limit,
            DiscoveryError::Stale => Self::StaleCandidate,
            DiscoveryError::Incompatible => Self::Incompatible,
            DiscoveryError::Unavailable => Self::Unavailable,
        }
    }
}
pub trait SetupClock {
    fn now_ms(&self) -> Result<u64, SetupError>;
}
pub struct OsSetupClock {
    origin: Instant,
}
impl Default for OsSetupClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}
impl SetupClock for OsSetupClock {
    fn now_ms(&self) -> Result<u64, SetupError> {
        u64::try_from(self.origin.elapsed().as_millis()).map_err(|_| SetupError::Limit)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handle {
    pub scope: String,
    pub window: u64,
    pub sequence: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SetupCommand {
    Snapshot {},
    OpenDiscovery {},
    Refresh {},
    CloseDiscovery {},
    Select { handle: Handle },
    Cancel {},
    CompareMatch {},
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupStatus {
    Closed,
    Browsing,
    HandshakeEnvelopePending,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportStatus {
    HandshakeEnvelopePending,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CandidateView {
    pub handle: Handle,
    pub version: u16,
    pub pairable: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetupSnapshot {
    pub schema_version: u32,
    pub status: SetupStatus,
    pub pairing_transport: TransportStatus,
    pub candidates: Vec<CandidateView>,
    pub authenticated_sessions: u32,
    pub promotion_enabled: bool,
    pub input_enabled: bool,
    pub clipboard_enabled: bool,
}

pub trait DiscoveryBackend {
    fn poll(&mut self) -> Result<Vec<LocatorEvent>, SetupError>;
}
impl DiscoveryBackend for GuidedMdns {
    fn poll(&mut self) -> Result<Vec<LocatorEvent>, SetupError> {
        GuidedMdns::poll(self).map_err(Into::into)
    }
}
pub type BackendFactory = Box<dyn FnMut() -> Result<Box<dyn DiscoveryBackend>, SetupError>>;
pub struct SetupController<C: SetupClock> {
    clock: C,
    factory: BackendFactory,
    backend: Option<Box<dyn DiscoveryBackend>>,
    catalog: ConsentCatalog,
    status: SetupStatus,
    last: u64,
    poisoned: bool,
    scope: String,
}
impl Default for SetupController<OsSetupClock> {
    fn default() -> Self {
        Self::new(
            OsSetupClock::default(),
            Box::new(|| Ok(Box::new(GuidedMdns::start().map_err(SetupError::from)?))),
        )
    }
}
impl<C: SetupClock> SetupController<C> {
    pub fn new(clock: C, factory: BackendFactory) -> Self {
        use rand::RngCore;
        let mut scope = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut scope);
        Self {
            clock,
            factory,
            backend: None,
            catalog: ConsentCatalog::default(),
            status: SetupStatus::Closed,
            last: 0,
            poisoned: false,
            scope: scope.iter().map(|b| format!("{b:02x}")).collect(),
        }
    }
    fn stop(&mut self, now: u64) {
        self.backend = None;
        let _ = self.catalog.close(now);
        self.status = SetupStatus::Closed;
    }
    /// Explicit shutdown drops the backend without waiting for another request.
    pub fn shutdown(&mut self) {
        self.stop(self.last);
    }
    pub fn execute(&mut self, command: SetupCommand) -> Result<SetupSnapshot, SetupError> {
        let now = match self.clock.now_ms() {
            Ok(now) => now,
            Err(error) => {
                self.poisoned = true;
                self.stop(self.last);
                return Err(error);
            }
        };
        if self.poisoned || now < self.last {
            self.poisoned = true;
            self.stop(self.last);
            return Err(SetupError::ClockRollback);
        }
        self.last = now;
        if self.backend.is_some()
            && let Err(error) = self.catalog.candidates(now)
        {
            self.stop(now);
            return Err(error.into());
        }
        match command {
            SetupCommand::Snapshot {} => {}
            SetupCommand::OpenDiscovery {} => {
                // Windows remains non-operational until its secure persistence
                // and admission dependencies pass a separate gate.
                if !cfg!(unix) {
                    return Err(SetupError::UnsupportedPlatform);
                }
                if self.backend.is_some() {
                    return Err(SetupError::InvalidState);
                }
                self.catalog.open(now)?;
                match (self.factory)() {
                    Ok(backend) => {
                        self.backend = Some(backend);
                        self.status = SetupStatus::Browsing
                    }
                    Err(error) => {
                        self.stop(now);
                        return Err(error);
                    }
                }
            }
            SetupCommand::Refresh {} => {
                let backend = self.backend.as_mut().ok_or(SetupError::InvalidState)?;
                let events = match backend.poll() {
                    Ok(events) => events,
                    Err(error) => {
                        self.stop(now);
                        return Err(error);
                    }
                };
                if events.len() > 32 {
                    self.stop(now);
                    return Err(SetupError::Limit);
                }
                for event in events {
                    let result = match event {
                        LocatorEvent::Observed(ad) => self.catalog.observe(ad, now).map(|_| ()),
                        LocatorEvent::Removed(id) => self.catalog.remove(&id, now),
                    };
                    match result {
                        Ok(()) | Err(DiscoveryError::Invalid) | Err(DiscoveryError::Limit) => {}
                        Err(error) => {
                            self.stop(now);
                            return Err(error.into());
                        }
                    }
                }
            }
            SetupCommand::CloseDiscovery {} | SetupCommand::Cancel {} => self.stop(now),
            SetupCommand::Select { handle } => {
                if handle.scope != self.scope {
                    return Err(SetupError::StaleCandidate);
                }
                let selected = self.catalog.select(
                    CandidateHandle {
                        window: handle.window,
                        sequence: handle.sequence,
                    },
                    now,
                )?;
                self.stop(now);
                self.status = SetupStatus::HandshakeEnvelopePending;
                // Typed composition endpoint: bilateral envelope integration is disabled.
                // Consuming a locator cannot call legacy pairing or PeerEndpoint.
                return closed_provisional_transport(selected);
            }
            SetupCommand::CompareMatch {} => return Err(SetupError::InvalidState),
        }
        let candidates = if self.backend.is_some() {
            self.catalog
                .candidates(now)?
                .into_iter()
                .map(|v| CandidateView {
                    handle: Handle {
                        scope: self.scope.clone(),
                        window: v.handle.window,
                        sequence: v.handle.sequence,
                    },
                    version: v.version,
                    pairable: v.pairable,
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(SetupSnapshot {
            schema_version: 1,
            status: self.status,
            pairing_transport: TransportStatus::HandshakeEnvelopePending,
            candidates,
            authenticated_sessions: 0,
            promotion_enabled: false,
            input_enabled: false,
            clipboard_enabled: false,
        })
    }
}
fn closed_provisional_transport(
    _: seamless_discovery::guided::SelectedLocator,
) -> Result<SetupSnapshot, SetupError> {
    Err(SetupError::HandshakeEnvelopePending)
}
