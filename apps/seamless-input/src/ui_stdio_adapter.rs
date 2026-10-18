//! Bounded, child-owned stdio projection for native presentation hosts.
//!
//! This module is intentionally not a transport, input, clipboard, or layout
//! authority. The host can refresh a redacted projection, change local browsing
//! state, or record its own V01 comparison choice. Pairing gestures are typed
//! but remain state-gated until their engine owner is admitted. Facts enter through
//! `AuthoritativeUiEvent` with an injected monotonic clock.

use std::{
    collections::BTreeMap,
    io::{self, Write},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

#[cfg(feature = "pairing-v2-g4")]
use crate::g4_pairing::{
    G4Command, G4Event, G4PairingWorker, PairingToken, RealG4Backend, WorkerError,
};
use crate::{
    control_api::{self, Request},
    ui_contract::{
        CandidateHandle, CandidateView, CapabilityView, DiagnosticRow, InventoryView, LayoutView,
        RelationshipHandle, RelationshipState, RelationshipView, UiCommand, UiError, UiSnapshot,
        UiState, V01View,
    },
    ui_controller::{UiController, UiRuntimeEvent},
};

const MAX_REPLAYED_REQUESTS: usize = 256;
const SAS_MAX_MS: u32 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthoritativeUiEvent {
    RelationshipVerified,
    V01SasReady { view: V01View, remaining_ms: u32 },
    PeerConfirmed,
    Diagnostics(Vec<DiagnosticRow>),
    PermissionRevoked,
    ReceiptRevoked,
    RemoteOutcomeUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SasDisplayFrame {
    pub v: u8,
    pub kind: &'static str,
    pub attempt_binding: u64,
    pub generation: u64,
    pub current: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_groups: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotFrame {
    pub v: u8,
    pub kind: &'static str,
    pub snapshot: HostSnapshot,
}

/// The ordinary host projection deliberately cannot contain V01 SAS content.
/// A current code is represented only by the separate transient SAS frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostSnapshot {
    pub schema_version: u16,
    pub generation: u64,
    pub state: UiState,
    pub diagnostics: Vec<DiagnosticRow>,
    pub candidates: Vec<CandidateView>,
    pub confirmed: Vec<RelationshipView>,
    pub inventory: Option<InventoryView>,
    pub layout: LayoutView,
    pub capabilities: CapabilityView,
}

impl From<UiSnapshot> for HostSnapshot {
    fn from(value: UiSnapshot) -> Self {
        Self {
            schema_version: value.schema_version,
            generation: value.generation,
            state: value.state,
            diagnostics: value.diagnostics,
            candidates: value.candidates,
            confirmed: value.confirmed,
            inventory: value.inventory,
            layout: value.layout,
            capabilities: value.capabilities,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsFrame {
    pub v: u8,
    pub kind: &'static str,
    pub generation: u64,
    pub rows: Vec<DiagnosticRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseFrame {
    pub v: u8,
    pub kind: &'static str,
    pub id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<UiError>,
}

/// A transient bootstrap-code projection, never V01 or admission evidence.
/// Construction validates display bounds only; no current engine path emits it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairingFrame {
    v: u8,
    kind: &'static str,
    generation: u64,
    phase: PairingPhase,
    candidate_handle: CandidateHandle,
    verification_words: [String; 4],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PairingPhase {
    AwaitingLocalConfirmation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairingFrameWire {
    v: u8,
    kind: String,
    generation: u64,
    phase: String,
    candidate_handle: CandidateHandle,
    verification_words: [String; 4],
}

impl PairingFrame {
    pub fn awaiting_local_confirmation(
        generation: u64,
        candidate_handle: CandidateHandle,
        verification_words: [String; 4],
    ) -> Result<Self, UiError> {
        if generation == 0
            || verification_words.iter().any(|word| {
                word.is_empty()
                    || word.len() > 16
                    || !word.bytes().all(|byte| byte.is_ascii_lowercase())
            })
        {
            return Err(UiError::InvalidRequest);
        }
        Ok(Self {
            v: 1,
            kind: "ui_pairing_v1",
            generation,
            phase: PairingPhase::AwaitingLocalConfirmation,
            candidate_handle,
            verification_words,
        })
    }
}

impl TryFrom<PairingFrameWire> for PairingFrame {
    type Error = &'static str;

    fn try_from(value: PairingFrameWire) -> Result<Self, Self::Error> {
        if value.v != 1
            || value.kind != "ui_pairing_v1"
            || value.phase != "awaiting_local_confirmation"
        {
            return Err("invalid pairing projection");
        }
        Self::awaiting_local_confirmation(
            value.generation,
            value.candidate_handle,
            value.verification_words,
        )
        .map_err(|_| "invalid pairing projection")
    }
}

impl<'de> Deserialize<'de> for PairingFrame {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        PairingFrameWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ChildFrame {
    Snapshot(SnapshotFrame),
    Diagnostics(DiagnosticsFrame),
    SasDisplay(SasDisplayFrame),
    Pairing(PairingFrame),
    Response(ResponseFrame),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveSas {
    attempt_binding: u64,
    expires_at_ms: u64,
}

#[cfg(feature = "pairing-v2-g4")]
struct ActivePairing {
    token: PairingToken,
    generation: u64,
    decided: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostCommand {
    Refresh,
    StartDiscovery,
    StopDiscovery,
    SelectCandidate { handle: CandidateHandle },
    ApproveSas { generation: u64, matches: bool },
    CancelPairing { generation: u64 },
    ConfirmV01 { matches: bool },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArgs {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectCandidateArgs {
    handle: CandidateHandle,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveSasArgs {
    generation: std::num::NonZeroU64,
    matches: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelPairingArgs {
    generation: std::num::NonZeroU64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmV01Args {
    matches: bool,
}

pub struct UiStdioAdapter {
    controller: UiController,
    outgoing: Vec<ChildFrame>,
    replays: BTreeMap<String, (Request, Vec<ChildFrame>)>,
    active_sas: Option<ActiveSas>,
    next_attempt_binding: u64,
    next_generation: u64,
    now_ms: u64,
    #[cfg(feature = "pairing-v2-g4")]
    g4: Option<G4PairingWorker>,
    #[cfg(feature = "pairing-v2-g4")]
    g4_generation: u64,
    #[cfg(feature = "pairing-v2-g4")]
    active_pairing: Option<ActivePairing>,
}

impl UiStdioAdapter {
    pub fn new(now_ms: u64) -> Self {
        Self {
            controller: UiController::new(now_ms),
            outgoing: Vec::new(),
            replays: BTreeMap::new(),
            active_sas: None,
            next_attempt_binding: 1,
            next_generation: 1,
            now_ms,
            #[cfg(feature = "pairing-v2-g4")]
            g4: None,
            #[cfg(feature = "pairing-v2-g4")]
            g4_generation: 0,
            #[cfg(feature = "pairing-v2-g4")]
            active_pairing: None,
        }
    }

    #[cfg(feature = "pairing-v2-g4")]
    pub fn with_g4(now_ms: u64, root: impl AsRef<std::path::Path>) -> Result<Self, WorkerError> {
        let mut adapter = Self::new(now_ms);
        let backend = RealG4Backend::open(root).map_err(|_| WorkerError::Closed)?;
        adapter.g4 = Some(G4PairingWorker::spawn(backend)?);
        Ok(adapter)
    }

    pub fn has_current_sas(&self) -> bool {
        self.active_sas.is_some()
    }

    pub fn drain_child_frames(&mut self) -> Vec<ChildFrame> {
        std::mem::take(&mut self.outgoing)
    }

    pub fn on_authoritative_at(
        &mut self,
        now_ms: u64,
        event: AuthoritativeUiEvent,
    ) -> Vec<ChildFrame> {
        let now_ms = self.advance_clock(now_ms);
        match event {
            AuthoritativeUiEvent::RelationshipVerified => {
                self.controller
                    .on_runtime_at(now_ms, UiRuntimeEvent::RelationshipVerified);
            }
            AuthoritativeUiEvent::V01SasReady { view, remaining_ms }
                if (1..=SAS_MAX_MS).contains(&remaining_ms) =>
            {
                let was_pending = self.controller.snapshot().state == UiState::V01Pending;
                self.controller
                    .on_runtime_at(now_ms, UiRuntimeEvent::V01SasReady(view.clone()));
                let accepted = !was_pending
                    && self.controller.snapshot().state == UiState::V01Pending
                    && self.controller.snapshot().v01.as_ref() == Some(&view)
                    && self.active_sas.is_none();
                if accepted {
                    let binding = self.allocate_attempt_binding();
                    let generation = self.allocate_generation();
                    self.active_sas = Some(ActiveSas {
                        attempt_binding: binding,
                        expires_at_ms: now_ms.saturating_add(u64::from(remaining_ms)),
                    });
                    self.outgoing.push(ChildFrame::SasDisplay(SasDisplayFrame {
                        v: 1,
                        kind: "sas_display_v1",
                        attempt_binding: binding,
                        generation,
                        current: true,
                        remaining_ms: Some(remaining_ms),
                        code_groups: Some(view.code.groups().to_vec()),
                    }));
                }
            }
            AuthoritativeUiEvent::V01SasReady { .. } => self.clear_sas(),
            AuthoritativeUiEvent::PeerConfirmed => self
                .controller
                .on_runtime_at(now_ms, UiRuntimeEvent::PeerConfirmed),
            AuthoritativeUiEvent::Diagnostics(rows) => self
                .controller
                .on_runtime_at(now_ms, UiRuntimeEvent::Diagnostics(rows)),
            AuthoritativeUiEvent::PermissionRevoked => self
                .controller
                .on_runtime_at(now_ms, UiRuntimeEvent::PermissionRevoked),
            AuthoritativeUiEvent::ReceiptRevoked => self
                .controller
                .on_runtime_at(now_ms, UiRuntimeEvent::ReceiptRevoked),
            AuthoritativeUiEvent::RemoteOutcomeUnknown => self
                .controller
                .on_runtime_at(now_ms, UiRuntimeEvent::RemoteOutcomeUnknown),
        }
        if self.controller.snapshot().v01.is_none() {
            self.clear_sas();
        }
        self.publish_snapshot_and_diagnostics();
        self.drain_child_frames()
    }

    pub fn handle_host_request_at(&mut self, now_ms: u64, request: &Request) -> Vec<ChildFrame> {
        let now_ms = self.advance_clock(now_ms);
        #[cfg(feature = "pairing-v2-g4")]
        self.poll_g4(now_ms);
        let pending = self.drain_child_frames();
        if control_api::validate_request(request).is_err() {
            let rejected = self.rejected(&request.id, UiError::InvalidRequest);
            return self.with_pending(pending, rejected);
        }
        if let Some((previous, response)) = self.replays.get(&request.id) {
            return if previous == request {
                self.with_pending(pending, response.clone())
            } else {
                let rejected = self.rejected(&request.id, UiError::RequestIdConflict);
                self.with_pending(pending, rejected)
            };
        }
        if self.replays.len() >= MAX_REPLAYED_REQUESTS {
            let rejected = self.rejected(&request.id, UiError::RequestLimit);
            return self.with_pending(pending, rejected);
        }
        let frames = match parse_host_command(request) {
            Ok(HostCommand::Refresh) => {
                self.publish_snapshot_and_diagnostics();
                self.accepted(&request.id)
            }
            Ok(HostCommand::StartDiscovery) => {
                #[cfg(feature = "pairing-v2-g4")]
                if let Some(g4) = self.g4.as_ref() {
                    let generation = self.g4_generation.saturating_add(1);
                    if g4.try_command(G4Command::Start { generation }).is_err() {
                        let rejected = self.rejected(&request.id, UiError::Blocked);
                        return self.with_pending(pending, rejected);
                    }
                    self.g4_generation = generation;
                }
                let result = self
                    .controller
                    .apply_local_at(now_ms, UiCommand::StartDiscovery);
                self.publish_snapshot_and_diagnostics();
                match result {
                    Ok(()) => self.accepted(&request.id),
                    Err(error) => self.rejected(&request.id, error),
                }
            }
            Ok(HostCommand::StopDiscovery) => {
                #[cfg(feature = "pairing-v2-g4")]
                if let Some(g4) = self.g4.as_ref()
                    && g4
                        .try_command(G4Command::Stop {
                            generation: self.g4_generation,
                        })
                        .is_err()
                {
                    let rejected = self.rejected(&request.id, UiError::Blocked);
                    return self.with_pending(pending, rejected);
                }
                let result = self
                    .controller
                    .apply_local_at(now_ms, UiCommand::StopDiscovery);
                self.publish_snapshot_and_diagnostics();
                match result {
                    Ok(()) => self.accepted(&request.id),
                    Err(error) => self.rejected(&request.id, error),
                }
            }
            Ok(HostCommand::ConfirmV01 { matches }) => {
                let result = self
                    .controller
                    .apply_local_at(now_ms, UiCommand::ConfirmV01 { matches });
                if self.controller.snapshot().v01.is_none() {
                    self.clear_sas();
                }
                self.publish_snapshot_and_diagnostics();
                match result {
                    Ok(()) => self.accepted(&request.id),
                    Err(error) => self.rejected(&request.id, error),
                }
            }
            Ok(HostCommand::SelectCandidate { handle }) => {
                self.handle_g4_select(now_ms, &request.id, handle)
            }
            Ok(HostCommand::ApproveSas {
                generation,
                matches,
            }) => self.handle_g4_decision(now_ms, &request.id, generation, matches),
            Ok(HostCommand::CancelPairing { generation }) => {
                self.handle_g4_cancel(now_ms, &request.id, generation)
            }
            Err(error) => self.rejected(&request.id, error),
        };
        self.replays
            .insert(request.id.clone(), (request.clone(), frames.clone()));
        self.with_pending(pending, frames)
    }

    /// Delivers an autonomous timer observation. Callers must use the same
    /// monotonic source as every decisive event; no host request is required.
    pub fn poll_at(&mut self, now_ms: u64) -> Vec<ChildFrame> {
        self.advance_clock(now_ms);
        #[cfg(feature = "pairing-v2-g4")]
        self.poll_g4(now_ms);
        self.drain_child_frames()
    }

    fn handle_g4_select(
        &mut self,
        now_ms: u64,
        id: &str,
        handle: CandidateHandle,
    ) -> Vec<ChildFrame> {
        #[cfg(feature = "pairing-v2-g4")]
        if let Some(g4) = self.g4.as_ref() {
            if g4
                .try_command(G4Command::Select {
                    generation: self.g4_generation,
                    handle: handle.clone(),
                })
                .is_err()
            {
                return self.rejected(id, UiError::Blocked);
            }
            let result = self
                .controller
                .apply_local_at(
                    now_ms,
                    UiCommand::SelectCandidate {
                        handle: handle.clone(),
                    },
                )
                .and_then(|_| {
                    self.controller
                        .apply_local_at(now_ms, UiCommand::BeginBootstrap)
                });
            self.publish_snapshot_and_diagnostics();
            return match result {
                Ok(()) => self.accepted(id),
                Err(error) => self.rejected(id, error),
            };
        }
        self.rejected(id, UiError::InvalidState)
    }

    fn handle_g4_decision(
        &mut self,
        now_ms: u64,
        id: &str,
        generation: u64,
        matches: bool,
    ) -> Vec<ChildFrame> {
        #[cfg(feature = "pairing-v2-g4")]
        if let (Some(g4), Some(active)) = (self.g4.as_ref(), self.active_pairing.as_ref()) {
            if active.generation != generation || active.decided {
                return self.rejected(id, UiError::InvalidState);
            }
            let token = active.token;
            if g4
                .try_command(G4Command::Decide { token, matches })
                .is_err()
            {
                return self.rejected(id, UiError::Blocked);
            }
            let result = self
                .controller
                .apply_local_at(now_ms, UiCommand::ConfirmBootstrap { matches });
            if matches {
                if let Some(active) = self.active_pairing.as_mut() {
                    active.decided = true;
                }
            } else {
                self.active_pairing = None;
            }
            self.publish_snapshot_and_diagnostics();
            return match result {
                Ok(()) => self.accepted(id),
                Err(error) => self.rejected(id, error),
            };
        }
        self.rejected(id, UiError::InvalidState)
    }

    fn handle_g4_cancel(&mut self, now_ms: u64, id: &str, generation: u64) -> Vec<ChildFrame> {
        #[cfg(feature = "pairing-v2-g4")]
        if let (Some(g4), Some(active)) = (self.g4.as_ref(), self.active_pairing.as_ref()) {
            if active.generation != generation {
                return self.rejected(id, UiError::InvalidState);
            }
            if g4
                .try_command(G4Command::Cancel {
                    generation: self.g4_generation,
                })
                .is_err()
            {
                return self.rejected(id, UiError::Blocked);
            }
            let result = self.controller.apply_local_at(now_ms, UiCommand::Cancel);
            self.active_pairing = None;
            self.publish_snapshot_and_diagnostics();
            return match result {
                Ok(()) => self.accepted(id),
                Err(error) => self.rejected(id, error),
            };
        }
        self.rejected(id, UiError::InvalidState)
    }

    #[cfg(feature = "pairing-v2-g4")]
    fn poll_g4(&mut self, now_ms: u64) {
        let mut events = Vec::new();
        if let Some(g4) = self.g4.as_ref() {
            while let Some(event) = g4.try_event() {
                events.push(event);
            }
        }
        for event in events {
            match event {
                G4Event::Browsing { .. } => {}
                G4Event::Candidates { candidates, .. } => self
                    .controller
                    .on_runtime_at(now_ms, UiRuntimeEvent::Candidates(candidates)),
                G4Event::SasReady {
                    token,
                    candidate,
                    words,
                } => {
                    if self.controller.snapshot().state == UiState::Browsing
                        && (self
                            .controller
                            .apply_local_at(
                                now_ms,
                                UiCommand::SelectCandidate {
                                    handle: candidate.clone(),
                                },
                            )
                            .is_err()
                            || self
                                .controller
                                .apply_local_at(now_ms, UiCommand::BeginBootstrap)
                                .is_err())
                    {
                        continue;
                    }
                    self.controller
                        .on_runtime_at(now_ms, UiRuntimeEvent::BootstrapSasReady);
                    let generation = self.allocate_generation();
                    if let Ok(frame) = PairingFrame::awaiting_local_confirmation(
                        generation,
                        candidate.clone(),
                        words,
                    ) {
                        self.active_pairing = Some(ActivePairing {
                            token,
                            generation,
                            decided: false,
                        });
                        self.outgoing.push(ChildFrame::Pairing(frame));
                    }
                }
                G4Event::DurableSnapshot(entries) => {
                    let confirmed: Vec<RelationshipView> = entries
                        .iter()
                        .filter(|entry| entry.confirmed)
                        .filter_map(|entry| RelationshipHandle::try_from(entry.handle.clone()).ok())
                        .map(|handle| RelationshipView {
                            handle,
                            state: RelationshipState::Unavailable,
                        })
                        .collect();
                    if entries.iter().any(|entry| !entry.confirmed) {
                        self.controller
                            .on_runtime_at(now_ms, UiRuntimeEvent::RemoteOutcomeUnknown);
                    } else if !confirmed.is_empty() {
                        self.controller.on_runtime_at(
                            now_ms,
                            UiRuntimeEvent::G4DurableRelationships(confirmed),
                        );
                    }
                    self.active_pairing = None;
                }
                G4Event::RemoteOutcomeUnknown => {
                    self.controller
                        .on_runtime_at(now_ms, UiRuntimeEvent::RemoteOutcomeUnknown);
                    self.active_pairing = None;
                }
                G4Event::Rejected | G4Event::Cancelled | G4Event::Expired => {
                    let _ = self.controller.apply_local_at(now_ms, UiCommand::Cancel);
                    self.active_pairing = None;
                }
            }
            self.publish_snapshot_and_diagnostics();
        }
    }

    #[cfg(not(feature = "pairing-v2-g4"))]
    fn poll_g4(&mut self, _now_ms: u64) {}

    fn with_pending(
        &mut self,
        mut pending: Vec<ChildFrame>,
        mut frames: Vec<ChildFrame>,
    ) -> Vec<ChildFrame> {
        pending.append(&mut frames);
        pending
    }

    fn accepted(&mut self, id: &str) -> Vec<ChildFrame> {
        let mut frames = self.drain_child_frames();
        frames.push(response(id, true, None));
        frames
    }

    fn rejected(&mut self, id: &str, error: UiError) -> Vec<ChildFrame> {
        let mut frames = self.drain_child_frames();
        frames.push(response(id, false, Some(error)));
        frames
    }

    fn advance_clock(&mut self, observed_now_ms: u64) -> u64 {
        self.now_ms = self.now_ms.max(observed_now_ms);
        self.expire_before(self.now_ms);
        self.now_ms
    }

    fn expire_before(&mut self, now_ms: u64) {
        if self
            .active_sas
            .as_ref()
            .is_some_and(|sas| now_ms >= sas.expires_at_ms)
        {
            // A shorter authoritative display window cannot leave the controller
            // pending after the visible code has been invalidated.
            self.controller
                .on_runtime_at(now_ms, UiRuntimeEvent::V01Expired);
            self.clear_sas();
        }
    }

    fn clear_sas(&mut self) {
        if let Some(active) = self.active_sas.take() {
            let generation = self.allocate_generation();
            self.outgoing.push(ChildFrame::SasDisplay(SasDisplayFrame {
                v: 1,
                kind: "sas_display_v1",
                attempt_binding: active.attempt_binding,
                generation,
                current: false,
                remaining_ms: None,
                code_groups: None,
            }));
        }
    }

    fn publish_snapshot_and_diagnostics(&mut self) {
        let mut snapshot = self.controller.snapshot().clone();
        snapshot.generation = self.allocate_generation();
        let rows = snapshot.diagnostics.clone();
        self.outgoing.push(ChildFrame::Snapshot(SnapshotFrame {
            v: 1,
            kind: "ui_snapshot_v1",
            snapshot: snapshot.into(),
        }));
        let diagnostics_generation = self.allocate_generation();
        self.outgoing
            .push(ChildFrame::Diagnostics(DiagnosticsFrame {
                v: 1,
                kind: "ui_diagnostics_v1",
                generation: diagnostics_generation,
                rows,
            }));
    }

    fn allocate_attempt_binding(&mut self) -> u64 {
        let binding = self.next_attempt_binding;
        self.next_attempt_binding = self.next_attempt_binding.saturating_add(1);
        binding
    }

    fn allocate_generation(&mut self) -> u64 {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1);
        generation
    }

    fn wait_until_next_deadline(&self) -> Duration {
        let sas = self
            .active_sas
            .as_ref()
            .map(|sas| Duration::from_millis(sas.expires_at_ms.saturating_sub(self.now_ms)))
            .unwrap_or(Duration::from_secs(60));
        #[cfg(feature = "pairing-v2-g4")]
        if self.g4.is_some() {
            return sas.min(Duration::from_millis(20));
        }
        sas
    }
}

fn response(id: &str, ok: bool, error: Option<UiError>) -> ChildFrame {
    ChildFrame::Response(ResponseFrame {
        v: 1,
        kind: "ui_response_v1",
        id: id.into(),
        ok,
        error,
    })
}

fn parse_host_command(request: &Request) -> Result<HostCommand, UiError> {
    if request.v != 1 || !request.args.is_object() {
        return Err(UiError::InvalidRequest);
    }
    fn args<T: serde::de::DeserializeOwned>(request: &Request) -> Result<T, UiError> {
        serde_json::from_value(request.args.clone()).map_err(|_| UiError::InvalidRequest)
    }
    match request.command.as_str() {
        "ui.refresh" => args::<EmptyArgs>(request).map(|_| HostCommand::Refresh),
        "ui.start_discovery" => args::<EmptyArgs>(request).map(|_| HostCommand::StartDiscovery),
        "ui.stop_discovery" => args::<EmptyArgs>(request).map(|_| HostCommand::StopDiscovery),
        "ui.select_candidate" => {
            args::<SelectCandidateArgs>(request).map(|args| HostCommand::SelectCandidate {
                handle: args.handle,
            })
        }
        "ui.approve_sas" => args::<ApproveSasArgs>(request).map(|args| HostCommand::ApproveSas {
            generation: args.generation.get(),
            matches: args.matches,
        }),
        "ui.cancel_pairing" => {
            args::<CancelPairingArgs>(request).map(|args| HostCommand::CancelPairing {
                generation: args.generation.get(),
            })
        }
        "ui.confirm_v01" => args::<ConfirmV01Args>(request).map(|args| HostCommand::ConfirmV01 {
            matches: args.matches,
        }),
        _ => Err(UiError::InvalidCommand),
    }
}

/// A bounded event source owned by the engine runner. The concrete inherited
/// pipe owner must honor its timeout and synchronously release on `cancel`.
/// This avoids a detached reader that can outlive a failed stdout writer.
pub trait TimedRequestReader {
    fn receive_until(&mut self, timeout: Duration) -> io::Result<StdioReadEvent>;
    fn cancel(&mut self);
}

#[derive(Debug, Clone, PartialEq)]
pub enum StdioReadEvent {
    Request(Request),
    Timeout,
    Eof,
}

/// The single monotonic epoch shared by admission, authoritative updates and
/// the stdio runner. A runner never manufactures a second epoch for an
/// already-admitted adapter.
pub trait MonotonicClock {
    fn now_ms(&mut self) -> u64;
}

pub struct InstantEpoch {
    origin: Instant,
}

impl InstantEpoch {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for InstantEpoch {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for InstantEpoch {
    fn now_ms(&mut self) -> u64 {
        self.origin.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
}

/// Runs the bounded inherited-pipe adapter. It deliberately has no listener,
/// shell, process spawning, or network path. The caller owns the cancellable
/// framed-pipe reader, so a writer failure cannot strand a background read.
pub fn run_stdio(reader: &mut impl TimedRequestReader, writer: &mut impl Write) -> io::Result<()> {
    let mut clock = InstantEpoch::new();
    let adapter = UiStdioAdapter::new(clock.now_ms());
    run_stdio_with_adapter(reader, writer, adapter, &mut clock)
}

#[cfg(feature = "pairing-v2-g4")]
pub fn run_stdio_g4(
    reader: &mut impl TimedRequestReader,
    writer: &mut impl Write,
    root: impl AsRef<std::path::Path>,
) -> io::Result<()> {
    let mut clock = InstantEpoch::new();
    let adapter = UiStdioAdapter::with_g4(clock.now_ms(), root)
        .map_err(|_| io::Error::other("G4 pairing owner unavailable"))?;
    run_stdio_with_adapter(reader, writer, adapter, &mut clock)
}

/// Runs a previously admitted adapter over the owned cancellable pipe reader.
pub fn run_stdio_with_adapter<C: MonotonicClock>(
    reader: &mut impl TimedRequestReader,
    writer: &mut impl Write,
    mut adapter: UiStdioAdapter,
    clock: &mut C,
) -> io::Result<()> {
    loop {
        match reader.receive_until(adapter.wait_until_next_deadline())? {
            StdioReadEvent::Request(request) => {
                // Time is sampled after the blocking receive returns, so an
                // overdue request cannot confirm or refresh a stale SAS.
                let now_ms = clock.now_ms();
                for frame in adapter.handle_host_request_at(now_ms, &request) {
                    if let Err(error) = control_api::write_message(writer, &frame) {
                        reader.cancel();
                        return Err(error);
                    }
                }
            }
            StdioReadEvent::Eof => return Ok(()),
            StdioReadEvent::Timeout => {
                let now_ms = clock.now_ms();
                for frame in adapter.poll_at(now_ms) {
                    if let Err(error) = control_api::write_message(writer, &frame) {
                        reader.cancel();
                        return Err(error);
                    }
                }
            }
        }
    }
}

#[cfg(all(test, feature = "pairing-v2-g4"))]
mod g4_tests {
    use super::*;
    use crate::{
        g4_pairing::G4WorkerBackend,
        ui_contract::{CandidateCompatibility, CandidateFreshness},
    };
    use std::sync::{Arc, Mutex};

    struct Backend {
        commands: Arc<Mutex<Vec<G4Command>>>,
        commit_on_match: bool,
        quarantine_on_cancel: bool,
    }
    impl G4WorkerBackend for Backend {
        fn command(&mut self, command: G4Command) -> Vec<G4Event> {
            self.commands.lock().unwrap().push(command.clone());
            match command {
                G4Command::Start { generation } => vec![G4Event::Candidates {
                    generation,
                    candidates: vec![CandidateView {
                        handle: "nearby-1".to_owned().try_into().unwrap(),
                        compatibility: CandidateCompatibility::Compatible,
                        freshness: CandidateFreshness::Current,
                    }],
                }],
                G4Command::Select { .. } => vec![G4Event::SasReady {
                    token: PairingToken::from_engine([1; 32], [2; 32], 3),
                    candidate: "nearby-1".to_owned().try_into().unwrap(),
                    words: ["able", "baker", "cable", "delta"].map(str::to_owned),
                }],
                G4Command::Decide { matches: true, .. } if self.commit_on_match => vec![
                    G4Event::DurableSnapshot(vec![crate::g4_pairing::DurableView {
                        handle: "relationship-1".into(),
                        confirmed: true,
                    }]),
                ],
                G4Command::Cancel { .. } if self.quarantine_on_cancel => vec![
                    G4Event::DurableSnapshot(vec![crate::g4_pairing::DurableView {
                        handle: "quarantine-1".into(),
                        confirmed: false,
                    }]),
                ],
                _ => Vec::new(),
            }
        }
        fn poll(&mut self) -> Vec<G4Event> {
            Vec::new()
        }
        fn shutdown(&mut self) {}
    }

    fn request(id: &str, command: &str, args: serde_json::Value) -> Request {
        Request {
            v: 1,
            id: id.into(),
            command: command.into(),
            args,
        }
    }

    fn poll_until(
        adapter: &mut UiStdioAdapter,
        predicate: impl Fn(&ChildFrame) -> bool,
    ) -> Vec<ChildFrame> {
        for now in 1..=100 {
            let frames = adapter.poll_at(now);
            if frames.iter().any(&predicate) {
                return frames;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!("expected G4 frame was not emitted");
    }

    fn wait_for_command(
        commands: &Arc<Mutex<Vec<G4Command>>>,
        predicate: impl Fn(&G4Command) -> bool,
    ) {
        for _ in 0..100 {
            if commands.lock().unwrap().iter().any(&predicate) {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!("expected G4 command was not recorded");
    }

    #[test]
    fn real_g4_port_accepts_select_sas_and_mismatch() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let mut adapter = UiStdioAdapter::new(0);
        adapter.g4 = Some(
            G4PairingWorker::spawn(Backend {
                commands: commands.clone(),
                commit_on_match: false,
                quarantine_on_cancel: false,
            })
            .unwrap(),
        );
        let started = adapter.handle_host_request_at(
            0,
            &request("start", "ui.start_discovery", serde_json::json!({})),
        );
        assert!(
            started
                .iter()
                .any(|frame| matches!(frame, ChildFrame::Response(response) if response.ok))
        );
        poll_until(
            &mut adapter,
            |frame| matches!(frame, ChildFrame::Snapshot(snapshot) if snapshot.snapshot.candidates.len() == 1),
        );

        let selected = adapter.handle_host_request_at(
            2,
            &request(
                "select",
                "ui.select_candidate",
                serde_json::json!({"handle":"nearby-1"}),
            ),
        );
        assert!(
            selected
                .iter()
                .any(|frame| matches!(frame, ChildFrame::Response(response) if response.ok))
        );
        let pairing = poll_until(&mut adapter, |frame| {
            matches!(frame, ChildFrame::Pairing(_))
        });
        let generation = pairing
            .iter()
            .find_map(|frame| match frame {
                ChildFrame::Pairing(pairing) => serde_json::to_value(pairing)
                    .ok()?
                    .get("generation")?
                    .as_u64(),
                _ => None,
            })
            .unwrap();
        let mismatched = adapter.handle_host_request_at(
            3,
            &request(
                "mismatch",
                "ui.approve_sas",
                serde_json::json!({"generation":generation,"matches":false}),
            ),
        );
        assert!(
            mismatched
                .iter()
                .any(|frame| matches!(frame, ChildFrame::Response(response) if response.ok))
        );
        wait_for_command(&commands, |command| {
            matches!(command, G4Command::Decide { matches: false, .. })
        });
    }

    #[test]
    fn exact_generation_can_cancel_after_local_match_without_duplicate_decision() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let mut adapter = UiStdioAdapter::new(0);
        adapter.g4 = Some(
            G4PairingWorker::spawn(Backend {
                commands: commands.clone(),
                commit_on_match: false,
                quarantine_on_cancel: false,
            })
            .unwrap(),
        );
        adapter.handle_host_request_at(
            0,
            &request("start", "ui.start_discovery", serde_json::json!({})),
        );
        poll_until(
            &mut adapter,
            |frame| matches!(frame, ChildFrame::Snapshot(snapshot) if snapshot.snapshot.candidates.len() == 1),
        );
        adapter.handle_host_request_at(
            2,
            &request(
                "select",
                "ui.select_candidate",
                serde_json::json!({"handle":"nearby-1"}),
            ),
        );
        let pairing = poll_until(&mut adapter, |frame| {
            matches!(frame, ChildFrame::Pairing(_))
        });
        let generation = pairing
            .iter()
            .find_map(|frame| match frame {
                ChildFrame::Pairing(pairing) => serde_json::to_value(pairing)
                    .ok()?
                    .get("generation")?
                    .as_u64(),
                _ => None,
            })
            .unwrap();
        let matched = adapter.handle_host_request_at(
            3,
            &request(
                "match",
                "ui.approve_sas",
                serde_json::json!({"generation":generation,"matches":true}),
            ),
        );
        assert!(
            matched
                .iter()
                .any(|frame| matches!(frame, ChildFrame::Response(response) if response.ok))
        );
        let duplicate = adapter.handle_host_request_at(
            4,
            &request(
                "match-again",
                "ui.approve_sas",
                serde_json::json!({"generation":generation,"matches":true}),
            ),
        );
        assert!(duplicate.iter().any(|frame| matches!(frame, ChildFrame::Response(response) if !response.ok && response.error == Some(UiError::InvalidState))));
        let cancelled = adapter.handle_host_request_at(
            5,
            &request(
                "cancel",
                "ui.cancel_pairing",
                serde_json::json!({"generation":generation}),
            ),
        );
        assert!(
            cancelled
                .iter()
                .any(|frame| matches!(frame, ChildFrame::Response(response) if response.ok))
        );
        wait_for_command(&commands, |command| {
            matches!(command, G4Command::Cancel { .. })
        });
        let recorded = commands.lock().unwrap();
        assert_eq!(
            recorded
                .iter()
                .filter(|command| matches!(command, G4Command::Decide { .. }))
                .count(),
            1
        );
        assert!(
            recorded
                .iter()
                .any(|command| matches!(command, G4Command::Cancel { .. }))
        );
    }

    #[test]
    fn durable_g4_confirmation_projects_metadata_without_operational_capability() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let mut adapter = UiStdioAdapter::new(0);
        adapter.g4 = Some(
            G4PairingWorker::spawn(Backend {
                commands,
                commit_on_match: true,
                quarantine_on_cancel: false,
            })
            .unwrap(),
        );
        adapter.handle_host_request_at(
            0,
            &request("start", "ui.start_discovery", serde_json::json!({})),
        );
        poll_until(
            &mut adapter,
            |frame| matches!(frame, ChildFrame::Snapshot(snapshot) if snapshot.snapshot.candidates.len() == 1),
        );
        adapter.handle_host_request_at(
            2,
            &request(
                "select",
                "ui.select_candidate",
                serde_json::json!({"handle":"nearby-1"}),
            ),
        );
        let pairing = poll_until(&mut adapter, |frame| {
            matches!(frame, ChildFrame::Pairing(_))
        });
        let generation = pairing
            .iter()
            .find_map(|frame| match frame {
                ChildFrame::Pairing(pairing) => serde_json::to_value(pairing)
                    .ok()?
                    .get("generation")?
                    .as_u64(),
                _ => None,
            })
            .unwrap();
        adapter.handle_host_request_at(
            3,
            &request(
                "match",
                "ui.approve_sas",
                serde_json::json!({"generation":generation,"matches":true}),
            ),
        );
        let terminal = poll_until(
            &mut adapter,
            |frame| matches!(frame, ChildFrame::Snapshot(snapshot) if snapshot.snapshot.state == UiState::ConfirmedRelationship),
        );
        let snapshot = terminal
            .iter()
            .find_map(|frame| match frame {
                ChildFrame::Snapshot(frame)
                    if frame.snapshot.state == UiState::ConfirmedRelationship =>
                {
                    Some(&frame.snapshot)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(snapshot.confirmed.len(), 1);
        assert_eq!(snapshot.confirmed[0].state, RelationshipState::Unavailable);
        assert!(!snapshot.capabilities.input_enabled());
        assert!(!snapshot.capabilities.clipboard_enabled());
        assert_eq!(
            snapshot.layout.state,
            crate::ui_contract::LayoutState::NotConfigured
        );
    }

    #[test]
    fn cancel_projects_store_owned_quarantine_without_operational_capability() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let mut adapter = UiStdioAdapter::new(0);
        adapter.g4 = Some(
            G4PairingWorker::spawn(Backend {
                commands,
                commit_on_match: false,
                quarantine_on_cancel: true,
            })
            .unwrap(),
        );
        adapter.handle_host_request_at(
            0,
            &request("start", "ui.start_discovery", serde_json::json!({})),
        );
        poll_until(
            &mut adapter,
            |frame| matches!(frame, ChildFrame::Snapshot(snapshot) if snapshot.snapshot.candidates.len() == 1),
        );
        adapter.handle_host_request_at(
            2,
            &request(
                "select",
                "ui.select_candidate",
                serde_json::json!({"handle":"nearby-1"}),
            ),
        );
        let pairing = poll_until(&mut adapter, |frame| {
            matches!(frame, ChildFrame::Pairing(_))
        });
        let generation = pairing
            .iter()
            .find_map(|frame| match frame {
                ChildFrame::Pairing(pairing) => serde_json::to_value(pairing)
                    .ok()?
                    .get("generation")?
                    .as_u64(),
                _ => None,
            })
            .unwrap();
        let cancelled = adapter.handle_host_request_at(
            3,
            &request(
                "cancel",
                "ui.cancel_pairing",
                serde_json::json!({"generation":generation}),
            ),
        );
        assert!(
            cancelled
                .iter()
                .any(|frame| matches!(frame, ChildFrame::Response(response) if response.ok))
        );
        let terminal = poll_until(
            &mut adapter,
            |frame| matches!(frame, ChildFrame::Snapshot(snapshot) if snapshot.snapshot.state == UiState::RemoteOutcomeUnknown),
        );
        let snapshot = terminal
            .iter()
            .find_map(|frame| match frame {
                ChildFrame::Snapshot(frame)
                    if frame.snapshot.state == UiState::RemoteOutcomeUnknown =>
                {
                    Some(&frame.snapshot)
                }
                _ => None,
            })
            .unwrap();
        assert!(snapshot.confirmed.is_empty());
        assert!(!snapshot.capabilities.input_enabled());
        assert!(!snapshot.capabilities.clipboard_enabled());
        assert_eq!(
            snapshot.layout.state,
            crate::ui_contract::LayoutState::NotConfigured
        );
    }
}
