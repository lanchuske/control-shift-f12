//! Bounded, child-owned stdio projection for native presentation hosts.
//!
//! This module is intentionally not a transport, input, clipboard, or layout
//! authority. The host can only refresh a redacted projection or record its
//! own V01 comparison choice. Engine-owned facts enter through
//! `AuthoritativeUiEvent` with an injected monotonic clock.

use std::{
    collections::BTreeMap,
    io::{self, Write},
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::Value;

use crate::{
    control_api::{self, Request},
    ui_contract::{
        CandidateView, CapabilityView, DiagnosticRow, InventoryView, LayoutView, RelationshipView,
        UiCommand, UiError, UiSnapshot, UiState, V01View,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ChildFrame {
    Snapshot(SnapshotFrame),
    Diagnostics(DiagnosticsFrame),
    SasDisplay(SasDisplayFrame),
    Response(ResponseFrame),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveSas {
    attempt_binding: u64,
    expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostCommand {
    Refresh,
    ConfirmV01 { matches: bool },
}

pub struct UiStdioAdapter {
    controller: UiController,
    outgoing: Vec<ChildFrame>,
    replays: BTreeMap<String, (Request, Vec<ChildFrame>)>,
    active_sas: Option<ActiveSas>,
    next_attempt_binding: u64,
    next_generation: u64,
    now_ms: u64,
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
        }
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
        self.drain_child_frames()
    }

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
        self.active_sas
            .as_ref()
            .map(|sas| Duration::from_millis(sas.expires_at_ms.saturating_sub(self.now_ms)))
            .unwrap_or(Duration::from_secs(60))
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
    if request.v != 1 || contains_sas_field(&request.args) {
        return Err(UiError::InvalidRequest);
    }
    let object = request.args.as_object().ok_or(UiError::InvalidRequest)?;
    match request.command.as_str() {
        "ui.refresh" if object.is_empty() => Ok(HostCommand::Refresh),
        "ui.confirm_v01" if object.len() == 1 => object
            .get("matches")
            .and_then(Value::as_bool)
            .map(|matches| HostCommand::ConfirmV01 { matches })
            .ok_or(UiError::InvalidRequest),
        _ => Err(UiError::InvalidCommand),
    }
}

fn contains_sas_field(value: &Value) -> bool {
    const FORBIDDEN: &[&str] = &[
        "v",
        "kind",
        "sas_display_v1",
        "attempt_binding",
        "generation",
        "current",
        "remaining_ms",
        "code_groups",
        "details_suffix",
    ];
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| FORBIDDEN.contains(&key.as_str()) || contains_sas_field(value)),
        Value::Array(values) => values.iter().any(contains_sas_field),
        Value::String(value) => value == "sas_display_v1",
        _ => false,
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
