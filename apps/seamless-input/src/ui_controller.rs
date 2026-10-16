//! Local UI state transitions only; no transport or capability authority.

use crate::{
    ui_contract::{
        CandidateFreshness, CandidateHandle, CandidateView, CapabilityView, DiagnosticRow,
        LayoutState, LayoutView, UI_SCHEMA_VERSION, UiCommand, UiError, UiSnapshot, UiState,
        V01View,
    },
    ui_projection::{UiView, project},
};

const V01_MAX_MS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiRuntimeEvent {
    Candidates(Vec<CandidateView>),
    BootstrapSasReady,
    BootstrapReceiptVerified,
    V01SasReady(V01View),
    PeerConfirmed,
    Diagnostics(Vec<DiagnosticRow>),
    PermissionRevoked,
    ReceiptRevoked,
    RemoteOutcomeUnknown,
}

pub struct UiController {
    snapshot: UiSnapshot,
    selected_candidate: Option<CandidateHandle>,
    v01_started_ms: Option<u64>,
    local_v01_confirmed: bool,
    now_ms: u64,
}

impl UiController {
    pub fn new(now_ms: u64) -> Self {
        Self {
            snapshot: UiSnapshot {
                schema_version: UI_SCHEMA_VERSION,
                generation: 0,
                state: UiState::NotStarted,
                diagnostics: Vec::new(),
                candidates: Vec::new(),
                confirmed: Vec::new(),
                v01: None,
                inventory: None,
                layout: LayoutView {
                    state: LayoutState::NotConfigured,
                },
                capabilities: CapabilityView::all_disabled(),
            },
            selected_candidate: None,
            v01_started_ms: None,
            local_v01_confirmed: false,
            now_ms,
        }
    }

    pub fn snapshot(&self) -> &UiSnapshot {
        &self.snapshot
    }

    pub fn view(&self) -> UiView {
        project(&self.snapshot)
    }

    pub fn advance_to(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        if self
            .v01_started_ms
            .is_some_and(|started| now_ms.saturating_sub(started) > V01_MAX_MS)
        {
            self.clear_v01_to_confirmed();
        }
    }

    pub fn apply_local(&mut self, command: UiCommand) -> Result<(), UiError> {
        self.advance_to(self.now_ms);
        match command {
            UiCommand::RefreshDiagnostics => Ok(()),
            UiCommand::StartDiscovery if self.snapshot.state == UiState::NotStarted => {
                self.snapshot.state = UiState::Browsing;
                Ok(())
            }
            UiCommand::StopDiscovery if self.snapshot.state == UiState::Browsing => {
                self.snapshot.state = UiState::NotStarted;
                self.snapshot.candidates.clear();
                Ok(())
            }
            UiCommand::SelectCandidate { handle }
                if self.snapshot.state == UiState::Browsing
                    && self.snapshot.candidates.iter().any(|candidate| {
                        candidate.handle == handle
                            && candidate.freshness == CandidateFreshness::Current
                            && matches!(
                                candidate.compatibility,
                                crate::ui_contract::CandidateCompatibility::Compatible
                            )
                    }) =>
            {
                self.selected_candidate = Some(handle);
                self.snapshot.state = UiState::CandidateSelected;
                Ok(())
            }
            UiCommand::BeginBootstrap if self.snapshot.state == UiState::CandidateSelected => {
                self.snapshot.state = UiState::BootstrapConnecting;
                Ok(())
            }
            UiCommand::ConfirmBootstrap { matches: true }
                if self.snapshot.state == UiState::BootstrapSasPending =>
            {
                self.snapshot.state = UiState::BootstrapReceiptPrepared;
                Ok(())
            }
            UiCommand::ConfirmBootstrap { matches: false }
                if self.snapshot.state == UiState::BootstrapSasPending =>
            {
                self.selected_candidate = None;
                self.snapshot.state = UiState::Browsing;
                Ok(())
            }
            UiCommand::BeginV01 if self.snapshot.state == UiState::ConfirmedRelationship => Ok(()),
            UiCommand::ConfirmV01 { matches: true }
                if self.snapshot.state == UiState::V01Pending =>
            {
                self.local_v01_confirmed = true;
                Ok(())
            }
            UiCommand::ConfirmV01 { matches: false }
                if self.snapshot.state == UiState::V01Pending =>
            {
                self.clear_v01_to_confirmed();
                Ok(())
            }
            UiCommand::RefreshInventory if self.snapshot.state == UiState::InventoryCurrent => {
                Ok(())
            }
            UiCommand::MoveDisplay { .. }
                if matches!(
                    self.snapshot.state,
                    UiState::InventoryCurrent | UiState::ProposalLocal
                ) =>
            {
                self.snapshot.state = UiState::ProposalLocal;
                self.snapshot.layout.state = LayoutState::Draft;
                Ok(())
            }
            UiCommand::ResetLayout if self.snapshot.state == UiState::ProposalLocal => {
                self.snapshot.state = UiState::InventoryCurrent;
                self.snapshot.layout.state = LayoutState::NotConfigured;
                Ok(())
            }
            UiCommand::SubmitLayout if self.snapshot.state == UiState::ProposalLocal => {
                self.snapshot.state = UiState::LayoutPreparePending;
                self.snapshot.layout.state = LayoutState::PreparePending;
                Ok(())
            }
            UiCommand::RespondLayout { .. } => Err(UiError::InvalidState),
            UiCommand::Cancel => {
                self.cancel();
                Ok(())
            }
            UiCommand::ForgetRelationship { .. } => {
                self.reset_to_not_started();
                Ok(())
            }
            _ => Err(
                if matches!(
                    self.snapshot.state,
                    UiState::RemoteOutcomeUnknown
                        | UiState::LayoutRecoveryPending
                        | UiState::Blocked
                ) {
                    UiError::Blocked
                } else {
                    UiError::InvalidState
                },
            ),
        }
    }

    pub fn on_runtime(&mut self, event: UiRuntimeEvent) {
        match event {
            UiRuntimeEvent::Candidates(candidates) if self.snapshot.state == UiState::Browsing => {
                self.snapshot.candidates = candidates;
            }
            UiRuntimeEvent::BootstrapSasReady
                if self.snapshot.state == UiState::BootstrapConnecting =>
            {
                self.snapshot.state = UiState::BootstrapSasPending;
            }
            UiRuntimeEvent::BootstrapReceiptVerified
                if self.snapshot.state == UiState::BootstrapReceiptPrepared =>
            {
                self.snapshot.state = UiState::ConfirmedRelationship;
            }
            UiRuntimeEvent::V01SasReady(v01)
                if self.snapshot.state == UiState::ConfirmedRelationship =>
            {
                self.snapshot.v01 = Some(v01);
                self.v01_started_ms = Some(self.now_ms);
                self.snapshot.state = UiState::V01Pending;
            }
            UiRuntimeEvent::PeerConfirmed
                if self.snapshot.state == UiState::V01Pending && self.local_v01_confirmed =>
            {
                self.snapshot.v01 = None;
                self.v01_started_ms = None;
                self.snapshot.state = UiState::InventoryCurrent;
            }
            UiRuntimeEvent::Diagnostics(rows) => self.snapshot.diagnostics = rows,
            UiRuntimeEvent::PermissionRevoked => {
                self.snapshot.capabilities = CapabilityView::all_disabled();
            }
            UiRuntimeEvent::ReceiptRevoked => self.reset_to_not_started(),
            UiRuntimeEvent::RemoteOutcomeUnknown => {
                self.clear_volatile();
                self.snapshot.state = UiState::RemoteOutcomeUnknown;
                self.snapshot.layout.state = LayoutState::RemoteOutcomeUnknown;
            }
            _ => {}
        }
    }

    fn cancel(&mut self) {
        match self.snapshot.state {
            UiState::V01Pending => self.clear_v01_to_confirmed(),
            UiState::BootstrapConnecting
            | UiState::BootstrapSasPending
            | UiState::BootstrapReceiptPrepared => {
                self.selected_candidate = None;
                self.snapshot.state = UiState::Browsing;
            }
            UiState::ProposalLocal | UiState::InventoryCurrent => {
                self.snapshot.state = UiState::InventoryCurrent;
                self.snapshot.layout.state = LayoutState::NotConfigured;
            }
            _ => self.reset_to_not_started(),
        }
    }

    fn clear_v01_to_confirmed(&mut self) {
        self.snapshot.v01 = None;
        self.v01_started_ms = None;
        self.local_v01_confirmed = false;
        self.snapshot.state = UiState::ConfirmedRelationship;
    }

    fn clear_volatile(&mut self) {
        self.snapshot.v01 = None;
        self.v01_started_ms = None;
        self.local_v01_confirmed = false;
        self.snapshot.capabilities = CapabilityView::all_disabled();
    }

    fn reset_to_not_started(&mut self) {
        self.clear_volatile();
        self.selected_candidate = None;
        self.snapshot.candidates.clear();
        self.snapshot.inventory = None;
        self.snapshot.layout.state = LayoutState::NotConfigured;
        self.snapshot.state = UiState::NotStarted;
    }
}
