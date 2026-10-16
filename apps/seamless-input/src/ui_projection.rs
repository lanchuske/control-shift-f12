//! Pure, deterministic presentation projection for a local native host.

use crate::ui_contract::{DiagnosticId, DiagnosticState, UiSnapshot, UiState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiView {
    pub state: UiState,
    pub runtime_not_running: bool,
    pub can_start_sharing: bool,
    pub can_edit_layout: bool,
}

pub fn project(snapshot: &UiSnapshot) -> UiView {
    let runtime_not_running = snapshot
        .diagnostics
        .iter()
        .any(|row| row.id == DiagnosticId::Runtime && row.state != DiagnosticState::Pass);
    let fenced = matches!(
        snapshot.state,
        UiState::RemoteOutcomeUnknown | UiState::LayoutRecoveryPending | UiState::Blocked
    );
    UiView {
        state: snapshot.state,
        runtime_not_running,
        // Capability ownership remains outside this local controller.
        can_start_sharing: false,
        can_edit_layout: matches!(
            snapshot.state,
            UiState::InventoryCurrent | UiState::ProposalLocal
        ) && !fenced,
    }
}
