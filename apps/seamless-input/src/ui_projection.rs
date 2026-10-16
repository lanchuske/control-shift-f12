//! Pure, deterministic presentation projection for a local native host.

use crate::ui_contract::{DiagnosticDetail, DiagnosticId, DiagnosticState, UiSnapshot, UiState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiView {
    pub state: UiState,
    pub runtime_not_running: bool,
    pub can_start_sharing: bool,
    pub can_edit_layout: bool,
}

pub fn project(snapshot: &UiSnapshot) -> UiView {
    let current_runtime_passes = snapshot
        .diagnostics
        .iter()
        .filter(|row| {
            row.id == DiagnosticId::Runtime
                && row.state == DiagnosticState::Pass
                && row.detail == DiagnosticDetail::Ready
        })
        .count();
    // Missing, duplicate, stale or non-PASS runtime rows are all ambiguous.
    // A host must render ambiguity as not running, never as a usable action.
    let runtime_not_running = current_runtime_passes != 1;
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
        ) && !fenced
            && !runtime_not_running,
    }
}
