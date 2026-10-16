//! Structured, redacted diagnostics projected from current local facts.
//!
//! This module does not probe a peer, alter runtime state, or grant a
//! capability. Callers must supply their measurements. Missing, stale and
//! malformed measurements are intentionally represented as non-successful
//! rows.

use crate::{
    runtime_status::{RuntimeStatus, RuntimeStatusRead},
    ui_contract::{
        DiagnosticAction, DiagnosticDetail, DiagnosticFailureCode, DiagnosticId, DiagnosticLabel,
        DiagnosticRow, DiagnosticState,
    },
};
use seamless_input_core::platform::AccessState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeObservation {
    Current(RuntimeStatus),
    Missing,
    Stale,
    Malformed,
}

impl From<RuntimeStatusRead> for RuntimeObservation {
    fn from(value: RuntimeStatusRead) -> Self {
        match value {
            RuntimeStatusRead::Current(status) => Self::Current(status),
            RuntimeStatusRead::Missing => Self::Missing,
            RuntimeStatusRead::Stale => Self::Stale,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardObservation {
    Ready,
    PermissionDenied,
    PermissionNotDetermined,
    Unavailable,
    Fault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayObservation {
    Measured(usize),
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryObservation {
    Ready,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationshipObservation {
    Configured,
    NotConfigured,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairedSessionObservation {
    Current(usize),
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticFacts {
    pub runtime: RuntimeObservation,
    pub input_access: AccessState,
    pub clipboard: ClipboardObservation,
    pub displays: DisplayObservation,
    pub discovery: DiscoveryObservation,
    pub relationship: RelationshipObservation,
    pub paired_session: PairedSessionObservation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticSnapshot {
    pub rows: Vec<DiagnosticRow>,
}

impl DiagnosticSnapshot {
    pub fn from_live(facts: DiagnosticFacts) -> Self {
        let runtime_is_current = matches!(facts.runtime, RuntimeObservation::Current(_));
        let paired_session = if runtime_is_current {
            facts.paired_session
        } else {
            // A session count has no meaning without the current owner
            // heartbeat that measured it. Never replay a prior success.
            PairedSessionObservation::Unavailable
        };
        Self {
            rows: vec![
                runtime_row(facts.runtime),
                input_row(facts.input_access),
                clipboard_row(facts.clipboard),
                displays_row(facts.displays),
                discovery_row(facts.discovery),
                relationship_row(facts.relationship),
                session_row(paired_session),
                row(
                    DiagnosticId::Layout,
                    DiagnosticState::Unknown,
                    DiagnosticDetail::NotMeasured,
                    Some(DiagnosticAction::Refresh),
                    None,
                ),
            ],
        }
    }
}

pub fn compatibility_lines(rows: &[DiagnosticRow]) -> Vec<(&'static str, &'static str)> {
    rows.iter()
        .map(|row| (label(row.id), compatibility_value(row)))
        .collect()
}

fn runtime_row(observation: RuntimeObservation) -> DiagnosticRow {
    match observation {
        RuntimeObservation::Current(_) => row(
            DiagnosticId::Runtime,
            DiagnosticState::Pass,
            DiagnosticDetail::Ready,
            None,
            None,
        ),
        RuntimeObservation::Missing => row(
            DiagnosticId::Runtime,
            DiagnosticState::NotConfigured,
            DiagnosticDetail::NotConfigured,
            Some(DiagnosticAction::Refresh),
            None,
        ),
        RuntimeObservation::Stale | RuntimeObservation::Malformed => row(
            DiagnosticId::Runtime,
            DiagnosticState::Unknown,
            DiagnosticDetail::Stale,
            Some(DiagnosticAction::Refresh),
            Some(DiagnosticFailureCode::RuntimeStatusUnavailable),
        ),
    }
}

fn input_row(access: AccessState) -> DiagnosticRow {
    match access {
        AccessState::Granted => row(
            DiagnosticId::Input,
            DiagnosticState::Pass,
            DiagnosticDetail::Ready,
            None,
            None,
        ),
        AccessState::Denied | AccessState::NotDetermined => row(
            DiagnosticId::Input,
            if access == AccessState::Denied {
                DiagnosticState::Fail
            } else {
                DiagnosticState::NotConfigured
            },
            if access == AccessState::Denied {
                DiagnosticDetail::PolicyBlocked
            } else {
                DiagnosticDetail::NotConfigured
            },
            Some(DiagnosticAction::ReviewLocalPermission),
            Some(DiagnosticFailureCode::InputPermissionDenied),
        ),
    }
}

fn clipboard_row(observation: ClipboardObservation) -> DiagnosticRow {
    match observation {
        ClipboardObservation::Ready => row(
            DiagnosticId::Clipboard,
            DiagnosticState::Pass,
            DiagnosticDetail::Ready,
            None,
            None,
        ),
        ClipboardObservation::PermissionDenied | ClipboardObservation::PermissionNotDetermined => {
            row(
                DiagnosticId::Clipboard,
                if observation == ClipboardObservation::PermissionDenied {
                    DiagnosticState::Fail
                } else {
                    DiagnosticState::NotConfigured
                },
                if observation == ClipboardObservation::PermissionDenied {
                    DiagnosticDetail::PolicyBlocked
                } else {
                    DiagnosticDetail::NotConfigured
                },
                Some(DiagnosticAction::ReviewLocalPermission),
                Some(DiagnosticFailureCode::ClipboardUnavailable),
            )
        }
        ClipboardObservation::Unavailable => row(
            DiagnosticId::Clipboard,
            DiagnosticState::Fail,
            DiagnosticDetail::Unavailable,
            Some(DiagnosticAction::Retry),
            Some(DiagnosticFailureCode::ClipboardUnavailable),
        ),
        ClipboardObservation::Fault => row(
            DiagnosticId::Clipboard,
            DiagnosticState::Fail,
            DiagnosticDetail::Fault,
            Some(DiagnosticAction::Retry),
            Some(DiagnosticFailureCode::ClipboardFault),
        ),
    }
}

fn displays_row(observation: DisplayObservation) -> DiagnosticRow {
    match observation {
        DisplayObservation::Measured(count) if count > 0 => row(
            DiagnosticId::Displays,
            DiagnosticState::Pass,
            DiagnosticDetail::Ready,
            None,
            None,
        ),
        DisplayObservation::Measured(_) | DisplayObservation::Unavailable => row(
            DiagnosticId::Displays,
            DiagnosticState::Fail,
            DiagnosticDetail::Unavailable,
            Some(DiagnosticAction::Retry),
            Some(DiagnosticFailureCode::DisplaysUnavailable),
        ),
    }
}

fn discovery_row(observation: DiscoveryObservation) -> DiagnosticRow {
    match observation {
        DiscoveryObservation::Ready => row(
            DiagnosticId::Relationship,
            DiagnosticState::Pass,
            DiagnosticDetail::Ready,
            None,
            None,
        ),
        DiscoveryObservation::Unavailable => row(
            DiagnosticId::Relationship,
            DiagnosticState::Fail,
            DiagnosticDetail::Unavailable,
            Some(DiagnosticAction::ReviewPrivateNetwork),
            Some(DiagnosticFailureCode::DiscoveryUnavailable),
        ),
    }
}

fn relationship_row(observation: RelationshipObservation) -> DiagnosticRow {
    match observation {
        RelationshipObservation::Configured => row(
            DiagnosticId::Policy,
            DiagnosticState::Pass,
            DiagnosticDetail::Ready,
            None,
            None,
        ),
        RelationshipObservation::NotConfigured => row(
            DiagnosticId::Policy,
            DiagnosticState::NotConfigured,
            DiagnosticDetail::NotConfigured,
            None,
            None,
        ),
        RelationshipObservation::Unavailable => row(
            DiagnosticId::Policy,
            DiagnosticState::Unknown,
            DiagnosticDetail::Unavailable,
            Some(DiagnosticAction::Refresh),
            Some(DiagnosticFailureCode::SessionUnavailable),
        ),
    }
}

fn session_row(observation: PairedSessionObservation) -> DiagnosticRow {
    match observation {
        PairedSessionObservation::Current(count) if count > 0 => row(
            DiagnosticId::Session,
            DiagnosticState::Pass,
            DiagnosticDetail::Ready,
            None,
            None,
        ),
        PairedSessionObservation::Current(_) => row(
            DiagnosticId::Session,
            DiagnosticState::NotConfigured,
            DiagnosticDetail::NotConfigured,
            None,
            None,
        ),
        PairedSessionObservation::Unavailable => row(
            DiagnosticId::Session,
            DiagnosticState::Unknown,
            DiagnosticDetail::Unavailable,
            Some(DiagnosticAction::Refresh),
            Some(DiagnosticFailureCode::SessionUnavailable),
        ),
    }
}

fn row(
    id: DiagnosticId,
    state: DiagnosticState,
    detail: DiagnosticDetail,
    action: Option<DiagnosticAction>,
    failure_code: Option<DiagnosticFailureCode>,
) -> DiagnosticRow {
    DiagnosticRow {
        id,
        label: diagnostic_label(id),
        state,
        detail,
        action,
        failure_code,
    }
}

fn diagnostic_label(id: DiagnosticId) -> DiagnosticLabel {
    match id {
        DiagnosticId::Runtime => DiagnosticLabel::Runtime,
        DiagnosticId::Input => DiagnosticLabel::Input,
        DiagnosticId::Clipboard => DiagnosticLabel::Clipboard,
        DiagnosticId::Displays => DiagnosticLabel::Displays,
        DiagnosticId::Relationship => DiagnosticLabel::Relationship,
        DiagnosticId::Session => DiagnosticLabel::Session,
        DiagnosticId::Layout => DiagnosticLabel::Layout,
        DiagnosticId::Policy => DiagnosticLabel::Policy,
    }
}

fn label(id: DiagnosticId) -> &'static str {
    match id {
        DiagnosticId::Runtime => "runtime",
        DiagnosticId::Input => "input access",
        DiagnosticId::Clipboard => "clipboard access",
        DiagnosticId::Displays => "displays",
        DiagnosticId::Relationship => "discovery",
        DiagnosticId::Session => "authenticated sessions",
        DiagnosticId::Layout => "layout",
        DiagnosticId::Policy => "relationship policy",
    }
}

fn compatibility_value(row: &DiagnosticRow) -> &'static str {
    match row.state {
        DiagnosticState::Pass => "PASS",
        DiagnosticState::Fail => "FAIL",
        DiagnosticState::Unknown => "UNKNOWN",
        DiagnosticState::NotConfigured => "NOT CONFIGURED",
    }
}
