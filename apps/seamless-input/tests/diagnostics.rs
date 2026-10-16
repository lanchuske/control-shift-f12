use seamless_input::{
    diagnostics::{
        ClipboardObservation, DiagnosticFacts, DiagnosticSnapshot, DiscoveryObservation,
        DisplayObservation, PairedSessionObservation, RelationshipObservation, RuntimeObservation,
    },
    runtime_status::{RuntimeStatus, RuntimeStatusStore},
    ui_contract::{
        DiagnosticAction, DiagnosticDetail, DiagnosticFailureCode, DiagnosticId, DiagnosticState,
    },
};
use seamless_input_core::platform::AccessState;
use std::time::{Duration, UNIX_EPOCH};

fn current_runtime(sessions: usize) -> RuntimeObservation {
    RuntimeObservation::Current(RuntimeStatus {
        process_id: 42,
        updated_unix_ms: 10_000,
        displays: 2,
        authenticated_sessions: sessions,
    })
}

fn live_facts() -> DiagnosticFacts {
    DiagnosticFacts {
        runtime: current_runtime(1),
        input_access: AccessState::Granted,
        clipboard: ClipboardObservation::Ready,
        displays: DisplayObservation::Measured(2),
        discovery: DiscoveryObservation::Ready,
        relationship: RelationshipObservation::Configured,
        paired_session: PairedSessionObservation::Current(1),
    }
}

fn row(
    snapshot: &DiagnosticSnapshot,
    id: DiagnosticId,
) -> &seamless_input::ui_contract::DiagnosticRow {
    snapshot
        .rows
        .iter()
        .find(|row| row.id == id)
        .expect("stable diagnostic row")
}

#[test]
fn current_live_facts_project_only_structured_redacted_rows() {
    let snapshot = DiagnosticSnapshot::from_live(live_facts());

    assert_eq!(
        row(&snapshot, DiagnosticId::Runtime).state,
        DiagnosticState::Pass
    );
    assert_eq!(
        row(&snapshot, DiagnosticId::Clipboard).state,
        DiagnosticState::Pass
    );
    assert_eq!(
        row(&snapshot, DiagnosticId::Displays).state,
        DiagnosticState::Pass
    );
    assert_eq!(
        row(&snapshot, DiagnosticId::Session).state,
        DiagnosticState::Pass
    );
    assert!(snapshot.rows.iter().all(|row| row.failure_code.is_none()));

    let serialized = serde_json::to_string(&snapshot.rows).unwrap();
    assert!(!serialized.contains("42"));
    assert!(!serialized.contains("10_000"));
    assert!(!serialized.contains("address"));
}

#[test]
fn stale_or_malformed_runtime_never_projects_a_running_or_authenticated_pass() {
    for runtime in [RuntimeObservation::Stale, RuntimeObservation::Malformed] {
        let mut facts = live_facts();
        facts.runtime = runtime;

        let snapshot = DiagnosticSnapshot::from_live(facts);
        let runtime = row(&snapshot, DiagnosticId::Runtime);
        assert_eq!(runtime.state, DiagnosticState::Unknown);
        assert_eq!(runtime.detail, DiagnosticDetail::Stale);
        assert_eq!(
            runtime.failure_code,
            Some(DiagnosticFailureCode::RuntimeStatusUnavailable)
        );

        let session = row(&snapshot, DiagnosticId::Session);
        assert_ne!(session.state, DiagnosticState::Pass);
    }
}

#[test]
fn clipboard_fault_is_fail_not_green_and_has_only_a_safe_failure_code() {
    let mut facts = live_facts();
    facts.clipboard = ClipboardObservation::Unavailable;

    let snapshot = DiagnosticSnapshot::from_live(facts);
    let clipboard = row(&snapshot, DiagnosticId::Clipboard);
    assert_eq!(clipboard.state, DiagnosticState::Fail);
    assert_eq!(clipboard.detail, DiagnosticDetail::Unavailable);
    assert_eq!(clipboard.action, Some(DiagnosticAction::Retry));
    assert_eq!(
        clipboard.failure_code,
        Some(DiagnosticFailureCode::ClipboardUnavailable)
    );
}

#[test]
fn unavailable_discovery_and_unconfigured_session_stay_truthful_without_authority() {
    let mut facts = live_facts();
    facts.discovery = DiscoveryObservation::Unavailable;
    facts.relationship = RelationshipObservation::NotConfigured;
    facts.paired_session = PairedSessionObservation::Current(0);

    let snapshot = DiagnosticSnapshot::from_live(facts);
    let discovery = row(&snapshot, DiagnosticId::Relationship);
    assert_eq!(discovery.state, DiagnosticState::Fail);
    assert_eq!(
        discovery.action,
        Some(DiagnosticAction::ReviewPrivateNetwork)
    );
    assert_eq!(
        discovery.failure_code,
        Some(DiagnosticFailureCode::DiscoveryUnavailable)
    );

    let session = row(&snapshot, DiagnosticId::Session);
    assert_eq!(session.state, DiagnosticState::NotConfigured);
    assert_eq!(session.detail, DiagnosticDetail::NotConfigured);
}

#[test]
fn runtime_observation_reads_current_missing_stale_and_malformed_owner_status() {
    let root = tempfile::tempdir().unwrap();
    let store = RuntimeStatusStore::within(root.path(), 4242);
    let now = UNIX_EPOCH + Duration::from_secs(100);

    assert_eq!(
        RuntimeObservation::from_owner_status(root.path(), now),
        RuntimeObservation::Missing
    );

    store
        .publish(&RuntimeStatus {
            process_id: 4242,
            updated_unix_ms: 100_000,
            displays: 2,
            authenticated_sessions: 1,
        })
        .unwrap();
    assert!(matches!(
        RuntimeObservation::from_owner_status(root.path(), now),
        RuntimeObservation::Current(status) if status.process_id == 4242
    ));

    store
        .publish(&RuntimeStatus {
            process_id: 4242,
            updated_unix_ms: 10_000,
            displays: 2,
            authenticated_sessions: 1,
        })
        .unwrap();
    assert_eq!(
        RuntimeObservation::from_owner_status(root.path(), now),
        RuntimeObservation::Stale
    );

    std::fs::write(store.path(), "malformed\n").unwrap();
    assert_eq!(
        RuntimeObservation::from_owner_status(root.path(), now),
        RuntimeObservation::Malformed
    );

    store
        .publish(&RuntimeStatus {
            process_id: 4242,
            updated_unix_ms: 101_001,
            displays: 2,
            authenticated_sessions: 1,
        })
        .unwrap();
    assert_eq!(
        RuntimeObservation::from_owner_status(root.path(), now),
        RuntimeObservation::Malformed,
        "a future heartbeat must not be treated as current"
    );

    let unreadable_root = root.path().join("not-a-directory");
    std::fs::write(&unreadable_root, "not a status root").unwrap();
    assert_eq!(
        RuntimeObservation::from_owner_status(&unreadable_root, now),
        RuntimeObservation::Malformed,
        "status I/O failures must not claim a running runtime"
    );
}
