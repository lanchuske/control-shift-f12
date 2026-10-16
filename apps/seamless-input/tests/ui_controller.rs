use seamless_input::{
    ui_contract::{
        CandidateCompatibility, CandidateFreshness, CandidateHandle, CandidateView,
        DiagnosticDetail, DiagnosticId, DiagnosticLabel, DiagnosticRow, DiagnosticState,
        LayoutState, LayoutView, RemainingDuration, SasCode, UiCommand, UiError, UiState, V01View,
    },
    ui_controller::{UiController, UiRuntimeEvent},
};

fn candidate() -> CandidateHandle {
    CandidateHandle::try_from("nearby_1".to_owned()).unwrap()
}

fn controller() -> UiController {
    UiController::new(0)
}

fn confirmed_controller() -> UiController {
    let mut controller = controller();
    controller
        .apply_local_at(0, UiCommand::StartDiscovery)
        .unwrap();
    controller.on_runtime_at(
        0,
        UiRuntimeEvent::Candidates(vec![CandidateView {
            handle: candidate(),
            compatibility: CandidateCompatibility::Compatible,
            freshness: CandidateFreshness::Current,
        }]),
    );
    controller
        .apply_local_at(
            0,
            UiCommand::SelectCandidate {
                handle: candidate(),
            },
        )
        .unwrap();
    controller
        .apply_local_at(0, UiCommand::BeginBootstrap)
        .unwrap();
    controller.on_runtime_at(0, UiRuntimeEvent::BootstrapSasReady);
    controller
        .apply_local_at(0, UiCommand::ConfirmBootstrap { matches: true })
        .unwrap();
    controller.on_runtime_at(0, UiRuntimeEvent::BootstrapReceiptVerified);
    controller
}

fn enter_v01(controller: &mut UiController) {
    controller.apply_local_at(0, UiCommand::BeginV01).unwrap();
    controller.on_runtime_at(
        0,
        UiRuntimeEvent::V01SasReady(V01View {
            code: SasCode::try_from(vec!["42".to_owned(), "71".to_owned()]).unwrap(),
            remaining: RemainingDuration::MoreThanTenSeconds,
        }),
    );
}

fn runtime_pass() -> DiagnosticRow {
    DiagnosticRow {
        id: DiagnosticId::Runtime,
        label: DiagnosticLabel::Runtime,
        state: DiagnosticState::Pass,
        detail: DiagnosticDetail::Ready,
        action: None,
        failure_code: None,
    }
}

fn inventory_controller() -> UiController {
    let mut controller = confirmed_controller();
    enter_v01(&mut controller);
    controller
        .apply_local_at(29_999, UiCommand::ConfirmV01 { matches: true })
        .unwrap();
    controller.on_runtime_at(29_999, UiRuntimeEvent::PeerConfirmed);
    assert_eq!(controller.snapshot().state, UiState::InventoryCurrent);
    controller
}

#[test]
fn legal_local_route_keeps_capabilities_off() {
    let mut controller = controller();
    controller
        .apply_local_at(0, UiCommand::StartDiscovery)
        .unwrap();
    controller.on_runtime_at(
        0,
        UiRuntimeEvent::Candidates(vec![CandidateView {
            handle: candidate(),
            compatibility: CandidateCompatibility::Compatible,
            freshness: CandidateFreshness::Current,
        }]),
    );
    controller
        .apply_local_at(
            0,
            UiCommand::SelectCandidate {
                handle: candidate(),
            },
        )
        .unwrap();
    controller
        .apply_local_at(0, UiCommand::BeginBootstrap)
        .unwrap();
    controller.on_runtime_at(0, UiRuntimeEvent::BootstrapSasReady);
    controller
        .apply_local_at(0, UiCommand::ConfirmBootstrap { matches: true })
        .unwrap();
    controller.on_runtime_at(0, UiRuntimeEvent::BootstrapReceiptVerified);
    enter_v01(&mut controller);

    assert_eq!(controller.snapshot().state, UiState::V01Pending);
    assert!(!controller.snapshot().capabilities.input_enabled());
    assert!(!controller.snapshot().capabilities.clipboard_enabled());
}

#[test]
fn remote_confirm_cannot_advance_v01_without_local_confirm() {
    let mut controller = confirmed_controller();
    enter_v01(&mut controller);
    controller.on_runtime_at(0, UiRuntimeEvent::PeerConfirmed);
    assert_eq!(controller.snapshot().state, UiState::V01Pending);
}

#[test]
fn invalid_candidate_switch_and_layout_before_inventory_are_rejected_locally() {
    let mut controller = controller();
    assert_eq!(
        controller.apply_local_at(0, UiCommand::SubmitLayout),
        Err(UiError::InvalidState)
    );
    controller
        .apply_local_at(0, UiCommand::StartDiscovery)
        .unwrap();
    controller.on_runtime_at(
        0,
        UiRuntimeEvent::Candidates(vec![CandidateView {
            handle: candidate(),
            compatibility: CandidateCompatibility::Compatible,
            freshness: CandidateFreshness::Current,
        }]),
    );
    controller
        .apply_local_at(
            0,
            UiCommand::SelectCandidate {
                handle: candidate(),
            },
        )
        .unwrap();
    assert_eq!(
        controller.apply_local_at(
            0,
            UiCommand::SelectCandidate {
                handle: candidate()
            }
        ),
        Err(UiError::InvalidState)
    );
}

#[test]
fn v01_deadline_and_cancel_clear_volatile_state_without_extending_it() {
    let mut controller = confirmed_controller();
    enter_v01(&mut controller);
    controller.on_runtime_at(30_001, UiRuntimeEvent::Diagnostics(vec![]));
    assert_eq!(controller.snapshot().state, UiState::ConfirmedRelationship);
    assert!(controller.snapshot().v01.is_none());

    enter_v01(&mut controller);
    controller
        .apply_local_at(30_001, UiCommand::Cancel)
        .unwrap();
    assert_eq!(controller.snapshot().state, UiState::ConfirmedRelationship);
    assert!(controller.snapshot().v01.is_none());
}

#[test]
fn decisive_commands_and_runtime_events_expire_v01_at_exact_deadline_without_a_tick() {
    let mut confirm_controller = confirmed_controller();
    enter_v01(&mut confirm_controller);
    assert_eq!(
        confirm_controller.apply_local_at(30_000, UiCommand::ConfirmV01 { matches: true }),
        Err(UiError::InvalidState)
    );
    assert_eq!(
        confirm_controller.snapshot().state,
        UiState::ConfirmedRelationship
    );
    assert!(confirm_controller.snapshot().v01.is_none());

    let mut peer_controller = confirmed_controller();
    enter_v01(&mut peer_controller);
    peer_controller
        .apply_local_at(29_999, UiCommand::ConfirmV01 { matches: true })
        .unwrap();
    peer_controller.on_runtime_at(30_000, UiRuntimeEvent::PeerConfirmed);
    assert_eq!(
        peer_controller.snapshot().state,
        UiState::ConfirmedRelationship
    );
    assert!(peer_controller.snapshot().v01.is_none());
}

#[test]
fn invalid_v01_runtime_fact_is_rejected_before_snapshot_storage() {
    let mut controller = confirmed_controller();
    controller.apply_local_at(0, UiCommand::BeginV01).unwrap();
    controller.on_runtime_at(
        0,
        UiRuntimeEvent::V01SasReady(V01View {
            code: SasCode::try_from(vec!["42".to_owned(), "71".to_owned()]).unwrap(),
            remaining: RemainingDuration::Seconds(0),
        }),
    );

    assert_eq!(controller.snapshot().state, UiState::ConfirmedRelationship);
    assert!(controller.snapshot().v01.is_none());
    assert!(controller.snapshot().validate().is_ok());
}

#[test]
fn projection_requires_one_current_runtime_pass_before_any_actions() {
    let cases = [
        vec![],
        vec![runtime_pass(), runtime_pass()],
        vec![DiagnosticRow {
            id: DiagnosticId::Runtime,
            label: DiagnosticLabel::Runtime,
            state: DiagnosticState::Unknown,
            detail: DiagnosticDetail::Stale,
            action: None,
            failure_code: None,
        }],
    ];

    for rows in cases {
        let mut controller = inventory_controller();
        controller.on_runtime_at(29_999, UiRuntimeEvent::Diagnostics(rows));
        let view = controller.view();
        assert!(view.runtime_not_running);
        assert!(!view.can_start_sharing);
        assert!(!view.can_edit_layout);
    }
}

#[test]
fn public_controller_surface_exposes_only_timestamped_decisive_paths() {
    let source = include_str!("../src/ui_controller.rs");

    assert!(source.contains("pub fn apply_local_at"));
    assert!(source.contains("pub fn on_runtime_at"));
    assert!(!source.contains("pub fn apply_local("));
    assert!(!source.contains("pub fn on_runtime("));
    assert!(!source.contains("pub fn advance_to("));
}

#[test]
fn stale_diagnostics_project_as_not_running_and_do_not_enable_actions() {
    let mut controller = controller();
    controller.on_runtime_at(
        0,
        UiRuntimeEvent::Diagnostics(vec![DiagnosticRow {
            id: DiagnosticId::Runtime,
            label: DiagnosticLabel::Runtime,
            state: DiagnosticState::Unknown,
            detail: DiagnosticDetail::Stale,
            action: None,
            failure_code: None,
        }]),
    );
    let view = controller.view();
    assert!(view.runtime_not_running);
    assert!(!view.can_start_sharing);
    assert_eq!(
        controller.snapshot().layout,
        LayoutView {
            state: LayoutState::NotConfigured
        }
    );
}

#[test]
fn fenced_remote_outcome_refuses_new_v01_or_layout_edits() {
    let mut controller = confirmed_controller();
    controller.on_runtime_at(0, UiRuntimeEvent::RemoteOutcomeUnknown);

    assert_eq!(controller.snapshot().state, UiState::RemoteOutcomeUnknown);
    assert_eq!(
        controller.apply_local_at(0, UiCommand::BeginV01),
        Err(UiError::Blocked)
    );
    assert_eq!(
        controller.apply_local_at(0, UiCommand::ResetLayout),
        Err(UiError::Blocked)
    );
    assert!(!controller.snapshot().capabilities.input_enabled());
    assert!(!controller.snapshot().capabilities.clipboard_enabled());
}
