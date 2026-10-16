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
    controller.apply_local(UiCommand::StartDiscovery).unwrap();
    controller.on_runtime(UiRuntimeEvent::Candidates(vec![CandidateView {
        handle: candidate(),
        compatibility: CandidateCompatibility::Compatible,
        freshness: CandidateFreshness::Current,
    }]));
    controller
        .apply_local(UiCommand::SelectCandidate {
            handle: candidate(),
        })
        .unwrap();
    controller.apply_local(UiCommand::BeginBootstrap).unwrap();
    controller.on_runtime(UiRuntimeEvent::BootstrapSasReady);
    controller
        .apply_local(UiCommand::ConfirmBootstrap { matches: true })
        .unwrap();
    controller.on_runtime(UiRuntimeEvent::BootstrapReceiptVerified);
    controller
}

fn enter_v01(controller: &mut UiController) {
    controller.apply_local(UiCommand::BeginV01).unwrap();
    controller.on_runtime(UiRuntimeEvent::V01SasReady(V01View {
        code: SasCode::try_from(vec!["42".to_owned(), "71".to_owned()]).unwrap(),
        remaining: RemainingDuration::MoreThanTenSeconds,
    }));
}

#[test]
fn legal_local_route_keeps_capabilities_off() {
    let mut controller = controller();
    controller.apply_local(UiCommand::StartDiscovery).unwrap();
    controller.on_runtime(UiRuntimeEvent::Candidates(vec![CandidateView {
        handle: candidate(),
        compatibility: CandidateCompatibility::Compatible,
        freshness: CandidateFreshness::Current,
    }]));
    controller
        .apply_local(UiCommand::SelectCandidate {
            handle: candidate(),
        })
        .unwrap();
    controller.apply_local(UiCommand::BeginBootstrap).unwrap();
    controller.on_runtime(UiRuntimeEvent::BootstrapSasReady);
    controller
        .apply_local(UiCommand::ConfirmBootstrap { matches: true })
        .unwrap();
    controller.on_runtime(UiRuntimeEvent::BootstrapReceiptVerified);
    enter_v01(&mut controller);

    assert_eq!(controller.snapshot().state, UiState::V01Pending);
    assert!(!controller.snapshot().capabilities.input_enabled());
    assert!(!controller.snapshot().capabilities.clipboard_enabled());
}

#[test]
fn remote_confirm_cannot_advance_v01_without_local_confirm() {
    let mut controller = confirmed_controller();
    enter_v01(&mut controller);
    controller.on_runtime(UiRuntimeEvent::PeerConfirmed);
    assert_eq!(controller.snapshot().state, UiState::V01Pending);
}

#[test]
fn invalid_candidate_switch_and_layout_before_inventory_are_rejected_locally() {
    let mut controller = controller();
    assert_eq!(
        controller.apply_local(UiCommand::SubmitLayout),
        Err(UiError::InvalidState)
    );
    controller.apply_local(UiCommand::StartDiscovery).unwrap();
    controller.on_runtime(UiRuntimeEvent::Candidates(vec![CandidateView {
        handle: candidate(),
        compatibility: CandidateCompatibility::Compatible,
        freshness: CandidateFreshness::Current,
    }]));
    controller
        .apply_local(UiCommand::SelectCandidate {
            handle: candidate(),
        })
        .unwrap();
    assert_eq!(
        controller.apply_local(UiCommand::SelectCandidate {
            handle: candidate()
        }),
        Err(UiError::InvalidState)
    );
}

#[test]
fn v01_deadline_and_cancel_clear_volatile_state_without_extending_it() {
    let mut controller = confirmed_controller();
    enter_v01(&mut controller);
    controller.advance_to(30_001);
    assert_eq!(controller.snapshot().state, UiState::ConfirmedRelationship);
    assert!(controller.snapshot().v01.is_none());

    enter_v01(&mut controller);
    controller.apply_local(UiCommand::Cancel).unwrap();
    assert_eq!(controller.snapshot().state, UiState::ConfirmedRelationship);
    assert!(controller.snapshot().v01.is_none());
}

#[test]
fn stale_diagnostics_project_as_not_running_and_do_not_enable_actions() {
    let mut controller = controller();
    controller.on_runtime(UiRuntimeEvent::Diagnostics(vec![DiagnosticRow {
        id: DiagnosticId::Runtime,
        label: DiagnosticLabel::Runtime,
        state: DiagnosticState::Unknown,
        detail: DiagnosticDetail::Stale,
        action: None,
        failure_code: None,
    }]));
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
    controller.on_runtime(UiRuntimeEvent::RemoteOutcomeUnknown);

    assert_eq!(controller.snapshot().state, UiState::RemoteOutcomeUnknown);
    assert_eq!(
        controller.apply_local(UiCommand::BeginV01),
        Err(UiError::Blocked)
    );
    assert_eq!(
        controller.apply_local(UiCommand::ResetLayout),
        Err(UiError::Blocked)
    );
    assert!(!controller.snapshot().capabilities.input_enabled());
    assert!(!controller.snapshot().capabilities.clipboard_enabled());
}
