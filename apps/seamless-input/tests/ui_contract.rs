use seamless_input::ui_contract::{
    CandidateCompatibility, CandidateFreshness, CandidateHandle, CandidateView, CapabilityView,
    DiagnosticAction, DiagnosticDetail, DiagnosticId, DiagnosticLabel, DiagnosticRow,
    DiagnosticState, DisplayHandle, DisplayOrientation, DisplayView, InventoryProvenance,
    InventoryView, LayoutState, LayoutView, RelationshipHandle, RelationshipState,
    RelationshipView, RemainingDuration, RequestId, SasCode, UI_SCHEMA_VERSION, UiCommand,
    UiContractError, UiEvent, UiRequest, UiRequestCache, UiResponse, UiSnapshot, UiState, V01View,
};
use serde_json::json;

fn handle<T>(value: &str) -> T
where
    T: TryFrom<String, Error = UiContractError>,
{
    T::try_from(value.to_owned()).expect("test handle is valid")
}

fn snapshot() -> UiSnapshot {
    UiSnapshot {
        schema_version: UI_SCHEMA_VERSION,
        generation: 7,
        state: UiState::Browsing,
        diagnostics: vec![DiagnosticRow {
            id: DiagnosticId::Runtime,
            label: DiagnosticLabel::Runtime,
            state: DiagnosticState::Unknown,
            detail: DiagnosticDetail::NotMeasured,
            action: Some(DiagnosticAction::Refresh),
        }],
        candidates: vec![CandidateView {
            handle: handle::<CandidateHandle>("nearby_1"),
            compatibility: CandidateCompatibility::Compatible,
            freshness: CandidateFreshness::Current,
        }],
        confirmed: vec![RelationshipView {
            handle: handle::<RelationshipHandle>("relationship_1"),
            state: RelationshipState::Active,
        }],
        v01: None,
        inventory: Some(InventoryView {
            generation: 4,
            provenance: InventoryProvenance::MeasuredLocally,
            displays: vec![DisplayView {
                handle: handle::<DisplayHandle>("display_1"),
                logical_width: 1440,
                logical_height: 900,
                scale_milli: 1000,
                orientation: DisplayOrientation::Landscape,
                physical_width_mm: None,
                physical_height_mm: None,
            }],
        }),
        layout: LayoutView {
            state: LayoutState::NotConfigured,
        },
        capabilities: CapabilityView::all_disabled(),
    }
}

fn v01_view() -> V01View {
    V01View {
        code: SasCode::try_from(vec!["42".to_owned(), "71".to_owned(), "68".to_owned()])
            .expect("test SAS is valid"),
        remaining: RemainingDuration::MoreThanTenSeconds,
    }
}

#[test]
fn valid_snapshot_round_trips_and_framing_stays_bounded() {
    let source = snapshot();
    source.validate().expect("valid local projection");

    let encoded = serde_json::to_vec(&source).expect("serialize snapshot");
    let decoded: UiSnapshot = serde_json::from_slice(&encoded).expect("deserialize snapshot");
    assert_eq!(decoded, source);

    let mut framed = Vec::new();
    source.write_framed(&mut framed).expect("bounded frame");
    assert_eq!(
        u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize,
        encoded.len()
    );
}

#[test]
fn snapshot_rejects_unknown_raw_address_or_identity_fields() {
    let mut raw_address = serde_json::to_value(snapshot()).unwrap();
    raw_address["address"] = json!("192.0.2.10:4444");
    assert!(serde_json::from_value::<UiSnapshot>(raw_address).is_err());

    let mut raw_identity = serde_json::to_value(snapshot()).unwrap();
    raw_identity["candidates"][0]["identity"] = json!("ed25519:secret");
    assert!(serde_json::from_value::<UiSnapshot>(raw_identity).is_err());
}

#[test]
fn snapshot_rejects_wrong_schema_or_more_than_32_visible_items() {
    let mut wrong_schema = serde_json::to_value(snapshot()).unwrap();
    wrong_schema["schema_version"] = json!(2);
    assert!(serde_json::from_value::<UiSnapshot>(wrong_schema).is_err());

    let mut too_many = snapshot();
    too_many.candidates = (0..33)
        .map(|index| CandidateView {
            handle: handle::<CandidateHandle>(&format!("nearby_{index}")),
            compatibility: CandidateCompatibility::Compatible,
            freshness: CandidateFreshness::Current,
        })
        .collect();
    assert_eq!(too_many.validate(), Err(UiContractError::TooManyCandidates));
    assert!(serde_json::from_value::<UiSnapshot>(serde_json::to_value(too_many).unwrap()).is_err());
}

#[test]
fn snapshot_rejects_more_than_32_diagnostics_before_writing_a_frame() {
    let mut too_many = snapshot();
    too_many.diagnostics = (0..33)
        .map(|_| DiagnosticRow {
            id: DiagnosticId::Runtime,
            label: DiagnosticLabel::Runtime,
            state: DiagnosticState::Unknown,
            detail: DiagnosticDetail::NotMeasured,
            action: None,
        })
        .collect();

    let mut framed = Vec::new();
    assert_eq!(
        too_many.write_framed(&mut framed),
        Err(UiContractError::TooManyDiagnostics)
    );
    assert!(framed.is_empty());
}

#[test]
fn snapshot_rejects_sas_outside_v01_pending() {
    let mut outside_v01 = snapshot();
    outside_v01.v01 = Some(v01_view());
    assert_eq!(outside_v01.validate(), Err(UiContractError::SasOutsideV01));
    assert!(
        serde_json::from_value::<UiSnapshot>(serde_json::to_value(outside_v01).unwrap()).is_err()
    );
}

#[test]
fn commands_default_to_denied_capabilities_and_reject_injected_authorization() {
    let capabilities = CapabilityView::all_disabled();
    assert!(!capabilities.input_enabled());
    assert!(!capabilities.clipboard_enabled());

    let injected = json!({"kind":"refresh_diagnostics","input_enabled":true});
    assert!(serde_json::from_value::<UiCommand>(injected).is_err());
}

#[test]
fn remote_looking_event_is_not_a_local_ui_event() {
    let remote = json!({"kind":"peer_confirmed","generation":8});
    assert!(serde_json::from_value::<UiEvent>(remote).is_err());
}

#[test]
fn local_event_rejects_identity_or_other_unknown_fields() {
    let injected = json!({
        "kind":"snapshot_published",
        "generation":8,
        "identity":"ed25519:secret"
    });
    assert!(serde_json::from_value::<UiEvent>(injected).is_err());
}

#[test]
fn response_rejects_untyped_identity_material() {
    let injected = json!({
        "kind":"acknowledged",
        "identity":"ed25519:secret"
    });
    assert!(serde_json::from_value::<UiResponse>(injected).is_err());
}

#[test]
fn duplicate_request_id_replays_only_an_identical_typed_request() {
    let id = handle::<RequestId>("request_1");
    let request = UiRequest::new(id.clone(), UiCommand::RefreshDiagnostics).unwrap();
    let response = UiResponse::Snapshot(snapshot());
    let mut cache = UiRequestCache::default();

    assert_eq!(
        cache.record(request.clone(), response.clone()),
        Ok(response.clone())
    );
    assert_eq!(
        cache.record(request.clone(), UiResponse::Acknowledged),
        Ok(response.clone())
    );

    let changed = UiRequest::new(id, UiCommand::StartDiscovery).unwrap();
    assert_eq!(
        cache.record(changed, UiResponse::Acknowledged),
        Err(UiContractError::RequestIdConflict)
    );
}

#[test]
fn typed_ui_request_uses_the_existing_control_request_shape() {
    let request = UiRequest::new(
        handle::<RequestId>("request_2"),
        UiCommand::SelectCandidate {
            handle: handle::<CandidateHandle>("nearby_1"),
        },
    )
    .unwrap();

    let control = request
        .as_control_request()
        .expect("existing framed request shape");
    assert_eq!(control.v, 1);
    assert_eq!(control.id, "request_2");
    assert_eq!(control.command, "ui.command");
    assert_eq!(control.args, serde_json::to_value(request.command).unwrap());
}
