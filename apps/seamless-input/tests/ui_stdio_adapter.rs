use seamless_input::{
    control_api::{self, Request},
    ui_contract::{RemainingDuration, SasCode, V01View},
    ui_stdio_adapter::{AuthoritativeUiEvent, ChildFrame, UiStdioAdapter, run_stdio},
};
use serde_json::json;

fn request(id: &str, command: &str, args: serde_json::Value) -> Request {
    Request {
        v: 1,
        id: id.into(),
        command: command.into(),
        args,
    }
}

fn v01() -> V01View {
    V01View {
        code: SasCode::try_from(vec!["42".into(), "71".into(), "68".into()]).unwrap(),
        remaining: RemainingDuration::MoreThanTenSeconds,
    }
}

fn adapter_in_v01() -> (UiStdioAdapter, Vec<ChildFrame>) {
    let mut adapter = UiStdioAdapter::new(0);
    adapter.on_authoritative_at(0, AuthoritativeUiEvent::RelationshipVerified);
    let frames = adapter.on_authoritative_at(
        1,
        AuthoritativeUiEvent::V01SasReady {
            view: v01(),
            remaining_ms: 30_000,
        },
    );
    (adapter, frames)
}

#[test]
fn current_sas_is_child_only_and_terminal_cleanup_invalidates_it() {
    let (mut adapter, frames) = adapter_in_v01();
    assert!(
        frames
            .iter()
            .any(|frame| matches!(frame, ChildFrame::SasDisplay(value) if value.current))
    );
    let snapshots: Vec<_> = frames
        .iter()
        .filter_map(|frame| match frame {
            ChildFrame::Snapshot(snapshot) => Some(serde_json::to_string(snapshot).unwrap()),
            _ => None,
        })
        .collect();
    assert!(snapshots.iter().all(|snapshot| !snapshot.contains("42")));

    let frames = adapter.on_authoritative_at(2, AuthoritativeUiEvent::PermissionRevoked);
    assert!(
        frames
            .iter()
            .any(|frame| matches!(frame, ChildFrame::SasDisplay(value) if !value.current))
    );
    assert!(!adapter.has_current_sas());
}

#[test]
fn host_accepts_only_refresh_or_boolean_confirm_and_rejects_sas_reexports() {
    let (mut adapter, _) = adapter_in_v01();
    let rejected = adapter.handle_host_request_at(
        2,
        &request(
            "bad",
            "ui.confirm_v01",
            json!({"matches": true, "generation": 9}),
        ),
    );
    assert!(
        rejected
            .iter()
            .any(|frame| matches!(frame, ChildFrame::Response(response) if !response.ok))
    );

    let rejected = adapter.handle_host_request_at(
        2,
        &request(
            "bad-v",
            "ui.confirm_v01",
            json!({"matches": true, "nested": {"v": 1}}),
        ),
    );
    assert!(
        rejected
            .iter()
            .any(|frame| matches!(frame, ChildFrame::Response(response) if !response.ok))
    );

    let rejected =
        adapter.handle_host_request_at(2, &request("bad2", "ui.start_discovery", json!({})));
    assert!(
        rejected
            .iter()
            .any(|frame| matches!(frame, ChildFrame::Response(response) if !response.ok))
    );

    let accepted = adapter.handle_host_request_at(
        2,
        &request("confirm", "ui.confirm_v01", json!({"matches": true})),
    );
    assert!(
        accepted
            .iter()
            .any(|frame| matches!(frame, ChildFrame::Response(response) if response.ok))
    );
}

#[test]
fn deadline_is_enforced_before_every_host_command_and_replay_does_not_extend_it() {
    let (mut adapter, _) = adapter_in_v01();
    let frames = adapter.handle_host_request_at(
        30_001,
        &request("late", "ui.confirm_v01", json!({"matches": true})),
    );
    assert!(
        frames
            .iter()
            .any(|frame| matches!(frame, ChildFrame::SasDisplay(value) if !value.current))
    );
    assert!(
        frames
            .iter()
            .any(|frame| matches!(frame, ChildFrame::Response(response) if !response.ok))
    );

    let replay = adapter.handle_host_request_at(
        30_002,
        &request("late", "ui.confirm_v01", json!({"matches": true})),
    );
    assert_eq!(frames, replay);
}

#[test]
fn framed_stdio_rejects_malformed_and_oversized_requests_before_dispatch() {
    let mut malformed = Vec::new();
    malformed.extend_from_slice(&3u32.to_be_bytes());
    malformed.extend_from_slice(b"{");
    assert!(run_stdio(&mut malformed.as_slice(), &mut Vec::new()).is_err());

    let mut oversized = Vec::new();
    oversized.extend_from_slice(&((control_api::MAX_FRAME_BYTES + 1) as u32).to_be_bytes());
    assert!(run_stdio(&mut oversized.as_slice(), &mut Vec::new()).is_err());
}
