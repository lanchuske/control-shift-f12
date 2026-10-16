use seamless_input::{
    control_api::{self, Request},
    ui_contract::{RemainingDuration, SasCode, V01View},
    ui_stdio_adapter::{
        AuthoritativeUiEvent, ChildFrame, UiStdioAdapter, run_stdio, run_stdio_with_adapter,
    },
};
use serde_json::json;
use std::{io::Read, time::Duration};

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

fn other_v01() -> V01View {
    V01View {
        code: SasCode::try_from(vec!["11".into(), "22".into(), "33".into()]).unwrap(),
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
    assert!(
        replay
            .iter()
            .any(|frame| matches!(frame, ChildFrame::Response(response) if !response.ok))
    );
    assert!(!adapter.has_current_sas());
}

#[test]
fn duplicate_v01_ready_cannot_rebind_replace_or_extend_the_current_sas() {
    let (mut adapter, initial) = adapter_in_v01();
    let initial_binding = initial
        .iter()
        .find_map(|frame| match frame {
            ChildFrame::SasDisplay(frame) if frame.current => Some(frame.attempt_binding),
            _ => None,
        })
        .unwrap();

    let duplicate = adapter.on_authoritative_at(
        2,
        AuthoritativeUiEvent::V01SasReady {
            view: other_v01(),
            remaining_ms: 30_000,
        },
    );
    assert!(
        !duplicate
            .iter()
            .any(|frame| matches!(frame, ChildFrame::SasDisplay(_)))
    );

    let expired = adapter.poll_at(30_001);
    assert!(expired.iter().any(|frame| matches!(frame, ChildFrame::SasDisplay(frame) if !frame.current && frame.attempt_binding == initial_binding)));
}

#[test]
fn idle_expiry_and_replay_flush_terminal_invalidation_without_new_host_command() {
    let (mut adapter, _) = adapter_in_v01();
    let before_expiry = request("refresh", "ui.refresh", json!({}));
    adapter.handle_host_request_at(2, &before_expiry);

    let idle = adapter.poll_at(30_001);
    assert!(
        idle.iter()
            .any(|frame| matches!(frame, ChildFrame::SasDisplay(frame) if !frame.current))
    );

    let (mut adapter, _) = adapter_in_v01();
    adapter.handle_host_request_at(2, &before_expiry);
    let replay = adapter.handle_host_request_at(30_001, &before_expiry);
    assert!(
        replay
            .iter()
            .any(|frame| matches!(frame, ChildFrame::SasDisplay(frame) if !frame.current))
    );
}

#[test]
fn backward_clock_cannot_extend_a_sas_deadline() {
    let (mut adapter, _) = adapter_in_v01();
    assert!(adapter.poll_at(0).is_empty());
    let expired = adapter.poll_at(30_001);
    assert!(
        expired
            .iter()
            .any(|frame| matches!(frame, ChildFrame::SasDisplay(frame) if !frame.current))
    );
}

#[test]
fn framed_stdio_rejects_malformed_and_oversized_requests_before_dispatch() {
    let mut malformed = Vec::new();
    malformed.extend_from_slice(&3u32.to_be_bytes());
    malformed.extend_from_slice(b"{");
    assert!(run_stdio(std::io::Cursor::new(malformed), &mut Vec::new()).is_err());

    let mut oversized = Vec::new();
    oversized.extend_from_slice(&((control_api::MAX_FRAME_BYTES + 1) as u32).to_be_bytes());
    assert!(run_stdio(std::io::Cursor::new(oversized), &mut Vec::new()).is_err());
}

#[derive(Default)]
struct DelayedEof {
    waited: bool,
}

impl Read for DelayedEof {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        if !self.waited {
            self.waited = true;
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(0)
    }
}

#[test]
fn stdio_poll_emits_terminal_sas_invalidation_while_host_is_idle() {
    let mut adapter = UiStdioAdapter::new(0);
    adapter.on_authoritative_at(0, AuthoritativeUiEvent::RelationshipVerified);
    adapter.on_authoritative_at(
        0,
        AuthoritativeUiEvent::V01SasReady {
            view: v01(),
            remaining_ms: 1,
        },
    );
    let mut output = Vec::new();
    run_stdio_with_adapter(DelayedEof::default(), &mut output, adapter).unwrap();
    assert!(String::from_utf8_lossy(&output).contains("sas_display_v1"));
    assert!(String::from_utf8_lossy(&output).contains("\"current\":false"));
}
