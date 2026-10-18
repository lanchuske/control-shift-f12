use seamless_input::{
    control_api::{self, Request},
    ui_contract::{RemainingDuration, SasCode, UiError, UiState, V01View},
    ui_stdio_adapter::{
        AuthoritativeUiEvent, ChildFrame, MonotonicClock, PairingFrame, StdioReadEvent,
        TimedRequestReader, UiStdioAdapter, run_stdio_with_adapter,
    },
};
use serde_json::json;
use std::{io::Write, time::Duration};

struct ManualClock {
    readings: std::collections::VecDeque<u64>,
}

impl ManualClock {
    fn new(readings: impl IntoIterator<Item = u64>) -> Self {
        Self {
            readings: readings.into_iter().collect(),
        }
    }
}

impl MonotonicClock for ManualClock {
    fn now_ms(&mut self) -> u64 {
        self.readings.pop_front().unwrap_or(u64::MAX)
    }
}

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
fn select_extra_fields_are_invalid_but_valid_pairing_commands_remain_state_gated() {
    let mut adapter = UiStdioAdapter::new(0);
    let rejected = adapter.handle_host_request_at(
        1,
        &request(
            "select-extra",
            "ui.select_candidate",
            json!({"handle":"nearby-1","address":"192.0.2.4"}),
        ),
    );
    assert!(rejected.iter().any(|frame| matches!(frame,
        ChildFrame::Response(response) if !response.ok && response.error == Some(UiError::InvalidRequest)
    )));

    for (id, command, args) in [
        (
            "select",
            "ui.select_candidate",
            json!({"handle":"nearby-1"}),
        ),
        (
            "approve",
            "ui.approve_sas",
            json!({"generation":1,"matches":true}),
        ),
        (
            "reject",
            "ui.approve_sas",
            json!({"generation":1,"matches":false}),
        ),
        ("cancel", "ui.cancel_pairing", json!({"generation":1})),
    ] {
        let frames = adapter.handle_host_request_at(2, &request(id, command, args));
        assert_eq!(frames.len(), 1, "a schema alone must not change projection");
        assert!(matches!(&frames[0], ChildFrame::Response(response)
            if !response.ok && response.error == Some(UiError::InvalidState)));
    }
}

#[test]
fn pairing_request_fields_are_bounded_strict_and_replays_are_deterministic() {
    let mut adapter = UiStdioAdapter::new(0);
    let invalid = [
        ("ui.select_candidate", json!({})),
        ("ui.select_candidate", json!({"handle":""})),
        ("ui.select_candidate", json!({"handle":"a".repeat(65)})),
        ("ui.select_candidate", json!({"handle":"192.0.2.4"})),
        (
            "ui.select_candidate",
            json!({"handle":{"address":"192.0.2.4"}}),
        ),
        ("ui.select_candidate", json!({"handle":["nearby-1"]})),
        ("ui.approve_sas", json!({"generation":0,"matches":true})),
        ("ui.approve_sas", json!({"generation":-1,"matches":true})),
        ("ui.approve_sas", json!({"generation":1.5,"matches":true})),
        ("ui.approve_sas", json!({"generation":"1","matches":true})),
        ("ui.approve_sas", json!({"generation":1,"matches":"true"})),
        ("ui.approve_sas", json!({"generation":1})),
        ("ui.cancel_pairing", json!({})),
        ("ui.cancel_pairing", json!({"generation":0})),
        ("ui.cancel_pairing", json!({"generation":1,"extra":true})),
    ];
    for (index, (command, args)) in invalid.into_iter().enumerate() {
        let frames =
            adapter.handle_host_request_at(1, &request(&format!("bad-{index}"), command, args));
        assert!(
            matches!(&frames[..], [ChildFrame::Response(response)]
            if !response.ok && response.error == Some(UiError::InvalidRequest)),
            "{frames:?}"
        );
    }
    for field in [
        "address",
        "identity",
        "certificate",
        "sas",
        "capability",
        "layout",
    ] {
        for (command, mut args) in [
            ("ui.select_candidate", json!({"handle":"nearby-1"})),
            ("ui.approve_sas", json!({"generation":1,"matches":true})),
        ] {
            args["nested"] = json!([{field: "private-value"}]);
            let frames = adapter.handle_host_request_at(
                1,
                &request(&format!("nested-{command}-{field}"), command, args),
            );
            assert!(matches!(&frames[..], [ChildFrame::Response(response)]
                if !response.ok && response.error == Some(UiError::InvalidRequest)));
            assert!(
                !serde_json::to_string(&frames)
                    .unwrap()
                    .contains("private-value")
            );
        }
    }
    for (id, command, args) in [
        (
            "select-boundary",
            "ui.select_candidate",
            json!({"handle":"a".repeat(64)}),
        ),
        (
            "approve-boundary",
            "ui.approve_sas",
            json!({"generation":u64::MAX,"matches":true}),
        ),
    ] {
        let valid = request(id, command, args);
        let first = adapter.handle_host_request_at(2, &valid);
        assert!(matches!(&first[..], [ChildFrame::Response(response)]
            if response.error == Some(UiError::InvalidState)));
        assert_eq!(adapter.handle_host_request_at(3, &valid), first);
        let conflict = adapter.handle_host_request_at(4, &request(id, command, json!({})));
        assert!(matches!(&conflict[..], [ChildFrame::Response(response)]
            if response.error == Some(UiError::RequestIdConflict)));
    }
}

#[test]
fn host_command_arguments_are_objects_never_positional_arrays() {
    let mut adapter = UiStdioAdapter::new(0);
    for (index, (command, args)) in [
        ("ui.refresh", json!([])),
        ("ui.start_discovery", json!([])),
        ("ui.stop_discovery", json!([])),
        ("ui.select_candidate", json!(["nearby-1"])),
        ("ui.approve_sas", json!([1, true])),
        ("ui.confirm_v01", json!([true])),
    ]
    .into_iter()
    .enumerate()
    {
        let frames =
            adapter.handle_host_request_at(1, &request(&format!("array-{index}"), command, args));
        assert!(
            matches!(&frames[..], [ChildFrame::Response(response)]
            if !response.ok && response.error == Some(UiError::InvalidRequest)),
            "{frames:?}"
        );
    }
}

fn pairing_projection() -> serde_json::Value {
    json!({
        "v":1,
        "kind":"ui_pairing_v1",
        "generation":1,
        "phase":"awaiting_local_confirmation",
        "candidate_handle":"nearby-1",
        "verification_words":["abandon","ability","able","about"]
    })
}

#[test]
fn pairing_projection_is_exact_bounded_and_separate_from_v01() {
    let expected = pairing_projection();
    let pairing: PairingFrame = serde_json::from_value(expected.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(ChildFrame::Pairing(pairing)).unwrap(),
        expected
    );

    for (field, value) in [
        ("v", json!(2)),
        ("kind", json!("sas_display_v1")),
        ("generation", json!(0)),
        ("generation", json!(-1)),
        ("generation", json!("1")),
        ("phase", json!("admitted")),
        ("phase", json!({"awaiting_local_confirmation":null})),
        ("candidate_handle", json!("")),
        ("candidate_handle", json!("a".repeat(65))),
        ("candidate_handle", json!("192.0.2.4")),
        ("verification_words", json!(["abandon", "ability", "able"])),
        (
            "verification_words",
            json!(["abandon", "ability", "able", "about", "above"]),
        ),
        (
            "verification_words",
            json!(["Abandon", "ability", "able", "about"]),
        ),
        (
            "verification_words",
            json!(["", "ability", "able", "about"]),
        ),
        (
            "verification_words",
            json!(["a".repeat(17), "ability", "able", "about"]),
        ),
        (
            "verification_words",
            json!([{"address":"192.0.2.4"},"ability","able","about"]),
        ),
    ] {
        let mut invalid = expected.clone();
        invalid[field] = value;
        assert!(
            serde_json::from_value::<PairingFrame>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
    for field in [
        "address",
        "identity",
        "certificate",
        "sas",
        "capability",
        "layout",
        "attempt_binding",
        "transcript",
    ] {
        let mut invalid = expected.clone();
        invalid[field] = json!({"nested":"private-value"});
        assert!(serde_json::from_value::<PairingFrame>(invalid).is_err());
    }
    for field in [
        "v",
        "kind",
        "generation",
        "phase",
        "candidate_handle",
        "verification_words",
    ] {
        let mut invalid = expected.clone();
        invalid.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<PairingFrame>(invalid).is_err());
    }
}

#[test]
fn pairing_schema_cannot_change_browsing_v01_or_the_redacted_snapshot() {
    let mut browsing = UiStdioAdapter::new(0);
    browsing.handle_host_request_at(1, &request("start", "ui.start_discovery", json!({})));
    let (v01, _) = adapter_in_v01();
    for mut adapter in [browsing, v01] {
        let before = adapter.handle_host_request_at(2, &request("before", "ui.refresh", json!({})));
        let before = before
            .into_iter()
            .find_map(|frame| match frame {
                ChildFrame::Snapshot(frame) => Some(frame.snapshot),
                _ => None,
            })
            .unwrap();
        for (id, command, args) in [
            (
                "select",
                "ui.select_candidate",
                json!({"handle":"nearby-1"}),
            ),
            (
                "approve",
                "ui.approve_sas",
                json!({"generation":1,"matches":true}),
            ),
        ] {
            let frames = adapter.handle_host_request_at(3, &request(id, command, args));
            assert!(matches!(&frames[..], [ChildFrame::Response(response)]
                if response.error == Some(UiError::InvalidState)));
        }
        let after = adapter.handle_host_request_at(4, &request("after", "ui.refresh", json!({})));
        let mut after = after
            .into_iter()
            .find_map(|frame| match frame {
                ChildFrame::Snapshot(frame) => Some(frame.snapshot),
                _ => None,
            })
            .unwrap();
        after.generation = before.generation;
        assert_eq!(after, before);
        assert_eq!(
            adapter.has_current_sas(),
            before.state == UiState::V01Pending
        );
    }
}

#[test]
fn snapshot_and_response_frames_have_only_the_frozen_redacted_fields() {
    let mut adapter = UiStdioAdapter::new(0);
    let frames = adapter.handle_host_request_at(1, &request("refresh", "ui.refresh", json!({})));
    let snapshot = frames
        .iter()
        .find(|frame| matches!(frame, ChildFrame::Snapshot(_)))
        .unwrap();
    assert_eq!(
        serde_json::to_value(snapshot).unwrap(),
        json!({
            "v":1,"kind":"ui_snapshot_v1","snapshot":{
                "schema_version":1,"generation":1,"state":"not_started",
                "diagnostics":[],"candidates":[],"confirmed":[],"inventory":null,
                "layout":{"state":"not_configured"},
                "capabilities":{"input_enabled":false,"clipboard_enabled":false}
            }
        })
    );
    assert_eq!(
        serde_json::to_value(frames.last().unwrap()).unwrap(),
        json!({
            "v":1,"kind":"ui_response_v1","id":"refresh","ok":true
        })
    );
    let rejected = adapter.handle_host_request_at(
        2,
        &request(
            "select",
            "ui.select_candidate",
            json!({"handle":"nearby-1"}),
        ),
    );
    assert_eq!(
        serde_json::to_value(&rejected).unwrap(),
        json!([{
            "v":1,"kind":"ui_response_v1","id":"select","ok":false,"error":"invalid_state"
        }])
    );
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
fn host_accepts_only_empty_discovery_actions_or_boolean_confirm_and_rejects_sas_reexports() {
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

    let rejected = adapter.handle_host_request_at(
        2,
        &request(
            "bad2",
            "ui.start_discovery",
            json!({"address": "192.0.2.1"}),
        ),
    );
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
fn empty_discovery_actions_only_transition_the_local_browsing_projection() {
    let mut adapter = UiStdioAdapter::new(0);

    let started =
        adapter.handle_host_request_at(1, &request("start", "ui.start_discovery", json!({})));
    assert!(
        started
            .iter()
            .any(|frame| matches!(frame, ChildFrame::Response(response) if response.ok))
    );
    assert!(started.iter().any(|frame| {
        matches!(frame, ChildFrame::Snapshot(snapshot) if snapshot.snapshot.state == UiState::Browsing)
    }));

    let stopped =
        adapter.handle_host_request_at(2, &request("stop", "ui.stop_discovery", json!({})));
    assert!(
        stopped
            .iter()
            .any(|frame| matches!(frame, ChildFrame::Response(response) if response.ok))
    );
    assert!(stopped.iter().any(|frame| {
        matches!(frame, ChildFrame::Snapshot(snapshot) if snapshot.snapshot.state == UiState::NotStarted)
    }));
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
    assert!(control_api::read_request(&mut malformed.as_slice()).is_err());

    let mut oversized = Vec::new();
    oversized.extend_from_slice(&((control_api::MAX_FRAME_BYTES + 1) as u32).to_be_bytes());
    assert!(control_api::read_request(&mut oversized.as_slice()).is_err());
}

fn assert_duplicate_args_rejected(command: &str, args: &str) {
    let body = format!(r#"{{"v":1,"id":"duplicate","command":"{command}","args":{args}}}"#);
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body.as_bytes());
    let result = control_api::read_request(&mut frame.as_slice());
    assert!(
        result.is_err(),
        "duplicate wire arguments reached Request: {result:?}"
    );
    let error = result.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "control protocol: invalid frame");
}

#[test]
fn raw_pairing_frames_reject_duplicate_handle_in_either_order() {
    for args in [
        r#"{"handle":{"address":"192.0.2.4"},"handle":"nearby-1"}"#,
        r#"{"handle":"nearby-1","handle":{"address":"192.0.2.4"}}"#,
        r#"{"handle":"nearby-1","handle":"nearby-1"}"#,
        r#"{"handle":"nearby-1","\u0068andle":"nearby-1"}"#,
    ] {
        assert_duplicate_args_rejected("ui.select_candidate", args);
    }
}

#[test]
fn raw_pairing_frames_reject_duplicate_generation_in_either_order() {
    for args in [
        r#"{"generation":0,"generation":1,"matches":true}"#,
        r#"{"generation":1,"generation":0,"matches":true}"#,
        r#"{"generation":1,"generation":1,"matches":true}"#,
    ] {
        assert_duplicate_args_rejected("ui.approve_sas", args);
    }
}

#[test]
fn raw_pairing_frames_reject_duplicate_matches_and_nested_members() {
    for (command, args) in [
        (
            "ui.approve_sas",
            r#"{"generation":1,"matches":false,"matches":true}"#,
        ),
        (
            "ui.approve_sas",
            r#"{"generation":1,"matches":true,"matches":false}"#,
        ),
        (
            "ui.confirm_v01",
            r#"{"matches":{"certificate":"private-value"},"matches":true}"#,
        ),
        (
            "ui.confirm_v01",
            r#"{"matches":true,"matches":{"certificate":"private-value"}}"#,
        ),
        (
            "ui.select_candidate",
            r#"{"handle":{"nested":[{"address":"first","address":"second"}]}}"#,
        ),
    ] {
        assert_duplicate_args_rejected(command, args);
    }
}

#[test]
fn framed_unique_arguments_preserve_json_values_and_independent_nested_keys() {
    let body = br#"{"v":1,"id":"unique","command":"ui.refresh","args":{"values":[null,true,false,-1,1,1.5,"hello",{"same":1},{"same":2}],"maximum":18446744073709551615}}"#;
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    let decoded = control_api::read_request(&mut frame.as_slice())
        .unwrap()
        .unwrap();
    assert_eq!(
        decoded.args,
        json!({
            "values":[null,true,false,-1,1,1.5,"hello",{"same":1},{"same":2}],
            "maximum":u64::MAX
        })
    );
}

#[derive(Default)]
struct DelayedEof {
    waited: bool,
    cancelled: bool,
}

impl TimedRequestReader for DelayedEof {
    fn receive_until(&mut self, _timeout: Duration) -> std::io::Result<StdioReadEvent> {
        if !self.waited {
            self.waited = true;
            std::thread::sleep(Duration::from_millis(20));
            return Ok(StdioReadEvent::Timeout);
        }
        Ok(StdioReadEvent::Eof)
    }

    fn cancel(&mut self) {
        self.cancelled = true;
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
    run_stdio_with_adapter(
        &mut DelayedEof::default(),
        &mut output,
        adapter,
        &mut ManualClock::new([20]),
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&output).contains("sas_display_v1"));
    assert!(String::from_utf8_lossy(&output).contains("\"current\":false"));
}

struct DelayedRequest {
    request: Option<Request>,
    cancelled: bool,
}

struct ScriptedReader {
    events: std::collections::VecDeque<StdioReadEvent>,
    cancelled: bool,
}

impl ScriptedReader {
    fn new(events: impl IntoIterator<Item = StdioReadEvent>) -> Self {
        Self {
            events: events.into_iter().collect(),
            cancelled: false,
        }
    }
}

impl TimedRequestReader for ScriptedReader {
    fn receive_until(&mut self, _timeout: Duration) -> std::io::Result<StdioReadEvent> {
        Ok(self.events.pop_front().unwrap_or(StdioReadEvent::Eof))
    }

    fn cancel(&mut self) {
        self.cancelled = true;
    }
}

impl TimedRequestReader for DelayedRequest {
    fn receive_until(&mut self, _timeout: Duration) -> std::io::Result<StdioReadEvent> {
        if let Some(request) = self.request.take() {
            std::thread::sleep(Duration::from_millis(20));
            Ok(StdioReadEvent::Request(request))
        } else {
            Ok(StdioReadEvent::Eof)
        }
    }

    fn cancel(&mut self) {
        self.cancelled = true;
    }
}

#[test]
fn delayed_request_is_measured_after_receive_and_cannot_confirm_an_expired_sas() {
    let mut adapter = UiStdioAdapter::new(0);
    adapter.on_authoritative_at(0, AuthoritativeUiEvent::RelationshipVerified);
    adapter.on_authoritative_at(
        0,
        AuthoritativeUiEvent::V01SasReady {
            view: v01(),
            remaining_ms: 1,
        },
    );
    let mut reader = DelayedRequest {
        request: Some(request("late", "ui.confirm_v01", json!({"matches": true}))),
        cancelled: false,
    };
    let mut output = Vec::new();
    run_stdio_with_adapter(
        &mut reader,
        &mut output,
        adapter,
        &mut ManualClock::new([20]),
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&output).contains("\"current\":false"));
    assert!(String::from_utf8_lossy(&output).contains("invalid_state"));
    assert!(!reader.cancelled);
}

#[derive(Default)]
struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("closed"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_failure_cancels_the_owned_reader_before_returning() {
    let mut adapter = UiStdioAdapter::new(0);
    adapter.on_authoritative_at(0, AuthoritativeUiEvent::RelationshipVerified);
    adapter.on_authoritative_at(
        0,
        AuthoritativeUiEvent::V01SasReady {
            view: v01(),
            remaining_ms: 1,
        },
    );
    let mut reader = DelayedEof::default();
    let mut writer = FailingWriter;
    assert!(
        run_stdio_with_adapter(
            &mut reader,
            &mut writer,
            adapter,
            &mut ManualClock::new([20])
        )
        .is_err()
    );
    assert!(reader.cancelled);
}

#[test]
fn late_runner_uses_the_admission_epoch_and_repeated_requests_cannot_extend_sas() {
    let mut adapter = UiStdioAdapter::new(0);
    adapter.on_authoritative_at(0, AuthoritativeUiEvent::RelationshipVerified);
    adapter.on_authoritative_at(
        0,
        AuthoritativeUiEvent::V01SasReady {
            view: v01(),
            remaining_ms: 30_000,
        },
    );
    let first = request("late-one", "ui.confirm_v01", json!({"matches": true}));
    let second = request("late-two", "ui.confirm_v01", json!({"matches": true}));
    let mut reader = ScriptedReader::new([
        StdioReadEvent::Request(first),
        StdioReadEvent::Request(second),
        StdioReadEvent::Eof,
    ]);
    let mut output = Vec::new();
    run_stdio_with_adapter(
        &mut reader,
        &mut output,
        adapter,
        &mut ManualClock::new([30_001, 30_002]),
    )
    .unwrap();
    let output = String::from_utf8_lossy(&output);
    assert_eq!(output.matches("\"current\":false").count(), 1);
    assert_eq!(output.matches("invalid_state").count(), 2);
}
