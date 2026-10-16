//! Real child-process contract: no native input, network, or pairing is required.
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
};

fn exchange(input: &[u8]) -> std::process::Output {
    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
        .args(["control", "--stdio"])
        .env("SEAMLESS_INPUT_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn frame(body: &str) -> Vec<u8> {
    let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(body.as_bytes());
    bytes
}

fn bodies(bytes: &[u8]) -> Vec<String> {
    let mut remaining = bytes;
    let mut result = Vec::new();
    while !remaining.is_empty() {
        assert!(remaining.len() >= 4, "unframed stdout");
        let len = u32::from_be_bytes(remaining[..4].try_into().unwrap()) as usize;
        assert!(len <= 256 * 1024);
        assert!(remaining.len() >= 4 + len);
        result.push(String::from_utf8(remaining[4..4 + len].to_vec()).unwrap());
        remaining = &remaining[4 + len..];
    }
    result
}

#[test]
fn snapshot_is_framed_and_input_and_clipboard_stay_disabled() {
    let output = exchange(&frame(
        r#"{"v":1,"id":"snapshot-1","command":"snapshot","args":{}}"#,
    ));
    assert!(
        output.status.success(),
        "control failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = bodies(&output.stdout);
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains(r#""id":"snapshot-1""#));
    assert!(messages[0].contains(r#""input_enabled":false"#));
    assert!(messages[0].contains(r#""clipboard_enabled":false"#));
    assert!(messages[0].contains(r#""authenticated_sessions":0"#));
}

#[test]
fn unsafe_commands_never_fall_through_to_legacy_pairing_or_runtime() {
    for command in [
        "pair.request",
        "pair.legacy_start",
        "input.set_enabled",
        "clipboard.set_enabled",
    ] {
        let input = frame(&format!(
            r#"{{"v":1,"id":"blocked","command":"{command}","args":{{"enabled":true}}}}"#
        ));
        let output = exchange(&input);
        assert!(output.status.success());
        let messages = bodies(&output.stdout);
        assert!(messages[0].contains(r#""code":"not_available_in_foundations""#));
    }
}

#[test]
fn same_request_id_with_changed_payload_is_rejected() {
    let mut input = frame(r#"{"v":1,"id":"same","command":"snapshot","args":{}}"#);
    input.extend(frame(
        r#"{"v":1,"id":"same","command":"shutdown","args":{}}"#,
    ));
    let output = exchange(&input);
    assert!(output.status.success());
    assert!(bodies(&output.stdout)[1].contains(r#""code":"request_id_conflict""#));
}

#[test]
fn oversized_or_truncated_frames_fail_without_unframed_stdout() {
    for bytes in [vec![0, 4, 0, 1], vec![0, 0, 0], vec![0, 0, 0, 10, b'{']] {
        let output = exchange(&bytes);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("control protocol"));
    }
}

#[test]
fn inventory_refresh_is_read_only_and_never_claims_a_paired_session() {
    let output = exchange(&frame(
        r#"{"v":1,"id":"inventory-1","command":"inventory.refresh","args":{}}"#,
    ));
    assert!(output.status.success());
    let message = &bodies(&output.stdout)[0];
    assert!(message.contains(r#""ok":true"#));
    assert!(message.contains(r#""inventory""#));
    assert!(message.contains(r#""input_enabled":false"#));
}

#[test]
fn invalid_versions_and_arguments_are_typed_and_redacted() {
    for (request, code) in [
        (
            r#"{"v":2,"id":"version","command":"snapshot","args":{}}"#,
            "unsupported_version",
        ),
        (
            r#"{"v":1,"id":"args","command":"snapshot","args":{"phrase":"DO_NOT_ECHO"}}"#,
            "invalid_arguments",
        ),
    ] {
        let output = exchange(&frame(request));
        assert!(output.status.success());
        let text = bodies(&output.stdout).join("");
        assert!(text.contains(code));
        assert!(!text.contains("DO_NOT_ECHO"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("DO_NOT_ECHO"));
    }
}

#[test]
fn only_one_control_process_owns_a_user_root_and_exit_releases_it() {
    let home = tempfile::tempdir().unwrap();
    let spawn = || {
        Command::new(env!("CARGO_BIN_EXE_seamless-input"))
            .args(["control", "--stdio"])
            .env("SEAMLESS_INPUT_HOME", home.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let mut first = spawn();
    first
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&frame(
            r#"{"v":1,"id":"ready","command":"snapshot","args":{}}"#,
        ))
        .unwrap();
    let stdout = first.stdout.as_mut().unwrap();
    let mut prefix = [0; 4];
    stdout.read_exact(&mut prefix).unwrap();
    let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
    stdout.read_exact(&mut body).unwrap();
    let mut second = spawn();
    drop(second.stdin.take());
    let result = second.wait_with_output().unwrap();
    drop(first.stdin.take());
    assert!(first.wait().unwrap().success());
    assert!(
        !result.status.success(),
        "second control engine must not acquire the same root"
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains("already running"));
    let mut after = spawn();
    drop(after.stdin.take());
    assert!(after.wait().unwrap().success());
}

#[test]
fn refresh_events_are_sequenced_and_request_replay_does_not_repeat_measurement() {
    let request = frame(r#"{"v":1,"id":"refresh","command":"inventory.refresh","args":{}}"#);
    let mut input = request.clone();
    input.extend(request);
    input.extend(frame(
        r#"{"v":1,"id":"last","command":"snapshot","args":{}}"#,
    ));
    let output = exchange(&input);
    assert!(output.status.success());
    let messages: Vec<serde_json::Value> = bodies(&output.stdout)
        .iter()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(
        messages
            .iter()
            .filter(|v| v["event"] == "InventoryChanged")
            .count(),
        1
    );
    assert_eq!(messages.last().unwrap()["result"]["last_event_seq"], 1);
}

#[test]
fn frozen_control_contract_has_no_implicit_admission_or_permission_success() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/control-foundations-v1.json")).unwrap();
    let output = exchange(&frame(
        r#"{"v":1,"id":"snapshot","command":"snapshot","args":{}}"#,
    ));
    assert!(output.status.success());
    let response: serde_json::Value = serde_json::from_str(&bodies(&output.stdout)[0]).unwrap();
    let mut snapshot = response["result"].clone();
    let object = snapshot.as_object_mut().unwrap();
    assert_eq!(object.remove("engine").unwrap().as_str().unwrap().len(), 32);
    assert_eq!(
        object.remove("build_version").unwrap(),
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(snapshot, fixture["snapshot"]);
    let blocked = exchange(&frame(
        r#"{"v":1,"id":"blocked","command":"pair.legacy_start","args":{}}"#,
    ));
    let response: serde_json::Value = serde_json::from_str(&bodies(&blocked.stdout)[0]).unwrap();
    assert_eq!(response, fixture["unavailable"]);
}
