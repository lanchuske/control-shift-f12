#![cfg(feature = "pairing-v2-experimental")]
use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
};
fn exchange(requests: Vec<Value>) -> Vec<Value> {
    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
        .args(["control", "--stdio"])
        .env("SEAMLESS_INPUT_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for request in requests {
        let body = serde_json::to_vec(&request).unwrap();
        stdin.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
        stdin.write_all(&body).unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let entries: Vec<_> = std::fs::read_dir(home.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    #[cfg(unix)]
    {
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from("setup-control")],
            "only control ownership lock is allowed"
        );
        let locks: Vec<_> = std::fs::read_dir(home.path().join("setup-control"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(locks, vec![std::ffi::OsString::from("writer.lock")]);
    }
    #[cfg(not(unix))]
    assert!(entries.is_empty(), "no product/trust mutation");
    let mut remaining = output.stdout.as_slice();
    let mut result = Vec::new();
    while !remaining.is_empty() {
        let n = u32::from_be_bytes(remaining[..4].try_into().unwrap()) as usize;
        result.push(serde_json::from_slice(&remaining[4..4 + n]).unwrap());
        remaining = &remaining[4 + n..];
    }
    result
}
fn request(id: &str, args: Value) -> Value {
    json!({"v":1,"id":id,"command":"pairing.v2","args":args})
}
#[test]
fn frozen_closed_snapshot_is_typed_and_request_replay_has_no_new_event() {
    let r = request("s", json!({"action":"snapshot"}));
    let messages = exchange(vec![r.clone(), r]);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0], messages[1]);
    assert_eq!(messages[0]["ok"], true);
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/guided-snapshot.json")).unwrap();
    assert_eq!(messages[0]["result"], fixture);
}
#[test]
fn invalid_args_confirmation_and_stale_selection_are_redacted_and_never_fallback() {
    let messages = exchange(vec![
        request("bad", json!({"action":"snapshot","secret":"do-not-echo"})),
        request("confirm", json!({"action":"compare_match"})),
        request(
            "stale",
            json!({"action":"select","handle":{"scope":"11111111111111111111111111111111","window":1,"sequence":1}}),
        ),
        request("legacy", json!({"action":"legacy_start"})),
    ]);
    for (message, code) in messages.iter().zip([
        "invalid_arguments",
        "invalid_state",
        "stale_candidate",
        "invalid_arguments",
    ]) {
        assert_eq!(message["ok"], false);
        assert_eq!(message["error"]["code"], code);
        assert!(!message.to_string().contains("do-not-echo"));
    }
    assert_eq!(messages.len(), 4);
}
#[test]
fn cancel_emits_one_typed_event_and_changed_request_id_cannot_reopen() {
    let r = request("c", json!({"action":"cancel"}));
    let messages = exchange(vec![
        r.clone(),
        r,
        request("c", json!({"action":"open_discovery"})),
    ]);
    assert_eq!(messages.len(), 4);
    assert_eq!(messages[0], messages[2]);
    assert_eq!(messages[1]["event"], "PairingV2Changed");
    assert_eq!(messages[3]["error"]["code"], "request_id_conflict");
}
