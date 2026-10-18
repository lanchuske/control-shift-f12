use seamless_input::control_api::{self, Request};
use serde_json::json;
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn read_child_frame(reader: &mut impl Read) -> serde_json::Value {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix).expect("child frame length");
    let length = u32::from_be_bytes(prefix) as usize;
    assert!(
        (1..=control_api::MAX_FRAME_BYTES).contains(&length),
        "child emitted a bounded frame"
    );
    let mut body = vec![0; length];
    reader.read_exact(&mut body).expect("child frame body");
    serde_json::from_slice(&body).expect("child frame JSON")
}

fn refresh() -> Request {
    Request {
        v: 1,
        id: "ui-refresh".into(),
        command: "ui.refresh".into(),
        args: json!({}),
    }
}

#[test]
fn ui_stdio_child_exits_when_stdout_closes_while_stdin_is_held_open() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
        .args(["control", "--ui-stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ui stdio child should start");
    thread::sleep(Duration::from_millis(20));
    assert!(
        child.try_wait().expect("check startup").is_none(),
        "ui stdio mode must be running before stdout is closed"
    );
    let mut stdin = child.stdin.take().expect("child stdin");
    drop(child.stdout.take());

    control_api::write_message(&mut stdin, &refresh()).expect("send refresh");
    stdin.flush().expect("keep stdin open after refresh");

    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(status) = child.try_wait().expect("read child status") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "child did not exit after stdout closed"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert!(
        !status.success(),
        "broken stdout is a terminal child failure"
    );
    drop(stdin);
}

#[test]
fn ui_stdio_child_projects_refresh_without_changing_foundations_control() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
        .args(["control", "--ui-stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ui stdio child should start");
    let mut stdin = child.stdin.take().expect("child stdin");
    let mut stdout = child.stdout.take().expect("child stdout");

    control_api::write_message(&mut stdin, &refresh()).expect("send refresh");
    let first = read_child_frame(&mut stdout);
    assert_eq!(first["kind"], "ui_snapshot_v1");

    drop(stdin);
    let status = child.wait().expect("wait for eof child");
    assert!(status.success(), "stderr: {:?}", child.stderr.take());
}

#[test]
fn ui_stdio_child_rejects_oversized_inherited_frames() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
        .args(["control", "--ui-stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ui stdio child should start");
    let mut stdin = child.stdin.take().expect("child stdin");
    stdin
        .write_all(&((control_api::MAX_FRAME_BYTES as u32 + 1).to_be_bytes()))
        .expect("write oversized frame length");
    stdin.flush().expect("flush oversized frame length");
    drop(stdin);

    let status = child.wait().expect("wait for invalid-frame child");
    assert!(!status.success(), "oversized frames must be terminal");
}

#[test]
fn ui_stdio_child_rejects_duplicate_arguments_without_projection_or_argument_echo() {
    for body in [
        r#"{"v":1,"id":"duplicate-handle","command":"ui.select_candidate","args":{"handle":{"address":"192.0.2.4"},"handle":"nearby-1"}}"#,
        r#"{"v":1,"id":"duplicate-generation","command":"ui.approve_sas","args":{"generation":0,"generation":1,"matches":true}}"#,
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
            .args(["control", "--ui-stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("ui stdio child should start");
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
        stdin.write_all(body.as_bytes()).unwrap();
        drop(stdin);
        let output = child.wait_with_output().unwrap();
        assert!(
            !output.status.success(),
            "duplicate arguments must be terminal"
        );
        assert!(
            output.stdout.is_empty(),
            "ambiguous requests must not emit frames"
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stderr.contains("192.0.2.4"));
        assert!(!stderr.contains("nearby-1"));
        assert!(!stderr.contains("generation"));
    }
}
