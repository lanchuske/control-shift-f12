#![cfg(feature = "g4-test-helper")]

use seamless_input::control_api::{self, Request};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};

struct Harness {
    child: Child,
    input: Option<ChildStdin>,
    frames: Receiver<Value>,
    stderr: Arc<Mutex<String>>,
    history: Arc<Mutex<Vec<Value>>>,
}

impl Harness {
    fn start(
        root: &Path,
        local_rendezvous: &str,
        peer_rendezvous: &str,
        bind: &str,
        peer: &str,
    ) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
            .args(["control", "--ui-stdio"])
            .env("SEAMLESS_INPUT_HOME", root)
            .env("CSF12_G4_TEST_LOCAL_RENDEZVOUS", local_rendezvous)
            .env("CSF12_G4_TEST_PEER_RENDEZVOUS", peer_rendezvous)
            .env("CSF12_G4_TEST_BIND", bind)
            .env("CSF12_G4_TEST_PEER_ADDRESS", peer)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = child.stdout.take().unwrap();
        let mut error_output = child.stderr.take().unwrap();
        let stderr = Arc::new(Mutex::new(String::new()));
        let captured_stderr = stderr.clone();
        thread::spawn(move || {
            for line in BufReader::new(&mut error_output)
                .lines()
                .map_while(Result::ok)
            {
                let mut captured = captured_stderr.lock().unwrap();
                captured.push_str(&line);
                captured.push('\n');
            }
        });
        let (sender, frames) = mpsc::sync_channel(64);
        let history = Arc::new(Mutex::new(Vec::new()));
        let captured_history = history.clone();
        thread::spawn(move || {
            loop {
                let mut prefix = [0; 4];
                if output.read_exact(&mut prefix).is_err() {
                    break;
                }
                let length = u32::from_be_bytes(prefix) as usize;
                if !(1..=control_api::MAX_FRAME_BYTES).contains(&length) {
                    break;
                }
                let mut body = vec![0; length];
                if output.read_exact(&mut body).is_err() {
                    break;
                }
                let Ok(frame) = serde_json::from_slice::<Value>(&body) else {
                    break;
                };
                if let Ok(mut observed) = captured_history.lock() {
                    observed.push(frame.clone());
                    if observed.len() > 64 {
                        observed.remove(0);
                    }
                }
                if sender.send(frame).is_err() {
                    break;
                }
            }
        });
        let input = child.stdin.take();
        Self {
            child,
            input,
            frames,
            stderr,
            history,
        }
    }

    fn send(&mut self, id: &str, command: &str, args: Value) {
        let request = Request {
            v: 1,
            id: id.into(),
            command: command.into(),
            args,
        };
        control_api::write_message(self.input.as_mut().unwrap(), &request).unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
    }

    fn wait_for(
        &self,
        deadline: Instant,
        label: &str,
        predicate: impl Fn(&Value) -> bool,
    ) -> Value {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for child projection"
            );
            let frame = self.frames.recv_timeout(remaining).unwrap_or_else(|error| {
                panic!(
                    "child frame before deadline at {label}: {error:?}; history={:?}; stderr={}",
                    self.history.lock().unwrap(),
                    self.stderr.lock().unwrap(),
                )
            });
            if predicate(&frame) {
                return frame;
            }
        }
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "child did not exit before bounded deadline"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.input.take();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn helper_two_processes_transport_match_and_reopen_same_stores() {
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let a_reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let b_reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let a_port = a_reservation.local_addr().unwrap().port();
    let b_port = b_reservation.local_addr().unwrap().port();
    assert_ne!(a_port, b_port);
    let a_address = format!("127.0.0.1:{a_port}");
    let b_address = format!("127.0.0.1:{b_port}");
    let a_rendezvous = "11111111111111111111111111111111";
    let b_rendezvous = "22222222222222222222222222222222";
    drop(a_reservation);
    drop(b_reservation);
    let mut a = Harness::start(
        a_root.path(),
        a_rendezvous,
        b_rendezvous,
        &a_address,
        &b_address,
    );
    let mut b = Harness::start(
        b_root.path(),
        b_rendezvous,
        a_rendezvous,
        &b_address,
        &a_address,
    );
    a.send("start-a", "ui.start_discovery", json!({}));
    b.send("start-b", "ui.start_discovery", json!({}));
    let a_snapshot = a.wait_for(
        Instant::now() + Duration::from_secs(20),
        "a discovery",
        |frame| {
            frame["kind"] == "ui_snapshot_v1"
                && frame["snapshot"]["candidates"]
                    .as_array()
                    .is_some_and(|v| v.len() == 1)
        },
    );
    let b_snapshot = b.wait_for(
        Instant::now() + Duration::from_secs(20),
        "b discovery",
        |frame| {
            frame["kind"] == "ui_snapshot_v1"
                && frame["snapshot"]["candidates"]
                    .as_array()
                    .is_some_and(|v| v.len() == 1)
        },
    );
    let a_handle = a_snapshot["snapshot"]["candidates"][0]["handle"]
        .as_str()
        .unwrap();
    let b_handle = b_snapshot["snapshot"]["candidates"][0]["handle"]
        .as_str()
        .unwrap();
    a.send(
        "select-a",
        "ui.select_candidate",
        json!({"handle":a_handle}),
    );
    b.send(
        "select-b",
        "ui.select_candidate",
        json!({"handle":b_handle}),
    );

    let a_pairing = a.wait_for(Instant::now() + Duration::from_secs(15), "a sas", |frame| {
        frame["kind"] == "ui_pairing_v1"
    });
    let b_pairing = b.wait_for(Instant::now() + Duration::from_secs(15), "b sas", |frame| {
        frame["kind"] == "ui_pairing_v1"
    });
    assert_eq!(
        a_pairing["verification_words"],
        b_pairing["verification_words"]
    );
    assert_eq!(a_pairing["verification_words"].as_array().unwrap().len(), 4);
    a.send(
        "match-a",
        "ui.approve_sas",
        json!({"generation":a_pairing["generation"],"matches":true}),
    );
    b.send(
        "match-b",
        "ui.approve_sas",
        json!({"generation":b_pairing["generation"],"matches":true}),
    );

    let mut durable_handles = Vec::new();
    for harness in [&a, &b] {
        let terminal = harness.wait_for(
            Instant::now() + Duration::from_secs(15),
            "durable commit",
            |frame| {
                frame["kind"] == "ui_snapshot_v1"
                    && frame["snapshot"]["state"] == "confirmed_relationship"
            },
        );
        assert_eq!(
            terminal["snapshot"]["confirmed"].as_array().unwrap().len(),
            1
        );
        durable_handles.push(
            terminal["snapshot"]["confirmed"][0]["handle"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
        assert_eq!(terminal["snapshot"]["confirmed"][0]["state"], "unavailable");
        assert_eq!(terminal["snapshot"]["capabilities"]["input_enabled"], false);
        assert_eq!(
            terminal["snapshot"]["capabilities"]["clipboard_enabled"],
            false
        );
        assert_eq!(terminal["snapshot"]["layout"]["state"], "not_configured");
    }

    drop(a.input.take());
    drop(b.input.take());
    assert!(a.wait_for_exit(Duration::from_secs(2)).success());
    assert!(b.wait_for_exit(Duration::from_secs(2)).success());

    let reopened_a = Harness::start(
        a_root.path(),
        a_rendezvous,
        b_rendezvous,
        &a_address,
        &b_address,
    );
    let reopened_b = Harness::start(
        b_root.path(),
        b_rendezvous,
        a_rendezvous,
        &b_address,
        &a_address,
    );
    for (harness, expected_handle) in [
        (&reopened_a, &durable_handles[0]),
        (&reopened_b, &durable_handles[1]),
    ] {
        let restored = harness.wait_for(
            Instant::now() + Duration::from_secs(5),
            "durable reopen",
            |frame| {
                frame["kind"] == "ui_snapshot_v1"
                    && frame["snapshot"]["state"] == "confirmed_relationship"
            },
        );
        assert_eq!(
            restored["snapshot"]["confirmed"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            restored["snapshot"]["confirmed"][0]["handle"],
            expected_handle.as_str()
        );
        assert_eq!(restored["snapshot"]["confirmed"][0]["state"], "unavailable");
        assert_eq!(restored["snapshot"]["capabilities"]["input_enabled"], false);
        assert_eq!(
            restored["snapshot"]["capabilities"]["clipboard_enabled"],
            false
        );
        assert_eq!(restored["snapshot"]["layout"]["state"], "not_configured");
    }
}

#[test]
fn helper_stop_then_start_isolates_the_new_generation() {
    let root = tempfile::tempdir().unwrap();
    let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer_reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap().to_string();
    let peer = peer_reservation.local_addr().unwrap().to_string();
    drop(reservation);
    drop(peer_reservation);
    let mut child = Harness::start(
        root.path(),
        "33333333333333333333333333333333",
        "44444444444444444444444444444444",
        &address,
        &peer,
    );
    child.send("start-1", "ui.start_discovery", json!({}));
    child.wait_for(
        Instant::now() + Duration::from_secs(5),
        "first discovery",
        |frame| {
            frame["kind"] == "ui_snapshot_v1"
                && frame["snapshot"]["candidates"]
                    .as_array()
                    .is_some_and(|v| v.len() == 1)
        },
    );
    child.send("stop", "ui.stop_discovery", json!({}));
    child.wait_for(Instant::now() + Duration::from_secs(5), "stop", |frame| {
        frame["kind"] == "ui_snapshot_v1" && frame["snapshot"]["state"] == "not_started"
    });
    child.send("start-2", "ui.start_discovery", json!({}));
    child.wait_for(
        Instant::now() + Duration::from_secs(5),
        "second discovery",
        |frame| {
            frame["kind"] == "ui_snapshot_v1"
                && frame["snapshot"]["candidates"]
                    .as_array()
                    .is_some_and(|v| v.len() == 1)
        },
    );
    std::thread::sleep(Duration::from_millis(100));
    child.send("refresh", "ui.refresh", json!({}));
    let current = child.wait_for(
        Instant::now() + Duration::from_secs(5),
        "post-restart refresh",
        |frame| frame["kind"] == "ui_snapshot_v1",
    );
    assert_eq!(current["snapshot"]["state"], "browsing");
}

#[test]
fn helper_either_rendezvous_order_can_select_unilaterally() {
    for (a_rendezvous, b_rendezvous) in [
        (
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "11111111111111111111111111111111",
        ),
        (
            "11111111111111111111111111111111",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        ),
    ] {
        let a_root = tempfile::tempdir().unwrap();
        let b_root = tempfile::tempdir().unwrap();
        let a_reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let b_reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let a_address = a_reservation.local_addr().unwrap().to_string();
        let b_address = b_reservation.local_addr().unwrap().to_string();
        drop(a_reservation);
        drop(b_reservation);
        let mut a = Harness::start(
            a_root.path(),
            a_rendezvous,
            b_rendezvous,
            &a_address,
            &b_address,
        );
        let mut b = Harness::start(
            b_root.path(),
            b_rendezvous,
            a_rendezvous,
            &b_address,
            &a_address,
        );
        a.send("start-a", "ui.start_discovery", json!({}));
        b.send("start-b", "ui.start_discovery", json!({}));
        let a_snapshot = a.wait_for(
            Instant::now() + Duration::from_secs(10),
            "unilateral discovery",
            |frame| {
                frame["kind"] == "ui_snapshot_v1"
                    && frame["snapshot"]["candidates"]
                        .as_array()
                        .is_some_and(|value| value.len() == 1)
            },
        );
        a.send(
            "select-a",
            "ui.select_candidate",
            json!({"handle":a_snapshot["snapshot"]["candidates"][0]["handle"]}),
        );

        let a_pairing = a.wait_for(
            Instant::now() + Duration::from_secs(15),
            "unilateral selector sas",
            |frame| frame["kind"] == "ui_pairing_v1",
        );
        let b_pairing = b.wait_for(
            Instant::now() + Duration::from_secs(15),
            "unilateral receiver sas",
            |frame| frame["kind"] == "ui_pairing_v1",
        );
        assert_eq!(
            a_pairing["verification_words"],
            b_pairing["verification_words"]
        );
        a.send(
            "mismatch-a",
            "ui.approve_sas",
            json!({"generation":a_pairing["generation"],"matches":false}),
        );
        b.send(
            "mismatch-b",
            "ui.approve_sas",
            json!({"generation":b_pairing["generation"],"matches":false}),
        );
        for child in [&a, &b] {
            child.wait_for(
                Instant::now() + Duration::from_secs(10),
                "unilateral mismatch",
                |frame| {
                    frame["kind"] == "ui_snapshot_v1" && frame["snapshot"]["state"] == "not_started"
                },
            );
        }
    }
}
