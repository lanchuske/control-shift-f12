#![cfg(all(feature = "pairing-v2-g4", not(feature = "g4-test-helper")))]

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

struct ProductChild {
    child: Child,
    input: Option<ChildStdin>,
    frames: Receiver<Value>,
    stderr: Arc<Mutex<String>>,
}

impl ProductChild {
    fn start(root: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
            .args(["control", "--ui-stdio"])
            .env("SEAMLESS_INPUT_HOME", root)
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
                let Ok(frame) = serde_json::from_slice(&body) else {
                    break;
                };
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
                "timed out waiting for product child; stderr={}",
                self.stderr.lock().unwrap()
            );
            let frame = self.frames.recv_timeout(remaining).unwrap_or_else(|error| {
                panic!(
                    "product child frame before deadline at {label}: {error:?}; stderr={}",
                    self.stderr.lock().unwrap()
                )
            });
            if predicate(&frame) {
                return frame;
            }
        }
    }
}

impl Drop for ProductChild {
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
fn product_two_processes_discover_by_mdns_match_and_persist_non_operationally() {
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let mut a = ProductChild::start(a_root.path());
    let mut b = ProductChild::start(b_root.path());
    a.send("start-a", "ui.start_discovery", json!({}));
    b.send("start-b", "ui.start_discovery", json!({}));
    let a_snapshot = a.wait_for(
        Instant::now() + Duration::from_secs(20),
        "a mdns discovery",
        |frame| {
            frame["kind"] == "ui_snapshot_v1"
                && frame["snapshot"]["candidates"]
                    .as_array()
                    .is_some_and(|v| v.len() == 1)
        },
    );
    let b_snapshot = b.wait_for(
        Instant::now() + Duration::from_secs(20),
        "b mdns discovery",
        |frame| {
            frame["kind"] == "ui_snapshot_v1"
                && frame["snapshot"]["candidates"]
                    .as_array()
                    .is_some_and(|v| v.len() == 1)
        },
    );
    a.send(
        "select-a",
        "ui.select_candidate",
        json!({"handle":a_snapshot["snapshot"]["candidates"][0]["handle"]}),
    );
    b.send(
        "select-b",
        "ui.select_candidate",
        json!({"handle":b_snapshot["snapshot"]["candidates"][0]["handle"]}),
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
    for child in [&a, &b] {
        let terminal = child.wait_for(
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
        assert_eq!(terminal["snapshot"]["confirmed"][0]["state"], "unavailable");
        assert_eq!(terminal["snapshot"]["capabilities"]["input_enabled"], false);
        assert_eq!(
            terminal["snapshot"]["capabilities"]["clipboard_enabled"],
            false
        );
        assert_eq!(terminal["snapshot"]["layout"]["state"], "not_configured");
    }
}
