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
        let mut timeline = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for product child at {label}; timeline={timeline:?}; stderr={}",
                self.stderr.lock().unwrap()
            );
            let frame = self.frames.recv_timeout(remaining).unwrap_or_else(|error| {
                panic!(
                    "product child frame before deadline at {label}: {error:?}; timeline={timeline:?}; stderr={}",
                    self.stderr.lock().unwrap()
                )
            });
            if predicate(&frame) {
                return frame;
            }
            timeline.push((
                frame["kind"].as_str().unwrap_or("unknown").to_owned(),
                frame["snapshot"]["state"]
                    .as_str()
                    .or_else(|| frame["error"].as_str())
                    .unwrap_or("-")
                    .to_owned(),
                frame["ok"].as_bool(),
            ));
            assert!(
                !matches!(
                    frame["snapshot"]["state"].as_str(),
                    Some("rejected" | "cancelled" | "expired" | "remote_outcome_unknown")
                ) && frame["ok"].as_bool() != Some(false),
                "terminal product frame at {label}; timeline={timeline:?}; stderr={}",
                self.stderr.lock().unwrap()
            );
        }
    }

    fn latest_until_quiet(&self, mut latest: Value, predicate: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + Duration::from_millis(250);
        while let Ok(frame) = self
            .frames
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            assert!(
                frame["ok"].as_bool() != Some(false),
                "rejected product frame while selecting latest candidate; error={}",
                frame["error"].as_str().unwrap_or("unknown")
            );
            if frame["kind"] == "ui_snapshot_v1" {
                latest = frame;
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        assert!(
            predicate(&latest),
            "latest product snapshot is no longer selectable"
        );
        latest
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
fn product_two_processes_recover_and_verify_v01_after_durable_pairing() {
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
                && frame["snapshot"]["candidates"].as_array().is_some_and(|v| {
                    v.iter().any(|candidate| {
                        candidate["compatibility"] == "compatible"
                            && candidate["freshness"] == "current"
                    })
                })
        },
    );
    let b_snapshot = b.wait_for(
        Instant::now() + Duration::from_secs(20),
        "b mdns discovery",
        |frame| {
            frame["kind"] == "ui_snapshot_v1"
                && frame["snapshot"]["candidates"].as_array().is_some_and(|v| {
                    v.iter().any(|candidate| {
                        candidate["compatibility"] == "compatible"
                            && candidate["freshness"] == "current"
                    })
                })
        },
    );
    let candidate_snapshot = |frame: &Value| {
        frame["kind"] == "ui_snapshot_v1"
            && frame["snapshot"]["candidates"].as_array().is_some_and(|v| {
                v.iter().any(|candidate| {
                    candidate["compatibility"] == "compatible"
                        && candidate["freshness"] == "current"
                })
            })
    };
    let a_snapshot = a.latest_until_quiet(a_snapshot, candidate_snapshot);
    let b_snapshot = b.latest_until_quiet(b_snapshot, candidate_snapshot);
    let compatible_handle = |frame: &Value| {
        frame["snapshot"]["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| {
                candidate["compatibility"] == "compatible" && candidate["freshness"] == "current"
            })
            .unwrap()["handle"]
            .clone()
    };
    a.send(
        "select-a",
        "ui.select_candidate",
        json!({"handle":compatible_handle(&a_snapshot)}),
    );
    b.send(
        "select-b",
        "ui.select_candidate",
        json!({"handle":compatible_handle(&b_snapshot)}),
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
    let durable = |child: &ProductChild| {
        child.wait_for(
            Instant::now() + Duration::from_secs(15),
            "durable commit",
            |frame| {
                frame["kind"] == "ui_snapshot_v1"
                    && frame["snapshot"]["state"] == "confirmed_relationship"
            },
        )
    };
    let a_terminal = durable(&a);
    let b_terminal = durable(&b);
    for terminal in [&a_terminal, &b_terminal] {
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

    a.send(
        "v01-a",
        "ui.v01.begin",
        json!({"relationship":a_terminal["snapshot"]["confirmed"][0]["handle"]}),
    );
    b.send(
        "v01-b",
        "ui.v01.begin",
        json!({"relationship":b_terminal["snapshot"]["confirmed"][0]["handle"]}),
    );
    let a_v01 = a.wait_for(Instant::now() + Duration::from_secs(20), "a v01", |frame| {
        frame["kind"] == "sas_display_v1" && frame["current"] == true
    });
    let b_v01 = b.wait_for(Instant::now() + Duration::from_secs(20), "b v01", |frame| {
        frame["kind"] == "sas_display_v1" && frame["current"] == true
    });
    assert_eq!(a_v01["code_groups"], b_v01["code_groups"]);
    a.send("confirm-v01-a", "ui.confirm_v01", json!({"matches":true}));
    b.send("confirm-v01-b", "ui.confirm_v01", json!({"matches":true}));
    for child in [&a, &b] {
        child.wait_for(
            Instant::now() + Duration::from_secs(20),
            "verified v01 returns to the durable relationship",
            |frame| {
                frame["kind"] == "ui_snapshot_v1"
                    && frame["snapshot"]["state"] == "confirmed_relationship"
                    && frame["snapshot"]["capabilities"]["input_enabled"] == false
                    && frame["snapshot"]["capabilities"]["clipboard_enabled"] == false
            },
        );
    }
}
