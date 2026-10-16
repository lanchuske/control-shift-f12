use std::{
    io::{BufRead, BufReader, Read},
    process::{Command, Stdio},
    sync::{
        Mutex, MutexGuard, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

static TEST_HOME_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn pairing_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_seamless-input"))
        .args(args)
        .env("SEAMLESS_INPUT_HOME", test_home())
        .output()
        .expect("CLI process should start")
}

fn test_home() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "seamless-input-cli-{}-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test"),
        TEST_HOME_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

#[test]
fn concurrent_cli_tests_receive_distinct_homes() {
    assert_ne!(test_home(), test_home());
}

fn run_with_sensitive_environment(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_seamless-input"))
        .args(args)
        .env("SEAMLESS_INPUT_HOME", test_home())
        .env("USER", "sensitive-user")
        .env("USERNAME", "sensitive-user")
        .env("COMPUTERNAME", "sensitive-machine")
        .env("HOSTNAME", "sensitive-machine")
        .env("SEAMLESS_INPUT_TEST_CLIPBOARD", "sensitive-clipboard")
        .output()
        .expect("CLI process should start")
}

#[test]
fn pair_new_creates_a_real_redacted_pairing_offer() {
    let _pairing = pairing_lock();
    let home = test_home();
    let mut offer = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_seamless-input"))
            .args(["pair", "new"])
            .env("SEAMLESS_INPUT_HOME", &home)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("pairing offer should start"),
    );
    let mut reader = BufReader::new(offer.0.stdout.take().unwrap());
    let mut stdout = String::new();
    reader.read_line(&mut stdout).unwrap();
    assert!(
        offer.0.try_wait().unwrap().is_none(),
        "pair new must remain pairable while it waits for a peer"
    );
    offer.0.kill().unwrap();
    reader.read_to_string(&mut stdout).unwrap();
    offer.0.wait().unwrap();
    assert!(stdout.contains("Pairing code:"));
    assert_eq!(stdout.split_whitespace().skip(2).take(6).count(), 6);
    assert!(!stdout.contains("not implemented"));
}

#[test]
fn two_cli_processes_pair_and_persist_reciprocal_peers() {
    let _pairing = pairing_lock();
    let offer_home = test_home().join("offer");
    let accept_home = test_home().join("accept");
    let mut offer = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_seamless-input"))
            .args(["pair", "new"])
            .env("SEAMLESS_INPUT_HOME", &offer_home)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("pairing offer should start"),
    );
    let mut reader = BufReader::new(offer.0.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let code = line
        .trim()
        .strip_prefix("Pairing code: ")
        .expect("offer should print a pairing code")
        .to_owned();
    line.clear();
    reader.read_line(&mut line).unwrap();
    let address = line
        .trim()
        .strip_prefix("Pairing address: ")
        .expect("offer should print a manual fallback address")
        .to_owned();

    let accept = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
        .arg("pair")
        .arg(&code)
        .arg("--address")
        .arg(&address)
        .env("SEAMLESS_INPUT_HOME", &accept_home)
        .output()
        .expect("pairing acceptor should finish");
    assert!(
        accept.status.success(),
        "accept stderr: {}",
        String::from_utf8_lossy(&accept.stderr)
    );
    assert!(!String::from_utf8_lossy(&accept.stdout).contains(&code));

    let status = offer.0.wait().unwrap();
    assert!(
        status.success(),
        "offer process should finish after one pairing"
    );

    for home in [&offer_home, &accept_home] {
        let peers = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
            .arg("peers")
            .env("SEAMLESS_INPUT_HOME", home)
            .output()
            .unwrap();
        assert!(peers.status.success());
        assert!(
            String::from_utf8_lossy(&peers.stdout).contains("Paired peers: 1"),
            "{}",
            String::from_utf8_lossy(&peers.stdout)
        );
    }
}

#[test]
fn wrong_code_fails_both_cli_processes_without_persisting_peers() {
    let _pairing = pairing_lock();
    let offer_home = test_home().join("wrong-offer");
    let accept_home = test_home().join("wrong-accept");
    let mut offer = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_seamless-input"))
            .args(["pair", "new"])
            .env("SEAMLESS_INPUT_HOME", &offer_home)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut reader = BufReader::new(offer.0.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let offered = line.trim().strip_prefix("Pairing code: ").unwrap();
    let mut words: Vec<_> = offered.split_whitespace().collect();
    words[0] = if words[0] == "abandon" {
        "ability"
    } else {
        "abandon"
    };
    let wrong_code = words.join(" ");
    line.clear();
    reader.read_line(&mut line).unwrap();
    let address = line
        .trim()
        .strip_prefix("Pairing address: ")
        .expect("offer should print a manual fallback address")
        .to_owned();

    let started = Instant::now();
    let accept = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
        .arg("pair")
        .arg(&wrong_code)
        .arg("--address")
        .arg(&address)
        .env("SEAMLESS_INPUT_HOME", &accept_home)
        .output()
        .unwrap();
    let server = offer.0.wait().unwrap();
    assert!(!accept.status.success());
    assert!(!server.success());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "wrong-code rejection must be bounded"
    );

    for home in [&offer_home, &accept_home] {
        let peers = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
            .arg("peers")
            .env("SEAMLESS_INPUT_HOME", home)
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&peers.stdout).contains("Paired peers: 0"));
    }
}

#[test]
fn start_bootstraps_the_real_supervisor_and_stays_running() {
    let home = test_home();
    let mut child = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
        .arg("start")
        .env("SEAMLESS_INPUT_HOME", &home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline
        && (!home.join("config.toml").is_file()
            || !home.join("identity").join("identity.json").is_file())
    {
        assert!(
            child.try_wait().unwrap().is_none(),
            "start exited before supervision began"
        );
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        child.try_wait().unwrap().is_none(),
        "start exited before supervision began"
    );
    let status_deadline = Instant::now() + Duration::from_secs(5);
    let live = loop {
        let status = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
            .args(["status", "--pid", &child.id().to_string(), "--machine"])
            .env("SEAMLESS_INPUT_HOME", &home)
            .output()
            .unwrap();
        let snapshot = String::from_utf8(status.stdout).unwrap();
        if snapshot.starts_with("state=running\t") || Instant::now() >= status_deadline {
            break snapshot;
        }
        assert!(child.try_wait().unwrap().is_none());
        thread::sleep(Duration::from_millis(25));
    };
    assert!(live.starts_with("state=running\t"), "{live}");
    assert!(
        live.contains(&format!("\tprocess_id={}\t", child.id())),
        "{live}"
    );

    let foreign = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
        .args(["status", "--pid", "1", "--machine"])
        .env("SEAMLESS_INPUT_HOME", &home)
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(foreign.stdout).unwrap().trim(),
        "state=stopped\tprocess_id=1\tdisplays=0\tauthenticated_sessions=0"
    );
    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(home.join("config.toml").is_file());
    assert!(home.join("identity").join("identity.json").is_file());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("not implemented"));
}

#[test]
fn pair_code_is_validated_without_echoing_the_secret() {
    let _pairing = pairing_lock();
    let code = "abandon abandon abandon abandon abandon abandon";
    let output = run(&["pair", code]);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains(code));
    assert!(!combined.contains("not implemented"));
}

#[test]
fn peers_reads_the_real_pairing_store() {
    let output = run(&["peers"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Paired peers: 0"));
    assert!(!stdout.contains("not implemented"));
}

#[test]
fn unpair_queries_the_real_pairing_store() {
    let output = run(&["unpair", "office-mac"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("paired peer was not found"));
    assert!(!stderr.contains("not implemented"));
}

#[test]
fn doctor_measures_real_local_capabilities() {
    let output = run(&["doctor"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Control Shift F12 doctor"));
    assert!(stdout.contains("administrator elevation: not required"));
    assert!(stdout.contains("input access:"));
    assert!(stdout.contains("displays:"));
    assert!(stdout.contains("discovery:"));
    assert!(!stdout.contains("runtime readiness: NOT MEASURED"));
}

#[test]
fn doctor_report_is_opt_in_redacted_and_stable_identifier_free() {
    let output = run_with_sensitive_environment(&["doctor", "--report"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for forbidden in [
        "clipboard content",
        "private key",
        "username",
        "127.0.0.1",
        "192.168.",
        "machine id",
        "sensitive-user",
        "sensitive-machine",
        "sensitive-clipboard",
    ] {
        assert!(
            !stdout.to_lowercase().contains(forbidden),
            "report leaked {forbidden}: {stdout}"
        );
    }
    assert!(stdout.contains("privacy: redacted"));
    assert!(stdout.contains("platform:"));
    assert!(stdout.contains("permissions:"));
}

#[test]
fn status_fails_closed_when_no_live_runtime_heartbeat_exists() {
    let output = run(&["status", "--pid", "4242"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "Control Shift F12 stopped: 0 authenticated session(s)"
    );
    assert_eq!(output.stderr, b"");
}

#[test]
fn machine_status_is_stable_and_filtered_by_process_id() {
    let output = run(&["status", "--pid", "8123", "--machine"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "state=stopped\tprocess_id=8123\tdisplays=0\tauthenticated_sessions=0"
    );
}

#[test]
fn config_show_loads_the_real_default_configuration() {
    let output = run(&["config", "show"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("version = 1"));
    assert!(!stdout.contains("not implemented"));
}

#[test]
fn config_path_prints_the_selected_user_path() {
    let home = test_home();
    let output = Command::new(env!("CARGO_BIN_EXE_seamless-input"))
        .args(["config", "path"])
        .env("SEAMLESS_INPUT_HOME", &home)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        home.join("config.toml").display().to_string()
    );
}

#[test]
fn version_is_available() {
    let output = run(&["--version"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("seamless-input {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(output.stderr, b"");
}

#[test]
fn server_and_client_roles_are_rejected_as_usage_errors() {
    for role in ["server", "client"] {
        let output = run(&[role]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{role} should be a usage error"
        );
        assert_eq!(output.stdout, b"");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("error: unrecognized subcommand"),
            "unexpected stderr: {stderr}"
        );
        assert!(
            stderr.contains(&format!(
                "Usage: seamless-input{} <COMMAND>",
                std::env::consts::EXE_SUFFIX
            )),
            "unexpected stderr: {stderr}"
        );
    }
}

#[test]
fn missing_required_arguments_exit_with_usage_code() {
    let output = run(&["unpair"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"");
    assert!(String::from_utf8(output.stderr).unwrap().contains("<PEER>"));
}
