use std::{
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

static TEST_HOME_SEQUENCE: AtomicU64 = AtomicU64::new(1);

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
    let output = run(&["pair", "new"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Pairing code:"));
    assert_eq!(stdout.split_whitespace().skip(2).take(6).count(), 6);
    assert!(!stdout.contains("not implemented"));
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
    thread::sleep(Duration::from_millis(700));
    assert!(
        child.try_wait().unwrap().is_none(),
        "start exited before supervision began"
    );
    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(home.join("config.toml").is_file());
    assert!(home.join("identity").join("identity.json").is_file());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("not implemented"));
}

#[test]
fn pair_code_is_validated_without_echoing_the_secret() {
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
    assert!(stdout.contains("SeamlessInput doctor"));
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
        "seamless-input 0.1.0\n"
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
            stderr.contains("Usage: seamless-input <COMMAND>"),
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
