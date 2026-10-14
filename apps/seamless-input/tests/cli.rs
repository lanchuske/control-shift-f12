use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_seamless-input"))
        .args(args)
        .output()
        .expect("CLI process should start")
}

#[test]
fn start_is_a_symmetric_peer_command() {
    let output = run(&["start"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Starting SeamlessInput peer\n"
    );
    assert_eq!(output.stderr, b"");
}

#[test]
fn pair_new_creates_a_pairing_code() {
    let output = run(&["pair", "new"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Creating pairing code\n"
    );
    assert_eq!(output.stderr, b"");
}

#[test]
fn pair_code_joins_the_symmetric_pairing_flow() {
    let output = run(&["pair", "amber-cedar-dawn-field-grove-harbor"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Pairing with code: amber-cedar-dawn-field-grove-harbor\n"
    );
    assert_eq!(output.stderr, b"");
}

#[test]
fn peers_lists_known_peers() {
    let output = run(&["peers"]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "Listing peers\n");
    assert_eq!(output.stderr, b"");
}

#[test]
fn unpair_takes_a_peer_name() {
    let output = run(&["unpair", "office-mac"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Unpairing peer: office-mac\n"
    );
    assert_eq!(output.stderr, b"");
}

#[test]
fn tui_opens_the_topology_interface() {
    let output = run(&["tui"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Opening topology interface\n"
    );
    assert_eq!(output.stderr, b"");
}

#[test]
fn doctor_runs_diagnostics() {
    let output = run(&["doctor"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Running diagnostics\n"
    );
    assert_eq!(output.stderr, b"");
}

#[test]
fn config_show_displays_configuration() {
    let output = run(&["config", "show"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Showing configuration\n"
    );
    assert_eq!(output.stderr, b"");
}

#[test]
fn config_path_displays_configuration_location() {
    let output = run(&["config", "path"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Configuration path\n"
    );
    assert_eq!(output.stderr, b"");
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
