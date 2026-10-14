use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_seamless-input"))
        .args(args)
        .output()
        .expect("CLI process should start")
}

fn assert_not_implemented(output: &std::process::Output, command: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!("error: {command} is not implemented yet\n")
    );
}

#[test]
fn start_routes_to_a_not_implemented_operational_error() {
    assert_not_implemented(&run(&["start"]), "start");
}

#[test]
fn pair_new_routes_to_a_not_implemented_operational_error() {
    assert_not_implemented(&run(&["pair", "new"]), "pair");
}

#[test]
fn pair_code_is_never_echoed_when_pairing_is_not_implemented() {
    let code = "amber-cedar-dawn-field-grove-harbor";
    let output = run(&["pair", code]);
    assert_not_implemented(&output, "pair");
    assert!(!String::from_utf8(output.stdout).unwrap().contains(code));
}

#[test]
fn peers_routes_to_a_not_implemented_operational_error() {
    assert_not_implemented(&run(&["peers"]), "peers");
}

#[test]
fn unpair_routes_to_a_not_implemented_operational_error() {
    assert_not_implemented(&run(&["unpair", "office-mac"]), "unpair");
}

#[test]
fn tui_routes_to_a_not_implemented_operational_error() {
    assert_not_implemented(&run(&["tui"]), "tui");
}

#[test]
fn doctor_routes_to_a_not_implemented_operational_error() {
    assert_not_implemented(&run(&["doctor"]), "doctor");
}

#[test]
fn config_show_routes_to_a_not_implemented_operational_error() {
    assert_not_implemented(&run(&["config", "show"]), "config show");
}

#[test]
fn config_path_routes_to_a_not_implemented_operational_error() {
    assert_not_implemented(&run(&["config", "path"]), "config path");
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
