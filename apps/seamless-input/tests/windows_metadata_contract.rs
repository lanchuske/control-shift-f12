use std::{fs, path::PathBuf};

fn require_exactly_once(source: &str, contract: &str) {
    assert_eq!(
        source.matches(contract).count(),
        1,
        "expected exactly one occurrence of {contract:?}"
    );
}

#[test]
fn windows_engine_uses_the_public_product_name_in_version_info() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(manifest_dir.join("Cargo.toml")).unwrap();
    let build_script = fs::read_to_string(manifest_dir.join("build.rs")).unwrap();
    let workspace_manifest = fs::read_to_string(manifest_dir.join("../../Cargo.toml")).unwrap();

    for contract in [
        r#"ProductName = "Control Shift F12""#,
        r#"FileDescription = "Control Shift F12""#,
        r#"OriginalFilename = "seamless-input.exe""#,
    ] {
        require_exactly_once(&manifest, contract);
    }
    for contract in [
        r#".set("ProductName", "Control Shift F12")"#,
        r#".set("FileDescription", "Control Shift F12")"#,
        r#".set("OriginalFilename", "seamless-input.exe")"#,
        r#".set("ProductVersion", version)"#,
        r#".set("FileVersion", version)"#,
    ] {
        require_exactly_once(&build_script, contract);
    }
    require_exactly_once(&build_script, r#"let version = env!("CARGO_PKG_VERSION");"#);
    require_exactly_once(&workspace_manifest, r#"version = "0.1.1""#);
    assert!(manifest.contains("version.workspace = true"));
    assert!(!manifest.contains("Seamless Input"));
    assert!(!build_script.contains("Seamless Input"));
    require_exactly_once(&build_script, "CARGO_CFG_TARGET_OS");
    require_exactly_once(&build_script, "winresource::WindowsResource::new()");
    require_exactly_once(&build_script, "resource.compile()");
}
