use std::{fs, path::PathBuf};

#[test]
fn windows_engine_uses_the_public_product_name_in_version_info() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(manifest_dir.join("Cargo.toml")).unwrap();
    let build_script = fs::read_to_string(manifest_dir.join("build.rs")).unwrap();

    for field in ["ProductName", "FileDescription"] {
        assert!(
            manifest.contains(&format!(r#"{field} = "Control Shift F12""#)),
            "missing {field} Windows VERSIONINFO"
        );
    }
    assert!(!manifest.contains(r#"ProductName = "Seamless Input""#));
    assert!(!manifest.contains(r#"FileDescription = "Seamless Input""#));
    assert!(build_script.contains("CARGO_CFG_TARGET_OS"));
    assert!(build_script.contains("winresource::WindowsResource::new()"));
    assert!(build_script.contains("resource.compile()"));
}
