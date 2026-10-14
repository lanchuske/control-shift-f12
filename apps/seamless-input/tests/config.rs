use std::{fs, path::Path};

use seamless_input::config::{ConfigError, ConfigStore, ConfigV1, PeerConfig, Placement};
use seamless_input::supervisor::topology_from_config;
use seamless_input_core::{DisplayId, NodeId, platform::LogicalDisplay};

fn sample() -> ConfigV1 {
    ConfigV1 {
        version: 1,
        peers: vec![PeerConfig {
            node_id: "00112233445566778899aabbccddeeff".into(),
            name: "Office PC".into(),
            displays: vec!["display-0".into()],
        }],
        placements: vec![Placement {
            display: "00112233445566778899aabbccddeeff:0".into(),
            x: 1,
            y: 0,
        }],
    }
}

#[test]
fn saves_and_loads_config_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.toml");
    let store = ConfigStore::new(path.clone()).unwrap();
    store.save(&sample()).unwrap();
    assert_eq!(store.load().unwrap(), sample());
    assert!(!temp.path().join("config.toml.tmp").exists());
}

#[test]
fn rejects_paths_outside_the_current_users_config_root() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("user-config");
    fs::create_dir_all(&root).unwrap();
    assert!(ConfigStore::within_user_root(root.join("seamless-input/config.toml"), &root).is_ok());
    assert!(matches!(
        ConfigStore::within_user_root(temp.path().join("elsewhere/config.toml"), &root),
        Err(ConfigError::OutsideUserConfig)
    ));
}

#[test]
fn rejects_unknown_config_versions() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.toml");
    fs::write(&path, "version = 2\npeers = []\nplacements = []\n").unwrap();
    assert_eq!(
        ConfigStore::new(path).unwrap().load(),
        Err(ConfigError::UnsupportedVersion(2))
    );
}

#[test]
fn failed_replacement_preserves_previous_config() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.toml");
    let store = ConfigStore::new(path.clone()).unwrap();
    store.save(&sample()).unwrap();
    let old = fs::read_to_string(&path).unwrap();
    store.write_temp_for_test("not valid toml").unwrap();
    assert!(store.commit_temp_for_test().is_err());
    assert_eq!(fs::read_to_string(path).unwrap(), old);
}

#[test]
fn serialized_config_never_contains_private_key_material() {
    let encoded = toml::to_string(&sample()).unwrap();
    for forbidden in ["private_key", "secret_key", "certificate_key", "seed"] {
        assert!(!encoded.to_ascii_lowercase().contains(forbidden));
    }
}

#[cfg(unix)]
#[test]
fn config_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.toml");
    let store = ConfigStore::new(path.clone()).unwrap();
    store.save(&sample()).unwrap();
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn reload_reports_only_real_changes_and_keeps_last_good_config() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.toml");
    let store = ConfigStore::new(path.clone()).unwrap();
    store.save(&sample()).unwrap();
    let mut reload = store.live_reload().unwrap();
    assert!(reload.poll().unwrap().is_none());
    let mut changed = sample();
    changed.placements[0].x = -1;
    store.save(&changed).unwrap();
    assert_eq!(reload.poll().unwrap(), Some(changed.clone()));
    fs::write(&path, "version = 999\n").unwrap();
    assert!(reload.poll().is_err());
    assert_eq!(reload.current(), &changed);
}

#[test]
fn default_path_is_below_a_user_owned_root() {
    let path = ConfigStore::default_path().unwrap();
    assert!(path.ends_with(Path::new("seamless-input").join("config.toml")));
    assert!(!path.starts_with("/etc"));
    assert!(!path.starts_with("/usr"));
}

#[test]
fn persisted_tui_placements_build_the_runtime_topology() {
    let local = NodeId([1; 16]);
    let remote = NodeId([2; 16]);
    let config = ConfigV1 {
        version: 1,
        peers: vec![
            PeerConfig {
                node_id: hex(local),
                name: "This Mac".into(),
                displays: vec!["0".into()],
            },
            PeerConfig {
                node_id: hex(remote),
                name: "Office PC".into(),
                displays: vec!["0".into()],
            },
        ],
        placements: vec![
            Placement {
                display: format!("{}:0", hex(local)),
                x: 0,
                y: 0,
            },
            Placement {
                display: format!("{}:0", hex(remote)),
                x: 1,
                y: 0,
            },
        ],
    };
    let local_displays = vec![LogicalDisplay {
        index: 0,
        origin_x: 0.0,
        origin_y: 0.0,
        width: 1920.0,
        height: 1080.0,
        scale: 2.0,
    }];

    let topology = topology_from_config(local, &local_displays, &config).unwrap();
    assert_eq!(
        topology.neighbor(
            DisplayId {
                node: local,
                index: 0
            },
            seamless_input_core::Edge::Right
        ),
        Some(DisplayId {
            node: remote,
            index: 0
        })
    );
}

fn hex(node: NodeId) -> String {
    node.0.iter().map(|byte| format!("{byte:02x}")).collect()
}
