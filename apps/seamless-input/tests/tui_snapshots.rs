use seamless_input::config::{ConfigStore, ConfigV1, PeerConfig};
use seamless_input::tui::{DisplayTile, PeerState, TuiModel, render_to_string, run_scripted};

fn tile(peer: &str, display: u32, x: i32, y: i32, state: PeerState) -> DisplayTile {
    DisplayTile {
        peer: peer.into(),
        display,
        x,
        y,
        state,
    }
}

fn models() -> Vec<(&'static str, TuiModel)> {
    vec![
        ("zero_peers", TuiModel::default()),
        (
            "unpaired_discovery",
            TuiModel::with_available("Nearby Mac", PeerState::Unpaired),
        ),
        (
            "horizontal",
            TuiModel::with_tiles(vec![
                tile("This Mac", 0, 0, 0, PeerState::Online),
                tile("Office PC", 0, 1, 0, PeerState::Online),
            ]),
        ),
        (
            "vertical",
            TuiModel::with_tiles(vec![
                tile("This Mac", 0, 0, 0, PeerState::Online),
                tile("Office PC", 0, 0, 1, PeerState::Online),
            ]),
        ),
        (
            "four_sided",
            TuiModel::with_tiles(vec![
                tile("Local", 0, 0, 0, PeerState::Online),
                tile("Left", 0, -1, 0, PeerState::Online),
                tile("Right", 0, 1, 0, PeerState::Online),
                tile("Above", 0, 0, -1, PeerState::Online),
                tile("Below", 0, 0, 1, PeerState::Online),
            ]),
        ),
        (
            "multi_display",
            TuiModel::with_tiles(vec![
                tile("Mac", 0, 0, 0, PeerState::Online),
                tile("Mac", 1, 1, 0, PeerState::Online),
                tile("PC", 0, 2, 0, PeerState::Online),
            ]),
        ),
        (
            "offline",
            TuiModel::with_tiles(vec![
                tile("This Mac", 0, 0, 0, PeerState::Online),
                tile("Office PC", 0, 1, 0, PeerState::Offline),
            ]),
        ),
        (
            "collision_error",
            TuiModel::with_error("That position is already occupied"),
        ),
    ]
}

#[test]
fn required_states_have_stable_snapshots_at_both_terminal_sizes() {
    for (name, model) in models() {
        for (width, height) in [(80, 24), (120, 40)] {
            insta::assert_snapshot!(
                format!("{name}_{width}x{height}"),
                render_to_string(&model, width, height)
            );
        }
    }
}

#[test]
fn keys_drive_cardinal_placement_save_delete_and_quit() {
    use seamless_input::tui::{EditorAction, EditorKey};
    let mut model = TuiModel::with_tiles(vec![tile("Local", 0, 0, 0, PeerState::Online)]);
    model
        .available
        .push(tile("Peer", 0, 0, 0, PeerState::Paired));
    assert_eq!(model.handle(EditorKey::Right), EditorAction::Changed);
    assert_eq!((model.available[0].x, model.available[0].y), (1, 0));
    assert_eq!(model.handle(EditorKey::Enter), EditorAction::Changed);
    assert_eq!(model.tiles.len(), 2);
    assert_eq!(model.handle(EditorKey::Save), EditorAction::Save);
    assert_eq!(model.handle(EditorKey::Delete), EditorAction::Changed);
    assert_eq!(model.handle(EditorKey::Quit), EditorAction::Quit);
}

#[test]
fn collision_is_rejected_without_mutating_the_canvas() {
    use seamless_input::tui::{EditorAction, EditorKey};
    let mut model = TuiModel::with_tiles(vec![
        tile("Local", 0, 0, 0, PeerState::Online),
        tile("Right", 0, 1, 0, PeerState::Online),
    ]);
    model
        .available
        .push(tile("New", 0, 0, 0, PeerState::Paired));
    assert_eq!(model.handle(EditorKey::Right), EditorAction::Changed);
    assert_eq!(model.handle(EditorKey::Enter), EditorAction::Rejected);
    assert_eq!(model.tiles.len(), 2);
    assert!(model.error.as_deref().unwrap().contains("occupied"));
}

#[test]
fn diagonal_only_placement_is_rejected_by_the_core_topology_rules() {
    use seamless_input::tui::{EditorAction, EditorKey};
    let mut model = TuiModel::with_tiles(vec![tile("Local", 0, 0, 0, PeerState::Online)]);
    model
        .available
        .push(tile("New", 0, 0, 0, PeerState::Paired));
    assert_eq!(model.handle(EditorKey::Right), EditorAction::Changed);
    assert_eq!(model.handle(EditorKey::Down), EditorAction::Changed);
    assert_eq!(model.handle(EditorKey::Enter), EditorAction::Rejected);
    assert_eq!(model.tiles.len(), 1);
    assert!(model.error.as_deref().unwrap().contains("cardinal"));
}

#[test]
fn scripted_editor_saves_topology_through_the_real_config_store() {
    use seamless_input::tui::EditorKey;

    let temp = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(temp.path().join("config.toml")).unwrap();
    store
        .save(&ConfigV1 {
            peers: vec![PeerConfig {
                node_id: "00112233445566778899aabbccddeeff".into(),
                name: "office-windows".into(),
                displays: vec!["0".into()],
            }],
            ..ConfigV1::default()
        })
        .unwrap();

    run_scripted(
        &store,
        [EditorKey::Right, EditorKey::Enter, EditorKey::Save],
    )
    .unwrap();

    let saved = store.load().unwrap();
    assert_eq!(saved.placements.len(), 1);
    assert_eq!(
        saved.placements[0].display,
        "00112233445566778899aabbccddeeff:0"
    );
    assert_eq!((saved.placements[0].x, saved.placements[0].y), (1, 0));
}
