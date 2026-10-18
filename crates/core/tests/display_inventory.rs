use seamless_input_core::{
    display_inventory::{DisplayInventory, InventoryError},
    platform::LogicalDisplay,
};

fn observed(index: u32, width: f64, scale: f64) -> LogicalDisplay {
    LogicalDisplay {
        index,
        origin_x: 0.0,
        origin_y: 0.0,
        width,
        height: 1080.0,
        scale,
    }
}

#[test]
fn unavailable_display_name_is_not_presented_as_a_measurement() {
    let inventory = DisplayInventory::from_logical(1, vec![observed(7, 1920.0, 2.0)]).unwrap();
    let json = serde_json::to_value(inventory).unwrap();
    assert_eq!(json["displays"][0]["name"], serde_json::Value::Null);
    assert_eq!(json["displays"][0]["name_provenance"], "unavailable");
}

#[test]
fn inventory_preserves_logical_measurements_without_inventing_physical_metadata() {
    let inventory = DisplayInventory::from_logical(1, vec![observed(7, 1920.0, 2.0)]).unwrap();
    let display = &inventory.displays()[0];
    assert_eq!(display.runtime_index, 7);
    assert_eq!(display.logical_bounds.width, 1920.0);
    assert_eq!(display.backing_scale.x, 2.0);
    assert!(display.physical_mm.is_none());
    assert!(display.rotation_degrees.is_none());
    assert!(display.framebuffer_pixels.is_none());
    assert!(display.stable_display_id.is_none());
    assert!(!inventory.is_layout_ready());
}

#[test]
fn invalid_geometry_duplicates_and_unbounded_inventory_are_rejected() {
    for value in [f64::NAN, f64::INFINITY, 0.0, -1.0, 1e30] {
        assert!(DisplayInventory::from_logical(1, vec![observed(0, value, 1.0)]).is_err());
    }
    assert_eq!(
        DisplayInventory::from_logical(1, vec![observed(0, 1920.0, 1.0), observed(0, 1920.0, 1.0)])
            .unwrap_err(),
        InventoryError::DuplicateDisplay
    );
    assert!(
        DisplayInventory::from_logical(1, (0..33).map(|i| observed(i, 1920.0, 1.0)).collect())
            .is_err()
    );
    assert!(DisplayInventory::from_logical(1, vec![observed(0, 1920.0, 0.0)]).is_err());
}

#[test]
fn digest_is_order_independent_and_binds_actual_geometry() {
    let a =
        DisplayInventory::from_logical(1, vec![observed(1, 1920.0, 1.0), observed(2, 1280.0, 2.0)])
            .unwrap();
    let b =
        DisplayInventory::from_logical(8, vec![observed(2, 1280.0, 2.0), observed(1, 1920.0, 1.0)])
            .unwrap();
    let changed =
        DisplayInventory::from_logical(1, vec![observed(1, 1920.0, 1.5), observed(2, 1280.0, 2.0)])
            .unwrap();
    assert_eq!(a.digest(), b.digest());
    assert_ne!(a.digest(), changed.digest());
}

#[test]
fn frozen_inventory_fixture_preserves_unknowns_and_change_digest() {
    let inventory = DisplayInventory::from_logical(1, vec![observed(7, 1920.0, 2.0)]).unwrap();
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/display-inventory-v1.json")).unwrap();
    assert_eq!(serde_json::to_value(inventory).unwrap(), expected);
}
