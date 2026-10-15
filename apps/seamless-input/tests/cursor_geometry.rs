use seamless_input::cursor::{CursorContinuity, bounded_edge_crossing};
use seamless_input::cursor::{logical_to_physical, physical_to_logical};
use seamless_input_core::platform::LogicalDisplay;
use seamless_input_core::{Display, DisplayId, Edge, NodeId, Point, Topology};

fn display(node: u8, index: u32, origin: (f64, f64), size: (f64, f64), scale: f64) -> Display {
    Display {
        id: DisplayId {
            node: NodeId([node; 16]),
            index,
        },
        origin: Point {
            x: origin.0,
            y: origin.1,
        },
        width: size.0,
        height: size.1,
        scale,
    }
}

#[test]
fn windows_physical_capture_maps_through_the_matching_monitor_scale() {
    let displays = vec![
        LogicalDisplay {
            index: 0,
            origin_x: 0.0,
            origin_y: 0.0,
            width: 1920.0,
            height: 1080.0,
            scale: 1.0,
        },
        LogicalDisplay {
            index: 1,
            origin_x: 1536.0,
            origin_y: -80.0,
            width: 1706.6666666667,
            height: 960.0,
            scale: 1.5,
        },
    ];
    assert_eq!(
        physical_to_logical(
            Point {
                x: 2880.0,
                y: 300.0
            },
            &displays
        ),
        Some(Point {
            x: 1920.0,
            y: 200.0
        })
    );
    assert_eq!(
        logical_to_physical(
            Point {
                x: 1920.0,
                y: 200.0
            },
            &displays
        ),
        Some(Point {
            x: 2880.0,
            y: 300.0
        })
    );
}

#[test]
fn native_absolute_capture_becomes_continuous_remote_logical_motion_and_returns() {
    let local = display(1, 0, (0.0, 0.0), (1728.0, 1117.0), 2.0);
    let remote = display(2, 0, (-1920.0, 0.0), (1920.0, 1080.0), 1.0);
    let mut cursor = CursorContinuity::new(local.id);

    assert_eq!(
        cursor.observe(
            Point {
                x: 1727.0,
                y: 558.5
            },
            &local
        ),
        Point {
            x: 1727.0,
            y: 558.5
        }
    );
    cursor.warp(
        remote.id,
        Point {
            x: -1920.0,
            y: 540.0,
        },
    );

    assert_eq!(
        cursor.observe(
            Point {
                x: 1717.0,
                y: 568.5
            },
            &remote
        ),
        Point {
            x: -1930.0,
            y: 550.0
        }
    );
    cursor.warp(
        local.id,
        Point {
            x: 1727.0,
            y: 568.5,
        },
    );
    assert_eq!(
        cursor.observe(
            Point {
                x: 1716.0,
                y: 569.5
            },
            &local
        ),
        Point {
            x: 1716.0,
            y: 569.5
        }
    );
}

#[test]
fn independent_remote_monitors_keep_their_own_origins_and_scales() {
    let local = display(1, 0, (0.0, 0.0), (1440.0, 900.0), 2.0);
    let remote_second = display(2, 1, (2560.0, -200.0), (1280.0, 1024.0), 1.25);
    let mut cursor = CursorContinuity::new(local.id);
    cursor.observe(
        Point {
            x: 1439.0,
            y: 450.0,
        },
        &local,
    );
    cursor.warp(
        remote_second.id,
        Point {
            x: 2560.0,
            y: 312.0,
        },
    );
    assert_eq!(
        cursor.observe(
            Point {
                x: 1434.0,
                y: 446.0
            },
            &remote_second
        ),
        Point {
            x: 2555.0,
            y: 308.0
        }
    );
}

#[test]
fn every_monitor_owned_by_the_local_peer_uses_native_absolute_coordinates() {
    let local_primary = display(1, 0, (0.0, 0.0), (1440.0, 900.0), 2.0);
    let local_second = display(1, 1, (-1920.0, 0.0), (1920.0, 1080.0), 1.0);
    let mut cursor = CursorContinuity::new(local_primary.id);
    cursor.observe(Point { x: 100.0, y: 100.0 }, &local_primary);
    cursor.warp(local_second.id, Point { x: -1.0, y: 400.0 });
    assert_eq!(
        cursor.observe(Point { x: -20.0, y: 410.0 }, &local_second),
        Point { x: -20.0, y: 410.0 }
    );
}

#[test]
fn configured_edge_cross_and_return_preserve_continuity_across_unequal_displays() {
    let local = display(1, 0, (0.0, 0.0), (1512.0, 982.0), 2.0);
    let remote = display(2, 0, (-2560.0, 120.0), (2560.0, 1440.0), 1.25);
    let mut topology = Topology::new(local.clone()).unwrap();
    topology
        .place(local.id, Edge::Left, remote.clone())
        .unwrap();
    let mut cursor = CursorContinuity::new(local.id);
    cursor.observe(Point { x: 0.0, y: 491.0 }, &local);
    let (remote_id, remote_entry) = topology
        .map_crossing(local.id, Edge::Left, Point { x: 0.0, y: 491.0 })
        .unwrap()
        .unwrap();
    cursor.warp(remote_id, remote_entry);

    let remote_motion = cursor.observe(Point { x: 8.0, y: 491.0 }, &remote);
    let (local_id, local_entry) = topology
        .map_crossing(remote.id, Edge::Right, remote_motion)
        .unwrap()
        .unwrap();
    cursor.warp(local_id, local_entry);
    assert_eq!(local_id, local.id);
    assert!(local_entry.x >= 0.0 && local_entry.x < local.width);
    assert!((local_entry.y - 491.0).abs() < 1.0);
}

#[test]
fn bounded_native_right_and_bottom_pixels_reach_the_configured_edges() {
    let display = display(1, 0, (0.0, 0.0), (1512.0, 982.0), 2.0);

    assert_eq!(
        bounded_edge_crossing(
            &display,
            Point {
                x: 1511.5,
                y: 400.0
            }
        ),
        Some((
            Edge::Right,
            Point {
                x: 1512.0,
                y: 400.0
            }
        ))
    );
    assert_eq!(
        bounded_edge_crossing(&display, Point { x: 800.0, y: 981.5 }),
        Some((Edge::Bottom, Point { x: 800.0, y: 982.0 }))
    );
}

#[test]
fn recentering_native_cursor_preserves_sustained_remote_relative_motion() {
    let local = display(1, 0, (0.0, 0.0), (1512.0, 982.0), 2.0);
    let remote = display(2, 0, (1512.0, 0.0), (2560.0, 1440.0), 1.25);
    let mut cursor = CursorContinuity::new(local.id);
    cursor.observe(
        Point {
            x: 1511.5,
            y: 491.0,
        },
        &local,
    );
    cursor.warp(
        remote.id,
        Point {
            x: 1512.0,
            y: 720.0,
        },
    );

    let center = Point { x: 756.0, y: 491.0 };
    cursor.recenter_native(center);
    assert_eq!(
        cursor.observe(Point { x: 768.0, y: 487.0 }, &remote),
        Point {
            x: 1524.0,
            y: 716.0
        }
    );
    cursor.recenter_native(center);
    assert_eq!(
        cursor.observe(Point { x: 768.0, y: 487.0 }, &remote),
        Point {
            x: 1536.0,
            y: 712.0
        }
    );
}

#[test]
fn unequal_dpi_displays_can_cross_and_return_on_every_edge() {
    for edge in [Edge::Left, Edge::Right, Edge::Top, Edge::Bottom] {
        let local = display(1, 0, (0.0, 0.0), (1512.0, 982.0), 2.0);
        let remote = display(2, 0, (0.0, 0.0), (2560.0, 1440.0), 1.25);
        let mut topology = Topology::new(local.clone()).unwrap();
        topology.place(local.id, edge, remote.clone()).unwrap();
        let source = match edge {
            Edge::Left => Point { x: 0.0, y: 491.0 },
            Edge::Right => Point {
                x: 1512.0,
                y: 491.0,
            },
            Edge::Top => Point { x: 756.0, y: 0.0 },
            Edge::Bottom => Point { x: 756.0, y: 982.0 },
        };
        let (remote_id, remote_entry) = topology
            .map_crossing(local.id, edge, source)
            .unwrap()
            .unwrap();
        let remote_exit = match edge.opposite() {
            Edge::Left => Point {
                x: remote.origin.x,
                y: remote_entry.y,
            },
            Edge::Right => Point {
                x: remote.origin.x + remote.width,
                y: remote_entry.y,
            },
            Edge::Top => Point {
                x: remote_entry.x,
                y: remote.origin.y,
            },
            Edge::Bottom => Point {
                x: remote_entry.x,
                y: remote.origin.y + remote.height,
            },
        };
        let (local_id, local_entry) = topology
            .map_crossing(remote_id, edge.opposite(), remote_exit)
            .unwrap()
            .unwrap();
        assert_eq!(local_id, local.id);
        assert!(local_entry.x >= local.origin.x);
        assert!(local_entry.x <= local.origin.x + local.width);
        assert!(local_entry.y >= local.origin.y);
        assert!(local_entry.y <= local.origin.y + local.height);
    }
}
