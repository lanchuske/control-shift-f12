use proptest::prelude::*;
use seamless_input_core::*;

fn display(n: u8, index: u32, width: f64, height: f64, scale: f64) -> Display {
    Display {
        id: DisplayId {
            node: NodeId([n; 16]),
            index,
        },
        origin: Point { x: 0.0, y: 0.0 },
        width,
        height,
        scale,
    }
}

#[test]
fn all_cardinal_placements_are_reciprocal() {
    let root = display(1, 0, 100.0, 200.0, 1.0);
    let mut topology = Topology::new(root.clone()).unwrap();
    for (n, edge, position) in [
        (2, Edge::Left, (-1, 0)),
        (3, Edge::Right, (1, 0)),
        (4, Edge::Top, (0, -1)),
        (5, Edge::Bottom, (0, 1)),
    ] {
        let peer = display(n, 0, 100.0, 100.0, 1.0);
        topology.place(root.id, edge, peer.clone()).unwrap();
        assert_eq!(topology.neighbor(root.id, edge), Some(peer.id));
        assert_eq!(topology.neighbor(peer.id, edge.opposite()), Some(root.id));
        assert_eq!(topology.position(peer.id), Some(position));
    }
}

#[test]
fn collision_rejects_atomically_and_preserves_original_neighbor() {
    let a = display(1, 0, 100.0, 100.0, 1.0);
    let b = display(2, 0, 100.0, 100.0, 1.0);
    let c = display(3, 0, 100.0, 100.0, 1.0);
    let mut topology = Topology::new(a.clone()).unwrap();
    topology.place(a.id, Edge::Right, b.clone()).unwrap();
    assert_eq!(
        topology.place(a.id, Edge::Right, c.clone()),
        Err(TopologyError::Collision)
    );
    assert_eq!(topology.neighbor(a.id, Edge::Right), Some(b.id));
    assert_eq!(topology.neighbor(b.id, Edge::Left), Some(a.id));
    assert_eq!(topology.display(c.id), None);
}

#[test]
fn cycle_closes_automatically_without_diagonal_edges() {
    let a = display(1, 0, 100.0, 100.0, 1.0);
    let b = display(2, 0, 100.0, 100.0, 1.0);
    let c = display(3, 0, 100.0, 100.0, 1.0);
    let d = display(4, 0, 100.0, 100.0, 1.0);
    let mut topology = Topology::new(a.clone()).unwrap();
    topology.place(a.id, Edge::Right, b.clone()).unwrap();
    topology.place(b.id, Edge::Bottom, c.clone()).unwrap();
    topology.place(c.id, Edge::Left, d.clone()).unwrap();
    assert_eq!(topology.neighbor(d.id, Edge::Top), Some(a.id));
    assert_eq!(topology.neighbor(a.id, Edge::Bottom), Some(d.id));
    assert_eq!(topology.neighbor(a.id, Edge::Top), None);
}

#[test]
fn multiple_displays_on_one_peer_retain_independent_edges() {
    let a = display(1, 0, 100.0, 100.0, 2.0);
    let mut b = display(1, 1, 200.0, 200.0, 1.0);
    b.origin = Point { x: -200.0, y: 50.0 };
    let c = display(2, 0, 100.0, 100.0, 1.0);
    let mut topology = Topology::new(a.clone()).unwrap();
    topology.place(a.id, Edge::Left, b.clone()).unwrap();
    topology.place(b.id, Edge::Left, c.clone()).unwrap();
    assert_eq!(topology.displays().len(), 3);
    let (id, point) = topology
        .map_crossing(a.id, Edge::Left, Point { x: 0.0, y: 50.0 })
        .unwrap()
        .unwrap();
    assert_eq!(id, b.id);
    assert!(point.x < 0.0 && point.x > -1.0);
    assert_eq!(point.y, 150.0);
}

#[test]
fn unequal_sizes_and_scales_map_logical_coordinates_proportionally() {
    let a = display(1, 0, 100.0, 200.0, 2.0);
    let mut b = display(2, 0, 400.0, 800.0, 1.25);
    b.origin = Point { x: 10.0, y: -100.0 };
    let mut topology = Topology::new(a.clone()).unwrap();
    topology.place(a.id, Edge::Right, b.clone()).unwrap();
    let (id, point) = topology
        .map_crossing(a.id, Edge::Right, Point { x: 100.0, y: 50.0 })
        .unwrap()
        .unwrap();
    assert_eq!(id, b.id);
    assert_eq!(point, Point { x: 10.0, y: 100.0 });
    let (_, reverse) = topology
        .map_crossing(b.id, Edge::Left, Point { x: 10.0, y: 100.0 })
        .unwrap()
        .unwrap();
    assert_eq!(reverse.y, 50.0);
    assert!(reverse.x >= 0.0 && reverse.x < 100.0);
}

#[test]
fn horizontal_coordinate_maps_when_crossing_vertical_edges() {
    let a = display(1, 0, 100.0, 100.0, 1.0);
    let b = display(2, 0, 400.0, 200.0, 2.0);
    let mut topology = Topology::new(a.clone()).unwrap();
    topology.place(a.id, Edge::Top, b.clone()).unwrap();
    let (_, point) = topology
        .map_crossing(a.id, Edge::Top, Point { x: 25.0, y: 0.0 })
        .unwrap()
        .unwrap();
    assert_eq!(point.x, 100.0);
    assert!(point.y > 199.0 && point.y < 200.0);
}

#[test]
fn reposition_removes_old_reciprocal_edges() {
    let a = display(1, 0, 100.0, 100.0, 1.0);
    let b = display(2, 0, 100.0, 100.0, 1.0);
    let mut topology = Topology::new(a.clone()).unwrap();
    topology.place(a.id, Edge::Right, b.clone()).unwrap();
    topology.place(a.id, Edge::Bottom, b.clone()).unwrap();
    assert_eq!(topology.neighbor(a.id, Edge::Right), None);
    assert_eq!(topology.neighbor(b.id, Edge::Left), None);
    assert_eq!(topology.neighbor(a.id, Edge::Bottom), Some(b.id));
}

#[test]
fn invalid_geometry_and_non_finite_points_are_rejected() {
    for (width, scale) in [
        (0.0, 1.0),
        (-1.0, 1.0),
        (f64::NAN, 1.0),
        (10.0, 0.0),
        (10.0, f64::INFINITY),
    ] {
        assert!(matches!(
            Topology::new(display(1, 0, width, 10.0, scale)),
            Err(TopologyError::InvalidDisplay)
        ));
    }
    let a = display(1, 0, 100.0, 100.0, 1.0);
    let topology = Topology::new(a.clone()).unwrap();
    assert_eq!(
        topology.map_crossing(
            a.id,
            Edge::Left,
            Point {
                x: 0.0,
                y: f64::NAN
            }
        ),
        Err(TopologyError::InvalidPoint)
    );
    assert_eq!(
        topology.map_crossing(a.id, Edge::Left, Point { x: 0.0, y: 50.0 }),
        Ok(None)
    );
}

#[test]
fn interior_motion_never_transfers_control_and_off_edge_coordinates_fail_closed() {
    let a = display(1, 0, 100.0, 100.0, 1.0);
    let b = display(2, 0, 100.0, 100.0, 1.0);
    let mut topology = Topology::new(a.clone()).unwrap();
    topology.place(a.id, Edge::Right, b).unwrap();
    assert_eq!(
        topology.map_crossing(a.id, Edge::Right, Point { x: 50.0, y: 50.0 }),
        Ok(None)
    );
    assert_eq!(
        topology.map_crossing(a.id, Edge::Right, Point { x: 100.0, y: 101.0 }),
        Err(TopologyError::InvalidPoint)
    );
}

#[test]
fn moving_bridge_cannot_leave_disconnected_or_diagonal_only_tiles() {
    let a = display(1, 0, 100.0, 100.0, 1.0);
    let b = display(2, 0, 100.0, 100.0, 1.0);
    let c = display(3, 0, 100.0, 100.0, 1.0);
    let mut topology = Topology::new(a.clone()).unwrap();
    topology.place(a.id, Edge::Right, b.clone()).unwrap();
    topology.place(b.id, Edge::Right, c.clone()).unwrap();
    assert!(topology.place(a.id, Edge::Bottom, b.clone()).is_err());
    assert_eq!(topology.position(b.id), Some((1, 0)));
    assert_eq!(topology.neighbor(b.id, Edge::Right), Some(c.id));
}

#[test]
fn geometry_whose_bounds_overflow_or_collapse_is_rejected() {
    let mut a = display(1, 0, f64::MAX, 100.0, 1.0);
    a.origin.x = f64::MAX;
    assert!(Topology::new(a).is_err());
    let mut a = display(1, 0, 1.0, 100.0, 1.0);
    a.origin.x = 1e300;
    assert!(Topology::new(a).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, ..ProptestConfig::default() })]
    #[test]
    fn generated_coordinates_stay_inside_destination_and_preserve_fraction(
        width in 1.0f64..10000.0, height in 1.0f64..10000.0,
        dest_width in 1.0f64..10000.0, dest_height in 1.0f64..10000.0,
        fraction in 0.0f64..1.0, scale in 0.25f64..4.0,
        edge in prop::sample::select(vec![Edge::Left, Edge::Right, Edge::Top, Edge::Bottom])
    ) {
        let a = display(1, 0, width, height, scale);
        let mut b = display(2, 0, dest_width, dest_height, 1.0);
        b.origin = Point { x: -333.0, y: 555.0 };
        let mut topology = Topology::new(a.clone()).unwrap();
        topology.place(a.id, edge, b.clone()).unwrap();
        let source = match edge {
            Edge::Left => Point { x: 0.0, y: height * fraction },
            Edge::Right => Point { x: width, y: height * fraction },
            Edge::Top => Point { x: width * fraction, y: 0.0 },
            Edge::Bottom => Point { x: width * fraction, y: height },
        };
        let (id, mapped) = topology.map_crossing(a.id, edge, source).unwrap().unwrap();
        prop_assert_eq!(id, b.id);
        prop_assert!(mapped.x >= -333.0 && mapped.x < -333.0 + dest_width);
        prop_assert!(mapped.y >= 555.0 && mapped.y < 555.0 + dest_height);
        let actual = match edge { Edge::Left | Edge::Right => (mapped.y - 555.0) / dest_height, _ => (mapped.x + 333.0) / dest_width };
        prop_assert!((actual - fraction).abs() < 1e-9);
    }
}
