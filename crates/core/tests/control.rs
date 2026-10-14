use seamless_input_core::*;

fn display(n: u8, index: u32) -> Display {
    Display {
        id: DisplayId {
            node: NodeId([n; 16]),
            index,
        },
        origin: Point { x: 0.0, y: 0.0 },
        width: 100.0,
        height: 100.0,
        scale: 1.0,
    }
}
fn controller() -> Controller {
    let a = display(1, 0);
    let b = display(2, 0);
    let c = display(3, 0);
    let mut topology = Topology::new(a.clone()).unwrap();
    topology.place(a.id, Edge::Right, b.clone()).unwrap();
    topology.place(b.id, Edge::Right, c.clone()).unwrap();
    Controller::new(topology, a.id, 1000).unwrap()
}
fn key() -> InputEvent {
    InputEvent::Key {
        code: 42,
        pressed: true,
    }
}
fn crossing() -> Point {
    Point { x: 100.0, y: 50.0 }
}
fn shift() -> InputEvent {
    InputEvent::Modifier {
        modifier: Modifier::Shift,
        pressed: true,
    }
}

#[test]
fn input_has_exactly_one_active_target() {
    let mut controller = controller();
    assert_eq!(controller.route(key()).unwrap(), vec![Action::Local(key())]);
    controller.cross(Edge::Right, crossing(), 0).unwrap();
    assert_eq!(controller.active_target(), NodeId([2; 16]));
    assert_eq!(
        controller.route(key()).unwrap(),
        vec![Action::Send {
            target: NodeId([2; 16]),
            event: key()
        }]
    );
}

#[test]
fn three_peer_traversal_routes_to_the_current_display_owner() {
    let mut controller = controller();
    let actions = controller.cross(Edge::Right, crossing(), 10).unwrap();
    assert!(actions.contains(&Action::Warp {
        target: NodeId([2; 16]),
        display: display(2, 0).id,
        point: Point { x: 0.0, y: 50.0 }
    }));
    controller.cross(Edge::Right, crossing(), 20).unwrap();
    assert_eq!(controller.active_display(), display(3, 0).id);
    assert_eq!(
        controller.route(key()).unwrap(),
        vec![Action::Send {
            target: NodeId([3; 16]),
            event: key()
        }]
    );
    controller
        .cross(Edge::Left, Point { x: 0.0, y: 50.0 }, 30)
        .unwrap();
    assert_eq!(controller.active_target(), NodeId([2; 16]));
}

#[test]
fn unconnected_edge_does_not_change_target() {
    let mut controller = controller();
    assert!(
        controller
            .cross(Edge::Top, Point { x: 20.0, y: 0.0 }, 0)
            .unwrap()
            .is_empty()
    );
    assert_eq!(controller.active_target(), NodeId([1; 16]));
}

#[test]
fn emergency_return_releases_modifiers_and_restores_local_control() {
    let mut controller = controller();
    controller.cross(Edge::Right, crossing(), 0).unwrap();
    controller.route(shift()).unwrap();
    let actions = controller.emergency_return();
    assert_eq!(
        actions.first(),
        Some(&Action::ReleaseAll {
            target: NodeId([2; 16])
        })
    );
    assert!(actions.contains(&Action::ReleaseAll {
        target: NodeId([1; 16])
    }));
    assert_eq!(controller.active_display(), display(1, 0).id);
    assert_eq!(controller.route(key()).unwrap(), vec![Action::Local(key())]);
}

#[test]
fn disconnect_of_active_peer_returns_locally_and_releases_all() {
    let mut controller = controller();
    controller.cross(Edge::Right, crossing(), 0).unwrap();
    controller.route(shift()).unwrap();
    assert!(controller.disconnect(NodeId([3; 16])).is_empty());
    let actions = controller.disconnect(NodeId([2; 16]));
    assert!(actions.contains(&Action::ReleaseAll {
        target: NodeId([2; 16])
    }));
    assert_eq!(controller.active_target(), NodeId([1; 16]));
}

#[test]
fn timeout_uses_selected_peer_heartbeat_and_releases_modifiers_at_boundary() {
    let mut controller = controller();
    controller.cross(Edge::Right, crossing(), 100).unwrap();
    controller.route(shift()).unwrap();
    controller.heartbeat(NodeId([2; 16]), 600).unwrap();
    controller.heartbeat(NodeId([3; 16]), 1000).unwrap();
    assert!(controller.tick(1599).unwrap().is_empty());
    let actions = controller.tick(1600).unwrap();
    assert!(actions.contains(&Action::ReleaseAll {
        target: NodeId([2; 16])
    }));
    assert_eq!(controller.active_target(), NodeId([1; 16]));
    assert!(controller.tick(2600).unwrap().is_empty());
}

#[test]
fn edge_handoff_releases_old_target_before_reapplying_held_modifiers() {
    let mut controller = controller();
    controller.route(shift()).unwrap();
    let actions = controller.cross(Edge::Right, crossing(), 0).unwrap();
    assert_eq!(
        actions.first(),
        Some(&Action::ReleaseAll {
            target: NodeId([1; 16])
        })
    );
    assert!(actions.contains(&Action::Send {
        target: NodeId([2; 16]),
        event: shift()
    }));
}

#[test]
fn same_peer_multi_display_crossing_warps_without_handoff_or_release() {
    let a = display(1, 0);
    let b = display(1, 1);
    let mut topology = Topology::new(a.clone()).unwrap();
    topology.place(a.id, Edge::Right, b.clone()).unwrap();
    let mut controller = Controller::new(topology, a.id, 1000).unwrap();
    let actions = controller.cross(Edge::Right, crossing(), 0).unwrap();
    assert_eq!(
        actions,
        vec![Action::Warp {
            target: a.id.node,
            display: b.id,
            point: Point { x: 0.0, y: 50.0 }
        }]
    );
}

#[test]
fn permission_loss_and_shutdown_release_even_when_local() {
    for stop in [Controller::permission_lost, Controller::shutdown] {
        let mut controller = controller();
        controller.route(shift()).unwrap();
        assert!(stop(&mut controller).contains(&Action::ReleaseAll {
            target: NodeId([1; 16])
        }));
        assert_eq!(controller.active_target(), NodeId([1; 16]));
    }
}

#[test]
fn clock_rollback_and_invalid_events_are_rejected_without_changing_target() {
    let mut controller = controller();
    controller.cross(Edge::Right, crossing(), 100).unwrap();
    assert_eq!(controller.tick(99), Err(ControlError::ClockWentBackwards));
    assert_eq!(
        controller.route(InputEvent::Pointer {
            x: f64::INFINITY,
            y: 0.0
        }),
        Err(ControlError::InvalidInput)
    );
    assert_eq!(controller.active_target(), NodeId([2; 16]));
}

#[test]
fn invalid_local_display_and_zero_timeout_are_rejected() {
    let a = display(1, 0);
    let topology = Topology::new(a.clone()).unwrap();
    assert!(matches!(
        Controller::new(topology.clone(), display(2, 0).id, 1000),
        Err(ControlError::InvalidLocalDisplay)
    ));
    assert!(matches!(
        Controller::new(topology, a.id, 0),
        Err(ControlError::InvalidTimeout)
    ));
}

#[test]
fn permission_loss_inhibits_new_transfers_until_grant_is_restored() {
    let mut controller = controller();
    controller.cross(Edge::Right, crossing(), 0).unwrap();
    controller.permission_lost();
    assert!(
        controller
            .cross(Edge::Right, crossing(), 100)
            .unwrap()
            .is_empty()
    );
    assert_eq!(controller.active_target(), NodeId([1; 16]));
    assert_eq!(controller.route(key()).unwrap(), vec![Action::Local(key())]);
}

#[test]
fn shutdown_prevents_new_input_or_transfer() {
    let mut controller = controller();
    controller.shutdown();
    controller.permission_restored();
    assert!(controller.route(key()).is_err());
    assert!(controller.cross(Edge::Right, crossing(), 100).is_err());
    assert_eq!(controller.active_target(), NodeId([1; 16]));
}

#[test]
fn restored_permission_allows_explicit_crossing_again() {
    let mut controller = controller();
    controller.permission_lost();
    controller.permission_restored();
    controller.cross(Edge::Right, crossing(), 100).unwrap();
    assert_eq!(controller.active_target(), NodeId([2; 16]));
}

#[test]
fn late_heartbeat_cannot_revive_an_expired_remote_target() {
    let mut controller = controller();
    controller.cross(Edge::Right, crossing(), 100).unwrap();
    assert!(controller.heartbeat(NodeId([2; 16]), 1100).is_err());
    assert!(!controller.tick(1100).unwrap().is_empty());
    assert_eq!(controller.active_target(), NodeId([1; 16]));
}

#[test]
fn crossing_after_timeout_returns_local_before_any_new_handoff() {
    let mut controller = controller();
    controller.cross(Edge::Right, crossing(), 100).unwrap();
    let actions = controller.cross(Edge::Right, crossing(), 1100).unwrap();
    assert!(actions.contains(&Action::ReleaseAll {
        target: NodeId([2; 16])
    }));
    assert_eq!(controller.active_target(), NodeId([1; 16]));
    assert!(!actions.contains(&Action::TargetChanged {
        target: NodeId([3; 16])
    }));
}
