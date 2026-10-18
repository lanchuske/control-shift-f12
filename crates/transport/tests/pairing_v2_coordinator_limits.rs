#![cfg(feature = "pairing-v2-experimental")]
use seamless_transport::pairing_v2::PairingLimits;
use std::net::{IpAddr, Ipv4Addr};
fn source(n: u8) -> IpAddr {
    Ipv4Addr::new(192, 168, 1, n).into()
}

#[test]
fn consent_window_precedes_work_and_one_gesture_selects_only_one_fresh_candidate() {
    let mut gate = PairingLimits::default();
    assert!(gate.connect(source(1), 1, 0).is_err());
    gate.open_window(0).unwrap();
    gate.connect(source(1), 1, 0).unwrap();
    gate.candidate(1, 30_000, 1).unwrap();
    gate.select(1, 2).unwrap();
    assert!(gate.select(1, 3).is_err());
    gate.close_window(4).unwrap();
    assert!(gate.check(4).is_err());
    assert!(gate.connect(source(1), 2, 4).is_err());
    gate.open_window(5).unwrap();
    assert!(gate.select(1, 5).is_err());
}

#[test]
fn source_and_global_buckets_do_not_reset_when_consent_window_reopens() {
    let mut gate = PairingLimits::default();
    gate.open_window(0).unwrap();
    for id in 1..=2 {
        gate.connect(source(1), id, 0).unwrap();
    }
    gate.close_window(0).unwrap();
    gate.open_window(0).unwrap();
    assert!(gate.connect(source(1), 3, 0).is_err());
    for id in 4..=6 {
        gate.connect(source(id as u8), id, 0).unwrap();
    }
    assert!(gate.connect(source(9), 9, 0).is_err());
    assert!(gate.connect(source(10), 10, 2999).is_err());
    gate.connect(source(10), 10, 3000).unwrap();
    gate.close_window(12_000).unwrap();
    gate.open_window(12_000).unwrap();
    gate.connect(source(1), 11, 12_000).unwrap();
    assert!(gate.connect(source(1), 12, 12_000).is_err());
}

#[test]
fn sockets_are_bounded_per_source_and_globally_before_crypto_allocation() {
    let mut gate = PairingLimits::default();
    gate.open_window(0).unwrap();
    gate.connect(source(1), 1, 0).unwrap();
    gate.connect(source(1), 2, 0).unwrap();
    assert!(gate.connect(source(1), 3, 12_000).is_err());
    for id in 3..=8 {
        gate.connect(source(id as u8), id, id * 12_000).unwrap();
    }
    assert!(gate.connect(source(9), 9, 120_000).is_err());
}

#[test]
fn exact_candidate_deadlines_and_monotonic_rollback_fail_closed() {
    let mut gate = PairingLimits::default();
    gate.open_window(0).unwrap();
    gate.connect(source(1), 1, 0).unwrap();
    assert!(gate.candidate(1, 30_000, 2000).is_err());
    gate.close_window(2000).unwrap();
    gate.open_window(2001).unwrap();
    gate.connect(source(2), 2, 2001).unwrap();
    gate.candidate(2, 50, 2002).unwrap();
    assert!(gate.select(2, 2052).is_err());
    assert!(gate.connect(source(3), 3, 2051).is_err());
    assert!(
        gate.open_window(2053).is_err(),
        "rollback poisons gate; cannot silently retry"
    );
}

#[test]
fn progress_never_extends_attempt_and_terminal_attempt_requires_fresh_candidate() {
    let mut gate = PairingLimits::default();
    gate.open_window(0).unwrap();
    gate.connect(source(1), 1, 0).unwrap();
    gate.candidate(1, 30_000, 0).unwrap();
    gate.select(1, 0).unwrap();
    for n in 1..=10 {
        gate.progress(n * 29_000).unwrap();
    }
    gate.check(299_999).unwrap();
    assert!(gate.check(300_000).is_err());
    assert!(gate.select(1, 300_000).is_err());
    gate.finish(300_001).unwrap();
    assert!(gate.check(300_001).is_err());
    assert!(
        gate.connect(source(1), 1, 300_001).is_err(),
        "consumed connection cannot retry"
    );
    gate.connect(source(1), 2, 300_001).unwrap();
    gate.candidate(2, 30_000, 300_001).unwrap();
    gate.select(2, 300_001).unwrap();
    assert!(
        gate.check(330_001).is_err(),
        "phase expires at exact 30 seconds"
    );
}
