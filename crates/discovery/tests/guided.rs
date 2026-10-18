#![cfg(feature = "pairing-v2-experimental")]
use seamless_discovery::{
    Advertisement,
    guided::{ConsentCatalog, DiscoveryError},
};
use std::time::Duration;

fn advertisement(n: u64) -> Advertisement {
    Advertisement {
        instance: format!("{n:032x}"),
        version: 2,
        pairable: true,
        addresses: vec!["127.0.0.1:7777".parse().unwrap()],
        ttl: None,
    }
}

#[test]
fn consent_window_and_current_handle_are_required_without_implicit_retry() {
    let mut catalog = ConsentCatalog::default();
    assert_eq!(
        catalog.observe(advertisement(1), 0),
        Err(DiscoveryError::Closed)
    );
    catalog.open(1).unwrap();
    let first = catalog.observe(advertisement(1), 2).unwrap();
    assert_eq!(catalog.select(first, 3).unwrap().addresses.len(), 1);
    catalog.close(4).unwrap();
    assert_eq!(catalog.select(first, 5), Err(DiscoveryError::Closed));
    catalog.open(6).unwrap();
    let next = catalog.observe(advertisement(1), 7).unwrap();
    assert_ne!(first, next);
    assert_eq!(catalog.select(first, 8), Err(DiscoveryError::Stale));
    assert!(catalog.select(next, 9).is_ok());
}

#[test]
fn capacity_and_address_bounds_precede_untrusted_catalogue_storage() {
    let mut catalog = ConsentCatalog::default();
    catalog.open(0).unwrap();
    for n in 1..=32 {
        catalog.observe(advertisement(n), 1).unwrap();
    }
    assert_eq!(
        catalog.observe(advertisement(33), 1),
        Err(DiscoveryError::Limit)
    );
    assert_eq!(catalog.candidates(1).unwrap().len(), 32);
    let mut peer = advertisement(1);
    peer.addresses = (1..=9)
        .map(|n| format!("127.0.0.1:{}", 7000 + n).parse().unwrap())
        .collect();
    assert_eq!(catalog.observe(peer, 1), Err(DiscoveryError::Invalid));
    assert_eq!(catalog.candidates(1).unwrap().len(), 32);
}

#[test]
fn g4_select_is_current_atomic_single_use_and_bounded() {
    let mut catalog = ConsentCatalog::default();
    catalog.open(0).unwrap();
    let mut handles = Vec::new();
    for n in 1..=32 {
        handles.push(catalog.observe(advertisement(n), 1).unwrap());
    }
    assert_eq!(catalog.candidates(1).unwrap().len(), 32);
    assert_eq!(
        catalog.observe(advertisement(33), 1),
        Err(DiscoveryError::Limit)
    );

    let selected = catalog.select_once(handles[0], 2).unwrap();
    assert_eq!(selected.handle, handles[0]);
    assert_eq!(
        catalog.select_once(handles[0], 3),
        Err(DiscoveryError::Closed)
    );
    assert_eq!(
        catalog.select_once(handles[1], 3),
        Err(DiscoveryError::Closed)
    );
}

#[test]
fn local_freshness_window_deadline_and_clock_rollback_are_fail_closed() {
    let mut catalog = ConsentCatalog::default();
    catalog.open(0).unwrap();
    let handle = catalog.observe(advertisement(1), 0).unwrap();
    assert!(catalog.select(handle, 29_999).is_ok());
    assert!(catalog.select(handle, 119_999).is_ok());
    assert_eq!(catalog.select(handle, 120_000), Err(DiscoveryError::Stale));
    assert!(catalog.candidates(120_000).unwrap().is_empty());
    let mut ttl = advertisement(2);
    ttl.ttl = Some(Duration::from_millis(5));
    let short = catalog.observe(ttl, 120_001).unwrap();
    assert_eq!(catalog.select(short, 120_006), Err(DiscoveryError::Stale));
    assert_eq!(catalog.candidates(300_000), Err(DiscoveryError::Expired));
    catalog.open(300_001).unwrap();
    assert_eq!(
        catalog.observe(advertisement(1), 300_000),
        Err(DiscoveryError::ClockRollback)
    );
    assert_eq!(catalog.open(300_002), Err(DiscoveryError::ClockRollback));
}

#[test]
fn duplicate_refresh_is_stable_but_address_drift_removal_and_expiry_revoke_handles() {
    let mut catalog = ConsentCatalog::default();
    catalog.open(0).unwrap();
    let first = catalog.observe(advertisement(1), 0).unwrap();
    let mut same = advertisement(1);
    same.instance = same.instance.to_ascii_uppercase();
    assert_eq!(catalog.observe(same, 10), Ok(first));
    assert_eq!(catalog.candidates(10).unwrap().len(), 1);
    let mut changed = advertisement(1);
    changed.addresses = vec!["127.0.0.2:7777".parse().unwrap()];
    let next = catalog.observe(changed, 11).unwrap();
    assert_ne!(first, next);
    assert_eq!(catalog.select(first, 12), Err(DiscoveryError::Stale));
    catalog.remove(&advertisement(1).instance, 13).unwrap();
    assert_eq!(catalog.select(next, 14), Err(DiscoveryError::Stale));
    let mut bounded = advertisement(1);
    bounded.ttl = Some(Duration::from_secs(30));
    let expired = catalog.observe(bounded.clone(), 15).unwrap();
    let fresh = catalog.observe(bounded, 30_015).unwrap();
    assert_ne!(expired, fresh);
}

#[test]
fn hostile_locators_and_incompatible_versions_never_become_connectable() {
    let mut catalog = ConsentCatalog::default();
    catalog.open(0).unwrap();
    for bad in 0..5 {
        let mut ad = advertisement(1);
        match bad {
            0 => ad.instance = "Friendly private machine".into(),
            1 => ad.addresses.clear(),
            2 => ad.addresses = vec!["255.255.255.255:9".parse().unwrap()],
            3 => ad.addresses = vec!["127.0.0.1:0".parse().unwrap()],
            _ => ad.ttl = Some(Duration::ZERO),
        }
        assert_eq!(catalog.observe(ad, 1), Err(DiscoveryError::Invalid));
    }
    let mut old = advertisement(2);
    old.version = 1;
    let handle = catalog.observe(old, 2).unwrap();
    assert_eq!(catalog.select(handle, 3), Err(DiscoveryError::Incompatible));
    let mut unavailable = advertisement(3);
    unavailable.pairable = false;
    let handle = catalog.observe(unavailable, 3).unwrap();
    assert_eq!(catalog.select(handle, 4), Err(DiscoveryError::Incompatible));
}
