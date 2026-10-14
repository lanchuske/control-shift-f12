use seamless_discovery::mdns::*;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

fn advertisement(version: u16, ttl: u64) -> Advertisement {
    Advertisement {
        instance: "0123456789abcdef0123456789abcdef".into(),
        version,
        pairable: true,
        addresses: vec!["127.0.0.1:5000".parse().unwrap()],
        ttl: Some(Duration::from_secs(ttl)),
    }
}

#[test]
fn duplicate_advertisements_refresh_one_peer_and_expire_at_ttl() {
    let now = Instant::now();
    let mut cache = PeerCache::new(1);
    cache.observe(advertisement(1, 5), now);
    cache.observe(advertisement(1, 5), now + Duration::from_secs(2));
    assert_eq!(cache.peers(now + Duration::from_secs(5)).len(), 1);
    assert!(cache.peers(now + Duration::from_secs(7)).is_empty());
}

#[test]
fn dns_case_variants_and_repeated_addresses_do_not_duplicate_a_peer() {
    let now = Instant::now();
    let mut cache = PeerCache::new(1);
    cache.observe(advertisement(1, 5), now);
    let mut duplicate = advertisement(1, 5);
    duplicate.instance = duplicate.instance.to_ascii_uppercase();
    duplicate.addresses.push("127.0.0.1:5000".parse().unwrap());
    cache.observe(duplicate, now);
    let peers = cache.peers(now);
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].advertisement.addresses.len(), 1);
}

#[test]
fn incompatible_peers_remain_visible_without_becoming_connectable() {
    let now = Instant::now();
    let mut cache = PeerCache::new(1);
    cache.observe(advertisement(2, 5), now);
    let peers = cache.peers(now);
    assert_eq!(peers.len(), 1);
    assert!(!peers[0].compatible);
}

#[test]
fn txt_advertises_only_protocol_version_and_pairability() {
    let txt = txt_records(1, true);
    assert_eq!(txt.len(), 2);
    assert_eq!(txt.get("v").map(String::as_str), Some("1"));
    assert_eq!(txt.get("pairable").map(String::as_str), Some("1"));
}

#[test]
fn manual_fallback_resolves_addresses_without_discovery() {
    let expected: SocketAddr = "127.0.0.1:7777".parse().unwrap();
    assert_eq!(manual_address("127.0.0.1:7777").unwrap(), vec![expected]);
    assert!(manual_address("127.0.0.1:0").is_err());
    assert!(manual_address("missing-port").is_err());
}

#[test]
fn manual_fallback_rejects_ipv4_broadcast() {
    assert!(manual_address("255.255.255.255:7777").is_err());
}

#[test]
fn publishing_rejects_ipv4_broadcast() {
    let mut discovery = Discovery::new(1).unwrap();
    assert!(
        discovery
            .publish(
                "b1111111111111111111111111111111",
                "255.255.255.255:7777".parse().unwrap(),
                false
            )
            .is_err()
    );
}

#[test]
fn publishing_rejects_human_machine_names_and_invalid_addresses() {
    let mut discovery = Discovery::new(1).unwrap();
    assert!(
        discovery
            .publish("user-laptop", "127.0.0.1:5000".parse().unwrap(), true)
            .is_err()
    );
    assert!(
        discovery
            .publish(
                "0123456789abcdef0123456789abcdef",
                "127.0.0.1:0".parse().unwrap(),
                true
            )
            .is_err()
    );
}

#[test]
fn real_mdns_publish_browse_preserves_udp_address_and_version() {
    let mut publisher = Discovery::new(1).unwrap();
    let mut browser = Discovery::new(2).unwrap();
    browser.browse(Duration::ZERO).unwrap();
    let instance = "a1111111111111111111111111111111";
    let address = "127.0.0.1:57891".parse().unwrap();
    let name = publisher.publish(instance, address, false).unwrap();
    assert!(name.ends_with("._seamless-input._udp.local."));
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let peers = browser.browse(Duration::from_millis(200)).unwrap();
        if let Some(peer) = peers
            .iter()
            .find(|peer| peer.advertisement.instance == instance)
        {
            assert!(peer.advertisement.addresses.contains(&address));
            assert!(!peer.compatible);
            assert!(!peer.advertisement.pairable);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "mDNS advertisement was not resolved"
        );
    }
    publisher.unpublish(instance).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if browser
            .browse(Duration::from_millis(100))
            .unwrap()
            .iter()
            .all(|peer| peer.advertisement.instance != instance)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "goodbye must remove expired availability"
        );
    }
}
