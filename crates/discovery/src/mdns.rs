use std::{
    collections::BTreeMap,
    net::{SocketAddr, ToSocketAddrs},
    time::{Duration, Instant},
};

pub const SERVICE_TYPE: &str = "_seamless-input._udp.local.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollBudget {
    max_events: usize,
    max_elapsed: Duration,
}

impl PollBudget {
    pub fn new(max_events: usize, max_elapsed: Duration) -> Result<Self, String> {
        if max_events == 0 || max_elapsed.is_zero() {
            return Err("discovery poll budget must be non-zero".into());
        }
        Ok(Self {
            max_events,
            max_elapsed,
        })
    }
}

struct PollAllowance {
    remaining: usize,
    deadline: Instant,
}

impl PollAllowance {
    fn new(budget: PollBudget, started: Instant) -> Self {
        Self {
            remaining: budget.max_events,
            deadline: started.checked_add(budget.max_elapsed).unwrap_or(started),
        }
    }
    fn take(&mut self, now: Instant) -> bool {
        if self.remaining == 0 || now >= self.deadline {
            return false;
        }
        self.remaining -= 1;
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advertisement {
    pub instance: String,
    pub version: u16,
    pub pairable: bool,
    pub addresses: Vec<SocketAddr>,
    /// None means expiry is maintained by the mDNS daemon's wire TTL events.
    pub ttl: Option<Duration>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredPeer {
    pub advertisement: Advertisement,
    pub compatible: bool,
}

pub struct PeerCache {
    version: u16,
    entries: BTreeMap<String, (Advertisement, Option<Instant>)>,
}
impl PeerCache {
    pub fn new(version: u16) -> Self {
        Self {
            version,
            entries: BTreeMap::new(),
        }
    }
    pub fn observe(&mut self, mut peer: Advertisement, now: Instant) {
        peer.instance.make_ascii_lowercase();
        peer.addresses.sort();
        peer.addresses.dedup();
        let expires = peer.ttl.map(|ttl| now.checked_add(ttl).unwrap_or(now));
        self.entries.insert(peer.instance.clone(), (peer, expires));
    }
    pub fn peers(&mut self, now: Instant) -> Vec<DiscoveredPeer> {
        self.entries
            .retain(|_, (_, expires)| expires.is_none_or(|expires| now < expires));
        self.entries
            .values()
            .map(|(peer, _)| DiscoveredPeer {
                advertisement: peer.clone(),
                compatible: peer.version == self.version,
            })
            .collect()
    }
    fn remove(&mut self, instance: &str) {
        self.entries.remove(&instance.to_ascii_lowercase());
    }
}

pub fn txt_records(version: u16, pairable: bool) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("v".into(), version.to_string()),
        ("pairable".into(), if pairable { "1" } else { "0" }.into()),
    ])
}
pub fn manual_address(value: &str) -> Result<Vec<SocketAddr>, String> {
    let mut addresses: Vec<_> = value
        .to_socket_addrs()
        .map_err(|_| "invalid or unresolved peer address")?
        .collect();
    if addresses.is_empty() || addresses.iter().any(|addr| !is_unicast_endpoint(*addr)) {
        return Err("peer address must be a unicast host with a nonzero port".into());
    }
    addresses.sort();
    addresses.dedup();
    Ok(addresses)
}

fn is_unicast_endpoint(address: SocketAddr) -> bool {
    address.port() != 0
        && !address.ip().is_unspecified()
        && !address.ip().is_multicast()
        && !matches!(address.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
}

fn resolved_addresses(info: &mdns_sd::ResolvedService) -> Vec<SocketAddr> {
    let mut addresses: Vec<_> = info
        .get_addresses()
        .iter()
        .filter_map(|ip| match ip {
            mdns_sd::ScopedIp::V4(ip) => {
                Some(SocketAddr::new((*ip.addr()).into(), info.get_port()))
            }
            mdns_sd::ScopedIp::V6(ip) => Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                *ip.addr(),
                info.get_port(),
                0,
                ip.scope_id().index,
            ))),
            _ => None,
        })
        .filter(|address| is_unicast_endpoint(*address))
        .collect();
    addresses.sort();
    addresses.dedup();
    addresses
}

/// A browse result is an untrusted locator, never a paired identity.
/// Callers supply a fresh random instance token for each application run.
pub struct Discovery {
    daemon: mdns_sd::ServiceDaemon,
    version: u16,
    published: Vec<String>,
    receiver: Option<mdns_sd::Receiver<mdns_sd::ServiceEvent>>,
    live: PeerCache,
}
impl Discovery {
    pub fn new(version: u16) -> Result<Self, String> {
        let daemon =
            mdns_sd::ServiceDaemon::new().map_err(|_| "mDNS unavailable; use a manual address")?;
        daemon
            .enable_interface(mdns_sd::IfKind::LoopbackV4)
            .map_err(|_| "mDNS interface unavailable")?;
        Ok(Self {
            daemon,
            version,
            published: vec![],
            receiver: None,
            live: PeerCache::new(version),
        })
    }
    pub fn publish(
        &mut self,
        instance: &str,
        address: SocketAddr,
        pairable: bool,
    ) -> Result<String, String> {
        if instance.len() != 32 || !instance.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(
                "instance must be an opaque 128-bit random token, never a device name".into(),
            );
        }
        if !is_unicast_endpoint(address) {
            return Err("publish requires a unicast interface address and nonzero port".into());
        }
        let hostname = format!("{instance}.local.");
        let properties: std::collections::HashMap<_, _> =
            txt_records(self.version, pairable).into_iter().collect();
        let info = mdns_sd::ServiceInfo::new(
            SERVICE_TYPE,
            instance,
            &hostname,
            address.ip(),
            address.port(),
            properties,
        )
        .map_err(|_| "invalid mDNS advertisement")?;
        let name = info.get_fullname().to_owned();
        self.daemon
            .register(info)
            .map_err(|_| "mDNS publication failed")?;
        self.published.push(name.clone());
        Ok(name)
    }

    fn ensure_browser(&mut self) -> Result<mdns_sd::Receiver<mdns_sd::ServiceEvent>, String> {
        if self.receiver.is_none() {
            self.receiver = Some(
                self.daemon
                    .browse(SERVICE_TYPE)
                    .map_err(|_| "mDNS browse unavailable; use a manual address")?,
            );
        }
        Ok(self.receiver.as_ref().unwrap().clone())
    }

    fn observe_event(&mut self, event: mdns_sd::ServiceEvent) {
        match event {
            mdns_sd::ServiceEvent::ServiceResolved(info) => {
                let Some(instance) = info
                    .get_fullname()
                    .strip_suffix(&format!(".{SERVICE_TYPE}"))
                else {
                    return;
                };
                if instance.len() != 32 || !instance.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return;
                }
                if self
                    .published
                    .iter()
                    .any(|name| name == info.get_fullname())
                {
                    return;
                }
                let Some(version) = info
                    .get_property_val_str("v")
                    .and_then(|s| s.parse::<u16>().ok())
                else {
                    return;
                };
                let pairable = match info.get_property_val_str("pairable") {
                    Some("1") => true,
                    Some("0") => false,
                    _ => return,
                };
                let addresses = resolved_addresses(&info);
                if addresses.is_empty() {
                    return;
                }
                self.live.observe(
                    Advertisement {
                        instance: instance.to_owned(),
                        version,
                        pairable,
                        addresses,
                        ttl: None,
                    },
                    Instant::now(),
                );
            }
            mdns_sd::ServiceEvent::ServiceRemoved(_, name) => {
                if let Some(instance) = name.strip_suffix(&format!(".{SERVICE_TYPE}")) {
                    self.live.remove(instance);
                }
            }
            _ => {}
        }
    }

    /// Drain only mDNS events that are already available. This method never
    /// waits for network traffic and is suitable for latency-sensitive loops.
    pub fn poll(&mut self) -> Result<Vec<DiscoveredPeer>, String> {
        self.poll_with_budget(PollBudget::new(64, Duration::from_millis(2))?)
    }

    /// Drain ready events within both a count and wall-clock budget so a
    /// continuously replenished daemon backlog cannot monopolize its caller.
    pub fn poll_with_budget(&mut self, budget: PollBudget) -> Result<Vec<DiscoveredPeer>, String> {
        let receiver = self.ensure_browser()?;
        let mut allowance = PollAllowance::new(budget, Instant::now());
        while allowance.take(Instant::now()) {
            let Ok(event) = receiver.try_recv() else {
                break;
            };
            self.observe_event(event);
        }
        if receiver.is_disconnected() {
            return Err("mDNS browser stopped".into());
        }
        Ok(self.live.peers(Instant::now()))
    }

    /// Poll discovery for at most `wait`. Wire TTL and goodbye expiry are owned
    /// by mdns-sd, which emits ServiceRemoved; ResolvedService exposes no TTL.
    pub fn browse(&mut self, wait: Duration) -> Result<Vec<DiscoveredPeer>, String> {
        let receiver = self.ensure_browser()?;
        let deadline = Instant::now()
            .checked_add(wait)
            .unwrap_or_else(Instant::now);
        loop {
            let event =
                match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                    Ok(event) => event,
                    Err(mdns_sd::RecvTimeoutError::Timeout) => break,
                    Err(_) => return Err("mDNS browser stopped".into()),
                };
            self.observe_event(event);
            if Instant::now() >= deadline {
                break;
            }
        }
        Ok(self.live.peers(Instant::now()))
    }
    pub fn unpublish(&mut self, instance: &str) -> Result<(), String> {
        let name = format!("{instance}.{SERVICE_TYPE}");
        if !self.published.contains(&name) {
            return Err("service is not published by this instance".into());
        }
        self.daemon
            .unregister(&name)
            .map_err(|_| "mDNS withdrawal failed")?;
        self.published.retain(|published| published != &name);
        self.live.remove(instance);
        Ok(())
    }
}
impl Drop for Discovery {
    fn drop(&mut self) {
        for name in &self.published {
            let _ = self.daemon.unregister(name);
        }
        if self.receiver.is_some() {
            let _ = self.daemon.stop_browse(SERVICE_TYPE);
        }
        let _ = self.daemon.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polling_allowance_stops_on_count_or_elapsed_budget() {
        let started = Instant::now();
        let mut count =
            PollAllowance::new(PollBudget::new(2, Duration::from_secs(1)).unwrap(), started);
        assert!(count.take(started));
        assert!(count.take(started));
        assert!(!count.take(started));

        let mut elapsed = PollAllowance::new(
            PollBudget::new(10, Duration::from_millis(1)).unwrap(),
            started,
        );
        assert!(!elapsed.take(started + Duration::from_millis(2)));
    }

    #[test]
    fn browse_rejects_broadcast_and_keeps_valid_unicast_from_resolved_service() {
        let info = mdns_sd::ServiceInfo::new(
            SERVICE_TYPE,
            "b1111111111111111111111111111111",
            "b1111111111111111111111111111111.local.",
            "255.255.255.255,127.0.0.1",
            7777,
            None,
        )
        .unwrap()
        .as_resolved_service();
        assert_eq!(
            resolved_addresses(&info),
            vec!["127.0.0.1:7777".parse::<SocketAddr>().unwrap()]
        );
        let only_broadcast = mdns_sd::ServiceInfo::new(
            SERVICE_TYPE,
            "b2222222222222222222222222222222",
            "b2222222222222222222222222222222.local.",
            "255.255.255.255",
            7777,
            None,
        )
        .unwrap()
        .as_resolved_service();
        assert!(resolved_addresses(&only_broadcast).is_empty());
    }
}
