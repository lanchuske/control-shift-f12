//! Experimental consent-owned locator catalogue. No identity or trust decisions.
use crate::Advertisement;
use std::{collections::BTreeMap, net::SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryError {
    Closed,
    Expired,
    ClockRollback,
    Invalid,
    Limit,
    Stale,
    Incompatible,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateHandle {
    pub window: u64,
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatorView {
    pub handle: CandidateHandle,
    pub version: u16,
    pub pairable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedLocator {
    pub handle: CandidateHandle,
    pub rendezvous: String,
    pub addresses: Vec<SocketAddr>,
}

struct Entry {
    advertisement: Advertisement,
    handle: CandidateHandle,
    expires: u64,
}

// mdns-sd's shortest default required-record TTL is 120 seconds (SRV/A).
// Keep an independent local bound while allowing its refresh cycle to renew
// a candidate before this deadline. The consent window remains the hard cap.
const DAEMON_MANAGED_FRESHNESS_MS: u64 = 120_000;

#[derive(Default)]
pub struct ConsentCatalog {
    last: u64,
    poisoned: bool,
    window: u64,
    sequence: u64,
    deadline: Option<u64>,
    entries: BTreeMap<String, Entry>,
}
impl ConsentCatalog {
    fn observe_clock(&mut self, now: u64) -> Result<(), DiscoveryError> {
        if self.poisoned || now < self.last {
            self.poisoned = true;
            self.deadline = None;
            self.entries.clear();
            return Err(DiscoveryError::ClockRollback);
        }
        self.last = now;
        Ok(())
    }
    fn current(&mut self, now: u64) -> Result<(), DiscoveryError> {
        self.observe_clock(now)?;
        let end = self.deadline.ok_or(DiscoveryError::Closed)?;
        if now >= end {
            self.deadline = None;
            self.entries.clear();
            return Err(DiscoveryError::Expired);
        }
        self.entries.retain(|_, e| now < e.expires);
        Ok(())
    }
    pub fn open(&mut self, now: u64) -> Result<(), DiscoveryError> {
        self.observe_clock(now)?;
        if self.deadline.is_some() {
            return Err(DiscoveryError::Invalid);
        }
        let next = self.window.checked_add(1).ok_or(DiscoveryError::Limit)?;
        let deadline = now.checked_add(300_000).ok_or(DiscoveryError::Limit)?;
        self.window = next;
        self.deadline = Some(deadline);
        self.entries.clear();
        Ok(())
    }
    pub fn close(&mut self, now: u64) -> Result<(), DiscoveryError> {
        let result = self.observe_clock(now);
        self.deadline = None;
        self.entries.clear();
        result
    }
    pub fn observe(
        &mut self,
        mut ad: Advertisement,
        now: u64,
    ) -> Result<CandidateHandle, DiscoveryError> {
        self.current(now)?;
        if !opaque(&ad.instance)
            || ad.addresses.is_empty()
            || ad.addresses.len() > 8
            || ad.addresses.iter().any(|a| !unicast(*a))
        {
            return Err(DiscoveryError::Invalid);
        }
        ad.instance.make_ascii_lowercase();
        ad.addresses.sort();
        ad.addresses.dedup();
        let ttl = match ad.ttl {
            Some(ttl) => ttl.as_millis().min(30_000) as u64,
            None => DAEMON_MANAGED_FRESHNESS_MS,
        };
        if ttl == 0 {
            return Err(DiscoveryError::Invalid);
        }
        let expires = now.checked_add(ttl).ok_or(DiscoveryError::Limit)?;
        // Wire TTL is never evidence of local freshness and isn't part of a handle.
        ad.ttl = None;
        if let Some(entry) = self.entries.get_mut(&ad.instance) {
            if entry.advertisement == ad {
                entry.expires = expires;
                return Ok(entry.handle);
            }
        } else if self.entries.len() >= 32 {
            return Err(DiscoveryError::Limit);
        }
        let sequence = self.sequence.checked_add(1).ok_or(DiscoveryError::Limit)?;
        let handle = CandidateHandle {
            window: self.window,
            sequence,
        };
        self.sequence = sequence;
        self.entries.insert(
            ad.instance.clone(),
            Entry {
                advertisement: ad,
                handle,
                expires,
            },
        );
        Ok(handle)
    }
    pub fn remove(&mut self, instance: &str, now: u64) -> Result<(), DiscoveryError> {
        self.current(now)?;
        if !opaque(instance) {
            return Err(DiscoveryError::Invalid);
        }
        self.entries.remove(&instance.to_ascii_lowercase());
        Ok(())
    }
    pub fn candidates(&mut self, now: u64) -> Result<Vec<LocatorView>, DiscoveryError> {
        self.current(now)?;
        Ok(self
            .entries
            .values()
            .map(|entry| LocatorView {
                handle: entry.handle,
                version: entry.advertisement.version,
                pairable: entry.advertisement.pairable,
            })
            .collect())
    }
    pub fn select(
        &mut self,
        handle: CandidateHandle,
        now: u64,
    ) -> Result<SelectedLocator, DiscoveryError> {
        self.current(now)?;
        let entry = self
            .entries
            .values()
            .find(|entry| entry.handle == handle)
            .ok_or(DiscoveryError::Stale)?;
        if handle.window != self.window {
            return Err(DiscoveryError::Stale);
        }
        if entry.advertisement.version != 2 || !entry.advertisement.pairable {
            return Err(DiscoveryError::Incompatible);
        }
        Ok(SelectedLocator {
            handle,
            rendezvous: entry.advertisement.instance.clone(),
            addresses: entry.advertisement.addresses.clone(),
        })
    }

    /// Atomically consumes the current discovery window after selecting one
    /// exact current handle. No later handle from the same window can begin a
    /// second transport attempt.
    pub fn select_once(
        &mut self,
        handle: CandidateHandle,
        now: u64,
    ) -> Result<SelectedLocator, DiscoveryError> {
        let selected = self.select(handle, now)?;
        self.deadline = None;
        self.entries.clear();
        Ok(selected)
    }
}

fn opaque(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn unicast(address: SocketAddr) -> bool {
    address.port() != 0
        && !address.ip().is_unspecified()
        && !address.ip().is_multicast()
        && !matches!(address.ip(),std::net::IpAddr::V4(ip) if ip.is_broadcast())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocatorEvent {
    Observed(Advertisement),
    Removed(String),
}

/// Browse only: deliberately has no register/publish/connect operation.
/// Construction requires an explicit local discovery gesture. The watchdog
/// closes sockets after five minutes even when the UI stops polling.
pub struct GuidedMdns {
    daemon: mdns_sd::ServiceDaemon,
    receiver: mdns_sd::Receiver<mdns_sd::ServiceEvent>,
    pending_receiver: Option<mdns_sd::Receiver<mdns_sd::ServiceEvent>>,
    pending_started: bool,
    monitor: mdns_sd::Receiver<mdns_sd::DaemonEvent>,
    refresh_every: std::time::Duration,
    refresh_at: std::time::Instant,
    stop: std::sync::mpsc::Sender<()>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl GuidedMdns {
    pub fn start() -> Result<Self, DiscoveryError> {
        let daemon = mdns_sd::ServiceDaemon::new().map_err(|_| DiscoveryError::Unavailable)?;
        // Keep normal LAN interfaces and also permit two product processes on
        // one host to discover each other through the real mDNS path.
        daemon
            .enable_interface(mdns_sd::IfKind::LoopbackV4)
            .map_err(|_| DiscoveryError::Unavailable)?;
        Self::from_daemon(daemon)
    }
    fn from_daemon(daemon: mdns_sd::ServiceDaemon) -> Result<Self, DiscoveryError> {
        Self::from_daemon_with_timing(
            daemon,
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(60),
        )
    }
    #[cfg(test)]
    fn from_daemon_with_duration(
        daemon: mdns_sd::ServiceDaemon,
        duration: std::time::Duration,
    ) -> Result<Self, DiscoveryError> {
        Self::from_daemon_with_timing(daemon, duration, duration / 2)
    }
    fn from_daemon_with_timing(
        daemon: mdns_sd::ServiceDaemon,
        duration: std::time::Duration,
        refresh_every: std::time::Duration,
    ) -> Result<Self, DiscoveryError> {
        if refresh_every.is_zero() || refresh_every >= duration {
            return Err(DiscoveryError::Invalid);
        }
        let result = (|| {
            let monitor = daemon.monitor().map_err(|_| DiscoveryError::Unavailable)?;
            let receiver = daemon
                .browse(crate::mdns::SERVICE_TYPE)
                .map_err(|_| DiscoveryError::Unavailable)?;
            Ok((monitor, receiver))
        })();
        let (monitor, receiver) = match result {
            Ok(value) => value,
            Err(error) => {
                let _ = daemon.shutdown();
                return Err(error);
            }
        };
        let (stop, signal) = std::sync::mpsc::channel();
        let cleanup = daemon.clone();
        let worker = std::thread::Builder::new()
            .name("pairing-discovery-expiry".into())
            .spawn(move || {
                let _ = signal.recv_timeout(duration);
                let _ = cleanup.stop_browse(crate::mdns::SERVICE_TYPE);
                let _ = cleanup.shutdown();
            });
        match worker {
            Ok(worker) => Ok(Self {
                daemon,
                receiver,
                pending_receiver: None,
                pending_started: false,
                monitor,
                refresh_every,
                refresh_at: std::time::Instant::now()
                    .checked_add(refresh_every)
                    .ok_or(DiscoveryError::Limit)?,
                stop,
                worker: Some(worker),
            }),
            Err(_) => {
                let _ = daemon.shutdown();
                Err(DiscoveryError::Unavailable)
            }
        }
    }
    pub fn poll(&mut self) -> Result<Vec<LocatorEvent>, DiscoveryError> {
        let now = std::time::Instant::now();
        if now >= self.refresh_at && self.pending_receiver.is_none() {
            self.pending_receiver = Some(
                self.daemon
                    .browse(crate::mdns::SERVICE_TYPE)
                    .map_err(|_| DiscoveryError::Unavailable)?,
            );
            self.refresh_at = now
                .checked_add(self.refresh_every)
                .ok_or(DiscoveryError::Limit)?;
        }
        // At most 16 monitor + 16 browse events per call; never drain an
        // attacker-controlled queue to exhaustion on the UI/control thread.
        for _ in 0..16 {
            match self.monitor.recv_timeout(std::time::Duration::ZERO) {
                Ok(mdns_sd::DaemonEvent::Error(_)) => return Err(DiscoveryError::Unavailable),
                Ok(_) => {}
                Err(mdns_sd::RecvTimeoutError::Timeout) => break,
                Err(_) => return Err(DiscoveryError::Unavailable),
            }
        }
        let mut events = Vec::new();
        let mut remaining = 16;
        if self.pending_started {
            let old_empty =
                drain_service_events(&self.receiver, &mut remaining, 16, &mut events)?.0;
            if old_empty {
                self.receiver = self.pending_receiver.take().unwrap();
                self.pending_started = false;
            }
            return Ok(events);
        }
        drain_service_events(
            &self.receiver,
            &mut remaining,
            if self.pending_receiver.is_some() {
                8
            } else {
                16
            },
            &mut events,
        )?;
        if let Some(pending) = self.pending_receiver.as_ref() {
            let (_, started) = drain_service_events(pending, &mut remaining, 8, &mut events)?;
            self.pending_started |= started;
        }
        if self.pending_started && remaining > 0 {
            // SearchStarted proves the replacement listener is live. Drain the old
            // receiver once more after that boundary so a queued withdrawal cannot
            // be lost between the first drain and the listener handoff.
            let old_empty_after_start =
                drain_service_events(&self.receiver, &mut remaining, 16, &mut events)?.0;
            if old_empty_after_start {
                self.receiver = self.pending_receiver.take().unwrap();
                self.pending_started = false;
            }
        }
        Ok(events)
    }
}

fn drain_service_events(
    receiver: &mdns_sd::Receiver<mdns_sd::ServiceEvent>,
    remaining: &mut usize,
    limit: usize,
    events: &mut Vec<LocatorEvent>,
) -> Result<(bool, bool), DiscoveryError> {
    let mut started = false;
    for _ in 0..limit.min(*remaining) {
        *remaining -= 1;
        match receiver.recv_timeout(std::time::Duration::ZERO) {
            Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                if let Some(event) = resolved_event(&info) {
                    events.push(event);
                }
            }
            Ok(mdns_sd::ServiceEvent::ServiceRemoved(_, name)) => {
                if let Some(id) = instance(&name) {
                    events.push(LocatorEvent::Removed(id.to_ascii_lowercase()));
                }
            }
            Ok(mdns_sd::ServiceEvent::SearchStarted(_)) => started = true,
            Ok(mdns_sd::ServiceEvent::SearchStopped(_)) => {
                return Err(DiscoveryError::Unavailable);
            }
            Ok(_) => {}
            Err(mdns_sd::RecvTimeoutError::Timeout) => return Ok((true, started)),
            Err(_) => return Err(DiscoveryError::Unavailable),
        }
    }
    Ok((false, started))
}
impl Drop for GuidedMdns {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn instance(name: &str) -> Option<&str> {
    name.strip_suffix(&format!(".{}", crate::mdns::SERVICE_TYPE))
        .filter(|id| opaque(id))
}
fn resolved_event(info: &mdns_sd::ResolvedService) -> Option<LocatorEvent> {
    let id = instance(info.get_fullname())?.to_ascii_lowercase();
    Some(match decode(info) {
        Some(advertisement) => LocatorEvent::Observed(advertisement),
        // A previously valid service that loses required metadata must not
        // leave its earlier selectable projection in the consent catalogue.
        None => LocatorEvent::Removed(id),
    })
}
fn decode(info: &mdns_sd::ResolvedService) -> Option<Advertisement> {
    let id = instance(info.get_fullname())?;
    if info.get_hostname() != format!("{id}.local.")
        || info.get_properties().len() != 2
        || info.get_addresses().len() > 8
    {
        return None;
    }
    let version = match info.get_property_val_str("v")? {
        "1" => 1,
        "2" => 2,
        _ => return None,
    };
    let pairable = match info.get_property_val_str("pairable")? {
        "0" => false,
        "1" => true,
        _ => return None,
    };
    let addresses: Vec<_> = info
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
        .collect();
    if addresses.is_empty() || addresses.iter().any(|a| !unicast(*a)) {
        return None;
    }
    Some(Advertisement {
        instance: id.to_owned(),
        version,
        pairable,
        addresses,
        ttl: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdns::SERVICE_TYPE;
    use std::time::{Duration, Instant};
    #[test]
    fn idle_browser_watchdog_stops_without_ui_poll_or_close() {
        let daemon = mdns_sd::ServiceDaemon::new_with_port(0).unwrap();
        daemon.disable_interface(mdns_sd::IfKind::All).unwrap();
        let mut browser =
            GuidedMdns::from_daemon_with_duration(daemon, Duration::from_millis(20)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        while browser.poll().is_ok() {
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "idle watchdog failed to stop daemon"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn info(extra: bool) -> mdns_sd::ResolvedService {
        let mut props = crate::mdns::txt_records(2, true);
        if extra {
            props.insert("name".into(), "private-name".into());
        }
        mdns_sd::ServiceInfo::new(
            SERVICE_TYPE,
            "11111111111111111111111111111111",
            "11111111111111111111111111111111.local.",
            "127.0.0.1",
            57892,
            props
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>(),
        )
        .unwrap()
        .as_resolved_service()
    }
    #[test]
    fn parser_accepts_only_minimal_metadata_and_opaque_hostname() {
        assert!(decode(&info(false)).is_some());
        assert!(decode(&info(true)).is_none());
        assert!(matches!(
            resolved_event(&info(true)),
            Some(LocatorEvent::Removed(id)) if id == "11111111111111111111111111111111"
        ));
        let bad = mdns_sd::ServiceInfo::new(
            SERVICE_TYPE,
            "11111111111111111111111111111111",
            "private-name.local.",
            "127.0.0.1",
            57892,
            crate::mdns::txt_records(2, true)
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>(),
        )
        .unwrap()
        .as_resolved_service();
        assert!(decode(&bad).is_none());
    }
    #[test]
    fn loopback_browse_and_goodbye_are_real_but_browser_never_publishes() {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let publisher = mdns_sd::ServiceDaemon::new_with_port(port).unwrap();
        publisher.disable_interface(mdns_sd::IfKind::All).unwrap();
        publisher
            .enable_interface(mdns_sd::IfKind::LoopbackV4)
            .unwrap();
        let daemon = mdns_sd::ServiceDaemon::new_with_port(port).unwrap();
        daemon.disable_interface(mdns_sd::IfKind::All).unwrap();
        daemon
            .enable_interface(mdns_sd::IfKind::LoopbackV4)
            .unwrap();
        let mut browser = GuidedMdns::from_daemon_with_timing(
            daemon,
            Duration::from_secs(300),
            Duration::from_millis(250),
        )
        .unwrap();
        let props = crate::mdns::txt_records(2, true)
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let service = mdns_sd::ServiceInfo::new(
            SERVICE_TYPE,
            "22222222222222222222222222222222",
            "22222222222222222222222222222222.local.",
            "127.0.0.1",
            57893,
            props,
        )
        .unwrap();
        let name = service.get_fullname().to_owned();
        publisher.register(service).unwrap();
        let start = Instant::now();
        let mut observations = 0;
        while start.elapsed() < Duration::from_secs(12) {
            let events = browser.poll().unwrap();
            assert!(events.len() <= 32);
            observations += events
                .iter()
                .filter(|e|matches!(e,LocatorEvent::Observed(a) if a.instance=="22222222222222222222222222222222"))
                .count();
            if observations >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(observations >= 2, "stable service is actively re-resolved");
        browser.refresh_at = Instant::now();
        publisher.unregister(&name).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        let mut removed = false;
        while start.elapsed() < Duration::from_secs(5) {
            if browser.poll().unwrap().iter().any(
                |e| matches!(e,LocatorEvent::Removed(id) if id=="22222222222222222222222222222222"),
            ) {
                removed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(removed, "real goodbye removal");
        drop(browser);
        publisher.shutdown().unwrap();
    }
}
