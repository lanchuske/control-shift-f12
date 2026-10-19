use std::net::{IpAddr, SocketAddr};

pub const OPERATIONAL_SERVICE_TYPE: &str = "_csf12-op._udp.local.";

const MAX_ADDRESSES: usize = 8;
const MAX_TTL_MS: u64 = 300_000;
const DAEMON_FRESHNESS_MS: u64 = 120_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalAdvertisement {
    pub locator: [u8; 16],
    pub recovery_addresses: Vec<SocketAddr>,
    pub operational_addresses: Vec<SocketAddr>,
    pub ttl_ms: u64,
}

fn decode_wire(
    instance: &str,
    hostname: &str,
    properties: &[(&str, &str)],
    addresses: &[IpAddr],
    port: u16,
    ttl_ms: u64,
) -> Option<OperationalAdvertisement> {
    let locator = decode_locator(instance)?;
    let properties: std::collections::BTreeMap<_, _> = properties.iter().copied().collect();
    let operational_port = properties
        .get("op")
        .and_then(|value| value.parse::<u16>().ok());
    if hostname != format!("{instance}.local.")
        || properties.len() != 2
        || properties.get("v") != Some(&"2")
        || operational_port.is_none()
        || addresses.is_empty()
        || addresses.len() > MAX_ADDRESSES
        || port == 0
        || operational_port == Some(0)
        || operational_port == Some(port)
        || !(1..=MAX_TTL_MS).contains(&ttl_ms)
    {
        return None;
    }
    let mut endpoints: Vec<_> = addresses
        .iter()
        .copied()
        .filter(|address| unicast_ip(*address))
        .map(|address| SocketAddr::new(address, port))
        .collect();
    endpoints.sort_unstable();
    endpoints.dedup();
    if endpoints.len() != addresses.len() {
        return None;
    }
    let operational_port = operational_port?;
    let operational_addresses = endpoints
        .iter()
        .map(|address| SocketAddr::new(address.ip(), operational_port))
        .collect();
    Some(OperationalAdvertisement {
        locator,
        recovery_addresses: endpoints,
        operational_addresses,
        ttl_ms,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationalEvent {
    Observed(OperationalAdvertisement),
    Removed([u8; 16]),
}

/// A product-owned operational discovery surface. Its wire contract contains
/// only an ephemeral locator and endpoint data; identity is verified later by
/// the pinned TLS certificate, never by mDNS.
pub struct OperationalMdns {
    daemon: mdns_sd::ServiceDaemon,
    receiver: mdns_sd::Receiver<mdns_sd::ServiceEvent>,
    published: Option<String>,
}

impl OperationalMdns {
    pub fn start() -> Result<Self, String> {
        let daemon = mdns_sd::ServiceDaemon::new().map_err(|_| "operational mDNS unavailable")?;
        daemon
            .enable_interface(mdns_sd::IfKind::LoopbackV4)
            .map_err(|_| "operational mDNS interface unavailable")?;
        let receiver = daemon
            .browse(OPERATIONAL_SERVICE_TYPE)
            .map_err(|_| "operational mDNS browse unavailable")?;
        Ok(Self {
            daemon,
            receiver,
            published: None,
        })
    }

    pub fn publish(
        &mut self,
        locator: [u8; 16],
        recovery_port: u16,
        operational_port: u16,
    ) -> Result<(), String> {
        if self.published.is_some()
            || locator == [0; 16]
            || recovery_port == 0
            || operational_port == 0
            || recovery_port == operational_port
        {
            return Err("invalid operational mDNS publication".into());
        }
        let instance = encode_locator(locator);
        let hostname = format!("{instance}.local.");
        let properties = std::collections::HashMap::from([
            ("v".to_owned(), "2".to_owned()),
            ("op".to_owned(), operational_port.to_string()),
        ]);
        let info = mdns_sd::ServiceInfo::new(
            OPERATIONAL_SERVICE_TYPE,
            &instance,
            &hostname,
            "",
            recovery_port,
            properties,
        )
        .map_err(|_| "invalid operational mDNS advertisement")?
        .enable_addr_auto();
        let fullname = info.get_fullname().to_owned();
        self.daemon
            .register(info)
            .map_err(|_| "operational mDNS publication failed")?;
        self.published = Some(fullname);
        Ok(())
    }

    /// Drains at most 16 ready events so an untrusted LAN cannot monopolize
    /// the product control loop.
    pub fn poll(&self) -> Result<Vec<OperationalEvent>, String> {
        let mut events = Vec::new();
        for _ in 0..16 {
            match self.receiver.recv_timeout(std::time::Duration::ZERO) {
                Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                    if self.published.as_deref() == Some(info.get_fullname()) {
                        continue;
                    }
                    if let Some(event) = decode_resolved(&info) {
                        events.push(OperationalEvent::Observed(event));
                    }
                }
                Ok(mdns_sd::ServiceEvent::ServiceRemoved(_, fullname)) => {
                    if let Some(locator) =
                        instance_from_fullname(&fullname).and_then(decode_locator)
                    {
                        events.push(OperationalEvent::Removed(locator));
                    }
                }
                Ok(mdns_sd::ServiceEvent::SearchStopped(_)) => {
                    return Err("operational mDNS browser stopped".into());
                }
                Ok(_) => {}
                Err(mdns_sd::RecvTimeoutError::Timeout) => break,
                Err(_) => return Err("operational mDNS browser unavailable".into()),
            }
        }
        Ok(events)
    }
}

impl Drop for OperationalMdns {
    fn drop(&mut self) {
        if let Some(fullname) = &self.published {
            let _ = self.daemon.unregister(fullname);
        }
        let _ = self.daemon.stop_browse(OPERATIONAL_SERVICE_TYPE);
        let _ = self.daemon.shutdown();
    }
}

fn decode_resolved(info: &mdns_sd::ResolvedService) -> Option<OperationalAdvertisement> {
    let instance = instance_from_fullname(info.get_fullname())?;
    let properties: Vec<_> = info
        .get_properties()
        .iter()
        .map(|property| (property.key(), property.val_str()))
        .collect();
    let addresses: Vec<_> = info
        .get_addresses()
        .iter()
        .filter_map(|address| match address {
            mdns_sd::ScopedIp::V4(address) => Some(IpAddr::V4(*address.addr())),
            mdns_sd::ScopedIp::V6(address) => Some(IpAddr::V6(*address.addr())),
            _ => None,
        })
        .collect();
    decode_wire(
        instance,
        info.get_hostname(),
        &properties,
        &addresses,
        info.get_port(),
        DAEMON_FRESHNESS_MS,
    )
}

fn instance_from_fullname(fullname: &str) -> Option<&str> {
    fullname.strip_suffix(&format!(".{OPERATIONAL_SERVICE_TYPE}"))
}

fn encode_locator(locator: [u8; 16]) -> String {
    locator.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_locator(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut locator = [0; 16];
    for (index, byte) in locator.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16).ok()?;
    }
    Some(locator)
}

fn unicast_ip(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && !matches!(address, IpAddr::V4(ip) if ip.is_broadcast())
}

#[cfg(test)]
mod tests {
    use super::{OPERATIONAL_SERVICE_TYPE, decode_wire};
    use std::net::IpAddr;

    #[test]
    fn operational_wire_v2_keeps_recovery_and_v01_on_distinct_ports() {
        assert_ne!(OPERATIONAL_SERVICE_TYPE, crate::mdns::SERVICE_TYPE);
        let locator = "11111111111111111111111111111111";
        let decoded = decode_wire(
            locator,
            "11111111111111111111111111111111.local.",
            &[("op", "5312"), ("v", "2")],
            &["192.0.2.10".parse::<IpAddr>().unwrap()],
            4312,
            15_000,
        )
        .unwrap();

        assert_eq!(decoded.locator, [0x11; 16]);
        assert_eq!(
            decoded.recovery_addresses,
            vec!["192.0.2.10:4312".parse().unwrap()]
        );
        assert_eq!(
            decoded.operational_addresses,
            vec!["192.0.2.10:5312".parse().unwrap()]
        );
        assert_eq!(decoded.ttl_ms, 15_000);
    }

    #[test]
    fn operational_wire_rejects_unknown_fields_versions_and_address_overflow() {
        let locator = "22222222222222222222222222222222";
        let address = "192.0.2.20".parse::<IpAddr>().unwrap();
        assert!(
            decode_wire(
                locator,
                "22222222222222222222222222222222.local.",
                &[("v", "1"), ("pairable", "1")],
                &[address],
                4312,
                15_000,
            )
            .is_none()
        );
        assert!(
            decode_wire(
                locator,
                "22222222222222222222222222222222.local.",
                &[("v", "2")],
                &[address],
                4312,
                15_000,
            )
            .is_none()
        );
        assert!(
            decode_wire(
                locator,
                "22222222222222222222222222222222.local.",
                &[("v", "1")],
                &[address; 9],
                4312,
                15_000,
            )
            .is_none()
        );
    }
}
