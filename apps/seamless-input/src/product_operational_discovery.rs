use crate::guided_setup::SetupError;
use seamless_discovery::operational::{OperationalEvent, OperationalMdns};
use seamless_transport::pairing_v2::{
    ProductIdentity, ProductOperationalEndpoint, ProductRecoveryEndpoint,
};
use std::{collections::BTreeMap, net::SocketAddr};

const MAX_LOCATORS: usize = 16;
const MAX_ADDRESSES: usize = 8;
const MAX_TTL_MS: u64 = 300_000;

pub(crate) struct OperationalObservation {
    pub(crate) locator: [u8; 16],
    pub(crate) recovery_addresses: Vec<SocketAddr>,
    pub(crate) operational_addresses: Vec<SocketAddr>,
    pub(crate) ttl_ms: u64,
}

pub(crate) struct SelectedOperationalLocator {
    pub(crate) recovery_addresses: Vec<SocketAddr>,
    pub(crate) operational_addresses: Vec<SocketAddr>,
}

pub(crate) struct OperationalCatalogue {
    local_locator: [u8; 16],
    entries: BTreeMap<[u8; 16], (Vec<SocketAddr>, Vec<SocketAddr>, u64)>,
    last_ms: u64,
}

impl OperationalCatalogue {
    pub(crate) fn open(local_locator: [u8; 16], now_ms: u64) -> Result<Self, SetupError> {
        if local_locator == [0; 16] {
            return Err(SetupError::InvalidArguments);
        }
        Ok(Self {
            local_locator,
            entries: BTreeMap::new(),
            last_ms: now_ms,
        })
    }

    pub(crate) fn apply(
        &mut self,
        observation: OperationalObservation,
        now_ms: u64,
    ) -> Result<(), SetupError> {
        self.advance(now_ms)?;
        if observation.locator == [0; 16]
            || observation.recovery_addresses.is_empty()
            || observation.operational_addresses.is_empty()
            || observation.recovery_addresses.len() > MAX_ADDRESSES
            || observation.operational_addresses.len() > MAX_ADDRESSES
            || observation
                .recovery_addresses
                .iter()
                .chain(observation.operational_addresses.iter())
                .any(|address| !unicast(*address))
            || !(1..=MAX_TTL_MS).contains(&observation.ttl_ms)
        {
            return Err(SetupError::InvalidArguments);
        }
        if observation.locator == self.local_locator {
            return Ok(());
        }
        if !self.entries.contains_key(&observation.locator) && self.entries.len() == MAX_LOCATORS {
            return Err(SetupError::Limit);
        }
        let expires_at = now_ms
            .checked_add(observation.ttl_ms)
            .ok_or(SetupError::Limit)?;
        self.entries.insert(
            observation.locator,
            (
                observation.recovery_addresses,
                observation.operational_addresses,
                expires_at,
            ),
        );
        Ok(())
    }

    pub(crate) fn take_current(
        &mut self,
        now_ms: u64,
    ) -> Result<Vec<SelectedOperationalLocator>, SetupError> {
        self.advance(now_ms)?;
        Ok(std::mem::take(&mut self.entries)
            .into_values()
            .map(
                |(recovery_addresses, operational_addresses, _)| SelectedOperationalLocator {
                    recovery_addresses,
                    operational_addresses,
                },
            )
            .collect())
    }

    pub(crate) fn remove(&mut self, locator: [u8; 16], now_ms: u64) -> Result<(), SetupError> {
        self.advance(now_ms)?;
        self.entries.remove(&locator);
        Ok(())
    }

    fn advance(&mut self, now_ms: u64) -> Result<(), SetupError> {
        if now_ms < self.last_ms {
            return Err(SetupError::ClockRollback);
        }
        self.last_ms = now_ms;
        self.entries
            .retain(|_, (_, _, expires_at)| now_ms < *expires_at);
        Ok(())
    }
}

fn unicast(address: SocketAddr) -> bool {
    address.port() != 0
        && !address.ip().is_unspecified()
        && !address.ip().is_multicast()
        && !matches!(address.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
}

pub(crate) struct ProductOperationalDiscovery {
    recovery: ProductRecoveryEndpoint,
    endpoint: ProductOperationalEndpoint,
    mdns: OperationalMdns,
    catalogue: OperationalCatalogue,
}

impl ProductOperationalDiscovery {
    pub(crate) fn start(identity: &ProductIdentity, now_ms: u64) -> Result<Self, SetupError> {
        let mut locator = [0; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut locator);
        if locator == [0; 16] {
            locator[0] = 1;
        }
        let recovery = identity
            .bind_recovery("0.0.0.0:0".parse().unwrap())
            .map_err(|_| SetupError::Unavailable)?;
        let endpoint = identity
            .bind_operational("0.0.0.0:0".parse().unwrap())
            .map_err(|_| SetupError::Unavailable)?;
        let recovery_port = recovery
            .publication_port()
            .map_err(|_| SetupError::Unavailable)?;
        let operational_port = endpoint
            .publication_port()
            .map_err(|_| SetupError::Unavailable)?;
        let mut mdns = OperationalMdns::start().map_err(|_| SetupError::Unavailable)?;
        mdns.publish(locator, recovery_port, operational_port)
            .map_err(|_| SetupError::Unavailable)?;
        Ok(Self {
            recovery,
            endpoint,
            mdns,
            catalogue: OperationalCatalogue::open(locator, now_ms)?,
        })
    }

    pub(crate) fn poll(&mut self, now_ms: u64) -> Result<(), SetupError> {
        for event in self.mdns.poll().map_err(|_| SetupError::Unavailable)? {
            match event {
                OperationalEvent::Observed(observation) => self.catalogue.apply(
                    OperationalObservation {
                        locator: observation.locator,
                        recovery_addresses: observation.recovery_addresses,
                        operational_addresses: observation.operational_addresses,
                        ttl_ms: observation.ttl_ms,
                    },
                    now_ms,
                )?,
                OperationalEvent::Removed(locator) => self.catalogue.remove(locator, now_ms)?,
            }
        }
        Ok(())
    }

    pub(crate) fn take_current(
        &mut self,
        now_ms: u64,
    ) -> Result<Vec<SelectedOperationalLocator>, SetupError> {
        self.poll(now_ms)?;
        self.catalogue.take_current(now_ms)
    }

    pub(crate) fn endpoint(&self) -> &ProductOperationalEndpoint {
        &self.endpoint
    }

    pub(crate) fn recovery(&self) -> &ProductRecoveryEndpoint {
        &self.recovery
    }
}

#[cfg(test)]
mod tests {
    use super::{OperationalCatalogue, OperationalObservation, ProductOperationalDiscovery};
    use seamless_transport::pairing_v2::ProductIdentity;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn observation(locator: u8, port: u16, ttl_ms: u64) -> OperationalObservation {
        OperationalObservation {
            locator: [locator; 16],
            recovery_addresses: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, locator)),
                port,
            )],
            operational_addresses: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, locator)),
                port + 1,
            )],
            ttl_ms,
        }
    }

    #[test]
    fn catalogue_filters_self_replaces_candidates_and_drains_once() {
        let mut catalogue = OperationalCatalogue::open([1; 16], 100).unwrap();
        catalogue.apply(observation(1, 4101, 500), 110).unwrap();
        catalogue.apply(observation(2, 4102, 500), 120).unwrap();
        catalogue.apply(observation(2, 4202, 500), 130).unwrap();

        let selected = catalogue.take_current(131).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected[0].recovery_addresses,
            observation(2, 4202, 500).recovery_addresses
        );
        assert_eq!(
            selected[0].operational_addresses,
            observation(2, 4202, 500).operational_addresses
        );
        assert!(catalogue.take_current(132).unwrap().is_empty());
    }

    #[test]
    fn catalogue_removes_goodbye_before_selection() {
        let mut catalogue = OperationalCatalogue::open([1; 16], 100).unwrap();
        catalogue.apply(observation(2, 4102, 500), 110).unwrap();
        catalogue.remove([2; 16], 120).unwrap();

        assert!(catalogue.take_current(121).unwrap().is_empty());
    }

    #[test]
    fn catalogue_expires_entries_and_rejects_unbounded_or_non_unicast_input() {
        let mut catalogue = OperationalCatalogue::open([1; 16], 100).unwrap();
        catalogue.apply(observation(2, 4102, 10), 100).unwrap();
        assert!(catalogue.take_current(110).unwrap().is_empty());

        let mut too_many_addresses = observation(3, 4103, 500);
        too_many_addresses.recovery_addresses = (1..=9)
            .map(|last| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), 4103))
            .collect();
        assert!(catalogue.apply(too_many_addresses, 120).is_err());

        let mut unspecified = observation(4, 4104, 500);
        unspecified.recovery_addresses = vec!["0.0.0.0:4104".parse().unwrap()];
        assert!(catalogue.apply(unspecified, 120).is_err());
    }

    #[test]
    fn catalogue_capacity_fails_closed_without_eviction() {
        let mut catalogue = OperationalCatalogue::open([255; 16], 0).unwrap();
        for locator in 1..=16 {
            catalogue
                .apply(observation(locator, 4000 + u16::from(locator), 500), 1)
                .unwrap();
        }
        assert!(catalogue.apply(observation(17, 4017, 500), 1).is_err());
        assert_eq!(catalogue.take_current(2).unwrap().len(), 16);
    }

    #[tokio::test]
    async fn product_owner_binds_publishes_and_owns_one_operational_endpoint() {
        let root = tempfile::tempdir().unwrap();
        let identity = ProductIdentity::open_or_create(&root.path().join("identity")).unwrap();
        let mut owner = ProductOperationalDiscovery::start(&identity, 0).unwrap();

        assert!(owner.endpoint().publication_port().unwrap() > 0);
        owner.poll(1).unwrap();
        assert!(owner.take_current(2).unwrap().is_empty());
    }

    #[tokio::test]
    async fn two_product_owners_discover_each_others_distinct_recovery_and_v01_ports() {
        let left_root = tempfile::tempdir().unwrap();
        let right_root = tempfile::tempdir().unwrap();
        let left_identity =
            ProductIdentity::open_or_create(&left_root.path().join("identity")).unwrap();
        let right_identity =
            ProductIdentity::open_or_create(&right_root.path().join("identity")).unwrap();
        let mut left = ProductOperationalDiscovery::start(&left_identity, 0).unwrap();
        let mut right = ProductOperationalDiscovery::start(&right_identity, 0).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut left_seen = Vec::new();
        let mut right_seen = Vec::new();
        while std::time::Instant::now() < deadline
            && (left_seen.is_empty() || right_seen.is_empty())
        {
            let current = left.take_current(1).unwrap();
            if !current.is_empty() {
                left_seen = current;
            }
            let current = right.take_current(1).unwrap();
            if !current.is_empty() {
                right_seen = current;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(left_seen.len(), 1);
        assert_eq!(right_seen.len(), 1);
        for seen in [&left_seen[0], &right_seen[0]] {
            assert!(!seen.recovery_addresses.is_empty());
            assert!(!seen.operational_addresses.is_empty());
            assert_ne!(
                seen.recovery_addresses[0].port(),
                seen.operational_addresses[0].port()
            );
        }
    }
}
