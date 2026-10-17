//! Engine-only, bounded advertisement/listener ownership. No IPC projection,
//! connection export, admission writer or runtime capability is provided here.
use crate::guided_setup::{DiscoveryWindowGeneration, PairingDiscoveryWindow, SetupError};
use rustls::pki_types::PrivateKeyDer;
use seamless_transport::pairing_v2::provisional_tls::ProvisionalEndpoint;
use std::{
    sync::{Arc, Mutex, Weak, mpsc},
    thread::JoinHandle,
    time::{Duration, Instant},
};

trait LeaseEndpoint: Send {
    fn healthy(&self) -> bool;
}
impl LeaseEndpoint for ProvisionalEndpoint {
    fn healthy(&self) -> bool {
        self.local_addr().is_ok()
    }
}
trait Advertisement: Send {
    fn healthy(&mut self) -> bool;
    fn withdraw(&mut self) -> Result<(), SetupError>;
}
struct LeaseResources {
    endpoint: Option<Box<dyn LeaseEndpoint>>,
    publication: Option<Box<dyn Advertisement>>,
}
impl LeaseResources {
    fn new(endpoint: Box<dyn LeaseEndpoint>, publication: Box<dyn Advertisement>) -> Self {
        Self {
            endpoint: Some(endpoint),
            publication: Some(publication),
        }
    }
    fn healthy(&mut self) -> bool {
        self.endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.healthy())
            && self
                .publication
                .as_mut()
                .is_some_and(|publication| publication.healthy())
    }
    fn close(mut self) -> Result<(), SetupError> {
        self.release()
    }
    fn release(&mut self) -> Result<(), SetupError> {
        let result = if let Some(mut publication) = self.publication.take() {
            let result = publication.withdraw();
            drop(publication);
            result
        } else {
            Ok(())
        };
        // This order is explicit rather than relying on struct field drop order.
        drop(self.endpoint.take());
        result
    }
}
impl Drop for LeaseResources {
    fn drop(&mut self) {
        let _ = self.release();
    }
}
struct LeaseState {
    resources: Option<LeaseResources>,
    last_ms: u64,
    terminal: Option<SetupError>,
}
impl LeaseState {
    fn stop(&mut self, reason: Option<SetupError>) -> Result<(), SetupError> {
        if let Some(resources) = self.resources.take() {
            let result = resources.close();
            self.terminal = reason.or(result.err());
        }
        self.terminal.map_or(Ok(()), Err)
    }
}

pub(crate) struct PairingLeaseRevocation(Weak<Mutex<LeaseState>>);
impl PairingLeaseRevocation {
    pub(crate) fn revoke(self) -> Result<(), SetupError> {
        if let Some(state) = self.0.upgrade() {
            state.lock().unwrap_or_else(|e| e.into_inner()).stop(None)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingLeaseEnd {
    Cancelled,
    EndpointFailed,
    AttemptCompleted,
}

/// Move-only engine resource. Credentials enter only the strict transport
/// constructor; neither credentials, rendezvous nor addresses can be read back.
/// A generation authorizes at most one lease, including after cancellation.
/// ```compile_fail
/// use seamless_input::product_pairing_adapter::PairingAdvertisementLease;
/// fn leak(lease: PairingAdvertisementLease) { let _ = lease.endpoint; }
/// ```
/// ```compile_fail
/// use seamless_input::product_pairing_adapter::PairingAdvertisementLease;
/// fn project(lease: &PairingAdvertisementLease) {
///     let _ = serde_json::to_value(lease);
/// }
/// ```
pub struct PairingAdvertisementLease {
    generation: DiscoveryWindowGeneration,
    expires_at_ms: u64,
    state: Arc<Mutex<LeaseState>>,
    stop: mpsc::Sender<()>,
    worker: Option<JoinHandle<()>>,
}
impl PairingAdvertisementLease {
    /// Must run inside the engine's Tokio runtime. The bind address/port and
    /// protocol configuration are fixed here and cannot be supplied by a host.
    pub fn open(
        window: &mut PairingDiscoveryWindow,
        generation: DiscoveryWindowGeneration,
        now_ms: u64,
        certificate: Vec<u8>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, SetupError> {
        Self::open_with(window, generation, now_ms, || {
            // One OS-allocated local UDP port, strict pairing-v2 only.
            let endpoint =
                ProvisionalEndpoint::bind(([0, 0, 0, 0], 0).into(), certificate, private_key)
                    .map_err(|_| SetupError::Unavailable)?;
            let port = endpoint
                .local_addr()
                .map_err(|_| SetupError::Unavailable)?
                .port();
            let publication = EngineAdvertisement::start(port)?;
            Ok(LeaseResources::new(
                Box::new(endpoint),
                Box::new(publication),
            ))
        })
    }

    fn open_with(
        window: &mut PairingDiscoveryWindow,
        generation: DiscoveryWindowGeneration,
        now_ms: u64,
        factory: impl FnOnce() -> Result<LeaseResources, SetupError>,
    ) -> Result<Self, SetupError> {
        let deadline = window.authorize_lease(generation, now_ms)?;
        let started = Instant::now();
        let expires = started
            .checked_add(Duration::from_millis(deadline - now_ms))
            .ok_or(SetupError::Limit)?;
        let resources = match factory() {
            Ok(resources) => resources,
            Err(error) => {
                let _ = window.close(now_ms);
                return Err(error);
            }
        };
        if Instant::now() >= expires {
            let _ = resources.close();
            let _ = window.close(now_ms);
            return Err(SetupError::Expired);
        }
        let state = Arc::new(Mutex::new(LeaseState {
            resources: Some(resources),
            last_ms: now_ms,
            terminal: None,
        }));
        let (stop, signal) = mpsc::channel();
        let watched = state.clone();
        let worker = std::thread::Builder::new()
            .name("pairing-advertisement-expiry".into())
            .spawn(move || {
                loop {
                    let remaining = expires.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        let _ = watched
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .stop(Some(SetupError::Expired));
                        break;
                    }
                    match signal.recv_timeout(remaining.min(Duration::from_millis(20))) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                            let _ = watched.lock().unwrap_or_else(|e| e.into_inner()).stop(None);
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            let mut state = watched.lock().unwrap_or_else(|e| e.into_inner());
                            let Some(resources) = state.resources.as_mut() else {
                                break;
                            };
                            if !resources.healthy() {
                                let _ = state.stop(Some(SetupError::Unavailable));
                                break;
                            }
                        }
                    }
                }
            });
        let worker = match worker {
            Ok(worker) => worker,
            Err(_) => {
                let _ = state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .stop(Some(SetupError::Unavailable));
                let _ = window.close(now_ms);
                return Err(SetupError::Unavailable);
            }
        };
        window.attach_lease(PairingLeaseRevocation(Arc::downgrade(&state)));
        Ok(Self {
            generation,
            expires_at_ms: deadline,
            state,
            stop,
            worker: Some(worker),
        })
    }

    pub fn generation(&self) -> DiscoveryWindowGeneration {
        self.generation
    }

    pub fn is_active(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .resources
            .is_some()
    }

    /// Engine monotonic-clock checkpoint. The watchdog independently expires
    /// idle leases; injected timestamps make exact boundaries deterministic.
    pub fn check(&self, now_ms: u64) -> Result<(), SetupError> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.resources.is_none() {
            return Err(state.terminal.unwrap_or(SetupError::InvalidState));
        }
        let error = if now_ms < state.last_ms {
            Some(SetupError::ClockRollback)
        } else if now_ms >= self.expires_at_ms {
            Some(SetupError::Expired)
        } else if !state.resources.as_mut().unwrap().healthy() {
            Some(SetupError::Unavailable)
        } else {
            None
        };
        if let Some(error) = error {
            return state.stop(Some(error));
        }
        state.last_ms = now_ms;
        Ok(())
    }

    pub fn finish(&self, reason: PairingLeaseEnd) -> Result<(), SetupError> {
        let failure =
            (reason == PairingLeaseEnd::EndpointFailed).then_some(SetupError::Unavailable);
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stop(failure)
    }
}
impl Drop for PairingAdvertisementLease {
    fn drop(&mut self) {
        let _ = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stop(None);
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn advertisement_info(rendezvous: &str, port: u16) -> Result<mdns_sd::ServiceInfo, SetupError> {
    if rendezvous.len() != 32 || !rendezvous.bytes().all(|b| b.is_ascii_hexdigit()) || port == 0 {
        return Err(SetupError::InvalidArguments);
    }
    mdns_sd::ServiceInfo::new(
        seamless_discovery::mdns::SERVICE_TYPE,
        rendezvous,
        &format!("{rendezvous}.local."),
        "",
        port,
        [("v", "2"), ("pairable", "1")].as_slice(),
    )
    .map(|info| info.enable_addr_auto())
    .map_err(|_| SetupError::Unavailable)
}
type DaemonAcknowledgement = Box<dyn FnOnce(Duration) -> Result<(), SetupError> + Send>;

// Keep enqueueing a command distinct from waiting for its completion: mdns-sd
// can return an API error after a command has already entered its queue.
trait AdvertisementDriver: Send {
    fn prepare(&mut self) -> Result<(), SetupError>;
    fn register(&mut self, info: mdns_sd::ServiceInfo) -> Result<(), SetupError>;
    fn healthy(&mut self) -> bool;
    fn unregister(&mut self, name: &str) -> Result<DaemonAcknowledgement, SetupError>;
    fn shutdown(&mut self) -> Result<DaemonAcknowledgement, SetupError>;
}
struct MdnsAdvertisementDriver {
    daemon: mdns_sd::ServiceDaemon,
    monitor: Option<mdns_sd::Receiver<mdns_sd::DaemonEvent>>,
}
impl AdvertisementDriver for MdnsAdvertisementDriver {
    fn prepare(&mut self) -> Result<(), SetupError> {
        // The listener is IPv4-only; never advertise unusable IPv6 locators.
        self.daemon
            .disable_interface(mdns_sd::IfKind::IPv6)
            .map_err(|_| SetupError::Unavailable)?;
        self.monitor = Some(self.daemon.monitor().map_err(|_| SetupError::Unavailable)?);
        Ok(())
    }
    fn register(&mut self, info: mdns_sd::ServiceInfo) -> Result<(), SetupError> {
        self.daemon
            .register(info)
            .map_err(|_| SetupError::Unavailable)
    }
    fn healthy(&mut self) -> bool {
        let Some(monitor) = &self.monitor else {
            return false;
        };
        for _ in 0..16 {
            match monitor.recv_timeout(Duration::ZERO) {
                Ok(mdns_sd::DaemonEvent::Error(_)) => return false,
                Ok(_) => {}
                Err(mdns_sd::RecvTimeoutError::Timeout) => return true,
                Err(_) => return false,
            }
        }
        true
    }
    fn unregister(&mut self, name: &str) -> Result<DaemonAcknowledgement, SetupError> {
        let ack = self
            .daemon
            .unregister(name)
            .map_err(|_| SetupError::Unavailable)?;
        Ok(Box::new(move |timeout| {
            ack.recv_timeout(timeout)
                .map(|_| ())
                .map_err(|_| SetupError::Unavailable)
        }))
    }
    fn shutdown(&mut self) -> Result<DaemonAcknowledgement, SetupError> {
        let ack = self
            .daemon
            .shutdown()
            .map_err(|_| SetupError::Unavailable)?;
        Ok(Box::new(move |timeout| match ack.recv_timeout(timeout) {
            Ok(mdns_sd::DaemonStatus::Shutdown) => Ok(()),
            _ => Err(SetupError::Unavailable),
        }))
    }
}
struct EngineAdvertisement {
    driver: Box<dyn AdvertisementDriver>,
    name: String,
    withdrawn: bool,
}
impl EngineAdvertisement {
    fn start(port: u16) -> Result<Self, SetupError> {
        use rand::RngCore;
        let mut token = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut token);
        let rendezvous: String = token.iter().map(|b| format!("{b:02x}")).collect();
        let info = advertisement_info(&rendezvous, port)?;
        let daemon = mdns_sd::ServiceDaemon::new().map_err(|_| SetupError::Unavailable)?;
        Self::start_with_driver(
            info,
            Box::new(MdnsAdvertisementDriver {
                daemon,
                monitor: None,
            }),
        )
    }
    fn start_with_driver(
        info: mdns_sd::ServiceInfo,
        driver: Box<dyn AdvertisementDriver>,
    ) -> Result<Self, SetupError> {
        // Acquire cleanup ownership before any command can be enqueued. A
        // register error can mean only its wakeup failed, not that it was absent.
        let mut publication = Self {
            driver,
            name: info.get_fullname().into(),
            withdrawn: false,
        };
        let result = publication
            .driver
            .prepare()
            .and_then(|_| publication.driver.register(info));
        if let Err(error) = result {
            // The endpoint caller cannot resume (and drop its endpoint) until
            // both bounded acknowledgement waits have completed or failed.
            publication.withdraw()?;
            return Err(error);
        }
        Ok(publication)
    }
}
impl Advertisement for EngineAdvertisement {
    fn healthy(&mut self) -> bool {
        self.driver.healthy()
    }
    fn withdraw(&mut self) -> Result<(), SetupError> {
        if self.withdrawn {
            return Ok(());
        }
        self.withdrawn = true;
        // Await command processing before releasing the endpoint. This proves
        // local daemon withdrawal, not remote DNS cache eviction or packet loss.
        let unregistered = self
            .driver
            .unregister(&self.name)
            .and_then(|ack| ack(Duration::from_secs(1)))
            .is_ok();
        let stopped = self
            .driver
            .shutdown()
            .and_then(|ack| ack(Duration::from_secs(1)))
            .is_ok();
        if unregistered && stopped {
            Ok(())
        } else {
            Err(SetupError::Unavailable)
        }
    }
}
impl Drop for EngineAdvertisement {
    fn drop(&mut self) {
        let _ = self.withdraw();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Probe {
        advertising: bool,
        listener: bool,
        failed: bool,
        publication_failed: bool,
        withdrawal_failed: bool,
        events: Vec<&'static str>,
    }
    struct Endpoint(Arc<Mutex<Probe>>);
    impl LeaseEndpoint for Endpoint {
        fn healthy(&self) -> bool {
            !self.0.lock().unwrap().failed
        }
    }
    impl Drop for Endpoint {
        fn drop(&mut self) {
            let mut probe = self.0.lock().unwrap();
            probe.listener = false;
            probe.events.push("endpoint_dropped");
        }
    }
    struct Publication(Arc<Mutex<Probe>>);
    impl Advertisement for Publication {
        fn healthy(&mut self) -> bool {
            !self.0.lock().unwrap().publication_failed
        }
        fn withdraw(&mut self) -> Result<(), SetupError> {
            let mut probe = self.0.lock().unwrap();
            assert!(probe.listener, "withdrawal must precede endpoint drop");
            probe.advertising = false;
            probe.events.push("withdrawn");
            if probe.withdrawal_failed {
                Err(SetupError::Unavailable)
            } else {
                Ok(())
            }
        }
    }
    impl Drop for Publication {
        fn drop(&mut self) {
            self.0.lock().unwrap().events.push("publisher_dropped");
        }
    }
    struct Fixture {
        window: PairingDiscoveryWindow,
        probe: Arc<Mutex<Probe>>,
    }
    impl Fixture {
        fn new() -> Self {
            Self {
                window: PairingDiscoveryWindow::default(),
                probe: Arc::new(Mutex::new(Probe::default())),
            }
        }
        fn lease(
            &mut self,
            generation: DiscoveryWindowGeneration,
            now: u64,
        ) -> Result<PairingAdvertisementLease, SetupError> {
            let probe = self.probe.clone();
            PairingAdvertisementLease::open_with(&mut self.window, generation, now, move || {
                {
                    let mut state = probe.lock().unwrap();
                    state.advertising = true;
                    state.listener = true;
                }
                Ok(LeaseResources::new(
                    Box::new(Endpoint(probe.clone())),
                    Box::new(Publication(probe)),
                ))
            })
        }
        fn assert_closed(&self) {
            let probe = self.probe.lock().unwrap();
            assert!(!probe.advertising);
            assert!(!probe.listener);
            assert_eq!(
                probe.events,
                ["withdrawn", "publisher_dropped", "endpoint_dropped"]
            );
        }
    }

    #[test]
    fn browsing_without_a_lease_never_opens_a_listener() {
        let mut fixture = Fixture::new();
        fixture.window.open(10).unwrap();
        assert!(!fixture.probe.lock().unwrap().listener);
        fixture.window.close(11).unwrap();
        assert!(fixture.probe.lock().unwrap().events.is_empty());
    }

    #[test]
    fn closing_the_pairing_window_withdraws_before_endpoint_drop() {
        let mut fixture = Fixture::new();
        let generation = fixture.window.open(10).unwrap();
        let lease = fixture.lease(generation, 10).unwrap();
        fixture.window.close(11).unwrap();
        assert!(!lease.is_active());
        drop(lease);
        fixture.assert_closed();
    }

    #[test]
    fn dropping_unattached_resources_also_withdraws_before_endpoint_drop() {
        let fixture = Fixture::new();
        {
            let mut probe = fixture.probe.lock().unwrap();
            probe.advertising = true;
            probe.listener = true;
        }
        drop(LeaseResources::new(
            Box::new(Endpoint(fixture.probe.clone())),
            Box::new(Publication(fixture.probe.clone())),
        ));
        fixture.assert_closed();
    }

    #[test]
    fn expiry_and_clock_rollback_withdraw_and_drop_resources() {
        for (now, expected) in [
            (300_010, SetupError::Expired),
            (9, SetupError::ClockRollback),
        ] {
            let mut fixture = Fixture::new();
            let generation = fixture.window.open(10).unwrap();
            let lease = fixture.lease(generation, 10).unwrap();
            assert_eq!(lease.check(now), Err(expected));
            fixture.assert_closed();
        }
    }

    #[test]
    fn idle_expiry_needs_no_ui_request_or_poll() {
        let mut fixture = Fixture::new();
        let generation = fixture.window.open(0).unwrap();
        let lease = fixture.lease(generation, 299_990).unwrap();
        let started = Instant::now();
        while lease.is_active() {
            assert!(started.elapsed() < Duration::from_secs(2));
            std::thread::sleep(Duration::from_millis(2));
        }
        fixture.assert_closed();
    }

    #[test]
    fn cancellation_endpoint_fault_completion_and_drop_are_terminal() {
        for reason in [
            PairingLeaseEnd::Cancelled,
            PairingLeaseEnd::EndpointFailed,
            PairingLeaseEnd::AttemptCompleted,
        ] {
            let mut fixture = Fixture::new();
            let generation = fixture.window.open(0).unwrap();
            let lease = fixture.lease(generation, 0).unwrap();
            let _ = lease.finish(reason);
            assert!(!lease.is_active());
            assert!(fixture.lease(generation, 1).is_err());
            drop(lease);
            fixture.assert_closed();
        }
        let mut fixture = Fixture::new();
        let generation = fixture.window.open(0).unwrap();
        drop(fixture.lease(generation, 0).unwrap());
        fixture.assert_closed();
    }

    #[test]
    fn endpoint_health_failure_fails_closed() {
        let mut fixture = Fixture::new();
        let generation = fixture.window.open(0).unwrap();
        let lease = fixture.lease(generation, 0).unwrap();
        fixture.probe.lock().unwrap().failed = true;
        assert_eq!(lease.check(1), Err(SetupError::Unavailable));
        fixture.assert_closed();
    }

    #[test]
    fn publisher_failure_and_withdrawal_error_release_the_endpoint_in_order() {
        for withdrawal_failure in [false, true] {
            let mut fixture = Fixture::new();
            let generation = fixture.window.open(0).unwrap();
            let lease = fixture.lease(generation, 0).unwrap();
            {
                let mut probe = fixture.probe.lock().unwrap();
                probe.publication_failed = !withdrawal_failure;
                probe.withdrawal_failed = withdrawal_failure;
            }
            let result = if withdrawal_failure {
                fixture.window.close(1)
            } else {
                lease.check(1)
            };
            assert_eq!(result, Err(SetupError::Unavailable));
            fixture.assert_closed();
        }
    }

    #[test]
    fn slow_resource_creation_cannot_return_a_lease_after_the_deadline() {
        let mut fixture = Fixture::new();
        let generation = fixture.window.open(0).unwrap();
        let probe = fixture.probe.clone();
        let result = PairingAdvertisementLease::open_with(
            &mut fixture.window,
            generation,
            299_999,
            move || {
                std::thread::sleep(Duration::from_millis(5));
                {
                    let mut state = probe.lock().unwrap();
                    state.advertising = true;
                    state.listener = true;
                }
                Ok(LeaseResources::new(
                    Box::new(Endpoint(probe.clone())),
                    Box::new(Publication(probe)),
                ))
            },
        );
        assert!(matches!(result, Err(SetupError::Expired)));
        fixture.assert_closed();
    }

    #[test]
    fn failed_creation_closes_the_window_and_cannot_retry_the_same_generation() {
        let mut fixture = Fixture::new();
        let generation = fixture.window.open(10).unwrap();
        assert!(matches!(
            PairingAdvertisementLease::open_with(&mut fixture.window, generation, 10, || Err(
                SetupError::Unavailable
            )),
            Err(SetupError::Unavailable)
        ));
        assert!(fixture.lease(generation, 11).is_err());
        assert!(!fixture.probe.lock().unwrap().listener);
        let fresh = fixture.window.open(12).unwrap();
        drop(fixture.lease(fresh, 12).unwrap());
        fixture.assert_closed();
    }

    #[tokio::test]
    async fn real_provisional_port_is_owned_until_withdrawal_and_released_after_close() {
        use rustls::pki_types::PrivatePkcs8KeyDer;
        use std::net::{SocketAddr, UdpSocket};
        struct PortPublication(SocketAddr, Arc<Mutex<bool>>);
        impl Advertisement for PortPublication {
            fn healthy(&mut self) -> bool {
                true
            }
            fn withdraw(&mut self) -> Result<(), SetupError> {
                assert!(
                    UdpSocket::bind(self.0).is_err(),
                    "endpoint was dropped before withdrawal"
                );
                *self.1.lock().unwrap() = true;
                Ok(())
            }
        }
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut certificate = rcgen::CertificateParams::default();
        certificate.is_ca = rcgen::IsCa::ExplicitNoCa;
        certificate.subject_alt_names = vec![rcgen::SanType::URI(
            "urn:control-shift-f12:identity".try_into().unwrap(),
        )];
        certificate.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let endpoint = ProvisionalEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            certificate.self_signed(&key).unwrap().der().to_vec(),
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let withdrawn = Arc::new(Mutex::new(false));
        let publication = PortPublication(address, withdrawn.clone());
        let mut window = PairingDiscoveryWindow::default();
        let generation = window.open(0).unwrap();
        let lease = PairingAdvertisementLease::open_with(&mut window, generation, 0, || {
            Ok(LeaseResources::new(
                Box::new(endpoint),
                Box::new(publication),
            ))
        })
        .unwrap();
        assert!(UdpSocket::bind(address).is_err());
        window.close(1).unwrap();
        assert!(*withdrawn.lock().unwrap());
        assert!(!lease.is_active());
        tokio::time::timeout(Duration::from_secs(2), async {
            while UdpSocket::bind(address).is_err() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("strict endpoint did not release its real UDP port");
    }

    #[test]
    fn stale_foreign_and_duplicate_generations_do_not_create_resources() {
        let mut fixture = Fixture::new();
        let old = fixture.window.open(0).unwrap();
        fixture.window.close(1).unwrap();
        let current = fixture.window.open(2).unwrap();
        assert!(fixture.lease(old, 2).is_err());
        let mut foreign = PairingDiscoveryWindow::default();
        assert!(fixture.lease(foreign.open(2).unwrap(), 2).is_err());
        assert!(!fixture.probe.lock().unwrap().listener);
        let lease = fixture.lease(current, 2).unwrap();
        assert!(fixture.lease(current, 2).is_err());
        drop(lease);
        fixture.assert_closed();
    }

    #[test]
    fn dropping_the_window_revokes_a_retained_lease() {
        let mut fixture = Fixture::new();
        let generation = fixture.window.open(0).unwrap();
        let lease = fixture.lease(generation, 0).unwrap();
        drop(std::mem::take(&mut fixture.window));
        assert!(!lease.is_active());
        fixture.assert_closed();
    }

    #[test]
    fn advertisement_has_only_opaque_rendezvous_version_and_pairable_metadata() {
        let info = advertisement_info("11111111111111111111111111111111", 57899).unwrap();
        assert_eq!(info.get_properties().len(), 2);
        assert_eq!(info.get_property_val_str("v"), Some("2"));
        assert_eq!(info.get_property_val_str("pairable"), Some("1"));
        assert_eq!(
            info.get_hostname(),
            "11111111111111111111111111111111.local."
        );
        assert!(advertisement_info("private device name", 57899).is_err());
        assert!(advertisement_info("11111111111111111111111111111111", 0).is_err());
    }

    #[test]
    fn register_enqueued_then_error_awaits_withdrawal_before_endpoint_drop() {
        struct QueuedRegistrationError(Arc<Mutex<Probe>>);
        impl AdvertisementDriver for QueuedRegistrationError {
            fn prepare(&mut self) -> Result<(), SetupError> {
                Ok(())
            }
            fn register(&mut self, info: mdns_sd::ServiceInfo) -> Result<(), SetupError> {
                assert_eq!(
                    info.get_fullname(),
                    "11111111111111111111111111111111._seamless-input._udp.local."
                );
                let mut state = self.0.lock().unwrap();
                state.advertising = true;
                state.events.extend(["register_queued", "register_error"]);
                Err(SetupError::Unavailable)
            }
            fn healthy(&mut self) -> bool {
                true
            }
            fn unregister(&mut self, name: &str) -> Result<DaemonAcknowledgement, SetupError> {
                assert_eq!(
                    name,
                    "11111111111111111111111111111111._seamless-input._udp.local."
                );
                self.0.lock().unwrap().events.push("withdraw_queued");
                let probe = self.0.clone();
                Ok(Box::new(move |timeout| {
                    assert_eq!(timeout, Duration::from_secs(1));
                    let mut state = probe.lock().unwrap();
                    assert!(
                        state.listener,
                        "endpoint released before withdrawal acknowledgement"
                    );
                    state.advertising = false;
                    state.events.push("withdraw_ack");
                    Ok(())
                }))
            }
            fn shutdown(&mut self) -> Result<DaemonAcknowledgement, SetupError> {
                self.0.lock().unwrap().events.push("shutdown_queued");
                let probe = self.0.clone();
                Ok(Box::new(move |timeout| {
                    assert_eq!(timeout, Duration::from_secs(1));
                    let mut state = probe.lock().unwrap();
                    assert!(
                        state.listener,
                        "endpoint released before shutdown acknowledgement"
                    );
                    state.advertising = false;
                    state.events.push("shutdown_ack");
                    Ok(())
                }))
            }
        }
        impl Drop for QueuedRegistrationError {
            fn drop(&mut self) {
                self.0.lock().unwrap().events.push("publisher_dropped");
            }
        }

        let mut fixture = Fixture::new();
        let generation = fixture.window.open(0).unwrap();
        let probe = fixture.probe.clone();
        let result =
            PairingAdvertisementLease::open_with(&mut fixture.window, generation, 0, || {
                probe.lock().unwrap().listener = true;
                let endpoint = Endpoint(probe.clone());
                let info = advertisement_info("11111111111111111111111111111111", 57899)?;
                let publication = EngineAdvertisement::start_with_driver(
                    info,
                    Box::new(QueuedRegistrationError(probe.clone())),
                )?;
                Ok(LeaseResources::new(
                    Box::new(endpoint),
                    Box::new(publication),
                ))
            });
        assert!(matches!(result, Err(SetupError::Unavailable)));
        let state = fixture.probe.lock().unwrap();
        assert!(
            !state.advertising,
            "queued registration was not synchronously withdrawn"
        );
        assert!(!state.listener);
        assert_eq!(
            state.events,
            [
                "register_queued",
                "register_error",
                "withdraw_queued",
                "withdraw_ack",
                "shutdown_queued",
                "shutdown_ack",
                "publisher_dropped",
                "endpoint_dropped",
            ]
        );
    }
}
