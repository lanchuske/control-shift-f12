#![cfg(feature = "pairing-v2-experimental")]
use seamless_discovery::{Advertisement, guided::LocatorEvent};
use seamless_input::guided_setup::*;
use std::{cell::Cell, rc::Rc};

struct Clock(Rc<Cell<u64>>);
impl SetupClock for Clock {
    fn now_ms(&self) -> Result<u64, SetupError> {
        Ok(self.0.get())
    }
}
struct Backend {
    drops: Rc<Cell<u32>>,
    events: Vec<LocatorEvent>,
}
impl DiscoveryBackend for Backend {
    fn poll(&mut self) -> Result<Vec<LocatorEvent>, SetupError> {
        Ok(std::mem::take(&mut self.events))
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
type Fixture = (
    SetupController<Clock>,
    Rc<Cell<u64>>,
    Rc<Cell<u32>>,
    Rc<Cell<u32>>,
);
fn fixture() -> Fixture {
    let now = Rc::new(Cell::new(0));
    let starts = Rc::new(Cell::new(0));
    let drops = Rc::new(Cell::new(0));
    let s = starts.clone();
    let d = drops.clone();
    let controller = SetupController::new(
        Clock(now.clone()),
        Box::new(move || {
            s.set(s.get() + 1);
            Ok(Box::new(Backend {
                drops: d.clone(),
                events: vec![LocatorEvent::Observed(Advertisement {
                    instance: "11111111111111111111111111111111".into(),
                    version: 2,
                    pairable: true,
                    addresses: vec!["127.0.0.1:57899".parse().unwrap()],
                    ttl: None,
                })],
            }))
        }),
    );
    (controller, now, starts, drops)
}
#[test]
fn snapshot_is_inert_and_contract_never_claims_identity_or_admission() {
    let (mut c, _, starts, _) = fixture();
    let s = c.execute(SetupCommand::Snapshot {}).unwrap();
    assert_eq!(starts.get(), 0);
    assert_eq!(s.authenticated_sessions, 0);
    assert!(!s.input_enabled && !s.clipboard_enabled && !s.promotion_enabled);
    assert_eq!(s.pairing_transport, TransportStatus::ContractPending);
    assert!(s.candidates.is_empty());
    assert_eq!(
        c.execute(SetupCommand::CompareMatch {}),
        Err(SetupError::InvalidState)
    );
}

#[test]
fn closed_snapshot_clock_rollback_poison_is_independent_of_catalogue() {
    let (mut c, now, starts, _) = fixture();
    now.set(10);
    c.execute(SetupCommand::Snapshot {}).unwrap();
    now.set(9);
    assert_eq!(
        c.execute(SetupCommand::Snapshot {}),
        Err(SetupError::ClockRollback)
    );
    now.set(11);
    assert_eq!(
        c.execute(SetupCommand::Snapshot {}),
        Err(SetupError::ClockRollback)
    );
    assert_eq!(starts.get(), 0);
}
#[cfg(unix)]
#[test]
fn explicit_open_refresh_select_stops_at_closed_transport_and_retry_revokes_handle() {
    let (mut c, _, starts, drops) = fixture();
    c.execute(SetupCommand::OpenDiscovery {}).unwrap();
    assert_eq!(starts.get(), 1);
    assert_eq!(
        c.execute(SetupCommand::OpenDiscovery {}),
        Err(SetupError::InvalidState)
    );
    let s = c.execute(SetupCommand::Refresh {}).unwrap();
    let h = s.candidates[0].handle.clone();
    assert_eq!(
        c.execute(SetupCommand::Select { handle: h.clone() }),
        Err(SetupError::OperationalContractPending)
    );
    assert_eq!(drops.get(), 1);
    let s = c.execute(SetupCommand::Snapshot {}).unwrap();
    assert_eq!(s.status, SetupStatus::ContractPending);
    assert_eq!(s.authenticated_sessions, 0);
    assert!(s.candidates.is_empty());
    c.execute(SetupCommand::OpenDiscovery {}).unwrap();
    c.execute(SetupCommand::Refresh {}).unwrap();
    assert_eq!(
        c.execute(SetupCommand::Select { handle: h }),
        Err(SetupError::StaleCandidate)
    );
    c.execute(SetupCommand::Cancel {}).unwrap();
    assert_eq!(drops.get(), 2);
}
#[cfg(unix)]
#[test]
fn expiry_rollback_cancel_and_drop_release_backend() {
    let (mut c, now, _, drops) = fixture();
    c.execute(SetupCommand::OpenDiscovery {}).unwrap();
    let h = c.execute(SetupCommand::Refresh {}).unwrap().candidates[0]
        .handle
        .clone();
    now.set(30_000);
    assert_eq!(
        c.execute(SetupCommand::Select { handle: h }),
        Err(SetupError::StaleCandidate)
    );
    now.set(300_000);
    assert_eq!(
        c.execute(SetupCommand::Refresh {}),
        Err(SetupError::Expired)
    );
    assert_eq!(drops.get(), 1);
    c.execute(SetupCommand::OpenDiscovery {}).unwrap();
    now.set(299_999);
    assert_eq!(
        c.execute(SetupCommand::Snapshot {}),
        Err(SetupError::ClockRollback)
    );
    assert_eq!(drops.get(), 2);
    now.set(400_000);
    assert_eq!(
        c.execute(SetupCommand::OpenDiscovery {}),
        Err(SetupError::ClockRollback)
    );
    let (mut c, _, _, drops) = fixture();
    c.execute(SetupCommand::OpenDiscovery {}).unwrap();
    drop(c);
    assert_eq!(drops.get(), 1);
}
#[cfg(not(unix))]
#[test]
fn unsupported_platform_never_invokes_factory() {
    let (mut c, _, starts, _) = fixture();
    assert_eq!(
        c.execute(SetupCommand::OpenDiscovery {}),
        Err(SetupError::UnsupportedPlatform)
    );
    assert_eq!(starts.get(), 0);
}
#[test]
fn typed_commands_reject_extra_fields_and_raw_identity_address_or_secret() {
    for value in [
        r#"{"action":"snapshot","secret":"do-not-echo"}"#,
        r#"{"action":"select","handle":{"window":1,"sequence":1,"address":"x"}}"#,
        r#"{"action":"legacy_start"}"#,
    ] {
        assert!(serde_json::from_str::<SetupCommand>(value).is_err());
    }
}
#[test]
fn os_clock_uses_elapsed_monotonic_time() {
    let c = OsSetupClock::default();
    let a = c.now_ms().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    assert!(c.now_ms().unwrap() > a);
}
#[cfg(unix)]
#[test]
fn restart_cannot_reuse_a_handle_even_when_counters_repeat() {
    let (mut first, _, _, _) = fixture();
    first.execute(SetupCommand::OpenDiscovery {}).unwrap();
    let old = first.execute(SetupCommand::Refresh {}).unwrap().candidates[0]
        .handle
        .clone();
    drop(first);
    let (mut second, _, _, _) = fixture();
    second.execute(SetupCommand::OpenDiscovery {}).unwrap();
    second.execute(SetupCommand::Refresh {}).unwrap();
    assert_eq!(
        second.execute(SetupCommand::Select { handle: old }),
        Err(SetupError::StaleCandidate)
    );
}
#[cfg(unix)]
#[test]
fn backend_failure_is_not_a_healthy_empty_snapshot_and_cannot_leave_browse_active() {
    struct Bad;
    impl DiscoveryBackend for Bad {
        fn poll(&mut self) -> Result<Vec<LocatorEvent>, SetupError> {
            Err(SetupError::Unavailable)
        }
    }
    let clock = Clock(Rc::new(Cell::new(0)));
    let mut c = SetupController::new(clock, Box::new(|| Ok(Box::new(Bad))));
    c.execute(SetupCommand::OpenDiscovery {}).unwrap();
    assert_eq!(
        c.execute(SetupCommand::Refresh {}),
        Err(SetupError::Unavailable)
    );
    assert_eq!(
        c.execute(SetupCommand::Snapshot {}).unwrap().status,
        SetupStatus::Closed
    );
    assert_eq!(
        c.execute(SetupCommand::Refresh {}),
        Err(SetupError::InvalidState)
    );
}

#[cfg(unix)]
#[test]
fn oversized_backend_batch_fails_closed_before_processing_any_event() {
    struct Flood;
    impl DiscoveryBackend for Flood {
        fn poll(&mut self) -> Result<Vec<LocatorEvent>, SetupError> {
            Ok(vec![
                LocatorEvent::Removed(
                    "11111111111111111111111111111111".into()
                );
                33
            ])
        }
    }
    let mut c = SetupController::new(
        Clock(Rc::new(Cell::new(0))),
        Box::new(|| Ok(Box::new(Flood))),
    );
    c.execute(SetupCommand::OpenDiscovery {}).unwrap();
    assert_eq!(c.execute(SetupCommand::Refresh {}), Err(SetupError::Limit));
    let s = c.execute(SetupCommand::Snapshot {}).unwrap();
    assert_eq!(s.status, SetupStatus::Closed);
    assert!(s.candidates.is_empty());
}
