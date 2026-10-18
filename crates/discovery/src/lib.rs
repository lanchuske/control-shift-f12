//! Untrusted LAN locators with minimal discovery metadata.
#[cfg(feature = "pairing-v2-experimental")]
pub mod guided;
pub mod mdns;
pub use mdns::{Advertisement, DiscoveredPeer, Discovery, PeerCache, PollBudget, manual_address};
