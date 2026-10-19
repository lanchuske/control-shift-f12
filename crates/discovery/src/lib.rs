//! Untrusted LAN locators with minimal discovery metadata.
#[cfg(feature = "pairing-v2-g4")]
pub mod guided;
pub mod mdns;
#[cfg(feature = "pairing-v2-operational-experimental")]
pub mod operational;
pub use mdns::{Advertisement, DiscoveredPeer, Discovery, PeerCache, PollBudget, manual_address};
