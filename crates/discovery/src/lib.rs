//! Untrusted LAN locators with minimal discovery metadata.
pub mod mdns;
pub use mdns::{Advertisement, DiscoveredPeer, Discovery, PeerCache, PollBudget, manual_address};
