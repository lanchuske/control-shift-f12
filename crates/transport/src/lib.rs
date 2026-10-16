//! Symmetric QUIC endpoints and deterministic election. Task 4 supplies trust.
pub mod identity;
pub mod pairing;
pub mod pairing_pending;
#[cfg(unix)]
mod private_fs;
pub mod quic;
pub mod setup_lock;
pub use identity::{IdentityStore, PinnedIdentityVerifier, PinnedPeer};
pub use pairing::{
    PairingCode, PairingConfirmation, PairingError, PairingSession, pair_accept_over_quic,
    pair_accept_over_quic_with_timeout, pair_offer_over_quic, pair_offer_over_quic_with_timeout,
};
pub use quic::{
    EndpointOptions, NodeId, PeerEndpoint, PeerIdentityVerifier, PeerSession, ReconnectPolicy,
    SessionTrust, TransportError,
};
