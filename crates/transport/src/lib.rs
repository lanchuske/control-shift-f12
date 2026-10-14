//! Symmetric QUIC endpoints and deterministic election. Task 4 supplies trust.
pub mod quic;
pub use quic::{
    EndpointOptions, NodeId, PeerEndpoint, PeerIdentityVerifier, PeerSession, ReconnectPolicy,
    SessionTrust, TransportError,
};
