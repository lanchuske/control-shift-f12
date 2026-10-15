use seamless_input_core::clipboard::ClipboardTransfer;
use seamless_input_protocol::{InputEvent, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub input: bool,
    pub text: bool,
    pub png: bool,
}
impl Capabilities {
    pub fn all() -> Self {
        Self {
            input: true,
            text: true,
            png: true,
        }
    }
    pub fn intersect(self, other: Self) -> Self {
        Self {
            input: self.input && other.input,
            text: self.text && other.text,
            png: self.png && other.png,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PeerMessage {
    Capabilities {
        epoch: u64,
        capabilities: Capabilities,
    },
    AcquireLease {
        epoch: u64,
    },
    ReleaseLease {
        epoch: u64,
    },
    Input {
        epoch: u64,
        sequence: u64,
        event: InputEvent,
    },
    Clipboard {
        epoch: u64,
        sequence: u64,
        transfer: ClipboardTransfer,
    },
    Heartbeat {
        epoch: u64,
    },
    /// Appended to preserve the MessagePack discriminants of the original
    /// production data-plane messages.
    Displays {
        epoch: u64,
        displays: Vec<u32>,
    },
}

pub fn encode_peer_message(message: &PeerMessage) -> Result<Vec<u8>, String> {
    rmp_serde::to_vec(message).map_err(|_| "peer message encoding failed".into())
}

pub fn decode_peer_message(bytes: &[u8]) -> Result<PeerMessage, String> {
    if bytes.len() > seamless_input_protocol::MAX_FRAME_BYTES + 64 * 1024 {
        return Err("peer message exceeds the wire limit".into());
    }
    rmp_serde::from_slice(bytes).map_err(|_| "peer message decoding failed".into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseError {
    UnknownPeer,
    Busy,
    WrongEpoch,
    NoLease,
    Stale,
    CapabilityDenied,
}

#[derive(Debug, Clone)]
struct PeerState {
    local_epoch: u64,
    remote_epoch: Option<u64>,
    remote: Capabilities,
    negotiated: Capabilities,
    last_sequence: Option<u64>,
}

#[derive(Debug)]
pub struct PeerRegistry {
    local: NodeId,
    next_epoch: u64,
    peers: BTreeMap<NodeId, PeerState>,
    lease: Option<(NodeId, u64)>,
}

impl PeerRegistry {
    pub fn new(local: NodeId) -> Self {
        Self {
            local,
            next_epoch: 1,
            peers: BTreeMap::new(),
            lease: None,
        }
    }
    pub fn local(&self) -> NodeId {
        self.local
    }
    pub fn connected(&mut self, peer: NodeId, remote: Capabilities) -> u64 {
        let epoch = self.next_epoch;
        self.next_epoch = self.next_epoch.saturating_add(1);
        self.peers.insert(
            peer,
            PeerState {
                local_epoch: epoch,
                remote_epoch: None,
                remote,
                negotiated: remote,
                last_sequence: None,
            },
        );
        epoch
    }
    pub fn negotiated(
        &mut self,
        peer: NodeId,
        local: Capabilities,
    ) -> Result<Capabilities, LeaseError> {
        let p = self.peers.get_mut(&peer).ok_or(LeaseError::UnknownPeer)?;
        p.negotiated = local.intersect(p.remote);
        Ok(p.negotiated)
    }
    pub fn epoch(&self, peer: NodeId) -> Option<u64> {
        self.peers.get(&peer).map(|p| p.local_epoch)
    }
    pub fn peers(&self) -> impl Iterator<Item = (NodeId, u64, Capabilities)> + '_ {
        self.peers
            .iter()
            .map(|(id, p)| (*id, p.local_epoch, p.negotiated))
    }
    pub fn disconnected(&mut self, peer: NodeId) {
        self.peers.remove(&peer);
        if self.lease.is_some_and(|(p, _)| p == peer) {
            self.lease = None;
        }
    }
    pub fn receive(&mut self, peer: NodeId, message: PeerMessage) -> Result<(), LeaseError> {
        let state = self.peers.get_mut(&peer).ok_or(LeaseError::UnknownPeer)?;
        let epoch = match &message {
            PeerMessage::Capabilities { epoch, .. } | PeerMessage::Displays { epoch, .. } => *epoch,
            PeerMessage::AcquireLease { epoch }
            | PeerMessage::ReleaseLease { epoch }
            | PeerMessage::Heartbeat { epoch }
            | PeerMessage::Input { epoch, .. }
            | PeerMessage::Clipboard { epoch, .. } => *epoch,
        };
        if !matches!(
            &message,
            PeerMessage::Capabilities { .. } | PeerMessage::Displays { .. }
        ) && state.remote_epoch != Some(epoch)
        {
            return Err(LeaseError::WrongEpoch);
        }
        match message {
            PeerMessage::Capabilities {
                epoch,
                capabilities,
            } => {
                state.remote_epoch = Some(epoch);
                state.negotiated = state.remote.intersect(capabilities);
            }
            PeerMessage::Displays { .. } => {}
            PeerMessage::AcquireLease { .. } => match self.lease {
                None => self.lease = Some((peer, epoch)),
                Some((p, e)) if p == peer && e == epoch => {}
                Some(_) => return Err(LeaseError::Busy),
            },
            PeerMessage::ReleaseLease { .. } => {
                if self.lease == Some((peer, epoch)) {
                    self.lease = None
                } else {
                    return Err(LeaseError::NoLease);
                }
            }
            PeerMessage::Input { sequence, .. } => {
                if !state.negotiated.input {
                    return Err(LeaseError::CapabilityDenied);
                };
                require_lease(self.lease, peer, epoch)?;
                accept_sequence(&mut state.last_sequence, sequence)?;
            }
            PeerMessage::Clipboard {
                sequence,
                ref transfer,
                ..
            } => {
                let allowed = match transfer.payload {
                    seamless_input_core::clipboard::ClipboardPayload::Text(_) => {
                        state.negotiated.text
                    }
                    seamless_input_core::clipboard::ClipboardPayload::Png(_) => {
                        state.negotiated.png
                    }
                };
                if !allowed {
                    return Err(LeaseError::CapabilityDenied);
                };
                accept_sequence(&mut state.last_sequence, sequence)?;
            }
            PeerMessage::Heartbeat { .. } => {}
        }
        Ok(())
    }
}
fn require_lease(lease: Option<(NodeId, u64)>, peer: NodeId, epoch: u64) -> Result<(), LeaseError> {
    if lease == Some((peer, epoch)) {
        Ok(())
    } else {
        Err(LeaseError::NoLease)
    }
}
fn accept_sequence(last: &mut Option<u64>, sequence: u64) -> Result<(), LeaseError> {
    if last.is_some_and(|n| sequence <= n) {
        Err(LeaseError::Stale)
    } else {
        *last = Some(sequence);
        Ok(())
    }
}
