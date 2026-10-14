use seamless_input_core::clipboard::ClipboardTransfer;
use seamless_input_protocol::{InputEvent, NodeId};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq)]
pub enum PeerMessage {
    Capabilities(Capabilities),
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
    epoch: u64,
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
                epoch,
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
        self.peers.get(&peer).map(|p| p.epoch)
    }
    pub fn peers(&self) -> impl Iterator<Item = (NodeId, u64, Capabilities)> + '_ {
        self.peers
            .iter()
            .map(|(id, p)| (*id, p.epoch, p.negotiated))
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
            PeerMessage::Capabilities(_) => state.epoch,
            PeerMessage::AcquireLease { epoch }
            | PeerMessage::ReleaseLease { epoch }
            | PeerMessage::Heartbeat { epoch }
            | PeerMessage::Input { epoch, .. }
            | PeerMessage::Clipboard { epoch, .. } => *epoch,
        };
        if epoch != state.epoch {
            return Err(LeaseError::WrongEpoch);
        }
        match message {
            PeerMessage::Capabilities(c) => {
                state.negotiated = state.remote.intersect(c);
            }
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
