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
}

pub fn encode_peer_message(message: &PeerMessage) -> Result<Vec<u8>, String> {
    rmp_serde::to_vec(message).map_err(|_| "peer message encoding failed".into())
}

pub fn decode_peer_message(bytes: &[u8]) -> Result<PeerMessage, String> {
    const MAX_WIRE_BYTES: usize = seamless_input_protocol::MAX_FRAME_BYTES + 64 * 1024;
    const MAX_DEPTH: usize = 24;
    if bytes.len() > MAX_WIRE_BYTES {
        return Err("peer message exceeds the wire limit".into());
    }
    let consumed = scan_messagepack(bytes, 0, 0, MAX_DEPTH, MAX_WIRE_BYTES)
        .map_err(|_| "peer message decoding failed")?;
    if consumed != bytes.len() {
        return Err("peer message decoding failed".into());
    }
    let mut cursor = std::io::Cursor::new(bytes);
    let mut decoder = rmp_serde::Deserializer::new(&mut cursor);
    decoder.set_max_depth(MAX_DEPTH);
    let message = PeerMessage::deserialize(&mut decoder)
        .map_err(|_| "peer message decoding failed".to_string())?;
    if cursor.position() as usize != bytes.len() {
        return Err("peer message decoding failed".into());
    }
    Ok(message)
}

/// Validate the complete MessagePack object before serde sees any attacker
/// supplied collection length. This prevents forged array/string lengths from
/// driving allocations and puts a small, protocol-specific cap on recursion.
fn scan_messagepack(
    bytes: &[u8],
    at: usize,
    depth: usize,
    max_depth: usize,
    max_items: usize,
) -> Result<usize, ()> {
    if depth > max_depth || at >= bytes.len() {
        return Err(());
    }
    let marker = bytes[at];
    let next = at + 1;
    let take_len = |start: usize, count: usize| -> Result<(usize, usize), ()> {
        let end = start.checked_add(count).ok_or(())?;
        let slice = bytes.get(start..end).ok_or(())?;
        let value = match count {
            1 => usize::from(slice[0]),
            2 => usize::from(u16::from_be_bytes(slice.try_into().map_err(|_| ())?)),
            4 => usize::try_from(u32::from_be_bytes(slice.try_into().map_err(|_| ())?))
                .map_err(|_| ())?,
            _ => return Err(()),
        };
        Ok((end, value))
    };
    let skip = |start: usize, count: usize| -> Result<usize, ()> {
        start
            .checked_add(count)
            .filter(|end| *end <= bytes.len())
            .ok_or(())
    };
    let scan_items = |mut cursor: usize, count: usize, item_depth: usize| -> Result<usize, ()> {
        if count > max_items {
            return Err(());
        }
        for _ in 0..count {
            cursor = scan_messagepack(bytes, cursor, item_depth, max_depth, max_items)?;
        }
        Ok(cursor)
    };

    match marker {
        0x00..=0x7f | 0xc0 | 0xc2 | 0xc3 | 0xe0..=0xff => Ok(next),
        0xcc | 0xd0 => skip(next, 1),
        0xcd | 0xd1 => skip(next, 2),
        0xce | 0xd2 | 0xca => skip(next, 4),
        0xcf | 0xd3 | 0xcb => skip(next, 8),
        0xa0..=0xbf => skip(next, usize::from(marker & 0x1f)),
        0x90..=0x9f => scan_items(next, usize::from(marker & 0x0f), depth + 1),
        0x80..=0x8f => scan_items(next, usize::from(marker & 0x0f) * 2, depth + 1),
        0xd9 | 0xc4 => {
            let (cursor, length) = take_len(next, 1)?;
            if length > max_items {
                Err(())
            } else {
                skip(cursor, length)
            }
        }
        0xda | 0xc5 => {
            let (cursor, length) = take_len(next, 2)?;
            if length > max_items {
                Err(())
            } else {
                skip(cursor, length)
            }
        }
        0xdb | 0xc6 => {
            let (cursor, length) = take_len(next, 4)?;
            if length > max_items {
                Err(())
            } else {
                skip(cursor, length)
            }
        }
        0xdc | 0xdd => {
            let width = if marker == 0xdc { 2 } else { 4 };
            let (cursor, count) = take_len(next, width)?;
            scan_items(cursor, count, depth + 1)
        }
        0xde | 0xdf => {
            let width = if marker == 0xde { 2 } else { 4 };
            let (cursor, count) = take_len(next, width)?;
            scan_items(cursor, count.checked_mul(2).ok_or(())?, depth + 1)
        }
        // Extensions are not part of the peer schema. Reserved markers fail
        // closed rather than entering generic decoder paths.
        0xc1 | 0xc7..=0xc9 | 0xd4..=0xd8 => Err(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseError {
    UnknownPeer,
    Busy,
    WrongEpoch,
    NoLease,
    Stale,
    CapabilityDenied,
    InvalidInput,
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
            PeerMessage::Capabilities { epoch, .. } => *epoch,
            PeerMessage::AcquireLease { epoch }
            | PeerMessage::ReleaseLease { epoch }
            | PeerMessage::Heartbeat { epoch }
            | PeerMessage::Input { epoch, .. }
            | PeerMessage::Clipboard { epoch, .. } => *epoch,
        };
        if !matches!(&message, PeerMessage::Capabilities { .. })
            && state.remote_epoch != Some(epoch)
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
            PeerMessage::Input {
                sequence,
                ref event,
                ..
            } => {
                if !state.negotiated.input {
                    return Err(LeaseError::CapabilityDenied);
                };
                if !event.is_valid() {
                    return Err(LeaseError::InvalidInput);
                }
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
