//! Bounded clipboard validation and content-hash loop suppression.

use seamless_input_protocol::{MAX_PNG_BYTES, MAX_TEXT_BYTES};
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardPayload {
    Text(String),
    Png(Vec<u8>),
}

impl ClipboardPayload {
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }
    pub fn png(value: Vec<u8>) -> Self {
        Self::Png(value)
    }
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Text(v) => v.as_bytes(),
            Self::Png(v) => v,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardTransfer {
    pub hash: [u8; 32],
    pub payload: ClipboardPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardError {
    TooLarge,
    MalformedPng,
    HashMismatch,
}

#[derive(Debug)]
pub struct ClipboardDeduper {
    capacity: usize,
    order: VecDeque<[u8; 32]>,
    seen: HashSet<[u8; 32]>,
}

impl ClipboardDeduper {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            seen: HashSet::new(),
        }
    }
    pub fn accept_local(
        &mut self,
        payload: ClipboardPayload,
    ) -> Result<Option<ClipboardTransfer>, ClipboardError> {
        validate(&payload)?;
        let hash = digest(&payload);
        if !self.remember(hash) {
            return Ok(None);
        }
        Ok(Some(ClipboardTransfer { hash, payload }))
    }
    pub fn accept_remote(
        &mut self,
        transfer: ClipboardTransfer,
    ) -> Result<Option<ClipboardPayload>, ClipboardError> {
        validate(&transfer.payload)?;
        if digest(&transfer.payload) != transfer.hash {
            return Err(ClipboardError::HashMismatch);
        }
        if !self.remember(transfer.hash) {
            return Ok(None);
        }
        Ok(Some(transfer.payload))
    }
    fn remember(&mut self, hash: [u8; 32]) -> bool {
        if !self.seen.insert(hash) {
            return false;
        }
        self.order.push_back(hash);
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }
}

fn digest(payload: &ClipboardPayload) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(match payload {
        ClipboardPayload::Text(_) => b"text".as_slice(),
        ClipboardPayload::Png(_) => b"png".as_slice(),
    });
    h.update(payload.bytes());
    h.finalize().into()
}

fn validate(payload: &ClipboardPayload) -> Result<(), ClipboardError> {
    match payload {
        ClipboardPayload::Text(v) if v.len() > MAX_TEXT_BYTES => Err(ClipboardError::TooLarge),
        ClipboardPayload::Png(v) if v.len() > MAX_PNG_BYTES => Err(ClipboardError::TooLarge),
        ClipboardPayload::Png(v) if !valid_png(v) => Err(ClipboardError::MalformedPng),
        _ => Ok(()),
    }
}

fn valid_png(bytes: &[u8]) -> bool {
    if !bytes.starts_with(&[137, 80, 78, 71, 13, 10, 26, 10]) {
        return false;
    }
    let mut at = 8usize;
    let mut first = true;
    let mut ended = false;
    let mut image_data = false;
    while at.checked_add(12).is_some_and(|n| n <= bytes.len()) {
        let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let Some(end) = at.checked_add(12).and_then(|n| n.checked_add(len)) else {
            return false;
        };
        if end > bytes.len() {
            return false;
        }
        let kind = &bytes[at + 4..at + 8];
        if first && (kind != b"IHDR" || len != 13) {
            return false;
        }
        if kind == b"IEND" {
            if len != 0 || end != bytes.len() {
                return false;
            }
            ended = true;
        }
        if kind == b"IDAT" {
            image_data = true;
        }
        let expected = u32::from_be_bytes(bytes[end - 4..end].try_into().unwrap());
        let mut crc = crc32fast::Hasher::new();
        crc.update(&bytes[at + 4..end - 4]);
        if crc.finalize() != expected {
            return false;
        }
        first = false;
        at = end;
    }
    ended && image_data
}
