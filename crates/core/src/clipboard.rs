//! Bounded clipboard validation and content-hash loop suppression.

use seamless_input_protocol::{MAX_PNG_BYTES, MAX_TEXT_BYTES};
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};

/// Decode limits are intentionally lower than the wire-size limit can imply.
/// Native clipboard decoders expand every accepted image to RGBA.
pub const MAX_PNG_DIMENSION: u32 = 16_384;
pub const MAX_PNG_PIXELS: u64 = 16 * 1024 * 1024;
pub const MAX_PNG_DECODED_BYTES: u64 = MAX_PNG_PIXELS * 4;

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
        ClipboardPayload::Png(v) => validate_png(v),
        _ => Ok(()),
    }
}

/// Validate PNG structure and decoded RGBA allocation bounds without invoking
/// an image decoder. Call this before passing untrusted bytes to native APIs.
pub fn validate_png(bytes: &[u8]) -> Result<(), ClipboardError> {
    if !bytes.starts_with(&[137, 80, 78, 71, 13, 10, 26, 10]) {
        return Err(ClipboardError::MalformedPng);
    }
    let mut at = 8usize;
    let mut first = true;
    let mut ended = false;
    let mut image_data = false;
    while at.checked_add(12).is_some_and(|n| n <= bytes.len()) {
        let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let Some(end) = at.checked_add(12).and_then(|n| n.checked_add(len)) else {
            return Err(ClipboardError::MalformedPng);
        };
        if end > bytes.len() {
            return Err(ClipboardError::MalformedPng);
        }
        let kind = &bytes[at + 4..at + 8];
        if first && (kind != b"IHDR" || len != 13) {
            return Err(ClipboardError::MalformedPng);
        }
        if first {
            let width = u32::from_be_bytes(bytes[at + 8..at + 12].try_into().unwrap());
            let height = u32::from_be_bytes(bytes[at + 12..at + 16].try_into().unwrap());
            if width == 0 || height == 0 {
                return Err(ClipboardError::MalformedPng);
            }
            let pixels = u64::from(width)
                .checked_mul(u64::from(height))
                .ok_or(ClipboardError::TooLarge)?;
            let decoded_bytes = pixels.checked_mul(4).ok_or(ClipboardError::TooLarge)?;
            if width > MAX_PNG_DIMENSION
                || height > MAX_PNG_DIMENSION
                || pixels > MAX_PNG_PIXELS
                || decoded_bytes > MAX_PNG_DECODED_BYTES
            {
                return Err(ClipboardError::TooLarge);
            }
        }
        if kind == b"IEND" {
            if len != 0 || end != bytes.len() {
                return Err(ClipboardError::MalformedPng);
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
            return Err(ClipboardError::MalformedPng);
        }
        first = false;
        at = end;
    }
    if ended && image_data {
        Ok(())
    } else {
        Err(ClipboardError::MalformedPng)
    }
}
