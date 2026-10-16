//! Experimental offline pairing components: verification, phase ordering,
//! injected-clock limits and quarantined durable evidence. No application
//! adapter, network, trust-store signer, production emitter or admission.
pub mod codec;
mod evidence;
pub use evidence::*;
mod primitives;
pub use primitives::*;
mod candidate;
pub use candidate::*;
mod coordinator_limits;
mod identity;
pub use coordinator_limits::*;
mod recovery_authority;
pub use recovery_authority::*;
mod session;
pub use identity::{Identity, validate_identity};
pub use session::*;
mod journal;
pub use journal::*;
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid pairing v2 evidence")]
pub struct Invalid;

pub const WORDLIST_HASH: [u8; 32] = [
    0x2f, 0x5e, 0xed, 0x53, 0xa4, 0x72, 0x7b, 0x4b, 0xf8, 0x88, 0x0d, 0x8f, 0x3f, 0x19, 0x9e, 0xfc,
    0x90, 0xe5, 0x85, 0x03, 0x64, 0x6d, 0x9f, 0xf8, 0xef, 0xf3, 0xa2, 0xed, 0x3b, 0x24, 0xdb, 0xda,
];
pub fn sas_words(digest: &[u8; 32]) -> Result<[String; 4], Invalid> {
    let raw = include_bytes!("bip39-english.txt");
    validate_wordlist(raw)?;
    let words: Vec<_> = std::str::from_utf8(raw)
        .map_err(|_| Invalid)?
        .lines()
        .collect();
    let prefix = u64::from_be_bytes([
        0, 0, digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
    ]) >> 4;
    Ok([33, 22, 11, 0].map(|shift| words[((prefix >> shift) & 2047) as usize].to_owned()))
}
pub fn validate_wordlist(bytes: &[u8]) -> Result<(), Invalid> {
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    if hash != WORDLIST_HASH {
        return Err(Invalid);
    }
    let words: Vec<_> = std::str::from_utf8(bytes)
        .map_err(|_| Invalid)?
        .lines()
        .collect();
    if words.len() != 2048
        || words
            .iter()
            .any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_lowercase()))
        || words
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != 2048
    {
        return Err(Invalid);
    }
    Ok(())
}
