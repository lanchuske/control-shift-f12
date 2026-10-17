//! Experimental pairing primitives, isolated provisional TLS, phase ordering,
//! injected-clock limits and quarantined durable evidence. The sealed bilateral
//! handshake emits only the reviewed control wire. No application I/O,
//! RecoveryAuthority provider, active trust, promotion or admission.
#[cfg(feature = "pairing-v2-experimental")]
#[allow(dead_code)] // Internal foundation remains deliberately unwired and default-off.
pub(crate) mod admission_authority;
pub mod codec;
mod evidence;
mod handshake_binding;
mod handshake_evidence;
mod handshake_machine;
mod handshake_wire;
pub mod operational_binding;
#[cfg(feature = "pairing-v2-experimental")]
#[allow(dead_code)] // Sealed default-off foundation; product has no caller in this phase.
pub(crate) mod operational_session;
#[cfg(test)]
mod operational_session_tests;
pub mod operational_wire;
pub mod provisional_tls;
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
#[cfg(feature = "pairing-v2-experimental")]
#[allow(dead_code)] // The sealed grammar precedes the future authenticated transport.
pub(crate) mod recovery;
mod session;
pub use identity::{Identity, validate_identity};
pub use session::*;
mod journal;
pub use journal::*;
use sha2::{Digest, Sha256};
use std::borrow::Cow;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid pairing v2 evidence")]
pub struct Invalid;

pub const WORDLIST_HASH: [u8; 32] = [
    0x2f, 0x5e, 0xed, 0x53, 0xa4, 0x72, 0x7b, 0x4b, 0xf8, 0x88, 0x0d, 0x8f, 0x3f, 0x19, 0x9e, 0xfc,
    0x90, 0xe5, 0x85, 0x03, 0x64, 0x6d, 0x9f, 0xf8, 0xef, 0xf3, 0xa2, 0xed, 0x3b, 0x24, 0xdb, 0xda,
];
pub fn sas_words(digest: &[u8; 32]) -> Result<[String; 4], Invalid> {
    sas_words_for_wordlist(digest, include_bytes!("bip39-english.txt"))
}

fn sas_words_for_wordlist(digest: &[u8; 32], wordlist: &[u8]) -> Result<[String; 4], Invalid> {
    let raw = validated_wordlist(wordlist)?;
    let words: Vec<_> = std::str::from_utf8(raw.as_ref())
        .map_err(|_| Invalid)?
        .lines()
        .collect();
    let prefix = u64::from_be_bytes([
        0, 0, digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
    ]) >> 4;
    Ok([33, 22, 11, 0].map(|shift| words[((prefix >> shift) & 2047) as usize].to_owned()))
}
pub fn validate_wordlist(bytes: &[u8]) -> Result<(), Invalid> {
    validated_wordlist(bytes).map(|_| ())
}

fn validated_wordlist(bytes: &[u8]) -> Result<Cow<'_, [u8]>, Invalid> {
    let raw = canonical_wordlist(bytes)?;
    let hash: [u8; 32] = Sha256::digest(raw.as_ref()).into();
    if hash != WORDLIST_HASH {
        return Err(Invalid);
    }
    let words: Vec<_> = std::str::from_utf8(raw.as_ref())
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
    Ok(raw)
}

fn canonical_wordlist(bytes: &[u8]) -> Result<Cow<'_, [u8]>, Invalid> {
    if !bytes.contains(&b'\r') {
        return Ok(Cow::Borrowed(bytes));
    }

    let mut canonical = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' if bytes.get(index + 1) == Some(&b'\n') => index += 1,
            b'\r' => return Err(Invalid),
            _ => {}
        }
        canonical.push(bytes[index]);
        index += 1;
    }
    Ok(Cow::Owned(canonical))
}

#[cfg(test)]
mod wordlist_tests {
    use super::*;

    fn crlf_wordlist() -> Vec<u8> {
        let mut crlf = Vec::new();
        for byte in include_bytes!("bip39-english.txt")
            .iter()
            .copied()
            .filter(|byte| *byte != b'\r')
        {
            if byte == b'\n' {
                crlf.extend_from_slice(b"\r\n");
            } else {
                crlf.push(byte);
            }
        }
        crlf
    }

    #[test]
    fn crlf_wordlist_is_canonicalized_before_validation() {
        assert!(validate_wordlist(&crlf_wordlist()).is_ok());
    }

    #[test]
    fn isolated_carriage_returns_are_rejected() {
        let lf: Vec<_> = include_bytes!("bip39-english.txt")
            .iter()
            .copied()
            .filter(|byte| *byte != b'\r')
            .collect();
        let mut at_start = lf.clone();
        at_start.insert(0, b'\r');
        let mut in_middle = lf.clone();
        in_middle.insert(lf.len() / 2, b'\r');
        let mut at_end = lf;
        at_end.push(b'\r');

        for malformed in [at_start, in_middle, at_end] {
            assert!(validate_wordlist(&malformed).is_err());
        }
    }

    #[test]
    fn crcrlf_and_mixed_line_endings_with_lone_carriage_return_are_rejected() {
        let mut repeated_cr = crlf_wordlist();
        let first_cr = repeated_cr.iter().position(|byte| *byte == b'\r').unwrap();
        repeated_cr.insert(first_cr, b'\r');
        let mut mixed = crlf_wordlist();
        mixed.insert(mixed.len() / 2, b'\r');

        assert!(validate_wordlist(&repeated_cr).is_err());
        assert!(validate_wordlist(&mixed).is_err());
    }

    #[test]
    fn changed_word_under_crlf_still_fails_canonical_hash_validation() {
        let mut changed = crlf_wordlist();
        changed[0] = b'z';

        assert!(validate_wordlist(&changed).is_err());
    }

    #[test]
    fn sas_vectors_for_the_embedded_wordlist_are_stable() {
        assert_eq!(
            sas_words(&[0; 32]).unwrap(),
            ["abandon", "abandon", "abandon", "abandon"]
        );
        assert_eq!(
            sas_words(&[
                0x00, 0x20, 0x08, 0x01, 0x80, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ])
            .unwrap(),
            ["ability", "able", "about", "above"]
        );
    }

    #[test]
    fn sas_mapping_uses_the_same_words_for_canonical_crlf() {
        let digest = [
            0x00, 0x20, 0x08, 0x01, 0x80, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let lf = include_bytes!("bip39-english.txt");
        let crlf = crlf_wordlist();

        assert_eq!(
            sas_words_for_wordlist(&digest, lf).unwrap(),
            sas_words_for_wordlist(&digest, &crlf).unwrap()
        );
        assert_eq!(
            sas_words_for_wordlist(&digest, &crlf).unwrap(),
            ["ability", "able", "about", "above"]
        );
    }
}
