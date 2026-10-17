//! Exact bilateral recovery evidence.
//!
//! This is deliberately only the sealed record grammar and comparison rule.
//! It does not open a connection, trust a peer, mutate durable state, or
//! activate a session.  A later mutual-TLS exchange must authenticate this
//! record before the durable store can consume it.

use super::{
    Invalid,
    codec::{Value, decode, encode},
};

const RECOVERY_DOMAIN: &str = "control-shift-f12/bilateral-recovery-v1";
const RECOVERY_KIND: &str = "bilateral-recovery";

/// The immutable proof shape one peer presents when recovering one durable
/// bilateral transaction.  `sender_receipt_hash` names the sender's local
/// receipt; `peer_receipt_hash` names the receiver's receipt when it was
/// durably observed before the interruption.  It is absent for a valid
/// store-owned-but-not-yet-confirmed receipt, so recovery must not invent it.
/// The pair is intentionally directional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactPeerRecovery {
    transaction_id: [u8; 32],
    sender_receipt_hash: [u8; 32],
    peer_receipt_hash: Option<[u8; 32]>,
    identity_generation: u64,
    revocation_generation: u64,
    policy_revision: u64,
}

impl ExactPeerRecovery {
    pub(crate) fn new(
        transaction_id: [u8; 32],
        sender_receipt_hash: [u8; 32],
        peer_receipt_hash: Option<[u8; 32]>,
        identity_generation: u64,
        revocation_generation: u64,
        policy_revision: u64,
    ) -> Result<Self, Invalid> {
        if transaction_id == [0; 32]
            || sender_receipt_hash == [0; 32]
            || peer_receipt_hash.is_some_and(|hash| hash == [0; 32])
        {
            return Err(Invalid);
        }
        Ok(Self {
            transaction_id,
            sender_receipt_hash,
            peer_receipt_hash,
            identity_generation,
            revocation_generation,
            policy_revision,
        })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, Invalid> {
        encode(
            RECOVERY_KIND,
            &[
                Value::Text(RECOVERY_DOMAIN.to_owned()),
                Value::Bytes(self.transaction_id.to_vec()),
                Value::Bytes(self.sender_receipt_hash.to_vec()),
                Value::Bool(self.peer_receipt_hash.is_some()),
                Value::Bytes(self.peer_receipt_hash.unwrap_or([0; 32]).to_vec()),
                Value::Number(self.identity_generation),
                Value::Number(self.revocation_generation),
                Value::Number(self.policy_revision),
            ],
        )
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Invalid> {
        let values = decode(RECOVERY_KIND, bytes, &[3, 2, 2, 4, 2, 1, 1, 1])?;
        if values[0] != Value::Text(RECOVERY_DOMAIN.to_owned()) {
            return Err(Invalid);
        }
        let array = |value: &Value| -> Result<[u8; 32], Invalid> {
            let Value::Bytes(bytes) = value else {
                return Err(Invalid);
            };
            bytes.as_slice().try_into().map_err(|_| Invalid)
        };
        let Value::Bool(has_peer_receipt_hash) = values[3] else {
            return Err(Invalid);
        };
        let peer_receipt_hash = array(&values[4])?;
        let peer_receipt_hash = match (has_peer_receipt_hash, peer_receipt_hash) {
            (true, hash) if hash != [0; 32] => Some(hash),
            (false, hash) if hash == [0; 32] => None,
            _ => return Err(Invalid),
        };
        let Value::Number(identity_generation) = values[5] else {
            return Err(Invalid);
        };
        let Value::Number(revocation_generation) = values[6] else {
            return Err(Invalid);
        };
        let Value::Number(policy_revision) = values[7] else {
            return Err(Invalid);
        };
        Self::new(
            array(&values[1])?,
            array(&values[2])?,
            peer_receipt_hash,
            identity_generation,
            revocation_generation,
            policy_revision,
        )
    }

    /// Reject anything except the complementary evidence for this exact
    /// transaction.  This check is pure and unauthenticated by design: its
    /// caller must first bind the bytes to the peer's mutual-TLS identity.
    pub(crate) fn accepts_peer(&self, peer: &Self) -> bool {
        self.transaction_id == peer.transaction_id
            && self
                .peer_receipt_hash
                .is_none_or(|hash| hash == peer.sender_receipt_hash)
            && peer
                .peer_receipt_hash
                .is_none_or(|hash| hash == self.sender_receipt_hash)
            && self.identity_generation == peer.identity_generation
            && self.revocation_generation == peer.revocation_generation
            && self.policy_revision == peer.policy_revision
    }
}

#[cfg(test)]
mod tests {
    use super::ExactPeerRecovery;

    fn left() -> ExactPeerRecovery {
        ExactPeerRecovery::new([1; 32], [2; 32], Some([3; 32]), 7, 11, 0).unwrap()
    }

    fn right() -> ExactPeerRecovery {
        ExactPeerRecovery::new([1; 32], [3; 32], Some([2; 32]), 7, 11, 0).unwrap()
    }

    #[test]
    fn exact_peer_recovery_round_trips_and_accepts_only_complementary_evidence() {
        let left = left();
        let right = ExactPeerRecovery::decode(&right().encode().unwrap()).unwrap();
        assert!(left.accepts_peer(&right));
        assert!(right.accepts_peer(&left));
    }

    #[test]
    fn exact_peer_recovery_rejects_every_changed_binding() {
        let left = left();
        for changed in [
            ExactPeerRecovery::new([9; 32], [3; 32], Some([2; 32]), 7, 11, 0).unwrap(),
            ExactPeerRecovery::new([1; 32], [9; 32], Some([2; 32]), 7, 11, 0).unwrap(),
            ExactPeerRecovery::new([1; 32], [3; 32], Some([9; 32]), 7, 11, 0).unwrap(),
            ExactPeerRecovery::new([1; 32], [3; 32], Some([2; 32]), 9, 11, 0).unwrap(),
            ExactPeerRecovery::new([1; 32], [3; 32], Some([2; 32]), 7, 9, 0).unwrap(),
            ExactPeerRecovery::new([1; 32], [3; 32], Some([2; 32]), 7, 11, 9).unwrap(),
        ] {
            assert!(!left.accepts_peer(&changed));
        }
    }

    #[test]
    fn exact_peer_recovery_rejects_malformed_or_zero_records() {
        assert!(ExactPeerRecovery::new([0; 32], [2; 32], Some([3; 32]), 1, 1, 0).is_err());
        assert!(ExactPeerRecovery::decode(b"not a recovery record").is_err());
    }

    #[test]
    fn exact_peer_recovery_preserves_the_valid_unconfirmed_durable_state() {
        let left = ExactPeerRecovery::new([1; 32], [2; 32], None, 7, 11, 0).unwrap();
        let right = ExactPeerRecovery::new([1; 32], [3; 32], None, 7, 11, 0).unwrap();
        assert!(left.accepts_peer(&right));
        assert_eq!(ExactPeerRecovery::decode(&left.encode().unwrap()).unwrap(), left);
    }
}
