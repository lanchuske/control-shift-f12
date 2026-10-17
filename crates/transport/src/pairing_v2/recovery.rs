//! Exact bilateral recovery evidence.
//!
//! The sealed grammar and bounded exchange operate on a caller-owned pinned
//! mutual-TLS control connection. This module cannot mutate durable state or
//! activate a session; only its authenticated result reaches the coordinator.

use super::{
    Invalid,
    codec::{Value, decode, encode},
};

const RECOVERY_DOMAIN: &str = "control-shift-f12/bilateral-recovery-v1";
const RECOVERY_KIND: &str = "bilateral-recovery";
const RECOVERY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
const RECOVERY_MAX_RECORD: usize = 2048;
const RECOVERY_ACK: u8 = 0xA1;

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

    pub(crate) fn sender_receipt_hash(&self) -> [u8; 32] {
        self.sender_receipt_hash
    }
}

/// Evidence returned only after the fresh pinned mutual-TLS exchange has
/// compared the two descriptors. Its payload remains crate-private so raw
/// serialized recovery data cannot be mistaken for transport-authenticated
/// evidence by the durable store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedExactPeerRecovery(ExactPeerRecovery);

impl AuthenticatedExactPeerRecovery {
    pub(crate) fn evidence(&self) -> &ExactPeerRecovery {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn test_only(evidence: ExactPeerRecovery) -> Self {
        Self(evidence)
    }
}

/// Exchanges exactly one evidence record on a fresh pinned mutual-TLS
/// connection. The initiator sends first; the responder sends only after it
/// has validated the initiator's complementary descriptor. No store mutation
/// is possible here, and every rejection closes this recovery-only channel.
/// The caller retains the connection for the duration of the exchange so a
/// successful responder cannot tear it down before the initiator observes its
/// clean stream finish.
pub(crate) async fn exchange_exact_pair(
    connection: &quinn::Connection,
    initiator: bool,
    local: ExactPeerRecovery,
) -> Result<AuthenticatedExactPeerRecovery, Invalid> {
    let result = tokio::time::timeout(RECOVERY_DEADLINE, async {
        let protocol = async {
            if initiator {
                let (mut send, mut recv) = connection.open_bi().await.map_err(|_| Invalid)?;
                write_recovery_record(&mut send, &local).await?;
                let peer = read_recovery_record(&mut recv).await?;
                if !local.accepts_peer(&peer) {
                    return Err(Invalid);
                }
                send.write_all(&[RECOVERY_ACK]).await.map_err(|_| Invalid)?;
                send.finish().map_err(|_| Invalid)?;
                recovery_eof(&mut recv).await?;
                Ok(AuthenticatedExactPeerRecovery(peer))
            } else {
                let (mut send, mut recv) = connection.accept_bi().await.map_err(|_| Invalid)?;
                let peer = read_recovery_record(&mut recv).await?;
                if !local.accepts_peer(&peer) {
                    return Err(Invalid);
                }
                write_recovery_record(&mut send, &local).await?;
                let mut ack = [0; 1];
                recv.read_exact(&mut ack).await.map_err(|_| Invalid)?;
                if ack != [RECOVERY_ACK] {
                    return Err(Invalid);
                }
                recovery_eof(&mut recv).await?;
                send.finish().map_err(|_| Invalid)?;
                Ok(AuthenticatedExactPeerRecovery(peer))
            }
        };
        tokio::select! { biased;
            result = protocol => result,
            extra = connection.accept_bi() => {
                if let Ok((send, recv)) = extra { drop(send); drop(recv); }
                Err(Invalid)
            }
            extra = connection.accept_uni() => {
                if let Ok(mut recv) = extra { let _ = recv.stop(0u32.into()); }
                Err(Invalid)
            }
            _ = connection.closed() => Err(Invalid),
        }
    })
    .await;
    match result {
        Ok(Ok(peer)) => Ok(peer),
        Ok(Err(_)) | Err(_) => {
            connection.close(0u32.into(), b"exact recovery rejected");
            Err(Invalid)
        }
    }
}

async fn write_recovery_record(
    send: &mut quinn::SendStream,
    evidence: &ExactPeerRecovery,
) -> Result<(), Invalid> {
    let payload = evidence.encode()?;
    if payload.is_empty() || payload.len() > RECOVERY_MAX_RECORD {
        return Err(Invalid);
    }
    send.write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .map_err(|_| Invalid)?;
    send.write_all(&payload).await.map_err(|_| Invalid)
}

async fn read_recovery_record(recv: &mut quinn::RecvStream) -> Result<ExactPeerRecovery, Invalid> {
    let mut length = [0; 4];
    recv.read_exact(&mut length).await.map_err(|_| Invalid)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > RECOVERY_MAX_RECORD {
        return Err(Invalid);
    }
    let mut payload = vec![0; length];
    recv.read_exact(&mut payload).await.map_err(|_| Invalid)?;
    ExactPeerRecovery::decode(&payload)
}

async fn recovery_eof(recv: &mut quinn::RecvStream) -> Result<(), Invalid> {
    recv.read_to_end(1)
        .await
        .map_err(|_| Invalid)?
        .is_empty()
        .then_some(())
        .ok_or(Invalid)
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
        assert_eq!(
            ExactPeerRecovery::decode(&left.encode().unwrap()).unwrap(),
            left
        );
    }
}
