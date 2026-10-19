//! Exact bilateral recovery evidence.
//!
//! The sealed grammar and bounded exchange operate on a caller-owned pinned
//! mutual-TLS control connection. This module cannot mutate durable state or
//! activate a session; only its authenticated result reaches the coordinator.

use super::{
    Invalid,
    codec::{Value, decode, encode},
};
use rustls::pki_types::PrivateKeyDer;
use std::net::SocketAddr;

const RECOVERY_DOMAIN: &str = "control-shift-f12/bilateral-recovery-v1";
const RECOVERY_KIND: &str = "bilateral-recovery";
const RECOVERY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
const RECOVERY_MAX_RECORD: usize = 2048;
const RECOVERY_ACK: u8 = 0xA1;
const RECOVERY_ALPN: &[u8] = b"control-shift-f12-recovery/1";

/// A short-lived recovery-only QUIC endpoint. It negotiates a distinct ALPN
/// and requires mutual TLS; exact durable pin validation remains coupled to
/// `exchange_exact_pair`, which consumes the resulting connection.
pub(crate) struct RecoveryEndpoint {
    endpoint: quinn::Endpoint,
    client: super::provisional_tls::StrictClient,
    local_leaf: [u8; 32],
}

impl RecoveryEndpoint {
    pub(crate) fn bind(
        address: SocketAddr,
        certificate: Vec<u8>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, Invalid> {
        let local_leaf = super::evidence::hash(&certificate);
        let (server, client) =
            super::provisional_tls::strict_configs(certificate, key, RECOVERY_ALPN, 1, 0)?;
        let endpoint = quinn::Endpoint::server(server, address).map_err(|_| Invalid)?;
        Ok(Self {
            endpoint,
            client,
            local_leaf,
        })
    }

    pub(crate) fn local_fingerprint(&self) -> [u8; 32] {
        self.local_leaf
    }

    pub(crate) fn local_addr(&self) -> Result<SocketAddr, Invalid> {
        self.endpoint.local_addr().map_err(|_| Invalid)
    }

    pub(crate) async fn connect(&self, peer: SocketAddr) -> Result<quinn::Connection, Invalid> {
        let (client, auth) = self.client.fresh()?;
        let connecting = self
            .endpoint
            .connect_with(client, peer, "recovery.local")
            .map_err(|_| Invalid)?;
        let connection = tokio::time::timeout(RECOVERY_DEADLINE, connecting)
            .await
            .map_err(|_| Invalid)?
            .map_err(|_| Invalid)?;
        if !auth.was_requested() {
            connection.close(0u32.into(), b"mutual authentication required");
            return Err(Invalid);
        }
        Ok(connection)
    }

    pub(crate) async fn accept(&self) -> Result<quinn::Connection, Invalid> {
        tokio::time::timeout(RECOVERY_DEADLINE, async {
            self.endpoint
                .accept()
                .await
                .ok_or(Invalid)?
                .await
                .map_err(|_| Invalid)
        })
        .await
        .map_err(|_| Invalid)?
    }
}

impl Drop for RecoveryEndpoint {
    fn drop(&mut self) {
        self.endpoint
            .close(0u32.into(), b"recovery endpoint closed");
    }
}

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
/// evidence by the durable store. The observed TLS pin travels with the proof
/// and must match the consuming receipt's durable peer pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedExactPeerRecovery {
    evidence: ExactPeerRecovery,
    peer_pin: [u8; 32],
}

impl AuthenticatedExactPeerRecovery {
    pub(crate) fn evidence(&self) -> &ExactPeerRecovery {
        &self.evidence
    }

    pub(crate) fn authenticated_peer_pin(&self) -> [u8; 32] {
        self.peer_pin
    }

    #[cfg(test)]
    pub(crate) fn test_only(evidence: ExactPeerRecovery, peer_pin: [u8; 32]) -> Self {
        Self { evidence, peer_pin }
    }
}

/// Exchanges exactly one evidence record on a fresh pinned mutual-TLS
/// connection. The initiator sends first; the responder sends only after it
/// has validated the initiator's complementary descriptor. No store mutation
/// is possible here, and every rejection closes this recovery-only channel.
/// The caller retains the connection for the duration of the exchange so a
/// successful responder cannot tear it down before the initiator observes its
/// clean stream finish.
/// Authentication is checked here, before any record exchange: callers cannot
/// mint this wrapper through another ALPN or by supplying a different pin.
pub(crate) async fn exchange_exact_pair(
    connection: &quinn::Connection,
    initiator: bool,
    local: ExactPeerRecovery,
    expected_peer_pin: [u8; 32],
) -> Result<AuthenticatedExactPeerRecovery, Invalid> {
    let result = tokio::time::timeout(RECOVERY_DEADLINE, async {
        validate_recovery_channel(connection, expected_peer_pin)?;
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
                Ok(AuthenticatedExactPeerRecovery {
                    evidence: peer,
                    peer_pin: expected_peer_pin,
                })
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
                Ok(AuthenticatedExactPeerRecovery {
                    evidence: peer,
                    peer_pin: expected_peer_pin,
                })
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

fn validate_recovery_channel(connection: &quinn::Connection, pin: [u8; 32]) -> Result<(), Invalid> {
    let handshake = connection
        .handshake_data()
        .ok_or(Invalid)?
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(|_| Invalid)?;
    let certificates = connection
        .peer_identity()
        .ok_or(Invalid)?
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .map_err(|_| Invalid)?;
    if connection.close_reason().is_some() {
        return Err(Invalid);
    }
    validate_recovery_identity(handshake.protocol.as_deref(), certificates.as_slice(), pin)
}

fn validate_recovery_identity(
    protocol: Option<&[u8]>,
    certificates: &[rustls::pki_types::CertificateDer<'_>],
    pin: [u8; 32],
) -> Result<(), Invalid> {
    if pin == [0; 32]
        || protocol != Some(b"control-shift-f12-recovery/1")
        || certificates.len() != 1
        || super::evidence::hash(certificates[0].as_ref()) != pin
    {
        return Err(Invalid);
    }
    Ok(())
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

    fn identity() -> (Vec<u8>, rustls::pki_types::PrivateKeyDer<'static>) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.subject_alt_names = vec![rcgen::SanType::URI(
            "urn:control-shift-f12:identity".try_into().unwrap(),
        )];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let cert = params.self_signed(&key).unwrap();
        (
            cert.der().to_vec(),
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
    }

    #[tokio::test]
    async fn recovery_endpoint_uses_fresh_mutual_tls_and_exact_recovery_alpn() {
        let (left_cert, left_key) = identity();
        let (right_cert, right_key) = identity();
        let left_pin = super::super::evidence::hash(&left_cert);
        let right_pin = super::super::evidence::hash(&right_cert);
        let left_endpoint =
            super::RecoveryEndpoint::bind("127.0.0.1:0".parse().unwrap(), left_cert, left_key)
                .unwrap();
        let right_endpoint =
            super::RecoveryEndpoint::bind("127.0.0.1:0".parse().unwrap(), right_cert, right_key)
                .unwrap();

        let (left_connection, right_connection) = tokio::join!(
            left_endpoint.connect(right_endpoint.local_addr().unwrap()),
            right_endpoint.accept()
        );
        let left_connection = left_connection.unwrap();
        let right_connection = right_connection.unwrap();
        let (left_peer, right_peer) = tokio::join!(
            super::exchange_exact_pair(&left_connection, true, left(), right_pin),
            super::exchange_exact_pair(&right_connection, false, right(), left_pin),
        );
        assert_eq!(left_peer.unwrap().authenticated_peer_pin(), right_pin);
        assert_eq!(right_peer.unwrap().authenticated_peer_pin(), left_pin);
    }

    #[test]
    fn exact_peer_recovery_identity_gate_requires_recovery_alpn_and_durable_pin() {
        use rustls::pki_types::CertificateDer;
        use sha2::{Digest, Sha256};
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = rcgen::CertificateParams::default()
            .self_signed(&key)
            .unwrap();
        let chain = [CertificateDer::from(cert.der().to_vec())];
        let pin: [u8; 32] = Sha256::digest(chain[0].as_ref()).into();
        assert!(
            super::validate_recovery_identity(Some(b"control-shift-f12-recovery/1"), &chain, pin)
                .is_ok()
        );
        for protocol in [None, Some(&b"different-control-channel/1"[..])] {
            assert!(super::validate_recovery_identity(protocol, &chain, pin).is_err());
        }
        let mut other_pin = pin;
        other_pin[0] ^= 1;
        assert!(
            super::validate_recovery_identity(
                Some(b"control-shift-f12-recovery/1"),
                &chain,
                other_pin
            )
            .is_err()
        );
        assert!(
            super::validate_recovery_identity(
                Some(b"control-shift-f12-recovery/1"),
                &chain,
                [0; 32]
            )
            .is_err()
        );
        assert!(
            super::validate_recovery_identity(Some(b"control-shift-f12-recovery/1"), &[], pin)
                .is_err()
        );
        assert!(
            super::validate_recovery_identity(
                Some(b"control-shift-f12-recovery/1"),
                &[chain[0].clone(), chain[0].clone()],
                pin
            )
            .is_err()
        );
    }

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
