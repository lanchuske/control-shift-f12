use crate::identity::{IdentityStore, PinnedPeer};
use bip39::Language;
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::{
    fmt,
    time::{Duration, SystemTime},
};
use zeroize::Zeroize;

const CODE_LIFETIME: Duration = Duration::from_secs(300);
const PAIRING_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const CONTEXT: &[u8] = b"seamless-input pairing v1";
type ConfirmMac = Hmac<Sha256>;

#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    #[error("pairing code expired")]
    Expired,
    #[error("pairing code already consumed")]
    Consumed,
    #[error("invalid pairing code")]
    InvalidCode,
    #[error("invalid peer identity")]
    InvalidIdentity,
    #[error("pairing key confirmation failed")]
    ConfirmationMismatch,
    #[error("peer certificate pin mismatch")]
    PinMismatch,
    #[error("pairing protocol message invalid")]
    InvalidMessage,
    #[error("identity storage failed")]
    Io(#[from] std::io::Error),
    #[error("identity encoding failed")]
    Json(#[from] serde_json::Error),
    #[error("identity certificate failed")]
    Certificate(#[from] rcgen::Error),
    #[error("identity encoding failed")]
    Base64(#[from] base64::DecodeError),
    #[error("mutual TLS configuration failed")]
    Tls,
    #[error("temporary pairing channel failed")]
    Network,
    #[error("pairing operation timed out")]
    TimedOut,
}

pub struct PairingCode {
    phrase: String,
    expires_at: SystemTime,
    consumed: bool,
}
impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingCode")
            .field("phrase", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("consumed", &self.consumed)
            .finish()
    }
}
impl Drop for PairingCode {
    fn drop(&mut self) {
        self.phrase.zeroize();
    }
}
impl PairingCode {
    pub fn generate(now: SystemTime) -> Result<Self, PairingError> {
        let words = Language::English.word_list();
        let mut random = [0u8; 12];
        OsRng.fill_bytes(&mut random);
        let phrase = (0..6)
            .map(|i| {
                let v = u16::from_be_bytes([random[i * 2], random[i * 2 + 1]]);
                words[usize::from(v) & 0x7ff]
            })
            .collect::<Vec<_>>()
            .join(" ");
        random.zeroize();
        Ok(Self {
            phrase,
            expires_at: now
                .checked_add(CODE_LIFETIME)
                .ok_or(PairingError::InvalidCode)?,
            consumed: false,
        })
    }
    pub const fn entropy_bits() -> usize {
        66
    }
    pub fn phrase(&self) -> &str {
        &self.phrase
    }
    fn consume(&mut self, now: SystemTime) -> Result<String, PairingError> {
        if self.consumed {
            return Err(PairingError::Consumed);
        }
        if now > self.expires_at {
            return Err(PairingError::Expired);
        }
        self.consumed = true;
        Ok(self.phrase.clone())
    }
}

#[derive(Serialize, Deserialize)]
struct WireMessage {
    version: u8,
    session_id: [u8; 16],
    node_id: [u8; 16],
    friendly_name: String,
    certificate_der: Vec<u8>,
    pake_message: Vec<u8>,
}
pub struct PairingSession {
    state: Spake2<Ed25519Group>,
    outbound: Vec<u8>,
}
impl fmt::Debug for PairingSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingSession")
            .field("outbound", &"[PAIRING MESSAGE]")
            .finish_non_exhaustive()
    }
}
impl PairingSession {
    pub fn offer(
        identity: &IdentityStore,
        code: &mut PairingCode,
        now: SystemTime,
    ) -> Result<Self, PairingError> {
        let mut phrase = code.consume(now)?;
        let result = Self::start(identity, &phrase);
        phrase.zeroize();
        result
    }
    pub fn accept(identity: &IdentityStore, phrase: &str) -> Result<Self, PairingError> {
        Self::start(identity, phrase)
    }
    fn start(identity: &IdentityStore, phrase: &str) -> Result<Self, PairingError> {
        validate_phrase(phrase)?;
        let (state, pake_message) = Spake2::<Ed25519Group>::start_symmetric(
            &Password::new(phrase.as_bytes()),
            &Identity::new(CONTEXT),
        );
        let mut session_id = [0u8; 16];
        OsRng.fill_bytes(&mut session_id);
        let wire = WireMessage {
            version: 1,
            session_id,
            node_id: identity.node_id().0,
            friendly_name: identity.friendly_name().to_owned(),
            certificate_der: identity.certificate_der().to_vec(),
            pake_message,
        };
        Ok(Self {
            state,
            outbound: serde_json::to_vec(&wire)?,
        })
    }
    pub fn message(&self) -> &[u8] {
        &self.outbound
    }
    pub fn finish(
        self,
        peer_message: &[u8],
    ) -> Result<(PendingPairing, PairingConfirmation), PairingError> {
        let local: WireMessage =
            serde_json::from_slice(&self.outbound).map_err(|_| PairingError::InvalidMessage)?;
        let peer: WireMessage =
            serde_json::from_slice(peer_message).map_err(|_| PairingError::InvalidMessage)?;
        validate_wire(&peer)?;
        if peer.node_id == local.node_id || peer.session_id == local.session_id {
            return Err(PairingError::InvalidMessage);
        }
        let mut shared = self
            .state
            .finish(&peer.pake_message)
            .map_err(|_| PairingError::InvalidMessage)?;
        let transcript = canonical_transcript(&self.outbound, peer_message);
        let local_tag = confirmation_tag(&shared, &transcript, local.node_id);
        let expected_peer_tag = confirmation_tag(&shared, &transcript, peer.node_id);
        shared.zeroize();
        let record = record_from_wire(&peer)?;
        let confirmation = PairingConfirmation {
            session_id: local.session_id,
            peer_session_id: peer.session_id,
            tag: local_tag,
        };
        Ok((
            PendingPairing {
                record,
                local_session_id: local.session_id,
                peer_session_id: peer.session_id,
                expected_peer_tag,
            },
            confirmation,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingConfirmation {
    pub session_id: [u8; 16],
    pub peer_session_id: [u8; 16],
    tag: [u8; 32],
}
pub struct PendingPairing {
    record: PinnedPeer,
    local_session_id: [u8; 16],
    peer_session_id: [u8; 16],
    expected_peer_tag: [u8; 32],
}
impl PendingPairing {
    pub fn confirm(self, peer: &PairingConfirmation) -> Result<PinnedPeer, PairingError> {
        if peer.session_id != self.peer_session_id
            || peer.peer_session_id != self.local_session_id
            || peer.tag != self.expected_peer_tag
        {
            Err(PairingError::ConfirmationMismatch)
        } else {
            Ok(self.record)
        }
    }
}

fn validate_phrase(phrase: &str) -> Result<(), PairingError> {
    let words = Language::English.word_list();
    let parts: Vec<_> = phrase.split_whitespace().collect();
    if parts.len() != 6 || parts.iter().any(|p| words.binary_search(p).is_err()) {
        Err(PairingError::InvalidCode)
    } else {
        Ok(())
    }
}
fn validate_wire(w: &WireMessage) -> Result<(), PairingError> {
    if w.version != 1
        || w.session_id == [0; 16]
        || w.node_id == [0; 16]
        || w.friendly_name.trim().is_empty()
        || w.friendly_name.len() > 80
        || w.certificate_der.is_empty()
        || w.pake_message.len() != 33
    {
        Err(PairingError::InvalidMessage)
    } else {
        Ok(())
    }
}
fn record_from_wire(w: &WireMessage) -> Result<PinnedPeer, PairingError> {
    let pin: [u8; 32] = Sha256::digest(&w.certificate_der).into();
    if w.node_id != pin[..16] {
        return Err(PairingError::InvalidIdentity);
    }
    Ok(PinnedPeer {
        node_id: seamless_input_protocol::NodeId(w.node_id),
        friendly_name: w.friendly_name.clone(),
        public_identity: w.certificate_der.clone(),
        certificate_pin: pin,
    })
}
fn canonical_transcript(first: &[u8], second: &[u8]) -> Vec<u8> {
    let (left, right) = if first <= second {
        (first, second)
    } else {
        (second, first)
    };
    let mut out = Vec::with_capacity(CONTEXT.len() + left.len() + right.len() + 16);
    out.extend_from_slice(CONTEXT);
    out.extend_from_slice(&(left.len() as u64).to_be_bytes());
    out.extend_from_slice(left);
    out.extend_from_slice(&(right.len() as u64).to_be_bytes());
    out.extend_from_slice(right);
    out
}
fn confirmation_tag(key: &[u8], transcript: &[u8], sender: [u8; 16]) -> [u8; 32] {
    let mut mac = ConfirmMac::new_from_slice(key).expect("SPAKE2 key length is valid");
    mac.update(transcript);
    mac.update(&sender);
    mac.finalize().into_bytes().into()
}

pub async fn pair_offer_over_quic(
    connection: &quinn::Connection,
    identity: &mut IdentityStore,
    code: &mut PairingCode,
    now: SystemTime,
) -> Result<PinnedPeer, PairingError> {
    pair_offer_over_quic_with_timeout(connection, identity, code, now, PAIRING_OPERATION_TIMEOUT)
        .await
}

pub async fn pair_offer_over_quic_with_timeout(
    connection: &quinn::Connection,
    identity: &mut IdentityStore,
    code: &mut PairingCode,
    now: SystemTime,
    timeout: Duration,
) -> Result<PinnedPeer, PairingError> {
    let session = PairingSession::offer(identity, code, now)?;
    let peer = tokio::time::timeout(timeout, async {
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|_| PairingError::Network)?;
        exchange_pairing(send, recv, session).await
    })
    .await
    .map_err(|_| PairingError::TimedOut)??;
    identity.pin_peer(peer.clone())?;
    Ok(peer)
}

pub async fn pair_accept_over_quic(
    connection: &quinn::Connection,
    identity: &mut IdentityStore,
    phrase: &str,
) -> Result<PinnedPeer, PairingError> {
    pair_accept_over_quic_with_timeout(connection, identity, phrase, PAIRING_OPERATION_TIMEOUT)
        .await
}

pub async fn pair_accept_over_quic_with_timeout(
    connection: &quinn::Connection,
    identity: &mut IdentityStore,
    phrase: &str,
    timeout: Duration,
) -> Result<PinnedPeer, PairingError> {
    let session = PairingSession::accept(identity, phrase)?;
    let peer = tokio::time::timeout(timeout, async {
        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|_| PairingError::Network)?;
        exchange_pairing(send, recv, session).await
    })
    .await
    .map_err(|_| PairingError::TimedOut)??;
    identity.pin_peer(peer.clone())?;
    Ok(peer)
}

async fn exchange_pairing(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    session: PairingSession,
) -> Result<PinnedPeer, PairingError> {
    write_frame(&mut send, session.message()).await?;
    let peer_message = read_frame(&mut recv).await?;
    let (pending, confirmation) = session.finish(&peer_message)?;
    let confirmation = serde_json::to_vec(&confirmation)?;
    write_frame(&mut send, &confirmation).await?;
    send.finish().map_err(|_| PairingError::Network)?;
    let peer_confirmation: PairingConfirmation =
        serde_json::from_slice(&read_frame(&mut recv).await?)
            .map_err(|_| PairingError::InvalidMessage)?;
    pending.confirm(&peer_confirmation)
}

async fn write_frame(send: &mut quinn::SendStream, payload: &[u8]) -> Result<(), PairingError> {
    use tokio::io::AsyncWriteExt;
    if payload.len() > 64 * 1024 {
        return Err(PairingError::InvalidMessage);
    }
    send.write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .map_err(|_| PairingError::Network)?;
    send.write_all(payload)
        .await
        .map_err(|_| PairingError::Network)?;
    send.flush().await.map_err(|_| PairingError::Network)
}
async fn read_frame(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, PairingError> {
    let mut header = [0u8; 4];
    recv.read_exact(&mut header)
        .await
        .map_err(|_| PairingError::Network)?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > 64 * 1024 {
        return Err(PairingError::InvalidMessage);
    }
    let mut payload = vec![0; len];
    recv.read_exact(&mut payload)
        .await
        .map_err(|_| PairingError::Network)?;
    Ok(payload)
}
