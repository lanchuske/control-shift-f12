//! Reviewed transport record grammar; no handshake-envelope or stream-role policy.
use super::Invalid;
use super::codec::{Value, decode, encode};
use tokio::io::AsyncReadExt;
pub const ALPN: &[u8] = b"csf12-pair/2";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRequest {
    pub(super) request_id: [u8; 16],
    pub(super) rendezvous: [u8; 16],
    pub(super) nonce: [u8; 16],
}
impl CandidateRequest {
    pub fn new(request_id: [u8; 16], rendezvous: [u8; 16], nonce: [u8; 16]) -> Self {
        Self {
            request_id,
            rendezvous,
            nonce,
        }
    }
    pub fn decode(raw: &[u8]) -> Result<Self, Invalid> {
        if raw.len() > 1024 {
            return Err(Invalid);
        }
        let fields = decode("candidate-request", raw, &[1, 2, 2, 2, 3, 1])?;
        if fields[0] != Value::Number(2)
            || fields[4] != Value::Text("csf12-pair/2".into())
            || fields[5] != Value::Number(4096)
        {
            return Err(Invalid);
        }
        let array = |i| match &fields[i] {
            Value::Bytes(v) => v.as_slice().try_into().map_err(|_| Invalid),
            _ => Err(Invalid),
        };
        let request = Self::new(array(1)?, array(2)?, array(3)?);
        if request.encode()? != raw {
            return Err(Invalid);
        }
        Ok(request)
    }
    pub fn encode(&self) -> Result<Vec<u8>, Invalid> {
        encode(
            "candidate-request",
            &[
                Value::Number(2),
                Value::Bytes(self.request_id.to_vec()),
                Value::Bytes(self.rendezvous.to_vec()),
                Value::Bytes(self.nonce.to_vec()),
                Value::Text("csf12-pair/2".into()),
                Value::Number(4096),
            ],
        )
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    CandidateRequest,
    CandidateHello,
    Handshake,
}
impl FrameKind {
    fn limit(self) -> usize {
        match self {
            Self::CandidateRequest => 1024,
            Self::CandidateHello => 4096,
            Self::Handshake => 16384,
        }
    }
    fn tag(self) -> u8 {
        match self {
            Self::CandidateRequest => 1,
            Self::CandidateHello => 2,
            Self::Handshake => 3,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFrame {
    pub kind: FrameKind,
    pub payload: Vec<u8>,
}
impl TransportFrame {
    pub fn encode(&self) -> Result<Vec<u8>, Invalid> {
        if self.payload.len() > self.kind.limit() {
            return Err(Invalid);
        }
        let mut out = b"CSF12P2\0".to_vec();
        out.extend(2u16.to_be_bytes());
        out.push(self.kind.tag());
        out.extend((self.payload.len() as u32).to_be_bytes());
        out.extend(&self.payload);
        Ok(out)
    }
    pub fn decode(raw: &[u8]) -> Result<Self, Invalid> {
        let (kind, len) = header(raw.get(..15).ok_or(Invalid)?)?;
        if raw.len() != 15 + len {
            return Err(Invalid);
        }
        Ok(Self {
            kind,
            payload: raw[15..].to_vec(),
        })
    }
}
fn header(raw: &[u8]) -> Result<(FrameKind, usize), Invalid> {
    if raw.len() != 15 || raw[..8] != *b"CSF12P2\0" || raw[8..10] != 2u16.to_be_bytes() {
        return Err(Invalid);
    }
    let kind = match raw[10] {
        1 => FrameKind::CandidateRequest,
        2 => FrameKind::CandidateHello,
        3 => FrameKind::Handshake,
        _ => return Err(Invalid),
    };
    let len = u32::from_be_bytes(raw[11..15].try_into().map_err(|_| Invalid)?) as usize;
    if len > kind.limit() {
        return Err(Invalid);
    }
    Ok((kind, len))
}
/// Adapter for an externally delimited complete record. Requires EOF after one
/// frame; does not assign QUIC streams, directions or handshake message order.
pub async fn read_record<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    deadline: tokio::time::Instant,
) -> Result<TransportFrame, Invalid> {
    tokio::time::timeout_at(deadline, async {
        let mut raw = [0; 15];
        reader.read_exact(&mut raw).await.map_err(|_| Invalid)?;
        let (kind, len) = header(&raw)?;
        let mut payload = vec![0; len];
        reader.read_exact(&mut payload).await.map_err(|_| Invalid)?;
        let mut trailing = [0; 1];
        if reader.read(&mut trailing).await.map_err(|_| Invalid)? != 0 {
            return Err(Invalid);
        }
        Ok(TransportFrame { kind, payload })
    })
    .await
    .map_err(|_| Invalid)?
}
