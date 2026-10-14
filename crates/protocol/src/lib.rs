//! Bounded, versioned wire types for authenticated peer sessions.
//!
//! Framing does not authenticate a sender or grant an input lease. Consumers
//! must use one `SequenceTracker` per authenticated session direction before
//! dispatching decoded input. Clipboard chunks are wire data only; reassembly,
//! content validation, deduplication, and capability negotiation belong to the
//! peer runtime. No wire contents are logged here.

use serde::{Deserialize, Serialize};

pub const VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;
pub const MAX_PNG_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Modifier {
    Shift,
    Control,
    Alt,
    Meta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Button {
    Left,
    Right,
    Middle,
    Back,
    Forward,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InputEvent {
    /// Absolute position in the selected display owner's logical desktop.
    Pointer {
        x: f64,
        y: f64,
    },
    Button {
        button: Button,
        pressed: bool,
    },
    Scroll {
        horizontal: f64,
        vertical: f64,
    },
    /// Physical USB HID keyboard usage ID, translated by each OS adapter.
    Key {
        code: u16,
        pressed: bool,
    },
    Modifier {
        modifier: Modifier,
        pressed: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub input: bool,
    pub text: bool,
    pub png: bool,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum Message {
    Input(InputEvent),
    Heartbeat,
    Capabilities(Capabilities),
    ClipboardChunk {
        hash: [u8; 32],
        offset: u32,
        total: u32,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input(event) => f.debug_tuple("Input").field(event).finish(),
            Self::Heartbeat => f.write_str("Heartbeat"),
            Self::Capabilities(capabilities) => {
                f.debug_tuple("Capabilities").field(capabilities).finish()
            }
            Self::ClipboardChunk {
                offset,
                total,
                data,
                ..
            } => f
                .debug_struct("ClipboardChunk")
                .field("offset", offset)
                .field("total", total)
                .field("bytes", &data.len())
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Frame {
    pub version: u16,
    pub sequence: u64,
    pub message: Message,
}

impl Frame {
    pub fn new(sequence: u64, message: Message) -> Self {
        Self {
            version: VERSION,
            sequence,
            message,
        }
    }
}

impl InputEvent {
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Pointer { x, y } => x.is_finite() && y.is_finite(),
            Self::Scroll {
                horizontal,
                vertical,
            } => horizontal.is_finite() && vertical.is_finite(),
            _ => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Truncated,
    TooLarge,
    UnknownVersion(u16),
    Malformed,
    DuplicateSequence,
    StaleSequence,
    InvalidInput,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ProtocolError {}

fn validate(frame: &Frame) -> Result<(), ProtocolError> {
    if frame.version != VERSION {
        return Err(ProtocolError::UnknownVersion(frame.version));
    }
    if let Message::Input(event) = &frame.message
        && !event.is_valid()
    {
        return Err(ProtocolError::InvalidInput);
    }
    Ok(())
}

struct BoundedWriter {
    bytes: Vec<u8>,
    exceeded: bool,
}
impl std::io::Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_FRAME_BYTES - self.bytes.len() {
            self.exceeded = true;
            return Err(std::io::Error::other("frame limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A four-byte big-endian payload length followed by one MessagePack frame.
/// The 8 MiB cap includes MessagePack overhead, excludes the four-byte prefix.
/// Clipboard PNGs at the full content limit must therefore be chunked.
pub fn encode(frame: &Frame) -> Result<Vec<u8>, ProtocolError> {
    validate(frame)?;
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        exceeded: false,
    };
    if rmp_serde::encode::write(&mut writer, frame).is_err() {
        return Err(if writer.exceeded {
            ProtocolError::TooLarge
        } else {
            ProtocolError::Malformed
        });
    }
    let mut bytes = Vec::with_capacity(writer.bytes.len() + 4);
    bytes.extend_from_slice(&(writer.bytes.len() as u32).to_be_bytes());
    bytes.extend(writer.bytes);
    Ok(bytes)
}

fn payload_length(prefix: &[u8]) -> Result<usize, ProtocolError> {
    let prefix: [u8; 4] = prefix.try_into().map_err(|_| ProtocolError::Truncated)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    Ok(length)
}

fn decode_payload(payload: &[u8]) -> Result<Frame, ProtocolError> {
    let mut cursor = std::io::Cursor::new(payload);
    let frame = Frame::deserialize(&mut rmp_serde::Deserializer::new(&mut cursor))
        .map_err(|_| ProtocolError::Malformed)?;
    if cursor.position() as usize != payload.len() {
        return Err(ProtocolError::Malformed);
    }
    validate(&frame)?;
    Ok(frame)
}

/// Decode exactly one frame. Extra bytes fail closed; stream readers should
/// use `read_frame` to consume one frame at a time instead.
pub fn decode(bytes: &[u8]) -> Result<Frame, ProtocolError> {
    if bytes.len() < 4 {
        return Err(ProtocolError::Truncated);
    }
    let length = payload_length(&bytes[..4])?;
    if bytes.len() < length + 4 {
        return Err(ProtocolError::Truncated);
    }
    if bytes.len() != length + 4 {
        return Err(ProtocolError::Malformed);
    }
    decode_payload(&bytes[4..])
}

/// Validate the prefix before allocating or requesting the payload. The reader
/// owns its deadline; an incomplete or failed read fails closed.
pub fn read_frame(reader: &mut impl std::io::Read) -> Result<Frame, ProtocolError> {
    let mut prefix = [0; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|_| ProtocolError::Truncated)?;
    let length = payload_length(&prefix)?;
    let mut payload = vec![0; length];
    reader
        .read_exact(&mut payload)
        .map_err(|_| ProtocolError::Truncated)?;
    decode_payload(&payload)
}

#[derive(Debug, Default)]
pub struct SequenceTracker {
    last: Option<u64>,
}
impl SequenceTracker {
    /// One tracker per authenticated direction/session; sequence gaps are safe,
    /// duplicates and rollback (including counter wrap) never reset history.
    pub fn accept(&mut self, sequence: u64) -> Result<(), ProtocolError> {
        if let Some(last) = self.last {
            if sequence == last {
                return Err(ProtocolError::DuplicateSequence);
            }
            if sequence < last {
                return Err(ProtocolError::StaleSequence);
            }
        }
        self.last = Some(sequence);
        Ok(())
    }
}
