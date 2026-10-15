//! Small OS-neutral contracts implemented by the user-session adapters.

use seamless_input_protocol::InputEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessState {
    NotDetermined,
    Denied,
    Granted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    Local,
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventDisposition {
    PassThrough,
    Suppress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardContent {
    Text(String),
    Png(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardOutcome {
    Disabled,
    Pending,
    Unchanged,
    Changed(ClipboardContent),
}

#[derive(Debug, Clone, PartialEq)]
pub struct NativeDisplay {
    pub index: u32,
    pub physical_x: f64,
    pub physical_y: f64,
    pub physical_width: f64,
    pub physical_height: f64,
    pub scale: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LogicalDisplay {
    pub index: u32,
    pub origin_x: f64,
    pub origin_y: f64,
    pub width: f64,
    pub height: f64,
    pub scale: f64,
}

pub trait PlatformInput {
    type Error;

    fn access_state(&self) -> AccessState;
    fn inject(&mut self, event: &InputEvent) -> Result<(), Self::Error>;
    fn release_all(&mut self) -> Result<(), Self::Error>;
}

pub trait PlatformDisplays {
    type Error;

    fn displays(&self) -> Result<Vec<LogicalDisplay>, Self::Error>;
}

pub trait PlatformClipboard {
    type Error;

    fn access_state(&self) -> AccessState;
    fn poll(&mut self, now_ms: u64) -> Result<ClipboardOutcome, Self::Error>;
    fn write_remote(&mut self, content: &ClipboardContent) -> Result<(), Self::Error>;
}
