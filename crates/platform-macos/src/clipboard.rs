use seamless_input_core::clipboard::{ClipboardError as CoreClipboardError, validate_png};
use seamless_input_core::platform::{
    AccessState, ClipboardContent, ClipboardOutcome, PlatformClipboard,
};
use seamless_input_protocol::{MAX_PNG_BYTES, MAX_TEXT_BYTES};
use sha2::{Digest, Sha256};

const DEBOUNCE_MS: u64 = 200;

pub trait ClipboardBackend {
    fn access_state(&self) -> AccessState;
    fn change_count(&self) -> Result<u64, ClipboardError>;
    fn read(&mut self) -> Result<Option<ClipboardContent>, ClipboardError>;
    fn write(&mut self, content: &ClipboardContent) -> Result<(), ClipboardError>;
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ClipboardError {
    #[error("pasteboard access is unavailable")]
    AccessUnavailable,
    #[error("clipboard content exceeds the protocol limit")]
    TooLarge,
    #[error("clipboard data could not be converted")]
    Conversion,
    #[error("clipboard backend failed")]
    Backend,
    #[error("monotonic clock moved backwards")]
    ClockWentBackwards,
}

pub struct MacClipboard {
    backend: Box<dyn ClipboardBackend>,
    observed_change: Option<u64>,
    pending_since: Option<u64>,
    last_now: u64,
    last_hash: Option<[u8; 32]>,
}

impl MacClipboard {
    pub fn with_backend(backend: impl ClipboardBackend + 'static) -> Self {
        Self {
            backend: Box::new(backend),
            observed_change: None,
            pending_since: None,
            last_now: 0,
            last_hash: None,
        }
    }

    fn validate(content: &ClipboardContent) -> Result<(), ClipboardError> {
        match content {
            ClipboardContent::Text(text) if text.len() > MAX_TEXT_BYTES => {
                Err(ClipboardError::TooLarge)
            }
            ClipboardContent::Png(bytes) if bytes.len() > MAX_PNG_BYTES => {
                Err(ClipboardError::TooLarge)
            }
            ClipboardContent::Png(bytes) => validate_png(bytes).map_err(|error| match error {
                CoreClipboardError::TooLarge => ClipboardError::TooLarge,
                CoreClipboardError::MalformedPng | CoreClipboardError::HashMismatch => {
                    ClipboardError::Conversion
                }
            }),
            _ => Ok(()),
        }
    }

    fn hash(content: &ClipboardContent) -> [u8; 32] {
        let mut hash = Sha256::new();
        match content {
            ClipboardContent::Text(text) => {
                hash.update([0]);
                hash.update(text.as_bytes());
            }
            ClipboardContent::Png(bytes) => {
                hash.update([1]);
                hash.update(bytes);
            }
        }
        hash.finalize().into()
    }
}

impl PlatformClipboard for MacClipboard {
    type Error = ClipboardError;

    fn access_state(&self) -> AccessState {
        self.backend.access_state()
    }

    fn poll(&mut self, now_ms: u64) -> Result<ClipboardOutcome, Self::Error> {
        if now_ms < self.last_now {
            return Err(ClipboardError::ClockWentBackwards);
        }
        self.last_now = now_ms;
        if self.backend.access_state() != AccessState::Granted {
            return Ok(ClipboardOutcome::Disabled);
        }
        let change = self.backend.change_count()?;
        if self.observed_change != Some(change) {
            self.observed_change = Some(change);
            self.pending_since = Some(now_ms);
            return Ok(ClipboardOutcome::Pending);
        }
        let Some(since) = self.pending_since else {
            return Ok(ClipboardOutcome::Unchanged);
        };
        if now_ms - since < DEBOUNCE_MS {
            return Ok(ClipboardOutcome::Pending);
        }
        self.pending_since = None;
        let Some(content) = self.backend.read()? else {
            return Ok(ClipboardOutcome::Unchanged);
        };
        Self::validate(&content)?;
        let hash = Self::hash(&content);
        if self.last_hash == Some(hash) {
            return Ok(ClipboardOutcome::Unchanged);
        }
        self.last_hash = Some(hash);
        Ok(ClipboardOutcome::Changed(content))
    }

    fn write_remote(&mut self, content: &ClipboardContent) -> Result<(), Self::Error> {
        if self.backend.access_state() != AccessState::Granted {
            return Err(ClipboardError::AccessUnavailable);
        }
        Self::validate(content)?;
        self.backend.write(content)?;
        self.last_hash = Some(Self::hash(content));
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use arboard::{Clipboard, ImageData};
    use image::{DynamicImage, ImageFormat, RgbaImage};
    use std::{
        borrow::Cow,
        io::Cursor,
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
    };

    pub struct PasteboardBackend {
        clipboard: Mutex<Option<Clipboard>>,
        access: AccessState,
        count: AtomicU64,
        observed_hash: Mutex<Option<[u8; 32]>>,
    }

    impl PasteboardBackend {
        pub fn new() -> Self {
            match Clipboard::new() {
                Ok(clipboard) => Self {
                    clipboard: Mutex::new(Some(clipboard)),
                    access: AccessState::Granted,
                    count: AtomicU64::new(0),
                    observed_hash: Mutex::new(None),
                },
                Err(_) => Self {
                    clipboard: Mutex::new(None),
                    access: AccessState::Denied,
                    count: AtomicU64::new(0),
                    observed_hash: Mutex::new(None),
                },
            }
        }

        fn snapshot(&self) -> Result<Option<ClipboardContent>, ClipboardError> {
            let mut guard = self.clipboard.lock().map_err(|_| ClipboardError::Backend)?;
            let clipboard = guard.as_mut().ok_or(ClipboardError::AccessUnavailable)?;
            match clipboard.get_text() {
                Ok(text) => return Ok(Some(ClipboardContent::Text(text))),
                Err(arboard::Error::ContentNotAvailable) => {}
                Err(_) => return Err(ClipboardError::Backend),
            }
            match clipboard.get_image() {
                Ok(image) => {
                    let rgba = RgbaImage::from_raw(
                        image.width as u32,
                        image.height as u32,
                        image.bytes.into_owned(),
                    )
                    .ok_or(ClipboardError::Conversion)?;
                    let mut encoded = Cursor::new(Vec::new());
                    DynamicImage::ImageRgba8(rgba)
                        .write_to(&mut encoded, ImageFormat::Png)
                        .map_err(|_| ClipboardError::Conversion)?;
                    Ok(Some(ClipboardContent::Png(encoded.into_inner())))
                }
                Err(arboard::Error::ContentNotAvailable) => Ok(None),
                Err(_) => Err(ClipboardError::Backend),
            }
        }
    }

    impl Default for PasteboardBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ClipboardBackend for PasteboardBackend {
        fn access_state(&self) -> AccessState {
            self.access
        }
        fn change_count(&self) -> Result<u64, ClipboardError> {
            if self.access != AccessState::Granted {
                return Err(ClipboardError::AccessUnavailable);
            }
            let content = self.snapshot()?;
            let hash = content.as_ref().map(MacClipboard::hash);
            let mut observed = self
                .observed_hash
                .lock()
                .map_err(|_| ClipboardError::Backend)?;
            if *observed != hash {
                *observed = hash;
                self.count.fetch_add(1, Ordering::Relaxed);
            }
            Ok(self.count.load(Ordering::Relaxed))
        }
        fn read(&mut self) -> Result<Option<ClipboardContent>, ClipboardError> {
            self.snapshot()
        }
        fn write(&mut self, content: &ClipboardContent) -> Result<(), ClipboardError> {
            MacClipboard::validate(content)?;
            let mut guard = self.clipboard.lock().map_err(|_| ClipboardError::Backend)?;
            let clipboard = guard.as_mut().ok_or(ClipboardError::AccessUnavailable)?;
            match content {
                ClipboardContent::Text(text) => clipboard
                    .set_text(text)
                    .map_err(|_| ClipboardError::Backend),
                ClipboardContent::Png(bytes) => {
                    let image = image::load_from_memory_with_format(bytes, ImageFormat::Png)
                        .map_err(|_| ClipboardError::Conversion)?
                        .into_rgba8();
                    let (width, height) = image.dimensions();
                    clipboard
                        .set_image(ImageData {
                            width: width as usize,
                            height: height as usize,
                            bytes: Cow::Owned(image.into_raw()),
                        })
                        .map_err(|_| ClipboardError::Backend)
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub use native::PasteboardBackend;

#[cfg(target_os = "macos")]
impl MacClipboard {
    pub fn new() -> Self {
        Self::with_backend(PasteboardBackend::new())
    }
}

#[cfg(target_os = "macos")]
impl Default for MacClipboard {
    fn default() -> Self {
        Self::new()
    }
}
