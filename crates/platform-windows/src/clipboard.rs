use seamless_input_core::clipboard::{ClipboardError as CoreClipboardError, validate_png};
use seamless_input_core::platform::{
    AccessState, ClipboardContent, ClipboardOutcome, PlatformClipboard,
};
use seamless_input_protocol::{MAX_PNG_BYTES, MAX_TEXT_BYTES};
use sha2::{Digest, Sha256};

const DEBOUNCE_MS: u64 = 200;

pub trait ClipboardBackend {
    fn available(&self) -> bool;
    fn sequence_number(&self) -> Result<u64, ClipboardError>;
    fn read(&mut self) -> Result<Option<ClipboardContent>, ClipboardError>;
    fn write(&mut self, content: &ClipboardContent) -> Result<(), ClipboardError>;
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ClipboardError {
    #[error("clipboard is temporarily held by another process")]
    Busy,
    #[error("clipboard access is unavailable")]
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

pub struct WindowsClipboard {
    backend: Box<dyn ClipboardBackend>,
    observed_sequence: Option<u64>,
    pending_since: Option<u64>,
    last_now: u64,
    last_hash: Option<[u8; 32]>,
    pending_remote: Option<ClipboardContent>,
}

impl WindowsClipboard {
    pub fn with_backend(backend: impl ClipboardBackend + 'static) -> Self {
        Self {
            backend: Box::new(backend),
            observed_sequence: None,
            pending_since: None,
            last_now: 0,
            last_hash: None,
            pending_remote: None,
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

impl PlatformClipboard for WindowsClipboard {
    type Error = ClipboardError;

    fn access_state(&self) -> AccessState {
        if self.backend.available() {
            AccessState::Granted
        } else {
            AccessState::Denied
        }
    }

    fn poll(&mut self, now_ms: u64) -> Result<ClipboardOutcome, Self::Error> {
        if now_ms < self.last_now {
            return Err(ClipboardError::ClockWentBackwards);
        }
        self.last_now = now_ms;
        if let Some(content) = self.pending_remote.take() {
            match self.backend.write(&content) {
                Ok(()) => self.last_hash = Some(Self::hash(&content)),
                Err(ClipboardError::Busy) => {
                    self.pending_remote = Some(content);
                    return Ok(ClipboardOutcome::Pending);
                }
                Err(error) => return Err(error),
            }
        }
        if !self.backend.available() {
            return Ok(ClipboardOutcome::Disabled);
        }
        let sequence = self.backend.sequence_number()?;
        if self.observed_sequence != Some(sequence) {
            self.observed_sequence = Some(sequence);
            self.pending_since = Some(now_ms);
            return Ok(ClipboardOutcome::Pending);
        }
        let Some(since) = self.pending_since else {
            return Ok(ClipboardOutcome::Unchanged);
        };
        if now_ms - since < DEBOUNCE_MS {
            return Ok(ClipboardOutcome::Pending);
        }
        let content = match self.backend.read() {
            // Another process may acquire the clipboard after available() succeeds.
            // Keep this sequence pending so a later tick can retry it.
            Err(ClipboardError::Busy | ClipboardError::AccessUnavailable) => {
                self.pending_since = Some(now_ms);
                return Ok(ClipboardOutcome::Pending);
            }
            result => result?,
        };
        self.pending_since = None;
        let Some(content) = content else {
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
        Self::validate(content)?;
        // The read-only access probe is a snapshot; the native write must get
        // its own bounded open attempts. Retain only the latest validated update
        // if those attempts encounter contention, without committing its hash.
        self.pending_remote = None;
        match self.backend.write(content) {
            Ok(()) => {
                self.last_hash = Some(Self::hash(content));
                Ok(())
            }
            Err(ClipboardError::Busy) => {
                self.pending_remote = Some(content.clone());
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(target_os = "windows")]
mod native {
    use super::*;
    use arboard::{Clipboard, ImageData};
    use image::{DynamicImage, ImageFormat, RgbaImage};
    use std::{borrow::Cow, io::Cursor, sync::Mutex};
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardSequenceNumber, OpenClipboard,
    };

    fn backend_error(error: arboard::Error) -> ClipboardError {
        match error {
            arboard::Error::ClipboardOccupied => ClipboardError::Busy,
            arboard::Error::ClipboardNotSupported => ClipboardError::AccessUnavailable,
            arboard::Error::ConversionFailure => ClipboardError::Conversion,
            _ => ClipboardError::Backend,
        }
    }

    pub struct Win32Clipboard {
        clipboard: Mutex<Option<Clipboard>>,
    }

    impl Win32Clipboard {
        pub fn new() -> Self {
            Self {
                clipboard: Mutex::new(Clipboard::new().ok()),
            }
        }
    }
    impl Default for Win32Clipboard {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ClipboardBackend for Win32Clipboard {
        fn available(&self) -> bool {
            let Ok(guard) = self.clipboard.lock() else {
                return false;
            };
            if guard.is_none() {
                return false;
            }
            // arboard's Windows constructor does not open the clipboard. Probe
            // actual current-session access without reading or changing content.
            unsafe {
                if OpenClipboard(std::ptr::null_mut()) == 0 {
                    return false;
                }
                CloseClipboard() != 0
            }
        }
        fn sequence_number(&self) -> Result<u64, ClipboardError> {
            Ok(u64::from(unsafe { GetClipboardSequenceNumber() }))
        }
        fn read(&mut self) -> Result<Option<ClipboardContent>, ClipboardError> {
            let mut guard = self.clipboard.lock().map_err(|_| ClipboardError::Backend)?;
            let clipboard = guard.as_mut().ok_or(ClipboardError::AccessUnavailable)?;
            match clipboard.get_text() {
                Ok(text) => return Ok(Some(ClipboardContent::Text(text))),
                Err(arboard::Error::ContentNotAvailable) => {}
                Err(error) => return Err(backend_error(error)),
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
                Err(error) => Err(backend_error(error)),
            }
        }
        fn write(&mut self, content: &ClipboardContent) -> Result<(), ClipboardError> {
            WindowsClipboard::validate(content)?;
            let mut guard = self.clipboard.lock().map_err(|_| ClipboardError::Backend)?;
            let clipboard = guard.as_mut().ok_or(ClipboardError::AccessUnavailable)?;
            match content {
                ClipboardContent::Text(text) => clipboard.set_text(text).map_err(backend_error),
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
                        .map_err(backend_error)
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn native_busy_error_is_retryable_but_conversion_and_unknown_errors_are_not() {
            assert_eq!(
                backend_error(arboard::Error::ClipboardOccupied),
                ClipboardError::Busy
            );
            assert_eq!(
                backend_error(arboard::Error::ConversionFailure),
                ClipboardError::Conversion
            );
            assert_eq!(
                backend_error(arboard::Error::Unknown {
                    description: "must not expose native details".into(),
                }),
                ClipboardError::Backend
            );
        }
    }
}

#[cfg(target_os = "windows")]
pub use native::Win32Clipboard;

#[cfg(target_os = "windows")]
impl WindowsClipboard {
    pub fn new() -> Self {
        Self::with_backend(Win32Clipboard::new())
    }
}

#[cfg(target_os = "windows")]
impl Default for WindowsClipboard {
    fn default() -> Self {
        Self::new()
    }
}
