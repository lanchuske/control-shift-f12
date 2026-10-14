//! macOS current-user-session adapter.

pub mod clipboard;
pub mod displays;
pub mod input;

pub use clipboard::MacClipboard;
pub use displays::MacDisplays;
pub use input::MacInput;
