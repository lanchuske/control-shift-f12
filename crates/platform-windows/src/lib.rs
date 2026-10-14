//! Windows current-user-session adapter.

pub mod clipboard;
pub mod displays;
pub mod input;

pub use clipboard::WindowsClipboard;
pub use displays::WindowsDisplays;
pub use input::WindowsInput;
