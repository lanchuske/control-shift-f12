//! Per-user-root control process ownership. No trust or transport admission.
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum InstanceError {
    #[error("control engine already running for this user root")]
    AlreadyRunning,
    #[error("control engine instance lock unavailable")]
    Unavailable,
}

pub struct SetupInstanceLock {
    #[cfg(unix)]
    _file: std::fs::File,
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(unix)]
impl SetupInstanceLock {
    pub fn acquire(root: &Path) -> Result<Self, InstanceError> {
        let root =
            crate::private_fs::PrivateDir::root(root).map_err(|_| InstanceError::Unavailable)?;
        let directory = root
            .child("setup-control")
            .map_err(|_| InstanceError::Unavailable)?;
        Ok(Self {
            _file: directory.try_lock()?,
        })
    }
}

#[cfg(windows)]
impl SetupInstanceLock {
    pub fn acquire(root: &Path) -> Result<Self, InstanceError> {
        use sha2::{Digest, Sha256};
        use windows_sys::Win32::{
            Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError},
            System::Threading::CreateMutexW,
        };
        if !root.is_absolute() {
            return Err(InstanceError::Unavailable);
        }
        std::fs::create_dir_all(root).map_err(|_| InstanceError::Unavailable)?;
        let canonical = std::fs::canonicalize(root).map_err(|_| InstanceError::Unavailable)?;
        let hash = Sha256::digest(canonical.to_string_lossy().to_lowercase().as_bytes());
        let suffix: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        let name: Vec<u16> = format!("Local\\ControlShiftF12.Setup.{suffix}")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        // Default security descriptor uses the caller token; object lives in this session.
        // This is only an instance lock, not the owner-only persistent pending store.
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(InstanceError::Unavailable);
        }
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe {
                CloseHandle(handle);
            }
            return Err(InstanceError::AlreadyRunning);
        }
        Ok(Self { handle })
    }
}

#[cfg(windows)]
impl Drop for SetupInstanceLock {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(not(any(unix, windows)))]
impl SetupInstanceLock {
    pub fn acquire(_root: &Path) -> Result<Self, InstanceError> {
        Err(InstanceError::Unavailable)
    }
}
