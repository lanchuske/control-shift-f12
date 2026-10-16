//! Directory-FD anchored Unix storage. Never follows symlinks beneath the root.
use crate::pairing_pending::StoreError;
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
};

pub(crate) struct PrivateDir(File);

// Fault controls exist only in the unit-test executable, never in library builds.
#[cfg(all(test, feature = "pairing-v2-experimental"))]
pub(crate) mod faults {
    use super::StoreError;
    std::thread_local! {static ARMED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };}
    pub fn arm() {
        ARMED.set(true);
    }
    pub fn point(file: &str, stage: &str) -> Result<(), StoreError> {
        if !ARMED.get() {
            return Ok(());
        };
        let target = if file == "ledger.json" {
            "ledger"
        } else if file.starts_with("journal-") {
            "journal"
        } else {
            "pending"
        };
        let Ok(setting) = std::env::var("PAIRING_TEST_FS_FAULT") else {
            return Ok(());
        };
        if setting == format!("{target}:{stage}:crash") {
            std::process::exit(91)
        }
        if setting == format!("{target}:{stage}:error") {
            return Err(StoreError::Unavailable);
        }
        Ok(())
    }
}

macro_rules! fault_point {
    ($file:expr, $stage:expr) => {
        #[cfg(all(test, feature = "pairing-v2-experimental"))]
        faults::point($file, $stage)?;
    };
}

fn name(value: &str) -> Result<CString, StoreError> {
    if value.is_empty() || value.contains('/') || value == "." || value == ".." {
        return Err(StoreError::Invalid);
    }
    CString::new(value).map_err(|_| StoreError::Invalid)
}

fn validate(file: &File, directory: bool) -> Result<(), StoreError> {
    let m = file.metadata().map_err(|_| StoreError::Unavailable)?;
    // SAFETY: geteuid has no arguments or memory preconditions.
    if m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || if directory {
            !m.is_dir()
        } else {
            !m.is_file() || m.nlink() != 1
        }
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

impl PrivateDir {
    pub fn root(path: &Path) -> Result<Self, StoreError> {
        if !path.is_absolute() {
            return Err(StoreError::Invalid);
        }
        match std::fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(path).map_err(|_| StoreError::Unavailable)?;
            }
            Err(_) => return Err(StoreError::Unavailable),
        }
        // Reject root links at the atomic open, not with a raceable path precheck.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| StoreError::Invalid)?;
        let m = file.metadata().map_err(|_| StoreError::Unavailable)?;
        // Root is explicitly supplied by the trusted local caller, never a peer field.
        if m.uid() != unsafe { libc::geteuid() } {
            return Err(StoreError::Invalid);
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o700))
            .map_err(|_| StoreError::Unavailable)?;
        validate(&file, true)?;
        Ok(Self(file))
    }

    pub fn child(&self, value: &str) -> Result<Self, StoreError> {
        let name = name(value)?;
        // SAFETY: live directory FD, NUL-terminated fixed child name.
        let made = unsafe { libc::mkdirat(self.0.as_raw_fd(), name.as_ptr(), 0o700) };
        if made != 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(StoreError::Unavailable);
        }
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(StoreError::Invalid);
        }
        // SAFETY: successful openat transferred a new owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        validate(&file, true)?;
        self.0.sync_all().map_err(|_| StoreError::Unavailable)?;
        Ok(Self(file))
    }

    fn open(&self, value: &str, flags: i32) -> Result<Option<File>, StoreError> {
        let name = name(value)?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(StoreError::Invalid)
            };
        }
        let file = unsafe { File::from_raw_fd(fd) };
        validate(&file, false)?;
        Ok(Some(file))
    }

    pub fn lock(&self) -> Result<File, StoreError> {
        let file = self
            .open("writer.lock", libc::O_RDWR | libc::O_CREAT)?
            .ok_or(StoreError::Unavailable)?;
        file.lock().map_err(|_| StoreError::Unavailable)?;
        Ok(file)
    }

    pub fn try_lock(&self) -> Result<File, crate::setup_lock::InstanceError> {
        use crate::setup_lock::InstanceError;
        let file = self
            .open("writer.lock", libc::O_RDWR | libc::O_CREAT)
            .map_err(|_| InstanceError::Unavailable)?
            .ok_or(InstanceError::Unavailable)?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => Err(InstanceError::AlreadyRunning),
            Err(_) => Err(InstanceError::Unavailable),
        }
    }

    pub fn read(&self, value: &str, limit: usize) -> Result<Option<Vec<u8>>, StoreError> {
        let Some(file) = self.open(value, libc::O_RDONLY)? else {
            return Ok(None);
        };
        if file.metadata().map_err(|_| StoreError::Unavailable)?.len() > limit as u64 {
            return Err(StoreError::Limit);
        }
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| StoreError::Unavailable)?;
        if bytes.len() > limit {
            return Err(StoreError::Limit);
        }
        Ok(Some(bytes))
    }

    pub fn replace(&self, value: &str, bytes: &[u8]) -> Result<(), StoreError> {
        use rand::RngCore;
        // Reject existing indirect/nonprivate targets before a replacement.
        let _ = self.open(value, libc::O_RDONLY)?;
        let mut random = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let tmp = format!(
            ".pending-{}.tmp",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let result = (|| {
            fault_point!(value, "before_write");
            let mut file = self
                .open(&tmp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?
                .ok_or(StoreError::Unavailable)?;
            file.write_all(bytes).map_err(|_| StoreError::Unavailable)?;
            fault_point!(value, "after_write");
            fault_point!(value, "before_file_sync");
            file.sync_all().map_err(|_| StoreError::Unavailable)?;
            fault_point!(value, "after_file_sync");
            let from = name(&tmp)?;
            let to = name(value)?;
            fault_point!(value, "before_rename");
            let result = unsafe {
                libc::renameat(
                    self.0.as_raw_fd(),
                    from.as_ptr(),
                    self.0.as_raw_fd(),
                    to.as_ptr(),
                )
            };
            if result != 0 {
                return Err(StoreError::Unavailable);
            }
            fault_point!(value, "after_rename");
            // Failure after rename is ambiguous; fail closed, then re-read on the next operation.
            fault_point!(value, "before_dir_sync");
            self.0.sync_all().map_err(|_| StoreError::Unavailable)?;
            fault_point!(value, "after_dir_sync");
            fault_point!(value, "before_readback");
            if self.read(value, bytes.len())?.as_deref() != Some(bytes) {
                return Err(StoreError::Invalid);
            }
            fault_point!(value, "after_readback");
            fault_point!(value, "before_cleanup");
            // The atomic rename consumed the temporary name. This boundary is
            // explicit so crash schedules prove cleanup cannot alter publication.
            fault_point!(value, "after_cleanup");
            Ok(())
        })();
        if result.is_err() {
            let _ = self.remove(&tmp);
        }
        result
    }

    pub fn remove(&self, value: &str) -> Result<(), StoreError> {
        let name = name(value)?;
        let result = unsafe { libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), 0) };
        if result != 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound {
            return Err(StoreError::Unavailable);
        }
        self.0.sync_all().map_err(|_| StoreError::Unavailable)
    }
}
