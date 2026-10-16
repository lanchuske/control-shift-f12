use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use thiserror::Error;

const VERSION: u8 = 1;
const MAX_AGE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeStatus {
    pub process_id: u32,
    pub updated_unix_ms: u64,
    pub displays: usize,
    pub authenticated_sessions: usize,
}

impl RuntimeStatus {
    pub fn live(
        process_id: u32,
        displays: usize,
        authenticated_sessions: usize,
    ) -> Result<Self, RuntimeStatusError> {
        Ok(Self {
            process_id,
            updated_unix_ms: unix_millis(SystemTime::now())?,
            displays,
            authenticated_sessions,
        })
    }

    pub fn display_line(self) -> String {
        format!(
            "Control Shift F12 running: {} display(s), {} authenticated session(s)",
            self.displays, self.authenticated_sessions
        )
    }
}

#[derive(Debug, Error)]
pub enum RuntimeStatusError {
    #[error("runtime status I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("runtime status is invalid")]
    Invalid,
    #[error("system clock is before the Unix epoch")]
    Clock,
}

#[derive(Debug, Clone)]
pub struct RuntimeStatusStore {
    path: PathBuf,
}

impl RuntimeStatusStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn within(root: &Path) -> Self {
        Self::new(root.join("runtime-status.v1"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn publish(&self, status: &RuntimeStatus) -> Result<(), RuntimeStatusError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp = temp_path(&self.path);
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        writeln!(file, "version={VERSION}")?;
        writeln!(file, "process_id={}", status.process_id)?;
        writeln!(file, "updated_unix_ms={}", status.updated_unix_ms)?;
        writeln!(file, "displays={}", status.displays)?;
        writeln!(
            file,
            "authenticated_sessions={}",
            status.authenticated_sessions
        )?;
        file.sync_all()?;
        replace_file(&temp, &self.path)?;
        sync_parent(&self.path)?;
        Ok(())
    }

    pub fn read_current(
        &self,
        now: SystemTime,
    ) -> Result<Option<RuntimeStatus>, RuntimeStatusError> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let status = decode(&text)?;
        let now_ms = unix_millis(now)?;
        if status.updated_unix_ms > now_ms.saturating_add(1_000) {
            return Err(RuntimeStatusError::Invalid);
        }
        if now_ms.saturating_sub(status.updated_unix_ms) > MAX_AGE.as_millis() as u64 {
            return Ok(None);
        }
        Ok(Some(status))
    }

    pub fn clear(&self) -> Result<(), RuntimeStatusError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn decode(text: &str) -> Result<RuntimeStatus, RuntimeStatusError> {
    let mut version = None;
    let mut process_id = None;
    let mut updated_unix_ms = None;
    let mut displays = None;
    let mut authenticated_sessions = None;
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or(RuntimeStatusError::Invalid)?;
        match key {
            "version" => version = value.parse::<u8>().ok(),
            "process_id" => process_id = value.parse::<u32>().ok(),
            "updated_unix_ms" => updated_unix_ms = value.parse::<u64>().ok(),
            "displays" => displays = value.parse::<usize>().ok(),
            "authenticated_sessions" => authenticated_sessions = value.parse::<usize>().ok(),
            _ => return Err(RuntimeStatusError::Invalid),
        }
    }
    if version != Some(VERSION) {
        return Err(RuntimeStatusError::Invalid);
    }
    Ok(RuntimeStatus {
        process_id: process_id.ok_or(RuntimeStatusError::Invalid)?,
        updated_unix_ms: updated_unix_ms.ok_or(RuntimeStatusError::Invalid)?,
        displays: displays.ok_or(RuntimeStatusError::Invalid)?,
        authenticated_sessions: authenticated_sessions.ok_or(RuntimeStatusError::Invalid)?,
    })
}

fn unix_millis(time: SystemTime) -> Result<u64, RuntimeStatusError> {
    u64::try_from(
        time.duration_since(UNIX_EPOCH)
            .map_err(|_| RuntimeStatusError::Clock)?
            .as_millis(),
    )
    .map_err(|_| RuntimeStatusError::Clock)
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

fn sync_parent(path: &Path) -> Result<(), RuntimeStatusError> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(target_os = "windows")]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
