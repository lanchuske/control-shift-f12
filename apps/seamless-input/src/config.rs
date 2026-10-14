use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

pub const CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigV1 {
    pub version: u32,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub placements: Vec<Placement>,
}

impl Default for ConfigV1 {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            peers: Vec::new(),
            placements: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    /// Public, opaque node identity. Private key material belongs in the identity store.
    pub node_id: String,
    pub name: String,
    #[serde(default)]
    pub displays: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Placement {
    pub display: String,
    pub x: i32,
    pub y: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    UserConfigUnavailable,
    OutsideUserConfig,
    UnsupportedVersion(u32),
    Io(String),
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserConfigUnavailable => {
                write!(f, "the current user's config directory is unavailable")
            }
            Self::OutsideUserConfig => write!(
                f,
                "config path must remain inside the current user's config directory"
            ),
            Self::UnsupportedVersion(version) => write!(f, "unsupported config version {version}"),
            Self::Io(error) => write!(f, "config I/O failed: {error}"),
            Self::Invalid(error) => write!(f, "invalid config: {error}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<io::Error> for ConfigError {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct ConfigStore {
    path: PathBuf,
}

impl ConfigStore {
    pub fn new(path: PathBuf) -> Result<Self, ConfigError> {
        if path.as_os_str().is_empty() {
            return Err(ConfigError::OutsideUserConfig);
        }
        Ok(Self { path })
    }

    pub fn default_path() -> Result<PathBuf, ConfigError> {
        #[cfg(target_os = "windows")]
        let root = env::var_os("APPDATA").map(PathBuf::from);
        #[cfg(not(target_os = "windows"))]
        let root = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")));
        root.map(|root| root.join("seamless-input").join("config.toml"))
            .ok_or(ConfigError::UserConfigUnavailable)
    }

    pub fn within_user_root(path: PathBuf, root: &Path) -> Result<Self, ConfigError> {
        let clean_root = lexical_normalize(root);
        let clean_path = lexical_normalize(&path);
        if !clean_path.starts_with(&clean_root) || clean_path == clean_root {
            return Err(ConfigError::OutsideUserConfig);
        }
        Ok(Self { path: clean_path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<ConfigV1, ConfigError> {
        let bytes = fs::read(&self.path)?;
        decode(&bytes)
    }

    pub fn load_or_default(&self) -> Result<ConfigV1, ConfigError> {
        match self.load() {
            Ok(config) => Ok(config),
            Err(ConfigError::Io(_)) if !self.path.exists() => Ok(ConfigV1::default()),
            Err(error) => Err(error),
        }
    }

    pub fn save(&self, config: &ConfigV1) -> Result<(), ConfigError> {
        validate(config)?;
        let encoded = toml::to_string_pretty(config)
            .map_err(|error| ConfigError::Invalid(error.to_string()))?;
        self.write_temp(encoded.as_bytes())?;
        self.commit_temp()
    }

    pub fn live_reload(&self) -> Result<LiveConfig, ConfigError> {
        let current = self.load_or_default()?;
        let observed = serialized_fingerprint(&current)?;
        Ok(LiveConfig {
            store: self.clone(),
            current,
            observed,
        })
    }

    fn temp_path(&self) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(".tmp");
        PathBuf::from(name)
    }

    fn write_temp(&self, bytes: &[u8]) -> Result<(), ConfigError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp = self.temp_path();
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn commit_temp(&self) -> Result<(), ConfigError> {
        let temp = self.temp_path();
        let bytes = fs::read(&temp)?;
        decode(&bytes)?;
        replace_file(&temp, &self.path)?;
        sync_parent(&self.path)?;
        Ok(())
    }

    #[doc(hidden)]
    pub fn write_temp_for_test(&self, text: &str) -> Result<(), ConfigError> {
        self.write_temp(text.as_bytes())
    }

    #[doc(hidden)]
    pub fn commit_temp_for_test(&self) -> Result<(), ConfigError> {
        self.commit_temp()
    }
}

pub struct LiveConfig {
    store: ConfigStore,
    current: ConfigV1,
    observed: Vec<u8>,
}

impl LiveConfig {
    pub fn store(&self) -> ConfigStore {
        self.store.clone()
    }

    /// Polling keeps the runtime dependency-free and works with atomic renames.
    pub fn poll(&mut self) -> Result<Option<ConfigV1>, ConfigError> {
        let candidate = self.store.load()?;
        let fingerprint = serialized_fingerprint(&candidate)?;
        if fingerprint == self.observed {
            return Ok(None);
        }
        self.observed = fingerprint;
        self.current = candidate.clone();
        Ok(Some(candidate))
    }

    pub fn current(&self) -> &ConfigV1 {
        &self.current
    }
}

fn decode(bytes: &[u8]) -> Result<ConfigV1, ConfigError> {
    let text =
        std::str::from_utf8(bytes).map_err(|error| ConfigError::Invalid(error.to_string()))?;
    let config: ConfigV1 =
        toml::from_str(text).map_err(|error| ConfigError::Invalid(error.to_string()))?;
    validate(&config)?;
    Ok(config)
}

fn validate(config: &ConfigV1) -> Result<(), ConfigError> {
    if config.version != CONFIG_VERSION {
        return Err(ConfigError::UnsupportedVersion(config.version));
    }
    Ok(())
}

fn serialized_fingerprint(config: &ConfigV1) -> Result<Vec<u8>, ConfigError> {
    toml::to_string(config)
        .map(String::into_bytes)
        .map_err(|error| ConfigError::Invalid(error.to_string()))
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    result
}

fn sync_parent(path: &Path) -> Result<(), ConfigError> {
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
    // SAFETY: both buffers are NUL-terminated and remain alive for the call.
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
