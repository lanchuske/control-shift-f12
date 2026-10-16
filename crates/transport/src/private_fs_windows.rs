//! Owner-only Windows storage for pairing quarantine data.
use crate::pairing_pending::StoreError;
use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GENERIC_READ, GENERIC_WRITE,
        HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
        AddAccessAllowedAceEx,
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo},
        CONTAINER_INHERIT_ACE, CopySid, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetAclInformation, GetLengthSid, GetTokenInformation, InitializeAcl, OBJECT_INHERIT_ACE,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID, TOKEN_QUERY,
        TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_ALWAYS, CREATE_NEW, CreateFileW, DELETE,
        FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FlushFileBuffers,
        GetFileInformationByHandle, LOCKFILE_EXCLUSIVE_LOCK, LockFileEx, MOVEFILE_REPLACE_EXISTING,
        MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_EXISTING, READ_CONTROL, ReplaceFileW, WRITE_DAC,
        WRITE_OWNER,
    },
    System::{
        IO::OVERLAPPED,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

const ERROR_SUCCESS: u32 = 0;

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
        }
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

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn valid_name(value: &str) -> Result<(), StoreError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains(['/', '\\', ':'])
        || value.encode_utf16().any(|c| c == 0)
    {
        Err(StoreError::Invalid)
    } else {
        Ok(())
    }
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn current_user_sid() -> Result<Vec<u8>, StoreError> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(StoreError::Unavailable);
    }
    let token = Handle(token);
    let mut needed = 0;
    unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(StoreError::Unavailable);
    }
    // Token information contains pointer-aligned structs; a byte vector does not
    // promise sufficient alignment even though the Windows allocator usually does.
    let words = (needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut info = vec![0usize; words];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            info.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(StoreError::Unavailable);
    }
    let source = unsafe { (*(info.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let length = unsafe { GetLengthSid(source) };
    if length == 0 {
        return Err(StoreError::Unavailable);
    }
    let mut sid = vec![0u8; length as usize];
    if unsafe { CopySid(length, sid.as_mut_ptr().cast(), source) } == 0 {
        return Err(StoreError::Unavailable);
    }
    Ok(sid)
}

fn file_info(handle: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION, StoreError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(StoreError::Unavailable);
    }
    Ok(info)
}

fn identity(info: &BY_HANDLE_FILE_INFORMATION) -> (u32, u64) {
    (
        info.dwVolumeSerialNumber,
        ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
    )
}

fn build_acl(sid: &[u8], directory: bool) -> Result<Vec<u32>, StoreError> {
    let ace_size =
        std::mem::size_of::<ACCESS_ALLOWED_ACE>() - std::mem::size_of::<u32>() + sid.len();
    let byte_len = std::mem::size_of::<ACL>() + ace_size;
    let mut bytes = vec![0u32; byte_len.div_ceil(std::mem::size_of::<u32>())];
    let acl = bytes.as_mut_ptr().cast::<ACL>();
    if unsafe { InitializeAcl(acl, byte_len as u32, ACL_REVISION) } == 0 {
        return Err(StoreError::Unavailable);
    }
    let flags = if directory {
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    } else {
        0
    };
    if unsafe {
        AddAccessAllowedAceEx(
            acl,
            ACL_REVISION,
            flags,
            FILE_ALL_ACCESS,
            sid.as_ptr().cast_mut().cast(),
        )
    } == 0
    {
        return Err(StoreError::Unavailable);
    }
    Ok(bytes)
}

fn harden(handle: HANDLE, directory: bool, sid: &[u8]) -> Result<(), StoreError> {
    let mut acl = build_acl(sid, directory)?;
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            sid.as_ptr().cast_mut().cast(),
            ptr::null_mut(),
            acl.as_mut_ptr().cast(),
            ptr::null(),
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(StoreError::Unavailable)
    }
}

fn validate(handle: HANDLE, directory: bool, sid: &[u8]) -> Result<(), StoreError> {
    let info = file_info(handle)?;
    let is_dir = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || is_dir != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(StoreError::Invalid);
    }
    let mut owner: PSID = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || owner.is_null() || dacl.is_null() || descriptor.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor) };
        }
        return Err(StoreError::Invalid);
    }
    let result = (|| {
        if unsafe { EqualSid(owner, sid.as_ptr().cast_mut().cast()) } == 0 {
            return Err(StoreError::Invalid);
        }
        let mut size = ACL_SIZE_INFORMATION::default();
        if unsafe {
            GetAclInformation(
                dacl,
                (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
            || size.AceCount != 1
        {
            return Err(StoreError::Invalid);
        }
        let mut raw_ace = ptr::null_mut();
        if unsafe { GetAce(dacl, 0, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(StoreError::Invalid);
        }
        let ace = unsafe { &*(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) };
        let ace_sid = (&ace.SidStart as *const u32).cast_mut().cast();
        let expected_flags = if directory {
            CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
        } else {
            0
        };
        if ace.Header.AceType != 0
            || ace.Header.AceFlags != expected_flags as u8
            || ace.Mask != FILE_ALL_ACCESS
            || unsafe { EqualSid(ace_sid, sid.as_ptr().cast_mut().cast()) } == 0
        {
            return Err(StoreError::Invalid);
        }
        Ok(())
    })();
    unsafe { LocalFree(descriptor) };
    result
}

fn open_path(path: &Path, directory: bool, disposition: u32) -> Result<Option<File>, StoreError> {
    let flags = if directory {
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    } else {
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
    };
    let handle = unsafe {
        CreateFileW(
            wide(path.as_os_str()).as_ptr(),
            GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            disposition,
            flags,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = std::io::Error::last_os_error();
        return if matches!(error.raw_os_error(), Some(x) if x as u32 == ERROR_FILE_NOT_FOUND || x as u32 == ERROR_PATH_NOT_FOUND)
        {
            Ok(None)
        } else {
            Err(StoreError::Invalid)
        };
    }
    Ok(Some(unsafe { File::from_raw_handle(handle.cast()) }))
}

pub(crate) struct PrivateDir {
    path: PathBuf,
    file: File,
    id: (u32, u64),
    sid: Vec<u8>,
}

impl PrivateDir {
    #[cfg(feature = "pairing-v2-experimental")]
    pub(crate) fn try_clone(&self) -> Result<Self, StoreError> {
        self.validate_self()?;
        let file = self.file.try_clone().map_err(|_| StoreError::Unavailable)?;
        let handle = file.as_raw_handle().cast();
        validate(handle, true, &self.sid)?;
        if identity(&file_info(handle)?) != self.id {
            return Err(StoreError::Invalid);
        }
        Ok(Self {
            path: self.path.clone(),
            file,
            id: self.id,
            sid: self.sid.clone(),
        })
    }

    pub fn root(path: &Path) -> Result<Self, StoreError> {
        if !path.is_absolute() {
            return Err(StoreError::Invalid);
        }
        std::fs::create_dir_all(path).map_err(|_| StoreError::Unavailable)?;
        let file = open_path(path, true, OPEN_EXISTING)?.ok_or(StoreError::Invalid)?;
        let sid = current_user_sid()?;
        let handle = file.as_raw_handle().cast();
        let info = file_info(handle)?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        {
            return Err(StoreError::Invalid);
        }
        harden(handle, true, &sid)?;
        validate(handle, true, &sid)?;
        Ok(Self {
            path: path.to_owned(),
            file,
            id: identity(&info),
            sid,
        })
    }

    fn validate_self(&self) -> Result<(), StoreError> {
        validate(self.file.as_raw_handle().cast(), true, &self.sid)?;
        let current = open_path(&self.path, true, OPEN_EXISTING)?.ok_or(StoreError::Invalid)?;
        validate(current.as_raw_handle().cast(), true, &self.sid)?;
        if identity(&file_info(current.as_raw_handle().cast())?) != self.id {
            return Err(StoreError::Invalid);
        }
        Ok(())
    }

    pub fn child(&self, value: &str) -> Result<Self, StoreError> {
        valid_name(value)?;
        self.validate_self()?;
        let path = self.path.join(value);
        let created = match std::fs::create_dir(&path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(_) => return Err(StoreError::Unavailable),
        };
        let file = open_path(&path, true, OPEN_EXISTING)?.ok_or(StoreError::Invalid)?;
        let handle = file.as_raw_handle().cast();
        let info = file_info(handle)?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(StoreError::Invalid);
        }
        if created {
            harden(handle, true, &self.sid)?;
        }
        validate(handle, true, &self.sid)?;
        self.flush()?;
        Ok(Self {
            path,
            file,
            id: identity(&info),
            sid: self.sid.clone(),
        })
    }

    fn open(&self, value: &str, create: bool, exclusive: bool) -> Result<Option<File>, StoreError> {
        valid_name(value)?;
        self.validate_self()?;
        let disposition = if exclusive {
            CREATE_NEW
        } else if create {
            CREATE_ALWAYS
        } else {
            OPEN_EXISTING
        };
        let Some(file) = open_path(&self.path.join(value), false, disposition)? else {
            return Ok(None);
        };
        let handle = file.as_raw_handle().cast();
        if create {
            harden(handle, false, &self.sid)?;
        }
        validate(handle, false, &self.sid)?;
        Ok(Some(file))
    }

    pub fn lock(&self) -> Result<File, StoreError> {
        self.validate_self()?;
        let path = self.path.join("writer.lock");
        let file = match self.open("writer.lock", false, false)? {
            Some(file) => file,
            None => {
                let file = open_path(&path, false, CREATE_NEW)?.ok_or(StoreError::Unavailable)?;
                harden(file.as_raw_handle().cast(), false, &self.sid)?;
                validate(file.as_raw_handle().cast(), false, &self.sid)?;
                file
            }
        };
        let mut overlapped = OVERLAPPED::default();
        if unsafe {
            LockFileEx(
                file.as_raw_handle().cast(),
                LOCKFILE_EXCLUSIVE_LOCK,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        } == 0
        {
            return Err(StoreError::Unavailable);
        }
        Ok(file)
    }

    pub fn read(&self, value: &str, limit: usize) -> Result<Option<Vec<u8>>, StoreError> {
        let Some(file) = self.open(value, false, false)? else {
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
        valid_name(value)?;
        self.validate_self()?;
        let _ = self.open(value, false, false)?;
        use rand::RngCore;
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
                .open(&tmp, true, true)?
                .ok_or(StoreError::Unavailable)?;
            file.write_all(bytes).map_err(|_| StoreError::Unavailable)?;
            fault_point!(value, "after_write");
            fault_point!(value, "before_file_sync");
            file.sync_all().map_err(|_| StoreError::Unavailable)?;
            fault_point!(value, "after_file_sync");
            drop(file);
            self.validate_self()?;
            let from = wide(self.path.join(&tmp).as_os_str());
            let to = wide(self.path.join(value).as_os_str());
            let target_exists = self.open(value, false, false)?.is_some();
            fault_point!(value, "before_rename");
            let ok = unsafe {
                if target_exists {
                    ReplaceFileW(
                        to.as_ptr(),
                        from.as_ptr(),
                        ptr::null(),
                        0,
                        ptr::null(),
                        ptr::null(),
                    )
                } else {
                    MoveFileExW(
                        from.as_ptr(),
                        to.as_ptr(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                    )
                }
            };
            if ok == 0 {
                return Err(StoreError::Unavailable);
            }
            fault_point!(value, "after_rename");
            let target = self.open(value, false, false)?.ok_or(StoreError::Invalid)?;
            validate(target.as_raw_handle().cast(), false, &self.sid)?;
            fault_point!(value, "before_dir_sync");
            self.flush()?;
            fault_point!(value, "after_dir_sync");
            fault_point!(value, "before_readback");
            if self.read(value, bytes.len())?.as_deref() != Some(bytes) {
                return Err(StoreError::Invalid);
            }
            fault_point!(value, "after_readback");
            fault_point!(value, "before_cleanup");
            fault_point!(value, "after_cleanup");
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(self.path.join(tmp));
        }
        result
    }

    pub fn remove(&self, value: &str) -> Result<(), StoreError> {
        valid_name(value)?;
        self.validate_self()?;
        if self.open(value, false, false)?.is_none() {
            return self.flush();
        }
        std::fs::remove_file(self.path.join(value)).map_err(|_| StoreError::Unavailable)?;
        self.flush()
    }

    fn flush(&self) -> Result<(), StoreError> {
        self.validate_self()?;
        if unsafe { FlushFileBuffers(self.file.as_raw_handle().cast()) } == 0 {
            return Err(StoreError::Unavailable);
        }
        Ok(())
    }
}
