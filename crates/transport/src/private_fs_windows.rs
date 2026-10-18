//! Owner-only Windows storage for pairing quarantine data.
use crate::pairing_pending::StoreError;
use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
    mem::{offset_of, size_of},
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
        GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
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
        FILE_FLAG_WRITE_THROUGH, FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FileRenameInfoEx, FlushFileBuffers, GetFileInformationByHandle,
        LOCKFILE_EXCLUSIVE_LOCK, LockFileEx, OPEN_EXISTING, READ_CONTROL,
        SetFileInformationByHandle, WRITE_DAC, WRITE_OWNER,
    },
    System::{
        IO::OVERLAPPED,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

const ERROR_SUCCESS: u32 = 0;
const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: u32 = 0x0000_0001;
const FILE_RENAME_FLAG_POSIX_SEMANTICS: u32 = 0x0000_0002;

fn rename_info(
    directory: &File,
    leaf: &str,
    replace: bool,
) -> Result<(Vec<usize>, u32), StoreError> {
    valid_name(leaf)?;
    let name: Vec<u16> = OsStr::new(leaf).encode_wide().collect();
    let name_bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(StoreError::Invalid)?;
    let header = offset_of!(FILE_RENAME_INFO, FileName);
    let used = header
        .checked_add(name_bytes)
        .and_then(|size| size.checked_add(size_of::<u16>()))
        .ok_or(StoreError::Invalid)?;
    let allocation = used.max(size_of::<FILE_RENAME_INFO>());
    let words = allocation
        .checked_add(size_of::<usize>() - 1)
        .ok_or(StoreError::Invalid)?
        / size_of::<usize>();
    let name_bytes = u32::try_from(name_bytes).map_err(|_| StoreError::Invalid)?;
    let mut storage = vec![0usize; words];
    let buffer_size = u32::try_from(
        storage
            .len()
            .checked_mul(size_of::<usize>())
            .ok_or(StoreError::Invalid)?,
    )
    .map_err(|_| StoreError::Invalid)?;
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*info).Anonymous.Flags = FILE_RENAME_FLAG_POSIX_SEMANTICS
            | if replace {
                FILE_RENAME_FLAG_REPLACE_IF_EXISTS
            } else {
                0
            };
        (*info).RootDirectory = directory.as_raw_handle().cast();
        (*info).FileNameLength = name_bytes;
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name.len(),
        );
    }
    Ok((storage, buffer_size))
}

fn rename_open_file(
    source: &File,
    directory: &File,
    leaf: &str,
    replace: bool,
) -> Result<(), StoreError> {
    let (info, buffer_size) = rename_info(directory, leaf, replace)?;
    let result = unsafe {
        SetFileInformationByHandle(
            source.as_raw_handle().cast(),
            FileRenameInfoEx,
            info.as_ptr().cast(),
            buffer_size,
        )
    };
    let _error = if result == 0 {
        unsafe { GetLastError() }
    } else {
        ERROR_SUCCESS
    };
    #[cfg(test)]
    faults::record_rename_attempt(_error);
    if result == 0 {
        #[cfg(test)]
        faults::record_failure("rename", Some(_error as i32));
        return Err(StoreError::Unavailable);
    }
    #[cfg(test)]
    faults::record("rename");
    Ok(())
}

#[cfg(test)]
pub(crate) mod faults {
    #[cfg(feature = "pairing-v2-experimental")]
    use super::StoreError;
    use std::cell::RefCell;
    std::thread_local! {static ARMED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };}
    std::thread_local! {static OPERATIONS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };}
    std::thread_local! {static FAILURE: RefCell<Option<(&'static str, Option<i32>)>> = const { RefCell::new(None) };}
    std::thread_local! {static RENAME_ATTEMPTS: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };}
    #[cfg(feature = "pairing-v2-experimental")]
    pub fn arm() {
        ARMED.set(true);
    }
    #[cfg(feature = "pairing-v2-experimental")]
    pub fn point(file: &str, stage: &str) -> Result<(), StoreError> {
        if !ARMED.get() {
            return Ok(());
        }
        let target = if file == "ledger.json" {
            "ledger"
        } else if file.starts_with("admission-revocation-") {
            "guard"
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
    pub fn record(operation: &'static str) {
        OPERATIONS.with(|operations| operations.borrow_mut().push(operation));
    }
    pub fn reset_operations() {
        OPERATIONS.with(|operations| operations.borrow_mut().clear());
        FAILURE.with(|failure| *failure.borrow_mut() = None);
        RENAME_ATTEMPTS.with(|attempts| attempts.borrow_mut().clear());
    }
    pub fn take_operations() -> Vec<&'static str> {
        OPERATIONS.with(|operations| std::mem::take(&mut *operations.borrow_mut()))
    }
    pub fn record_failure(operation: &'static str, code: Option<i32>) {
        FAILURE.with(|failure| *failure.borrow_mut() = Some((operation, code)));
    }
    pub fn take_failure() -> Option<(&'static str, Option<i32>)> {
        FAILURE.with(|failure| failure.borrow_mut().take())
    }
    pub fn record_rename_attempt(code: u32) {
        RENAME_ATTEMPTS.with(|attempts| attempts.borrow_mut().push(code));
    }
    pub fn take_rename_attempts() -> Vec<u32> {
        RENAME_ATTEMPTS.with(|attempts| std::mem::take(&mut *attempts.borrow_mut()))
    }
}

macro_rules! fault_point {
    ($file:expr, $stage:expr) => {
        #[cfg(all(test, feature = "pairing-v2-experimental"))]
        faults::point($file, $stage)?;
    };
}

fn flush_before_rename(file: &File, _value: &str) -> Result<(), StoreError> {
    fault_point!(_value, "before_file_sync");
    let result = file.sync_all();
    #[cfg(test)]
    if let Err(error) = &result {
        faults::record_failure("pre-file-flush", error.raw_os_error());
    }
    result.map_err(|_| StoreError::Unavailable)?;
    #[cfg(test)]
    faults::record("pre-file-flush");
    fault_point!(_value, "after_file_sync");
    Ok(())
}

fn publish_renamed_file(
    file: &File,
    directory: &File,
    leaf: &str,
    replace: bool,
    _value: &str,
) -> Result<(), StoreError> {
    fault_point!(_value, "before_rename");
    rename_open_file(file, directory, leaf, replace)?;
    fault_point!(_value, "after_rename");
    Ok(())
}

fn flush_after_rename(file: &File) -> Result<(), StoreError> {
    let result = file.sync_all();
    #[cfg(test)]
    if let Err(error) = &result {
        faults::record_failure("post-file-flush", error.raw_os_error());
    }
    result.map_err(|_| StoreError::Unavailable)?;
    #[cfg(test)]
    faults::record("post-file-flush");
    Ok(())
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

fn open_path_with_flags(
    path: &Path,
    directory: bool,
    disposition: u32,
    additional_flags: u32,
) -> Result<Option<File>, StoreError> {
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
            flags | additional_flags,
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

fn open_path(path: &Path, directory: bool, disposition: u32) -> Result<Option<File>, StoreError> {
    open_path_with_flags(path, directory, disposition, 0)
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
        let result = self.flush();
        #[cfg(test)]
        if result.is_err() {
            faults::record_failure("directory-flush", None);
        }
        result?;
        Ok(Self {
            path,
            file,
            id: identity(&info),
            sid: self.sid.clone(),
        })
    }

    fn open(&self, value: &str, create: bool, exclusive: bool) -> Result<Option<File>, StoreError> {
        self.open_with_flags(value, create, exclusive, 0)
    }

    fn open_with_flags(
        &self,
        value: &str,
        create: bool,
        exclusive: bool,
        additional_flags: u32,
    ) -> Result<Option<File>, StoreError> {
        valid_name(value)?;
        self.validate_self()?;
        let disposition = if exclusive {
            CREATE_NEW
        } else if create {
            CREATE_ALWAYS
        } else {
            OPEN_EXISTING
        };
        let Some(file) =
            open_path_with_flags(&self.path.join(value), false, disposition, additional_flags)?
        else {
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
        drop(self.open(value, false, false)?);
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
                .open_with_flags(&tmp, true, true, FILE_FLAG_WRITE_THROUGH)?
                .ok_or(StoreError::Unavailable)?;
            file.write_all(bytes).map_err(|_| StoreError::Unavailable)?;
            fault_point!(value, "after_write");
            flush_before_rename(&file, value)?;
            self.validate_self()?;
            let target = self.open(value, false, false)?;
            let target_exists = target.is_some();
            drop(target);
            let source_id = identity(&file_info(file.as_raw_handle().cast())?);
            publish_renamed_file(&file, &self.file, value, target_exists, value)?;
            flush_after_rename(&file)?;
            let target = self.open(value, false, false)?.ok_or(StoreError::Invalid)?;
            validate(target.as_raw_handle().cast(), false, &self.sid)?;
            if identity(&file_info(target.as_raw_handle().cast())?) != source_id {
                return Err(StoreError::Invalid);
            }
            self.flush_for_replace(value)?;
            fault_point!(value, "before_readback");
            if self.read(value, bytes.len())?.as_deref() != Some(bytes) {
                return Err(StoreError::Invalid);
            }
            fault_point!(value, "after_readback");
            fault_point!(value, "before_cleanup");
            fault_point!(value, "after_cleanup");
            #[cfg(test)]
            faults::record("success");
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

    fn flush_for_replace(&self, _value: &str) -> Result<(), StoreError> {
        fault_point!(_value, "before_dir_sync");
        self.flush()?;
        #[cfg(test)]
        faults::record("directory-flush");
        fault_point!(_value, "after_dir_sync");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};

    fn directory(path: &Path) -> File {
        open_path(path, true, OPEN_EXISTING).unwrap().unwrap()
    }

    fn directory_with_access(path: &Path, access: u32) -> Result<File, u32> {
        let handle = unsafe {
            CreateFileW(
                wide(path.as_os_str()).as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            Err(unsafe { GetLastError() })
        } else {
            Ok(unsafe { File::from_raw_handle(handle.cast()) })
        }
    }

    fn flush_code(file: &File) -> u32 {
        if unsafe { FlushFileBuffers(file.as_raw_handle().cast()) } == 0 {
            unsafe { GetLastError() }
        } else {
            ERROR_SUCCESS
        }
    }

    #[test]
    fn retained_source_handle_can_replace_existing_target() {
        let root = tempfile::tempdir().unwrap();
        let from = root.path().join("replacement");
        let to = root.path().join("target");
        std::fs::write(&from, b"new").unwrap();
        std::fs::write(&to, b"old").unwrap();
        let source = open_path(&from, false, OPEN_EXISTING).unwrap().unwrap();
        let source_id = identity(&file_info(source.as_raw_handle().cast()).unwrap());

        let root_handle = directory(root.path());
        let result = rename_open_file(&source, &root_handle, "target", true);

        assert_eq!(result, Ok(()), "path replace failed with {result:?}");
        assert!(!from.exists());
        assert_eq!(std::fs::read(&to).unwrap(), b"new");
        let target = open_path(&to, false, OPEN_EXISTING).unwrap().unwrap();
        assert_eq!(
            identity(&file_info(target.as_raw_handle().cast()).unwrap()),
            source_id
        );
    }

    #[test]
    fn replacement_keeps_delete_shared_old_target_handle_readable() {
        let root = tempfile::tempdir().unwrap();
        let from = root.path().join("replacement");
        let to = root.path().join("target");
        std::fs::write(&from, b"new").unwrap();
        std::fs::write(&to, b"old").unwrap();
        let source = open_path(&from, false, OPEN_EXISTING).unwrap().unwrap();
        let source_id = identity(&file_info(source.as_raw_handle().cast()).unwrap());
        let mut old_target = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&to)
            .unwrap();
        faults::reset_operations();

        let root_handle = directory(root.path());
        let result = rename_open_file(&source, &root_handle, "target", true);
        let attempts = faults::take_rename_attempts();

        assert_eq!(
            result,
            Ok(()),
            "delete-shared target replacement failed; attempts={attempts:?}"
        );
        let mut old_bytes = Vec::new();
        old_target.read_to_end(&mut old_bytes).unwrap();
        assert_eq!(old_bytes, b"old");
        assert_eq!(std::fs::read(&to).unwrap(), b"new");
        assert!(!from.exists());
        let target = open_path(&to, false, OPEN_EXISTING).unwrap().unwrap();
        assert_eq!(
            identity(&file_info(target.as_raw_handle().cast()).unwrap()),
            source_id
        );
    }

    #[test]
    fn destination_blocker_fails_immediately_and_preserves_both_files() {
        let root = tempfile::tempdir().unwrap();
        let from = root.path().join("replacement");
        let to = root.path().join("target");
        std::fs::write(&from, b"new").unwrap();
        std::fs::write(&to, b"old").unwrap();
        let source = open_path(&from, false, OPEN_EXISTING).unwrap().unwrap();
        let blocker = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&to)
            .unwrap();
        faults::reset_operations();

        let root_handle = directory(root.path());
        let result = rename_open_file(&source, &root_handle, "target", true);
        let attempts = faults::take_rename_attempts();

        assert_eq!(result, Err(StoreError::Unavailable));
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts, [32]);
        assert_eq!(faults::take_failure(), Some(("rename", Some(32))));
        assert_eq!(std::fs::read(&to).unwrap(), b"old");
        assert_eq!(std::fs::read(&from).unwrap(), b"new");
        drop(blocker);
    }

    #[test]
    fn handle_rename_rejects_a_non_leaf_without_a_native_call() {
        let root = tempfile::tempdir().unwrap();
        let from = root.path().join("replacement");
        std::fs::write(&from, b"new").unwrap();
        let source = open_path(&from, false, OPEN_EXISTING).unwrap().unwrap();
        let root_handle = directory(root.path());
        faults::reset_operations();

        let result = rename_open_file(&source, &root_handle, "missing-parent\\target", true);

        assert_eq!(result, Err(StoreError::Invalid));
        assert!(faults::take_rename_attempts().is_empty());
        assert_eq!(std::fs::read(&from).unwrap(), b"new");
    }

    #[test]
    fn handle_rename_supports_missing_target_and_supplementary_unicode_leaf() {
        let root = tempfile::tempdir().unwrap();
        let from = root.path().join("replacement");
        let to = root.path().join("target-🦀");
        std::fs::write(&from, b"new").unwrap();
        let source = open_path(&from, false, OPEN_EXISTING).unwrap().unwrap();
        let root_handle = directory(root.path());
        rename_open_file(&source, &root_handle, "target-🦀", false).unwrap();
        assert_eq!(std::fs::read(&to).unwrap(), b"new");
        assert!(!from.exists());
    }

    #[test]
    fn handle_rename_preserves_a_long_manifest_leaf_exactly() {
        let root = tempfile::tempdir().unwrap();
        let from = root.path().join("replacement");
        let leaf = format!("journal-{}.json", "01".repeat(32));
        let to = root.path().join(&leaf);
        std::fs::write(&from, b"new").unwrap();
        let source = open_path(&from, false, OPEN_EXISTING).unwrap().unwrap();
        let root_handle = directory(root.path());

        rename_open_file(&source, &root_handle, &leaf, false).unwrap();

        assert_eq!(std::fs::read(&to).unwrap(), b"new");
        let names = std::fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, [std::ffi::OsString::from(leaf)]);
    }

    #[test]
    fn root_relative_rename_binds_the_destination_to_the_retained_directory() {
        const CHILD: &str = "CSF12_ROOT_BINDING_CHILD";
        const ROOT_A: &str = "CSF12_ROOT_BINDING_A";
        const ROOT_B: &str = "CSF12_ROOT_BINDING_B";
        if std::env::var_os(CHILD).is_some() {
            let root_a = PathBuf::from(std::env::var_os(ROOT_A).unwrap());
            let root_b = PathBuf::from(std::env::var_os(ROOT_B).unwrap());
            let private_a = PrivateDir::root(&root_a).unwrap();
            let private_b = PrivateDir::root(&root_b).unwrap();
            let source = private_b.open("source", false, false).unwrap().unwrap();
            drop(private_b);
            faults::reset_operations();
            let result = rename_open_file(&source, &private_a.file, "x", true);
            let attempts = faults::take_rename_attempts();
            eprintln!("CSF12_ROOT_BIND result={result:?} attempts={attempts:?}");
            assert_eq!(attempts.len(), 1, "expected exactly one native rename call");
            result.unwrap();
            return;
        }

        let root = tempfile::tempdir().unwrap();
        let root_a = root.path().join("a");
        let root_b = root.path().join("b");
        let root_c = root.path().join("c");
        std::fs::create_dir_all(&root_a).unwrap();
        std::fs::create_dir_all(&root_b).unwrap();
        std::fs::create_dir_all(&root_c).unwrap();
        let private_a = PrivateDir::root(&root_a).unwrap();
        let private_b = PrivateDir::root(&root_b).unwrap();
        let mut target_a = private_a.open("x", true, true).unwrap().unwrap();
        target_a.write_all(b"old-a").unwrap();
        target_a.sync_all().unwrap();
        let mut target_b = private_b.open("x", true, true).unwrap().unwrap();
        target_b.write_all(b"old-b").unwrap();
        target_b.sync_all().unwrap();
        let mut source = private_b.open("source", true, true).unwrap().unwrap();
        source.write_all(b"new").unwrap();
        source.sync_all().unwrap();
        let source_id = identity(&file_info(source.as_raw_handle().cast()).unwrap());
        drop(target_a);
        drop(target_b);
        drop(source);
        drop(private_a);
        drop(private_b);

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "private_fs::tests::root_relative_rename_binds_the_destination_to_the_retained_directory",
                "--nocapture",
            ])
            .current_dir(&root_c)
            .env(CHILD, "1")
            .env(ROOT_A, &root_a)
            .env(ROOT_B, &root_b)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
            "child selector did not execute exactly one test: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("CSF12_ROOT_BIND result="),
            "child did not emit native-stage evidence: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!root_b.join("source").exists());
        assert_eq!(std::fs::read(root_b.join("x")).unwrap(), b"old-b");
        assert_eq!(std::fs::read(root_a.join("x")).unwrap(), b"new");
        let target = open_path(&root_a.join("x"), false, OPEN_EXISTING)
            .unwrap()
            .unwrap();
        assert_eq!(
            identity(&file_info(target.as_raw_handle().cast()).unwrap()),
            source_id
        );
    }

    #[test]
    fn root_relative_rename_handles_short_and_supplementary_leaves() {
        let root = tempfile::tempdir().unwrap();
        let root_handle = directory(root.path());
        for leaf in ["x", "🦀"] {
            for replace in [false, true] {
                if replace {
                    std::fs::write(root.path().join(leaf), b"old").unwrap();
                }
                let source_path = root.path().join(format!("source-{leaf}-{replace}"));
                std::fs::write(&source_path, b"new").unwrap();
                let source = open_path(&source_path, false, OPEN_EXISTING)
                    .unwrap()
                    .unwrap();
                rename_open_file(&source, &root_handle, leaf, replace).unwrap();
                assert_eq!(std::fs::read(root.path().join(leaf)).unwrap(), b"new");
                assert!(!source_path.exists());
                if !replace {
                    std::fs::remove_file(root.path().join(leaf)).unwrap();
                }
            }
        }
    }

    #[test]
    fn retained_directory_rights_diagnostic_matrix() {
        let candidate = GENERIC_READ | GENERIC_WRITE | READ_CONTROL;
        let rows = [
            ("broad", candidate | DELETE | WRITE_DAC | WRITE_OWNER, false),
            ("candidate", candidate, true),
            ("candidate_plus_delete", candidate | DELETE, false),
            (
                "candidate_plus_security_write",
                candidate | WRITE_DAC | WRITE_OWNER,
                false,
            ),
            ("read_control_only", GENERIC_READ | READ_CONTROL, false),
        ];
        let mut candidate_passed = false;
        let mut observed = 0;

        for (label, access, is_candidate) in rows {
            let root = tempfile::tempdir().unwrap();
            let private = PrivateDir::root(root.path()).unwrap();
            let mut target = private.open("x", true, true).unwrap().unwrap();
            target.write_all(b"old").unwrap();
            target.sync_all().unwrap();
            drop(target);
            let mut source = private.open("source", true, true).unwrap().unwrap();
            source.write_all(b"new").unwrap();
            source.sync_all().unwrap();
            let admin_id = identity(&file_info(private.file.as_raw_handle().cast()).unwrap());
            let retained = match directory_with_access(root.path(), access) {
                Ok(file) => file,
                Err(code) => {
                    writeln!(
                        std::io::stderr(),
                        "CSF12_RIGHTS label={label} access=0x{access:08x} open_error={code}"
                    )
                    .unwrap();
                    continue;
                }
            };
            let validation = validate(retained.as_raw_handle().cast(), true, &private.sid);
            let identity_matches = file_info(retained.as_raw_handle().cast())
                .map(|info| identity(&info) == admin_id)
                .unwrap_or(false);
            drop(private);

            let flush_before = flush_code(&retained);
            faults::reset_operations();
            let rename = rename_open_file(&source, &retained, "x", true);
            let attempts = faults::take_rename_attempts();
            let flush_after = flush_code(&retained);
            writeln!(
                std::io::stderr(),
                "CSF12_RIGHTS label={label} access=0x{access:08x} validation={validation:?} identity={identity_matches} flush_before={flush_before} rename={rename:?} attempts={attempts:?} flush_after={flush_after}"
            )
            .unwrap();
            assert_eq!(attempts.len(), 1, "{label} must make one native call");
            observed += 1;
            if is_candidate {
                candidate_passed = validation == Ok(())
                    && identity_matches
                    && flush_before == ERROR_SUCCESS
                    && rename == Ok(())
                    && attempts == [ERROR_SUCCESS]
                    && flush_after == ERROR_SUCCESS;
            }
        }

        assert_eq!(observed, rows.len(), "every rights row must reach rename");
        assert!(
            candidate_passed,
            "candidate retained-directory rights did not preserve the full contract"
        );
    }

    #[test]
    fn rename_info_rejects_embedded_nul() {
        let root = tempfile::tempdir().unwrap();
        let root_handle = directory(root.path());
        assert_eq!(
            rename_info(&root_handle, "x\0y", true),
            Err(StoreError::Invalid)
        );
    }

    #[test]
    fn rename_info_sizes_the_buffer_with_a_terminator_outside_file_name_length() {
        let root = tempfile::tempdir().unwrap();
        let root_handle = directory(root.path());
        let leaf = "🦀";
        let expected_units = leaf.encode_utf16().count();
        let (storage, buffer_size) = rename_info(&root_handle, leaf, true).unwrap();
        let info = storage.as_ptr().cast::<FILE_RENAME_INFO>();
        assert_eq!(
            unsafe { (*info).Anonymous.Flags },
            FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS
        );
        assert_eq!(
            unsafe { (*info).FileNameLength },
            u32::try_from(expected_units * size_of::<u16>()).unwrap()
        );
        assert_eq!(
            unsafe { (*info).RootDirectory },
            root_handle.as_raw_handle().cast()
        );
        assert!(buffer_size as usize >= size_of::<FILE_RENAME_INFO>());
        assert_eq!(buffer_size as usize, storage.len() * size_of::<usize>());
        let terminator = unsafe {
            ptr::addr_of!((*info).FileName)
                .cast::<u16>()
                .add(expected_units)
                .read()
        };
        assert_eq!(terminator, 0);
    }

    #[test]
    fn rename_info_uses_posix_semantics_without_replace_for_a_missing_target() {
        let root = tempfile::tempdir().unwrap();
        let root_handle = directory(root.path());
        let (storage, buffer_size) = rename_info(&root_handle, "x", false).unwrap();
        let info = storage.as_ptr().cast::<FILE_RENAME_INFO>();
        assert_eq!(
            unsafe { (*info).Anonymous.Flags },
            FILE_RENAME_FLAG_POSIX_SEMANTICS
        );
        assert_eq!(unsafe { (*info).FileNameLength }, 2);
        assert!(buffer_size as usize >= size_of::<FILE_RENAME_INFO>());
    }

    #[cfg(any())]
    #[test]
    fn hosted_stage_isolation_diagnostic() {
        struct Observation {
            result: Result<(), StoreError>,
            attempts: Vec<u32>,
            operations: Vec<&'static str>,
            failure: Option<(&'static str, Option<i32>)>,
        }

        fn emit(label: &str, outcome: Result<Observation, String>) -> bool {
            let line = match &outcome {
                Ok(observation) => {
                    let stage = match (observation.attempts.as_slice(), observation.result.as_ref())
                    {
                        ([], Err(_)) => "before-publication-failure",
                        ([code], Err(_)) if *code != ERROR_SUCCESS => "native-rename-failure",
                        ([ERROR_SUCCESS], Err(_)) => "post-rename-failure",
                        ([ERROR_SUCCESS], Ok(())) => "success",
                        _ => "observer-violation",
                    };
                    format!(
                        "CSF12_DIAG label={label} stage={stage} result={:?} calls={} attempts={:?} operations={:?} failure={:?}\n",
                        observation.result,
                        observation.attempts.len(),
                        observation.attempts,
                        observation.operations,
                        observation.failure
                    )
                }
                Err(stage) => format!(
                    "CSF12_DIAG label={label} stage=setup result=Err calls=0 detail={stage}\n"
                ),
            };
            std::io::stderr()
                .write_all(line.as_bytes())
                .expect("write diagnostic line");
            match &outcome {
                Ok(Observation {
                    result: Ok(()),
                    attempts,
                    ..
                }) => attempts == &[ERROR_SUCCESS],
                _ => false,
            }
        }

        fn store<T>(stage: &str, result: Result<T, StoreError>) -> Result<T, String> {
            result.map_err(|error| format!("{stage}:{error:?}"))
        }

        fn io<T>(stage: &str, result: std::io::Result<T>) -> Result<T, String> {
            result.map_err(|error| format!("{stage}:{error:?}"))
        }

        fn observed(result: Result<(), StoreError>) -> Result<Observation, String> {
            Ok(Observation {
                result,
                attempts: faults::take_rename_attempts(),
                operations: faults::take_operations(),
                failure: faults::take_failure(),
            })
        }

        let mut passed = Vec::new();

        passed.push(emit(
            "private_target_directory_retained",
            (|| {
                let root = tempfile::tempdir().map_err(|error| format!("tempdir:{error:?}"))?;
                let private = store("private-root", PrivateDir::root(root.path()))?;
                let mut target = store("target-open", private.open("target", true, true))?
                    .ok_or_else(|| "target-open:none".to_owned())?;
                io("target-write", target.write_all(b"old"))?;
                io("target-flush", target.sync_all())?;
                drop(target);
                let from = root.path().join(".pending-diagnostic.tmp");
                io("source-write", std::fs::write(&from, b"new"))?;
                let source = store("source-open", open_path(&from, false, OPEN_EXISTING))?
                    .ok_or_else(|| "source-open:none".to_owned())?;
                faults::reset_operations();
                let result = rename_open_file(&source, &root.path().join("target"), true);
                std::hint::black_box(&private);
                observed(result)
            })(),
        ));

        passed.push(emit(
            "private_target_directory_dropped",
            (|| {
                let root = tempfile::tempdir().map_err(|error| format!("tempdir:{error:?}"))?;
                let private = store("private-root", PrivateDir::root(root.path()))?;
                let mut target = store("target-open", private.open("target", true, true))?
                    .ok_or_else(|| "target-open:none".to_owned())?;
                io("target-write", target.write_all(b"old"))?;
                io("target-flush", target.sync_all())?;
                drop(target);
                let from = root.path().join(".pending-diagnostic.tmp");
                io("source-write", std::fs::write(&from, b"new"))?;
                let source = store("source-open", open_path(&from, false, OPEN_EXISTING))?
                    .ok_or_else(|| "source-open:none".to_owned())?;
                drop(private);
                faults::reset_operations();
                observed(rename_open_file(&source, &root.path().join("target"), true))
            })(),
        ));

        for (label, flags) in [
            ("raw_source_normal", 0),
            ("raw_source_write_through", FILE_FLAG_WRITE_THROUGH),
        ] {
            passed.push(emit(
                label,
                (|| {
                    let root = tempfile::tempdir().map_err(|error| format!("tempdir:{error:?}"))?;
                    let private = store("private-root", PrivateDir::root(root.path()))?;
                    io(
                        "target-write",
                        std::fs::write(root.path().join("target"), b"old"),
                    )?;
                    let from = root.path().join(".pending-diagnostic.tmp");
                    let mut source = store(
                        "source-open",
                        open_path_with_flags(&from, false, CREATE_NEW, flags),
                    )?
                    .ok_or_else(|| "source-open:none".to_owned())?;
                    io("source-write", source.write_all(b"new"))?;
                    io("source-flush", source.sync_all())?;
                    faults::reset_operations();
                    let result = rename_open_file(&source, &root.path().join("target"), true);
                    std::hint::black_box(&private);
                    observed(result)
                })(),
            ));
        }

        passed.push(emit(
            "private_source_write_through",
            (|| {
                let root = tempfile::tempdir().map_err(|error| format!("tempdir:{error:?}"))?;
                let private = store("private-root", PrivateDir::root(root.path()))?;
                io(
                    "target-write",
                    std::fs::write(root.path().join("target"), b"old"),
                )?;
                let mut source = store(
                    "source-open",
                    private.open_with_flags(
                        ".pending-diagnostic.tmp",
                        true,
                        true,
                        FILE_FLAG_WRITE_THROUGH,
                    ),
                )?
                .ok_or_else(|| "source-open:none".to_owned())?;
                io("source-write", source.write_all(b"new"))?;
                io("source-flush", source.sync_all())?;
                faults::reset_operations();
                observed(rename_open_file(&source, &root.path().join("target"), true))
            })(),
        ));

        for (label, existing) in [
            ("full_replace_missing_target", false),
            ("full_replace_existing_target", true),
        ] {
            passed.push(emit(
                label,
                (|| {
                    let root = tempfile::tempdir().map_err(|error| format!("tempdir:{error:?}"))?;
                    let private = store("private-root", PrivateDir::root(root.path()))?;
                    if existing {
                        let mut target = store("target-open", private.open("target", true, true))?
                            .ok_or_else(|| "target-open:none".to_owned())?;
                        io("target-write", target.write_all(b"old"))?;
                        io("target-flush", target.sync_all())?;
                        drop(target);
                    }
                    faults::reset_operations();
                    observed(private.replace("target", b"new"))
                })(),
            ));
        }

        assert_eq!(passed, vec![true; 7], "one or more diagnostic cases failed");
    }

    #[test]
    fn replacement_operations_run_in_durable_order() {
        let root = tempfile::tempdir().unwrap();
        let private = PrivateDir::root(root.path()).unwrap();
        let mut target = private.open("target", true, true).unwrap().unwrap();
        target.write_all(b"old").unwrap();
        target.sync_all().unwrap();
        drop(target);
        faults::reset_operations();

        let result = private.replace("target", b"new");
        let operations = faults::take_operations();
        let failure = faults::take_failure();

        assert_eq!(
            result,
            Ok(()),
            "replacement failed after {operations:?}; failure={failure:?}"
        );

        assert_eq!(
            operations,
            [
                "pre-file-flush",
                "rename",
                "post-file-flush",
                "directory-flush",
                "success",
            ]
        );
    }
}
