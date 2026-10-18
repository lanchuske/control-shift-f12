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
        FILE_SHARE_WRITE, FileRenameInfo, FlushFileBuffers, GetFileInformationByHandle,
        LOCKFILE_EXCLUSIVE_LOCK, LockFileEx, OPEN_EXISTING, READ_CONTROL,
        SetFileInformationByHandle, WRITE_DAC, WRITE_OWNER,
    },
    System::{
        IO::OVERLAPPED,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

const ERROR_SUCCESS: u32 = 0;

fn rename_info(destination: &Path, replace: bool) -> Result<(Vec<usize>, u32), StoreError> {
    let name: Vec<u16> = destination.as_os_str().encode_wide().collect();
    if name.is_empty() || name.contains(&0) {
        return Err(StoreError::Invalid);
    }
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
    let used = u32::try_from(used).map_err(|_| StoreError::Invalid)?;
    let name_bytes = u32::try_from(name_bytes).map_err(|_| StoreError::Invalid)?;
    let mut storage = vec![0usize; words];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = ptr::null_mut();
        (*info).FileNameLength = name_bytes;
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name.len(),
        );
    }
    Ok((storage, used))
}

fn rename_open_file(source: &File, destination: &Path, replace: bool) -> Result<(), StoreError> {
    rename_open_file_with_backoff(source, destination, replace, || {})
}

fn rename_open_file_with_backoff(
    source: &File,
    destination: &Path,
    replace: bool,
    _backoff: impl FnMut(),
) -> Result<(), StoreError> {
    let (info, used) = rename_info(destination, replace)?;
    let result = unsafe {
        SetFileInformationByHandle(
            source.as_raw_handle().cast(),
            FileRenameInfo,
            info.as_ptr().cast(),
            used,
        )
    };
    if result == 0 {
        let error = unsafe { GetLastError() };
        #[cfg(test)]
        faults::record_rename_attempt(error);
        #[cfg(test)]
        faults::record_failure("rename", Some(error as i32));
        Err(StoreError::Unavailable)
    } else {
        #[cfg(test)]
        faults::record_rename_attempt(ERROR_SUCCESS);
        Ok(())
    }
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
    destination: &Path,
    replace: bool,
    _value: &str,
) -> Result<(), StoreError> {
    fault_point!(_value, "before_rename");
    rename_open_file(file, destination, replace)?;
    #[cfg(test)]
    faults::record("rename");
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
            publish_renamed_file(&file, &self.path.join(value), target_exists, value)?;
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

    #[test]
    fn retained_source_handle_can_replace_existing_target() {
        let root = tempfile::tempdir().unwrap();
        let from = root.path().join("replacement");
        let to = root.path().join("target");
        std::fs::write(&from, b"new").unwrap();
        std::fs::write(&to, b"old").unwrap();
        let source = open_path(&from, false, OPEN_EXISTING).unwrap().unwrap();
        let source_id = identity(&file_info(source.as_raw_handle().cast()).unwrap());

        let result = rename_open_file(&source, &to, true);

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
    fn handle_rename_retries_a_transient_sharing_violation_on_the_same_source_handle() {
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
        let source_id = identity(&file_info(source.as_raw_handle().cast()).unwrap());
        let mut blocker = Some(blocker);
        let mut backoffs = 0;
        faults::reset_operations();

        let result = rename_open_file_with_backoff(&source, &to, true, || {
            backoffs += 1;
            drop(blocker.take());
        });
        let attempts = faults::take_rename_attempts();

        assert_eq!(result, Ok(()));
        assert_eq!(attempts.first(), Some(&32));
        assert_eq!(attempts.last(), Some(&ERROR_SUCCESS));
        assert!(attempts.len() <= 21);
        assert_eq!(backoffs, attempts.len() - 1);
        assert_eq!(std::fs::read(&to).unwrap(), b"new");
        assert!(!from.exists());
        let target = open_path(&to, false, OPEN_EXISTING).unwrap().unwrap();
        assert_eq!(
            identity(&file_info(target.as_raw_handle().cast()).unwrap()),
            source_id
        );
    }

    #[test]
    fn handle_rename_exhausts_exactly_and_leaves_both_files_unchanged() {
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
        let mut backoffs = 0;
        faults::reset_operations();

        let result = rename_open_file_with_backoff(&source, &to, true, || backoffs += 1);
        let attempts = faults::take_rename_attempts();

        assert_eq!(result, Err(StoreError::Unavailable));
        assert_eq!(attempts, vec![32; 21]);
        assert_eq!(backoffs, 20);
        assert_eq!(faults::take_failure(), Some(("rename", Some(32))));
        assert_eq!(std::fs::read(&to).unwrap(), b"old");
        assert_eq!(std::fs::read(&from).unwrap(), b"new");
        drop(blocker);
    }

    #[test]
    fn handle_rename_does_not_retry_a_non_sharing_error() {
        let root = tempfile::tempdir().unwrap();
        let from = root.path().join("replacement");
        let to = root.path().join("missing-parent").join("target");
        std::fs::write(&from, b"new").unwrap();
        let source = open_path(&from, false, OPEN_EXISTING).unwrap().unwrap();
        let mut backoffs = 0;
        faults::reset_operations();

        let result = rename_open_file_with_backoff(&source, &to, true, || backoffs += 1);
        let attempts = faults::take_rename_attempts();

        assert_eq!(result, Err(StoreError::Unavailable));
        assert_eq!(attempts.len(), 1);
        assert_ne!(attempts[0], ERROR_SUCCESS);
        assert_ne!(attempts[0], 32);
        assert_eq!(backoffs, 0);
        assert_eq!(std::fs::read(&from).unwrap(), b"new");
    }

    #[test]
    fn handle_rename_supports_missing_target_and_supplementary_unicode_leaf() {
        let root = tempfile::tempdir().unwrap();
        let from = root.path().join("replacement");
        let to = root.path().join("target-🦀");
        std::fs::write(&from, b"new").unwrap();
        let source = open_path(&from, false, OPEN_EXISTING).unwrap().unwrap();
        rename_open_file(&source, &to, false).unwrap();
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

        rename_open_file(&source, &to, false).unwrap();

        assert_eq!(std::fs::read(&to).unwrap(), b"new");
        let names = std::fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, [std::ffi::OsString::from(leaf)]);
    }

    #[test]
    fn rename_info_rejects_embedded_nul() {
        use std::os::windows::ffi::OsStringExt;
        let path = std::ffi::OsString::from_wide(&[b'C' as u16, b':' as u16, 0, b'x' as u16]);
        assert_eq!(
            rename_info(Path::new(&path), true),
            Err(StoreError::Invalid)
        );
    }

    #[test]
    fn rename_info_sizes_the_buffer_with_a_terminator_outside_file_name_length() {
        let destination = Path::new(r"C:\temp\target-🦀");
        let expected_units = destination.as_os_str().encode_wide().count();
        let (storage, used) = rename_info(destination, true).unwrap();
        let info = storage.as_ptr().cast::<FILE_RENAME_INFO>();
        assert_eq!(
            unsafe { (*info).FileNameLength },
            u32::try_from(expected_units * size_of::<u16>()).unwrap()
        );
        assert_eq!(
            used as usize,
            offset_of!(FILE_RENAME_INFO, FileName)
                + expected_units * size_of::<u16>()
                + size_of::<u16>()
        );
        let terminator = unsafe {
            ptr::addr_of!((*info).FileName)
                .cast::<u16>()
                .add(expected_units)
                .read()
        };
        assert_eq!(terminator, 0);
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
