use std::{
    error::Error, ffi::OsStr, os::windows::ffi::OsStrExt, path::PathBuf, process::exit,
    string::FromUtf16Error,
};

use colored::Colorize;
use log::debug;
use path_abs::PathAbs;
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{GetLastError, ERROR_SUCCESS, HANDLE, PSID},
        Security::{
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            LookupAccountSidW, SidTypeUnknown, OWNER_SECURITY_INFORMATION, SECURITY_DESCRIPTOR,
            SID_NAME_USE,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
        },
    },
};

#[derive(Debug)]
struct WideString(Vec<u16>);

impl WideString {
    fn as_const_ptr(&self) -> *const u16 {
        let s_ref: &Vec<u16> = &self.0.as_ref();
        s_ref.as_ptr() as *const u16
    }

    fn as_ptr(&self) -> *mut u16 {
        let s_ref: &Vec<u16> = &self.0.as_ref();
        s_ref.as_ptr() as *mut u16
    }

    fn from_os_str(s: &OsStr) -> Self {
        Self(s.encode_wide().chain(std::iter::once(0)).collect())
    }

    #[allow(dead_code)]
    fn from_str(s: &str) -> Self {
        Self(s.encode_utf16().chain(std::iter::once(0)).collect())
    }

    fn new(capacity: usize) -> Self {
        let mut v: Vec<u16> = Vec::default();
        v.resize(capacity, 0);
        Self(v)
    }

    #[allow(dead_code)]
    fn to_string(&self) -> Result<String, FromUtf16Error> {
        let v = &self.0;
        String::from_utf16(&v[..(v.len() - 1)]) // remove trailing null
    }
}

// https://docs.microsoft.com/en-us/windows/win32/secauthz/finding-the-owner-of-a-file-object-in-c--
fn run() -> Result<(), Box<dyn Error>> {
    // Example file - README.md in this repository
    let path = PathBuf::new().join(env!("CARGO_MANIFEST_DIR"));
    let readme_path = PathAbs::new(path.clone())?.as_path().join("README.md");

    debug!("path is {:#?}", path);
    debug!(
        "File path is {}",
        format!("{:#?}", readme_path).bright_yellow()
    );

    let path_as_wstring = WideString::from_os_str(readme_path.as_os_str());
    let path_as_wstring_ptr = path_as_wstring.as_const_ptr();
    let path_as_pcwstr = PCWSTR(path_as_wstring_ptr);

    // File handle
    let handle: HANDLE = unsafe {
        CreateFileW(
            path_as_pcwstr,
            FILE_GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };

    if let Err(e) = handle.ok() {
        panic!("Error with {:#?}: {:#?}", path_as_pcwstr, e);
    } else {
        debug!("Handle is {:#X?}", handle);
    }

    // Security Info
    let mut psidowner = PSID::default();
    let mut sd: *mut SECURITY_DESCRIPTOR =
        &mut SECURITY_DESCRIPTOR::default() as *mut SECURITY_DESCRIPTOR;

    let gsi_rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION.0,
            &mut psidowner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };

    if gsi_rc != ERROR_SUCCESS.0 {
        let last_error = unsafe { GetLastError() };
        panic!("Error code is {:#?}", last_error);
    } else {
        debug!("psidowner is {:#?}", psidowner);
    }

    // Lookup Account Sid
    let mut name_size = 0 as u32;
    let mut domain_size = 0 as u32;

    let name_as_wstring = WideString::new(name_size as usize);
    let name_as_wstring_ptr = name_as_wstring.as_ptr();
    let name_as_pwstr = PWSTR(name_as_wstring_ptr);

    let domain_as_wstring = WideString::new(domain_size as usize);
    let domain_as_wstring_ptr = domain_as_wstring.as_ptr();
    let domain_as_pwstr = PWSTR(domain_as_wstring_ptr);

    let euse = &mut SidTypeUnknown.to_owned() as *mut SID_NAME_USE;

    // Call to get size of name_size and domain_size
    let las_rc = unsafe {
        LookupAccountSidW(
            None,
            psidowner,
            name_as_pwstr,
            &mut name_size,
            domain_as_pwstr,
            &mut domain_size,
            euse,
        )
    };

    if las_rc.0 == 0 {
        let last_error = unsafe { GetLastError() };
        debug!("Error code is {:#?}", last_error);
        debug!("name_size {:#?}", name_size);
        debug!("domain_size {:#?}", domain_size);
    } else {
        panic!("Expecting an error when calling LookupAccountSidW initially");
    }

    // Call again, this time with appropriately sized buffers
    let name_as_wstring = WideString::new(name_size as usize);
    let name_as_wstring_ptr = name_as_wstring.as_ptr();
    let name_as_pwstr = PWSTR(name_as_wstring_ptr);

    let domain_as_wstring = WideString::new(domain_size as usize);
    let domain_as_wstring_ptr = domain_as_wstring.as_ptr();
    let domain_as_pwstr = PWSTR(domain_as_wstring_ptr);

    let las_rc = unsafe {
        LookupAccountSidW(
            None,
            psidowner,
            name_as_pwstr,
            &mut name_size,
            domain_as_pwstr,
            &mut domain_size,
            euse,
        )
    };

    if las_rc.0 == 0 {
        let last_error = unsafe { GetLastError() };
        panic!("Error code is {:#?}", last_error);
    } else {
        println!(
            "File {} is owned by {}",
            format!("{:#?}", readme_path).bright_yellow(),
            name_as_wstring.to_string()?.bright_blue()
        );
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        println!("Stopping with error: {}", e);
        exit(1);
    }
    exit(0);
}
