use std::os::windows::ffi::OsStrExt;
use std::{error::Error, ffi::OsStr, path::PathBuf, process::exit};

use path_abs::PathAbs;
use windows::{
    core::{PWSTR, PCWSTR},
    Win32::{
        Foundation::{GetLastError, ERROR_SUCCESS, HANDLE, PSID},
        Security::{
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            LookupAccountSidW, OWNER_SECURITY_INFORMATION, SECURITY_DESCRIPTOR, SidTypeUnknown
        },
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
        },
    },
};

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
}

// https://docs.microsoft.com/en-us/windows/win32/secauthz/finding-the-owner-of-a-file-object-in-c--
fn run() -> Result<(), Box<dyn Error>> {
    // Example file - README.md in this repository
    let path = PathBuf::new().join(env!("CARGO_MANIFEST_DIR"));
    let readme_path = PathAbs::new(path.clone())?.as_path().join("README.md");

    println!("path is {:#?}", path);
    println!("readme_path is {:#?}", readme_path);

    let wstring = WideString::from_os_str(readme_path.as_os_str());
    let wstring_ptr = wstring.as_const_ptr();
    let pcwstr = PCWSTR(wstring_ptr);

    // File handle
    let handle: HANDLE = unsafe {
        CreateFileW(
            pcwstr,
            FILE_GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };

    if let Err(e) = handle.ok() {
        panic!("Error with {:#?}: {:#?}", pcwstr, e);
    }

    println!("Handle is {:#X?}", handle);

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
        println!("Error code is {:#?}", last_error);
    } else {
        println!("psidowner is {:#?}", psidowner);
    }

    // Lookup Account Sid
    let name_size = 256;
    let name_size_ptr = name_size as *mut u32;
    let name = PWSTR(WideString::new(name_size).as_ptr());
    let domain_name_size = 256;
    let domain_name_size_ptr = domain_name_size as *mut u32;
    let domain_name = PWSTR(WideString::new(domain_name_size).as_ptr());
    let mut e = SidTypeUnknown;

    let las_rc = unsafe {
        LookupAccountSidW(
            None,
            &psidowner,
            name,
            name_size_ptr,
            domain_name,
            domain_name_size_ptr,
            &mut e
        )
    };

    println!("name is {:#?}", name);

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        println!("Stopping with error: {}", e);
        exit(1);
    }
    exit(0);
}
