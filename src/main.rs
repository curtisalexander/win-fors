use std::{error::Error, path::PathBuf, process::exit};

use path_abs::PathAbs;
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
        },
    },
};

struct WString(Vec<u16>);

impl WString {
    fn from_str(s: &str) -> Self {
        Self(
            s.encode_utf16().chain(std::iter::once(0x0000)).collect::<Vec<u16>>()
        )
    }

    fn as_ptr(&self) -> *const u16 {
        let s_ref: &Vec<u16> = &self.0.as_ref();
        s_ref.as_ptr() as *const u16
    }
}

// https://docs.microsoft.com/en-us/windows/win32/secauthz/finding-the-owner-of-a-file-object-in-c--
fn run() -> Result<(), Box<dyn Error>> {
    // Example file - README.md in this repository
    let path = PathBuf::new().join(env!("CARGO_MANIFEST_DIR"));
    let readme_path = PathAbs::new(path.clone())?.as_path().join("README.md");

    println!("path is {:#?}", path);
    println!("readme_path is {:#?}", readme_path);

    let path_as_str = readme_path
        .as_os_str()
        .to_str()
        .ok_or_else(|| format!("Unable to convert {:#?} to string", readme_path))?;

    let wstring = WString::from_str(path_as_str);
    let wstring_ptr = wstring.as_ptr();
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

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        println!("Stopping with error: {}", e);
        exit(1);
    }
    exit(0);
}
