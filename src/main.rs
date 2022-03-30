use std::{
    ffi::{CStr, CString},
    fs::File,
    os::windows::io::AsRawHandle,
    path::PathBuf,
};

use path_abs::PathAbs;
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{GetLastError, HANDLE},
        Storage::FileSystem::{
            CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
        },
    },
};


// https://docs.microsoft.com/en-us/windows/win32/secauthz/finding-the-owner-of-a-file-object-in-c--
fn main() {
    let path = PathBuf::new().join(env!("CARGO_MANIFEST_DIR"));
    let readme_path = PathAbs::new(path.clone())
        .unwrap()
        .as_path()
        .join("README.md");
    // let readme_path = path.join("README.md");
    let readme_path = readme_path.as_os_str().to_str().unwrap();
    //let readme_path2 = readme_path.as_os_str().to_str().unwrap();
    // let readme_path = String::from("README.md");
    let readme_path_as_cstring = CString::new(readme_path)
        .unwrap()
        .into_raw() as *const u8;
        //.as_bytes_with_nul()
    //let readme_path_as_cstring = b"README.md\0".as_ptr() as *const u8;
    let pcstr = PCSTR(readme_path_as_cstring);
    // let pcstr = PCSTR(CString::new(readme_path).unwrap().as_bytes_with_nul().as_ptr());

    println!("path is {:#?}", path);
    println!("readme_path is {:#?}", readme_path);

    // File handle
    let handle: HANDLE = unsafe {
        CreateFileA(
            pcstr,
            FILE_GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None
        )
    };
    let error = unsafe { GetLastError() };
    println!("Last error is {:#?}", error);

    println!("Handle is {:#X?}", handle);

    //let handle = File::open(readme_path).unwrap().as_raw_handle();
    //println!("Handle is {:#?}", handle);
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
