use std::ffi::{OsStr, OsString};

// #[link(name = "dll_stuff.dll", kind = "dylib")]
// extern "C" {
//     fn add(left: usize, right: usize) -> usize;
// }
use windows::{
    core::{HSTRING, PCWSTR},
    Win32::System::LibraryLoader::LoadLibraryW,
    Win32::System::Threading::GetCurrentProcessId,
};
fn main() {
    println!(" :( Make sure you provide the path to the dll, relative to where you're running this binary from\nPlease give me the path: ");

    let mut path = String::new();
    std::io::stdin().read_line(&mut path).unwrap();

    // without this null character fuckery, we can't load the lib via user input.
    path = path.as_str().trim().to_string();
    path.push_str("\0");

    // fuckery to get an appropriate windows string.
    let lol: HSTRING = HSTRING::from(path.clone());
    let w_string: PCWSTR = PCWSTR::from_raw(lol.as_ptr());

    unsafe {
        // let what: HSTRING = HSTRING::from(".\\dll_stuff.dll");
        // let path = PCWSTR::from_raw(what.as_ptr());
        let res = LoadLibraryW(w_string);
        // let res = LoadLibraryW(path.clone());
        match res {
            Ok(_) => println!(
                "Succesfully loaded the library into process with PID: {}",
                GetCurrentProcessId()
            ),
            Err(err) => {
                println!(
                    "Loading the library at: {:?} failed with error: {:?}",
                    path, err
                );
                return;
            }
        }
    }
    println!("Press enter to exit the program");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}
