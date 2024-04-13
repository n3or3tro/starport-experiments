use windows::{
    core::*,
    Win32::UI::WindowsAndMessaging::{MessageBoxA, MESSAGEBOX_RESULT},
};
use windows::{Win32::Foundation::*, Win32::System::SystemServices::*};

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => attach(),
        DLL_PROCESS_DETACH => detach(),
        _ => (),
    }

    true
}

fn attach() {
    unsafe {
        let _create_result = MessageBoxA(HWND(0), s!("ZOMG!"), s!("hello.dll"), Default::default());
    }
}

fn detach() {
    unsafe {
        let _create_result = MessageBoxA(
            HWND(0),
            s!("Goodbye :("),
            s!("hello.dll"),
            Default::default(),
        );
    }
}
#[no_mangle]
pub fn add(left: usize, right: usize) -> usize {
    println!("hello from add in the dll");
    println!("your mums a hoe");
    left + right + (3 as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
