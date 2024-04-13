// use std::os::windows::prelude::*;

use std::{any::Any, mem::transmute};
use widestring::{self};
use windows::{
    core::{HSTRING, PCSTR, PCWSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE, HSTR},
        System::{
            Diagnostics::{
                Debug::WriteProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                    TH32CS_SNAPPROCESS,
                },
            },
            LibraryLoader::{GetModuleHandleA, GetModuleHandleW, GetProcAddress},
            Memory::{
                VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
            },
            Threading::{CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS},
        },
    },
};
#[derive(Debug, Clone)]
struct Process {
    // name: Utf16String,
    name: String,
    pid: u32,
    handle: Option<HANDLE>,
}

fn main() {
    println!("hello :)");
    let target_name = "notepad.exe".to_string();
    let target_process = match get_remote_process_handle(target_name.clone()) {
        Some(p) => p,
        None => panic!("couldnt get remote process handle! :("),
    };
    println!("Found the target process: {:?}", target_name);

    let mut dll_path = String::new();
    println!("Enter the path to the DLL you want to inject:");
    std::io::stdin()
        .read_line(&mut dll_path)
        .expect("Failed to read line");

    inject_dll(target_process, dll_path);
}

fn inject_dll(process: Process, dll_name: String) {
    unsafe {
        // allocate space in the remote process to store the name of the DLL we want to inject.
        let dll_name_addr = VirtualAllocEx(
            process.handle.unwrap(),
            None,
            dll_name.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
            // PAGE_READWRITE,
        );
        if dll_name_addr.is_null() {
            panic!("failed to allocate space in remote process for dll name");
        }
        // wait for input
        println!("Press enter to continue");
        std::io::stdin().read_line(&mut String::new()).unwrap();

        // write our dll name to the allocated space in the remote process.
        let bytes_written = 0;
        let res = WriteProcessMemory(
            process.handle.unwrap(),
            dll_name_addr,
            transmute(dll_name.as_ptr()),
            dll_name.len(),
            Some(transmute(&bytes_written)),
        );
        if bytes_written != dll_name.len() {
            panic!("Failed to write the entire dll name to remote process!");
        }
        match res {
            Ok(_) => {}
            Err(err) => panic!(
                "Failed to write dll name to remote process!\nErr: {:?}",
                err
            ),
        }

        // wait for input
        println!("Press enter to continue");
        std::io::stdin().read_line(&mut String::new()).unwrap();

        // get handle to kernel32.dll
        let kernel_32_module_handle =
            GetModuleHandleA(PCSTR::from_raw("kernel32.dll\0".as_ptr())).unwrap();
        let fn_name = PCSTR::from_raw("LoadLibraryW".as_ptr());
        // get the address of the function which loads dlls.
        let load_library = GetProcAddress(kernel_32_module_handle, fn_name).unwrap();

        // create a remote thread in the target process which will load our dll.
        let remote_thread = match CreateRemoteThread(
            process.handle.unwrap(),
            None,
            0,
            Some(transmute(load_library)),
            Some(dll_name_addr),
            0,
            None,
        ) {
            Ok(remote_thread) => remote_thread,
            Err(_) => panic!("Failed to create remote thread! :("),
        };

        if !remote_thread.is_invalid() {
            println!("DLL injection should have worked by now");
            println!("Press enter to end the program");
            std::io::stdin().read_line(&mut String::new()).unwrap();
        } else {
            panic!("fuckkkkkkkkkkkkkkkkk");
        }
    }
    // add cleanup code once the above is working.
}
// I feel like this is abit shoddy... what happens if 2 processes have the same name.
fn get_remote_process_handle(process_name: String) -> Option<Process> {
    let process_list = get_process_list();
    for process in process_list {
        // we use .contains(), because process.name is always 260 characters long.
        if process
            .name
            .to_lowercase()
            .starts_with(process_name.as_str())
        {
            let handle: Result<HANDLE, _>;
            unsafe {
                handle = OpenProcess(PROCESS_ALL_ACCESS, false, process.pid);
            }
            match handle {
                Ok(handle) => {
                    let mut new = process.clone();
                    new.handle = Some(handle);
                    return Some(new);
                }
                Err(err) => {
                    panic!(
                        "Could not get handle for process: {:#?}\n Err: {:?}",
                        process, err
                    );
                }
            }
        }
    }
    None
}

fn get_process_list() -> Vec<Process> {
    let mut processes = Vec::<Process>::new();
    // co-pilot auto filled this for me... be careful!
    let proc_entry_32w = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; 260],
    };
    let process_snapshot: HANDLE;

    unsafe {
        let res = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        process_snapshot = match res {
            Ok(snapshot) => snapshot,
            Err(_) => panic!("Could not get process snapshot! :("),
        };

        match Process32FirstW(process_snapshot, transmute(&proc_entry_32w)) {
            Ok(_) => {}
            Err(err) => panic!(":(( Err: {err:?}"),
        };
    }

    processes.push(Process {
        name: widestring::Utf16Str::from_slice(&proc_entry_32w.szExeFile)
            .unwrap()
            .to_string(),
        pid: proc_entry_32w.th32ProcessID,
        handle: None,
    });

    unsafe {
        // should implement propper error handling irl.
        while Process32NextW(process_snapshot, transmute(&proc_entry_32w)).is_ok() {
            processes.push(Process {
                name: widestring::Utf16Str::from_slice(&proc_entry_32w.szExeFile)
                    .unwrap()
                    .to_string(),
                pid: proc_entry_32w.th32ProcessID,
                handle: None,
            });
        }
    }
    if !process_snapshot.is_invalid() {
        unsafe {
            match CloseHandle(process_snapshot) {
                Ok(_) => {}
                Err(_) => panic!("failed to close process_snapshot"),
            }
        }
    }
    return processes;
}
