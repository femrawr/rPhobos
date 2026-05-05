use std::error::Error;
use std::ffi::c_void;
use std::mem;

use windows::core::PCSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Memory::{MEM_RELEASE, VirtualAllocEx, VirtualFreeEx};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows::Win32::System::Threading::{CreateRemoteThread, OpenProcess, WaitForSingleObject};
use windows::Win32::System::Threading::{PROCESS_ALL_ACCESS, INFINITE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

use crate::utils::to_null_terminated;

pub fn inject_dll(pid: u32, dll_path: &str) -> Result<(), Box<dyn Error>> {
    let dll_path_str = to_null_terminated(dll_path);

    let kernel32_str = to_null_terminated("kernel32");
    let load_library_str = to_null_terminated("LoadLibraryA");

    unsafe {
        let process = match OpenProcess(PROCESS_ALL_ACCESS, false, pid) {
            Ok(handle) => handle,
            Err(_) => return Err("failed to open process".into())
        };

        let allocated = VirtualAllocEx(
            process,
            None,
            dll_path_str.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if allocated.is_null() {
            return Err("failed to allocate".into());
        }

        let written = WriteProcessMemory(
            process,
            allocated,
            dll_path_str.as_ptr() as *const c_void,
            dll_path_str.len(),
            None
        );

        if written.is_err() {
            return Err("failed to write process memory".into());
        }

        let kernel32 = match GetModuleHandleA(PCSTR(kernel32_str.as_ptr())) {
            Ok(handle) => handle,
            Err(_) => return Err("failed to get kernel32".into())
        };

        let load_library = match GetProcAddress(kernel32, PCSTR(load_library_str.as_ptr())) {
            Some(handle) => handle,
            None => return Err("failed to get loadlibray".into())
        };

        let thread = match CreateRemoteThread(
            process,
            None,
            0,
            Some(mem::transmute(load_library)),
            Some(allocated),
            0,
            None
        ) {
            Ok(handle) => handle,
            Err(_) => return Err("failed to create thread".into())
        };

        WaitForSingleObject(thread, INFINITE);

        VirtualFreeEx(process, allocated, dll_path_str.len(), MEM_RELEASE).ok();

        CloseHandle(thread).ok();
        CloseHandle(process).ok();
    }

    Ok(())
}
