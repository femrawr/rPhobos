use std::error::Error;
use std::ffi::c_void;

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Threading::GetCurrentProcess;

const PATCH_SIZE: usize = 16;

pub struct HookedState {
    pub original: [u8; PATCH_SIZE],
    pub target: usize
}

impl HookedState {
    pub unsafe fn hook(dll: PCSTR, func: PCSTR, hook: usize) -> Result<Self, Box<dyn Error>> {
        unsafe {
            let mut dll_handle = match GetModuleHandleA(dll) {
                Ok(handle) => handle,
                Err(_) => return Err("failed to get module handle".into())
            };

            if dll_handle.is_invalid() {
                dll_handle = match LoadLibraryA(dll) {
                    Ok(handle) => handle,
                    Err(_) => return Err("failed to load module".into())
                };
            }

            let target = match GetProcAddress(dll_handle, func) {
                Some(address) => address as usize,
                None => return Err("failed to get func address".into())
            };

            let mut original = [0u8; PATCH_SIZE];

            let read_memory = ReadProcessMemory(
                GetCurrentProcess(),
                target as *const c_void,
                original.as_mut_ptr() as *mut c_void,
                PATCH_SIZE,
                None
            );

            if read_memory.is_err() {
                return Err("failed to read process memory".into());
            }

            let state = Self {
                original,
                target
            };

            state.write_patch(target, state.create_patch(hook));

            Ok(state)
        }
    }

    pub unsafe fn unhook(&self) {
        unsafe {
            self.write_patch(self.target, self.original);
        }
    }

    pub unsafe fn repatch(&self, hook: usize) {
        unsafe {
            self.write_patch(self.target, self.create_patch(hook));
        }
    }

    unsafe fn write_patch(&self, target: usize, patch: [u8; PATCH_SIZE]) {
        unsafe {
            WriteProcessMemory(
                GetCurrentProcess(),
                target as *const c_void,
                patch.as_ptr() as *const c_void,
                PATCH_SIZE,
                None
            ).unwrap();
        }
    }

    fn create_patch(&self, address: usize) -> [u8; PATCH_SIZE] {
        let mut patch = [
            0x48, 0xB8,                                     // mov rax, imm46
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // placeholder
            0xFF, 0xE0,                                     // jmp rax
            0x90, 0x90, 0x90, 0x90                          // padding
        ];

        patch[2..10].copy_from_slice(&address.to_le_bytes());

        patch
    }
}
