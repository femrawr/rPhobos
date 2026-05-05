use std::{fs, mem};
use std::path::PathBuf;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW};
use windows::Win32::System::Diagnostics::ToolHelp::{PROCESSENTRY32W, TH32CS_SNAPPROCESS};

pub fn find_file_upstream(start_path: &PathBuf, hashed_name: &[u8]) -> Option<PathBuf> {
    let mut current_dir = start_path.as_path();

    loop {
        let directory = match fs::read_dir(current_dir) {
            Ok(entries) => entries,
            Err(_) => return None
        };

        for entry in directory.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();

            let name_hash = blake3::hash(name.as_bytes());
            if name_hash.as_bytes() == hashed_name {
                return Some(path);
            }
        }

        current_dir = match current_dir.parent() {
            Some(parent) => parent,
            None => return None
        };
    }
}

pub fn find_pids_by_names(names: &[&str]) -> Vec<u32> {
    let mut results = Vec::new();

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(handle) => handle,
            Err(_) => return results
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let process = Process32FirstW(snapshot, &mut entry);
        if process.is_err() {
            CloseHandle(snapshot).ok();
            return results;
        }

        loop {
            let process_name = String::from_utf16_lossy(
                &entry.szExeFile[..entry.szExeFile
                    .iter()
                    .position(|&char| char == 0)
                    .unwrap_or(entry.szExeFile.len())]
            );

            for &name in names {
                if !process_name.eq_ignore_ascii_case(name) {
                    continue;
                }

                results.push(entry.th32ProcessID);
            }

            let next_process = Process32NextW(snapshot, &mut entry);
            if next_process.is_err() {
                break;
            }
        }

        CloseHandle(snapshot).ok();
    }

    results
}

pub fn to_null_terminated(string: &str) -> Vec<u8> {
    let mut string = string
        .as_bytes()
        .to_vec();

    string.push(0);

    string
}
