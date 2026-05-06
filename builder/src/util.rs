use std::path::PathBuf;
use std::fs;

pub fn find_file_upstream(start_path: &PathBuf, file_name: &str) -> Option<PathBuf> {
    let mut current_dir = start_path
        .as_path()
        .parent()
        .unwrap();

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

            if name == file_name {
                return Some(path);
            }
        }

        current_dir = match current_dir.parent() {
            Some(parent) => parent,
            None => return None
        };
    }
}

pub fn find_dir_upstream(start_path: &PathBuf, dir_name: &str) -> Option<PathBuf> {
    let mut current_dir = start_path
        .as_path()
        .parent()
        .unwrap();

    loop {
        let directory = match fs::read_dir(current_dir) {
            Ok(entries) => entries,
            Err(_) => return None
        };

        for entry in directory.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();

            if name == dir_name {
                return Some(path);
            }
        }

        current_dir = match current_dir.parent() {
            Some(parent) => parent,
            None => return None
        };
    }
}
