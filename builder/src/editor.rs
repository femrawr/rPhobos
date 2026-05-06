use std::path::PathBuf;
use std::collections::HashMap;
use std::error::Error;
use std::fs;

pub struct Editor {
    path: PathBuf,

    bools: HashMap<String, bool>,
    byte_arrays: HashMap<String, Vec<u8>>,
    string_arrays: HashMap<String, Vec<String>>
}

impl Editor {
    pub fn new(path: &PathBuf) -> Self {
        Self {
            path: path.to_path_buf(),

            bools: HashMap::new(),
            byte_arrays: HashMap::new(),
            string_arrays: HashMap::new()
        }
    }

    pub fn set_bool(mut self, name: &str, value: bool) -> Self {
        self.bools.insert(name.to_string(), value);
        self
    }

    pub fn set_byte_array(mut self, name: &str, value: &[u8]) -> Self {
        self.byte_arrays.insert(name.to_string(), value.to_vec());
        self
    }

    pub fn set_string_array(mut self, name: &str, value: &[&str]) -> Self {
        self.string_arrays.insert(
            name.to_string(),
            value.iter().map(|str| str.to_string()).collect()
        );

        self
    }

    pub fn finalize(self) -> Result<(), Box<dyn Error>> {
        let content = fs::read_to_string(&self.path)?;
        let mut lines = content
            .lines()
            .map(|l| l.to_string())
            .collect::<Vec<String>>();

        for (name, value) in &self.bools {
            for line in lines.iter_mut() {
                if line.contains(&format!("pub const {}", name)) && line.contains(": bool") {
                    *line = format!("pub const {}: bool = {};", name, value);
                    break;
                }
            }
        }

        for (name, value) in &self.byte_arrays {
            for line in lines.iter_mut() {
                if line.contains(&format!("pub const {}", name)) && line.contains("&[u8]") {
                    *line = format!("pub const {}: &[u8] = &{:?};", name, value);
                    break;
                }
            }
        }

        for (name, value) in &self.string_arrays {
            for line in lines.iter_mut() {
                if line.contains(&format!("pub const {}", name)) && line.contains("&[&str]") {
                    let entries = value
                        .iter()
                        .map(|str| format!("\"{}\"", str))
                        .collect::<Vec<String>>()
                        .join(", ");

                    *line = format!("pub const {}: &[&str] = &[{}];", name, entries);
                    break;
                }
            }
        }

        fs::write(&self.path, lines.join("\n"))?;

        Ok(())
    }
}
