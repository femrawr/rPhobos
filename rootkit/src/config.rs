const HIDE_FILE_NAME_PREFIX: &str = "rp!";

const HIDE_FILE_NAME_EXACTS: &[&str] = &["thug.txt", "feminist literature.pdf"];

pub fn should_hide_file(name: &[u16]) -> bool {
    let name_str = String::from_utf16_lossy(name);

    let should_hide_prefix = name_str.starts_with(HIDE_FILE_NAME_PREFIX);
    let should_hide_exact = HIDE_FILE_NAME_EXACTS.contains(&name_str.as_str());

    should_hide_prefix || should_hide_exact
}
