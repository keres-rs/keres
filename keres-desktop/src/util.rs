use std::path::PathBuf;

/// Base directory for all Keres state. Override with `KERES_HOME`.
///
/// Existing Krypton users are transparently pointed at `~/.krypton` when
/// `~/.keres` does not exist yet, so their old vaults remain reachable for
/// migration. [`using_legacy_dir`] lets the UI warn about that case.
pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("KERES_HOME") {
        return PathBuf::from(dir);
    }
    if let Ok(home) = std::env::var("HOME") {
        let modern = PathBuf::from(&home).join(".keres");
        if modern.exists() {
            return modern;
        }
        let legacy = PathBuf::from(&home).join(".krypton");
        if legacy.exists() {
            return legacy;
        }
        return modern;
    }
    PathBuf::from(".")
}

/// Whether [`data_dir`] fell back to the pre-rename Krypton directory.
pub fn using_legacy_dir() -> bool {
    if std::env::var_os("KERES_HOME").is_some() {
        return false;
    }
    match std::env::var_os("HOME") {
        Some(home) => {
            let modern = PathBuf::from(&home).join(".keres");
            let legacy = PathBuf::from(&home).join(".krypton");
            !modern.exists() && legacy.exists()
        }
        None => false,
    }
}

pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}
