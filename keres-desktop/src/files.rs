use keres::Result;
use std::path::Path;
use std::path::PathBuf;

pub fn encrypt_file(
    password: &str,
    input: &Path,
    output: Option<&Path>,
) -> Result<(PathBuf, String)> {
    if !input.is_file() {
        return Err(keres::Error::Operation("input file does not exist".into()));
    }
    let out = keres::encrypt_file(password, input, output)?;
    let note = if output.is_none() {
        " (auto-generated container name; original filename stays hidden)"
    } else {
        ""
    };
    Ok((
        out.clone(),
        format!("Encrypted {} -> {}{note}", input.display(), out.display()),
    ))
}

pub fn decrypt_file(
    password: &str,
    input: &Path,
    output: &Path,
) -> Result<(String, PathBuf, String)> {
    if !input.is_file() {
        return Err(keres::Error::Operation("input file does not exist".into()));
    }
    let original = keres::decrypt_file(password, input, output)?;
    Ok((
        original.clone(),
        output.to_path_buf(),
        format!(
            "Decrypted {} -> {}\nRecovered original filename: {}",
            input.display(),
            output.display(),
            original
        ),
    ))
}

/// Derives a default output path for decryption when the user leaves the field blank.
pub fn default_decrypt_output(input: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "output".to_string());
    input.with_file_name(format!("{stem}.decrypted"))
}
