use std::path::PathBuf;

use keres::Result;
use keres::Vault;

pub struct PasswordsStore {
    pub path: PathBuf,
    pub vault: Option<Vault>,
}

impl Default for PasswordsStore {
    fn default() -> Self {
        Self {
            path: crate::util::data_dir().join("passwords"),
            vault: None,
        }
    }
}

fn sanitize_name(name: &str) -> String {
    let trimmed = name.trim();
    let cleaned: String = trimmed
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c == ':' || c == '\0' {
                '-'
            } else {
                c
            }
        })
        .collect();
    if cleaned.is_empty() {
        "entry".to_string()
    } else {
        cleaned
    }
}

pub fn create(session: &mut PasswordsStore, password: &str) -> Result<String> {
    let mut vault = Vault::new(session.path.clone());
    vault.init(password)?;
    session.vault = Some(vault);
    Ok(format!(
        "Password vault created at {}",
        session.path.display()
    ))
}

pub fn unlock(session: &mut PasswordsStore, password: &str) -> Result<String> {
    if session.vault.is_some() {
        return Err(keres::Error::VaultUnlocked);
    }
    if !Vault::new(session.path.clone()).exists() {
        return Err(keres::Error::VaultNotFound);
    }
    let mut vault = Vault::new(session.path.clone());
    vault.unlock(password)?;
    session.vault = Some(vault);
    Ok("Password vault unlocked".to_string())
}

pub fn lock(session: &mut PasswordsStore) -> Result<String> {
    match session.vault.take() {
        Some(mut v) => {
            v.lock();
            Ok("Password vault locked".to_string())
        }
        None => Err(keres::Error::VaultLocked),
    }
}

/// Returns (entry name, display name, username) for each stored entry.
pub fn list_entries(session: &PasswordsStore) -> Result<Vec<(String, String, String)>> {
    let vault = session.vault.as_ref().ok_or(keres::Error::VaultLocked)?;
    let mut out = Vec::new();
    for e in vault.list()? {
        if let Some(display) = e.name.strip_suffix(".txt") {
            let username = read_entry(session, &e.name)
                .map(|(_, u)| u)
                .unwrap_or_default();
            out.push((e.name.clone(), display.to_string(), username));
        }
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(out)
}

fn read_entry(session: &PasswordsStore, entry_name: &str) -> Result<(String, String)> {
    let vault = session.vault.as_ref().ok_or(keres::Error::VaultLocked)?;
    let mut content = Vec::new();
    vault.extract_to_writer(entry_name, &mut content)?;
    let text = String::from_utf8(content).map_err(|_| keres::Error::MalformedPayload)?;
    let mut lines = text.lines();
    let password = lines.next().unwrap_or_default().to_string();
    let username = lines.next().unwrap_or_default().to_string();
    Ok((password, username))
}

pub fn save_entry(
    session: &mut PasswordsStore,
    name: &str,
    username: &str,
    password: &str,
) -> Result<String> {
    let vault = session.vault.as_mut().ok_or(keres::Error::VaultLocked)?;
    let clean = sanitize_name(name);
    let entry_name = format!("{clean}.txt");
    let content = format!("{password}\n{username}\n");

    // Keep the plaintext in memory. The reader/writer API avoids the
    // temporary file the previous implementation needed, so secrets never
    // reach the filesystem unencrypted.
    vault.add_from_reader(&entry_name, content.as_bytes(), Some(content.len() as u64))?;
    Ok(format!("Saved entry '{name}'"))
}

pub fn entry_password(session: &PasswordsStore, entry_name: &str) -> Result<String> {
    let (password, _) = read_entry(session, entry_name)?;
    Ok(password)
}

pub fn remove_entry(session: &mut PasswordsStore, entry_name: &str) -> Result<String> {
    let vault = session.vault.as_mut().ok_or(keres::Error::VaultLocked)?;
    vault.remove(entry_name)?;
    Ok(format!("Removed entry '{entry_name}'"))
}

pub fn generate(length: usize, symbols: bool) -> Result<String> {
    let mut charset: Vec<u8> =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_vec();
    if symbols {
        charset.extend_from_slice(b"!@#$%^&*-_=+?");
    }
    let mut buf = vec![0u8; length];
    keres::crypto::fill_random(&mut buf);
    let mut out = String::with_capacity(length);
    for b in buf {
        out.push(charset[(b as usize) % charset.len()] as char);
    }
    Ok(out)
}
