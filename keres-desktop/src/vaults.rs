use std::fmt;
use std::path::PathBuf;

use keres::Result;
use keres::Vault;
use keres::{KdfParams, Padding, VaultOptions};

#[derive(Debug)]
pub struct OpenVault {
    pub name: String,
    pub vault: Vault,
}

pub struct VaultSession {
    pub base_dir: PathBuf,
    pub open: Option<OpenVault>,
}

impl Default for VaultSession {
    fn default() -> Self {
        Self {
            base_dir: crate::util::data_dir().join("vaults"),
            open: None,
        }
    }
}

/// Everything the dashboard can show about the open vault.
#[derive(Debug, Clone)]
pub struct VaultStatus {
    pub name: String,
    pub path: PathBuf,
    pub unlocked: bool,
    pub entries: usize,
    pub generation: u64,
    pub records: u64,
    pub padding: String,
    pub keyslots: usize,
    pub recovery_kit: bool,
}

/// Argon2id cost presets exposed by the create form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KdfPreset {
    Fast,
    #[default]
    Balanced,
    Paranoid,
}

impl KdfPreset {
    pub const ALL: [KdfPreset; 3] = [Self::Fast, Self::Balanced, Self::Paranoid];

    #[must_use]
    pub fn params(self) -> KdfParams {
        match self {
            // Interactive devices with a small memory budget. Still far above
            // the library's minimum; useful for tests and low-end hardware.
            Self::Fast => KdfParams {
                m_cost_kib: 32 * 1024,
                t_cost: 2,
                p_cost: 2,
            },
            Self::Balanced => KdfParams::new(),
            // High-value archives on a workstation. Unlocking is deliberately
            // slow and allocates a quarter of a GiB.
            Self::Paranoid => KdfParams {
                m_cost_kib: 256 * 1024,
                t_cost: 6,
                p_cost: 4,
            },
        }
    }
}

impl fmt::Display for KdfPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Fast => "fast · 32 MiB · 2 passes",
            Self::Balanced => "balanced · 64 MiB · 4 passes",
            Self::Paranoid => "paranoid · 256 MiB · 6 passes",
        })
    }
}

/// Size-padding presets exposed by the create form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PaddingPreset {
    #[default]
    None,
    Adaptive,
    Fixed4K,
    Fixed64K,
    Fixed1M,
}

impl PaddingPreset {
    pub const ALL: [PaddingPreset; 5] = [
        Self::None,
        Self::Adaptive,
        Self::Fixed4K,
        Self::Fixed64K,
        Self::Fixed1M,
    ];

    #[must_use]
    pub fn padding(self) -> Padding {
        match self {
            Self::None => Padding::None,
            Self::Adaptive => Padding::Adaptive,
            Self::Fixed4K => Padding::Fixed { size: 4 * 1024 },
            Self::Fixed64K => Padding::Fixed { size: 64 * 1024 },
            Self::Fixed1M => Padding::Fixed { size: 1024 * 1024 },
        }
    }
}

impl fmt::Display for PaddingPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none · exact ciphertext size",
            Self::Adaptive => "adaptive · powers of two",
            Self::Fixed4K => "fixed · 4 KiB buckets",
            Self::Fixed64K => "fixed · 64 KiB buckets",
            Self::Fixed1M => "fixed · 1 MiB buckets",
        })
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(keres::Error::InvalidEntryName("vault name is empty".into()));
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(keres::Error::InvalidEntryName(
            "vault name must be a plain name, not a path".into(),
        ));
    }
    Ok(())
}

fn vault_path(session: &VaultSession, name: &str) -> PathBuf {
    session.base_dir.join(name)
}

pub fn list_vault_names(session: &VaultSession) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&session.base_dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() && Vault::new(path.clone()).exists() {
                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    names.push(name.to_string());
                }
            }
        }
    }
    names.sort();
    names
}

#[must_use]
pub fn status(session: &VaultSession) -> Option<VaultStatus> {
    let open = session.open.as_ref()?;
    let keyslots = open.vault.keyslots().map(|s| s.len()).unwrap_or(0);
    let recovery_kit = open.vault.has_recovery_kit();
    let unlocked = open.vault.is_unlocked();

    let (entries, generation, records, padding) = if unlocked {
        let entries = open.vault.list().map(|e| e.len()).unwrap_or(0);
        let (generation, records) = open
            .vault
            .version()
            .map(|v| (v.generation, v.records))
            .unwrap_or((0, 0));
        let padding = open
            .vault
            .padding()
            .map(describe_padding)
            .unwrap_or_else(|_| "unknown".to_string());
        (entries, generation, records, padding)
    } else {
        (0, 0, 0, "—".to_string())
    };

    Some(VaultStatus {
        name: open.name.clone(),
        path: open.vault.path().to_path_buf(),
        unlocked,
        entries,
        generation,
        records,
        padding,
        keyslots,
        recovery_kit,
    })
}

#[must_use]
pub fn describe_padding(padding: Padding) -> String {
    match padding {
        Padding::None => "none".to_string(),
        Padding::Adaptive => "adaptive".to_string(),
        Padding::Fixed { size } => format!("fixed · {size} B"),
        // Padding is #[non_exhaustive]; a future policy must still render.
        _ => "unknown".to_string(),
    }
}

pub fn create_vault_with_options(
    session: &mut VaultSession,
    name: &str,
    password: &str,
    confirm: &str,
    padding: PaddingPreset,
    kdf: KdfPreset,
) -> Result<String> {
    validate_name(name)?;
    if session.open.is_some() {
        return Err(keres::Error::VaultUnlocked);
    }
    if password.is_empty() {
        return Err(keres::Error::Operation(
            "passphrase must not be empty".into(),
        ));
    }
    if password != confirm {
        return Err(keres::Error::Operation("passphrases do not match".into()));
    }

    let path = vault_path(session, name);
    let mut vault = Vault::new(path);
    if vault.exists() {
        return Err(keres::Error::VaultExists);
    }
    vault.init_with_options(
        password,
        VaultOptions::new()
            .padding(padding.padding())
            .kdf(kdf.params()),
    )?;

    let message = format!("Vault '{name}' created · {} · {kdf}", padding.padding());
    session.open = Some(OpenVault {
        name: name.to_string(),
        vault,
    });
    Ok(message)
}

pub fn unlock_vault(session: &mut VaultSession, name: &str, password: &str) -> Result<String> {
    validate_name(name)?;
    if session.open.is_some() {
        return Err(keres::Error::VaultUnlocked);
    }
    let path = vault_path(session, name);
    let mut vault = Vault::new(path);
    if !vault.exists() {
        return Err(keres::Error::VaultNotFound);
    }
    vault.unlock(password)?;
    session.open = Some(OpenVault {
        name: name.to_string(),
        vault,
    });
    Ok(format!("Vault '{name}' unlocked"))
}

/// Upgrades a legacy (manifest v2) vault in place, then unlocks it.
///
/// `Vault::migrate` leaves the vault locked, so this re-unlocks with the same
/// passphrase before handing the handle to the UI.
pub fn migrate_vault(session: &mut VaultSession, name: &str, password: &str) -> Result<String> {
    validate_name(name)?;
    if session.open.is_some() {
        return Err(keres::Error::VaultUnlocked);
    }
    let path = vault_path(session, name);
    let mut vault = Vault::new(path);
    if !vault.exists() {
        return Err(keres::Error::VaultNotFound);
    }
    let report = vault.migrate(password)?;
    vault.unlock(password)?;
    let message = format!(
        "Migrated '{name}' · {} entries · {} bytes re-encrypted",
        report.entries, report.bytes
    );
    session.open = Some(OpenVault {
        name: name.to_string(),
        vault,
    });
    Ok(message)
}

pub fn lock_vault(session: &mut VaultSession) -> Result<String> {
    match session.open.take() {
        Some(mut v) => {
            v.vault.lock();
            Ok(format!("Vault '{}' locked", v.name))
        }
        None => Err(keres::Error::VaultLocked),
    }
}

pub fn list_entries(session: &VaultSession) -> Result<Vec<(String, String)>> {
    let open = session.open.as_ref().ok_or(keres::Error::VaultLocked)?;
    let mut out = Vec::new();
    for e in open.vault.list()? {
        let suffix = if e.is_directory { "  (dir)" } else { "" };
        let display = format!(
            "{}{}  ·  {}",
            e.name,
            suffix,
            crate::util::human_size(e.size)
        );
        out.push((e.name, display));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

pub fn entry_is_directory(session: &VaultSession, name: &str) -> Result<bool> {
    let open = session.open.as_ref().ok_or(keres::Error::VaultLocked)?;
    Ok(open
        .vault
        .list()?
        .iter()
        .any(|e| e.name == name && e.is_directory))
}

fn safe_basename(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

pub fn add_file(session: &mut VaultSession) -> Result<String> {
    let source = rfd::FileDialog::new()
        .set_title("Add file to vault")
        .add_filter("Any file", &["*"])
        .pick_file()
        .ok_or_else(|| keres::Error::Operation("no file selected".into()))?;
    add_path(session, &source)
}

pub fn add_dir(session: &mut VaultSession) -> Result<String> {
    let source = rfd::FileDialog::new()
        .set_title("Add folder to vault")
        .pick_folder()
        .ok_or_else(|| keres::Error::Operation("no folder selected".into()))?;
    add_path(session, &source)
}

fn add_path(session: &mut VaultSession, source: &std::path::Path) -> Result<String> {
    let open = session.open.as_mut().ok_or(keres::Error::VaultLocked)?;
    let base = source
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "entry".to_string());
    open.vault.add(source, Some(&base))?;
    Ok(format!("Added '{base}' to vault '{}'", open.name))
}

pub fn replace_entry(session: &mut VaultSession, name: &str) -> Result<String> {
    let source = rfd::FileDialog::new()
        .set_title("Choose the replacement file")
        .add_filter("Any file", &["*"])
        .pick_file()
        .ok_or_else(|| keres::Error::Operation("no file selected".into()))?;
    let open = session.open.as_mut().ok_or(keres::Error::VaultLocked)?;
    open.vault.replace(&source, name)?;
    Ok(format!("Replaced '{name}' with {}", source.display()))
}

pub fn rename_entry(session: &mut VaultSession, from: &str, to: &str) -> Result<String> {
    let open = session.open.as_mut().ok_or(keres::Error::VaultLocked)?;
    open.vault.rename(from, to)?;
    Ok(format!("Renamed '{from}' to '{to}'"))
}

pub fn extract_entry(session: &VaultSession, name: &str) -> Result<String> {
    let dest_dir = rfd::FileDialog::new()
        .set_title("Extract to folder")
        .pick_folder()
        .ok_or_else(|| keres::Error::Operation("no destination selected".into()))?;
    let is_dir = entry_is_directory(session, name)?;
    let dest = if is_dir {
        dest_dir
    } else {
        dest_dir.join(safe_basename(name))
    };
    let open = session.open.as_ref().ok_or(keres::Error::VaultLocked)?;
    let written = open.vault.extract(name, &dest)?;
    Ok(format!("Extracted '{name}' -> {}", written.display()))
}

pub fn remove_entry(session: &mut VaultSession, name: &str) -> Result<String> {
    let open = session.open.as_mut().ok_or(keres::Error::VaultLocked)?;
    open.vault.remove(name)?;
    Ok(format!("Removed '{name}' from vault '{}'", open.name))
}

pub fn verify_vault(session: &mut VaultSession, password: &str) -> Result<String> {
    let open = session.open.as_mut().ok_or(keres::Error::VaultLocked)?;
    let report = open.vault.verify(password)?;
    let mut lines = vec![format!(
        "Verified {} of {} entries",
        report.verified, report.total_entries
    )];
    for m in &report.missing {
        lines.push(format!("missing: {m}"));
    }
    for c in &report.corrupted {
        lines.push(format!("corrupt: {c}"));
    }
    if report.missing.is_empty() && report.corrupted.is_empty() {
        lines.push("OK: all entries authenticated.".into());
    }
    Ok(lines.join("\n"))
}

pub fn change_vault_password(session: &mut VaultSession, old: &str, new: &str) -> Result<String> {
    let name = match &session.open {
        Some(o) => o.name.clone(),
        None => return Err(keres::Error::VaultLocked),
    };
    let path = vault_path(session, &name);
    let mut vault = Vault::new(path);
    vault.change_password(old, new)?;
    Ok(format!("Password changed for vault '{name}'"))
}

// ---------------------------------------------------------------- recovery ---

pub fn create_recovery_kit(session: &mut VaultSession, password: &str) -> Result<String> {
    let open = session.open.as_mut().ok_or(keres::Error::VaultLocked)?;
    let code = open.vault.create_recovery_kit(password)?;
    Ok(code.expose().to_string())
}

pub fn recover_vault(
    session: &mut VaultSession,
    name: &str,
    recovery_code: &str,
    new_password: &str,
) -> Result<String> {
    validate_name(name)?;
    if session.open.is_some() {
        return Err(keres::Error::VaultUnlocked);
    }
    if new_password.is_empty() {
        return Err(keres::Error::Operation(
            "new passphrase must not be empty".into(),
        ));
    }
    let path = vault_path(session, name);
    let mut vault = Vault::new(path);
    if !vault.exists() {
        return Err(keres::Error::VaultNotFound);
    }
    vault.recover(recovery_code.trim(), new_password)?;
    Ok(format!(
        "Vault '{name}' recovered · unlock with the new passphrase"
    ))
}

// ---------------------------------------------------------------- keyslots ---

pub fn keyslots(session: &VaultSession) -> Result<Vec<String>> {
    let open = session.open.as_ref().ok_or(keres::Error::VaultLocked)?;
    Ok(open
        .vault
        .keyslots()?
        .into_iter()
        .map(|slot| slot.id)
        .collect())
}

pub fn add_keyslot(
    session: &mut VaultSession,
    existing_password: &str,
    new_password: &str,
) -> Result<String> {
    let open = session.open.as_mut().ok_or(keres::Error::VaultLocked)?;
    let slot = open.vault.add_keyslot(existing_password, new_password)?;
    Ok(format!("Added keyslot {}", slot.id))
}

pub fn remove_keyslot(session: &mut VaultSession, slot_id: &str, password: &str) -> Result<String> {
    let open = session.open.as_mut().ok_or(keres::Error::VaultLocked)?;
    open.vault.remove_keyslot(slot_id, password)?;
    Ok(format!("Removed keyslot {slot_id}"))
}

// ---------------------------------------------------------------- rotation ---

pub fn rotate_vault(
    session: &mut VaultSession,
    old_password: &str,
    new_password: &str,
) -> Result<String> {
    let mut open = session.open.take().ok_or(keres::Error::VaultLocked)?;
    match open.vault.rotate(old_password, new_password) {
        Ok(report) => Ok(format!(
            "Rotated '{}' · {} entries · {} bytes · {} keyslots dropped{}",
            open.name,
            report.entries,
            report.bytes,
            report.discarded_keyslots,
            if report.recovery_kit_removed {
                " · recovery kit removed"
            } else {
                ""
            }
        )),
        Err(e) => {
            // Keep the unlocked handle so the user can retry.
            session.open = Some(open);
            Err(e)
        }
    }
}

pub fn erase_entry(session: &mut VaultSession, name: &str, new_password: &str) -> Result<String> {
    let mut open = session.open.take().ok_or(keres::Error::VaultLocked)?;
    match open.vault.erase(name, new_password) {
        Ok(report) => Ok(format!(
            "Erased '{name}' · {} survivors re-encrypted · {} bytes · {} keyslots dropped",
            report.entries, report.bytes, report.discarded_keyslots
        )),
        Err(e) => {
            session.open = Some(open);
            Err(e)
        }
    }
}
