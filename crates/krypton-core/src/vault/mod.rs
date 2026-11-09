//! Multi-file encrypted vaults.
//!
//! # Layout
//!
//! ```text
//! vault/
//! |-- vault.config        encrypted master key + KDF parameters (v2 JSON)
//! +-- d/
//!     |-- .manifest.enc   encrypted index of every entry
//!     +-- <hash>/<hash>.enc  per-entry ciphertext blobs
//! ```
//!
//! # Example
//!
//! ```no_run
//! use krypton::Vault;
//! use std::path::Path;
//!
//! let mut vault = Vault::new("myvault".into());
//! vault.init("correct horse battery staple").unwrap();
//! vault.add(Path::new("secret.pdf"), None).unwrap();
//! let entries = vault.list().unwrap();
//! vault.extract("secret.pdf", Path::new("./out")).unwrap();
//! vault.change_password("correct horse battery staple", "new password").unwrap();
//! vault.lock();
//! ```

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::crypto::Key;
use crate::error::{Error, Result};
use crate::sanitize;

pub(crate) mod file_ops;
pub(crate) mod keystore;
pub(crate) mod manifest;

use file_ops as blobs;
use keystore::{KeyStore, VaultConfig};
use manifest::{EntryMetadata, ManifestMap};

/// A handle to an on-disk encrypted vault.
///
/// Operations follow an explicit lock/unlock protocol: [`Vault::unlock`]
/// derives the master key into zeroizing memory, every content operation
/// requires the unlocked state, and [`Vault::lock`] (plus `Drop`) scrubs it.
///
/// # Example
///
/// ```no_run
/// use krypton::Vault;
/// use std::path::Path;
///
/// let mut vault = Vault::new("myvault".into());
///
/// // First run: create the vault (fails if it already exists).
/// if !vault.exists() {
///     vault.init("correct horse battery staple")?;
/// }
/// vault.unlock("correct horse battery staple")?;
///
/// // Store a file and a whole directory tree.
/// vault.add(Path::new("report.pdf"), None)?;          // stored as "report.pdf"
/// vault.add(Path::new("photos"), Some("pictures"))?;  // tree renamed to "pictures"
///
/// for entry in vault.list()? {
///     println!("{} — {} bytes, dir: {}", entry.name, entry.size, entry.is_directory);
/// }
///
/// // Restore later; returns where the data was written.
/// let where_ = vault.extract("report.pdf", Path::new("./out"))?;
///
/// // Rotate the password without touching encrypted data.
/// vault.change_password("correct horse battery staple", "new secret")?;
///
/// vault.lock();
/// # Ok::<(), krypton::Error>(())
/// ```
pub struct Vault {
    path: PathBuf,
    keystore: KeyStore,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("unlocked", &self.keystore.is_unlocked())
            .finish_non_exhaustive()
    }
}

/// One entry as returned by [`Vault::list`].
#[derive(Debug, Clone)]
pub struct EntryInfo {
    /// Full vault-relative path.
    pub name: String,
    /// Original size in bytes.
    pub size: u64,
    /// Directory placeholder or file.
    pub is_directory: bool,
}

/// Result of a full-integrity check.
#[derive(Debug, Default, Clone)]
pub struct IntegrityReport {
    /// Entries recorded in the manifest.
    pub total_entries: usize,
    /// Blobs that authenticated successfully.
    pub verified: usize,
    /// Manifest entries whose blob file is missing.
    pub missing: Vec<String>,
    /// Blobs present but failing authentication.
    pub corrupted: Vec<String>,
}

impl Vault {
    /// Creates an unattached handle for the vault at `path`.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            keystore: KeyStore::new(),
        }
    }

    /// Whether this path looks like an initialized vault.
    pub fn exists(&self) -> bool {
        self.config_path().exists()
    }

    /// The vault's base directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the master key is currently held in memory.
    pub fn is_unlocked(&self) -> bool {
        self.keystore.is_unlocked()
    }

    fn config_path(&self) -> PathBuf {
        self.path.join("vault.config")
    }

    fn load_config(&self) -> Result<VaultConfig> {
        let json = fs::read_to_string(self.config_path())?;
        VaultConfig::parse(&json)
    }

    /// Initializes a new vault protected by `password`.
    ///
    /// Fails if the vault already exists. Created directories get owner-only
    /// permissions on Unix; the config is written atomically.
    ///
    /// ```no_run
    /// let mut vault = krypton::Vault::new("secrets".into());
    /// vault.init("correct horse")?;
    /// # Ok::<(), krypton::Error>(())
    /// ```
    pub fn init(&mut self, password: &str) -> Result<()> {
        if self.exists() {
            return Err(Error::VaultExists);
        }

        crate::fsutil::create_private_dir(&self.path)?;
        crate::fsutil::create_private_dir(&self.path.join("d"))?;

        let config = self.keystore.init(password)?;

        let json = serde_json::to_string_pretty(&config).map_err(|_| Error::InvalidVault)?;
        crate::fsutil::atomic_write(&self.config_path(), json.as_bytes())?;

        manifest::save(&self.path, &ManifestMap::new(), self.keystore.master_key()?)?;
        Ok(())
    }

    /// Unlocks the vault with `password`.
    ///
    /// Authentication failure reports [`Error::Authentication`] without
    /// distinguishing wrong password from tampered config.
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        if !self.exists() {
            return Err(Error::VaultNotFound);
        }
        let config = self.load_config()?;
        self.keystore.unlock(password, &config)
    }

    /// Scrubs the master key from memory.
    pub fn lock(&mut self) {
        self.keystore.lock();
    }

    fn require_unlocked(&self) -> Result<Key> {
        Ok(self.keystore.master_key()?.clone())
    }

    /// Adds a file or directory tree to the vault.
    ///
    /// * `source` - filesystem path to add (symlinks inside trees are
    ///   skipped).
    /// * `name` - explicit vault name; defaults to the source basename. Must
    ///   not contain path separators or `..`.
    ///
    /// Adding a directory stores every child recursively; each child gets its
    /// own independently authenticated blob. An entry with the same name must
    /// not already exist (remove it first to replace). The manifest is
    /// committed last and atomically, so a crash can leave orphaned blobs but
    /// never a dangling index.
    ///
    /// ```no_run
    /// let mut vault = krypton::Vault::new("secrets".into());
    /// vault.unlock("correct horse")?;
    ///
    /// vault.add(std::path::Path::new("notes.txt"), None)?;
    /// vault.add(std::path::Path::new("~/docs"), Some("docs"))?; // whole tree
    /// # Ok::<(), krypton::Error>(())
    /// ```
    pub fn add(&mut self, source: &Path, name: Option<&str>) -> Result<()> {
        let master = self.require_unlocked()?;

        let source = source
            .canonicalize()
            .map_err(|_| Error::invalid_name(source.display()))?;
        if !source.is_file() && !source.is_dir() {
            return Err(Error::invalid_name(source.display()));
        }

        let root_name = match name {
            Some(n) => n.to_string(),
            None => source
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .ok_or_else(|| Error::invalid_name(source.display()))?,
        };
        sanitize::validate_new_name(&root_name)?;

        let mut all = manifest::load(&self.path, &master)?;
        if all.contains_key(&root_name) {
            return Err(Error::EntryExists(root_name));
        }

        // Phase 1: write every blob (index updated last, so a crash leaves at
        // worst invisible orphans).
        if source.is_dir() {
            add_directory_tree(&self.path, &master, &source, &root_name, &mut all)?;
        } else {
            let meta = EntryMetadata {
                original_name: root_name.clone(),
                original_size: fs::metadata(&source)?.len(),
                is_directory: false,
                children: None,
            };
            blobs::write_entry(&self.path, &master, &root_name, &meta, Some(&source))?;
            all.insert(root_name.clone(), meta);
        }

        // Phase 2: commit index atomically.
        manifest::save(&self.path, &all, &master)?;
        Ok(())
    }

    /// Removes an entry (and, for directories, its whole subtree).
    ///
    /// Both the ciphertext blobs and their manifest records are deleted.
    pub fn remove(&mut self, name: &str) -> Result<()> {
        let master = self.require_unlocked()?;
        sanitize::validate_new_name(name)?;

        let mut all = manifest::load(&self.path, &master)?;
        if !all.contains_key(name) {
            return Err(Error::EntryNotFound(preview(name)));
        }

        remove_subtree(&self.path, &master, name, &mut all);
        manifest::save(&self.path, &all, &master)?;
        Ok(())
    }

    /// Lists top-level entries. Children of directories are addressed by
    /// their full `parent/child` path in other operations.
    pub fn list(&self) -> Result<Vec<EntryInfo>> {
        let master = self.require_unlocked()?;
        let all = manifest::load(&self.path, &master)?;
        Ok(all
            .iter()
            .filter(|(k, _)| !k.contains('/'))
            .map(|(k, m)| EntryInfo {
                name: k.clone(),
                size: m.original_size,
                is_directory: m.is_directory,
            })
            .collect())
    }

    /// Extracts an entry.
    ///
    /// * Files are written to `dest` (temp file + rename).
    /// * Directories are recreated under `dest` with their full subtree.
    ///
    /// Returns the output location actually used. Child names recovered from
    /// the vault are sanitized before being joined onto `dest`; any traversal
    /// attempt aborts the operation.
    ///
    /// ```no_run
    /// let vault = krypton::Vault::new("secrets".into());
    /// let written = vault.extract("docs", std::path::Path::new("./restored"))?;
    /// println!("restored to {}", written.display());
    /// # Ok::<(), krypton::Error>(())
    /// ```
    pub fn extract(&self, name: &str, dest: &Path) -> Result<PathBuf> {
        let master = self.require_unlocked()?;

        let all = manifest::load(&self.path, &master)?;
        let meta = all
            .get(name)
            .ok_or_else(|| Error::EntryNotFound(preview(name)))?
            .clone();

        if !meta.is_directory {
            stream_blob_to_file(&self.path, &master, name, dest, false)?;
            return Ok(dest.to_path_buf());
        }

        crate::fsutil::create_private_dir(dest)?;
        let prefix = format!("{name}/");
        for (child_path, child_meta) in all.range(prefix.clone()..) {
            if !child_path.starts_with(&prefix) {
                break;
            }
            let rel = &child_path[prefix.len()..];
            if rel.is_empty() {
                continue;
            }
            let target = join_sanitized(dest, rel)?;
            if child_meta.is_directory {
                crate::fsutil::create_private_dir(&target)?;
            } else {
                stream_blob_to_file(&self.path, &master, child_path, &target, false)?;
            }
        }
        Ok(dest.to_path_buf())
    }

    /// Changes the vault password after verifying `old_password`.
    ///
    /// Only the wrapped master key is re-encrypted; stored data is untouched.
    /// Works regardless of lock state and leaves the lock state unchanged.
    ///
    /// ```no_run
    /// let mut vault = krypton::Vault::new("secrets".into());
    /// vault.change_password("old horse", "new horse")?;
    /// # Ok::<(), krypton::Error>(())
    /// ```
    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        let config = self.load_config()?;
        // Prove knowledge of the old password even if the vault was already
        // unlocked.
        config.unwrap_master_key(old_password)?;

        if !self.keystore.is_unlocked() {
            self.unlock(old_password)?;
        }

        let new_config = self.keystore.rotate_password(new_password)?;
        let json = serde_json::to_string_pretty(&new_config).map_err(|_| Error::InvalidVault)?;
        crate::fsutil::atomic_write(&self.config_path(), json.as_bytes())?;
        Ok(())
    }

    /// Verifies every entry's blob by fully decrypting it (authenticating
    /// all chunk tags), reporting missing or corrupted items.
    ///
    /// Restores the prior lock state when done.
    ///
    /// ```no_run
    /// let mut vault = krypton::Vault::new("secrets".into());
    /// let report = vault.verify("correct horse")?;
    /// if report.missing.is_empty() && report.corrupted.is_empty() {
    ///     println!("all {} entries authenticated", report.total_entries);
    /// } else {
    ///     eprintln!("missing: {:?}, corrupted: {:?}", report.missing, report.corrupted);
    /// }
    /// # Ok::<(), krypton::Error>(())
    /// ```
    pub fn verify(&mut self, password: &str) -> Result<IntegrityReport> {
        let was_unlocked = self.is_unlocked();
        if !was_unlocked {
            self.unlock(password)?;
        }
        let result = self.verify_unlocked();
        if !was_unlocked {
            self.lock();
        }
        result
    }

    fn verify_unlocked(&mut self) -> Result<IntegrityReport> {
        let master = self.require_unlocked()?;
        let all = manifest::load(&self.path, &master)?;

        let mut report = IntegrityReport {
            total_entries: all.len(),
            ..IntegrityReport::default()
        };

        for (name, meta) in all.iter() {
            match blobs::read_entry(&self.path, &master, name, meta.is_directory, |_| Ok(())) {
                Ok(_) => report.verified += 1,
                Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    report.missing.push(name.clone());
                }
                Err(_) => report.corrupted.push(name.clone()),
            }
        }

        Ok(report)
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.keystore.lock();
    }
}

/// Adds a directory tree: one blob per file plus directory placeholders,
/// with manifest child lists wired up for recursive removal.
fn add_directory_tree(
    vault_dir: &Path,
    master: &Key,
    source_root: &Path,
    vault_name: &str,
    all: &mut ManifestMap,
) -> Result<()> {
    use walkdir::WalkDir;

    // Insert the root placeholder first so children can register with it.
    all.insert(
        vault_name.to_string(),
        EntryMetadata {
            original_name: vault_name.to_string(),
            original_size: 0,
            is_directory: true,
            children: Some(Vec::new()),
        },
    );
    let mut dir_paths: Vec<String> = vec![vault_name.to_string()];

    let entries: Vec<_> = WalkDir::new(source_root)
        .sort_by_file_name()
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::invalid_name(source_root.display()))?;

    // WalkDir yields parents before children, so each entry's parent record
    // already exists here.
    for entry in entries {
        let ft = entry.file_type();
        if ft.is_symlink() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(source_root)
            .map_err(|_| Error::invalid_name(entry.path().display()))?
            .to_string_lossy()
            .to_string();
        if rel.is_empty() {
            continue;
        }
        sanitize::validate_new_name(&rel)?;

        let full = format!("{vault_name}/{rel}");
        let parent_full = full
            .rsplit_once('/')
            .map(|(p, _)| p.to_string())
            .ok_or(Error::InvalidVault)?;

        if ft.is_dir() {
            all.insert(
                full.clone(),
                EntryMetadata {
                    original_name: full.clone(),
                    original_size: 0,
                    is_directory: true,
                    children: Some(Vec::new()),
                },
            );
            dir_paths.push(full.clone());
        } else if ft.is_file() {
            let meta = EntryMetadata {
                original_name: full.clone(),
                original_size: entry.metadata().map(|m| m.len()).unwrap_or(0),
                is_directory: false,
                children: None,
            };
            blobs::write_entry(vault_dir, master, &full, &meta, Some(entry.path()))?;
            all.insert(full.clone(), meta);
        }

        if let Some(pmeta) = all.get_mut(&parent_full) {
            if let Some(children) = pmeta.children.as_mut() {
                children.push(full);
            }
        }
    }

    // Persist directory placeholder blobs (only the ones from this call).
    for dir_path in &dir_paths {
        if let Some(meta) = all.get(dir_path) {
            blobs::write_entry(vault_dir, master, dir_path, meta, None)?;
        }
    }
    Ok(())
}

/// Removes an entry subtree: blobs first, index records second.
fn remove_subtree(vault_dir: &Path, master: &Key, name: &str, all: &mut ManifestMap) {
    let mut stack = vec![name.to_string()];
    let mut doomed = Vec::new();
    while let Some(cur) = stack.pop() {
        if let Some(meta) = all.get(&cur) {
            if let Some(children) = &meta.children {
                stack.extend(children.iter().cloned());
            }
        }
        doomed.push(cur);
    }
    for cur in doomed {
        let _ = blobs::remove_blob(vault_dir, master, &cur);
        all.remove(&cur);
    }
}

/// Joins a stored relative name onto `base`, refusing traversal attempts.
fn join_sanitized(base: &Path, rel: &str) -> Result<PathBuf> {
    sanitize::sanitize_stored_name(rel)?;
    Ok(base.join(rel))
}

/// Streams one blob's plaintext through a temp file onto `target`.
fn stream_blob_to_file(
    vault_dir: &Path,
    master: &Key,
    entry_path: &str,
    target: &Path,
    is_directory: bool,
) -> Result<()> {
    let tmp = crate::fsutil::sibling_temp_path(target);

    let outcome = (|| -> Result<()> {
        {
            let f = fs::File::create(&tmp)?;
            crate::fsutil::restrict_perms(&tmp);
            let mut w = std::io::BufWriter::new(f);
            blobs::read_entry(vault_dir, master, entry_path, is_directory, |chunk| {
                w.write_all(chunk)?;
                Ok(())
            })?;
            w.flush()?;
            w.get_ref().sync_all()?;
        }
        #[cfg(windows)]
        if target.exists() {
            fs::remove_file(target)?;
        }
        fs::rename(&tmp, target)?;
        crate::fsutil::sync_dir(target.parent().unwrap_or_else(|| Path::new(".")));
        Ok(())
    })();

    match outcome {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn preview(name: &str) -> String {
    name.chars().take(64).collect()
}
