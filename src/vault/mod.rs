//! Multi-file encrypted vaults.
//!
//! # Layout
//!
//! ```text
//! vault/
//! |-- vault.config        encrypted master key + KDF parameters (v3 JSON)
//! |-- vault.lock          advisory inter-process lock (empty)
//! +-- d/
//!     |-- .manifest.enc   encrypted snapshot of the index
//!     |-- .index.log      encrypted append-only mutations after that snapshot
//!     +-- <hash>/<hash>.enc  per-entry ciphertext blobs
//! ```
//!
//! # Example
//!
//! ```no_run
//! use keres::Vault;
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

use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::sanitize;

pub(crate) mod file_ops;
pub(crate) mod index_log;
pub(crate) mod keystore;
pub(crate) mod lock;
pub(crate) mod manifest;
pub(crate) mod migrate;
pub(crate) mod recovery;
pub(crate) mod rotation;

pub use keystore::KeyslotInfo;
pub use migrate::MigrationReport;
pub use recovery::RecoveryCode;
pub use rotation::RotationReport;

use file_ops as blobs;
use keystore::{KeyStore, VaultConfig};
use lock::VaultLock;
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
/// use keres::Vault;
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
/// # Ok::<(), keres::Error>(())
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

/// One mutation in an explicit batch commit.
#[derive(Debug)]
pub enum BatchOp {
    /// Add a file or directory tree under `name` (defaults to source basename).
    Add {
        /// Filesystem source.
        source: PathBuf,
        /// Vault name; `None` uses the source basename.
        name: Option<String>,
    },
    /// Replace an existing file entry's contents.
    Replace {
        /// New file contents.
        source: PathBuf,
        /// Existing entry name.
        name: String,
    },
    /// Remove an entry (and its subtree).
    Remove {
        /// Entry name.
        name: String,
    },
}
///
/// Captures the authenticated snapshot generation and the number of mutation
/// records appended on top of it. Two calls that observe the same version saw
/// identical index state, so a conditional write can compare against a value
/// captured earlier to detect intervening mutations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexVersion {
    /// Authenticated snapshot generation.
    pub generation: u64,
    /// Number of mutation records appended on top of that snapshot.
    pub records: u64,
}

/// Outcome of a conditional write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The mutation was applied. Carries the new index version.
    Applied {
        /// Version after the mutation.
        version: IndexVersion,
    },
    /// The precondition did not hold; nothing was written.
    Conflict {
        /// Current index version the caller should retry against.
        current: IndexVersion,
    },
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

    /// Serializes and atomically replaces `vault.config`.
    fn write_config(&self, config: &VaultConfig) -> Result<()> {
        let json = serde_json::to_string_pretty(config).map_err(|_| Error::InvalidVault)?;
        crate::fsutil::atomic_write(&self.config_path(), json.as_bytes())
    }

    /// Initializes a new vault protected by `password`.
    ///
    /// Fails if the vault already exists. Created directories get owner-only
    /// permissions on Unix; the config is written atomically.
    ///
    /// ```no_run
    /// let mut vault = keres::Vault::new("secrets".into());
    /// vault.init("correct horse")?;
    /// # Ok::<(), keres::Error>(())
    /// ```
    pub fn init(&mut self, password: &str) -> Result<()> {
        self.init_with_padding(password, crate::padding::Padding::None)
    }

    /// Initializes a new vault with a custom size-padding policy.
    ///
    /// `padding` is applied to file entries added to the vault. It is stored
    /// inside the authenticated index, so it cannot be silently disabled by an
    /// attacker with storage access.
    pub fn init_with_padding(
        &mut self,
        password: &str,
        padding: crate::padding::Padding,
    ) -> Result<()> {
        padding.validate()?;
        if self.exists() {
            return Err(Error::VaultExists);
        }

        crate::fsutil::create_private_dir(&self.path)?;
        crate::fsutil::create_private_dir(&self.path.join("d"))?;

        // Re-check under the lock: another process may have initialized the
        // vault between the check above and this point.
        let _lock = self.lock_exclusive()?;
        if self.exists() {
            return Err(Error::VaultExists);
        }
        // A config-less vault with a recovery kit is recoverable with
        // `Vault::recover`; never clobber it by re-initializing.
        if self.path.join("vault.recovery").is_file() {
            return Err(Error::VaultExists);
        }
        // A config-less vault whose index still exists is not safe to
        // overwrite: `init` would destroy the (possibly still recoverable)
        // data, and the caller should recover or remove it explicitly.
        if self.path.join("d").join(".manifest.enc").is_file() {
            return Err(Error::VaultExists);
        }

        let config = self.keystore.init(password)?;
        // Write the index before the config. A crash in between leaves no
        // config, so `init` can be retried safely; the reverse order would
        // leave an initialized-looking vault whose index is missing.
        manifest::init(&self.path, self.keystore.master_key()?, padding)?;
        self.write_config(&config)?;
        Ok(())
    }

    /// Returns the vault's authenticated size-padding policy.
    pub fn padding(&self) -> Result<crate::padding::Padding> {
        let master = self.require_unlocked()?;
        let _lock = self.lock_shared()?;
        let (_files, padding) = manifest::load_with_padding(&self.path, &master)?;
        Ok(padding)
    }

    /// Returns the current authenticated index version.
    ///
    /// Useful as a precondition token for [`Vault::add_if`] /
    /// [`Vault::replace_if`].
    pub fn version(&self) -> Result<IndexVersion> {
        let master = self.require_unlocked()?;
        let _lock = self.lock_shared()?;
        let (generation, records) = manifest::current_version(&self.path, &master)?;
        Ok(IndexVersion {
            generation,
            records,
        })
    }

    /// Adds `source` only if `expected` matches the current index version.
    ///
    /// `expected = None` means "apply unconditionally" (still reports the
    /// resulting version). Returns [`WriteOutcome::Conflict`] when the vault
    /// changed since `expected` was captured, or when an entry named
    /// `root_name` already exists (if-none-match). Nothing is written on
    /// conflict.
    pub fn add_if(
        &mut self,
        source: &Path,
        name: Option<&str>,
        expected: Option<IndexVersion>,
    ) -> Result<WriteOutcome> {
        let master = self.require_unlocked()?;
        let _lock = self.lock_exclusive()?;

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
        sanitize::validate_root_name(&root_name)?;

        let (mut all, padding) = manifest::load_with_padding(&self.path, &master)?;
        let (gen, records) = manifest::current_version(&self.path, &master)?;
        let current = IndexVersion {
            generation: gen,
            records,
        };

        if let Some(exp) = expected {
            if exp != current {
                return Ok(WriteOutcome::Conflict { current });
            }
        }
        if all.contains_key(&root_name) {
            return Ok(WriteOutcome::Conflict { current });
        }

        if source.is_dir() {
            add_directory_tree(&self.path, &master, &source, &root_name, &mut all, padding)?;
        } else {
            let id = new_entry_id();
            let meta = EntryMetadata {
                id: id.clone(),
                original_name: root_name.clone(),
                original_size: 0,
                is_directory: false,
                children: None,
                content_hash: None,
            };
            let (_, hash, size) =
                blobs::write_entry(&self.path, &master, &id, &meta, Some(&source), padding)?;
            let meta = EntryMetadata {
                original_size: size,
                content_hash: Some(hash),
                ..meta
            };
            all.insert(root_name.clone(), meta);
        }

        manifest::save(&self.path, &all, &master, padding)?;
        let (gen2, records2) = manifest::current_version(&self.path, &master)?;
        Ok(WriteOutcome::Applied {
            version: IndexVersion {
                generation: gen2,
                records: records2,
            },
        })
    }

    /// Replaces an existing file entry only if `expected` matches the current
    /// index version.
    ///
    /// `expected = None` means unconditional. Returns
    /// [`WriteOutcome::Conflict`] when the vault changed or the entry does not
    /// exist.
    pub fn replace_if(
        &mut self,
        source: &Path,
        name: &str,
        expected: Option<IndexVersion>,
    ) -> Result<WriteOutcome> {
        let master = self.require_unlocked()?;
        let _lock = self.lock_exclusive()?;
        sanitize::validate_new_name(name)?;

        let source = source
            .canonicalize()
            .map_err(|_| Error::invalid_name(source.display()))?;
        if !source.is_file() {
            return Err(Error::invalid_name(source.display()));
        }

        let (mut all, padding) = manifest::load_with_padding(&self.path, &master)?;
        let (gen, records) = manifest::current_version(&self.path, &master)?;
        let current = IndexVersion {
            generation: gen,
            records,
        };

        if let Some(exp) = expected {
            if exp != current {
                return Ok(WriteOutcome::Conflict { current });
            }
        }

        let existing = match all.get(name) {
            Some(e) => e.clone(),
            None => return Ok(WriteOutcome::Conflict { current }),
        };
        if existing.is_directory {
            return Err(Error::Operation(
                "cannot replace a directory entry; remove it first".into(),
            ));
        }
        // Copy-on-write, as in `replace`.
        let old_id = existing.id.clone();
        let id = new_entry_id();

        let meta = EntryMetadata {
            id: id.clone(),
            original_name: name.to_string(),
            original_size: 0,
            is_directory: false,
            children: None,
            content_hash: None,
        };
        let (_, hash, size) =
            blobs::write_entry(&self.path, &master, &id, &meta, Some(&source), padding)?;
        let meta = EntryMetadata {
            original_size: size,
            content_hash: Some(hash),
            ..meta
        };
        all.insert(name.to_string(), meta);
        manifest::save(&self.path, &all, &master, padding)?;
        let _ = blobs::remove_blob(&self.path, &master, &old_id);
        let (gen2, records2) = manifest::current_version(&self.path, &master)?;
        Ok(WriteOutcome::Applied {
            version: IndexVersion {
                generation: gen2,
                records: records2,
            },
        })
    }

    /// Replaces the vault's size-padding policy.
    ///
    /// Existing blobs are not rewritten; the policy only affects future adds
    /// and replaces. The change is authenticated and advances the index
    /// generation.
    pub fn set_padding(&mut self, padding: crate::padding::Padding) -> Result<()> {
        padding.validate()?;
        let master = self.require_unlocked()?;
        let _lock = self.lock_exclusive()?;
        manifest::set_padding(&self.path, &master, padding)
    }

    /// Unlocks the vault with `password`.
    ///
    /// Authentication failure reports [`Error::Authentication`] without
    /// distinguishing wrong password from tampered config.
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        if !self.exists() {
            return Err(Error::VaultNotFound);
        }
        // A pending rotation or compaction is finished under the exclusive
        // lock before the config or index is read.
        let _lock = self.lock_shared()?;
        self.unlock_inner(password)
    }

    /// Unlocks without acquiring the advisory lock. Callers that already hold
    /// a vault lock must use this to avoid a self-conflict.
    fn unlock_inner(&mut self, password: &str) -> Result<()> {
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

    /// Takes the exclusive vault lock, finishing any interrupted journaled
    /// operation (rotation or index compaction) first.
    fn lock_exclusive(&self) -> Result<VaultLock> {
        let lock = VaultLock::exclusive(&self.path)?;
        rotation::recover(&self.path)?;
        index_log::recover(&self.path)?;
        Ok(lock)
    }

    /// Takes at least a shared vault lock.
    ///
    /// A pending rotation or compaction needs exclusive access to finish, so
    /// it is recovered under the exclusive lock before returning.
    fn lock_shared(&self) -> Result<VaultLock> {
        if rotation::pending(&self.path) || index_log::compaction_pending(&self.path) {
            return self.lock_exclusive();
        }
        VaultLock::shared(&self.path)
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
    /// let mut vault = keres::Vault::new("secrets".into());
    /// vault.unlock("correct horse")?;
    ///
    /// vault.add(std::path::Path::new("notes.txt"), None)?;
    /// vault.add(std::path::Path::new("~/docs"), Some("docs"))?; // whole tree
    /// # Ok::<(), keres::Error>(())
    /// ```
    pub fn add(&mut self, source: &Path, name: Option<&str>) -> Result<()> {
        let master = self.require_unlocked()?;
        let _lock = self.lock_exclusive()?;

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
        sanitize::validate_root_name(&root_name)?;

        let (mut all, padding) = manifest::load_with_padding(&self.path, &master)?;
        if all.contains_key(&root_name) {
            return Err(Error::EntryExists(root_name));
        }

        // Phase 1: write every blob (index updated last, so a crash leaves at
        // worst invisible orphans).
        if source.is_dir() {
            add_directory_tree(&self.path, &master, &source, &root_name, &mut all, padding)?;
        } else {
            let id = new_entry_id();
            let meta = EntryMetadata {
                id: id.clone(),
                original_name: root_name.clone(),
                original_size: 0,
                is_directory: false,
                children: None,
                content_hash: None,
            };
            let (_, hash, size) =
                blobs::write_entry(&self.path, &master, &id, &meta, Some(&source), padding)?;
            let meta = EntryMetadata {
                original_size: size,
                content_hash: Some(hash),
                ..meta
            };
            all.insert(root_name.clone(), meta);
        }

        // Phase 2: commit index atomically.
        manifest::save(&self.path, &all, &master, padding)?;
        Ok(())
    }

    /// Replaces the contents of an existing file entry.
    ///
    /// `source` must be a regular file and `name` must refer to a file entry
    /// (remove a directory tree first). The new blob is written before the
    /// manifest is committed, matching [`Vault::add`]: a crash can leave
    /// stale size metadata, but never a dangling index.
    ///
    /// ```no_run
    /// let mut vault = keres::Vault::new("secrets".into());
    /// vault.unlock("correct horse")?;
    /// vault.replace(std::path::Path::new("notes.txt"), "notes.txt")?;
    /// # Ok::<(), keres::Error>(())
    /// ```
    pub fn replace(&mut self, source: &Path, name: &str) -> Result<()> {
        let master = self.require_unlocked()?;
        let _lock = self.lock_exclusive()?;
        sanitize::validate_new_name(name)?;

        let source = source
            .canonicalize()
            .map_err(|_| Error::invalid_name(source.display()))?;
        if !source.is_file() {
            return Err(Error::invalid_name(source.display()));
        }

        let (mut all, padding) = manifest::load_with_padding(&self.path, &master)?;
        let existing = all
            .get(name)
            .ok_or_else(|| Error::EntryNotFound(preview(name)))?;
        if existing.is_directory {
            return Err(Error::Operation(
                "cannot replace a directory entry; remove it first".into(),
            ));
        }
        // Copy-on-write: the old blob stays untouched until the index commits.
        // A failed save therefore leaves the previous version fully readable.
        let old_id = existing.id.clone();
        let id = new_entry_id();

        let meta = EntryMetadata {
            id: id.clone(),
            original_name: name.to_string(),
            original_size: 0,
            is_directory: false,
            children: None,
            content_hash: None,
        };
        let (_, hash, size) =
            blobs::write_entry(&self.path, &master, &id, &meta, Some(&source), padding)?;
        let meta = EntryMetadata {
            original_size: size,
            content_hash: Some(hash),
            ..meta
        };
        all.insert(name.to_string(), meta);
        manifest::save(&self.path, &all, &master, padding)?;
        let _ = blobs::remove_blob(&self.path, &master, &old_id);
        Ok(())
    }

    /// Renames a top-level file or directory entry without re-encrypting it.
    ///
    /// Because blob locations and container AAD are derived from the entry's
    /// stable random ID, a rename only rewrites the (encrypted) manifest.
    /// Directory renames rewrite the child paths inside the subtree as well.
    ///
    /// ```no_run
    /// let mut vault = keres::Vault::new("secrets".into());
    /// vault.unlock("correct horse")?;
    /// vault.rename("notes.txt", "journal.txt")?;
    /// # Ok::<(), keres::Error>(())
    /// ```
    pub fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        let master = self.require_unlocked()?;
        let _lock = self.lock_exclusive()?;
        sanitize::validate_root_name(from)?;
        sanitize::validate_root_name(to)?;
        if from == to {
            return Ok(());
        }

        let (mut all, padding) = manifest::load_with_padding(&self.path, &master)?;
        let original = all
            .get(from)
            .cloned()
            .ok_or_else(|| Error::EntryNotFound(preview(from)))?;
        if all.contains_key(to) {
            return Err(Error::EntryExists(to.to_string()));
        }

        let old_prefix = format!("{from}/");
        let new_prefix = format!("{to}/");
        let mut moves = Vec::new();
        if original.is_directory {
            for (path, meta) in all.range(old_prefix.clone()..) {
                if !path.starts_with(&old_prefix) {
                    break;
                }
                moves.push((path.clone(), meta.clone()));
            }
        }
        moves.push((from.to_string(), original));

        // Pre-flight every destination so a collision in the moved subtree
        // cannot overwrite an unrelated entry halfway through the rewrite.
        let old_keys: std::collections::HashSet<&str> =
            moves.iter().map(|(path, _)| path.as_str()).collect();
        for (path, _) in &moves {
            let new_path = if path == from {
                to.to_string()
            } else {
                format!("{new_prefix}{}", &path[old_prefix.len()..])
            };
            if !old_keys.contains(new_path.as_str()) && all.contains_key(&new_path) {
                return Err(Error::EntryExists(new_path));
            }
        }

        // Remove every old key first so inserting new ones cannot collide with
        // a stale subtree entry.
        for (path, _) in &moves {
            all.remove(path);
        }

        for (path, mut meta) in moves {
            let new_path = if path == from {
                to.to_string()
            } else {
                format!("{new_prefix}{}", &path[old_prefix.len()..])
            };
            meta.original_name = new_path.clone();
            if let Some(children) = meta.children.as_mut() {
                for child in children.iter_mut() {
                    if let Some(suffix) = child.strip_prefix(&old_prefix) {
                        *child = format!("{new_prefix}{suffix}");
                    } else if child == from {
                        *child = to.to_string();
                    }
                }
            }
            all.insert(new_path, meta);
        }

        manifest::save(&self.path, &all, &master, padding)?;
        Ok(())
    }

    /// Removes an entry (and, for directories, its whole subtree).
    ///
    /// The index commit happens first; blobs are deleted only after it
    /// succeeds. A crash or I/O failure between the two leaves unreferenced
    /// blobs (reclaimable with [`Vault::prune_orphans`]), never an index that
    /// points at missing data.
    ///
    /// Copies of the blob made under the old master key remain decryptable by
    /// anyone holding that key; use [`Vault::erase`] to invalidate the old
    /// master going forward.
    pub fn remove(&mut self, name: &str) -> Result<()> {
        let master = self.require_unlocked()?;
        let _lock = self.lock_exclusive()?;
        sanitize::validate_new_name(name)?;

        let (mut all, padding) = manifest::load_with_padding(&self.path, &master)?;
        if !all.contains_key(name) {
            return Err(Error::EntryNotFound(preview(name)));
        }

        let removed_ids = remove_subtree(&mut all, name);
        manifest::save(&self.path, &all, &master, padding)?;
        for id in removed_ids {
            let _ = blobs::remove_blob(&self.path, &master, &id);
        }
        Ok(())
    }

    /// Removes an entry and re-encrypts every survivor under a fresh master
    /// key, so the old master key can no longer decrypt the vault.
    ///
    /// This is a single journaled rotation: the entry is omitted from the new
    /// index and every survivor is re-encrypted before the commit. If rotation
    /// fails, the old vault (including the entry) is left intact.
    ///
    /// Crypto-erasure is *forward-looking*. Anyone who already captured the
    /// deleted blob together with an old `vault.config` or the old master key
    /// can still decrypt that copy; `erase` prevents that key material from
    /// being used against the vault from now on. It is not retroactive
    /// revocation of leaked keys.
    ///
    /// The vault ends up locked under `new_password`; extra keyslots and any
    /// recovery kit are dropped, as with [`Vault::rotate`].
    pub fn erase(&mut self, name: &str, new_password: &str) -> Result<RotationReport> {
        let old_master = self.require_unlocked()?;
        let _lock = self.lock_exclusive()?;
        sanitize::validate_new_name(name)?;

        // Plan the removal without committing anything: rotation writes the
        // survivors under the new master and omits these names from the new
        // index, so a failure leaves the old vault untouched.
        let (all, _padding) = manifest::load_with_padding(&self.path, &old_master)?;
        if !all.contains_key(name) {
            return Err(Error::EntryNotFound(preview(name)));
        }
        let removed = collect_subtree_names(&all, name);

        let config = self.load_config()?;
        let discarded = config.slot_ids().len().saturating_sub(1);
        let new_master = Key::generate();
        let new_config = VaultConfig::new(&new_master, new_password)?;
        let report = rotation::run(
            &self.path,
            &old_master,
            &new_master,
            &new_config,
            discarded,
            &removed,
        )?;

        self.keystore.lock();
        Ok(report)
    }

    /// Lists top-level entries. Children of directories are addressed by
    /// their full `parent/child` path in other operations.
    pub fn list(&self) -> Result<Vec<EntryInfo>> {
        let master = self.require_unlocked()?;
        let _lock = self.lock_shared()?;
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
    /// let vault = keres::Vault::new("secrets".into());
    /// let written = vault.extract("docs", std::path::Path::new("./restored"))?;
    /// println!("restored to {}", written.display());
    /// # Ok::<(), keres::Error>(())
    /// ```
    pub fn extract(&self, name: &str, dest: &Path) -> Result<PathBuf> {
        let master = self.require_unlocked()?;
        let _lock = self.lock_shared()?;

        let all = manifest::load(&self.path, &master)?;
        let meta = all
            .get(name)
            .ok_or_else(|| Error::EntryNotFound(preview(name)))?
            .clone();

        if !meta.is_directory {
            stream_blob_to_file(&self.path, &master, &meta, dest)?;
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
                stream_blob_to_file(&self.path, &master, child_meta, &target)?;
            }
        }
        Ok(dest.to_path_buf())
    }

    /// Upgrades a vault written by 0.5.x (manifest v2) to the current format.
    ///
    /// Every entry is re-encrypted under a fresh stable ID and the v3 manifest
    /// is committed atomically. The password and master key are unchanged:
    /// this is a format upgrade, not key rotation. A failure before that
    /// commit leaves the legacy vault readable: either run migration again,
    /// or reclaim any unreferenced blobs with [`Vault::prune_orphans`].
    ///
    /// Fails with [`Error::Operation`] if the vault already uses the current
    /// format.
    ///
    /// ```no_run
    /// use keres::Vault;
    ///
    /// let mut vault = Vault::new("old-vault".into());
    /// let report = vault.migrate("correct horse")?;
    /// println!("migrated {} entries ({} bytes)", report.entries, report.bytes);
    /// # Ok::<(), keres::Error>(())
    /// ```
    pub fn migrate(&mut self, password: &str) -> Result<MigrationReport> {
        if !self.exists() {
            return Err(Error::VaultNotFound);
        }
        let _lock = self.lock_exclusive()?;
        let config = self.load_config()?;
        let master = config.unwrap_master_key(password)?;
        migrate::run(&self.path, &master)
    }

    /// Creates or replaces the vault's printable recovery kit.
    ///
    /// The master key is wrapped under a fresh 160-bit recovery code and
    /// written to `vault.recovery` beside `vault.config`; the printed code is
    /// returned and is **not** stored. Anyone holding both the vault directory
    /// and the code can unlock the vault, so keep the code offline and
    /// separate. The password is verified first.
    ///
    /// Creating a new kit invalidates the previous code.
    ///
    /// ```no_run
    /// use keres::Vault;
    ///
    /// let mut vault = Vault::new("secrets".into());
    /// let code = vault.create_recovery_kit("correct horse")?;
    /// println!("{}", code.expose()); // print once and store offline
    /// # Ok::<(), keres::Error>(())
    /// ```
    pub fn create_recovery_kit(&mut self, password: &str) -> Result<RecoveryCode> {
        if !self.exists() {
            return Err(Error::VaultNotFound);
        }
        let _lock = self.lock_exclusive()?;
        let config = self.load_config()?;
        let master = config.unwrap_master_key(password)?;
        recovery::create(&self.path, &master)
    }

    /// Whether this vault has a recovery kit on disk.
    pub fn has_recovery_kit(&self) -> bool {
        recovery::exists(&self.path)
    }

    /// Resets the vault password using a recovery code.
    ///
    /// Works even when `vault.config` is missing or corrupt, as long as the
    /// vault directory and `vault.recovery` survive. The recovered master key
    /// is verified against the existing index before anything is written; on
    /// success the config is re-wrapped under `new_password` and the recovery
    /// kit is consumed (deleted) so the code cannot be replayed. The vault is
    /// left locked. Recovery writes a fresh single-slot config: any additional
    /// keyslots are lost and must be re-added.
    ///
    /// ```no_run
    /// use keres::Vault;
    ///
    /// let mut vault = Vault::new("secrets".into());
    /// vault.recover("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX", "new password")?;
    /// vault.unlock("new password")?;
    /// # Ok::<(), keres::Error>(())
    /// ```
    pub fn recover(&mut self, recovery_code: &str, new_password: &str) -> Result<()> {
        if !self.path.is_dir() {
            return Err(Error::VaultNotFound);
        }
        let _lock = self.lock_exclusive()?;
        let master = recovery::unlock(&self.path, recovery_code)?;

        // Refuse to overwrite the config with a key that cannot read this
        // vault's index (for example a recovery file copied from another
        // vault). A legacy manifest authenticates but reports migration.
        match manifest::load(&self.path, &master) {
            Ok(_) | Err(Error::MigrationRequired) => {}
            Err(_) => {
                return Err(Error::Operation(
                    "recovery kit does not unlock this vault's index".into(),
                ))
            }
        }

        let config = VaultConfig::new(&master, new_password)?;
        self.write_config(&config)?;
        // The vault is recovered even if the kit cannot be deleted; keep it
        // usable and report the cleanup failure so the caller knows the code
        // is still valid.
        if let Err(e) = recovery::remove(&self.path) {
            self.keystore.lock();
            return Err(Error::Operation(format!(
                "vault recovered, but the recovery kit could not be deleted; \
                 remove {} manually: {e}",
                self.path.join("vault.recovery").display()
            )));
        }
        self.keystore.lock();
        Ok(())
    }

    /// Lists the vault's keyslots.
    ///
    /// Slot ids and count are stored in plaintext in `vault.config`, so this
    /// needs no password. Secret material is never exposed.
    ///
    /// ```no_run
    /// let vault = keres::Vault::new("secrets".into());
    /// for slot in vault.keyslots()? {
    ///     println!("{}", slot.id);
    /// }
    /// # Ok::<(), keres::Error>(())
    /// ```
    pub fn keyslots(&self) -> Result<Vec<KeyslotInfo>> {
        if !self.exists() {
            return Err(Error::VaultNotFound);
        }
        let _lock = self.lock_shared()?;
        Ok(self.load_config()?.slot_ids())
    }

    /// Adds a keyslot: a new passphrase that unlocks the same master key.
    ///
    /// `existing_password` must unlock the vault (any slot works) and
    /// `new_password` becomes an independent slot. The master key and stored
    /// data are unchanged. A legacy single-password config is upgraded to the
    /// current slot format without changing the existing passphrase.
    ///
    /// ```no_run
    /// let mut vault = keres::Vault::new("secrets".into());
    /// let slot = vault.add_keyslot("current pass", "laptop pass")?;
    /// println!("added keyslot {}", slot.id);
    /// # Ok::<(), keres::Error>(())
    /// ```
    pub fn add_keyslot(
        &mut self,
        existing_password: &str,
        new_password: &str,
    ) -> Result<KeyslotInfo> {
        if !self.exists() {
            return Err(Error::VaultNotFound);
        }
        if existing_password == new_password {
            return Err(Error::Operation(
                "new passphrase must differ from the authorizing passphrase".into(),
            ));
        }
        let _lock = self.lock_exclusive()?;
        let config = self.load_config()?;
        let (master, _) = config.unlock(existing_password)?;
        let (new_config, info) = config.add_slot(&master, existing_password, new_password)?;
        self.write_config(&new_config)?;
        Ok(info)
    }

    /// Removes a keyslot, revoking its passphrase.
    ///
    /// `password` must unlock a slot that will remain, so a typo can never
    /// delete the only working credential. The last keyslot cannot be removed.
    /// Stored data is untouched.
    ///
    /// ```no_run
    /// let mut vault = keres::Vault::new("secrets".into());
    /// vault.remove_keyslot("0123456789abcdef", "remaining pass")?;
    /// # Ok::<(), keres::Error>(())
    /// ```
    pub fn remove_keyslot(&mut self, slot_id: &str, password: &str) -> Result<()> {
        if !self.exists() {
            return Err(Error::VaultNotFound);
        }
        let _lock = self.lock_exclusive()?;
        let config = self.load_config()?;
        let (_, authorizing) = config.unlock(password)?;
        let target = config
            .slot_index(slot_id)
            .ok_or_else(|| Error::Operation(format!("no keyslot with id {slot_id:?}")))?;
        if target == authorizing {
            return Err(Error::Operation(
                "authorize removal with a passphrase from a keyslot that will remain".into(),
            ));
        }
        let new_config = config.remove_slot(target)?;
        self.write_config(&new_config)?;
        Ok(())
    }

    /// Changes the password of the keyslot that `old_password` unlocks.
    ///
    /// Only that slot's wrapped copy of the master key is re-encrypted; other
    /// keyslots and all stored data are untouched. A legacy config is rewritten
    /// in the current slot format. Works regardless of lock state and leaves
    /// the lock state unchanged.
    ///
    /// ```no_run
    /// let mut vault = keres::Vault::new("secrets".into());
    /// vault.change_password("old horse", "new horse")?;
    /// # Ok::<(), keres::Error>(())
    /// ```
    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        if !self.exists() {
            return Err(Error::VaultNotFound);
        }
        let _lock = self.lock_exclusive()?;
        let config = self.load_config()?;
        let (master, index) = config.unlock(old_password)?;
        let new_config = config.rewrap_slot(index, &master, new_password)?;
        self.write_config(&new_config)?;
        Ok(())
    }

    /// Re-encrypts every entry under a fresh master key (deep rotation).
    ///
    /// Unlike [`Vault::change_password`], this changes the data key itself:
    /// every blob is streamed through re-encryption and the manifest is
    /// rewritten under the new master. The vault ends up locked.
    ///
    /// The new config has exactly one keyslot under `new_password`. Every
    /// other keyslot wraps the old master and cannot survive, so those
    /// passphrases stop working. Any recovery kit is also removed (create a
    /// new one afterwards). The returned [`RotationReport`] records how many
    /// keyslots and bytes were affected.
    ///
    /// Rotation is crash-safe: a journal written before the manifest swap lets
    /// the next unlock finish an interrupted run. If the process dies before
    /// the journal is committed, the old vault is untouched and staged blobs
    /// are reclaimable with [`Vault::prune_orphans`].
    ///
    /// ```no_run
    /// let mut vault = keres::Vault::new("secrets".into());
    /// let report = vault.rotate("old pass", "new pass")?;
    /// println!("re-encrypted {} entries", report.entries);
    /// # Ok::<(), keres::Error>(())
    /// ```
    pub fn rotate(&mut self, old_password: &str, new_password: &str) -> Result<RotationReport> {
        if !self.exists() {
            return Err(Error::VaultNotFound);
        }
        let _lock = self.lock_exclusive()?;
        let config = self.load_config()?;
        let (old_master, _) = config.unlock(old_password)?;
        let discarded_keyslots = config.slot_ids().len().saturating_sub(1);

        let new_master = Key::generate();
        let new_config = VaultConfig::new(&new_master, new_password)?;
        let report = rotation::run(
            &self.path,
            &old_master,
            &new_master,
            &new_config,
            discarded_keyslots,
            &std::collections::HashSet::new(),
        )?;

        // The in-memory key is stale by construction.
        self.keystore.lock();
        Ok(report)
    }

    /// Applies a batch of mutations in a single commit.
    ///
    /// Adds and replaces write fresh blob IDs, and removes only drop index
    /// records, so nothing the current index references is touched until the
    /// single commit succeeds. If any operation fails, the index is unchanged
    /// and freshly written blobs are orphans reclaimable with
    /// [`Vault::prune_orphans`]. Old blobs are deleted only after the commit.
    pub fn apply_batch(&mut self, ops: &[BatchOp]) -> Result<()> {
        let master = self.require_unlocked()?;
        let _lock = self.lock_exclusive()?;

        let (mut all, padding) = manifest::load_with_padding(&self.path, &master)?;
        let original_ids: std::collections::HashSet<String> =
            all.values().map(|meta| meta.id.clone()).collect();
        let mut written_ids = std::collections::HashSet::new();

        for op in ops {
            match op {
                BatchOp::Add { source, name } => {
                    let source = source
                        .canonicalize()
                        .map_err(|_| Error::invalid_name(source.display()))?;
                    if !source.is_file() && !source.is_dir() {
                        return Err(Error::invalid_name(source.display()));
                    }
                    let root_name = match name {
                        Some(n) => n.clone(),
                        None => source
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .ok_or_else(|| Error::invalid_name(source.display()))?,
                    };
                    sanitize::validate_root_name(&root_name)?;
                    if all.contains_key(&root_name) {
                        return Err(Error::EntryExists(root_name));
                    }
                    if source.is_dir() {
                        let created = add_directory_tree(
                            &self.path, &master, &source, &root_name, &mut all, padding,
                        )?;
                        written_ids.extend(created);
                    } else {
                        let id = new_entry_id();
                        let meta = EntryMetadata {
                            id: id.clone(),
                            original_name: root_name.clone(),
                            original_size: 0,
                            is_directory: false,
                            children: None,
                            content_hash: None,
                        };
                        let (_, hash, size) = blobs::write_entry(
                            &self.path,
                            &master,
                            &id,
                            &meta,
                            Some(&source),
                            padding,
                        )?;
                        written_ids.insert(id);
                        all.insert(
                            root_name,
                            EntryMetadata {
                                original_size: size,
                                content_hash: Some(hash),
                                ..meta
                            },
                        );
                    }
                }
                BatchOp::Replace { source, name } => {
                    sanitize::validate_new_name(name)?;
                    let source = source
                        .canonicalize()
                        .map_err(|_| Error::invalid_name(source.display()))?;
                    if !source.is_file() {
                        return Err(Error::invalid_name(source.display()));
                    }
                    let existing = all
                        .get(name)
                        .ok_or_else(|| Error::EntryNotFound(preview(name)))?
                        .clone();
                    if existing.is_directory {
                        return Err(Error::Operation(
                            "cannot replace a directory entry; remove it first".into(),
                        ));
                    }
                    // Copy-on-write: the old blob is untouched until commit.
                    let id = new_entry_id();
                    let meta = EntryMetadata {
                        id: id.clone(),
                        original_name: name.clone(),
                        original_size: 0,
                        is_directory: false,
                        children: None,
                        content_hash: None,
                    };
                    let (_, hash, size) = blobs::write_entry(
                        &self.path,
                        &master,
                        &id,
                        &meta,
                        Some(&source),
                        padding,
                    )?;
                    written_ids.insert(id);
                    all.insert(
                        name.clone(),
                        EntryMetadata {
                            original_size: size,
                            content_hash: Some(hash),
                            ..meta
                        },
                    );
                }
                BatchOp::Remove { name } => {
                    sanitize::validate_new_name(name)?;
                    if !all.contains_key(name) {
                        return Err(Error::EntryNotFound(preview(name)));
                    }
                    // Only drop index records here; blobs go after the commit.
                    let _ = remove_subtree(&mut all, name);
                }
            }
        }

        manifest::save(&self.path, &all, &master, padding)?;

        // The commit is durable; reclaim blobs the new index no longer
        // references (old versions from replaces and removed subtrees).
        let final_ids: std::collections::HashSet<String> =
            all.values().map(|meta| meta.id.clone()).collect();
        for id in original_ids.into_iter().chain(written_ids) {
            if !final_ids.contains(&id) {
                let _ = blobs::remove_blob(&self.path, &master, &id);
            }
        }
        Ok(())
    }

    /// Verifies every entry's blobs (size, trailer, and all chunk tags),
    /// reporting missing or corrupted items.
    ///
    /// Restores the prior lock state when done.
    ///
    /// ```no_run
    /// let mut vault = keres::Vault::new("secrets".into());
    /// let report = vault.verify("correct horse")?;
    /// if report.missing.is_empty() && report.corrupted.is_empty() {
    ///     println!("all {} entries authenticated", report.total_entries);
    /// } else {
    ///     eprintln!("missing: {:?}, corrupted: {:?}", report.missing, report.corrupted);
    /// }
    /// # Ok::<(), keres::Error>(())
    /// ```
    pub fn verify(&mut self, password: &str) -> Result<IntegrityReport> {
        if !self.exists() {
            return Err(Error::VaultNotFound);
        }
        let _lock = self.lock_shared()?;
        self.verify_with_lock(password)
    }

    /// Verifies with the caller already holding a vault lock.
    fn verify_with_lock(&mut self, password: &str) -> Result<IntegrityReport> {
        let was_unlocked = self.is_unlocked();
        if !was_unlocked {
            self.unlock_inner(password)?;
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
            // `read_entry_checked` verifies the trailer size and the
            // authenticated content hash in addition to every chunk tag, so a
            // substituted older blob is reported as corrupted.
            match blobs::read_entry_checked(&self.path, &master, meta, |_| Ok(())) {
                Ok(_) => report.verified += 1,
                Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    report.missing.push(name.clone());
                }
                Err(_) => report.corrupted.push(name.clone()),
            }
        }

        Ok(report)
    }

    /// Deletes blobs that no manifest record references.
    ///
    /// Failed or interrupted adds can leave ciphertext behind that the
    /// manifest never mentions. They are harmless but waste space. Pruning
    /// requires an unlocked vault and takes the exclusive lock. Only files
    /// ending in `.enc` (other than `.manifest.enc`) and leftover `.tmp-*`
    /// files under `d/` are candidates, so unrelated files are never touched.
    ///
    /// Refuses to run when the manifest is missing: treating that as an empty
    /// index would delete every blob.
    pub fn prune_orphans(&mut self) -> Result<usize> {
        let master = self.require_unlocked()?;
        let _lock = self.lock_exclusive()?;

        let data_dir = self.path.join("d");
        let manifest_file = data_dir.join(".manifest.enc");
        if !manifest_file.is_file() {
            return Err(Error::InvalidVault);
        }

        let all = manifest::load(&self.path, &master)?;
        let referenced: std::collections::HashSet<PathBuf> = all
            .values()
            .map(|meta| blobs::blob_path(&self.path, &master, &meta.id))
            .collect();

        let mut removed = 0usize;
        for entry in walkdir::WalkDir::new(&data_dir).min_depth(1) {
            let entry = entry.map_err(|_| Error::InvalidVault)?;
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if path == manifest_file.as_path() || referenced.contains(path) {
                continue;
            }
            let name = entry.file_name().to_string_lossy();
            if !name.ends_with(".enc") && !name.contains(".tmp-") {
                continue;
            }
            fs::remove_file(path)?;
            removed += 1;
        }

        // Drop shard directories that pruning emptied. Best-effort: a
        // non-empty directory is simply left in place.
        if let Ok(shards) = fs::read_dir(&data_dir) {
            for shard in shards.flatten() {
                if shard.path().is_dir() {
                    let _ = fs::remove_dir(shard.path());
                }
            }
        }

        Ok(removed)
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.keystore.lock();
    }
}

/// Adds a directory tree: one blob per file plus directory placeholders,
/// with manifest child lists wired up for recursive removal.
///
/// Returns the entry IDs created by this call so a batch can reclaim them if a
/// later operation fails.
fn add_directory_tree(
    vault_dir: &Path,
    master: &Key,
    source_root: &Path,
    vault_name: &str,
    all: &mut ManifestMap,
    padding: crate::padding::Padding,
) -> Result<Vec<String>> {
    use walkdir::WalkDir;

    let entries: Vec<_> = WalkDir::new(source_root)
        .sort_by_file_name()
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::invalid_name(source_root.display()))?;

    // Pre-flight every destination before writing a blob. A collision deep in
    // the tree must fail the whole add rather than silently overwrite an
    // existing entry or leave half a tree behind.
    let mut planned = Vec::with_capacity(entries.len());
    let mut seen = std::collections::HashSet::new();
    seen.insert(vault_name.to_string());
    for entry in &entries {
        let ft = entry.file_type();
        if ft.is_symlink() || (!ft.is_dir() && !ft.is_file()) {
            continue;
        }
        let rel = relative_entry_name(entry.path(), source_root)?;
        if rel.is_empty() {
            continue;
        }
        sanitize::validate_new_name(&rel)?;
        let full = format!("{vault_name}/{rel}");
        if all.contains_key(&full) || !seen.insert(full.clone()) {
            return Err(Error::EntryExists(full));
        }
        planned.push((
            full,
            ft.is_dir(),
            ft.is_file().then(|| entry.path().to_path_buf()),
        ));
    }

    let mut created = Vec::new();

    // Insert the root placeholder first so children can register with it.
    let root_id = new_entry_id();
    created.push(root_id.clone());
    all.insert(
        vault_name.to_string(),
        EntryMetadata {
            id: root_id,
            original_name: vault_name.to_string(),
            original_size: 0,
            is_directory: true,
            children: Some(Vec::new()),
            content_hash: None,
        },
    );
    let mut dir_paths: Vec<String> = vec![vault_name.to_string()];

    // WalkDir yields parents before children, so each entry's parent record
    // already exists here.
    for (full, is_dir, source) in planned {
        let parent_full = full
            .rsplit_once('/')
            .map(|(p, _)| p.to_string())
            .ok_or(Error::InvalidVault)?;

        if is_dir {
            let id = new_entry_id();
            created.push(id.clone());
            all.insert(
                full.clone(),
                EntryMetadata {
                    id,
                    original_name: full.clone(),
                    original_size: 0,
                    is_directory: true,
                    children: Some(Vec::new()),
                    content_hash: None,
                },
            );
            dir_paths.push(full.clone());
        } else if let Some(source) = source {
            let id = new_entry_id();
            let meta = EntryMetadata {
                id: id.clone(),
                original_name: full.clone(),
                original_size: 0,
                is_directory: false,
                children: None,
                content_hash: None,
            };
            let (_, hash, size) =
                blobs::write_entry(vault_dir, master, &id, &meta, Some(&source), padding)?;
            created.push(id);
            all.insert(
                full.clone(),
                EntryMetadata {
                    original_size: size,
                    content_hash: Some(hash),
                    ..meta
                },
            );
        }

        if let Some(pmeta) = all.get_mut(&parent_full) {
            if let Some(children) = pmeta.children.as_mut() {
                children.push(full);
            }
        }
    }

    // Persist directory placeholder blobs (only the ones from this call) and
    // record their content hashes.
    for dir_path in &dir_paths {
        let meta = all.get(dir_path).cloned().ok_or(Error::InvalidVault)?;
        let (_, hash, _) = blobs::write_entry(
            vault_dir,
            master,
            &meta.id,
            &meta,
            None,
            crate::padding::Padding::None,
        )?;
        if let Some(stored) = all.get_mut(dir_path) {
            stored.content_hash = Some(hash);
        }
    }
    Ok(created)
}

/// Builds the vault-relative name for an entry below `root`, always using
/// `/` as the separator.
///
/// `Path::to_string_lossy` would use the platform separator, producing
/// backslashes on Windows; manifest names are `/`-separated everywhere and
/// [`sanitize::validate_new_name`] rejects `\` as a separator.
fn relative_entry_name(path: &Path, root: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| Error::invalid_name(path.display()))?;
    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            std::path::Component::Normal(part) => parts.push(part.to_string_lossy()),
            _ => return Err(Error::invalid_name(path.display())),
        }
    }
    Ok(parts.join("/"))
}

/// Collects the names in an entry's subtree.
///
/// Child lists are authoritative, but a directory also seeds the scan from its
/// `/`-prefixed range so a stale child list cannot strand descendants. A
/// visited set makes a cyclic (malicious) index terminate.
fn subtree_names(all: &ManifestMap, name: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![name.to_string()];
    if all.get(name).is_some_and(|meta| meta.is_directory) {
        let prefix = format!("{name}/");
        for (path, _) in all.range(prefix.clone()..) {
            if !path.starts_with(&prefix) {
                break;
            }
            stack.push(path.clone());
        }
    }
    while let Some(cur) = stack.pop() {
        if !seen.insert(cur.clone()) {
            continue;
        }
        if let Some(meta) = all.get(&cur) {
            if let Some(children) = &meta.children {
                stack.extend(children.iter().cloned());
            }
        }
    }
    seen.into_iter().collect()
}

/// Removes an entry subtree from the in-memory index.
///
/// Returns the removed entry IDs; blobs are deleted by the caller only after
/// the index commit succeeds.
fn remove_subtree(all: &mut ManifestMap, name: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for entry_name in subtree_names(all, name) {
        if let Some(meta) = all.remove(&entry_name) {
            ids.push(meta.id);
        }
    }
    ids
}

/// Names in an entry's subtree, for operations (such as `erase`) that must
/// omit them from a new index without mutating the current one.
fn collect_subtree_names(all: &ManifestMap, name: &str) -> std::collections::HashSet<String> {
    subtree_names(all, name).into_iter().collect()
}

/// Joins a stored relative name onto `base`, refusing traversal attempts.
fn join_sanitized(base: &Path, rel: &str) -> Result<PathBuf> {
    sanitize::sanitize_stored_name(rel)?;
    Ok(base.join(rel))
}

/// Streams one blob's plaintext through a temp file onto `target`.
///
/// Uses [`blobs::read_entry_checked`], so extraction fails (and the temp file
/// is removed) if the blob's size or content hash does not match the index.
fn stream_blob_to_file(
    vault_dir: &Path,
    master: &Key,
    meta: &EntryMetadata,
    target: &Path,
) -> Result<()> {
    let tmp = crate::fsutil::sibling_temp_path(target);

    let outcome = (|| -> Result<()> {
        {
            let f = crate::fsutil::create_private_file(&tmp)?;
            let mut w = std::io::BufWriter::new(f);
            blobs::read_entry_checked(vault_dir, master, meta, |chunk| {
                w.write_all(chunk)?;
                Ok(())
            })?;
            w.flush()?;
            w.get_ref().sync_all()?;
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

/// Generates a 128-bit random entry identifier, hex-encoded.
fn new_entry_id() -> String {
    let mut bytes = [0u8; 16];
    crypto::fill_random(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_entry_names_use_forward_slashes() {
        let root = Path::new("root");
        let nested = root.join("sub").join("file.txt");
        assert_eq!(
            relative_entry_name(&nested, root).unwrap(),
            "sub/file.txt",
            "manifest names must use '/' on every platform"
        );
    }

    #[test]
    fn directory_tree_preflight_rejects_nested_collisions_before_writing() {
        let tmp = tempfile::tempdir().unwrap();
        let vault_dir = tmp.path().join("vault");
        std::fs::create_dir_all(vault_dir.join("d")).unwrap();
        let master = Key::generate();

        let source = tmp.path().join("tree");
        std::fs::create_dir_all(source.join("sub")).unwrap();
        std::fs::write(source.join("sub").join("file.txt"), b"payload").unwrap();

        // A stale nested entry that the new tree would overwrite.
        let mut all = ManifestMap::new();
        all.insert(
            "tree/sub/file.txt".to_string(),
            EntryMetadata {
                id: "stale".into(),
                original_name: "tree/sub/file.txt".into(),
                original_size: 1,
                is_directory: false,
                children: None,
                content_hash: None,
            },
        );

        let err = add_directory_tree(
            &vault_dir,
            &master,
            &source,
            "tree",
            &mut all,
            crate::padding::Padding::None,
        )
        .unwrap_err();
        assert!(matches!(err, Error::EntryExists(_)));

        // No blobs were written and the index was not mutated.
        assert!(std::fs::read_dir(vault_dir.join("d"))
            .unwrap()
            .next()
            .is_none());
        assert_eq!(all.len(), 1);
        assert!(all.contains_key("tree/sub/file.txt"));
    }

    #[test]
    fn shared_reads_recover_a_committed_compaction() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = Vault::new(tmp.path().join("vault"));
        vault.init("pw").unwrap();
        let src = tmp.path().join("a.txt");
        std::fs::write(&src, b"payload").unwrap();
        vault.add(&src, None).unwrap();

        let data = vault.path().join("d");
        let snapshot = std::fs::read(data.join(".manifest.enc")).unwrap();
        let log = std::fs::read(data.join(".index.log")).unwrap();
        let mut generation = [0u8; 8];
        generation.copy_from_slice(&log[10..18]);

        // Simulate a compaction that committed its journal but died before
        // promoting the staged pair.
        crate::fsutil::atomic_write(&data.join(".index.snapshot.next"), &snapshot).unwrap();
        crate::fsutil::atomic_write(&data.join(".index.log.next"), &log).unwrap();
        let journal = serde_json::json!({
            "version": 1,
            "generation": u64::from_le_bytes(generation),
            "snapshot_sha256": index_log::digest(&snapshot),
        });
        crate::fsutil::atomic_write(
            &data.join(".index.compact"),
            &serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();

        // `list` only needs a shared lock, but it must finish the compaction.
        let names: Vec<_> = vault
            .list()
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(names, vec!["a.txt"]);
        assert!(!data.join(".index.compact").exists());
        assert!(!data.join(".index.snapshot.next").exists());
    }
}
