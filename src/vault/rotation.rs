//! Opt-in deep rotation: re-encrypt every entry under a fresh master key.
//!
//! This is distinct from [`crate::Vault::change_password`], which only
//! re-wraps the existing master key. Rotation generates a new master, streams
//! every blob through re-encryption, and rewrites the index under the new key.
//! It is slow by design and is the only operation that changes the data key.
//!
//! # Crash safety
//!
//! Rotation follows the same rule as every other mutation: new data first,
//! commit last. It additionally writes a small `vault.rotate` journal before
//! the manifest swap. The journal records the new (wrapped) config and the
//! SHA-256 of the staged manifest — never a plaintext key. If the process
//! dies after the journal is written, [`recover`] finishes the prepare/swap
//! sequence on the next unlock; if it dies before, the old vault is untouched
//! and the staged blobs are ordinary orphans for `prune_orphans`.
//!
//! # Credentials
//!
//! Rotation produces a fresh single-slot config under the caller's new
//! password. Extra keyslots and any existing recovery kit wrap the old master
//! key and cannot survive, so they are invalidated (the kit file is removed).

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::Key;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::padding::Padding;
use crate::vault::index_log;
use crate::vault::keystore::VaultConfig;
use crate::vault::manifest::{self, EntryMetadata, ManifestMap};
use crate::vault::recovery;

use super::file_ops as blobs;

/// Journal file written before the manifest swap.
const JOURNAL_FILE: &str = "vault.rotate";
/// Journal schema version.
const JOURNAL_VERSION: u32 = 1;

/// Outcome of a successful deep rotation.
#[derive(Debug, Default, Clone)]
pub struct RotationReport {
    /// Entries rewritten under the new master key.
    pub entries: usize,
    /// Plaintext bytes re-encrypted for file entries.
    pub bytes: u64,
    /// Keyslots dropped because they wrapped the old master key.
    pub discarded_keyslots: usize,
    /// Whether a recovery kit wrapping the old master key was removed.
    pub recovery_kit_removed: bool,
}

#[derive(Serialize, Deserialize)]
struct Journal {
    version: u32,
    manifest_sha256: String,
    config: String,
    /// Vault-relative paths of blobs encrypted under the old master. Recovery
    /// deletes them after the swap so an interrupted rotation cannot leave
    /// old-key ciphertext behind.
    #[serde(default)]
    old_blobs: Vec<String>,
}

/// Whether an interrupted rotation left a journal behind.
pub(crate) fn pending(vault_dir: &Path) -> bool {
    journal_path(vault_dir).is_file()
}

/// Re-encrypts every manifest entry from `old_master` to `new_master`.
///
/// The caller holds the exclusive vault lock and has already unwrapped
/// `old_master` and built a single-slot `new_config` around `new_master`.
/// `discarded_keyslots` is the number of old slots that cannot survive.
/// Names in `removed` are omitted from the new index (used by
/// [`crate::Vault::erase`] to make removal and rotation a single commit).
pub(crate) fn run(
    vault_dir: &Path,
    old_master: &Key,
    new_master: &Key,
    new_config: &VaultConfig,
    discarded_keyslots: usize,
    removed: &HashSet<String>,
) -> Result<RotationReport> {
    let (old_files, padding) = manifest::load_with_padding(vault_dir, old_master)?;

    let mut new_files = ManifestMap::new();
    let mut report = RotationReport {
        discarded_keyslots,
        ..RotationReport::default()
    };

    for (vault_path, old) in &old_files {
        if removed.contains(vault_path) {
            continue;
        }
        let mut meta = old.clone();
        if old.is_directory {
            // Authenticate the placeholder before replacing it.
            blobs::read_entry_checked(vault_dir, old_master, old, |_| Ok(()))?;
            let (_, hash, _) = blobs::write_entry_from_reader(
                vault_dir,
                new_master,
                &old.id,
                &meta,
                None,
                Padding::None,
                None,
            )?;
            meta.original_size = 0;
            meta.content_hash = Some(hash);
        } else {
            let (size, hash) =
                copy_file(vault_dir, old_master, new_master, &old.id, &meta, padding)?;
            meta.original_size = size;
            meta.content_hash = Some(hash);
            report.bytes += size;
        }
        report.entries += 1;
        new_files.insert(vault_path.clone(), meta);
    }

    let manifest_blob = manifest::encode(&new_files, new_master, 1, padding)?;
    let digest = sha256_hex(&manifest_blob);
    fsutil::atomic_write(&next_manifest_path(vault_dir), &manifest_blob)?;

    let config_json = serde_json::to_string_pretty(new_config).map_err(|_| Error::InvalidVault)?;
    let old_blobs = old_files
        .values()
        .map(|old| {
            let path = blobs::blob_path(vault_dir, old_master, &old.id);
            path.strip_prefix(vault_dir)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string()
        })
        .collect();
    let journal = Journal {
        version: JOURNAL_VERSION,
        manifest_sha256: digest,
        config: config_json.clone(),
        old_blobs,
    };
    let journal_json = serde_json::to_vec(&journal).map_err(|_| Error::InvalidVault)?;

    // Commit point. From here on, recovery can finish the swap without the
    // old master (and therefore without the old password).
    fsutil::atomic_write(&journal_path(vault_dir), &journal_json)?;

    std::fs::rename(next_manifest_path(vault_dir), manifest::path(vault_dir))?;
    fsutil::sync_dir(&vault_dir.join("d"));

    fsutil::atomic_write(&vault_dir.join("vault.config"), config_json.as_bytes())?;
    report.recovery_kit_removed = recovery::exists(vault_dir);
    recovery::remove(vault_dir)?;

    // The index log was encrypted under the old master and extends the old
    // snapshot; the new snapshot replaces both.
    index_log::remove_all(vault_dir)?;

    // Old blobs are unreachable under the new master. Best-effort cleanup; the
    // journal still lists them, so recovery retries after a crash. Anything
    // left behind is also reclaimed by `prune_orphans`.
    for old in old_files.values() {
        let _ = blobs::remove_blob(vault_dir, old_master, &old.id);
    }
    fsutil::remove_file_if_exists(&journal_path(vault_dir))?;

    Ok(report)
}

/// Completes or rolls back an interrupted rotation.
///
/// Safe to call with no journal. The caller must hold the exclusive lock.
pub(crate) fn recover(vault_dir: &Path) -> Result<()> {
    let journal_path = journal_path(vault_dir);
    let json = match fs::read_to_string(&journal_path) {
        Ok(json) => json,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Nothing was committed; drop any staged manifest.
            let _ = fs::remove_file(next_manifest_path(vault_dir));
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let journal: Journal = serde_json::from_str(&json).map_err(|_| Error::InvalidVault)?;
    if journal.version != JOURNAL_VERSION {
        return Err(Error::UnsupportedVersion(journal.version));
    }
    let config = VaultConfig::parse(&journal.config)?;
    if !matches!(config, VaultConfig::Slots(_)) || config.slot_ids().len() != 1 {
        return Err(Error::InvalidVault);
    }

    let canonical = manifest::path(vault_dir);
    let next = next_manifest_path(vault_dir);
    let expected = journal.manifest_sha256.as_str();
    let canonical_matches = file_sha256(&canonical).as_deref() == Some(expected);
    let next_matches = file_sha256(&next).as_deref() == Some(expected);

    if !canonical_matches && !next_matches {
        // The staged manifest is gone or damaged; the old canonical manifest
        // is still authoritative, so roll back rather than install a config
        // that cannot read it.
        let _ = fs::remove_file(&next);
        fsutil::remove_file_if_exists(&journal_path)?;
        return Ok(());
    }

    if next_matches {
        if canonical_matches {
            let _ = fs::remove_file(&next);
        } else {
            fs::rename(&next, &canonical)?;
            fsutil::sync_dir(&vault_dir.join("d"));
        }
    }

    fsutil::atomic_write(&vault_dir.join("vault.config"), journal.config.as_bytes())?;
    recovery::remove(vault_dir)?;
    // The old log belonged to the pre-rotation snapshot/master.
    index_log::remove_all(vault_dir)?;
    // The old master is no longer available here, but the journal records the
    // old blob paths so recovery can still remove old-key ciphertext.
    remove_journal_blobs(vault_dir, &journal.old_blobs);
    fsutil::remove_file_if_exists(&journal_path)?;
    Ok(())
}

/// Deletes old-key blobs listed in a rotation journal.
///
/// The journal is unauthenticated, so only paths that look like vault blobs
/// under `d/` are accepted; anything else is ignored.
fn remove_journal_blobs(vault_dir: &Path, rels: &[String]) {
    for rel in rels {
        let path = Path::new(rel);
        let mut components = path.components();
        let under_data_dir =
            components.next().map(|c| c.as_os_str()) == Some(std::ffi::OsStr::new("d"));
        let all_normal = components.all(|c| matches!(c, std::path::Component::Normal(_)));
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !path.is_absolute()
            && under_data_dir
            && all_normal
            && name.ends_with(".enc")
            && name != ".manifest.enc"
        {
            let _ = fs::remove_file(vault_dir.join(path));
        }
    }
}

fn journal_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(JOURNAL_FILE)
}

fn next_manifest_path(vault_dir: &Path) -> PathBuf {
    manifest::next_path(vault_dir)
}

/// Streams one old file blob into a new-master blob.
///
/// The bounded channel keeps plaintext in memory only (no temp files) while
/// letting the reader and writer run concurrently.
fn copy_file(
    vault_dir: &Path,
    old_master: &Key,
    new_master: &Key,
    entry_id: &str,
    meta: &EntryMetadata,
    padding: Padding,
) -> Result<(u64, String)> {
    let (tx, rx) = mpsc::sync_channel::<Zeroizing<Vec<u8>>>(4);
    let expected_size = meta.original_size;

    std::thread::scope(|scope| -> Result<(u64, String)> {
        // `move` is essential: the sender must be dropped when the producer
        // finishes so the reader sees end-of-stream.
        let producer = scope.spawn(move || -> Result<u64> {
            // Verify the old blob's size and content hash before re-encrypting
            // it; a substituted older blob aborts the rotation.
            blobs::read_entry_checked(vault_dir, old_master, meta, |chunk| {
                tx.send(Zeroizing::new(chunk.to_vec()))
                    .map_err(|_| Error::Operation("rotation stream cancelled".into()))
            })
        });

        let mut reader = ChannelReader::new(rx);
        let write = blobs::write_entry_from_reader(
            vault_dir,
            new_master,
            entry_id,
            meta,
            Some(&mut reader),
            padding,
            Some(expected_size),
        );
        drop(reader);

        let read = producer
            .join()
            .map_err(|_| Error::Operation("rotation worker panicked".into()))?;

        let (_, hash, written) = write?;
        let read = read?;
        if written != read {
            return Err(Error::Authentication);
        }
        Ok((read, hash))
    })
}

/// Adapts the rotation's bounded plaintext channel to [`std::io::Read`].
struct ChannelReader {
    rx: mpsc::Receiver<Zeroizing<Vec<u8>>>,
    chunk: Zeroizing<Vec<u8>>,
    pos: usize,
}

impl ChannelReader {
    fn new(rx: mpsc::Receiver<Zeroizing<Vec<u8>>>) -> Self {
        Self {
            rx,
            chunk: Zeroizing::new(Vec::new()),
            pos: 0,
        }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pos >= self.chunk.len() {
            match self.rx.recv() {
                Ok(next) => {
                    self.chunk = next;
                    self.pos = 0;
                }
                // The producer drops its sender when it finishes (success or
                // failure); the failure path is detected by joining it.
                Err(_) => return Ok(0),
            }
        }

        let n = out.len().min(self.chunk.len() - self.pos);
        out[..n].copy_from_slice(&self.chunk[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn file_sha256(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).ok()?;
    Some(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::vault::Vault;

    fn make_vault(tag: &str) -> (tempfile::TempDir, Vault) {
        let dir = tempfile::Builder::new().prefix(tag).tempdir().unwrap();
        let mut vault = Vault::new(dir.path().join("vault"));
        vault.init("old-password").unwrap();
        (dir, vault)
    }

    fn blobs_under(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(blobs_under(&path));
            } else {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".enc") && name != ".manifest.enc" {
                    out.push(path);
                }
            }
        }
        out
    }

    #[test]
    fn rotates_contents_and_collapses_credentials() {
        let (tmp, mut vault) = make_vault("rotate");
        let big: Vec<u8> = (0..140_000u32).map(|i| (i % 253) as u8).collect();
        let src = tmp.path().join("big.bin");
        std::fs::write(&src, &big).unwrap();
        vault.add(&src, None).unwrap();
        vault.add_keyslot("old-password", "second").unwrap();
        let _kit = vault.create_recovery_kit("old-password").unwrap();

        let old_blobs = blobs_under(&vault.path().join("d"));
        assert_eq!(old_blobs.len(), 1);

        let report = vault.rotate("old-password", "rotated").unwrap();
        assert_eq!(report.entries, 1);
        assert_eq!(report.bytes, big.len() as u64);
        assert_eq!(report.discarded_keyslots, 1);
        assert!(report.recovery_kit_removed);
        assert!(!vault.is_unlocked());

        let dir = vault.path().to_path_buf();
        for blob in &old_blobs {
            assert!(!blob.exists(), "old blob left behind: {}", blob.display());
        }
        let new_blobs = blobs_under(&dir.join("d"));
        assert_eq!(new_blobs.len(), 1);
        assert_ne!(new_blobs, old_blobs);

        assert!(!dir.join("vault.recovery").exists());
        assert!(!dir.join(JOURNAL_FILE).exists());
        assert_eq!(Vault::new(dir.clone()).keyslots().unwrap().len(), 1);
        assert!(Vault::new(dir.clone()).unlock("old-password").is_err());
        assert!(Vault::new(dir.clone()).unlock("second").is_err());
        assert!(Vault::new(dir.clone()).unlock("rotated").is_ok());

        let mut opened = Vault::new(dir);
        opened.unlock("rotated").unwrap();
        let out = tmp.path().join("out.bin");
        opened.extract("big.bin", &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), big);
    }

    #[test]
    fn wrong_password_changes_nothing() {
        let (tmp, mut vault) = make_vault("rotatewrong");
        let src = tmp.path().join("a.txt");
        std::fs::write(&src, b"a").unwrap();
        vault.add(&src, None).unwrap();
        let before = blobs_under(&vault.path().join("d"));

        assert!(matches!(
            vault.rotate("WRONG", "new"),
            Err(Error::Authentication)
        ));
        assert_eq!(vault.keyslots().unwrap().len(), 1);
        // A failed rotation leaves the old vault fully usable.
        vault.lock();
        vault.unlock("old-password").unwrap();
        assert_eq!(blobs_under(&vault.path().join("d")), before);
        assert!(!vault.path().join(JOURNAL_FILE).exists());
    }

    #[test]
    fn interrupted_rotation_is_completed_on_unlock() {
        let (tmp, mut vault) = make_vault("rotatecrash");
        let src = tmp.path().join("a.txt");
        std::fs::write(&src, b"payload").unwrap();
        vault.add(&src, None).unwrap();
        let dir = vault.path().to_path_buf();

        // Reproduce a crash after the manifest swap but before the config
        // write: build the new blobs/manifest/journal, swap the manifest, and
        // leave the old config in place.
        let config =
            VaultConfig::parse(&std::fs::read_to_string(dir.join("vault.config")).unwrap())
                .unwrap();
        let old_master = config.unwrap_master_key("old-password").unwrap();
        let new_master = Key::generate();
        let new_config = VaultConfig::new(&new_master, "rotated").unwrap();

        let old_files = manifest::load(&dir, &old_master).unwrap();
        let mut new_files = ManifestMap::new();
        for (path, old) in &old_files {
            let mut meta = old.clone();
            let (size, hash) = copy_file(
                &dir,
                &old_master,
                &new_master,
                &old.id,
                &meta,
                Padding::None,
            )
            .unwrap();
            meta.original_size = size;
            meta.content_hash = Some(hash);
            new_files.insert(path.clone(), meta);
        }
        let blob = manifest::encode(&new_files, &new_master, 1, Padding::None).unwrap();
        fsutil::atomic_write(&next_manifest_path(&dir), &blob).unwrap();
        let journal = Journal {
            version: JOURNAL_VERSION,
            manifest_sha256: sha256_hex(&blob),
            config: serde_json::to_string_pretty(&new_config).unwrap(),
            old_blobs: Vec::new(),
        };
        fsutil::atomic_write(&journal_path(&dir), &serde_json::to_vec(&journal).unwrap()).unwrap();
        std::fs::rename(next_manifest_path(&dir), manifest::path(&dir)).unwrap();

        // The next unlock completes the rotation before reading the config.
        let mut recovered = Vault::new(dir.clone());
        recovered.unlock("rotated").unwrap();
        assert!(!pending(&dir));

        let out = tmp.path().join("out.txt");
        recovered.extract("a.txt", &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"payload");
        assert!(Vault::new(dir).unlock("old-password").is_err());
    }

    #[test]
    fn journal_without_a_valid_staged_manifest_rolls_back() {
        let (_tmp, mut vault) = make_vault("rotaterollback");
        let dir = vault.path().to_path_buf();
        vault.lock();

        let new_master = Key::generate();
        let new_config = VaultConfig::new(&new_master, "rotated").unwrap();
        let journal = Journal {
            version: JOURNAL_VERSION,
            manifest_sha256: "00".repeat(32),
            config: serde_json::to_string_pretty(&new_config).unwrap(),
            old_blobs: Vec::new(),
        };
        fsutil::atomic_write(&journal_path(&dir), &serde_json::to_vec(&journal).unwrap()).unwrap();

        // No staged manifest exists, so recovery keeps the old vault.
        let mut reopened = Vault::new(dir.clone());
        reopened.unlock("old-password").unwrap();
        assert!(!pending(&dir));
        assert!(Vault::new(dir).unlock("rotated").is_err());
    }
}
