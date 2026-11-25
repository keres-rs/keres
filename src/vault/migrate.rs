//! One-way upgrade from legacy (manifest v2) vaults.
//!
//! Legacy blobs are addressed and authenticated by their vault-relative path
//! (`SHA256(master || path)`), while the current format binds each blob to a
//! random 128-bit entry ID. An upgrade therefore cannot move ciphertext; it
//! re-encrypts every entry under a fresh ID and object salt, then swaps in a
//! v3 manifest atomically.
//!
//! Crash safety follows the same rule as ordinary writes: new blobs are
//! written first, the manifest is committed last. A failure before the
//! commit leaves the legacy manifest untouched (and the new blobs
//! unreferenced); leftovers are reclaimed by [`crate::Vault::prune_orphans`].

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::container::{self, PayloadType};
use crate::crypto::Key;
use crate::error::{Error, Result};
use crate::padding::Padding;
use crate::sanitize;

use super::file_ops as blobs;
use super::manifest::{self, EntryMetadata, ManifestMap};
use super::new_entry_id;

/// Outcome of a successful [`crate::Vault::migrate`] call.
#[derive(Debug, Default, Clone)]
pub struct MigrationReport {
    /// Entries rewritten into the current format (files and directories).
    pub entries: usize,
    /// Plaintext bytes re-encrypted for file entries.
    pub bytes: u64,
}

/// Rewrites `vault_dir` in place from manifest v2 to v3.
///
/// The caller must hold the vault's exclusive lock and have authenticated
/// `master` against the on-disk config.
pub(crate) fn run(vault_dir: &Path, master: &Key) -> Result<MigrationReport> {
    let legacy = manifest::load_legacy_v2(vault_dir, master)?;

    let mut upgraded = ManifestMap::new();
    let mut report = MigrationReport::default();

    for (path, old) in &legacy {
        // The manifest is authenticated, but validate names before using them
        // as identity material so a malformed index fails loudly.
        sanitize::sanitize_stored_name(path)?;

        let id = new_entry_id();
        let mut meta = EntryMetadata {
            id,
            original_name: if old.original_name.is_empty() {
                path.clone()
            } else {
                old.original_name.clone()
            },
            original_size: old.original_size,
            is_directory: old.is_directory,
            children: old.children.clone(),
            content_hash: None,
        };

        if old.is_directory {
            // Authenticate the placeholder before replacing it.
            read_legacy_entry(vault_dir, master, path, true, |_| Ok(()))?;
            let (_, hash, _) = blobs::write_entry_from_reader(
                vault_dir,
                master,
                &meta.id,
                &meta,
                None,
                Padding::None,
                None,
            )?;
            meta.original_size = 0;
            meta.content_hash = Some(hash);
        } else {
            let (size, hash) = copy_file(vault_dir, master, path, &meta)?;
            meta.original_size = size;
            meta.content_hash = Some(hash);
            report.bytes += size;
        }

        report.entries += 1;
        upgraded.insert(path.clone(), meta);
    }

    // Cut-over point: every new blob exists, so replacing the manifest makes
    // the upgrade visible atomically (temp file + rename).
    manifest::save(vault_dir, &upgraded, master, Padding::None)?;

    // Legacy blobs are unreachable now. Best-effort removal matches normal
    // `remove`; anything left behind is an orphan for `prune_orphans`.
    for path in legacy.keys() {
        let _ = remove_legacy_blob(vault_dir, master, path);
    }

    Ok(report)
}

/// Streams one legacy file blob into a new ID-addressed blob.
///
/// Plaintext stays in memory: the decryption callback feeds a small bounded
/// channel that the encryption side reads, so no temporary file is written.
fn copy_file(
    vault_dir: &Path,
    master: &Key,
    legacy_path: &str,
    meta: &EntryMetadata,
) -> Result<(u64, String)> {
    let (tx, rx) = mpsc::sync_channel::<Zeroizing<Vec<u8>>>(4);

    std::thread::scope(|scope| -> Result<(u64, String)> {
        // `move` is essential: the sender must be dropped when the producer
        // finishes so the reader sees end-of-stream.
        let producer = scope.spawn(move || -> Result<u64> {
            read_legacy_entry(vault_dir, master, legacy_path, false, |chunk| {
                tx.send(Zeroizing::new(chunk.to_vec()))
                    .map_err(|_| Error::Operation("migration stream cancelled".into()))
            })
        });

        let mut reader = ChannelReader::new(rx);
        let write = blobs::write_entry_from_reader(
            vault_dir,
            master,
            &meta.id,
            meta,
            Some(&mut reader),
            Padding::None,
            None,
        );
        // Close the receiving end before joining: if the write failed, the
        // producer may be blocked on a full channel and must see a disconnect.
        drop(reader);

        let read = producer
            .join()
            .map_err(|_| Error::Operation("migration worker panicked".into()))?;

        // Prefer the write error; a read error means the source failed
        // authentication, in which case nothing was committed.
        let (_, hash, written) = write?;
        let read = read?;
        if written != read {
            return Err(Error::Authentication);
        }
        Ok((read, hash))
    })
}

/// Reads and authenticates a legacy blob, streaming plaintext to `sink`.
/// Returns the authenticated plaintext size.
fn read_legacy_entry(
    vault_dir: &Path,
    master: &Key,
    entry_path: &str,
    is_directory: bool,
    sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<u64> {
    let expected = if is_directory {
        PayloadType::Directory
    } else {
        PayloadType::File
    };

    let reader = BufReader::new(File::open(legacy_blob_path(vault_dir, master, entry_path))?);
    let trailer = container::read_container(
        reader,
        None,
        Some(master),
        expected,
        entry_path.as_bytes(),
        sink,
    )?;
    Ok(trailer.size)
}

/// Legacy blob location: `SHA256(master || vault-relative path)`.
fn legacy_blob_path(vault_dir: &Path, master: &Key, entry_path: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(master.expose());
    hasher.update(entry_path.as_bytes());
    let h = format!("{:x}", hasher.finalize());
    vault_dir
        .join("d")
        .join(&h[..2])
        .join(format!("{}.enc", &h[2..50]))
}

/// Removes a legacy blob, tidying an emptied shard directory if possible.
fn remove_legacy_blob(vault_dir: &Path, master: &Key, entry_path: &str) -> Result<()> {
    let path = legacy_blob_path(vault_dir, master, entry_path);
    crate::fsutil::remove_file_if_exists(&path)?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::remove_dir(parent);
    }
    Ok(())
}

/// Adapts the migration's bounded plaintext channel to [`std::io::Read`].
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
                // failure). The failure path is detected by joining the
                // producer, so EOF is the right signal here.
                Err(_) => return Ok(0),
            }
        }

        let n = out.len().min(self.chunk.len() - self.pos);
        out[..n].copy_from_slice(&self.chunk[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::path::PathBuf;

    use crate::container::KeyDerivation;
    use crate::crypto;
    use crate::vault::keystore::KeyStore;
    use crate::vault::Vault;

    /// Builds a 0.5.x-style vault with manifest v2 and path-addressed blobs.
    /// `None` denotes a directory placeholder.
    fn write_legacy_vault(dir: &Path, password: &str, entries: &[(&str, Option<&[u8]>)]) {
        std::fs::create_dir_all(dir.join("d")).unwrap();

        let mut store = KeyStore::new();
        let config = store.init(password).unwrap();
        let master = store.master_key().unwrap().clone();
        let cfg_json = serde_json::to_string_pretty(&config).unwrap();
        crate::fsutil::atomic_write(&dir.join("vault.config"), cfg_json.as_bytes()).unwrap();

        let mut files = ManifestMap::new();
        for (path, data) in entries {
            write_legacy_blob(dir, &master, path, *data);
            files.insert(
                path.to_string(),
                EntryMetadata {
                    id: String::new(),
                    original_name: path.to_string(),
                    original_size: data.map(|b| b.len() as u64).unwrap_or(0),
                    is_directory: data.is_none(),
                    children: None,
                    content_hash: None,
                },
            );
        }

        // Wire up child lists exactly like the v2 writer did.
        let paths: Vec<String> = files.keys().cloned().collect();
        let directory_paths: Vec<String> = files
            .iter()
            .filter(|(_, meta)| meta.is_directory)
            .map(|(path, _)| path.clone())
            .collect();
        for dir_path in directory_paths {
            let prefix = format!("{dir_path}/");
            let children: Vec<String> = paths
                .iter()
                .filter(|p| p.starts_with(&prefix) && !p[prefix.len()..].contains('/'))
                .cloned()
                .collect();
            files.get_mut(&dir_path).unwrap().children = Some(children);
        }

        let manifest = serde_json::json!({ "version": 2, "files": files });
        let plaintext = serde_json::to_vec(&manifest).unwrap();

        let mut object_salt = [0u8; container::SALT_LEN];
        crypto::fill_random(&mut object_salt);
        let kd = KeyDerivation::Hkdf { object_salt };
        let mut bytes = Vec::new();
        container::write_container(
            &mut bytes,
            &kd,
            None,
            Some(&master),
            PayloadType::Manifest,
            b"vault-manifest",
            Some(&mut Cursor::new(plaintext)),
            None,
            Padding::None,
            None,
        )
        .unwrap();
        crate::fsutil::atomic_write(&dir.join("d").join(".manifest.enc"), &bytes).unwrap();
    }

    fn write_legacy_blob(dir: &Path, master: &Key, path: &str, data: Option<&[u8]>) {
        let mut object_salt = [0u8; container::SALT_LEN];
        crypto::fill_random(&mut object_salt);
        let kd = KeyDerivation::Hkdf { object_salt };
        let (typ, mut src) = match data {
            Some(bytes) => (PayloadType::File, Some(Cursor::new(bytes.to_vec()))),
            None => (PayloadType::Directory, None),
        };

        let mut blob = Vec::new();
        container::write_container(
            &mut blob,
            &kd,
            None,
            Some(master),
            typ,
            path.as_bytes(),
            src.as_mut().map(|c| c as &mut dyn Read),
            None,
            Padding::None,
            None,
        )
        .unwrap();

        let target = legacy_blob_path(dir, master, path);
        crate::fsutil::create_private_dir(target.parent().unwrap()).unwrap();
        crate::fsutil::atomic_write(&target, &blob).unwrap();
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
    fn migrates_v2_vault_and_preserves_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("vault");
        let big: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();

        write_legacy_vault(
            &dir,
            "correct horse",
            &[
                ("top.txt", Some(b"top")),
                ("docs", None),
                ("docs/a.txt", Some(b"alpha")),
                ("docs/sub", None),
                ("docs/sub/b.bin", Some(big.as_slice())),
            ],
        );

        let old_blobs = blobs_under(&dir.join("d"));
        assert_eq!(old_blobs.len(), 5);

        let mut vault = Vault::new(dir.clone());
        let report = vault.migrate("correct horse").unwrap();
        assert_eq!(report.entries, 5);
        assert_eq!(report.bytes, 3 + 5 + big.len() as u64);

        // Old path-addressed blobs are gone; new blobs are ID-addressed.
        for old in old_blobs {
            assert!(!old.exists(), "legacy blob left behind: {}", old.display());
        }
        assert_eq!(blobs_under(&dir.join("d")).len(), 5);

        vault.unlock("correct horse").unwrap();
        let mut names: Vec<_> = vault.list().unwrap().into_iter().map(|e| e.name).collect();
        names.sort();
        assert_eq!(names, vec!["docs", "top.txt"]);

        let one = tmp.path().join("one.txt");
        vault.extract("top.txt", &one).unwrap();
        assert_eq!(std::fs::read(&one).unwrap(), b"top");

        let tree = tmp.path().join("restored");
        vault.extract("docs", &tree).unwrap();
        assert_eq!(std::fs::read(tree.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(std::fs::read(tree.join("sub").join("b.bin")).unwrap(), big);

        // Copied child lists still drive recursive removal.
        vault.remove("docs").unwrap();
        let names: Vec<_> = vault.list().unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(names, vec!["top.txt"]);
    }

    #[test]
    fn legacy_vault_reports_migration_required() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("vault");
        write_legacy_vault(&dir, "pw", &[("a.txt", Some(b"a"))]);

        let mut vault = Vault::new(dir);
        vault.unlock("pw").unwrap();
        assert!(matches!(vault.list(), Err(Error::MigrationRequired)));
    }

    #[test]
    fn wrong_password_is_authentication_error() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("vault");
        write_legacy_vault(&dir, "pw", &[("a.txt", Some(b"a"))]);

        let mut vault = Vault::new(dir);
        assert!(matches!(vault.migrate("nope"), Err(Error::Authentication)));
    }

    #[test]
    fn current_format_is_not_migrated_again() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("vault");
        let mut vault = Vault::new(dir);
        vault.init("pw").unwrap();

        assert!(matches!(vault.migrate("pw"), Err(Error::Operation(_))));
    }

    #[test]
    fn missing_manifest_is_invalid_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("vault");
        std::fs::create_dir_all(dir.join("d")).unwrap();
        let mut store = KeyStore::new();
        let config = store.init("pw").unwrap();
        let cfg_json = serde_json::to_string_pretty(&config).unwrap();
        std::fs::write(dir.join("vault.config"), cfg_json).unwrap();

        assert!(matches!(
            Vault::new(dir).migrate("pw"),
            Err(Error::InvalidVault)
        ));
    }
}
