//! Encrypted entry blobs inside the vault data directory.
//!
//! Each vault entry lives at `d/<h2>/<rest>.enc` where the path is derived
//! from `SHA256(master_key || entry_id)`. Blob contents are universal keres
//! containers (see [`crate::container`]) using HKDF-from-master key
//! derivation, with the expected payload type (`file` / `directory`) supplied
//! by the manifest and enforced on every record.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::container::{self, KeyDerivation, PayloadType};
use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::padding::Padding;
use crate::vault::manifest::EntryMetadata;

/// Deterministic storage location for an entry's ciphertext.
///
/// The hash binds the master key and the entry's stable random ID (not its
/// path), so renaming an entry never requires re-encrypting its blob and the
/// location stays opaque outside the vault.
pub(crate) fn blob_path(vault_dir: &Path, master: &Key, entry_id: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(master.expose());
    hasher.update(entry_id.as_bytes());
    let h = format!("{:x}", hasher.finalize());
    vault_dir
        .join("d")
        .join(&h[..2])
        .join(format!("{}.enc", &h[2..50]))
}

/// Encrypts an entry into a new-format blob.
///
/// Blobs are written via temp file + rename so a crash cannot leave a
/// half-written entry that the manifest would still reference. Directory
/// placeholders carry no chunks — their trailer alone asserts emptiness.
///
/// `padding` is applied to file payloads only; directory placeholders are
/// always unpadded. The exact source length is captured before reading so
/// padded containers can zero-fill up to their bucket.
///
/// Returns `(blob_path, plaintext_sha256_hex, plaintext_size)`. Callers store
/// the hash and size in the authenticated index so a later read can detect a
/// substituted or rolled-back blob.
pub(crate) fn write_entry(
    vault_dir: &Path,
    master: &Key,
    entry_id: &str,
    meta: &EntryMetadata,
    source: Option<&Path>,
    padding: Padding,
) -> Result<(PathBuf, String, u64)> {
    let mut src_file;
    let (src, source_len): (Option<&mut dyn Read>, Option<u64>) = match source {
        Some(p) => {
            let len = std::fs::metadata(p)?.len();
            src_file = File::open(p)?;
            (Some(&mut src_file), Some(len))
        }
        None => (None, None),
    };
    write_entry_from_reader(vault_dir, master, entry_id, meta, src, padding, source_len)
}

/// Encrypts an entry from an arbitrary reader into a new-format blob.
///
/// This is the streaming core behind [`write_entry`]; `source: None` writes a
/// chunk-less directory placeholder. The output is written via temp file +
/// rename, so a crash can never leave a half-written entry that the manifest
/// references.
///
/// When `padding` is not [`Padding::None`], `source_len` must be the exact
/// number of plaintext bytes `source` will yield.
///
/// Returns `(blob_path, plaintext_sha256_hex, plaintext_size)`. The hash is
/// computed from the real plaintext bytes (padding is excluded).
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_entry_from_reader(
    vault_dir: &Path,
    master: &Key,
    entry_id: &str,
    meta: &EntryMetadata,
    source: Option<&mut dyn Read>,
    padding: Padding,
    source_len: Option<u64>,
) -> Result<(PathBuf, String, u64)> {
    // Directory placeholders have no plaintext to pad; a stray policy must
    // not turn a metadata-only entry into an error.
    let padding = if meta.is_directory {
        Padding::None
    } else {
        padding
    };
    padding.validate()?;

    let target = blob_path(vault_dir, master, entry_id);
    if let Some(parent) = target.parent() {
        crate::fsutil::create_private_dir(parent)?;
    }

    let mut object_salt = [0u8; container::SALT_LEN];
    crypto::fill_random(&mut object_salt);
    let kd = KeyDerivation::Hkdf { object_salt };
    let typ = if meta.is_directory {
        PayloadType::Directory
    } else {
        PayloadType::File
    };

    let tmp = crate::fsutil::sibling_temp_path(&target);
    let outcome = (|| -> Result<(String, u64)> {
        let mut hasher = Sha256::new();
        let mut out_file = crate::fsutil::create_private_file(&tmp)?;
        let written = {
            let mut w = BufWriter::new(&mut out_file);
            let written = {
                // Hash only the real plaintext bytes; padding is written by the
                // container layer after the source reaches EOF.
                let mut hashed = source.map(|s| HashingReader {
                    inner: s,
                    hasher: &mut hasher,
                });
                container::write_container(
                    &mut w,
                    &kd,
                    None,
                    Some(master),
                    typ,
                    entry_id.as_bytes(),
                    hashed.as_mut().map(|h| h as &mut dyn Read),
                    None,
                    padding,
                    source_len,
                )?
                .0
            };
            w.flush()?;
            written
        };
        out_file.sync_all()?;
        drop(out_file);

        std::fs::rename(&tmp, &target)?;
        if let Some(parent) = target.parent() {
            crate::fsutil::sync_dir(parent);
        }
        Ok((format!("{:x}", hasher.finalize()), written))
    })();

    match outcome {
        Ok((hash, size)) => Ok((target, hash, size)),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Hashes plaintext as the container reader pulls it from the source.
struct HashingReader<'a> {
    inner: &'a mut dyn Read,
    hasher: &'a mut Sha256,
}

impl Read for HashingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// Reads and authenticates an entry blob, streaming plaintext to `sink`
/// (no-op for directory placeholders). The expected payload type comes from
/// the manifest and is enforced by the container reader.
pub(crate) fn read_entry(
    vault_dir: &Path,
    master: &Key,
    entry_id: &str,
    is_directory: bool,
    mut sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<EntryMetadata> {
    let path = blob_path(vault_dir, master, entry_id);
    let expected = if is_directory {
        PayloadType::Directory
    } else {
        PayloadType::File
    };

    let reader = BufReader::new(File::open(&path)?);
    let trailer = container::read_container(
        reader,
        None,
        Some(master),
        expected,
        entry_id.as_bytes(),
        |chunk| sink(chunk),
    )?;

    Ok(EntryMetadata {
        id: entry_id.to_string(),
        original_name: String::new(),
        original_size: trailer.size,
        is_directory: trailer.typ == PayloadType::Directory,
        children: None,
        content_hash: None,
    })
}

/// Reads an entry and checks it against the authenticated index metadata.
///
/// Beyond AEAD authentication, this rejects a blob whose plaintext size or
/// content hash differs from what the index recorded. That catches a storage
/// attacker swapping in an older valid blob for the same entry ID, and stale
/// size metadata from an interrupted write. Entries written before content
/// hashes existed are only size-checked.
///
/// Returns the authenticated plaintext size.
pub(crate) fn read_entry_checked(
    vault_dir: &Path,
    master: &Key,
    meta: &EntryMetadata,
    mut sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<u64> {
    let mut hasher = Sha256::new();
    let read = read_entry(vault_dir, master, &meta.id, meta.is_directory, |chunk| {
        hasher.update(chunk);
        sink(chunk)
    })?;

    if read.original_size != meta.original_size {
        return Err(Error::Authentication);
    }
    if let Some(expected) = &meta.content_hash {
        let actual = format!("{:x}", hasher.finalize());
        if actual != *expected {
            return Err(Error::Authentication);
        }
    }
    Ok(read.original_size)
}

/// Removes the blob backing an entry, if present. Best-effort removal of
/// the now-empty shard directory keeps the data directory tidy.
pub(crate) fn remove_blob(vault_dir: &Path, master: &Key, entry_id: &str) -> Result<()> {
    let path = blob_path(vault_dir, master, entry_id);
    crate::fsutil::remove_file_if_exists(&path)?;
    if let Some(parent) = path.parent() {
        // Only succeeds when empty; races with concurrent adds are benign.
        let _ = std::fs::remove_dir(parent);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_paths_are_stable_and_distinct() {
        let m = Key::generate();
        let a1 = blob_path(Path::new("/v"), &m, "alpha");
        let a2 = blob_path(Path::new("/v"), &m.clone(), "alpha");
        let b = blob_path(Path::new("/v"), &m, "beta");
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert!(a1.starts_with("/v/d/"));
    }

    #[test]
    fn checked_read_rejects_size_and_hash_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path();
        std::fs::create_dir_all(vault.join("d")).unwrap();
        let master = Key::generate();
        let src = tmp.path().join("src.txt");
        std::fs::write(&src, b"hello world").unwrap();

        let mut meta = EntryMetadata {
            id: "entry".into(),
            original_name: "src.txt".into(),
            original_size: 0,
            is_directory: false,
            children: None,
            content_hash: None,
        };
        let (_, hash, size) =
            write_entry(vault, &master, "entry", &meta, Some(&src), Padding::None).unwrap();
        meta.original_size = size;
        meta.content_hash = Some(hash);

        let mut out = Vec::new();
        read_entry_checked(vault, &master, &meta, |chunk| {
            out.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
        assert_eq!(out, b"hello world");

        let mut wrong_size = meta.clone();
        wrong_size.original_size += 1;
        assert!(matches!(
            read_entry_checked(vault, &master, &wrong_size, |_| Ok(())),
            Err(Error::Authentication)
        ));

        let mut wrong_hash = meta;
        wrong_hash.content_hash = Some("00".repeat(32));
        assert!(matches!(
            read_entry_checked(vault, &master, &wrong_hash, |_| Ok(())),
            Err(Error::Authentication)
        ));
    }
}
