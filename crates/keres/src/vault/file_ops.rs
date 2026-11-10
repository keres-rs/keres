//! Encrypted entry blobs inside the vault data directory.
//!
//! Each vault entry lives at `d/<h2>/<rest>.enc` where the path is derived
//! from `SHA256(master_key || full_entry_path)` — identical naming to
//! previous releases. Blob contents are universal keres containers (see
//! [`crate::container`]) using HKDF-from-master key derivation, with the
//! expected payload type (`file` / `directory`) supplied by the manifest
//! and enforced on every record.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::container::{self, KeyDerivation, PayloadType};
use crate::crypto::{self, Key};
use crate::error::Result;
use crate::vault::manifest::EntryMetadata;

/// Deterministic storage location for an entry's ciphertext.
///
/// The hash binds the master key so paths are stable within a vault and
/// opaque outside it.
fn blob_path(vault_dir: &Path, master: &Key, entry_path: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(master.expose());
    hasher.update(entry_path.as_bytes());
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
pub(crate) fn write_entry(
    vault_dir: &Path,
    master: &Key,
    entry_path: &str,
    meta: &EntryMetadata,
    source: Option<&Path>,
) -> Result<PathBuf> {
    let target = blob_path(vault_dir, master, entry_path);
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
    let outcome = (|| -> Result<()> {
        let mut out_file = crate::fsutil::create_private_file(&tmp)?;
        {
            let mut w = BufWriter::new(&mut out_file);
            let mut src_file;
            let src: Option<&mut dyn Read> = match source {
                Some(p) => {
                    src_file = File::open(p)?;
                    Some(&mut src_file)
                }
                None => None,
            };
            container::write_container(
                &mut w,
                &kd,
                None,
                Some(master),
                typ,
                entry_path.as_bytes(),
                src,
                None,
            )?;
            w.flush()?;
        }
        out_file.sync_all()?;
        drop(out_file);

        std::fs::rename(&tmp, &target)?;
        if let Some(parent) = target.parent() {
            crate::fsutil::sync_dir(parent);
        }
        Ok(())
    })();

    match outcome {
        Ok(()) => Ok(target),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Reads and authenticates an entry blob, streaming plaintext to `sink`
/// (no-op for directory placeholders). The expected payload type comes from
/// the manifest and is enforced by the container reader.
pub(crate) fn read_entry(
    vault_dir: &Path,
    master: &Key,
    entry_path: &str,
    is_directory: bool,
    mut sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<EntryMetadata> {
    let path = blob_path(vault_dir, master, entry_path);
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
        entry_path.as_bytes(),
        |chunk| sink(chunk),
    )?;

    Ok(EntryMetadata {
        original_name: String::new(),
        original_size: trailer.size,
        is_directory: trailer.typ == PayloadType::Directory,
        children: None,
    })
}

/// Removes the blob backing an entry, if present. Best-effort removal of
/// the now-empty shard directory keeps the data directory tidy.
pub(crate) fn remove_blob(vault_dir: &Path, master: &Key, entry_path: &str) -> Result<()> {
    let path = blob_path(vault_dir, master, entry_path);
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
}
