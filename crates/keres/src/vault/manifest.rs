//! Vault manifest: the encrypted index of every entry in the vault.
//!
//! The manifest maps each entry's full vault-relative path to its metadata,
//! including the child lists that make recursive removal possible.
//!
//! Stored at `d/.manifest.enc` as a universal keres container (see
//! [`crate::container`]) with HKDF-from-master key derivation and payload
//! type `manifest`; the index JSON is carried in the chunk section, so
//! manifests grow past any artificial size limit.

use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::container::{self, KeyDerivation, PayloadType};
use crate::crypto::{self, Key};
use crate::error::{Error, Result};

/// Upper bound on accepted manifest plaintext, guarding against hostile
/// on-disk files forcing huge allocations (a real vault would need tens of
/// millions of entries to reach this).
const MAX_MANIFEST_LEN: u64 = 64 * 1024 * 1024;

/// Current manifest schema version (inside the authenticated payload).
pub(crate) const MANIFEST_VERSION: u32 = 2;

/// Metadata for one vault entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryMetadata {
    /// Original filesystem name of the entry.
    #[serde(default)]
    pub original_name: String,
    /// Original size in bytes.
    #[serde(default)]
    pub original_size: u64,
    /// Whether this entry is a directory placeholder.
    #[serde(default)]
    pub is_directory: bool,
    /// Full paths of direct children (directories only).
    #[serde(default)]
    pub children: Option<Vec<String>>,
}

/// The full vault index.
pub(crate) type ManifestMap = BTreeMap<String, EntryMetadata>;

#[derive(Serialize, Deserialize)]
struct ManifestFile {
    version: u32,
    files: ManifestMap,
}

fn manifest_path(vault_dir: &Path) -> std::path::PathBuf {
    vault_dir.join("d").join(".manifest.enc")
}

/// Loads the manifest, fully authenticating its container.
///
/// A *missing* manifest yields an empty index; anything present but damaged,
/// truncated or unauthentic is an error — silently treating corruption as
/// "no entries" would let the next save drop every existing record.
pub(crate) fn load(vault_dir: &Path, master: &Key) -> Result<ManifestMap> {
    let path = manifest_path(vault_dir);
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ManifestMap::new()),
        Err(e) => return Err(e.into()),
    };

    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_LEN)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidVault)?;

    let mut json = Zeroizing::new(Vec::new());
    container::read_container(
        Cursor::new(bytes),
        None,
        Some(master),
        PayloadType::Manifest,
        b"vault-manifest",
        |c| {
            json.extend_from_slice(c);
            Ok(())
        },
    )?;

    let manifest: ManifestFile =
        serde_json::from_slice(json.as_slice()).map_err(|_| Error::MalformedPayload)?;
    if manifest.version != MANIFEST_VERSION {
        return Err(Error::UnsupportedVersion(manifest.version));
    }
    Ok(manifest.files)
}

/// Atomically saves the manifest as a fresh container (new object salt on
/// every write).
pub(crate) fn save(vault_dir: &Path, files: &ManifestMap, master: &Key) -> Result<()> {
    let manifest = ManifestFile {
        version: MANIFEST_VERSION,
        files: files.clone(),
    };
    let json = Zeroizing::new(serde_json::to_vec(&manifest).map_err(|_| Error::Encryption)?);

    let mut object_salt = [0u8; container::SALT_LEN];
    crypto::fill_random(&mut object_salt);
    let kd = KeyDerivation::Hkdf { object_salt };

    let mut blob = Vec::new();
    let mut src = Cursor::new(json.as_slice());
    container::write_container(
        &mut blob,
        &kd,
        None,
        Some(master),
        PayloadType::Manifest,
        b"vault-manifest",
        Some(&mut src),
        None,
    )?;

    crate::fsutil::atomic_write(&manifest_path(vault_dir), &blob)
}
