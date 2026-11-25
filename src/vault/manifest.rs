//! Vault manifest: the encrypted index of every entry in the vault.
//!
//! The manifest maps each entry's full vault-relative path to its metadata,
//! including the child lists that make recursive removal possible.
//!
//! The index is stored in two parts:
//!
//! * `d/.manifest.enc` — a complete snapshot, written as a universal keres
//!   container (see [`crate::container`]) with HKDF-from-master key
//!   derivation and payload type `manifest`. The index JSON is carried in the
//!   chunk section, so manifests grow past any artificial size limit.
//! * `d/.index.log` — an append-only log of encrypted mutation batches that
//!   extend the snapshot (see [`super::index_log`]).
//!
//! [`load`] decodes the snapshot and replays the log; [`save`] computes a diff
//! against the current index, appends one authenticated batch, and compacts
//! into a fresh snapshot when the log grows large.

use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::container::{self, KeyDerivation, PayloadType};
use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::fsutil;
use crate::padding::Padding;
use crate::vault::index_log::{self, LogOp};

/// SHA-256 length used to bind a log to its snapshot.
const HASH_LEN: usize = 32;

/// Upper bound on accepted manifest plaintext, guarding against hostile
/// on-disk files forcing huge allocations (a real vault would need tens of
/// millions of entries to reach this).
const MAX_MANIFEST_LEN: u64 = 64 * 1024 * 1024;

/// Current manifest schema version (inside the authenticated payload).
pub(crate) const MANIFEST_VERSION: u32 = 3;

/// Metadata for one vault entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryMetadata {
    /// Stable random identifier. Blob location and container AAD are derived
    /// from it, so entries can be renamed without re-encrypting.
    #[serde(default)]
    pub id: String,
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
    /// SHA-256 of the entry's plaintext, hex-encoded.
    ///
    /// Stored in the authenticated index so a storage attacker cannot swap in
    /// an older valid blob for the same entry ID. `None` on entries written by
    /// releases before this field existed; those can only be size-checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

/// The full vault index.
pub(crate) type ManifestMap = BTreeMap<String, EntryMetadata>;

#[derive(Serialize, Deserialize)]
struct ManifestFile {
    version: u32,
    /// Monotonic index generation, authenticated inside the snapshot.
    ///
    /// Pre-generation v3 snapshots deserialize as `0`; the first compaction
    /// advances them normally.
    #[serde(default)]
    generation: u64,
    /// Size-padding policy applied to newly written file blobs.
    ///
    /// Stored inside the authenticated snapshot so an attacker with storage
    /// access cannot silently disable padding. Absent on older snapshots,
    /// which means [`Padding::None`].
    #[serde(default, skip_serializing_if = "Padding::is_none")]
    padding: Padding,
    files: ManifestMap,
}

pub(crate) fn path(vault_dir: &Path) -> std::path::PathBuf {
    vault_dir.join("d").join(".manifest.enc")
}

/// Staging path used by deep rotation.
pub(crate) fn next_path(vault_dir: &Path) -> std::path::PathBuf {
    vault_dir.join("d").join(".manifest.enc.next")
}

/// A decoded snapshot plus its authenticated generation.
pub(crate) struct Snapshot {
    files: ManifestMap,
    generation: u64,
    padding: Padding,
}

/// A decoded manifest, tagged by its on-disk schema version.
pub(crate) enum ManifestContents {
    /// Legacy 0.4/0.5 index: blobs are addressed by entry path and entries
    /// carry no stable ID.
    V2(ManifestMap),
    /// Current index: every entry carries a stable random ID.
    V3 {
        /// Full index.
        files: ManifestMap,
        /// Authenticated generation.
        generation: u64,
        /// Authenticated size-padding policy.
        padding: Padding,
    },
}

/// Loads the manifest, fully authenticating its snapshot and log.
///
/// A missing snapshot is an error, not an empty index: treating it as "no
/// entries" would let the next save drop every existing record, make `verify`
/// report a healthy empty vault, and let a foreign recovery kit validate
/// against an empty index. Use [`init`] to create the first snapshot.
pub(crate) fn load(vault_dir: &Path, master: &Key) -> Result<ManifestMap> {
    Ok(load_with_padding(vault_dir, master)?.0)
}

/// Loads the manifest together with its authenticated size-padding policy.
pub(crate) fn load_with_padding(vault_dir: &Path, master: &Key) -> Result<(ManifestMap, Padding)> {
    let (mut snapshot, snapshot_sha256) = load_snapshot(vault_dir, master)?;
    index_log::replay(
        vault_dir,
        master,
        &mut snapshot.files,
        Some(&snapshot_sha256),
        snapshot.generation,
    )?;
    Ok((snapshot.files, snapshot.padding))
}

/// Returns the current authenticated index version (generation + record count).
pub(crate) fn current_version(vault_dir: &Path, master: &Key) -> Result<(u64, u64)> {
    let (mut snapshot, snapshot_sha256) = load_snapshot(vault_dir, master)?;
    let log = index_log::replay(
        vault_dir,
        master,
        &mut snapshot.files,
        Some(&snapshot_sha256),
        snapshot.generation,
    )?;
    let records = log.map(|info| info.next_index).unwrap_or(0);
    Ok((snapshot.generation, records))
}

/// Writes the initial empty snapshot for a brand-new vault.
///
/// The caller must have verified that no usable vault exists (no config and no
/// recovery kit). Any stale index log is discarded: it would have been
/// encrypted under a master key that no longer exists.
pub(crate) fn init(vault_dir: &Path, master: &Key, padding: Padding) -> Result<()> {
    padding.validate()?;
    index_log::remove_all(vault_dir)?;
    let blob = encode(&ManifestMap::new(), master, 1, padding)?;
    fsutil::atomic_write(&path(vault_dir), &blob)
}

/// Reads and decodes the snapshot, returning its hash for log binding.
///
/// A missing snapshot is an error; [`init`] is the only way to create one.
fn load_snapshot(vault_dir: &Path, master: &Key) -> Result<(Snapshot, [u8; HASH_LEN])> {
    let path = path(vault_dir);
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::InvalidVault),
        Err(e) => return Err(e.into()),
    };

    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_LEN)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidVault)?;

    let snapshot_sha256 = index_log::digest(&bytes);
    let snapshot = decode_snapshot(&bytes, master)?;
    Ok((snapshot, snapshot_sha256))
}

/// Decodes and authenticates manifest bytes. Shared by [`load`] and the
/// hidden fuzz entry point.
pub(crate) fn decode(bytes: &[u8], master: &Key) -> Result<ManifestMap> {
    match decode_contents(bytes, master)? {
        ManifestContents::V2(_) => Err(Error::MigrationRequired),
        ManifestContents::V3 { files, .. } => Ok(files),
    }
}

/// Decodes a snapshot, rejecting legacy formats that cannot carry a log.
fn decode_snapshot(bytes: &[u8], master: &Key) -> Result<Snapshot> {
    match decode_contents(bytes, master)? {
        ManifestContents::V2(_) => Err(Error::MigrationRequired),
        ManifestContents::V3 {
            files,
            generation,
            padding,
        } => Ok(Snapshot {
            files,
            generation,
            padding,
        }),
    }
}

/// Loads a legacy manifest for the one-way upgrade path.
///
/// Unlike [`load`], a missing manifest is an error: migration must never
/// mistake an empty data directory for a complete legacy index.
pub(crate) fn load_legacy_v2(vault_dir: &Path, master: &Key) -> Result<ManifestMap> {
    let path = path(vault_dir);
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::InvalidVault),
        Err(e) => return Err(e.into()),
    };

    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_LEN)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidVault)?;

    match decode_contents(&bytes, master)? {
        ManifestContents::V2(files) => Ok(files),
        ManifestContents::V3 { .. } => Err(Error::Operation(
            "vault already uses the current format".into(),
        )),
    }
}

/// Decodes the authenticated JSON without enforcing a particular version.
fn decode_contents(bytes: &[u8], master: &Key) -> Result<ManifestContents> {
    if bytes.len() as u64 > MAX_MANIFEST_LEN {
        return Err(Error::InvalidVault);
    }

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
    match manifest.version {
        // Legacy entries deserialize with an empty `id`; migration allocates
        // fresh IDs rather than trusting anything on disk.
        2 => Ok(ManifestContents::V2(manifest.files)),
        MANIFEST_VERSION => {
            if manifest.files.values().any(|entry| entry.id.is_empty()) {
                return Err(Error::InvalidVault);
            }
            if manifest.files.values().any(|entry| {
                entry.content_hash.as_ref().is_some_and(|hash| {
                    hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit())
                })
            }) {
                return Err(Error::InvalidVault);
            }
            Ok(ManifestContents::V3 {
                files: manifest.files,
                generation: manifest.generation,
                padding: manifest.padding,
            })
        }
        other => Err(Error::UnsupportedVersion(other)),
    }
}

/// Commits `files` to the index.
///
/// Existing state is loaded once, the difference is appended as a single
/// authenticated log batch, and a fresh snapshot is written when the log has
/// accumulated enough records. The snapshot must already exist ([`init`]
/// creates it); a legacy snapshot is replaced wholesale during migration.
/// Callers hold the exclusive vault lock.
pub(crate) fn save(
    vault_dir: &Path,
    files: &ManifestMap,
    master: &Key,
    padding: Padding,
) -> Result<()> {
    padding.validate()?;
    let (mut snapshot, snapshot_sha256) = match load_snapshot(vault_dir, master) {
        Ok(state) => state,
        Err(Error::MigrationRequired) => {
            // The legacy index is replaced wholesale; never try to merge with
            // records that belong to another schema.
            index_log::remove_all(vault_dir)?;
            let blob = encode(files, master, 1, padding)?;
            return fsutil::atomic_write(&path(vault_dir), &blob);
        }
        Err(e) => return Err(e),
    };

    let log = index_log::replay(
        vault_dir,
        master,
        &mut snapshot.files,
        Some(&snapshot_sha256),
        snapshot.generation,
    )?;

    if snapshot.files == *files && snapshot.padding == padding {
        return Ok(());
    }

    // `replay` guarantees this matches the snapshot; prefer the log's copy so
    // the field stays the single source for the mutation phase.
    let generation = log
        .as_ref()
        .map_or(snapshot.generation, |info| info.generation);

    // A policy change cannot ride the mutation log: it lives only in the
    // snapshot, so force a fresh snapshot. Routine log growth compacts too.
    let policy_changed = snapshot.padding != padding;
    if policy_changed || log.as_ref().is_some_and(|info| info.should_compact()) {
        let generation = generation.saturating_add(1);
        let blob = encode(files, master, generation, padding)?;
        return index_log::compact(vault_dir, &blob, generation);
    }

    let ops = diff(&snapshot.files, files);
    if ops.is_empty() {
        return Ok(());
    }
    index_log::append(
        vault_dir,
        master,
        &snapshot_sha256,
        generation,
        log.as_ref(),
        &ops,
    )?;
    Ok(())
}

/// Replaces the authenticated size-padding policy.
///
/// The policy lives inside the snapshot, so a change rewrites it atomically
/// and advances the generation (the append-only log cannot carry it). Callers
/// must hold the exclusive vault lock.
pub(crate) fn set_padding(vault_dir: &Path, master: &Key, padding: Padding) -> Result<()> {
    padding.validate()?;
    let (mut snapshot, snapshot_sha256) = load_snapshot(vault_dir, master)?;
    index_log::replay(
        vault_dir,
        master,
        &mut snapshot.files,
        Some(&snapshot_sha256),
        snapshot.generation,
    )?;

    if snapshot.padding == padding {
        return Ok(());
    }

    let generation = snapshot.generation.saturating_add(1);
    let blob = encode(&snapshot.files, master, generation, padding)?;
    index_log::compact(vault_dir, &blob, generation)
}

/// Computes the mutation batch that turns `old` into `new`.
fn diff(old: &ManifestMap, new: &ManifestMap) -> Vec<LogOp> {
    let mut ops = Vec::new();
    for (path, entry) in new {
        if old.get(path) != Some(entry) {
            ops.push(LogOp::Put {
                path: path.clone(),
                entry: entry.clone(),
            });
        }
    }
    for path in old.keys() {
        if !new.contains_key(path) {
            ops.push(LogOp::Delete { path: path.clone() });
        }
    }
    ops
}

/// Encodes the manifest as a fresh container under `master`.
///
/// Deep rotation writes the encoded bytes to a staging path before swapping
/// them in, so the same encoder is shared with [`save`]. `generation` is
/// stored inside the authenticated JSON.
pub(crate) fn encode(
    files: &ManifestMap,
    master: &Key,
    generation: u64,
    padding: Padding,
) -> Result<Vec<u8>> {
    let manifest = ManifestFile {
        version: MANIFEST_VERSION,
        generation,
        padding,
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
        Padding::None,
        None,
    )?;

    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::index_log;

    fn temp_vault() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("d")).unwrap();
        tmp
    }

    fn meta(name: &str) -> EntryMetadata {
        EntryMetadata {
            id: format!("id-{name}"),
            original_name: name.into(),
            original_size: 1,
            is_directory: false,
            children: None,
            content_hash: None,
        }
    }

    fn log_len(vault_dir: &Path) -> u64 {
        std::fs::metadata(vault_dir.join("d").join(index_log::LOG_FILE))
            .unwrap()
            .len()
    }

    #[test]
    fn saves_append_to_the_log_without_rewriting_the_snapshot() {
        let tmp = temp_vault();
        let dir = tmp.path();
        let master = Key::generate();

        let mut files = ManifestMap::new();
        init(dir, &master, Padding::None).unwrap();
        let snapshot = std::fs::read(path(dir)).unwrap();
        assert!(!index_log::exists(dir));
        assert_eq!(decode_snapshot(&snapshot, &master).unwrap().generation, 1);

        files.insert("a".into(), meta("a"));
        files.insert("b".into(), meta("b"));
        save(dir, &files, &master, Padding::None).unwrap();

        // The snapshot bytes are untouched; mutations live in the log.
        assert_eq!(std::fs::read(path(dir)).unwrap(), snapshot);
        assert!(index_log::exists(dir));
        assert_eq!(load(dir, &master).unwrap(), files);

        // Deletes are recorded too.
        files.remove("a");
        save(dir, &files, &master, Padding::None).unwrap();
        assert_eq!(std::fs::read(path(dir)).unwrap(), snapshot);
        assert_eq!(load(dir, &master).unwrap(), files);
    }

    #[test]
    fn a_large_log_is_compacted_into_a_fresh_snapshot() {
        let tmp = temp_vault();
        let dir = tmp.path();
        let master = Key::generate();

        let mut files = ManifestMap::new();
        init(dir, &master, Padding::None).unwrap();
        let original = std::fs::read(path(dir)).unwrap();

        for i in 0..512 {
            files.insert(format!("e{i}"), meta(&format!("e{i}")));
            save(dir, &files, &master, Padding::None).unwrap();
        }
        assert!(log_len(dir) > 200, "expected a populated log");
        assert_eq!(std::fs::read(path(dir)).unwrap(), original);

        // The next save reaches the record threshold and compacts.
        files.insert("after".into(), meta("after"));
        save(dir, &files, &master, Padding::None).unwrap();

        assert!(std::fs::read(path(dir)).unwrap() != original);
        assert!(log_len(dir) < 200, "log should restart after compaction");
        assert_eq!(load(dir, &master).unwrap(), files);

        // The snapshot's authenticated generation advances on compaction.
        let compacted = std::fs::read(path(dir)).unwrap();
        assert_eq!(decode_snapshot(&compacted, &master).unwrap().generation, 2);
    }
}
