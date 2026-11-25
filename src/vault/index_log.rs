//! Append-only encrypted index log with periodic compacted snapshot.
//!
//! The vault index has two on-disk parts:
//!
//! * `d/.manifest.enc` — a complete snapshot of the map, exactly as before.
//! * `d/.index.log` — encrypted mutation batches appended after that snapshot.
//!
//! A save computes the difference between the current map and the new map and
//! appends one authenticated batch (`put`/`delete` records). Loading decrypts
//! the snapshot once, then replays the log on top. Compaction writes a fresh
//! snapshot, installs an empty log that names it by SHA-256, and removes the
//! old log.
//!
//! # Log format
//!
//! ```text
//! header:  b"KERESIDX" | version u16 | generation u64 |
//!          snapshot_sha256[32] | log_id[32]
//! record:  len u32 | index u64 | nonce[12] | ciphertext || tag
//! ```
//!
//! The per-log key is `HKDF(master, log_id)`; every record uses a random
//! 96-bit nonce and AAD binding the header bytes and record index. A record
//! cannot be moved between logs, reordered, or replayed under another
//! generation. The snapshot hash in the header ties the log to exactly the
//! snapshot it extends.
//!
//! # Crash safety
//!
//! A record is written with one `write_all` followed by `sync_data`. A crash
//! may leave a torn final record; replay stops at the last valid record and
//! the next append truncates the tail. Tampering or a gap in the middle is an
//! error, not a silent truncation.
//!
//! Compaction is journaled in `d/.index.compact`. The journal names the new
//! snapshot hash; recovery promotes the staged snapshot and log, removes the
//! old log, and deletes the journal. A crash before the journal exists leaves
//! orphaned staged files that the next recovery deletes.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::fsutil;
use crate::vault::manifest;

use super::manifest::{EntryMetadata, ManifestMap};

/// Append-only log beside the snapshot.
pub(crate) const LOG_FILE: &str = ".index.log";
/// Staged empty log for compaction.
const NEXT_LOG_FILE: &str = ".index.log.next";
/// Staged snapshot for compaction. Deliberately distinct from deep rotation's
/// `.manifest.enc.next` so the two recovery paths cannot delete each other's
/// staged files.
const NEXT_SNAPSHOT_FILE: &str = ".index.snapshot.next";
/// Compaction journal.
const COMPACT_FILE: &str = ".index.compact";

const MAGIC: &[u8; 8] = b"KERESIDX";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 8 + 2 + 8 + 32 + 32;
const HASH_LEN: usize = 32;
const NONCE_LEN: usize = crypto::NONCE_LEN;
const TAG_LEN: usize = crypto::TAG_LEN;
const RECORD_PREFIX_LEN: usize = 4 + 8;
/// Upper bound on one decrypted mutation batch (same order as the snapshot
/// cap; a directory rename should never approach it in practice).
const MAX_BATCH_LEN: usize = 64 * 1024 * 1024;
const MAX_RECORD_LEN: usize = MAX_BATCH_LEN + NONCE_LEN + TAG_LEN;

/// Compaction thresholds: enough small mutations, or a log larger than this.
const COMPACT_AFTER_RECORDS: u64 = 512;
const COMPACT_AFTER_BYTES: u64 = 8 * 1024 * 1024;

/// One mutation in a log batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub(crate) enum LogOp {
    /// Insert or replace one path.
    Put {
        /// Full vault-relative path.
        path: String,
        /// New metadata.
        entry: EntryMetadata,
    },
    /// Remove one path.
    Delete {
        /// Full vault-relative path.
        path: String,
    },
}

#[derive(Serialize, Deserialize)]
struct LogBatch {
    ops: Vec<LogOp>,
}

#[derive(Serialize, Deserialize)]
struct CompactJournal {
    version: u32,
    generation: u64,
    snapshot_sha256: [u8; HASH_LEN],
}

/// Authenticated log header.
#[derive(Clone)]
struct Header {
    generation: u64,
    snapshot_sha256: [u8; HASH_LEN],
    log_id: [u8; HASH_LEN],
    bytes: Vec<u8>,
}

impl Header {
    fn new(generation: u64, snapshot_sha256: [u8; HASH_LEN]) -> Self {
        let mut log_id = [0u8; HASH_LEN];
        crypto::fill_random(&mut log_id);
        Self::with_log_id(generation, snapshot_sha256, log_id)
    }

    fn with_log_id(
        generation: u64,
        snapshot_sha256: [u8; HASH_LEN],
        log_id: [u8; HASH_LEN],
    ) -> Self {
        let mut bytes = Vec::with_capacity(HEADER_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&generation.to_le_bytes());
        bytes.extend_from_slice(&snapshot_sha256);
        bytes.extend_from_slice(&log_id);
        debug_assert_eq!(bytes.len(), HEADER_LEN);
        Self {
            generation,
            snapshot_sha256,
            log_id,
            bytes,
        }
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_LEN || &bytes[..MAGIC.len()] != MAGIC.as_slice() {
            return Err(Error::InvalidVault);
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != VERSION {
            return Err(Error::UnsupportedVersion(u32::from(version)));
        }
        let mut generation = [0u8; 8];
        generation.copy_from_slice(&bytes[10..18]);
        let mut snapshot_sha256 = [0u8; HASH_LEN];
        snapshot_sha256.copy_from_slice(&bytes[18..18 + HASH_LEN]);
        let mut log_id = [0u8; HASH_LEN];
        log_id.copy_from_slice(&bytes[18 + HASH_LEN..]);
        Ok(Self {
            generation: u64::from_le_bytes(generation),
            snapshot_sha256,
            log_id,
            bytes: bytes.to_vec(),
        })
    }
}

/// Loaded log metadata, reused when appending.
#[derive(Clone)]
pub(crate) struct LogInfo {
    /// Snapshot generation this log extends.
    pub generation: u64,
    /// Index of the next record to write.
    pub next_index: u64,
    /// Byte length of the valid, replayable prefix.
    pub valid_len: u64,
    header: Header,
}

impl LogInfo {
    /// Whether the log is large enough to justify a new snapshot.
    pub(crate) fn should_compact(&self) -> bool {
        self.next_index >= COMPACT_AFTER_RECORDS || self.valid_len >= COMPACT_AFTER_BYTES
    }
}

/// Whether a committed compaction still needs finishing.
pub(crate) fn compaction_pending(vault_dir: &Path) -> bool {
    compact_path(vault_dir).is_file()
}

/// Whether an append-only log currently exists.
#[cfg(test)]
pub(crate) fn exists(vault_dir: &Path) -> bool {
    log_path(vault_dir).is_file()
}

/// Replays the log over `files`, returning its metadata when present.
///
/// `snapshot_sha256` is the hash of the exact snapshot bytes that were just
/// decoded and `snapshot_generation` is the generation stored inside that
/// authenticated snapshot. The log header must name both; otherwise the log
/// belongs to a different index state and the caller sees
/// [`Error::InvalidVault`].
pub(crate) fn replay(
    vault_dir: &Path,
    master: &Key,
    files: &mut ManifestMap,
    snapshot_sha256: Option<&[u8; HASH_LEN]>,
    snapshot_generation: u64,
) -> Result<Option<LogInfo>> {
    if compaction_pending(vault_dir) {
        return Err(Error::Operation(
            "index compaction is pending; finish it before reading".into(),
        ));
    }

    let path = log_path(vault_dir);
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let file_len = file.metadata()?.len();
    if file_len < HEADER_LEN as u64 {
        return Err(Error::InvalidVault);
    }

    let mut header_bytes = vec![0u8; HEADER_LEN];
    file.read_exact(&mut header_bytes)
        .map_err(|_| Error::InvalidVault)?;
    let header = Header::parse(&header_bytes)?;

    let snapshot_hash = snapshot_sha256.ok_or(Error::InvalidVault)?;
    if header.snapshot_sha256 != *snapshot_hash || header.generation != snapshot_generation {
        return Err(Error::InvalidVault);
    }

    let key = log_key(master, &header.log_id);
    let mut index: u64 = 0;
    let mut valid_len = HEADER_LEN as u64;

    loop {
        let record_start = file.stream_position()?;

        let mut len_bytes = [0u8; 4];
        match file.read_exact(&mut len_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let record_len = u32::from_le_bytes(len_bytes) as usize;
        if !(NONCE_LEN + TAG_LEN..=MAX_RECORD_LEN).contains(&record_len) {
            return Err(Error::InvalidVault);
        }

        let mut record_index = [0u8; 8];
        match file.read_exact(&mut record_index) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let stored_index = u64::from_le_bytes(record_index);
        if stored_index != index {
            return Err(Error::InvalidVault);
        }

        let mut nonce = [0u8; NONCE_LEN];
        match file.read_exact(&mut nonce) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let mut ciphertext = Zeroizing::new(vec![0u8; record_len - NONCE_LEN]);
        match file.read_exact(ciphertext.as_mut()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let record_end = record_start + RECORD_PREFIX_LEN as u64 + record_len as u64;

        if crypto::open_in_place(
            &nonce,
            &mut ciphertext,
            &key,
            &record_aad(&header.bytes, index),
        )
        .is_err()
        {
            // A crash can leave the final record fully sized but unreadable.
            // Anything before the final bytes is treated as tampering.
            if record_end == file_len {
                break;
            }
            return Err(Error::Authentication);
        }

        let batch: LogBatch =
            serde_json::from_slice(ciphertext.as_slice()).map_err(|_| Error::InvalidVault)?;
        apply(files, &batch.ops);

        index += 1;
        valid_len = record_end;
    }

    Ok(Some(LogInfo {
        generation: header.generation,
        next_index: index,
        valid_len,
        header,
    }))
}

/// Appends one mutation batch, creating the log when needed.
///
/// Returns the updated metadata. A torn tail from an earlier crash is
/// truncated first, so new records are always replayable.
pub(crate) fn append(
    vault_dir: &Path,
    master: &Key,
    snapshot_sha256: &[u8; HASH_LEN],
    generation: u64,
    log: Option<&LogInfo>,
    ops: &[LogOp],
) -> Result<LogInfo> {
    if ops.is_empty() {
        return Err(Error::Operation("empty index batch".into()));
    }

    let path = log_path(vault_dir);
    let (mut file, mut info) = match log {
        Some(info) => {
            if info.header.snapshot_sha256 != *snapshot_sha256
                || info.header.generation != generation
            {
                return Err(Error::InvalidVault);
            }
            let file = OpenOptions::new().write(true).open(&path)?;
            let file_len = file.metadata()?.len();
            if file_len < info.valid_len {
                return Err(Error::InvalidVault);
            }
            let info = info.clone();
            if file_len > info.valid_len {
                // Discard a torn final record left by a crash.
                file.set_len(info.valid_len)?;
                file.sync_data()?;
            }
            (file, info)
        }
        None => {
            if path.exists() {
                return Err(Error::InvalidVault);
            }
            let header = Header::new(generation, *snapshot_sha256);
            fsutil::atomic_write(&path, &header.bytes)?;
            let file = OpenOptions::new().write(true).open(&path)?;
            let info = LogInfo {
                generation,
                next_index: 0,
                valid_len: HEADER_LEN as u64,
                header,
            };
            (file, info)
        }
    };

    let key = log_key(master, &info.header.log_id);
    let mut plaintext = Zeroizing::new(
        serde_json::to_vec(&LogBatch { ops: ops.to_vec() }).map_err(|_| Error::Encryption)?,
    );
    if plaintext.len() > MAX_BATCH_LEN {
        return Err(Error::Encryption);
    }

    let nonce = crypto::random_nonce();
    crypto::seal_in_place(
        &nonce,
        &mut plaintext,
        &key,
        &record_aad(&info.header.bytes, info.next_index),
    )?;

    let record_len = NONCE_LEN + plaintext.len();
    let mut record = Vec::with_capacity(RECORD_PREFIX_LEN + record_len);
    record.extend_from_slice(&(record_len as u32).to_le_bytes());
    record.extend_from_slice(&info.next_index.to_le_bytes());
    record.extend_from_slice(&nonce);
    record.extend_from_slice(plaintext.as_slice());

    file.seek(SeekFrom::Start(info.valid_len))?;
    file.write_all(&record)?;
    file.sync_data()?;

    info.next_index += 1;
    info.valid_len += record.len() as u64;
    Ok(info)
}

/// Writes a new snapshot and replaces the log with an empty one.
///
/// `snapshot` must be the encoded `.manifest.enc` container for `files`.
/// Callers are expected to run this under the exclusive vault lock and to
/// resolve any previous compaction with [`recover`] first.
pub(crate) fn compact(vault_dir: &Path, snapshot: &[u8], generation: u64) -> Result<()> {
    let snapshot_sha256 = digest(snapshot);
    fsutil::atomic_write(&next_snapshot_path(vault_dir), snapshot)?;

    let header = Header::new(generation, snapshot_sha256);
    fsutil::atomic_write(&next_log_path(vault_dir), &header.bytes)?;

    let journal = CompactJournal {
        version: 1,
        generation,
        snapshot_sha256,
    };
    let json = serde_json::to_vec(&journal).map_err(|_| Error::InvalidVault)?;

    // Commit point: from here the snapshot/log pair is authoritative.
    fsutil::atomic_write(&compact_path(vault_dir), &json)?;

    fs::rename(next_snapshot_path(vault_dir), manifest::path(vault_dir))?;
    fsutil::sync_dir(&vault_dir.join("d"));

    fsutil::remove_file_if_exists(&log_path(vault_dir))?;
    fs::rename(next_log_path(vault_dir), log_path(vault_dir))?;
    fsutil::sync_dir(&vault_dir.join("d"));

    fsutil::remove_file_if_exists(&compact_path(vault_dir))?;
    Ok(())
}

/// Completes or discards a compaction interrupted by a crash.
///
/// Safe to call with no journal. Callers must hold the exclusive vault lock.
pub(crate) fn recover(vault_dir: &Path) -> Result<()> {
    let marker = compact_path(vault_dir);
    let json = match fs::read_to_string(&marker) {
        Ok(json) => json,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // No committed compaction: staged files are orphans.
            let _ = fs::remove_file(next_log_path(vault_dir));
            let _ = fs::remove_file(next_snapshot_path(vault_dir));
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let journal: CompactJournal = serde_json::from_str(&json).map_err(|_| Error::InvalidVault)?;
    if journal.version != 1 {
        return Err(Error::UnsupportedVersion(journal.version));
    }

    let canonical = manifest::path(vault_dir);
    let next_snapshot = next_snapshot_path(vault_dir);
    let canonical_matches = file_sha256(&canonical).as_ref() == Some(&journal.snapshot_sha256);
    let next_matches = file_sha256(&next_snapshot).as_ref() == Some(&journal.snapshot_sha256);

    if next_matches && !canonical_matches {
        fs::rename(&next_snapshot, &canonical)?;
        fsutil::sync_dir(&vault_dir.join("d"));
    } else if !canonical_matches {
        // Neither snapshot matches the journal. Leave the evidence in place.
        return Err(Error::InvalidVault);
    }

    // The snapshot is now authoritative; the old log cannot extend it. If the
    // canonical log already names the new snapshot/generation, a previous run
    // installed it and only cleanup is left.
    let canonical_log = log_path(vault_dir);
    let next_log = next_log_path(vault_dir);
    if log_matches(&canonical_log, &journal) {
        fsutil::remove_file_if_exists(&next_log)?;
    } else {
        fsutil::remove_file_if_exists(&canonical_log)?;
        if next_log.is_file() {
            let mut header_bytes = vec![0u8; HEADER_LEN];
            let mut file = File::open(&next_log)?;
            file.read_exact(&mut header_bytes)
                .map_err(|_| Error::InvalidVault)?;
            let header = Header::parse(&header_bytes)?;
            if header.snapshot_sha256 != journal.snapshot_sha256
                || header.generation != journal.generation
            {
                return Err(Error::InvalidVault);
            }
            fs::rename(&next_log, &canonical_log)?;
            fsutil::sync_dir(&vault_dir.join("d"));
        }
    }

    // The staged snapshot is now either canonical or stale.
    fsutil::remove_file_if_exists(&next_snapshot)?;
    fsutil::remove_file_if_exists(&marker)?;
    Ok(())
}

/// Removes the log and any staged compaction state.
///
/// Used by deep rotation and migration, where the old log is encrypted under a
/// master key that no longer belongs to the installed index.
pub(crate) fn remove_all(vault_dir: &Path) -> Result<()> {
    fsutil::remove_file_if_exists(&log_path(vault_dir))?;
    fsutil::remove_file_if_exists(&next_log_path(vault_dir))?;
    fsutil::remove_file_if_exists(&next_snapshot_path(vault_dir))?;
    fsutil::remove_file_if_exists(&compact_path(vault_dir))?;
    Ok(())
}

fn apply(files: &mut ManifestMap, ops: &[LogOp]) {
    for op in ops {
        match op {
            LogOp::Put { path, entry } => {
                files.insert(path.clone(), entry.clone());
            }
            LogOp::Delete { path } => {
                files.remove(path);
            }
        }
    }
}

fn log_key(master: &Key, log_id: &[u8; HASH_LEN]) -> Key {
    crypto::derive_subkey(master, log_id, b"keres-vault-index-log-v1")
}

fn record_aad(header: &[u8], index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(20 + header.len() + 8);
    aad.extend_from_slice(b"keres-index-log-v1");
    aad.extend_from_slice(header);
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

/// SHA-256 of a snapshot, binding a log to exactly one snapshot.
pub(crate) fn digest(bytes: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn file_sha256(path: &Path) -> Option<[u8; HASH_LEN]> {
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).ok()?;
    Some(hasher.finalize().into())
}

/// Whether `path` holds a log header naming the journal's snapshot/generation.
fn log_matches(path: &Path, journal: &CompactJournal) -> bool {
    let mut bytes = vec![0u8; HEADER_LEN];
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    if file.read_exact(&mut bytes).is_err() {
        return false;
    }
    match Header::parse(&bytes) {
        Ok(header) => {
            header.snapshot_sha256 == journal.snapshot_sha256
                && header.generation == journal.generation
        }
        Err(_) => false,
    }
}

fn log_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join("d").join(LOG_FILE)
}

fn next_log_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join("d").join(NEXT_LOG_FILE)
}

fn next_snapshot_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join("d").join(NEXT_SNAPSHOT_FILE)
}

fn compact_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join("d").join(COMPACT_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::manifest;

    fn temp_vault() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("d")).unwrap();
        tmp
    }

    fn entry(name: &str) -> EntryMetadata {
        EntryMetadata {
            id: format!("id-{name}"),
            original_name: name.into(),
            original_size: 1,
            is_directory: false,
            children: None,
            content_hash: None,
        }
    }

    fn put(name: &str) -> LogOp {
        LogOp::Put {
            path: name.into(),
            entry: entry(name),
        }
    }

    fn replay_all(
        dir: &Path,
        master: &Key,
        snapshot: &[u8],
        generation: u64,
    ) -> Result<(ManifestMap, Option<LogInfo>)> {
        let mut files = ManifestMap::new();
        let hash = digest(snapshot);
        let info = replay(dir, master, &mut files, Some(&hash), generation)?;
        Ok((files, info))
    }

    #[test]
    fn put_and_delete_batches_replay_in_order() {
        let tmp = temp_vault();
        let dir = tmp.path();
        let master = Key::generate();
        let snapshot = b"snapshot-one";
        let hash = digest(snapshot);

        let info = append(dir, &master, &hash, 7, None, &[put("a"), put("b")]).unwrap();
        assert_eq!(info.next_index, 1);
        let info = append(
            dir,
            &master,
            &hash,
            7,
            Some(&info),
            &[LogOp::Delete { path: "a".into() }, put("c")],
        )
        .unwrap();
        assert_eq!(info.next_index, 2);

        let (files, info) = replay_all(dir, &master, snapshot, 7).unwrap();
        let info = info.unwrap();
        assert_eq!(info.generation, 7);
        assert_eq!(info.next_index, 2);
        assert!(!files.contains_key("a"));
        assert!(files.contains_key("b"));
        assert!(files.contains_key("c"));
    }

    #[test]
    fn log_is_bound_to_one_snapshot_and_generation() {
        let tmp = temp_vault();
        let dir = tmp.path();
        let master = Key::generate();
        let snapshot = b"snapshot-one";
        let hash = digest(snapshot);
        let info = append(dir, &master, &hash, 3, None, &[put("a")]).unwrap();

        // A different snapshot cannot replay this log.
        let mut files = ManifestMap::new();
        let other = digest(b"snapshot-two");
        assert!(matches!(
            replay(dir, &master, &mut files, Some(&other), 3),
            Err(Error::InvalidVault)
        ));

        // The snapshot must also carry the same generation.
        assert!(matches!(
            replay(dir, &master, &mut files, Some(&hash), 4),
            Err(Error::InvalidVault)
        ));

        // Appends must name the same snapshot and generation.
        assert!(matches!(
            append(dir, &master, &other, 3, Some(&info), &[put("b")]),
            Err(Error::InvalidVault)
        ));
        assert!(matches!(
            append(dir, &master, &hash, 4, Some(&info), &[put("b")]),
            Err(Error::InvalidVault)
        ));
    }

    #[test]
    fn wrong_master_key_is_an_authentication_error() {
        let tmp = temp_vault();
        let dir = tmp.path();
        let master = Key::generate();
        let snapshot = b"snapshot";
        let hash = digest(snapshot);
        let info = append(dir, &master, &hash, 1, None, &[put("a")]).unwrap();
        // A second record makes the first failure provably tampering rather
        // than a crash-torn final write. (On its own, a single unreadable
        // final record is indistinguishable from a torn append; the snapshot
        // is authenticated first in every real load path.)
        append(dir, &master, &hash, 1, Some(&info), &[put("b")]).unwrap();

        let mut files = ManifestMap::new();
        assert!(matches!(
            replay(dir, &Key::generate(), &mut files, Some(&hash), 1),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn a_torn_final_record_is_ignored_and_truncated() {
        let tmp = temp_vault();
        let dir = tmp.path();
        let master = Key::generate();
        let snapshot = b"snapshot";
        let hash = digest(snapshot);
        let info = append(dir, &master, &hash, 1, None, &[put("a")]).unwrap();

        // Simulate a crash halfway through the next record's write.
        let mut file = OpenOptions::new().append(true).open(log_path(dir)).unwrap();
        file.write_all(&[0x40, 0x00, 0x00, 0x00, 0x01]).unwrap();
        file.sync_data().unwrap();
        drop(file);

        let (files, info2) = replay_all(dir, &master, snapshot, 1).unwrap();
        let info2 = info2.unwrap();
        assert_eq!(info2.valid_len, info.valid_len);
        assert!(files.contains_key("a"));

        // The next append discards the torn tail before writing.
        let info3 = append(dir, &master, &hash, 1, Some(&info2), &[put("b")]).unwrap();
        assert_eq!(info3.next_index, 2);
        assert_eq!(
            std::fs::metadata(log_path(dir)).unwrap().len(),
            info3.valid_len
        );

        let (files, _) = replay_all(dir, &master, snapshot, 1).unwrap();
        assert!(files.contains_key("a"));
        assert!(files.contains_key("b"));
    }

    #[test]
    fn tampering_with_a_middle_record_is_fatal() {
        let tmp = temp_vault();
        let dir = tmp.path();
        let master = Key::generate();
        let snapshot = b"snapshot";
        let hash = digest(snapshot);
        let info = append(dir, &master, &hash, 1, None, &[put("a")]).unwrap();
        append(dir, &master, &hash, 1, Some(&info), &[put("b")]).unwrap();

        // Flip the last byte (part of the AEAD tag) of the first record.
        let mut bytes = std::fs::read(log_path(dir)).unwrap();
        let first_len = u32::from_le_bytes([
            bytes[HEADER_LEN],
            bytes[HEADER_LEN + 1],
            bytes[HEADER_LEN + 2],
            bytes[HEADER_LEN + 3],
        ]) as usize;
        let first_end = HEADER_LEN + RECORD_PREFIX_LEN + first_len;
        assert!(
            first_end < bytes.len(),
            "need a record after the tampered one"
        );
        bytes[first_end - 1] ^= 0xff;
        std::fs::write(log_path(dir), bytes).unwrap();

        let mut files = ManifestMap::new();
        assert!(matches!(
            replay(dir, &master, &mut files, Some(&hash), 1),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn compaction_installs_a_fresh_snapshot_and_empty_log() {
        let tmp = temp_vault();
        let dir = tmp.path();
        let master = Key::generate();
        let old_snapshot = b"old-snapshot";
        let hash = digest(old_snapshot);
        let info = append(dir, &master, &hash, 4, None, &[put("a")]).unwrap();
        append(dir, &master, &hash, 4, Some(&info), &[put("b")]).unwrap();

        let new_snapshot = b"new-snapshot";
        compact(dir, new_snapshot, 5).unwrap();

        assert_eq!(std::fs::read(manifest::path(dir)).unwrap(), new_snapshot);
        assert_eq!(
            std::fs::metadata(log_path(dir)).unwrap().len(),
            HEADER_LEN as u64
        );
        assert!(!compaction_pending(dir));

        let (files, info) = replay_all(dir, &master, new_snapshot, 5).unwrap();
        let info = info.unwrap();
        assert_eq!(info.generation, 5);
        assert_eq!(info.next_index, 0);
        assert!(files.is_empty());
    }

    #[test]
    fn recovers_a_committed_compaction() {
        let tmp = temp_vault();
        let dir = tmp.path();
        let master = Key::generate();
        let old_snapshot = b"old-snapshot";
        fsutil::atomic_write(&manifest::path(dir), old_snapshot).unwrap();
        let hash = digest(old_snapshot);
        append(dir, &master, &hash, 1, None, &[put("a")]).unwrap();

        // Stage exactly what `compact` writes before its recovery steps run.
        let new_snapshot = b"new-snapshot";
        fsutil::atomic_write(&next_snapshot_path(dir), new_snapshot).unwrap();
        let header = Header::new(2, digest(new_snapshot));
        fsutil::atomic_write(&next_log_path(dir), &header.bytes).unwrap();
        let journal = serde_json::to_vec(&CompactJournal {
            version: 1,
            generation: 2,
            snapshot_sha256: digest(new_snapshot),
        })
        .unwrap();
        fsutil::atomic_write(&compact_path(dir), &journal).unwrap();

        assert!(compaction_pending(dir));
        recover(dir).unwrap();

        assert!(!compaction_pending(dir));
        assert_eq!(std::fs::read(manifest::path(dir)).unwrap(), new_snapshot);
        let (files, info) = replay_all(dir, &master, new_snapshot, 2).unwrap();
        assert!(files.is_empty());
        assert_eq!(info.unwrap().generation, 2);
    }

    #[test]
    fn uncommitted_compaction_files_are_discarded() {
        let tmp = temp_vault();
        let dir = tmp.path();
        let snapshot = b"canonical";
        fsutil::atomic_write(&manifest::path(dir), snapshot).unwrap();
        fsutil::atomic_write(&next_snapshot_path(dir), b"staged").unwrap();
        fsutil::atomic_write(&next_log_path(dir), &[0u8; HEADER_LEN]).unwrap();

        recover(dir).unwrap();

        assert_eq!(std::fs::read(manifest::path(dir)).unwrap(), snapshot);
        assert!(!next_snapshot_path(dir).exists());
        assert!(!next_log_path(dir).exists());
    }

    /// Stages a compaction journal plus its files, leaving the crash point to
    /// the caller.
    fn stage_compaction(dir: &Path, old_snapshot: &[u8], new_snapshot: &[u8]) {
        fsutil::atomic_write(&manifest::path(dir), old_snapshot).unwrap();
        let header = Header::new(2, digest(new_snapshot));
        fsutil::atomic_write(&next_snapshot_path(dir), new_snapshot).unwrap();
        fsutil::atomic_write(&next_log_path(dir), &header.bytes).unwrap();
        let journal = serde_json::to_vec(&CompactJournal {
            version: 1,
            generation: 2,
            snapshot_sha256: digest(new_snapshot),
        })
        .unwrap();
        fsutil::atomic_write(&compact_path(dir), &journal).unwrap();
    }

    #[test]
    fn recovers_after_the_snapshot_rename_but_before_log_cleanup() {
        let tmp = temp_vault();
        let dir = tmp.path();
        let master = Key::generate();
        let old_snapshot = b"old-snapshot";
        let new_snapshot = b"new-snapshot";
        stage_compaction(dir, old_snapshot, new_snapshot);
        // An old log with records is still the canonical log.
        let old_hash = digest(old_snapshot);
        append(dir, &master, &old_hash, 1, None, &[put("a")]).unwrap();
        // Crash point: the snapshot was already promoted.
        fsutil::atomic_write(&manifest::path(dir), new_snapshot).unwrap();

        recover(dir).unwrap();

        assert_eq!(std::fs::read(manifest::path(dir)).unwrap(), new_snapshot);
        let (files, info) = replay_all(dir, &master, new_snapshot, 2).unwrap();
        assert!(files.is_empty());
        assert_eq!(info.unwrap().next_index, 0);
        assert!(!compact_path(dir).exists());
    }

    #[test]
    fn recovers_after_old_log_removal_but_before_staged_log_install() {
        let tmp = temp_vault();
        let dir = tmp.path();
        let master = Key::generate();
        let old_snapshot = b"old-snapshot";
        let new_snapshot = b"new-snapshot";
        stage_compaction(dir, old_snapshot, new_snapshot);
        // Crash point: snapshot promoted and the old log removed; the staged
        // log has not been renamed yet.
        fsutil::atomic_write(&manifest::path(dir), new_snapshot).unwrap();

        recover(dir).unwrap();

        assert!(log_path(dir).is_file());
        assert!(!next_log_path(dir).exists());
        assert!(!compact_path(dir).exists());
        let (_, info) = replay_all(dir, &master, new_snapshot, 2).unwrap();
        let info = info.unwrap();
        assert_eq!(info.generation, 2);

        // The installed log accepts new records under the same generation.
        let hash = digest(new_snapshot);
        append(dir, &master, &hash, 2, Some(&info), &[put("b")]).unwrap();
        let (files, _) = replay_all(dir, &master, new_snapshot, 2).unwrap();
        assert!(files.contains_key("b"));
    }

    #[test]
    fn recovers_after_staged_log_install_but_before_journal_removal() {
        let tmp = temp_vault();
        let dir = tmp.path();
        let master = Key::generate();
        let old_snapshot = b"old-snapshot";
        let new_snapshot = b"new-snapshot";
        stage_compaction(dir, old_snapshot, new_snapshot);
        // Crash point: everything is installed, only the journal remains.
        fsutil::atomic_write(&manifest::path(dir), new_snapshot).unwrap();
        fs::rename(next_log_path(dir), log_path(dir)).unwrap();
        fsutil::remove_file_if_exists(&next_snapshot_path(dir)).unwrap();

        recover(dir).unwrap();

        assert!(!compact_path(dir).exists());
        // The already-installed log is kept, so appends continue in place.
        let (files, info) = replay_all(dir, &master, new_snapshot, 2).unwrap();
        assert!(files.is_empty());
        let info = info.unwrap();
        assert_eq!(info.generation, 2);
        let hash = digest(new_snapshot);
        append(dir, &master, &hash, 2, Some(&info), &[put("a")]).unwrap();
        let (files, _) = replay_all(dir, &master, new_snapshot, 2).unwrap();
        assert!(files.contains_key("a"));
    }

    #[test]
    fn compaction_thresholds_are_bounded() {
        let header = Header::new(1, [0u8; HASH_LEN]);
        let small = LogInfo {
            generation: 1,
            next_index: 1,
            valid_len: HEADER_LEN as u64,
            header: header.clone(),
        };
        assert!(!small.should_compact());

        let many = LogInfo {
            generation: 1,
            next_index: COMPACT_AFTER_RECORDS,
            valid_len: HEADER_LEN as u64,
            header: header.clone(),
        };
        assert!(many.should_compact());

        let large = LogInfo {
            generation: 1,
            next_index: 1,
            valid_len: COMPACT_AFTER_BYTES,
            header,
        };
        assert!(large.should_compact());
    }
}
