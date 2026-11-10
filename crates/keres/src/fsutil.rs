//! Filesystem helpers: atomic writes, durability and permission hardening.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::{crypto, error::Error};

/// Builds a unique temp path next to `target` (same directory, so `rename`
/// stays atomic on all platforms).
pub(crate) fn sibling_temp_path(target: &Path) -> PathBuf {
    let dir = target.parent().map(Path::to_path_buf).unwrap_or_default();
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "keres-out".into());
    let rnd = crypto::random_nonce();
    dir.join(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        hex_prefix(&rnd)
    ))
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// Writes `bytes` to `path` atomically.
///
/// The data is written to a temporary file in the same directory, flushed to
/// disk, and then renamed over the target path. A crash mid-write therefore
/// leaves either the old or the new file intact — never a truncated mix. This
/// is critical for the vault config and manifest: losing them bricks the
/// entire vault.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.parent().is_none() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "target has no parent directory",
        )));
    }

    let tmp = sibling_temp_path(path);

    let write_result = (|| -> Result<()> {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        restrict_perms(&tmp);
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        // `rename` replaces an existing destination on Unix and Windows
        // (Windows uses MoveFileEx with MOVEFILE_REPLACE_EXISTING), so the
        // old file is never deleted ahead of the new one.
        fs::rename(&tmp, path)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    } else {
        sync_dir(path.parent().expect("checked above"));
    }
    write_result
}

/// Best-effort directory fsync so renames are durable across power loss.
pub(crate) fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Restricts permissions of a newly created file to owner-only on Unix.
///
/// No-op on other platforms. Best-effort: failures are ignored because the
/// caller may legitimately be writing into a filesystem that does not support
/// POSIX permissions.
pub(crate) fn restrict_perms(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Restricts permissions of a newly created directory to owner-only on Unix.
pub(crate) fn restrict_dir_perms(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Creates a directory (and parents) with hardened permissions on Unix.
pub(crate) fn create_private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
        restrict_dir_perms(path);
    }
    Ok(())
}

/// Removes a file if it exists; missing files are not an error here.
pub(crate) fn remove_file_if_exists(path: &PathBuf) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
