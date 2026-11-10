//! Advisory locks that serialize access to a vault directory.
//!
//! Locks are implemented with `flock(2)` on Unix and `LockFileEx` on Windows
//! through [`fs4`]. They are advisory: every Keres process takes them, but
//! another program can still edit the files directly.
//!
//! The lock file lives at `vault.lock` in the vault root. It carries no
//! plaintext and is never encrypted; its only job is to make concurrent
//! writers fail fast instead of racing on the manifest.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use fs4::FileExt;

use crate::error::{Error, Result};

/// Name of the lock file inside the vault directory.
pub(crate) const LOCK_FILE: &str = "vault.lock";

/// An acquired advisory lock. Released when dropped.
pub(crate) struct VaultLock {
    file: File,
}

impl VaultLock {
    /// Attempts to take an exclusive lock, failing immediately if another
    /// process holds any lock.
    pub(crate) fn exclusive(vault_dir: &Path) -> Result<Self> {
        Self::acquire(vault_dir, Mode::Exclusive)
    }

    /// Attempts to take a shared lock, failing immediately if another process
    /// holds an exclusive lock.
    pub(crate) fn shared(vault_dir: &Path) -> Result<Self> {
        Self::acquire(vault_dir, Mode::Shared)
    }

    fn acquire(vault_dir: &Path, mode: Mode) -> Result<Self> {
        let path = lock_path(vault_dir);

        // The vault directory is private, but never follow a planted symlink:
        // otherwise locking (or chmod on) `vault.lock` could touch an
        // unrelated file.
        match path.symlink_metadata() {
            Ok(meta) if meta.file_type().is_symlink() => return Err(Error::InvalidVault),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        crate::fsutil::restrict_perms(&path);

        let result = match mode {
            Mode::Exclusive => FileExt::try_lock(&file),
            Mode::Shared => FileExt::try_lock_shared(&file),
        };

        match result {
            Ok(()) => Ok(Self { file }),
            Err(fs4::TryLockError::WouldBlock) => Err(Error::VaultBusy),
            Err(fs4::TryLockError::Error(e)) => Err(e.into()),
        }
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        // Closing the handle also releases the lock; unlocking explicitly keeps
        // the intent clear and works on every supported platform.
        let _ = FileExt::unlock(&self.file);
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Shared,
    Exclusive,
}

/// Path of the advisory lock file for `vault_dir`.
pub(crate) fn lock_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(LOCK_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_locks_coexist() {
        let dir = tempfile::tempdir().unwrap();
        let _a = VaultLock::shared(dir.path()).unwrap();
        assert!(VaultLock::shared(dir.path()).is_ok());
    }

    #[test]
    fn exclusive_lock_rejects_other_writers_and_readers() {
        let dir = tempfile::tempdir().unwrap();
        let held = VaultLock::exclusive(dir.path()).unwrap();

        assert!(matches!(
            VaultLock::exclusive(dir.path()),
            Err(Error::VaultBusy)
        ));
        assert!(matches!(
            VaultLock::shared(dir.path()),
            Err(Error::VaultBusy)
        ));

        drop(held);
        assert!(VaultLock::exclusive(dir.path()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"not a lock").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(LOCK_FILE)).unwrap();

        assert!(matches!(
            VaultLock::exclusive(dir.path()),
            Err(Error::InvalidVault)
        ));
    }

    #[test]
    fn shared_lock_rejects_writers() {
        let dir = tempfile::tempdir().unwrap();
        let held = VaultLock::shared(dir.path()).unwrap();

        assert!(matches!(
            VaultLock::exclusive(dir.path()),
            Err(Error::VaultBusy)
        ));

        drop(held);
        assert!(VaultLock::exclusive(dir.path()).is_ok());
    }
}
