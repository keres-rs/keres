//! Vault key management: password-derived KEK wrapping a random master key.
//!
//! The master key is generated once at `init` and never changes; changing
//! the password only re-wraps it. The unwrapped master key lives exclusively
//! in zeroizing memory and is handed out by reference.
//!
//! The on-disk config is a small JSON document (not a container): it must be
//! readable before any key exists — the bootstrap of the whole hierarchy.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::kdf::KdfParams;

/// Current config schema version.
pub(crate) const CONFIG_VERSION: u32 = 2;

/// On-disk vault config: KDF parameters plus the wrapped master key.
#[derive(Serialize, Deserialize)]
pub(crate) struct VaultConfig {
    pub version: u32,
    pub kdf: KdfParams,
    pub salt: Vec<u8>,
    pub wrapped_master_key: Vec<u8>,
}

pub(crate) const VAULT_CONFIG_AAD: &[u8] = b"keres-vault-config-v2";

/// Fixed nonce for the config blob.
///
/// Acceptable because the KEK is unique per vault (fresh random salt) and
/// this exact (key, nonce) pair encrypts exactly one short message ever.
fn config_nonce() -> [u8; 12] {
    let mut n = [0xFFu8; 12];
    n[0] = 0x01;
    n
}

impl VaultConfig {
    pub(crate) fn parse(json: &str) -> Result<Self> {
        let config: VaultConfig = serde_json::from_str(json).map_err(|_| Error::InvalidVault)?;
        if config.version != CONFIG_VERSION {
            return Err(Error::UnsupportedVersion(config.version));
        }
        Ok(config)
    }

    /// Unwraps the master key with a password-derived KEK.
    ///
    /// Authentication failure reports [`Error::Authentication`] without
    /// distinguishing wrong password from tampered config.
    pub(crate) fn unwrap_master_key(&self, password: &str) -> Result<Key> {
        if self.salt.len() < 8 {
            return Err(Error::InvalidVault);
        }
        let kek = crypto::derive_key(password.as_bytes(), &self.salt, self.kdf)?;

        let mut combined = Zeroizing::new(self.wrapped_master_key.clone());
        crypto::open_in_place(&config_nonce(), &mut combined, &kek, VAULT_CONFIG_AAD)?;

        if combined.len() != 32 {
            return Err(Error::InvalidVault);
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(combined.as_slice());
        Ok(Key::from_bytes(key_bytes))
    }
}

/// In-memory unlocked state of a vault.
#[derive(Default)]
pub(crate) struct KeyStore {
    master_key: Option<Key>,
}

impl KeyStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    pub(crate) fn master_key(&self) -> Result<&Key> {
        self.master_key.as_ref().ok_or(Error::VaultLocked)
    }

    /// Creates a fresh master key wrapped under `password`.
    pub(crate) fn init(&mut self, password: &str) -> Result<VaultConfig> {
        let master = Key::generate();
        let config = wrap_for_password(&master, password)?;
        self.master_key = Some(master);
        Ok(config)
    }

    /// Unlocks using the parsed config.
    pub(crate) fn unlock(&mut self, password: &str, config: &VaultConfig) -> Result<()> {
        if self.is_unlocked() {
            return Err(Error::VaultUnlocked);
        }
        let master = config.unwrap_master_key(password)?;
        self.master_key = Some(master);
        Ok(())
    }

    pub(crate) fn lock(&mut self) {
        self.master_key = None; // Key zeroizes on drop
    }

    /// Re-wraps the master key under a new password.
    ///
    /// Requires an unlocked vault; callers must independently prove knowledge
    /// of the old password (see [`crate::Vault::change_password`]). The
    /// master key itself never changes.
    pub(crate) fn rotate_password(&mut self, new: &str) -> Result<VaultConfig> {
        let master = self.master_key()?.clone();
        wrap_for_password(&master, new)
    }
}

/// Wraps `master` under a fresh password-derived KEK with a fresh salt.
fn wrap_for_password(master: &Key, password: &str) -> Result<VaultConfig> {
    let mut salt = [0u8; 32];
    crypto::fill_random(&mut salt);
    let params = KdfParams::new();
    let kek = crypto::derive_key(password.as_bytes(), &salt, params)?;

    // Zeroizing: the buffer holds the raw master key until sealed in place,
    // and must be scrubbed when it goes out of scope.
    let mut buf = Zeroizing::new(master.expose().to_vec());
    crypto::seal_in_place(&config_nonce(), &mut buf, &kek, VAULT_CONFIG_AAD)?;

    Ok(VaultConfig {
        version: CONFIG_VERSION,
        kdf: params,
        salt: salt.to_vec(),
        wrapped_master_key: buf.to_vec(),
    })
}
