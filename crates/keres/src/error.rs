use core::fmt;

/// Errors returned by keres operations.
///
/// Variants are deliberately coarse-grained: cryptographic failures never
/// reveal whether the password was wrong or the data was tampered with, and
/// internal details (key material, paths inside the vault) are never included
/// in error text.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying filesystem I/O failed.
    #[error("io error")]
    Io(#[from] std::io::Error),

    /// The container header is malformed or truncated.
    #[error("invalid or corrupted container header")]
    InvalidHeader,

    /// The container format version is not supported by this build.
    #[error("unsupported container version: {0}")]
    UnsupportedVersion(u32),

    /// The file uses a retired pre-0.4 keres format. Re-encrypt or
    /// extract it with a pre-rename Krypton release; no retired reader
    /// remains.
    #[error("file uses a retired keres format")]
    RetiredFormat,

    /// AEAD authentication failed — wrong password, corrupted data, or
    /// deliberate tampering.
    #[error("authentication failed: wrong password or corrupted data")]
    Authentication,

    /// Symmetric encryption failed.
    #[error("encryption failed")]
    Encryption,

    /// Argon2id key derivation failed.
    #[error("key derivation failed")]
    KeyDerivation,

    /// KDF parameters are outside the accepted safety bounds.
    #[error("invalid KDF parameters")]
    InvalidKdfParams,

    /// A vault-level structure could not be parsed.
    #[error("invalid vault structure")]
    InvalidVault,

    /// The vault has already been initialized.
    #[error("vault already initialized")]
    VaultExists,

    /// The vault does not exist or is missing required structures.
    #[error("vault not found")]
    VaultNotFound,

    /// The operation requires an unlocked vault.
    #[error("vault is locked")]
    VaultLocked,

    /// The vault is already unlocked.
    #[error("vault already unlocked")]
    VaultUnlocked,

    /// An entry name violates naming rules (empty, too long, path separators,
    /// `..` components).
    #[error("invalid entry name: {0}")]
    InvalidEntryName(String),

    /// The requested entry does not exist in the vault.
    #[error("entry not found: {0}")]
    EntryNotFound(String),

    /// An entry with this name already exists.
    #[error("entry already exists: {0}")]
    EntryExists(String),

    /// Serialization/deserialization of an encrypted structure failed after
    /// successful decryption.
    #[error("malformed decrypted payload")]
    MalformedPayload,

    /// A user-level operation could not be performed (e.g. password
    /// confirmation mismatch).
    #[error("{0}")]
    Operation(String),
}

impl Error {
    /// Convenience constructor for [`Error::InvalidEntryName`].
    pub(crate) fn invalid_name(name: impl fmt::Display) -> Self {
        // Only report a redacted preview; never echo arbitrary attacker
        // controlled bytes at full length.
        let s = name.to_string();
        let preview: String = s.chars().take(32).collect();
        Error::InvalidEntryName(preview)
    }
}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
