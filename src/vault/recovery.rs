//! Printable recovery kits: a second wrapped copy of the master key.
//!
//! A kit stores the master key wrapped under a key derived from a random
//! 160-bit recovery code. The wrapped copy lives in `vault.recovery`, next to
//! `vault.config`, so losing or corrupting either file does not brick the
//! vault. The printable code is never stored; keep it offline and separate
//! from the vault directory.
//!
//! The code is encoded with Crockford Base32 and a 16-bit checksum. It is a
//! high-entropy secret, not a password: Argon2id still raises the cost of an
//! offline guess, but no human-memorable input is involved.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::kdf::KdfParams;

/// Wrapped-master file stored beside `vault.config`.
const RECOVERY_FILE: &str = "vault.recovery";
/// Current recovery-file schema version.
const RECOVERY_VERSION: u32 = 1;
/// AAD binding the wrapped master to this purpose.
const RECOVERY_AAD: &[u8] = b"keres-vault-recovery-v1";
/// Recovery secret length in bytes (160 bits).
const SECRET_LEN: usize = 20;
/// Checksum length in bytes.
const CHECKSUM_LEN: usize = 2;
/// Secret plus checksum, in bytes.
const PAYLOAD_LEN: usize = SECRET_LEN + CHECKSUM_LEN;
/// Base32 symbols needed for the payload (zero-padded to a symbol boundary).
const SYMBOL_LEN: usize = (PAYLOAD_LEN * 8).div_ceil(5);
/// Crockford Base32: excludes `I`, `L`, `O`, and `U` to avoid ambiguity.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A printable recovery code.
///
/// The value is zeroized on drop and its [`fmt::Debug`] output is redacted;
/// use [`RecoveryCode::expose`] to show it to the user.
pub struct RecoveryCode(Zeroizing<String>);

impl RecoveryCode {
    /// The printable code, including its group separators.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    fn from_secret(secret: &[u8]) -> Self {
        let mut payload = Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN));
        payload.extend_from_slice(secret);
        payload.extend_from_slice(&checksum(secret));
        Self(Zeroizing::new(group(&encode_base32(&payload))))
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCode([REDACTED])")
    }
}

/// On-disk recovery file. Not a container: it must be parseable before any
/// key exists, exactly like `vault.config`.
#[derive(Serialize, Deserialize)]
struct RecoveryFile {
    version: u32,
    kdf: KdfParams,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    wrapped_master_key: Vec<u8>,
}

/// Creates (or replaces) the recovery kit and returns the printable code.
pub(crate) fn create(vault_dir: &Path, master: &Key) -> Result<RecoveryCode> {
    let secret = generate_secret();
    let code = RecoveryCode::from_secret(&secret[..]);

    let mut salt = [0u8; crypto::SALT_LEN];
    crypto::fill_random(&mut salt);
    let params = KdfParams::new();
    let kek = crypto::derive_key(&secret[..], &salt, params)?;
    let (nonce, wrapped) = crypto::seal(master.expose(), &kek, RECOVERY_AAD)?;

    let file = RecoveryFile {
        version: RECOVERY_VERSION,
        kdf: params,
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        wrapped_master_key: wrapped,
    };
    let json = serde_json::to_vec_pretty(&file).map_err(|_| Error::Encryption)?;
    crate::fsutil::atomic_write(&recovery_path(vault_dir), &json)?;

    Ok(code)
}

/// Unwraps the master key using a printed recovery code.
pub(crate) fn unlock(vault_dir: &Path, code: &str) -> Result<Key> {
    let file = load(vault_dir)?;
    let secret = normalize(code)?;
    let kek = crypto::derive_key(&secret[..], &file.salt, file.kdf)?;

    let nonce: [u8; crypto::NONCE_LEN] = file
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidVault)?;
    let plain = crypto::open(&file.wrapped_master_key, &nonce, &kek, RECOVERY_AAD)?;
    if plain.len() != crypto::KEY_LEN {
        return Err(Error::InvalidVault);
    }

    let mut bytes = [0u8; crypto::KEY_LEN];
    bytes.copy_from_slice(&plain);
    Ok(Key::from_bytes(bytes))
}

/// Removes the recovery file, consuming the kit.
pub(crate) fn remove(vault_dir: &Path) -> Result<()> {
    crate::fsutil::remove_file_if_exists(&recovery_path(vault_dir))
}

/// Whether this vault has a recovery kit on disk.
pub(crate) fn exists(vault_dir: &Path) -> bool {
    recovery_path(vault_dir).is_file()
}

fn recovery_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(RECOVERY_FILE)
}

fn load(vault_dir: &Path) -> Result<RecoveryFile> {
    let json = match fs::read_to_string(recovery_path(vault_dir)) {
        Ok(json) => json,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::Operation(
                "no recovery kit exists for this vault".into(),
            ))
        }
        Err(e) => return Err(e.into()),
    };
    parse(&json)
}

fn parse(json: &str) -> Result<RecoveryFile> {
    let file: RecoveryFile = serde_json::from_str(json).map_err(|_| Error::InvalidVault)?;
    if file.version != RECOVERY_VERSION {
        return Err(Error::UnsupportedVersion(file.version));
    }
    if file.salt.len() < 8
        || file.nonce.len() != crypto::NONCE_LEN
        || file.wrapped_master_key.len() != crypto::KEY_LEN + crypto::TAG_LEN
    {
        return Err(Error::InvalidVault);
    }
    file.kdf.validate()?;
    Ok(file)
}

fn generate_secret() -> Zeroizing<[u8; SECRET_LEN]> {
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    crypto::fill_random(&mut secret[..]);
    secret
}

fn checksum(secret: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"keres-recovery-checksum-v1");
    hasher.update(secret);
    let digest = hasher.finalize();

    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&digest[..CHECKSUM_LEN]);
    out
}

fn encode_base32(data: &[u8]) -> String {
    let mut out = String::with_capacity(SYMBOL_LEN);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in data {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((acc >> bits) & 0x1f) as usize;
            out.push(char::from(ALPHABET[index]));
            acc &= (1u32 << bits) - 1;
        }
    }
    if bits > 0 {
        let index = ((acc << (5 - bits)) & 0x1f) as usize;
        out.push(char::from(ALPHABET[index]));
    }
    out
}

fn group(encoded: &str) -> String {
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 4);
    for (index, ch) in encoded.chars().enumerate() {
        if index > 0 && index % 4 == 0 {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

/// Normalizes user input and decodes it back to the raw secret.
///
/// Hyphens and whitespace are ignored, lowercase is accepted, and the
/// Crockford confusables `I`/`L`/`O` map to `1`/`1`/`0`. The trailing
/// checksum rejects typos before any key derivation happens.
fn normalize(input: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut symbols = Vec::with_capacity(SYMBOL_LEN);
    for ch in input.chars() {
        if ch == '-' || ch.is_whitespace() {
            continue;
        }
        let mapped = match ch.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        let value = ALPHABET
            .iter()
            .position(|&b| char::from(b) == mapped)
            .ok_or_else(invalid_code)?;
        symbols.push(value as u8);
    }

    if symbols.len() != SYMBOL_LEN {
        return Err(invalid_code());
    }

    let mut payload = Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN));
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for value in symbols {
        acc = (acc << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            payload.push(((acc >> bits) & 0xff) as u8);
            acc &= (1u32 << bits) - 1;
        }
    }
    // Canonical encodings pad the final symbol with zero bits.
    if acc != 0 || payload.len() != PAYLOAD_LEN {
        return Err(invalid_code());
    }

    let (secret, stored_checksum) = payload.split_at(SECRET_LEN);
    if !crypto::secure_compare(&checksum(secret), stored_checksum) {
        return Err(Error::Operation(
            "recovery code checksum failed; check for typos".into(),
        ));
    }

    Ok(Zeroizing::new(secret.to_vec()))
}

fn invalid_code() -> Error {
    Error::Operation("invalid recovery code".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;

    #[test]
    fn code_roundtrips_and_is_grouped() {
        let secret = [0x11u8; SECRET_LEN];
        let code = RecoveryCode::from_secret(&secret);

        assert_eq!(code.expose().split('-').count(), SYMBOL_LEN / 4);
        assert_eq!(
            code.expose().chars().filter(|c| *c != '-').count(),
            SYMBOL_LEN
        );

        let decoded = normalize(code.expose()).unwrap();
        assert_eq!(&decoded[..], &secret);
    }

    #[test]
    fn normalization_accepts_case_separators_and_confusables() {
        // 0x10.. encodes to a mix of '0' and '1' symbols, so both Crockford
        // confusable mappings are exercised.
        let secret = [0x10u8; SECRET_LEN];
        let code = RecoveryCode::from_secret(&secret);

        let messy = code
            .expose()
            .to_ascii_lowercase()
            .replace('-', " ")
            .replace('0', "o")
            .replace('1', "l");
        let decoded = normalize(&messy).unwrap();
        assert_eq!(&decoded[..], &secret);
    }

    #[test]
    fn bad_checksum_and_short_codes_are_rejected() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x22u8; SECRET_LEN]);
        payload.extend_from_slice(&[0, 0]); // deliberately wrong checksum
        let encoded = group(&encode_base32(&payload));
        assert!(matches!(normalize(&encoded), Err(Error::Operation(_))));

        let code = RecoveryCode::from_secret(&[0x33u8; SECRET_LEN]);
        let short = &code.expose()[..code.expose().len() - 1];
        assert!(matches!(normalize(short), Err(Error::Operation(_))));
    }

    #[test]
    fn create_and_unlock_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let master = Key::generate();
        let code = create(tmp.path(), &master).unwrap();

        let recovered = unlock(tmp.path(), code.expose()).unwrap();
        assert_eq!(recovered.expose(), master.expose());

        assert!(exists(tmp.path()));
        remove(tmp.path()).unwrap();
        assert!(!exists(tmp.path()));
        assert!(matches!(
            unlock(tmp.path(), code.expose()),
            Err(Error::Operation(_))
        ));
    }

    #[test]
    fn wrong_but_well_formed_code_fails_authentication() {
        let tmp = tempfile::tempdir().unwrap();
        let master = Key::generate();
        let _code = create(tmp.path(), &master).unwrap();
        let other = RecoveryCode::from_secret(&[0x44u8; SECRET_LEN]);

        assert!(matches!(
            unlock(tmp.path(), other.expose()),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn recover_restores_a_lost_config() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("vault");
        let mut vault = Vault::new(dir.clone());
        vault.init("old password").unwrap();

        let source = tmp.path().join("secret.txt");
        std::fs::write(&source, b"still here").unwrap();
        vault.add(&source, None).unwrap();
        let code = vault.create_recovery_kit("old password").unwrap();
        assert!(vault.has_recovery_kit());

        // The config — the single point of failure this feature targets — is
        // gone, so the vault no longer even looks initialized.
        std::fs::remove_file(dir.join("vault.config")).unwrap();
        assert!(!vault.exists());

        let mut recovered = Vault::new(dir.clone());
        recovered.recover(code.expose(), "new password").unwrap();
        assert!(recovered.exists());
        assert!(!recovered.has_recovery_kit(), "kit must be consumed");

        assert!(matches!(
            Vault::new(dir.clone()).unlock("old password"),
            Err(Error::Authentication)
        ));
        recovered.unlock("new password").unwrap();

        let out = tmp.path().join("out.txt");
        recovered.extract("secret.txt", &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"still here");
    }

    #[test]
    fn wrong_recovery_code_leaves_config_and_kit_intact() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("vault");
        let mut vault = Vault::new(dir.clone());
        vault.init("pw").unwrap();
        let _code = vault.create_recovery_kit("pw").unwrap();

        let wrong = RecoveryCode::from_secret(&[0x55u8; SECRET_LEN]);
        assert!(matches!(
            Vault::new(dir.clone()).recover(wrong.expose(), "new pw"),
            Err(Error::Authentication)
        ));
        assert!(Vault::new(dir.clone()).has_recovery_kit());
        assert!(Vault::new(dir).unlock("pw").is_ok());
    }

    #[test]
    fn creating_a_kit_requires_the_password() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("vault");
        let mut vault = Vault::new(dir.clone());
        vault.init("pw").unwrap();

        assert!(matches!(
            vault.create_recovery_kit("wrong"),
            Err(Error::Authentication)
        ));
        assert!(!vault.has_recovery_kit());
    }

    #[test]
    fn tampered_wrapped_key_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("vault");
        let mut vault = Vault::new(dir.clone());
        vault.init("pw").unwrap();
        let code = vault.create_recovery_kit("pw").unwrap();

        let path = dir.join(RECOVERY_FILE);
        let mut file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let wrapped = file["wrapped_master_key"].as_array_mut().unwrap();
        wrapped[0] = serde_json::json!(wrapped[0].as_u64().unwrap() ^ 0xff);
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        assert!(matches!(
            unlock(&dir, code.expose()),
            Err(Error::Authentication)
        ));
    }
}
