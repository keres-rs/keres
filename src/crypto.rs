//! Low-level cryptographic primitives.
//!
//! Everything in this module is building-block level: authenticated
//! encryption with associated data (AES-256-GCM), password key derivation
//! (Argon2id), per-file subkey derivation (HKDF-SHA256) and constant-time
//! comparison. The higher-level single-file and vault APIs compose these
//! primitives; most applications should use [`crate::encrypt_file`],
//! [`crate::decrypt_file`] or [`crate::Vault`] instead.
//!
//! # Design notes
//!
//! * All keys live in [`zeroize::Zeroizing`] memory and are overwritten when
//!   dropped. Keys are passed by reference; no public API hands out raw key
//!   bytes by value.
//! * Every AEAD operation takes associated data (AAD). Callers bind all
//!   unauthenticated header fields through AAD — this is what makes
//!   truncation, reordering and format-confusion attacks detectable.
//! * [`Debug`] for keys is manually implemented and never prints key bytes.

use aes_gcm::{
    aead::{rand_core::RngCore, AeadInPlace, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::kdf::KdfParams;

/// Symmetric key length in bytes (AES-256).
pub const KEY_LEN: usize = 32;
/// GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// GCM authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Raw salt length used by new (v3+) containers.
pub const SALT_LEN: usize = 32;

/// A 32-byte symmetric key stored in zeroizing memory.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    /// Generates a fresh random key from the operating system CSPRNG.
    pub fn generate() -> Self {
        Self(Zeroizing::new(random_key_bytes()))
    }

    /// Constructs a key from existing bytes. The input is copied into
    /// zeroizing memory; callers are responsible for zeroing their own copy.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrows the raw key bytes.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub(crate) fn cipher(&self) -> Result<Aes256Gcm> {
        Aes256Gcm::new_from_slice(self.0.as_slice()).map_err(|_| Error::Encryption)
    }
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key([REDACTED])")
    }
}

/// A 96-bit GCM nonce.
pub type Nonce12 = [u8; NONCE_LEN];

/// Fills `buf` with random bytes from the operating system CSPRNG.
pub fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

pub(crate) fn random_key_bytes() -> [u8; KEY_LEN] {
    let mut k = [0u8; KEY_LEN];
    fill_random(&mut k);
    k
}

/// Generates a fresh random nonce.
pub fn random_nonce() -> Nonce12 {
    let mut n = [0u8; NONCE_LEN];
    fill_random(&mut n);
    n
}

/// Encrypts `plaintext` under `key`, binding `aad`.
///
/// Returns `(nonce, ciphertext)` where the ciphertext includes the trailing
/// 16-byte GCM tag.
pub fn seal(plaintext: &[u8], key: &Key, aad: &[u8]) -> Result<(Nonce12, Vec<u8>)> {
    let nonce = random_nonce();
    let mut buf = plaintext.to_vec();
    seal_in_place(&nonce, &mut buf, key, aad)?;
    Ok((nonce, buf))
}

/// In-place encryption: appends the authentication tag to `buf`.
pub(crate) fn seal_in_place(
    nonce: &Nonce12,
    buf: &mut Vec<u8>,
    key: &Key,
    aad: &[u8],
) -> Result<()> {
    let cipher = key.cipher()?;
    cipher
        .encrypt_in_place(Nonce::from_slice(nonce), aad, buf)
        .map_err(|_| Error::Encryption)
}

/// Decrypts `ciphertext_with_tag` under `key` after verifying `aad`.
///
/// Returns the plaintext in zeroizing memory. Fails with
/// [`Error::Authentication`] if the password/key is wrong or the data was
/// modified.
pub fn open(
    ciphertext_with_tag: &[u8],
    nonce: &Nonce12,
    key: &Key,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(ciphertext_with_tag.to_vec());
    open_in_place(nonce, &mut buf, key, aad)?;
    Ok(buf)
}

/// In-place decryption over a buffer holding `ciphertext || tag`.
pub(crate) fn open_in_place(
    nonce: &Nonce12,
    buf: &mut Vec<u8>,
    key: &Key,
    aad: &[u8],
) -> Result<()> {
    let cipher = key.cipher()?;
    cipher
        .decrypt_in_place(Nonce::from_slice(nonce), aad, buf)
        .map_err(|_| Error::Authentication)
}

struct Argon2Instance(Argon2<'static>);

fn make_argon2(params: KdfParams) -> Result<Argon2Instance> {
    let p = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::InvalidKdfParams)?;
    Ok(Argon2Instance(Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        p,
    )))
}

/// Derives a 256-bit key from `password` and `salt` using Argon2id.
///
/// `salt` must be at least 8 bytes; new containers use 32 raw random bytes.
pub fn derive_key(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Key> {
    params.validate()?;
    if salt.len() < 8 {
        return Err(Error::InvalidHeader);
    }

    let argon2 = make_argon2(params)?;

    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .0
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|_| Error::KeyDerivation)?;
    Ok(Key(out))
}

/// Derives an independent per-object subkey from a master key using
/// HKDF-SHA256.
///
/// Each encrypted object uses its own random `salt`, so even if two objects
/// were to end up with identical nonce sequences they would still be
/// protected by distinct keys.
pub(crate) fn derive_subkey(master: &Key, salt: &[u8], info: &[u8]) -> Key {
    let hk = Hkdf::<Sha256>::new(Some(salt), master.expose());
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(info, okm.as_mut())
        .expect("32-byte OKM is valid for SHA-256");
    Key(okm)
}

/// Constant-time equality comparison.
///
/// Unlike `==`, the runtime does not depend on where the first differing byte
/// occurs. Length mismatch still returns `false` immediately (lengths are not
/// secret in this crate).
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = Key::generate();
        let (nonce, ct) = seal(b"attack at dawn", &key, b"context").unwrap();
        let pt = open(&ct, &nonce, &key, b"context").unwrap();
        assert_eq!(&pt[..], b"attack at dawn");
    }

    #[test]
    fn aad_is_binding() {
        let key = Key::generate();
        let (nonce, ct) = seal(b"secret", &key, b"aad-1").unwrap();
        assert!(open(&ct, &nonce, &key, b"aad-2").is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let (nonce, ct) = seal(b"secret", &Key::generate(), b"").unwrap();
        assert!(open(&ct, &nonce, &Key::generate(), b"").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = Key::generate();
        let (nonce, mut ct) = seal(b"secret", &key, b"").unwrap();
        ct[0] ^= 1;
        assert!(open(&ct, &nonce, &key, b"").is_err());
    }

    #[test]
    fn derive_key_matches_params_and_salt() {
        let params = KdfParams {
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let k1 = derive_key(b"pw", b"0123456789abcdef", params).unwrap();
        let k2 = derive_key(b"pw", b"0123456789abcdef", params).unwrap();
        let k3 = derive_key(b"pw", b"fedcba9876543210", params).unwrap();
        assert_eq!(k1.expose(), k2.expose());
        assert_ne!(k1.expose(), k3.expose());
    }

    #[test]
    fn debug_redacts_keys() {
        let key = Key::generate();
        let rendered = format!("{key:?}");
        assert!(
            !rendered.contains("Key(") && !rendered.ends_with(')') || rendered.contains("REDACTED")
        );
    }

    #[test]
    fn secure_compare_basics() {
        assert!(secure_compare(b"abc", b"abc"));
        assert!(!secure_compare(b"abc", b"abd"));
        assert!(!secure_compare(b"abc", b"abcd"));
    }

    #[test]
    fn subkeys_are_distinct_per_salt() {
        let master = Key::generate();
        let a = derive_subkey(&master, b"salt-a", b"info");
        let b = derive_subkey(&master, b"salt-b", b"info");
        assert_ne!(a.expose(), b.expose());
    }
}
