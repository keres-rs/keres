//! Deterministic containers used to pin the wire format.
//!
//! Hidden from rustdoc and **not** part of the stable API. Every function
//! uses fixed salts and the minimum accepted Argon2id cost, so the produced
//! bytes are reproducible across machines and releases. The integration tests
//! in `tests/vectors.rs` assert both the bytes of the committed fixture and
//! its SHA-256 digest.

use std::io::Cursor;

use crate::container::{self, KeyDerivation, PayloadType};
use crate::crypto::Key;
use crate::kdf::KdfParams;

/// Fixed Argon2id salt for the standalone vector.
pub const ARGON_SALT: [u8; 32] = [0x11; 32];
/// Fixed HKDF object salt for the standalone vector.
pub const OBJECT_SALT: [u8; 32] = [0x22; 32];
/// Fixed master key shared by the HKDF vectors, benchmarks, and fuzz readers.
pub const MASTER_KEY: [u8; 32] = [0x42; 32];
/// Fixed HKDF object salt for the HKDF vector.
pub const HKDF_OBJECT_SALT: [u8; 32] = [0x33; 32];
/// Minimum accepted Argon2id parameters: fast, but still valid input.
pub const KDF_PARAMS: KdfParams = KdfParams {
    m_cost_kib: 8 * 1024,
    t_cost: 1,
    p_cost: 1,
};

/// Builds the deterministic standalone `.krs` container for `plaintext`.
///
/// The password must be non-empty; it is not stored in the output.
pub fn standalone(password: &str, plaintext: &[u8], original_name: &str) -> Vec<u8> {
    let kd = KeyDerivation::Password {
        argon_salt: ARGON_SALT,
        object_salt: OBJECT_SALT,
        params: KDF_PARAMS,
    };
    let mut out = Vec::new();
    let mut src = Cursor::new(plaintext);
    container::write_container(
        &mut out,
        &kd,
        Some(password),
        None,
        PayloadType::File,
        b"",
        Some(&mut src),
        Some(original_name),
    )
    .expect("deterministic vector construction cannot fail");
    out
}

/// Builds a deterministic HKDF-kind file container bound to `identity`.
///
/// Used by benchmarks to measure the chunk pipeline without paying the
/// Argon2id cost on every iteration.
pub fn hkdf_file(plaintext: &[u8], identity: &str) -> Vec<u8> {
    let master = Key::from_bytes(MASTER_KEY);
    let kd = KeyDerivation::Hkdf {
        object_salt: HKDF_OBJECT_SALT,
    };
    let mut out = Vec::new();
    let mut src = Cursor::new(plaintext);
    container::write_container(
        &mut out,
        &kd,
        None,
        Some(&master),
        PayloadType::File,
        identity.as_bytes(),
        Some(&mut src),
        None,
    )
    .expect("deterministic vector construction cannot fail");
    out
}

/// Builds a deterministic encrypted manifest from `json` plaintext.
///
/// Used to seed the manifest fuzz target with an input that authenticates.
pub fn manifest(json: &[u8]) -> Vec<u8> {
    let master = Key::from_bytes(MASTER_KEY);
    let kd = KeyDerivation::Hkdf {
        object_salt: HKDF_OBJECT_SALT,
    };
    let mut out = Vec::new();
    let mut src = Cursor::new(json);
    container::write_container(
        &mut out,
        &kd,
        None,
        Some(&master),
        PayloadType::Manifest,
        b"vault-manifest",
        Some(&mut src),
        None,
    )
    .expect("deterministic vector construction cannot fail");
    out
}
