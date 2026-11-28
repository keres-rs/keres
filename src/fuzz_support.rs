//! Hidden entry points for the fuzz targets in `fuzz/`.
//!
//! These wrappers exist only so `cargo fuzz` can reach parsers that are
//! otherwise crate-private. They are hidden from rustdoc and not part of the
//! stable API.

use std::io::Cursor;

use crate::container::{self, PayloadType};
use crate::crypto::Key;
use crate::error::Result;

/// Parses arbitrary bytes as an HKDF-kind file container.
///
/// Key derivation is HKDF, so this reaches the chunk and trailer parsers on
/// every iteration without paying Argon2id's memory cost.
pub fn read_hkdf_file(input: &[u8], identity: &str) -> Result<()> {
    let master = Key::from_bytes(crate::test_vectors::MASTER_KEY);
    container::read_container(
        Cursor::new(input),
        None,
        Some(&master),
        PayloadType::File,
        identity.as_bytes(),
        |_| Ok(()),
    )
    .map(|_| ())
}

/// Parses arbitrary bytes as a vault config JSON document.
pub fn parse_vault_config(json: &str) -> Result<()> {
    crate::vault::keystore::VaultConfig::parse(json).map(|_| ())
}

/// Parses arbitrary bytes as an encrypted vault manifest.
pub fn parse_manifest(input: &[u8]) -> Result<()> {
    let master = Key::from_bytes(crate::test_vectors::MASTER_KEY);
    crate::vault::manifest::decode(input, &master).map(|_| ())
}

/// Parses arbitrary bytes as a v2 padding metadata header.
///
/// The real decoder only runs after a padding record authenticates, so this
/// entry point lets the fuzzer exercise the length, mode and padding-policy
/// validation directly.
pub fn parse_padding_header(input: &[u8]) -> Result<()> {
    crate::container::PaddingHeader::decode(input).map(|_| ())
}
