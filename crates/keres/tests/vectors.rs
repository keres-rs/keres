//! Format test vectors.
//!
//! `tests/vectors/standalone.krs` is a committed, deterministic container
//! built by [`keres::test_vectors::standalone`]. The tests below pin its
//! bytes, its digest, and its behaviour through the public API, so any change
//! to the wire format is a visible, intentional failure.

use std::path::{Path, PathBuf};

use keres::{test_vectors, Error};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const PASSWORD: &str = "correct horse battery staple";
const NAME: &str = "hello.txt";
const DIGEST: &str = "978e1085b8ff2d199d70b52d0b4cff391ebadaa0efcc11298e3eaeff584f19d2";

fn plaintext() -> Vec<u8> {
    // More than one 64 KiB chunk, with a deterministic, non-repeating pattern.
    (0..100_000u32).map(|i| (i % 251) as u8).collect()
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("standalone.krs")
}

fn fixture() -> Vec<u8> {
    std::fs::read(fixture_path()).expect("committed vector is present")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_temp(dir: &TempDir, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join("tampered.krs");
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn committed_vector_matches_generator() {
    let generated = test_vectors::standalone(PASSWORD, &plaintext(), NAME);
    assert_eq!(
        generated,
        fixture(),
        "wire format changed; regenerate tests/vectors/standalone.krs deliberately"
    );
}

#[test]
fn committed_vector_digest_is_pinned() {
    assert_eq!(sha256_hex(&fixture()), DIGEST);
}

#[test]
fn committed_vector_decrypts_through_public_api() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("standalone.krs");
    std::fs::copy(fixture_path(), &input).unwrap();

    let output = dir.path().join("restored.bin");
    let name = keres::decrypt_file(PASSWORD, &input, &output).unwrap();

    assert_eq!(name, NAME);
    assert_eq!(std::fs::read(&output).unwrap(), plaintext());
}

#[test]
fn wrong_password_is_authentication_error() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("standalone.krs");
    std::fs::copy(fixture_path(), &input).unwrap();

    let output = dir.path().join("restored.bin");
    assert!(matches!(
        keres::decrypt_file("wrong password", &input, &output),
        Err(Error::Authentication)
    ));
}

#[test]
fn foreign_magic_is_incompatible() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = fixture();
    bytes[0] ^= 0xFF;
    let input = write_temp(&dir, &bytes);

    let output = dir.path().join("restored.bin");
    assert!(matches!(
        keres::decrypt_file(PASSWORD, &input, &output),
        Err(Error::IncompatibleFormat)
    ));
}

#[test]
fn tampered_trailer_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = fixture();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let input = write_temp(&dir, &bytes);

    let output = dir.path().join("restored.bin");
    assert!(matches!(
        keres::decrypt_file(PASSWORD, &input, &output),
        Err(Error::Authentication)
    ));
}

#[test]
fn truncated_container_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = fixture();
    let input = write_temp(&dir, &bytes[..bytes.len() / 2]);

    let output = dir.path().join("restored.bin");
    assert!(keres::decrypt_file(PASSWORD, &input, &output).is_err());
}
