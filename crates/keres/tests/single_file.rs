//! Single-file `.krs` integration tests.

use std::path::Path;

use keres::{decrypt_file, encrypt_file, Error};
use tempfile::TempDir;

fn setup(name: &str) -> TempDir {
    let dir = tempfile::Builder::new().prefix(name).tempdir().unwrap();
    std::fs::create_dir_all(dir.path()).unwrap();
    dir
}

#[test]
fn roundtrip_small_file() {
    let dir = setup("small");
    let src = dir.path().join("report.txt");
    std::fs::write(&src, b"quarterly numbers: 42").unwrap();

    let out = encrypt_file("pw", &src, Some(&dir.path().join("test.krs"))).unwrap();
    assert!(out.extension().unwrap() == "krs");

    let dst = dir.path().join("restored.txt");
    let name = decrypt_file("pw", &out, &dst).unwrap();
    assert_eq!(name, "report.txt");
    assert_eq!(std::fs::read(&dst).unwrap(), b"quarterly numbers: 42");
}

#[test]
fn multichunk_large_file_constant_memory() {
    let dir = setup("large");
    let src = dir.path().join("big.bin");
    // ~3.5 chunks
    let data: Vec<u8> = (0..(64 * 1024 * 3 + 999))
        .map(|i| (i % 251) as u8)
        .collect();
    std::fs::write(&src, &data).unwrap();

    let out = encrypt_file("pw", &src, Some(&dir.path().join("big.krs"))).unwrap();
    let dst = dir.path().join("back.bin");
    decrypt_file("pw", &out, &dst).unwrap();
    assert_eq!(std::fs::read(&dst).unwrap(), data);
}

#[test]
fn empty_file_roundtrip() {
    let dir = setup("empty");
    let src = dir.path().join("zero.bin");
    std::fs::write(&src, b"").unwrap();
    let out = encrypt_file("pw", &src, Some(&dir.path().join("test.krs"))).unwrap();
    let dst = dir.path().join("zero.out");
    decrypt_file("pw", &out, &dst).unwrap();
    assert_eq!(std::fs::read(&dst).unwrap(), b"");
}

#[test]
fn unicode_filename_survives() {
    let dir = setup("unicode");
    let src = dir.path().join("ünïcødé-文件.txt");
    std::fs::write(&src, b"data").unwrap();
    let out = encrypt_file("pw", &src, Some(&dir.path().join("test.krs"))).unwrap();
    let dst = dir.path().join("out");
    let name = decrypt_file("pw", &out, &dst).unwrap();
    assert_eq!(name, "ünïcødé-文件.txt");
}

#[test]
fn wrong_password_fails_with_authentication_error() {
    let dir = setup("wrongpw");
    let src = dir.path().join("f.txt");
    std::fs::write(&src, b"x").unwrap();
    let out = encrypt_file("right", &src, Some(&dir.path().join("test.krs"))).unwrap();

    match decrypt_file("wrong", &out, &dir.path().join("o")) {
        Err(Error::Authentication) => {}
        other => panic!("expected Authentication, got {other:?}"),
    }
}

#[test]
fn tampering_any_region_detected() {
    let dir = setup("tamper");
    let data: Vec<u8> = (0..70_000u32).map(|i| i as u8).collect(); // multi-chunk
    let src = dir.path().join("f.bin");
    std::fs::write(&src, &data).unwrap();
    let out = encrypt_file("pw", &src, Some(&dir.path().join("test.krs"))).unwrap();

    let total = out.metadata().unwrap().len() as usize;
    for flip_byte in [9usize, 50, total - 1] {
        let mut bytes = std::fs::read(&out).unwrap();
        bytes[flip_byte] ^= 0x01;
        let corrupted = dir.path().join("corrupt.krs");
        std::fs::write(&corrupted, &bytes).unwrap();
        let result = decrypt_file("pw", &corrupted, &dir.path().join("o"));
        assert!(
            result.is_err(),
            "flip at {flip_byte}: tampering must not decrypt, got {result:?}"
        );
    }
}

#[test]
fn truncated_container_rejected() {
    let dir = setup("trunc");
    let data = vec![7u8; 200_000];
    let src = dir.path().join("f.bin");
    std::fs::write(&src, &data).unwrap();
    let out = encrypt_file("pw", &src, Some(&dir.path().join("test.krs"))).unwrap();

    let mut bytes = std::fs::read(&out).unwrap();
    bytes.truncate(bytes.len() / 2);
    let cut = dir.path().join("cut.krs");
    std::fs::write(&cut, &bytes).unwrap();

    assert!(decrypt_file("pw", &cut, &dir.path().join("o")).is_err());
}

#[test]
fn trailing_garbage_rejected() {
    let dir = setup("garbage");
    let src = dir.path().join("f.txt");
    std::fs::write(&src, b"data").unwrap();
    let out = encrypt_file("pw", &src, Some(&dir.path().join("test.krs"))).unwrap();

    let mut bytes = std::fs::read(&out).unwrap();
    bytes.extend_from_slice(b"evil-extra-data");
    let padded = dir.path().join("padded.krs");
    std::fs::write(&padded, &bytes).unwrap();

    assert!(decrypt_file("pw", &padded, &dir.path().join("o")).is_err());
}

#[test]
fn garbage_header_rejected() {
    let dir = setup("hdr");
    let fake = dir.path().join("fake.krs");
    std::fs::write(&fake, b"TOTALLY-NOT\n000000000000000000000000000000000").unwrap();
    assert!(matches!(
        decrypt_file("pw", &fake, &dir.path().join("o")),
        Err(Error::InvalidHeader)
    ));
}

#[test]
fn missing_input_is_clean_error() {
    let _dir = setup("missing");
    let err = encrypt_file("pw", Path::new("/nonexistent/file"), None).unwrap_err();
    assert!(matches!(err, Error::InvalidEntryName(_)));
}
