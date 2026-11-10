//! Vault integration tests.

use std::path::Path;

use fs4::FileExt;
use keres::{Error, Vault};
use tempfile::TempDir;

fn make_vault(tag: &str) -> (TempDir, Vault) {
    let dir = tempfile::Builder::new().prefix(tag).tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    let mut v = Vault::new(vault_dir);
    v.init("master-password").unwrap();
    assert!(v.is_unlocked());
    (dir, v)
}

#[test]
fn init_twice_fails() {
    let (_d, mut v) = make_vault("init2");
    assert!(matches!(v.init("x"), Err(Error::VaultExists)));
}

#[test]
fn locked_vault_rejects_operations() {
    let (_d, mut v) = make_vault("locked");
    v.lock();
    assert!(!v.is_unlocked());
    let f = v.path().join("nope.txt");
    std::fs::write(&f, b"x").unwrap();
    assert!(matches!(v.add(&f, None), Err(Error::VaultLocked)));
    assert!(matches!(v.list(), Err(Error::VaultLocked)));
}

#[test]
fn concurrent_operations_fail_fast() {
    let (_d, mut v) = make_vault("busy");
    let parent = v.path().parent().unwrap().to_path_buf();
    let src = parent.join("busy.txt");
    std::fs::write(&src, b"payload").unwrap();

    let lock_path = v.path().join("vault.lock");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    FileExt::try_lock(&held).unwrap();

    assert!(matches!(v.add(&src, None), Err(Error::VaultBusy)));
    assert!(matches!(v.list(), Err(Error::VaultBusy)));
    assert!(matches!(
        v.extract("busy.txt", &parent.join("out")),
        Err(Error::VaultBusy)
    ));
    assert!(matches!(
        v.change_password("master-password", "new-password"),
        Err(Error::VaultBusy)
    ));
    assert!(matches!(v.verify("master-password"), Err(Error::VaultBusy)));

    FileExt::unlock(&held).unwrap();
    drop(held);

    // Once the lock is free, the same handle works again.
    v.add(&src, None).unwrap();
    assert_eq!(v.list().unwrap().len(), 1);
}

#[test]
fn unlock_wrong_password_is_authentication_error() {
    let (_d, mut v) = make_vault("wrongunlock");
    v.lock();
    assert!(matches!(v.unlock("bad"), Err(Error::Authentication)));
}

#[test]
fn file_roundtrip() {
    let (_d, mut v) = make_vault("file");
    let src = v.path().parent().unwrap().join("secret.txt");
    std::fs::write(&src, b"hidden payload").unwrap();

    v.add(&src, None).unwrap();
    let entries = v.list().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "secret.txt");
    assert_eq!(entries[0].size, 14); // b"hidden payload".len()

    let out = v.path().parent().unwrap().join("out.txt");
    v.extract("secret.txt", &out).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), b"hidden payload");

    // Duplicate add must not silently overwrite.
    assert!(matches!(v.add(&src, None), Err(Error::EntryExists(_))));
}

#[test]
fn directory_tree_roundtrip_and_recursive_remove() {
    let (_d, mut v) = make_vault("tree");
    let root = v.path().parent().unwrap().join("photos");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("a.png"), b"A").unwrap();
    std::fs::write(root.join("sub").join("b.png"), b"BB").unwrap();

    v.add(&root, Some("photos")).unwrap();
    assert_eq!(v.list().unwrap().len(), 1); // only top-level shown

    // Extract recreates the whole subtree under dest.
    let dest = v.path().parent().unwrap().join("restored");
    v.extract("photos", &dest).unwrap();
    assert_eq!(std::fs::read(dest.join("a.png")).unwrap(), b"A");
    assert_eq!(
        std::fs::read(dest.join("sub").join("b.png")).unwrap(),
        b"BB"
    );

    // Remove deletes every blob of the subtree.
    v.remove("photos").unwrap();
    assert!(v.list().unwrap().is_empty());

    // No orphan blobs: data dir holds only the manifest.
    let data_dir = v.path().join("d");
    let leftovers: Vec<_> = std::fs::read_dir(&data_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file() && e.file_name().to_string_lossy() != ".manifest.enc")
        .collect();
    assert!(leftovers.is_empty(), "orphaned files: {leftovers:?}");
    for entry in std::fs::read_dir(&data_dir).unwrap().filter_map(|e| e.ok()) {
        if entry.path().is_dir() {
            assert!(
                std::fs::read_dir(entry.path()).unwrap().next().is_none(),
                "empty shard dirs should be cleaned up"
            );
        }
    }
}

#[test]
fn symlinks_are_skipped_on_add() {
    #[cfg(unix)]
    {
        let (_d, mut v) = make_vault("symlink");
        let real = v.path().parent().unwrap().join("real.txt");
        std::fs::write(&real, b"data").unwrap();
        let link = v.path().parent().unwrap().join("link.txt");
        std::os::unix::fs::symlink("/etc/hostname", &link).unwrap();

        // Adding a bare symlink is rejected (or, if canonicalized to a
        // regular file, added as a copy — never followed out of the tree).
        let _ = v.add(&link, Some("innocent"));
        // Directory containing a symlink child.
        let tree = v.path().parent().unwrap().join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("ok.txt"), b"fine").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", tree.join("evil.txt")).unwrap();
        v.add(&tree, None).unwrap();
        v.lock();
        let _ = v;
    }
}

#[test]
fn verify_reports_missing_and_corrupted() {
    let (dir, mut v) = make_vault("verify");
    let f1 = dir.path().join("one.txt");
    let f2 = dir.path().join("two.txt");
    std::fs::write(&f1, b"1").unwrap();
    std::fs::write(&f2, b"22").unwrap();
    v.add(&f1, None).unwrap();
    v.add(&f2, None).unwrap();
    drop(v);

    // Exactly two blobs exist: corrupt one on disk, delete the other.
    let mut blobs = walk_blobs(&dir.path().join("vault"));
    assert_eq!(blobs.len(), 2);
    blobs.sort();

    let bytes = std::fs::read(&blobs[0]).unwrap();
    let corrupted_bytes: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, b)| if i == 40 { b ^ 0xFF } else { *b })
        .collect();
    std::fs::write(&blobs[0], &corrupted_bytes).unwrap();
    std::fs::remove_file(&blobs[1]).unwrap();

    let report = Vault::new(dir.path().join("vault"))
        .verify("master-password")
        .unwrap();
    assert_eq!(report.total_entries, 2);
    assert_eq!(report.missing.len() + report.corrupted.len(), 2);
    assert_eq!(report.verified, 0);
}

fn walk_blobs(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk_blobs(&p));
        } else {
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if name.ends_with(".enc") && name != ".manifest.enc" {
                out.push(p);
            }
        }
    }
    out
}

#[test]
fn change_password_rotates_kek_only() {
    let (_d, mut v) = make_vault("rotatepw");
    let src = v.path().parent().unwrap().join("f.txt");
    std::fs::write(&src, b"data").unwrap();
    v.add(&src, None).unwrap();
    v.lock();

    // Wrong old password rejected.
    assert!(Vault::new(v.path().to_path_buf())
        .change_password("WRONG", "new")
        .is_err());

    let mut fresh = Vault::new(v.path().to_path_buf());
    fresh
        .change_password("master-password", "brand-new")
        .unwrap();

    let mut reopened = Vault::new(v.path().to_path_buf());
    assert!(reopened.unlock("master-password").is_err());
    reopened.unlock("brand-new").unwrap();
    assert_eq!(reopened.list().unwrap().len(), 1);
}

#[test]
fn traversal_names_rejected() {
    let (_d, mut v) = make_vault("traversal");
    let src = v.path().parent().unwrap().join("f.txt");
    std::fs::write(&src, b"x").unwrap();

    for evil in ["../escape", "a/b/../c", "/abs", "..", "."] {
        let r = v.add(&src, Some(evil));
        assert!(
            matches!(r, Err(Error::InvalidEntryName(_))),
            "{evil}: {r:?}"
        );
    }
}

#[test]
fn persistence_across_reopen() {
    let (dir, mut v) = make_vault("reopen");
    let src = dir.path().join("persist.bin");
    let big: Vec<u8> = (0..150_000u32).map(|i| i as u8).collect(); // multichunk
    std::fs::write(&src, &big).unwrap();
    v.add(&src, None).unwrap();
    drop(v);

    let mut v2 = Vault::new(dir.path().join("vault"));
    v2.unlock("master-password").unwrap();
    let out = dir.path().join("back.bin");
    v2.extract("persist.bin", &out).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), big);
}
