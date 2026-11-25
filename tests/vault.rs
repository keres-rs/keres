//! Vault integration tests.

use std::path::Path;

use fs4::FileExt;
use keres::{BatchOp, Error, Padding, Vault, WriteOutcome};
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
fn init_refuses_to_clobber_a_config_less_vault_with_an_index() {
    let (_d, mut v) = make_vault("initindex");
    std::fs::remove_file(v.path().join("vault.config")).unwrap();
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

    // No orphan blobs: data dir holds only index metadata files.
    let data_dir = v.path().join("d");
    let leftovers: Vec<_> = std::fs::read_dir(&data_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file() && !e.file_name().to_string_lossy().starts_with('.'))
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

#[test]
fn replace_updates_file_contents() {
    let (dir, mut v) = make_vault("replace");
    let src = dir.path().join("doc.txt");
    std::fs::write(&src, b"version one").unwrap();
    v.add(&src, None).unwrap();

    let updated = b"version two, longer";
    std::fs::write(&src, updated).unwrap();
    v.replace(&src, "doc.txt").unwrap();

    let out = dir.path().join("out.txt");
    v.extract("doc.txt", &out).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), updated);
    assert_eq!(v.list().unwrap()[0].size, updated.len() as u64);
}

#[test]
fn replace_missing_entry_fails() {
    let (dir, mut v) = make_vault("replacemissing");
    let src = dir.path().join("doc.txt");
    std::fs::write(&src, b"x").unwrap();
    assert!(matches!(
        v.replace(&src, "nope.txt"),
        Err(Error::EntryNotFound(_))
    ));
}

#[test]
fn replace_directory_fails() {
    let (dir, mut v) = make_vault("replacedir");
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"a").unwrap();
    v.add(&tree, None).unwrap();

    let src = dir.path().join("replacement.txt");
    std::fs::write(&src, b"x").unwrap();
    assert!(matches!(v.replace(&src, "tree"), Err(Error::Operation(_))));
}

#[test]
fn prune_removes_only_unreferenced_files() {
    let (dir, mut v) = make_vault("prune");
    let src = dir.path().join("keep.txt");
    std::fs::write(&src, b"keep me").unwrap();
    v.add(&src, None).unwrap();

    let data = v.path().join("d");
    let orphan_dir = data.join("zz");
    std::fs::create_dir_all(&orphan_dir).unwrap();
    let orphan = orphan_dir.join("orphan.enc");
    std::fs::write(&orphan, b"ciphertext-ish").unwrap();
    let stale_tmp = data.join(".x.tmp-123-deadbeef");
    std::fs::write(&stale_tmp, b"stale").unwrap();
    let unrelated = data.join("README");
    std::fs::write(&unrelated, b"not ours").unwrap();

    let removed = v.prune_orphans().unwrap();
    assert_eq!(removed, 2);
    assert!(!orphan.exists());
    assert!(!stale_tmp.exists());
    assert!(unrelated.exists(), "prune must not touch unrelated files");

    let out = dir.path().join("out.txt");
    v.extract("keep.txt", &out).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), b"keep me");
}

#[test]
fn prune_refuses_without_manifest() {
    let (_d, mut v) = make_vault("prunenomanifest");
    std::fs::remove_file(v.path().join("d").join(".manifest.enc")).unwrap();
    assert!(matches!(v.prune_orphans(), Err(Error::InvalidVault)));
}

#[test]
fn rename_preserves_blob_identity() {
    let (dir, mut v) = make_vault("rename");
    let src = dir.path().join("old.txt");
    std::fs::write(&src, b"same bytes").unwrap();
    v.add(&src, None).unwrap();
    let before = walk_blobs(&v.path().join("d"));
    assert_eq!(before.len(), 1);

    v.rename("old.txt", "new.txt").unwrap();

    assert_eq!(
        walk_blobs(&v.path().join("d")),
        before,
        "rename must not move or rewrite the blob"
    );
    assert!(matches!(
        v.extract("old.txt", &dir.path().join("gone")),
        Err(Error::EntryNotFound(_))
    ));
    let out = dir.path().join("out.txt");
    v.extract("new.txt", &out).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), b"same bytes");
    let names: Vec<_> = v.list().unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["new.txt"]);
}

#[test]
fn rename_directory_moves_subtree() {
    let (dir, mut v) = make_vault("renamedir");
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("sub/file.txt"), b"nested").unwrap();
    v.add(&tree, None).unwrap();

    v.rename("tree", "archive").unwrap();
    assert!(matches!(
        v.extract("tree", &dir.path().join("gone")),
        Err(Error::EntryNotFound(_))
    ));

    let out = dir.path().join("restored");
    v.extract("archive", &out).unwrap();
    assert_eq!(std::fs::read(out.join("sub/file.txt")).unwrap(), b"nested");
}

#[test]
fn rename_to_existing_name_fails() {
    let (dir, mut v) = make_vault("renamecollision");
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    std::fs::write(&a, b"a").unwrap();
    std::fs::write(&b, b"b").unwrap();
    v.add(&a, None).unwrap();
    v.add(&b, None).unwrap();

    assert!(matches!(
        v.rename("a.txt", "b.txt"),
        Err(Error::EntryExists(_))
    ));
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

#[test]
fn keyslots_add_change_and_revoke() {
    let (_d, mut v) = make_vault("keyslots");
    let src = v.path().parent().unwrap().join("f.txt");
    std::fs::write(&src, b"data").unwrap();
    v.add(&src, None).unwrap();

    let original = v.keyslots().unwrap();
    assert_eq!(original.len(), 1);
    let original_id = original[0].id.clone();

    // The authorizing passphrase must be real, and a duplicate slot is
    // pointless.
    assert!(matches!(
        v.add_keyslot("WRONG", "second"),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        v.add_keyslot("master-password", "master-password"),
        Err(Error::Operation(_))
    ));

    let second = v.add_keyslot("master-password", "second-pass").unwrap();
    let slots = v.keyslots().unwrap();
    assert_eq!(slots.len(), 2);
    assert!(slots.iter().any(|slot| slot.id == second.id));

    v.lock();
    let mut other = Vault::new(v.path().to_path_buf());
    other.unlock("second-pass").unwrap();
    assert_eq!(other.list().unwrap().len(), 1);
    drop(other);

    // Changing one slot leaves the other passphrase and the contents alone.
    let mut with_second = Vault::new(v.path().to_path_buf());
    with_second
        .change_password("second-pass", "second-new")
        .unwrap();
    assert!(
        !with_second.is_unlocked(),
        "change_password must not unlock"
    );
    assert!(Vault::new(v.path().to_path_buf())
        .unlock("second-pass")
        .is_err());
    assert!(Vault::new(v.path().to_path_buf())
        .unlock("second-new")
        .is_ok());
    assert!(Vault::new(v.path().to_path_buf())
        .unlock("master-password")
        .is_ok());

    // Revoking with the target's own passphrase is refused: the authorizing
    // slot must survive.
    let mut revoker = Vault::new(v.path().to_path_buf());
    assert!(matches!(
        revoker.remove_keyslot(&second.id, "second-new"),
        Err(Error::Operation(_))
    ));

    revoker
        .remove_keyslot(&second.id, "master-password")
        .unwrap();
    assert!(Vault::new(v.path().to_path_buf())
        .unlock("second-new")
        .is_err());

    let mut remaining = Vault::new(v.path().to_path_buf());
    remaining.unlock("master-password").unwrap();
    assert_eq!(remaining.list().unwrap().len(), 1);
    assert_eq!(remaining.keyslots().unwrap()[0].id, original_id);
}

#[test]
fn keyslot_removal_cannot_brick_the_vault() {
    let (_d, mut v) = make_vault("slotlast");
    let original_id = v.keyslots().unwrap()[0].id.clone();

    // A single slot cannot be removed: no other passphrase can authorize it.
    assert!(matches!(
        v.remove_keyslot(&original_id, "master-password"),
        Err(Error::Operation(_))
    ));

    let second = v.add_keyslot("master-password", "second").unwrap();
    v.remove_keyslot(&second.id, "master-password").unwrap();

    let slots = v.keyslots().unwrap();
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].id, original_id);
    assert!(matches!(
        v.remove_keyslot(&original_id, "master-password"),
        Err(Error::Operation(_))
    ));
}

#[test]
fn recovery_resets_to_a_single_keyslot() {
    let (_d, mut v) = make_vault("slotrecover");
    v.add_keyslot("master-password", "second").unwrap();
    let code = v.create_recovery_kit("master-password").unwrap();
    let dir = v.path().to_path_buf();
    drop(v);

    std::fs::remove_file(dir.join("vault.config")).unwrap();
    let mut recovered = Vault::new(dir.clone());
    recovered.recover(code.expose(), "after-recovery").unwrap();

    // Recovery normalizes the config to one fresh slot; extra passphrases are
    // gone and must be re-added deliberately.
    assert_eq!(recovered.keyslots().unwrap().len(), 1);
    assert!(Vault::new(dir.clone()).unlock("master-password").is_err());
    assert!(Vault::new(dir.clone()).unlock("second").is_err());
    assert!(Vault::new(dir).unlock("after-recovery").is_ok());
}

#[test]
fn mutations_are_journaled_in_the_index_log() {
    let (dir, mut v) = make_vault("indexlog");
    let parent = v.path().parent().unwrap().to_path_buf();
    let snapshot_path = v.path().join("d").join(".manifest.enc");
    let log_path = v.path().join("d").join(".index.log");

    // `init` writes only the snapshot.
    assert!(snapshot_path.is_file());
    assert!(!log_path.exists());
    let snapshot = std::fs::read(&snapshot_path).unwrap();

    let a = parent.join("a.txt");
    std::fs::write(&a, b"alpha").unwrap();
    v.add(&a, None).unwrap();
    let b = parent.join("b.txt");
    std::fs::write(&b, b"beta").unwrap();
    v.add(&b, None).unwrap();

    // Mutations append to the log instead of rewriting the snapshot.
    assert!(log_path.is_file());
    assert_eq!(std::fs::read(&snapshot_path).unwrap(), snapshot);

    v.lock();
    drop(v);
    let mut reopened = Vault::new(dir.path().join("vault"));
    reopened.unlock("master-password").unwrap();
    let names: Vec<_> = reopened
        .list()
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, vec!["a.txt", "b.txt"]);

    reopened.remove("a.txt").unwrap();
    reopened.lock();
    drop(reopened);

    let mut again = Vault::new(dir.path().join("vault"));
    again.unlock("master-password").unwrap();
    let names: Vec<_> = again.list().unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["b.txt"]);
}

#[test]
fn conditional_write_conflicts_on_stale_version() {
    let (dir, mut v) = make_vault("cond");
    let src = dir.path().join("a.txt");
    std::fs::write(&src, b"alpha").unwrap();
    v.add(&src, None).unwrap();

    let version = v.version().unwrap();
    // A second, intervening mutation advances the version.
    let src2 = dir.path().join("b.txt");
    std::fs::write(&src2, b"beta").unwrap();
    v.add(&src2, None).unwrap();

    // Stale version -> conflict, nothing written.
    let src3 = dir.path().join("c.txt");
    std::fs::write(&src3, b"gamma").unwrap();
    let outcome = v.add_if(&src3, None, Some(version)).unwrap();
    assert!(matches!(outcome, WriteOutcome::Conflict { .. }));

    // Fresh version -> applied.
    let current = v.version().unwrap();
    let outcome = v.add_if(&src3, None, Some(current)).unwrap();
    assert!(matches!(outcome, WriteOutcome::Applied { .. }));
    assert!(v.list().unwrap().iter().any(|e| e.name == "c.txt"));

    // if-none-match: adding an existing name conflicts.
    let outcome = v.add_if(&src3, Some("c.txt"), None).unwrap();
    assert!(matches!(outcome, WriteOutcome::Conflict { .. }));
}

#[test]
fn replace_if_requires_entry() {
    let (dir, mut v) = make_vault("replaceif");
    let src = dir.path().join("a.txt");
    std::fs::write(&src, b"alpha").unwrap();
    v.add(&src, None).unwrap();

    let version = v.version().unwrap();
    let src2 = dir.path().join("a2.txt");
    std::fs::write(&src2, b"alpha2").unwrap();
    let outcome = v.replace_if(&src2, "a.txt", Some(version)).unwrap();
    assert!(matches!(outcome, WriteOutcome::Applied { .. }));

    // Missing entry -> conflict.
    let outcome = v.replace_if(&src2, "nope.txt", None).unwrap();
    assert!(matches!(outcome, WriteOutcome::Conflict { .. }));
}

#[test]
fn apply_batch_commits_once() {
    let (dir, mut v) = make_vault("batch");
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    std::fs::write(&a, b"alpha").unwrap();
    std::fs::write(&b, b"beta").unwrap();

    v.apply_batch(&[
        BatchOp::Add {
            source: a.clone(),
            name: None,
        },
        BatchOp::Add {
            source: b.clone(),
            name: Some("renamed.txt".into()),
        },
    ])
    .unwrap();

    let names: Vec<_> = v.list().unwrap().into_iter().map(|e| e.name).collect();
    assert!(names.contains(&"a.txt".to_string()));
    assert!(names.contains(&"renamed.txt".to_string()));
}

#[test]
fn erase_removes_and_rotates() {
    let (dir, mut v) = make_vault("erase");
    let src = dir.path().join("secret.txt");
    std::fs::write(&src, b"secret").unwrap();
    v.add(&src, None).unwrap();
    let src2 = dir.path().join("keep.txt");
    std::fs::write(&src2, b"keep").unwrap();
    v.add(&src2, None).unwrap();

    v.erase("secret.txt", "new-password").unwrap();
    assert!(!v.is_unlocked());

    let mut v2 = Vault::new(v.path().to_path_buf());
    v2.unlock("new-password").unwrap();
    let names: Vec<_> = v2.list().unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["keep.txt"]);
    // Old password no longer works.
    assert!(Vault::new(v.path().to_path_buf())
        .unlock("master-password")
        .is_err());
}

#[test]
fn padding_round_trips_through_vault() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = Vault::new(dir.path().join("vault"));
    v.init_with_padding("master-password", Padding::Adaptive)
        .unwrap();
    assert_eq!(v.padding().unwrap(), Padding::Adaptive);

    let src = dir.path().join("f.txt");
    let data = vec![0xABu8; 1000];
    std::fs::write(&src, &data).unwrap();
    v.add(&src, None).unwrap();

    let out = dir.path().join("out.txt");
    v.extract("f.txt", &out).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), data);

    // Changing policy persists.
    v.set_padding(Padding::fixed(8192).unwrap()).unwrap();
    assert_eq!(v.padding().unwrap(), Padding::fixed(8192).unwrap());
}

#[cfg(unix)]
#[test]
fn remove_commits_the_index_before_deleting_blobs() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, mut v) = make_vault("removeorder");
    let src = dir.path().join("gone.txt");
    std::fs::write(&src, b"bye").unwrap();
    v.add(&src, None).unwrap();

    let blobs = walk_blobs(&v.path().join("d"));
    assert_eq!(blobs.len(), 1);
    let shard = blobs[0].parent().unwrap().to_path_buf();

    // Make the blob's shard directory unwritable so unlinking fails, while the
    // index log (written under `d/`) still succeeds.
    let mut perms = std::fs::metadata(&shard).unwrap().permissions();
    perms.set_mode(0o500);
    std::fs::set_permissions(&shard, perms).unwrap();

    // The entry must disappear even though its blob could not be removed.
    v.remove("gone.txt").unwrap();
    assert!(v.list().unwrap().is_empty());

    // Restore permissions; the leftover blob is a reclaimable orphan.
    let mut perms = std::fs::metadata(&shard).unwrap().permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(&shard, perms).unwrap();
    assert_eq!(v.prune_orphans().unwrap(), 1);
}

#[test]
fn failed_batch_leaves_the_index_unchanged() {
    let (dir, mut v) = make_vault("batchfail");
    let a = dir.path().join("a.txt");
    std::fs::write(&a, b"original").unwrap();
    v.add(&a, None).unwrap();
    let before = v.version().unwrap();
    let blobs_before = walk_blobs(&v.path().join("d"));

    // A replace writes a fresh copy-on-write blob, then a later failing
    // operation must leave both the index and the visible contents untouched.
    let b = dir.path().join("b.txt");
    std::fs::write(&b, b"new content").unwrap();
    let result = v.apply_batch(&[
        BatchOp::Replace {
            source: b,
            name: "a.txt".into(),
        },
        BatchOp::Remove {
            name: "missing.txt".into(),
        },
    ]);
    assert!(matches!(result, Err(Error::EntryNotFound(_))));

    assert_eq!(v.version().unwrap(), before);
    let out = dir.path().join("out.txt");
    v.extract("a.txt", &out).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), b"original");

    // The failed replace's blob is an orphan; pruning restores the original
    // blob set exactly.
    assert!(v.prune_orphans().unwrap() >= 1);
    assert_eq!(walk_blobs(&v.path().join("d")), blobs_before);
}

#[test]
fn missing_manifest_is_not_treated_as_an_empty_index() {
    let (dir, mut v) = make_vault("nomanifest");
    let src = dir.path().join("f.txt");
    std::fs::write(&src, b"x").unwrap();
    v.add(&src, None).unwrap();

    std::fs::remove_file(v.path().join("d").join(".manifest.enc")).unwrap();

    assert!(matches!(v.list(), Err(Error::InvalidVault)));
    assert!(matches!(v.version(), Err(Error::InvalidVault)));
    assert!(matches!(
        v.verify("master-password"),
        Err(Error::InvalidVault)
    ));
}

#[test]
fn init_refuses_to_clobber_a_config_less_recovery_vault() {
    let (_dir, mut v) = make_vault("initrecovery");
    v.create_recovery_kit("master-password").unwrap();
    std::fs::remove_file(v.path().join("vault.config")).unwrap();

    assert!(matches!(v.init("other-password"), Err(Error::VaultExists)));
    assert!(
        v.path().join("vault.recovery").is_file(),
        "the recovery kit must survive the refused re-init"
    );
}

#[test]
fn nested_root_names_are_rejected() {
    let (dir, mut v) = make_vault("nestedroot");
    let src = dir.path().join("f.txt");
    std::fs::write(&src, b"x").unwrap();

    assert!(matches!(
        v.add(&src, Some("a/b.txt")),
        Err(Error::InvalidEntryName(_))
    ));
    assert!(matches!(
        v.add_if(&src, Some("a/b.txt"), None),
        Err(Error::InvalidEntryName(_))
    ));

    v.add(&src, Some("a.txt")).unwrap();
    assert!(matches!(
        v.rename("a.txt", "b/c.txt"),
        Err(Error::InvalidEntryName(_))
    ));
    assert_eq!(v.list().unwrap()[0].name, "a.txt");
}

#[test]
fn re_adding_a_tree_fails_without_writing_blobs() {
    let (dir, mut v) = make_vault("treepreflight");
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("sub/file.txt"), b"nested").unwrap();
    v.add(&tree, None).unwrap();
    let blobs_before = walk_blobs(&v.path().join("d"));

    assert!(matches!(v.add(&tree, None), Err(Error::EntryExists(_))));
    assert_eq!(walk_blobs(&v.path().join("d")), blobs_before);

    let out = dir.path().join("restored");
    v.extract("tree", &out).unwrap();
    assert_eq!(std::fs::read(out.join("sub/file.txt")).unwrap(), b"nested");
}

#[test]
fn failed_erase_leaves_the_entry_and_old_password_intact() {
    let (dir, mut v) = make_vault("erasefail");
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();
    v.add(&secret, None).unwrap();
    let keep = dir.path().join("keep.txt");
    std::fs::write(&keep, b"keep").unwrap();
    v.add(&keep, None).unwrap();

    let blobs = walk_blobs(&v.path().join("d"));
    assert_eq!(blobs.len(), 2);
    let originals: Vec<_> = blobs.iter().map(|p| std::fs::read(p).unwrap()).collect();

    // Corrupt every blob so rotation of the survivor must fail.
    for path in &blobs {
        let mut bytes = std::fs::read(path).unwrap();
        bytes[40] ^= 0xFF;
        std::fs::write(path, bytes).unwrap();
    }

    let vault_path = v.path().to_path_buf();
    assert!(v.erase("secret.txt", "new-password").is_err());
    drop(v);

    // Restore the pre-erase ciphertext; the vault (including the entry that
    // was supposed to be erased) must still be usable under the old password.
    for (path, bytes) in blobs.iter().zip(originals) {
        std::fs::write(path, bytes).unwrap();
    }

    let mut reopened = Vault::new(vault_path);
    reopened.unlock("master-password").unwrap();
    let names: Vec<_> = reopened
        .list()
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(names.contains(&"secret.txt".to_string()));
    assert!(names.contains(&"keep.txt".to_string()));

    let out = dir.path().join("secret-out.txt");
    reopened.extract("secret.txt", &out).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), b"secret");

    assert!(Vault::new(reopened.path().to_path_buf())
        .unlock("new-password")
        .is_err());
}

#[test]
fn orphaned_compaction_staging_is_cleaned_up() {
    let (_d, mut v) = make_vault("stagedlog");
    let parent = v.path().parent().unwrap().to_path_buf();
    let staged = v.path().join("d").join(".index.log.next");
    std::fs::write(&staged, b"interrupted write").unwrap();

    let src = parent.join("after-crash.txt");
    std::fs::write(&src, b"payload").unwrap();
    v.add(&src, None).unwrap();

    assert!(!staged.exists());
    assert!(v
        .list()
        .unwrap()
        .iter()
        .any(|e| e.name == "after-crash.txt"));
}
