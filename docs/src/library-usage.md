# Library guide

The `keres` crate exposes two high-level APIs and a small set of building
blocks:

| API | Import | Purpose |
|---|---|---|
| Single-file | `keres::{encrypt_file, decrypt_file}` | One self-contained `.krs` container |
| Vault | `keres::Vault` | Many files and directories under one password |
| Streaming | `keres::streaming` | `Read`/`Write` adapters over the same format |
| Building blocks | `keres::crypto`, `keres::kdf`, `keres::padding` | Primitives and parameter types |

Everything commonly used is re-exported from `keres::prelude`. All fallible
operations return `keres::Result<T>` with a typed
[`Error`](./architecture.md#error-taxonomy).

## Single-file encryption

```rust
use keres::{decrypt_file, encrypt_file};
use std::path::Path;

// `None` writes a hash-derived `.krs` name in the current directory.
let container = encrypt_file("correct horse", Path::new("report.pdf"), None)?;

// The returned String is the original filename stored in the trailer.
let name = decrypt_file("correct horse", &container, Path::new("restored.pdf"))?;
assert_eq!(name, "report.pdf");
# Ok::<(), keres::Error>(())
```

Properties:

- The output is self-contained: KDF parameters and the original filename are
  inside the authenticated container.
- Output is written through a temporary file in the destination directory and
  committed with `fsync` + `rename`. An error leaves no partial plaintext or
  ciphertext file behind.
- On Unix, new files and directories are created with owner-only permissions
  (`0600`/`0700`).
- If `output` is `None`, the filename is `sha256(argon_salt ‖ object_salt).krs`
  in the current directory. It is opaque, not secret.
- The filename returned by `decrypt_file` comes from the container. Treat it
  as untrusted if you use it to build paths, or pass it through
  `keres::sanitize::sanitize_stored_name`.

To hide the exact plaintext size behind a bucket:

```rust
use keres::Padding;
use std::path::Path;

let container = keres::encrypt_file_with_padding(
    "correct horse",
    Path::new("report.pdf"),
    None,
    Padding::Adaptive,
)?;
# Ok::<(), keres::Error>(())
```

## Vault lifecycle

```rust
use keres::Vault;
use std::path::Path;

let mut vault = Vault::new("myvault".into());

// Create. Fails if the path is already an initialized vault.
// `init` leaves the vault unlocked.
vault.init("correct horse")?;

// Later, in a new process:
vault.unlock("correct horse")?;
vault.add(Path::new("report.pdf"), None)?;
vault.lock();
# Ok::<(), keres::Error>(())
```

`Vault::new` only creates a handle. It does not touch the filesystem.
`exists()` reports whether the path has a vault config.

| Method | Requires unlocked | Notes |
|---|---|---|
| `init`, `init_with_padding` | no | Creates the vault and leaves it unlocked |
| `unlock`, `lock` | no | Loads/drops the master key in memory |
| `add`, `replace`, `rename`, `remove` | yes | Mutations commit through the index |
| `add_if`, `replace_if`, `apply_batch` | yes | Conditional or batched mutations |
| `list`, `extract`, `padding`, `version` | yes | Read or inspect the index |
| `verify` | either | Takes the password; restores the previous lock state |
| `change_password`, `rotate`, `erase`, `migrate`, `recover` | no | Authenticate the password/code passed to them |
| `keyslots` | no | Slot ids are plaintext metadata |
| `create_recovery_kit` | no | Verifies the password passed to it |

## Adding and reading entries

```rust
use keres::Vault;
use std::path::Path;

let mut vault = Vault::new("myvault".into());
vault.unlock("correct horse")?;

// Add one file and one directory tree.
vault.add(Path::new("report.pdf"), None)?;
vault.add(Path::new("photos"), Some("pictures"))?;

// List top-level entries.
for entry in vault.list()? {
    println!(
        "{} — {} bytes{}",
        entry.name,
        entry.size,
        if entry.is_directory { " (directory)" } else { "" }
    );
}

// Extract a file or a whole directory under `dest`.
let path = vault.extract("pictures", Path::new("./restored"))?;
println!("restored {}", path.display());

vault.lock();
# Ok::<(), keres::Error>(())
```

Names are vault-relative paths. A top-level entry may not contain `/`, `\`,
`..`, or control characters. Children of a directory are addressed by their
full `parent/child` path, for example `pictures/2026/summer.jpg` when
extracting a single nested file.

Mutating operations:

```rust
use keres::Vault;
use std::path::Path;

let mut vault = Vault::new("myvault".into());
vault.unlock("correct horse")?;

// Replace a file: copy-on-write, new entry ID, old blob removed after commit.
vault.replace(Path::new("report-v2.pdf"), "report.pdf")?;

// Rename a top-level file or directory without re-encrypting its ciphertext.
vault.rename("report.pdf", "report-final.pdf")?;

// Remove a file, or a directory and everything below it.
vault.remove("report-final.pdf")?;

vault.lock();
# Ok::<(), keres::Error>(())
```

## Batches and conditional writes

`version()` returns an `IndexVersion` token. `add_if` and `replace_if` compare
against it and write nothing on a mismatch:

```rust
use keres::{Vault, WriteOutcome};
use std::path::Path;

let mut vault = Vault::new("myvault".into());
vault.unlock("correct horse")?;
let expected = vault.version()?;

match vault.add_if(Path::new("new.txt"), None, Some(expected))? {
    WriteOutcome::Applied { version } => println!("added at {version:?}"),
    WriteOutcome::Conflict { current } => println!("retry against {current:?}"),
}
vault.lock();
# Ok::<(), keres::Error>(())
```

`add_if` also refuses to overwrite an existing name (if-none-match). Use
`apply_batch` to commit several operations with one index write:

```rust
use keres::{BatchOp, Vault};
use std::path::Path;

let mut vault = Vault::new("myvault".into());
vault.unlock("correct horse")?;

vault.apply_batch(&[
    BatchOp::Add {
        source: Path::new("new.txt").into(),
        name: None,
    },
    BatchOp::Replace {
        source: Path::new("report-v2.pdf").into(),
        name: "report.pdf".into(),
    },
    BatchOp::Remove {
        name: "old-notes.txt".into(),
    },
])?;
vault.lock();
# Ok::<(), keres::Error>(())
```

If any operation fails, the index is unchanged. Newly written blobs become
orphans and can be reclaimed with `prune_orphans`.

## Integrity checks and cleanup

```rust
use keres::Vault;

let mut vault = Vault::new("myvault".into());
vault.unlock("correct horse")?;
let report = vault.verify("correct horse")?;

println!("{} of {} entries authenticated", report.verified, report.total_entries);
println!("missing: {:?}", report.missing);
println!("corrupted: {:?}", report.corrupted);

if report.missing.is_empty() && report.corrupted.is_empty() {
    let removed = vault.prune_orphans()?;
    println!("pruned {removed} orphan(s)");
}
# Ok::<(), keres::Error>(())
```

`verify` authenticates every blob and the replayed index. It checks the
plaintext size and the SHA-256 content hash recorded in the index, so a
storage attacker cannot substitute an older valid blob under the same entry
ID. It does not write plaintext to disk and does not detect rollback of the
entire vault directory.

`prune_orphans` deletes `.enc` blobs and stale temp files under `d/` that no
index record references. It requires an unlocked vault and refuses to run if
the index snapshot is missing, so a damaged vault is never mistaken for an
empty one.

## Keyslots

A vault can have several independent passphrases, each wrapping the same
master key:

```rust
use keres::Vault;

let mut vault = Vault::new("myvault".into());

// List slot ids. No password required.
for slot in vault.keyslots()? {
    println!("slot {}", slot.id);
}

// Add a second passphrase, authorized by an existing one.
let slot = vault.add_keyslot("correct horse", "laptop passphrase")?;
println!("added {}", slot.id);

// Revoke a slot, authorized by a passphrase that will remain.
vault.remove_keyslot(&slot.id, "correct horse")?;
# Ok::<(), keres::Error>(())
```

Removing a keyslot revokes that passphrase but does not change the master key.
Anyone who already unwrapped the master key with the revoked passphrase keeps
access to existing ciphertext. Use `rotate` when a passphrase or key may have
leaked.

## Recovery kit

A recovery kit is a second wrapping of the master key, protected by a
one-time printable code:

```rust
use keres::Vault;

let mut vault = Vault::new("myvault".into());
let code = vault.create_recovery_kit("correct horse")?;

// Print once and store offline, separately from the vault directory.
println!("{}", code.expose());
# Ok::<(), keres::Error>(())
```

If `vault.config` is lost or damaged but `vault.recovery` survives:

```rust
use keres::Vault;

let mut vault = Vault::new("myvault".into());
vault.recover("<recovery code>", "new password")?;
vault.unlock("new password")?;
# Ok::<(), keres::Error>(())
```

Recovery validates the recovered master key against the encrypted index,
writes a fresh single-slot config, and consumes the kit. Additional keyslots
are lost and must be re-added. Losing both the password and the code is
unrecoverable.

## Password changes, rotation, and erasure

These operations are easy to confuse:

| Operation | Master key | Stored data | Other keyslots | Recovery kit | Final state |
|---|---|---|---|---|---|
| `change_password` | unchanged | untouched | untouched | untouched | unchanged |
| `rotate` | new | re-encrypted | revoked | removed | locked |
| `erase` | new | survivors re-encrypted, entry omitted | revoked | removed | locked |

```rust
use keres::Vault;

let mut vault = Vault::new("myvault".into());

// Re-wrap one keyslot. Cheap and safe.
vault.change_password("correct horse", "new password")?;
# Ok::<(), keres::Error>(())
```

```rust
use keres::Vault;

// Deep rotation: fresh master key, every entry re-encrypted.
let mut vault = Vault::new("myvault".into());
let report = vault.rotate("old password", "new password")?;
println!(
    "re-encrypted {} entries ({} bytes); revoked {} keyslot(s), kit removed: {}",
    report.entries,
    report.bytes,
    report.discarded_keyslots,
    report.recovery_kit_removed
);
# Ok::<(), keres::Error>(())
```

`erase` removes one entry and rotates in one journaled commit:

```rust
use keres::Vault;

let mut vault = Vault::new("myvault".into());
vault.unlock("old password")?;
let report = vault.erase("old-secret.txt", "new password")?;
println!("erased; re-encrypted {} entries", report.entries);
# Ok::<(), keres::Error>(())
```

Erasure is forward-looking. It stops the old key from working against the
vault from now on, but it cannot revoke a copy of the deleted blob that an
attacker already captured together with the old key material.

Both `rotate` and `erase` leave the vault locked. Both are crash-safe through
a journal: an interrupted run is completed or rolled back on the next open.

## Size padding

Padding is opt-in and applies to future writes:

```rust
use keres::{Padding, Vault};

let mut vault = Vault::new("private".into());
vault.init_with_padding("correct horse", Padding::Adaptive)?;

// Show the policy, then switch to fixed 64 KiB buckets.
println!("{:?}", vault.padding()?);
vault.set_padding(Padding::fixed(65_536)?)?;
vault.lock();
# Ok::<(), keres::Error>(())
```

- `Padding::None` — exact sizes (default).
- `Padding::Adaptive` — next power of two clamped to 4 KiB–16 MiB; larger
  payloads round to the next 16 MiB multiple.
- `Padding::Fixed { size }` — next multiple of a bucket in the same range.

The policy is stored in the authenticated index, so an attacker cannot
silently disable it. Existing blobs keep their original sizes until they are
rewritten. Manifests and directory placeholders are never padded.

## Streaming

`keres::streaming` encrypts and decrypts the `.krs` format over any
`Read`/`Write` pair:

```rust
use std::io::Cursor;
use keres::streaming::{decrypt_stream, encrypt_stream, StreamOptions};

let payload = b"streamed in 64 KiB chunks".to_vec();
let mut ciphertext = Vec::new();

encrypt_stream(
    "correct horse",
    &mut Cursor::new(payload.clone()),
    &mut ciphertext,
    Some("note.txt"),
    StreamOptions::new(),
)?;

let mut plaintext = Vec::new();
let info = decrypt_stream(
    "correct horse",
    Cursor::new(ciphertext),
    &mut plaintext,
    StreamOptions::new(),
)?;

assert_eq!(plaintext, payload);
assert_eq!(info.original_name.as_deref(), Some("note.txt"));
# Ok::<(), keres::Error>(())
```

`EncryptWriter` and `DecryptReader` are the underlying `Write`/`Read`
adapters. `StreamOptions` supports a cumulative progress callback and an
`AtomicBool` cancellation flag.

> **Integrity caveat:** each chunk is authenticated before its plaintext is
> yielded, but the trailer (total size and chunk count) can only be checked at
> end-of-stream. A truncated or trailer-tampered stream can yield some valid
> plaintext before the final error. Write to a temporary file and discard it
> on error, as `decrypt_file` does.

## Error handling

Wrong passwords and tampered ciphertext both map to `Error::Authentication`.
This is deliberate: error messages must not become a tamper oracle.

```rust
use keres::{decrypt_file, Error};
use std::path::Path;

match decrypt_file("pw", Path::new("backup.krs"), Path::new("out.bin")) {
    Ok(name) => println!("restored {name}"),
    Err(Error::Authentication) => eprintln!("wrong password or corrupted data"),
    Err(e) => eprintln!("failed: {e}"),
}
```

The full variant list is in the
[error taxonomy](./architecture.md#error-taxonomy).

## Concurrency and process safety

Vault operations take an advisory lock on `vault.lock`:

- writers take it exclusively;
- readers (`list`, `extract`, `verify`) take it shared;
- a contended call returns `Error::VaultBusy` instead of waiting.

The lock coordinates well-behaved processes. It is not a security boundary:
a process that ignores the lock can still read or modify files. Run one
writer per vault at a time, and do not point two Keres releases at the same
vault directory (see [Compatibility](./architecture.md#compatibility-and-versioning)).
