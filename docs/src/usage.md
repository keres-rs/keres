# Quick start

This page gets you from an installed binary to a working vault and an
encrypted file. For the full command set, see the [CLI reference](./cli-reference.md).

## Encrypt a single file

```console
$ keres encrypt report.pdf
Encrypted to: 7d3a9c1e...f04.krs
```

Without an output argument, the CLI writes a hash-derived `.krs` name in the
current directory. The original filename is encrypted inside the container,
not stored on disk.

Decrypt it:

```console
$ keres decrypt 7d3a9c1e...f04.krs report.pdf
Decrypted 'report.pdf' to: report.pdf
```

`decrypt` refuses to overwrite an existing destination unless you pass
`--force`.

## Create and use a vault

```console
$ keres init personal
Vault 'personal' created at /home/you/.keres/vaults/personal

$ keres add personal ./photos --name photos
Added successfully!

$ keres add personal ./notes.txt
Added successfully!

$ keres list personal
NAME                                              SIZE TYPE
------------------------------------------------------------
notes.txt                                          4.2 KB file
photos                                                  - dir

$ keres extract personal photos ./restored
Extracted to: ./restored

$ keres verify personal
Vault integrity check:
  Entries total:   42
  Entries verified: 42
  Status: OK — all files present and authenticated
```

Vaults store both files and directory trees. `list` shows top-level entries;
children are addressed by their full `parent/child` path in commands that take
an entry name.

## Change the password

```console
$ keres change-password personal
Current password:
New password:
Confirm new password:
Password changed successfully!
```

This re-wraps the vault's master key. Stored ciphertext is not rewritten.
To change the data key itself, use `keres rotate`; see
[Recovery, rotation, and migration](./operations.md).

## Use the library

```rust
use keres::{decrypt_file, encrypt_file, Vault};
use std::path::Path;

let container = encrypt_file("correct horse", Path::new("report.pdf"), None)?;
let name = decrypt_file("correct horse", &container, Path::new("report.pdf"))?;
assert_eq!(name, "report.pdf");

let mut vault = Vault::new("personal".into());
vault.init("correct horse")?;
vault.add(Path::new("photos"), Some("photos"))?;
vault.add(Path::new("notes.txt"), None)?;
vault.extract("photos", Path::new("./restored"))?;
vault.lock();
# Ok::<(), keres::Error>(())
```

`Vault::init` leaves the vault unlocked. For an existing vault, call
`vault.unlock(password)` before operations, and `vault.lock()` when finished.

## Where to go next

- [CLI guide](./cli-usage.md) for workflows, destructive operations, and
  automation.
- [Library guide](./library-usage.md) for the full API.
- [Security model](./security.md) for what Keres does and does not protect.
