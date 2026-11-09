# Krypton Core usage

## Single file

```rust
use krypton::{decrypt_file, encrypt_file};
use std::path::Path;

// Encrypt. `None` writes a random-looking `.krf` name in the current dir.
let out = encrypt_file("correct horse", Path::new("document.pdf"), None)?;

// Decrypt. Returns the original filename recovered from the authenticated
// trailer; treat it as untrusted if you use it to build paths.
let original_name = decrypt_file("correct horse", &out, Path::new("restored.pdf"))?;
assert_eq!(original_name, "document.pdf");
# Ok::<(), krypton::Error>(())
```

The container is self-contained: it carries the Argon2id parameters and the
encrypted original filename.

## Vault

```rust
use krypton::Vault;
use std::path::Path;

let mut vault = Vault::new("myvault".into());

// First run: create the vault. `init` fails if it already exists.
if !vault.exists() {
    vault.init("correct horse battery staple")?;
}
vault.unlock("correct horse battery staple")?;

// Store a file and a whole directory tree.
vault.add(Path::new("report.pdf"), None)?;
vault.add(Path::new("photos"), Some("pictures"))?;

for entry in vault.list()? {
    println!("{} — {} bytes, dir: {}", entry.name, entry.size, entry.is_directory);
}

// Restore. Files are written to `dest`; directories are recreated under it.
vault.extract("report.pdf", Path::new("./out"))?;

// Rotate the password without re-encrypting stored data.
vault.change_password("correct horse battery staple", "new secret")?;

vault.lock();
# Ok::<(), krypton::Error>(())
```

## Integrity check

```rust
# use krypton::Vault;
let mut vault = Vault::new("myvault".into());
let report = vault.verify("correct horse battery staple")?;
println!("{} of {} entries authenticated", report.verified, report.total_entries);
# Ok::<(), krypton::Error>(())
```

`verify` authenticates every blob and reports missing or corrupted entries.
It does not write plaintext to disk.

## Building blocks

The `krypton::crypto` module exposes `Key`, `seal`/`open` (AEAD with AAD),
`derive_key` (Argon2id), `secure_compare`, and the nonce helpers. Most
applications should use the higher-level APIs above.

## Error handling

All fallible operations return `krypton::Result<T>`. Wrong passwords and
tampered ciphertext deliberately map to the same `Error::Authentication`
variant, so callers cannot turn error messages into a tamper oracle.

```rust
use krypton::{decrypt_file, Error};
use std::path::Path;

match decrypt_file("pw", Path::new("backup.krf"), Path::new("out.bin")) {
    Ok(original_name) => println!("restored {original_name}"),
    Err(Error::Authentication) => eprintln!("wrong password or corrupted data"),
    Err(e) => eprintln!("failed: {e}"),
}
```
