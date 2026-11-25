# Embedding Keres

Keres is an encrypted storage engine for Rust applications. Use it when your
application owns files that must be confidential and tamper-evident at rest,
and you would otherwise design a container format, key hierarchy, and crash
safety protocol yourself.

This chapter is about integrating the library. For the full method list see
the [library guide](./library-usage.md); for the format and threat model see
[Architecture](./architecture.md) and [Security model](./security.md).

## Pick the right shape

| Your data | Use |
|---|---|
| One opaque blob per object, keyed by a password | [Single-file containers](./library-usage.md#single-file-encryption) |
| Many files with names, listing, replace, and one or more passphrases | [Vaults](./library-usage.md#vault-lifecycle) |
| Bytes already in memory, a socket, or an object store | Readers/writers and [`streaming`](https://docs.rs/keres/latest/keres/streaming/) |
| Only primitives (AEAD, HKDF, Argon2id) | [`keres::crypto`](https://docs.rs/keres/latest/keres/crypto/) |

A vault is the right default for application data: it hides names and
directory structure, supports many entries under one unlocked master key, and
lets you change a passphrase without rewriting stored ciphertext. Use
single-file containers when each object must be independently decryptable
with only a password, for example a portable export or an email attachment.

## A minimal embedded store

```rust
use keres::{KdfParams, Result, Vault, VaultOptions};

fn open_store(path: std::path::PathBuf, password: &str) -> Result<Vault> {
    let mut vault = Vault::new(path);
    if vault.exists() {
        vault.unlock(password)?;
    } else {
        vault.init_with_options(
            password,
            VaultOptions::new().kdf(KdfParams::new()),
        )?;
    }
    Ok(vault)
}

fn save_attachment(vault: &mut Vault, name: &str, bytes: &[u8]) -> Result<()> {
    vault.add_from_reader(name, bytes, Some(bytes.len() as u64))
}

fn load_attachment(vault: &Vault, name: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    vault.extract_to_writer(name, &mut out)?;
    Ok(out)
}
```

`init` leaves a new vault unlocked. On later runs, `unlock` loads the master
key; call `lock` (or drop the `Vault`) when the application no longer needs
it.

## Do not put a password in the source

A vault password protects the key hierarchy, so treat it like a secret, not a
configuration value. Common patterns:

- Ask the user once at startup and keep the unlocked `Vault` for the session.
- Generate a high-entropy passphrase with the OS random source, store it in
  the platform keychain (Keychain, Credential Manager, Secret Service), and
  pass it to `unlock`.
- Derive it from an application key only if that key is itself protected by
  the platform.

Keres never writes the password or master key to disk. The master key lives
in zeroizing memory and is scrubbed on `lock` or drop.

## Blocking calls and async runtimes

The library is synchronous and performs CPU-bound Argon2id work plus blocking
file I/O. It does not require Tokio or any other runtime. In an async
application, wrap calls in `spawn_blocking` (Tokio) or the equivalent:

```rust
use keres::{Result, Vault};

async fn add_in_background(
    path: std::path::PathBuf,
    password: String,
    name: String,
    bytes: Vec<u8>,
) -> Result<Vault> {
    tokio::task::spawn_blocking(move || {
        let mut vault = Vault::new(path);
        vault.unlock(&password)?;
        let len = bytes.len() as u64;
        vault.add_from_reader(&name, &bytes[..], Some(len))?;
        Ok(vault)
    })
    .await
    .expect("blocking task panicked")
}
```

Do not hold a `Vault` across `.await` points in a single-threaded executor:
the unlocked key and the advisory lock are process resources, not async
guards.

Unlocking is intentionally expensive. Do it once per session rather than per
operation, and avoid running the default parameters inside a request handler
on a latency-sensitive thread.

## Concurrency

Mutation methods take `&mut self`, so a single `Vault` value serializes
writes naturally. The on-disk lock coordinates processes:

- writers take an exclusive lock;
- readers take a shared lock;
- a contended call returns `Error::VaultBusy` immediately instead of waiting.

The practical model is one writer per vault and any number of readers, with
the application serializing access to a single `Vault` value. If several
threads need to write, put the handle behind a mutex or send operations to one
owner thread. The lock is advisory: it coordinates well-behaved processes, not
malicious ones.

## Errors

All fallible operations return `keres::Result<T>`. Match on `Error` rather
than parsing messages:

```rust
use keres::Error;

fn describe(error: &Error) -> &'static str {
    match error {
        Error::Authentication => "wrong password or corrupted data",
        Error::VaultBusy => "another process is using this vault",
        Error::VaultLocked => "unlock the vault first",
        Error::EntryNotFound(_) => "no such entry",
        Error::InvalidEntryName(_) => "the name is not a safe vault path",
        _ => "storage operation failed",
    }
}
```

Wrong passwords and tampered ciphertext deliberately share
`Error::Authentication`. Do not add detail that turns errors into a tamper
oracle.

## Choosing KDF parameters

`KdfParams::new()` uses Argon2id with 64 MiB, 4 passes, and parallelism 4.
That is a reasonable desktop/server default. Consider:

- **Memory-constrained devices:** lower `m_cost_kib` and `t_cost`, but stay
  within the validated range (8 MiB minimum). Argon2id memory is the main
  defense against parallel offline guessing.
- **Long-term archives:** raise `t_cost` and `m_cost_kib` if unlock latency
  is acceptable.
- **Tests and CI:** use a small cost such as 8 MiB, one pass, one lane. Never
  ship that as the default for real data.

Parameters are stored per keyslot and per container, so a later default change
does not break existing files. New keyslots inherit the vault's parameters.
Current releases do not raise the cost of an existing vault in place; choose
the parameters deliberately at `init`, and treat a change as a migration that
creates a new vault and re-adds the data.

## Size padding

Padding is opt-in. Without it, an observer who can measure storage learns the
exact plaintext size of every object. With `Padding::Adaptive` or a fixed
bucket, they learn only the bucket:

```rust
use keres::{Padding, Vault, VaultOptions};

let mut vault = Vault::new("myvault".into());
vault.init_with_options(
    "correct horse",
    VaultOptions::new().padding(Padding::Adaptive),
)?;
# Ok::<(), keres::Error>(())
```

Padding requires the plaintext length up front, so `add_from_reader` needs
`Some(len)` on a padded vault. Padding costs storage and a little CPU; decide
per application rather than enabling it everywhere.

## Versioning and stability

Keres is pre-1.0. The on-disk format is versioned and pinned by test vectors,
but the Rust API may still change between minor releases. For production
embedding:

- pin the exact version in `Cargo.lock` and review the changelog before
  upgrading;
- keep a test that opens a vault created by the previous release;
- do not treat the current API as a long-term compatibility promise until a
  1.0 release;
- budget for an independent security audit before storing high-value data.

The format is documented so that data is not locked to this crate forever;
see [Format test vectors](./test-vectors.md) and
[Architecture](./architecture.md).

## Checklist before shipping

- [ ] The password comes from a user or a platform secret store, never a
      literal in the binary.
- [ ] Unlocking happens once per session, off the async executor's hot path.
- [ ] One writer per vault, with a documented `VaultBusy` retry policy.
- [ ] `verify` is available as a maintenance/diagnostic operation.
- [ ] The application has a recovery plan: recovery kit, password reset, or
      both.
- [ ] Padding is enabled if exact sizes are sensitive.
- [ ] The crate version is pinned and the changelog is reviewed on upgrade.
- [ ] The [security model](./security.md) limitations are acceptable for the
      data being stored.
