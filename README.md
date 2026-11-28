# Keres

[![CI](https://github.com/Keres-rs/keres/actions/workflows/ci.yml/badge.svg)](https://github.com/Keres-rs/keres/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/keres.svg)](https://crates.io/crates/keres)
[![docs.rs](https://docs.rs/keres/badge.svg)](https://docs.rs/keres)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](https://github.com/Keres-rs/keres/blob/main/Cargo.toml)

Keres is an embedded encrypted storage engine for Rust applications. It gives
you authenticated file storage with encrypted names and directory structure,
crash-safe updates, key rotation, and recovery, without designing a container
format or key hierarchy yourself.

```rust
use keres::{Result, Vault};

fn store_attachment(vault: &mut Vault, name: &str, bytes: &[u8]) -> Result<()> {
    vault.add_from_reader(name, bytes, Some(bytes.len() as u64))
}

fn load_attachment(vault: &Vault, name: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    vault.extract_to_writer(name, &mut out)?;
    Ok(out)
}
```

Use it when your application owns files that must be confidential and
tamper-evident at rest: a local-first notes app, a desktop client, an
attachment store, or a service that keeps user documents on disk.

- **Embedded, not a service.** No mount, daemon, database, async runtime, or
  `unsafe` code. The crate is a library first.
- **Streaming.** `Read`/`Write` adapters and vault readers/writers keep memory
  bounded regardless of file size.
- **Encrypted metadata.** Entry names and directory layout never appear in
  plaintext. Opt-in size padding hides exact sizes behind buckets.
- **Crash safe.** Configs, indexes, and outputs are staged and committed
  atomically, with journaled rotation and compaction.
- **Configurable cost.** Argon2id parameters are selectable per container and
  stored inside the ciphertext, so defaults can evolve without breaking old
  files.
- **Operable.** Multiple keyslots, password changes, deep key rotation,
  crypto-erasure, recovery kits, and full-integrity verification.

The `keres` command-line tool in `keres-cli/` is the reference implementation
and a scripting/debugging aid. It uses the same format as the library.

`keres-desktop/` is a Rust + iced client that embeds the library
directly. It is a separate workspace and demonstrates the vault lifecycle,
keyslots, recovery, migration, padding, and rotation. See
[`keres-desktop/README.md`](keres-desktop/README.md).

> **Status:** Keres is pre-1.0 (0.7.x). The container format is versioned and
> tested, but the public API may still change. The project has not yet had an
> independent security audit. See
> [SECURITY.md](https://github.com/Keres-rs/keres/blob/main/SECURITY.md)
> before relying on it for high-value data.

## Install

```toml
[dependencies]
keres = "0.7"
```

The minimum supported Rust version is 1.85. The library builds on Linux,
macOS, and Windows, including ARM targets, because it has no
architecture-specific code.

The reference CLI is installed separately:

```console
$ cargo install keres-cli
```

Prebuilt CLI archives for Linux x86_64, macOS ARM64, and Windows x86_64 are
attached to [GitHub Releases](https://github.com/Keres-rs/keres/releases).
Other platforms should use `cargo install keres-cli`. Nix users can run
`nix run . -- --help` from a checkout.

## Embedding quick start

Create or unlock a vault, then read and write entries without temporary files:

```rust
use keres::{KdfParams, Result, Vault, VaultOptions};

fn open_store(path: std::path::PathBuf, password: &str) -> Result<Vault> {
    let mut vault = Vault::new(path);
    if vault.exists() {
        vault.unlock(password)?;
    } else {
        // A real application would usually keep the defaults. Lowering the
        // cost here only keeps examples and tests fast.
        vault.init_with_options(
            password,
            VaultOptions::new().kdf(KdfParams {
                m_cost_kib: 8 * 1024,
                t_cost: 1,
                p_cost: 1,
            }),
        )?;
    }
    Ok(vault)
}

fn main() -> Result<()> {
    let dir = std::env::temp_dir().join(format!("keres-readme-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let mut vault = open_store(dir.join("vault"), "correct horse")?;

    let attachment = b"application data".to_vec();
    vault.add_from_reader("report.txt", &attachment[..], Some(attachment.len() as u64))?;

    for entry in vault.list()? {
        println!("{} ({} bytes)", entry.name, entry.size);
    }

    let mut restored = Vec::new();
    vault.extract_to_writer("report.txt", &mut restored)?;
    assert_eq!(restored, attachment);

    vault.lock();
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
```

Path-based helpers are available too: `add`, `replace`, `extract`, and
`apply_batch`. For standalone `.krs` containers, use `encrypt_file` /
`decrypt_file` or the streaming API:

```rust
use keres::streaming::{decrypt_stream, encrypt_stream, StreamOptions};
use std::io::Cursor;

let mut ciphertext = Vec::new();
encrypt_stream(
    "correct horse",
    &mut Cursor::new(b"one self-contained object"),
    &mut ciphertext,
    Some("note.txt"),
    StreamOptions::new(),
)?;

let mut plaintext = Vec::new();
decrypt_stream("correct horse", Cursor::new(ciphertext), &mut plaintext, StreamOptions::new())?;
```

The [library guide](https://keres-rs.github.io/library-usage.html) covers
lifecycle, keyslots, recovery, rotation, padding, and concurrency. The
[embedding guide](https://keres-rs.github.io/embedding.html) covers async
runtimes, key management, error policy, and a shipping checklist.

## How it works

Every object — a `.krs` file, a vault entry, or the vault index — is a single
authenticated container:

- AES-256-GCM for all ciphertext, with the chunk index and payload context
  bound into every tag.
- Argon2id for password-based keys. Parameters are stored in each container
  so the defaults can change without breaking existing files.
- HKDF-SHA256 for per-object subkeys, so two entries never share a content
  key.
- 64 KiB chunks, processed at constant memory regardless of file size.
- Writes staged through a temporary file and committed with `fsync` +
  `rename`, so an interrupt does not leave half-written files or a broken
  vault.

Vault metadata is protected too: names, directory structure, and the index
are encrypted. A password change re-wraps the master key instead of
re-encrypting stored data. Deep rotation is available when the data key itself
must change.

## Reference CLI

The CLI exposes the same operations for scripts and manual recovery:

```console
$ keres init personal
$ keres add personal ./photos --name photos
$ keres list personal
$ keres extract personal photos ./restored
$ keres verify personal
```

```console
$ keres encrypt document.pdf
Encrypted to: 6f1c0e...c2a.krs

$ keres decrypt 6f1c0e...c2a.krs document.pdf
```

The CLI prompts for passwords by default. Avoid putting passwords on the
command line; use a terminal prompt, `--password-file`, `--password-stdin`,
or `KERES_PASSWORD` for automation. See the
[CLI reference](https://keres-rs.github.io/cli-reference.html).

## Security model

Keres protects data at rest against an attacker who can read (and modify)
stored files. It does not protect against malware running while a vault is
unlocked, a compromised operating system, or keyloggers.

What is protected:

- File contents and vault metadata (names and directory layout).
- Integrity of every byte: modification, truncation, reordering, and
  transplanting ciphertext are detected before plaintext is released.
- Password changes without rewriting stored ciphertext.
- Crash consistency for configs, indexes, and outputs.

What is not protected by default:

- Exact file sizes. Opt-in padding (`--padding adaptive` or a fixed bucket)
  hides sizes behind buckets, but not access patterns.
- Entry counts, modification times, and the fact that a Keres container
  exists.
- Rollback of an entire vault directory to an older valid copy.
- Deniability: the format identifies itself.

The full threat model, guarantees, and limitations are in the
[security documentation](https://github.com/Keres-rs/keres/blob/main/docs/src/security.md).

## Repository layout

| Path | Contents |
|---|---|
| `src/` | The `keres` library |
| `examples/` | Runnable embedding examples |
| `keres-cli/` | The reference CLI (not the product) |
| `docs/` | mdBook documentation source |
| `tests/`, `benches/` | Integration tests and Criterion benchmarks |
| `fuzz/` | `cargo-fuzz` targets (separate workspace) |

## Documentation

- [The Keres book](https://keres-rs.github.io) — installation, embedding and
  CLI guides, architecture, and security model.
- [API reference](https://docs.rs/keres) — generated rustdoc.
- [CHANGELOG.md](https://github.com/Keres-rs/keres/blob/main/CHANGELOG.md) —
  release history.
- [ROADMAP.md](https://github.com/Keres-rs/keres/blob/main/ROADMAP.md) —
  current priorities.
- [SECURITY.md](https://github.com/Keres-rs/keres/blob/main/SECURITY.md) —
  threat model and vulnerability reporting.
- [CONTRIBUTING.md](https://github.com/Keres-rs/keres/blob/main/CONTRIBUTING.md) —
  development workflow and review gates.

## Development

```console
$ cargo test --workspace --all-targets
$ cargo test --workspace --doc
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo fmt --all -- --check
$ cargo doc --workspace --no-deps
$ cargo run --example in_memory
$ cargo run --example vault_store
$ mdbook serve docs
```

CI runs the test suite on Linux, Windows, and macOS, plus the MSRV (1.85) on
Linux. It also checks formatting, clippy, rustdoc, dependency policy, package
dry-runs, and the documentation build. Fuzz targets run weekly.

## License

Licensed under
[Apache-2.0](https://github.com/Keres-rs/keres/blob/main/LICENSE). The
documentation in `docs/` is licensed under CC0-1.0; see
[docs/LICENSE](https://github.com/Keres-rs/keres/blob/main/docs/LICENSE).
