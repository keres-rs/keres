# Keres

[![CI](https://github.com/Keres-rs/keres/actions/workflows/ci.yml/badge.svg)](https://github.com/Keres-rs/keres/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/keres.svg)](https://crates.io/crates/keres)
[![docs.rs](https://docs.rs/keres/badge.svg)](https://docs.rs/keres)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](https://github.com/Keres-rs/keres/blob/main/Cargo.toml)

Keres encrypts files and directories at rest. It is available as a Rust
library (`keres`) and a command-line tool (`keres-cli`). Both use the same
container format, so data written by one can be read by the other.

There are two ways to use it:

- **Single-file encryption** turns one file into a self-contained `.krs`
  container. The original filename is encrypted inside the container.
- **Vaults** hold many files and directory trees under one password, with an
  encrypted index. Entries can be listed, renamed, replaced, or removed
  without decrypting the whole vault.

> **Status:** Keres is pre-1.0 (0.7.x). The container format is versioned and
> tested, but the public API may still change. The project has not yet had an
> independent security audit. See
> [SECURITY.md](https://github.com/Keres-rs/keres/blob/main/SECURITY.md)
> before relying on it for high-value data.

## Install

Command-line tool:

```console
$ cargo install keres-cli
```

Library:

```toml
[dependencies]
keres = "0.7"
```

Prebuilt CLI archives for Linux, macOS, and Windows are attached to
[GitHub Releases](https://github.com/Keres-rs/keres/releases). Nix users can
run `nix run . -- --help` from a checkout. The minimum supported Rust version
is 1.85.

## Quick start

Create a vault, add a directory, and restore it:

```console
$ keres init personal
$ keres add personal ./photos --name photos
$ keres list personal
$ keres extract personal photos ./restored
$ keres verify personal
```

Encrypt and decrypt a single file:

```console
$ keres encrypt document.pdf
Encrypted to: 6f1c0e...c2a.krs

$ keres decrypt 6f1c0e...c2a.krs document.pdf
```

The CLI prompts for passwords by default. Avoid putting passwords on the
command line; use a terminal prompt, `--password-file`, `--password-stdin`,
or `KERES_PASSWORD` for automation.

The same operations from Rust:

```rust
use keres::{decrypt_file, encrypt_file, Vault};
use std::path::Path;

// Single file: name is encrypted inside the container.
let container = encrypt_file("correct horse", Path::new("document.pdf"), None)?;
let original_name = decrypt_file("correct horse", &container, Path::new("restored.pdf"))?;
assert_eq!(original_name, "document.pdf");

// Vault.
let mut vault = Vault::new("myvault".into());
vault.init("correct horse")?;
vault.add(Path::new("photos"), Some("photos"))?;
vault.add(Path::new("notes.txt"), None)?;
vault.extract("photos", Path::new("./restored"))?;
vault.lock();
```

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
re-encrypting stored data. Deep rotation (`keres rotate`) is available when
the data key itself must change.

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
| `keres-cli/` | The `keres` binary |
| `docs/` | mdBook documentation source |
| `tests/`, `benches/` | Integration tests and Criterion benchmarks |
| `fuzz/` | `cargo-fuzz` targets (separate workspace) |

## Documentation

- [The Keres book](https://keres-rs.github.io) — installation, CLI and
  library guides, architecture, and security model.
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
