# Installation

Keres has two installable parts and a few optional extras:

| Component | Package | Install with |
|---|---|---|
| Library | `keres` | `cargo add keres` |
| CLI | `keres-cli` (binary: `keres`) | `cargo install keres-cli` |
| Source build | workspace | `git clone` + `cargo build` |
| Documentation | mdBook sources | `mdbook serve docs` |

The library and CLI do not depend on each other at runtime. Install only what
you need.

## Platform support

Keres targets the stable Rust toolchain and supports:

| Platform | Status | Notes |
|---|---|---|
| Linux | Tested in CI | POSIX permissions and `flock` locking |
| macOS | Tested in CI | POSIX permissions and `flock` locking |
| Windows | Tested in CI | `LockFileEx` locking and native `rename` |
| Other Unix-like systems | Best effort | Needs `std::fs`, `flock`, and a working OS random source |

The minimum supported Rust version (MSRV) is **1.85**.

## Requirements

- Rust 1.85 or newer (install via [rustup](https://rustup.rs/)).
- A filesystem that supports atomic rename within a directory. Local
  filesystems do; some network and FUSE filesystems do not.
- Enough memory for Argon2id. The default KDF uses 64 MiB per derivation.

## Next steps

- [Install the library](./library-install.md)
- [Install the CLI](./cli-install.md)
- [Build from source](./full-install.md)
- [Quick start](./usage.md)
