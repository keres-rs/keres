# Library installation

The library crate is named `keres`. The library target is also `keres`, so
imports use the crate name directly.

## Add the dependency

```console
$ cargo add keres
```

or edit `Cargo.toml`:

```toml
[dependencies]
keres = "0.7"
```

The crate currently exposes no optional Cargo features. It requires `std`:
Keres performs filesystem I/O and uses the operating system random source.

## Requirements

- Rust 1.85 or newer.
- No async runtime, external services, or background threads.
- About 64 MiB of memory during password-based key derivation (Argon2id
  defaults).

## Documentation

- API reference: [docs.rs/keres](https://docs.rs/keres)
- Local rustdoc: `cargo doc -p keres --open`
- Guides: [Library guide](./library-usage.md),
  [Embedding Keres](./embedding.md)

## Working from a checkout

```console
$ cargo build -p keres
$ cargo test -p keres
$ cargo doc -p keres --open
```

The workspace root is the library package, so plain `cargo build` also builds
`keres`.

## First example

```rust
use keres::{decrypt_file, encrypt_file};
use std::path::Path;

let container = encrypt_file("correct horse", Path::new("notes.txt"), None)?;
let name = decrypt_file("correct horse", &container, Path::new("restored.txt"))?;
assert_eq!(name, "notes.txt");
# Ok::<(), keres::Error>(())
```

See the [Library guide](./library-usage.md) for vaults, streaming, recovery,
and error handling.
