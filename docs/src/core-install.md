# Krypton Core

`krypton-core` is the library crate. The package is named `krypton-core` on
crates.io, but the library target is `krypton`, so imports look like this:

```rust
use krypton::{decrypt_file, encrypt_file, Vault};
```

## Add the dependency

```console
$ cargo add krypton-core
```

or, in `Cargo.toml`:

```toml
[dependencies]
krypton-core = "0.4"
```

## Requirements

- Rust 1.75 or newer (MSRV).
- No async runtime, no external services, and no I/O beyond `std::fs`.

## From the workspace

```console
$ cargo build -p krypton-core
$ cargo doc -p krypton-core --open
$ cargo test -p krypton-core
```

Next: [use the library](core-usage.md).
