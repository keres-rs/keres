# Keres library

`keres` is the library crate. The package is named `keres` on
crates.io, but the library target is `keres`, so imports look like this:

```rust
use keres::{decrypt_file, encrypt_file, Vault};
```

## Add the dependency

```console
$ cargo add keres
```

or, in `Cargo.toml`:

```toml
[dependencies]
keres = "0.4"
```

## Requirements

- Rust 1.85 or newer (MSRV).
- No async runtime, no external services, and no I/O beyond `std::fs`.

## From the workspace

```console
$ cargo build -p keres
$ cargo doc -p keres --open
$ cargo test -p keres
```

Next: [use the library](library-usage.md).
