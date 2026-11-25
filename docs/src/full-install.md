# Building from source

The repository is a Cargo workspace with the library at the root and the CLI
in `keres-cli/`.

## Prerequisites

- Rust 1.85 or newer via rustup
- Git
- Optional: mdBook for the documentation
- Optional: Nix, for a reproducible shell and build

```console
$ git clone https://github.com/Keres-rs/keres.git
$ cd keres
```

## Build and test

```console
$ cargo build --workspace
$ cargo test --workspace --all-targets
$ cargo test --workspace --doc
```

The CLI binary is written to `target/debug/keres`; a release build goes to
`target/release/keres`:

```console
$ cargo build --release -p keres-cli
```

The release profile enables LTO, one codegen unit, and symbol stripping. The
CLI additionally uses `opt-level = "z"`.

## Lint and documentation gates

These are the same gates CI runs:

```console
$ cargo fmt --all -- --check
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo doc --workspace --no-deps
$ cargo deny check
```

## Build the book

```console
$ cargo install mdbook
$ mdbook serve docs
```

`mdbook build docs` writes the static site to `docs/book/`.

## Nix

```console
$ nix develop        # rustc, cargo, clippy, rustfmt, rust-analyzer, mdbook
$ nix build          # library + CLI
$ nix run . -- help  # run the CLI from the flake
```

The flake reads the workspace version from `Cargo.toml`, so release builds and
the flake stay in sync.

## Fuzzing

The `fuzz/` directory is a separate Cargo workspace:

```console
$ cd fuzz
$ cargo fuzz run read_container
$ cargo fuzz run parse_manifest
$ cargo fuzz run parse_config
$ cargo fuzz run sanitize
```

Fuzz targets require the nightly toolchain selected by
`fuzz/rust-toolchain.toml`.
