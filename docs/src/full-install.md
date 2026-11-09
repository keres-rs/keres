# Building from source

The core, CLI, and documentation live in one repository:

```console
$ git clone https://github.com/KryptonOSS/krypton-core.git
$ cd krypton-core
```

## Build and test the workspace

```console
$ cargo test --workspace --all-targets
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo fmt --all -- --check
$ cargo doc --workspace --no-deps
```

The CLI binary is written to `target/debug/krypton` (or
`target/release/krypton` with `--release`).

## Build the documentation

```console
$ cargo install mdbook
$ mdbook serve docs
```

## With Nix

```console
$ nix develop        # rustc, cargo, clippy, rustfmt, mdbook
$ nix build          # build the workspace
```
