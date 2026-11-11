# Contributing

Contributions to Keres are welcome. The repository is a single Cargo
workspace containing the library, CLI, and documentation.

## Getting started

```console
$ git clone https://github.com/Keres-rs/keres.git
$ cd keres
$ cargo test --workspace --all-targets
```

The workspace layout:

- `crates/keres/` — library: container format, crypto, vault.
- `crates/keres-cli/` — the `keres` binary.
- `fuzz/` — `cargo-fuzz` targets (a separate, excluded workspace).
- `docs/` — this mdBook.

## Before opening a pull request

Run the same gates as CI:

```console
$ cargo fmt --all -- --check
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo test --workspace --all-targets
$ cargo test --workspace --doc
$ cargo deny check
$ cargo doc --workspace --no-deps
$ mdbook build docs
```

## Fuzzing and benchmarks

```console
$ cargo bench -p keres --bench throughput
$ cd fuzz
$ cargo fuzz run read_container
$ cargo fuzz run parse_manifest
$ cargo fuzz run parse_config
$ cargo fuzz run sanitize
```

Fuzz targets use a nightly toolchain (see `fuzz/rust-toolchain.toml`). The
weekly `Fuzz` workflow runs each target for 60 seconds.

Format test vectors live in `crates/keres/tests/vectors/`; see
[Test vectors](./test-vectors.md). Never regenerate a fixture to make a test
pass — a digest change means the wire format changed and needs a deliberate
review.

## Guidelines

- Security first. Do not weaken an authenticated property for convenience.
  Changes to the format, key derivation, or AAD need a regression test and a
  documented rationale.
- New public API needs rustdoc with an example; the library denies missing
  docs.
- New behavior needs a test that fails without the change.
- The container format is versioned. New object kinds are new payload types,
  never new magics.
- Keep the CLI a thin wrapper; business logic belongs in `keres`.
- Prefer small, focused commits.

## Reporting bugs and vulnerabilities

- Bugs and feature requests: open a GitHub issue with a minimal reproducer,
  OS, Rust version, and the command or API call used.
- Security issues: do **not** open a public issue. See
  [SECURITY.md](https://github.com/Keres-rs/keres/blob/main/SECURITY.md).

## License

By contributing, you agree that your contribution is licensed under
Apache-2.0 (code) or CC0-1.0 (documentation), matching the files you change.
