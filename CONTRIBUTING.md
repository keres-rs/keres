# Contributing to Keres

Keres handles other people's data. Changes are reviewed with a bias toward
correctness and explicit failure over convenience.

The repository is one Cargo workspace: the `keres` library at the root, the
`keres-cli` binary in `keres-cli/`, and the mdBook sources in `docs/`.

## Getting started

```console
$ git clone https://github.com/Keres-rs/keres.git
$ cd keres
$ cargo test --workspace --all-targets
$ cargo test --workspace --doc
```

Rust 1.85 or newer is required. Nix users can run `nix develop` for a shell
with the toolchain, clippy, rustfmt, rust-analyzer, and mdBook.

## Before opening a pull request

Run the same gates as CI:

```console
$ cargo fmt --all -- --check
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo test --workspace --all-targets
$ cargo test --workspace --doc
$ cargo doc --workspace --no-deps
$ cargo deny check
$ mdbook build docs
```

`cargo deny check` requires `cargo-deny`; the policy is in `deny.toml`. Do not
broaden the license allowlist without review.

## What a good change looks like

- **Do not weaken an authenticated property for convenience.** Changes to the
  container format, key derivation, or AAD need a written rationale and a
  regression test.
- **Fail loudly.** A damaged manifest, malformed header, or missing blob must
  be an error. Never treat corruption as an empty vault.
- **Test the failure path.** New behavior needs a test that fails without the
  change. Crash-safety changes should state what happens at each commit point.
- **Document public API.** The library denies missing docs and broken
  intra-doc links.
- **Keep the CLI thin.** Business logic belongs in the library.
- **Respect the format.** New object kinds are new payload types with new AAD
  contexts, never new magics or reused context strings.

## Tests, fuzzing, and benchmarks

```console
$ cargo test -p keres
$ cargo bench -p keres --bench throughput

$ cd fuzz
$ cargo fuzz run read_container
$ cargo fuzz run parse_manifest
$ cargo fuzz run parse_config
$ cargo fuzz run sanitize
```

Fuzz targets use the nightly toolchain from `fuzz/rust-toolchain.toml`.

Committed format fixtures live in `tests/vectors/`. A changed digest means the
wire format changed; never regenerate a fixture just to make a test pass. See
[Format test vectors](docs/src/test-vectors.md).

## Documentation

- Update the relevant page in `docs/src/` when behavior changes.
- Use relative links between book pages. The root `README.md` is published to
  crates.io, so it uses absolute repository and docs.rs links.
- CLI examples should be runnable as written.
- Keep normative format details in the architecture chapter; guides should
  describe tasks.

Build the book locally with `mdbook serve docs`. The writing conventions are
in [docs/README.md](docs/README.md).

## Commits and review

- Keep commits focused and explain the why in the message.
- Do not commit build output, vaults, or generated `.krs` files other than the
  committed test vector.
- Expect questions about failure modes, rollback behavior, and secret
  handling.

## Releases

Releases are tag-driven; see [docs/src/release.md](docs/src/release.md). A tag
must point at a commit on `main` and match the workspace version. Publishing
uses crates.io Trusted Publishing behind the protected `release` environment,
so maintainers do not need a long-lived registry token.

## Reporting bugs and vulnerabilities

Bugs and feature requests go to GitHub issues with a minimal reproducer, the
operating system and Rust version, and the command or API call used.

Do not open a public issue for a suspected vulnerability. Follow
[SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contribution is licensed under
Apache-2.0 (code) or CC0-1.0 (documentation), matching the files you change.
