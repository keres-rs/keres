# Contributing

Contributions are welcome. Keres handles other people's data, so changes are
reviewed with a bias toward correctness and explicit failure over convenience.

## Repository layout

| Path | Contents |
|---|---|
| `src/` | The `keres` library: container format, crypto, vault |
| `keres-cli/` | The `keres` binary; keep it a thin wrapper over the library |
| `tests/`, `benches/` | Integration tests and Criterion benchmarks |
| `fuzz/` | `cargo-fuzz` targets (separate, excluded workspace) |
| `docs/` | This mdBook |
| `.github/workflows/` | CI, docs deployment, fuzzing, and release |

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

`cargo deny check` requires `cargo-deny`. The policy is in `deny.toml`; do not
broaden the license allowlist without review.

## What a good change looks like

- **Security first.** Do not weaken an authenticated property for
  convenience. Changes to the format, key derivation, or AAD need a
  regression test and a written rationale.
- **Fail loudly.** A damaged manifest, malformed header, or missing blob must
  be an error. Never treat corruption as an empty vault.
- **Test the failure path.** New behavior needs a test that fails without the
  change. Crash-safety changes should explain what happens at each commit
  point.
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

Fuzz targets use the nightly toolchain from `fuzz/rust-toolchain.toml` and run
weekly in CI. Format test vectors live in `tests/vectors/`; see
[Format test vectors](./test-vectors.md). Never regenerate a fixture to make a
test pass — a digest change means the wire format changed and needs deliberate
review.

## Documentation

- Update the relevant page in `docs/src/` when behavior changes.
- Keep relative links between pages; use absolute GitHub or docs.rs links in
  the root README, which is also published to crates.io.
- CLI examples should be runnable as written.
- Separate normative format details (architecture chapter) from task-oriented
  guides.

Build locally with `mdbook serve docs`.

## Security reports

Do not open a public issue for a suspected vulnerability. Follow
[SECURITY.md](https://github.com/Keres-rs/keres/blob/main/SECURITY.md).

## Commits and review

- Keep commits focused and explain the why in the message.
- Do not commit generated build output, vaults, or `.krs` fixtures other than
  the committed test vector.
- Expect review questions about failure modes, rollback behavior, and secret
  handling.

By contributing, you agree that your contribution is licensed under
Apache-2.0 (code) or CC0-1.0 (documentation), matching the repository.
