# Contributing to Keres

Thanks for helping. This repository is a single Cargo workspace containing
the library, the CLI, and the documentation.

## Getting started

```console
$ git clone https://github.com/KeresOSS/keres.git
$ cd keres
$ cargo test --workspace --all-targets
```

Optional but recommended:

```console
$ rustup component add clippy rustfmt
$ nix develop            # if you use Nix; includes mdbook
```

## Layout

- `crates/keres/` — the library. Container format, crypto primitives,
  vault implementation, and integration tests.
- `crates/keres-cli/` — the `keres` binary. Keep it a thin wrapper over
  the library; business logic belongs in `keres`.
- `docs/` — the mdBook sources. Build locally with `mdbook serve docs`.

## Before opening a pull request

Run the same gates as CI:

```console
$ cargo fmt --all -- --check
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo test --workspace --all-targets
$ cargo doc --workspace --no-deps
$ mdbook build docs
```

## Guidelines

- Security first. Do not weaken an authenticated property for convenience.
  If a change alters the format, key derivation, or AAD, document it and add
  a regression test.
- New public API needs rustdoc with an example. The crate denies missing
  docs.
- New behavior needs a test that would fail without the change.
- Keep the container format backwards-compatible. New object kinds are new
  payload types, never new magics.
- Prefer small, focused commits with a clear rationale.

## Reporting bugs and vulnerabilities

- Bugs and feature requests: open a GitHub issue with a minimal reproducer,
  OS, Rust version, and the command or API call used.
- Security issues: do **not** open a public issue. Follow
  [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contribution is licensed under
Apache-2.0 (code) or CC0-1.0 (documentation), matching the files you change.
