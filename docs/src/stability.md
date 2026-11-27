# API stability and versioning

This page states what upgrades can and cannot break. It covers the Rust API,
the minimum supported Rust version (MSRV), and how the crate version relates to
the on-disk format.

## Crate version vs format version

These are independent:

- The **crate version** follows [Semantic Versioning](https://semver.org/) and
  describes the Rust API.
- The **container and vault format versions** are written into the data and
  evolve separately. They are documented in
  [Architecture](./architecture.md#compatibility-and-versioning) and pinned by
  [test vectors](./test-vectors.md).

A crate release can change the API without changing the format. A format
change requires a new format version and a documented migration path; it does
not silently reinterpret existing data.

## Pre-1.0 policy (current)

Keres is currently `0.7.x`.

- **Patch releases** (`0.7.1` → `0.7.2`) fix bugs and security issues without
  intentionally breaking the public API.
- **Minor releases** (`0.7.x` → `0.8.0`) may include breaking API changes.
  They will be called out in `CHANGELOG.md` with upgrade notes.
- The on-disk format is never changed in a way that makes existing data
  unreadable without a migration path.

Because breaking changes are allowed in minor releases, pin the exact version
in `Cargo.lock` and review the changelog before upgrading. Keep at least one
test that opens data written by the previous release.

## What counts as a breaking change

The usual Rust rules apply: removing or renaming a public item, changing a
signature, adding a required trait bound, or changing behaviour that callers
can observe.

Two attributes are used deliberately to keep future changes non-breaking:

- `#[non_exhaustive]` on growable enums (`Error`, `BatchOp`, `WriteOutcome`,
  `Padding`) and output structs (`EntryInfo`, `StreamInfo`,
  `IntegrityReport`, `IndexVersion`, `KeyslotInfo`, `MigrationReport`,
  `RotationReport`). Downstream code must include a wildcard arm when matching
  these enums and cannot construct the structs with a literal. In exchange,
  new variants and fields can be added in a patch or minor release.
- `#[must_use]` on constructors, getters, and builder methods whose result is
  otherwise easy to discard by accident.

Adding one of these attributes is itself a breaking change for downstream code
that matched exhaustively or used a struct literal. Treat it as such when
reviewing a release.

## Deprecation

Public items are deprecated with `#[deprecated]` for at least one minor release
before removal. The replacement is named in the attribute and in the changelog.
Security fixes may remove an unsafe API faster, with an explicit advisory.

## MSRV policy

The MSRV is **Rust 1.85**, declared as `rust-version` in `Cargo.toml`.

- CI builds and tests the workspace on the MSRV on every change.
- The MSRV may be raised in a **minor** release, never in a patch release.
- An MSRV bump is documented in `CHANGELOG.md`. Following normal Rust
  ecosystem practice, it is not treated as a semver-breaking change for the
  library.
- Raising the MSRV requires a reason: a required compiler feature, a dependency
  MSRV bump, or a security fix. It is not raised to use cosmetic syntax.

## Semver checking

Releases run [`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks)
against the last published version before publishing. The check fails when the
public API changed in a way the version bump does not allow.

Run it locally before opening a release pull request:

```console
$ cargo install cargo-semver-checks --locked
$ cargo semver-checks --package keres
```

The tool derives the release type from the version in `Cargo.toml`. If you
intend a breaking change, bump `[workspace.package].version` to the next minor
version before running it; a patch bump with a breaking change fails the check.

## Supported versions

Security fixes are applied to the latest published release. Only the current
container format is supported; data written by an older format must be upgraded
with the release that introduced the upgrade (for example, `keres migrate` for
legacy vaults).

## Stability checklist for embedders

- [ ] `Cargo.lock` is committed and the crate version is pinned.
- [ ] The changelog is read before every upgrade.
- [ ] A test opens a fixture written by the previous release.
- [ ] CI runs on the declared MSRV if you support it.
- [ ] The [security model](./security.md) limitations are acceptable for your
      data.
