# Release Notes

## Releasing

Releases are tag-driven. `.github/workflows/release.yml` runs when a `v*` tag
is pushed (or manually via **Run workflow**) and:

1. Verifies the tag is on `main` and matches the workspace version in
   `Cargo.toml`.
2. Runs `cargo test --workspace --locked`.
3. Publishes `keres` and then `keres-cli` to crates.io, waiting for the index
   to expose the library before the CLI.
4. Builds `keres` for Linux (x86_64), macOS (aarch64), and Windows (x86_64),
   packages each archive with a SHA-256 file, and attests build provenance.
5. Creates the GitHub Release and attaches the archives and checksums.

```console
$ git tag v0.6.0
$ git push origin v0.6.0
```

One-time repository setup:

- On crates.io, configure **Trusted Publishing** for both `keres` and
  `keres-cli`, pointing at `Keres-rs/keres` and
  `.github/workflows/release.yml`.
- Create a `release` **environment** in GitHub with required reviewers, so a
  publish cannot happen without approval.
- Ensure the workflow's `id-token: write` / `attestations: write` permissions
  are allowed by the repository's Actions policy.

The workflow is idempotent: if a crate version is already on crates.io it is
skipped, so a failed release can be re-run from the same tag. `keres-cli`
cannot be published before the matching `keres` version is live.

## 0.6.0 (unreleased)

- Added committed format test vectors, `cargo-fuzz` targets, and Criterion
  benchmarks.
- Added `Vault::replace` and `Vault::prune_orphans` (`keres replace`,
  `keres verify --prune`).
- Added `Vault::rename` and stable random entry IDs (manifest v3), so renames
  no longer re-encrypt data and blob identity is independent of the path.
- Added `--password-file`, `--password-stdin`, `--force`, and remove
  confirmation to the CLI, with zeroized password buffers.
- Added `.github/workflows/release.yml`: tag-driven crates.io publishing
  (library before CLI, Trusted Publishing), cross-platform binary archives,
  SHA-256 checksums, build-provenance attestations, and a GitHub Release.
- CI now runs doctests and `cargo-deny`, and the MSRV is 1.85.
- **Upgrade note:** vaults written by 0.5.0 use manifest v2 and are rejected
  by 0.6.0. `keres migrate` is required before the 0.6.0 tag; until then,
  extract with 0.5.0 before upgrading.

## 0.5.0

- Consolidated the library, CLI, and documentation into one Cargo workspace.
- Renamed the project from Krypton to Keres: library `keres`, CLI package
  `keres-cli`, binary `keres`, and `.krs` single-file containers.
- Added advisory vault locking: writers take an exclusive lock, readers a
  shared one, and concurrent access returns `Error::VaultBusy`.
- Added workspace-wide CI for tests on Linux, Windows, and macOS, plus
  linting, rustdoc, package dry-runs, and the mdBook build.
- Added root `CONTRIBUTING.md`, `SECURITY.md`, `ROADMAP.md`, and
  `CHANGELOG.md`.
- Hardened temp-file creation: files are created with `O_CREAT | O_EXCL`
  and mode `0600` (Unix) up front, so plaintext is never briefly readable
  by other users and a planted symlink cannot redirect a write.

## 0.4.2

- Renamed the crates.io package to `krypton-core` while keeping the library
  name `krypton`.
- Updated repository metadata.

## 0.4.1

- Version bump and lockfile update.

## 0.4.0

- Introduced the universal container format shared by `.krf` files, vault
  blobs, and manifests.
- Added Argon2id parameters stored in each container.
- Added per-object HKDF subkeys, counter nonces, and AAD binding.
- Added `Vault::verify`.
- Added crash-safe atomic writes.
- Retired pre-0.4 formats.

See [CHANGELOG.md](https://github.com/Keres-rs/keres/blob/main/CHANGELOG.md)
for the full history.
